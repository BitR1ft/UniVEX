"""

Configurable webhook delivery for scan events, with built-in
provider adapters for:
  - Slack (Incoming Webhooks / Block Kit)
  - Microsoft Teams (Adaptive Cards)
  - Discord (Embeds)
  - PagerDuty (Events API v2)
  - Jira (REST API v3 — create issue)
  - Generic HTTP (any endpoint, arbitrary JSON)
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import base64

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WebhookProvider(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    JIRA = "jira"
    GENERIC = "generic"


class WebhookEvent(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH = "finding_high"
    FINDING_NEW = "finding_new"
    APPROVAL_REQUIRED = "approval_required"
    REPORT_READY = "report_ready"


# ---------------------------------------------------------------------------
# Config model
# ---------------------------------------------------------------------------

@dataclass
class WebhookConfig:
    """Configuration for a single webhook destination."""

    id: str
    provider: WebhookProvider
    url: str
    name: str = ""
    enabled: bool = True
    events: List[WebhookEvent] = field(default_factory=list)  # empty = all events

    # Provider-specific fields
    token: str = ""                   # Slack OAuth / PagerDuty routing key / Jira API token
    jira_project: str = ""
    jira_issue_type: str = "Bug"
    jira_username: str = ""           # Jira email for basic auth
    jira_severity_threshold: str = "high"  # minimum severity to create ticket
    pagerduty_severity: str = "error"  # info | warning | error | critical
    custom_headers: Dict[str, str] = field(default_factory=dict)
    payload_template: Optional[str] = None  # optional Jinja2 template string

    def wants_event(self, event: WebhookEvent) -> bool:
        return not self.events or event in self.events


@dataclass
class WebhookDelivery:
    """Result of a single webhook delivery attempt."""

    config_id: str
    event: str
    url: str
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#0088FF",
    "info": "#00AAFF",
    "informational": "#00AAFF",
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "informational": "⚪",
}


def _build_slack_payload(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Slack Block Kit message."""
    sev = data.get("severity", "info").lower()
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")
    color = _SEVERITY_COLOR.get(sev, "#888888")
    title = data.get("title", event_type)
    description = data.get("description", "")
    target = data.get("target_host", "")
    ts = data.get("timestamp", datetime.now(tz=timezone.utc).isoformat())

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} UniVex — {title}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Event:*\n{event_type}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev.upper()}"},
                {"type": "mrkdwn", "text": f"*Target:*\n{target or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{ts}"},
            ],
        },
    ]
    if description:
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"_{description}_"}}
        )
    blocks.append({"type": "divider"})

    return {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
                "fallback": f"[UniVex] {event_type}: {title}",
            }
        ]
    }


def _build_teams_payload(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Microsoft Teams Adaptive Card (via Incoming Webhook)."""
    sev = data.get("severity", "info").lower()
    color = _SEVERITY_COLOR.get(sev, "#888888").lstrip("#")
    title = data.get("title", event_type)
    description = data.get("description", "")
    target = data.get("target_host", "")

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": f"UniVex — {event_type}",
        "sections": [
            {
                "activityTitle": f"**{title}**",
                "activitySubtitle": "UniVex Security Notification",
                "facts": [
                    {"name": "Event", "value": event_type},
                    {"name": "Severity", "value": sev.upper()},
                    {"name": "Target", "value": target or "N/A"},
                ],
                "text": description,
            }
        ],
    }


def _build_discord_payload(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Discord webhook with embed."""
    sev = data.get("severity", "info").lower()
    color_hex = _SEVERITY_COLOR.get(sev, "#888888").lstrip("#")
    color_int = int(color_hex, 16)
    title = data.get("title", event_type)
    description = data.get("description", "")
    target = data.get("target_host", "")

    return {
        "username": "UniVex",
        "embeds": [
            {
                "title": title,
                "description": description or f"Event: {event_type}",
                "color": color_int,
                "fields": [
                    {"name": "Severity", "value": sev.upper(), "inline": True},
                    {"name": "Target", "value": target or "N/A", "inline": True},
                    {"name": "Event", "value": event_type, "inline": False},
                ],
                "footer": {"text": "UniVex Security Platform"},
                "timestamp": data.get(
                    "timestamp", datetime.now(tz=timezone.utc).isoformat()
                ),
            }
        ],
    }


def _build_pagerduty_payload(
    event_type: str,
    data: Dict[str, Any],
    routing_key: str,
    severity: str = "error",
) -> Dict[str, Any]:
    """PagerDuty Events API v2 payload."""
    sev_map = {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
        "info": "info",
    }
    pd_sev = sev_map.get(data.get("severity", "medium").lower(), severity)
    title = data.get("title", event_type)
    target = data.get("target_host", "unknown")

    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[UniVex] {title} on {target}",
            "source": target,
            "severity": pd_sev,
            "timestamp": data.get(
                "timestamp", datetime.now(tz=timezone.utc).isoformat()
            ),
            "custom_details": {
                "event_type": event_type,
                "severity": data.get("severity", ""),
                "description": data.get("description", ""),
                "category": data.get("category", ""),
                "cve_id": data.get("cve_id", ""),
            },
        },
    }


def _build_jira_payload(
    event_type: str,
    data: Dict[str, Any],
    project: str,
    issue_type: str = "Bug",
) -> Dict[str, Any]:
    """Jira REST API v3 create-issue payload."""
    sev = data.get("severity", "medium").lower()
    title = data.get("title", event_type)
    description = data.get("description", "")
    target = data.get("target_host", "")
    cve = data.get("cve_id", "")

    body_parts = [
        f"*Severity:* {sev.upper()}",
        f"*Target:* {target or 'N/A'}",
        f"*CVE:* {cve or 'N/A'}",
        "",
        description,
    ]

    # Jira Atlassian Document Format (ADF)
    adf_content = [
        {
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "\n".join(body_parts)}
            ],
        }
    ]

    return {
        "fields": {
            "project": {"key": project.upper()},
            "summary": f"[UniVex] {title}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": adf_content,
            },
            "issuetype": {"name": issue_type},
            "priority": {
                "name": {
                    "critical": "Highest",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "info": "Lowest",
                }.get(sev, "Medium")
            },
            "labels": ["univex", "security", event_type.replace("_", "-")],
        }
    }


# ---------------------------------------------------------------------------
# WebhookManager
# ---------------------------------------------------------------------------

class WebhookManager:
    """
    Manages webhook configurations and delivers events to all matching
    configured destinations.
    """

    def __init__(self) -> None:
        self._configs: Dict[str, WebhookConfig] = {}
        self._history: List[WebhookDelivery] = []

    # ------------------------------------------------------------------
    # Configuration management
    # ------------------------------------------------------------------

    def add_config(self, config: WebhookConfig) -> None:
        """Register a webhook configuration."""
        if not config.url:
            raise ValueError("WebhookConfig.url must not be empty")
        parsed = urlparse(config.url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Webhook URL must use http or https: {config.url}")
        self._configs[config.id] = config

    def remove_config(self, config_id: str) -> bool:
        if config_id in self._configs:
            del self._configs[config_id]
            return True
        return False

    def get_config(self, config_id: str) -> Optional[WebhookConfig]:
        return self._configs.get(config_id)

    def list_configs(self) -> List[WebhookConfig]:
        return list(self._configs.values())

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------

    def fire(
        self,
        event: WebhookEvent,
        data: Dict[str, Any],
        *,
        timeout: float = 10.0,
    ) -> List[WebhookDelivery]:
        """
        Fire a webhook event to all enabled, subscribed configurations.

        Returns a list of :class:`WebhookDelivery` results.
        """
        results: List[WebhookDelivery] = []
        for cfg in self._configs.values():
            if not cfg.enabled or not cfg.wants_event(event):
                continue
            delivery = self._deliver(cfg, event, data, timeout=timeout)
            self._history.append(delivery)
            results.append(delivery)
        return results

    def _deliver(
        self,
        cfg: WebhookConfig,
        event: WebhookEvent,
        data: Dict[str, Any],
        *,
        timeout: float,
    ) -> WebhookDelivery:
        start = time.monotonic()
        try:
            payload, headers, url = self._build_request(cfg, event, data)
            result = self._http_post(url, payload, headers, timeout=timeout)
            elapsed = (time.monotonic() - start) * 1000
            return WebhookDelivery(
                config_id=cfg.id,
                event=event,
                url=url,
                success=result["success"],
                status_code=result.get("status_code"),
                error=result.get("error"),
                duration_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Webhook delivery failed for %s: %s", cfg.id, exc)
            return WebhookDelivery(
                config_id=cfg.id,
                event=event,
                url=cfg.url,
                success=False,
                error=str(exc),
                duration_ms=elapsed,
            )

    def _build_request(
        self,
        cfg: WebhookConfig,
        event: WebhookEvent,
        data: Dict[str, Any],
    ):
        """Build (payload_dict, headers, url) for the given provider."""
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        headers.update(cfg.custom_headers)
        url = cfg.url

        if cfg.provider == WebhookProvider.SLACK:
            payload = _build_slack_payload(event, data)

        elif cfg.provider == WebhookProvider.TEAMS:
            payload = _build_teams_payload(event, data)

        elif cfg.provider == WebhookProvider.DISCORD:
            payload = _build_discord_payload(event, data)

        elif cfg.provider == WebhookProvider.PAGERDUTY:
            payload = _build_pagerduty_payload(
                event, data, cfg.token, severity=cfg.pagerduty_severity
            )
            url = "https://events.pagerduty.com/v2/enqueue"

        elif cfg.provider == WebhookProvider.JIRA:
            payload = _build_jira_payload(event, data, cfg.jira_project, cfg.jira_issue_type)
            if cfg.jira_username and cfg.token:
                creds = base64.b64encode(
                    f"{cfg.jira_username}:{cfg.token}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {creds}"

        else:  # GENERIC
            payload = {
                "event": event,
                "source": "univex",
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "data": data,
            }

        return payload, headers, url

    @staticmethod
    def _http_post(
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        *,
        timeout: float,
    ) -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return {"success": True, "status_code": resp.status}
        except HTTPError as exc:
            return {"success": False, "status_code": exc.code, "error": exc.reason}
        except URLError as exc:
            return {"success": False, "error": str(exc.reason)}

    # ------------------------------------------------------------------
    # Jira convenience
    # ------------------------------------------------------------------

    def create_jira_ticket(
        self,
        cfg: WebhookConfig,
        finding_id: str,
        title: str,
        severity: str,
        description: str,
        target: str = "",
        *,
        timeout: float = 10.0,
    ) -> WebhookDelivery:
        """
        Directly create a Jira ticket for a finding, regardless of event
        subscription configuration.
        """
        if cfg.provider != WebhookProvider.JIRA:
            raise ValueError("config must be a Jira webhook config")

        sev_threshold = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        threshold_val = sev_threshold.get(cfg.jira_severity_threshold.lower(), 3)
        finding_val = sev_threshold.get(severity.lower(), 1)
        if finding_val < threshold_val:
            return WebhookDelivery(
                config_id=cfg.id,
                event="jira_skipped",
                url=cfg.url,
                success=True,
                error=f"Severity {severity} below threshold {cfg.jira_severity_threshold}",
            )

        data = {
            "title": title,
            "severity": severity,
            "description": description,
            "target_host": target,
            "id": finding_id,
        }
        delivery = self._deliver(cfg, WebhookEvent.FINDING_NEW, data, timeout=timeout)
        return delivery

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_delivery_history(self, limit: int = 100) -> List[WebhookDelivery]:
        return self._history[-limit:]

    def clear_history(self) -> None:
        self._history.clear()
