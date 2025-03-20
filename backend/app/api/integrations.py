"""

Endpoints:
  POST  /api/integrations/configure            — add / update a webhook config
  GET   /api/integrations/configure            — list all webhook configs
  DELETE /api/integrations/configure/{id}      — remove a webhook config
  POST  /api/integrations/test                 — send a test event to a webhook
  POST  /api/integrations/export/siem          — export findings in SIEM format
  POST  /api/integrations/syslog/send          — send a syslog message
  GET   /api/integrations/history              — delivery history
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from ..integrations.siem_exporter import SIEMExporter, SIEMEvent, SIEMFormat
from ..integrations.syslog_forwarder import (
    SyslogForwarder,
    SyslogMessage,
    SyslogProtocol,
    SyslogSeverity,
)
from ..integrations.webhook_manager import (
    WebhookConfig,
    WebhookDelivery,
    WebhookEvent,
    WebhookManager,
    WebhookProvider,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/integrations", tags=["Integrations"])

# ---------------------------------------------------------------------------
# Singletons (in-process state — replace with DB persistence in production)
# ---------------------------------------------------------------------------
_webhook_manager = WebhookManager()
_siem_exporter = SIEMExporter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class WebhookConfigRequest(BaseModel):
    id: str = Field(..., description="Unique config identifier")
    provider: str = Field(..., description="slack | teams | discord | pagerduty | jira | generic")
    url: str = Field(..., description="Webhook URL")
    name: str = Field("", description="Human-readable name")
    enabled: bool = Field(True)
    events: List[str] = Field(default_factory=list, description="Event types to subscribe to (empty = all)")
    token: str = Field("", description="Auth token / routing key / Jira API token")
    jira_project: str = Field("", description="Jira project key")
    jira_issue_type: str = Field("Bug", description="Jira issue type")
    jira_username: str = Field("", description="Jira email for basic auth")
    jira_severity_threshold: str = Field("high", description="Minimum severity to create Jira ticket")
    pagerduty_severity: str = Field("error", description="PagerDuty severity level")
    custom_headers: Dict[str, str] = Field(default_factory=dict)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        valid = {p.value for p in WebhookProvider}
        if v not in valid:
            raise ValueError(f"provider must be one of {valid}")
        return v


class WebhookConfigResponse(BaseModel):
    id: str
    provider: str
    url: str
    name: str
    enabled: bool
    events: List[str]


class TestEventRequest(BaseModel):
    config_id: str = Field(..., description="Webhook config ID to test")
    event: str = Field("scan_completed", description="Event type to simulate")
    data: Dict[str, Any] = Field(
        default_factory=lambda: {
            "title": "Test Finding — SQL Injection",
            "severity": "high",
            "description": "This is a test event from UniVex.",
            "target_host": "demo.univex.local",
            "category": "injection",
        }
    )


class SIEMExportRequest(BaseModel):
    format: str = Field("json", description="cef | leef | json")
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")

    @field_validator("format")
    @classmethod
    def _validate_format(cls, v: str) -> str:
        valid = {f.value for f in SIEMFormat}
        if v not in valid:
            raise ValueError(f"format must be one of {valid}")
        return v


class SplunkPushRequest(BaseModel):
    hec_url: str = Field(..., description="Splunk HEC base URL")
    hec_token: str = Field(..., description="Splunk HEC token")
    index: str = Field("main", description="Splunk index")
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")


class ELKPushRequest(BaseModel):
    elk_url: str = Field(..., description="Elasticsearch base URL")
    index: str = Field("univex-findings", description="Index name")
    api_key: Optional[str] = Field(None, description="API key (optional)")
    username: Optional[str] = Field(None, description="Basic auth username")
    password: Optional[str] = Field(None, description="Basic auth password")
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")


class SyslogSendRequest(BaseModel):
    host: str = Field(..., description="Syslog server host")
    port: Optional[int] = Field(None, description="Syslog server port")
    protocol: str = Field("udp", description="udp | tcp | tls")
    message: str = Field(..., description="Syslog message text")
    severity: str = Field("info", description="emerg|alert|crit|err|warning|notice|info|debug")
    app_name: str = Field("univex", description="SYSLOG-MSG APP-NAME field")
    msg_id: str = Field("-", description="SYSLOG-MSG MSGID field")

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, v: str) -> str:
        if v not in SyslogProtocol.values():
            raise ValueError(f"protocol must be one of {SyslogProtocol.values()}")
        return v


class DeliveryHistoryItem(BaseModel):
    config_id: str
    event: str
    url: str
    success: bool
    status_code: Optional[int]
    error: Optional[str]
    timestamp: str
    duration_ms: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_to_siem_event(f: Dict[str, Any]) -> SIEMEvent:
    return SIEMEvent(
        id=str(f.get("id", "")),
        title=str(f.get("title", "Unknown Finding")),
        description=str(f.get("description", "")),
        severity=str(f.get("severity", "medium")),
        category=str(f.get("category", "")),
        source_tool=str(f.get("source_tool", f.get("source", "UniVex"))),
        target_host=str(f.get("target_host", f.get("host", ""))),
        target_port=f.get("port") or f.get("target_port"),
        cve_id=f.get("cve_id"),
        cvss_score=f.get("cvss_score"),
        remediation=str(f.get("remediation", "")),
        extra={k: v for k, v in f.items() if k not in {
            "id", "title", "description", "severity", "category",
            "source_tool", "source", "target_host", "host",
            "port", "target_port", "cve_id", "cvss_score", "remediation",
        }},
    )


def _delivery_to_response(d: WebhookDelivery) -> DeliveryHistoryItem:
    return DeliveryHistoryItem(
        config_id=d.config_id,
        event=str(d.event),
        url=d.url,
        success=d.success,
        status_code=d.status_code,
        error=d.error,
        timestamp=d.timestamp.isoformat(),
        duration_ms=round(d.duration_ms, 2),
    )


# ---------------------------------------------------------------------------
# Webhook config endpoints
# ---------------------------------------------------------------------------

@router.post("/configure", status_code=201)
async def add_webhook_config(req: WebhookConfigRequest) -> Dict[str, Any]:
    """Register or update a webhook integration configuration."""
    try:
        events_parsed = [WebhookEvent(e) for e in req.events] if req.events else []
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    cfg = WebhookConfig(
        id=req.id,
        provider=WebhookProvider(req.provider),
        url=req.url,
        name=req.name,
        enabled=req.enabled,
        events=events_parsed,
        token=req.token,
        jira_project=req.jira_project,
        jira_issue_type=req.jira_issue_type,
        jira_username=req.jira_username,
        jira_severity_threshold=req.jira_severity_threshold,
        pagerduty_severity=req.pagerduty_severity,
        custom_headers=req.custom_headers,
    )
    try:
        _webhook_manager.add_config(cfg)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    logger.info("Webhook config added: %s (%s)", cfg.id, cfg.provider)
    return {"status": "ok", "id": cfg.id, "provider": cfg.provider.value}


@router.get("/configure")
async def list_webhook_configs() -> List[WebhookConfigResponse]:
    """List all registered webhook configurations."""
    return [
        WebhookConfigResponse(
            id=c.id,
            provider=c.provider.value,
            url=c.url,
            name=c.name,
            enabled=c.enabled,
            events=[e.value for e in c.events],
        )
        for c in _webhook_manager.list_configs()
    ]


@router.delete("/configure/{config_id}", status_code=204, response_model=None)
async def delete_webhook_config(config_id: str) -> None:
    """Remove a webhook configuration by ID."""
    removed = _webhook_manager.remove_config(config_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Config '{config_id}' not found")


# ---------------------------------------------------------------------------
# Test endpoint
# ---------------------------------------------------------------------------

@router.post("/test")
async def test_webhook(req: TestEventRequest) -> Dict[str, Any]:
    """Send a test event to a specific webhook configuration."""
    cfg = _webhook_manager.get_config(req.config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"Config '{req.config_id}' not found")

    try:
        event = WebhookEvent(req.event)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event type '{req.event}'",
        )

    # Temporarily enable and fire
    original_enabled = cfg.enabled
    original_events = cfg.events
    cfg.enabled = True
    cfg.events = []  # accept all events for test
    try:
        deliveries = _webhook_manager.fire(event, req.data)
    finally:
        cfg.enabled = original_enabled
        cfg.events = original_events

    if not deliveries:
        return {"status": "no_delivery", "message": "Config found but no delivery attempted"}

    d = deliveries[0]
    return {
        "status": "delivered" if d.success else "failed",
        "success": d.success,
        "status_code": d.status_code,
        "error": d.error,
        "duration_ms": round(d.duration_ms, 2),
    }


# ---------------------------------------------------------------------------
# SIEM export endpoints
# ---------------------------------------------------------------------------

@router.post("/export/siem")
async def export_siem(req: SIEMExportRequest) -> Dict[str, Any]:
    """Export findings in SIEM-compatible format (CEF, LEEF, or JSON)."""
    if not req.findings:
        raise HTTPException(status_code=422, detail="findings list is empty")

    events = [_finding_to_siem_event(f) for f in req.findings]
    fmt = SIEMFormat(req.format)
    records = _siem_exporter.export_batch(events, fmt)

    return {
        "format": fmt.value,
        "count": len(records),
        "records": records,
    }


@router.post("/export/splunk")
async def push_to_splunk(req: SplunkPushRequest) -> Dict[str, Any]:
    """Push findings directly to Splunk via HTTP Event Collector."""
    if not req.findings:
        raise HTTPException(status_code=422, detail="findings list is empty")

    events = [_finding_to_siem_event(f) for f in req.findings]
    try:
        result = _siem_exporter.push_to_splunk(
            events,
            hec_url=req.hec_url,
            hec_token=req.hec_token,
            index=req.index,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result


@router.post("/export/elk")
async def push_to_elk(req: ELKPushRequest) -> Dict[str, Any]:
    """Push findings directly to Elasticsearch via Bulk API."""
    if not req.findings:
        raise HTTPException(status_code=422, detail="findings list is empty")

    events = [_finding_to_siem_event(f) for f in req.findings]
    try:
        result = _siem_exporter.push_to_elk(
            events,
            elk_url=req.elk_url,
            index=req.index,
            api_key=req.api_key,
            username=req.username,
            password=req.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result


# ---------------------------------------------------------------------------
# Syslog endpoint
# ---------------------------------------------------------------------------

@router.post("/syslog/send")
async def send_syslog(req: SyslogSendRequest) -> Dict[str, Any]:
    """Send a syslog message to a remote server (UDP/TCP/TLS)."""
    _sev_map = {
        "emerg": SyslogSeverity.EMERG,
        "alert": SyslogSeverity.ALERT,
        "crit": SyslogSeverity.CRIT,
        "err": SyslogSeverity.ERR,
        "warning": SyslogSeverity.WARNING,
        "notice": SyslogSeverity.NOTICE,
        "info": SyslogSeverity.INFO,
        "debug": SyslogSeverity.DEBUG,
    }
    sev = _sev_map.get(req.severity.lower(), SyslogSeverity.INFO)

    msg = SyslogMessage(
        message=req.message,
        severity=sev,
        app_name=req.app_name,
        msg_id=req.msg_id,
    )

    forwarder = SyslogForwarder(
        host=req.host,
        port=req.port,
        protocol=req.protocol,
    )
    success = forwarder.send(msg)

    return {"success": success, "host": req.host, "protocol": req.protocol}


# ---------------------------------------------------------------------------
# Delivery history
# ---------------------------------------------------------------------------

@router.get("/history")
async def get_delivery_history(
    limit: int = Query(100, ge=1, le=500, description="Max records to return"),
) -> List[DeliveryHistoryItem]:
    """Return recent webhook delivery history."""
    history = _webhook_manager.get_delivery_history(limit=limit)
    return [_delivery_to_response(d) for d in reversed(history)]
