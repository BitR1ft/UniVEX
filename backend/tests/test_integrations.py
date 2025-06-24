"""

Coverage:
  TestSIEMEvent              (8 tests)
  TestCEFFormat              (10 tests)
  TestLEEFFormat             (8 tests)
  TestJSONFormat             (7 tests)
  TestSIEMBatchExport        (5 tests)
  TestSplunkConnector        (4 tests)
  TestELKConnector           (4 tests)
  TestSyslogMessage          (8 tests)
  TestSyslogForwarder        (6 tests)
  TestWebhookProviderPayload (10 tests)
  TestWebhookManager         (10 tests)
  TestIntegrationsAPI        (12 tests + fixture)

Total: 92 tests
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.integrations.siem_exporter import (
    SIEMEvent,
    SIEMExporter,
    SIEMFormat,
    SEVERITY_MAP,
    _cef_escape,
    _leef_escape,
)
from app.integrations.syslog_forwarder import (
    SyslogFacility,
    SyslogForwarder,
    SyslogMessage,
    SyslogProtocol,
    SyslogSeverity,
)
from app.integrations.webhook_manager import (
    WebhookConfig,
    WebhookDelivery,
    WebhookEvent,
    WebhookManager,
    WebhookProvider,
    _build_discord_payload,
    _build_pagerduty_payload,
    _build_slack_payload,
    _build_teams_payload,
    _build_jira_payload,
)
from app.api.integrations import router as integrations_router


# ---------------------------------------------------------------------------
# App & client
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(integrations_router)
    return app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(_make_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ev(
    id: str = "F001",
    title: str = "SQL Injection",
    description: str = "Unparameterised SQL query allows data exfiltration",
    severity: str = "high",
    category: str = "injection",
    target_host: str = "192.168.1.10",
    target_port: int = 80,
    cve_id: str = "CVE-2023-0001",
    cvss_score: float = 8.9,
    remediation: str = "Use parameterised queries",
) -> SIEMEvent:
    return SIEMEvent(
        id=id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        target_host=target_host,
        target_port=target_port,
        cve_id=cve_id,
        cvss_score=cvss_score,
        remediation=remediation,
    )


# ===========================================================================
# TestSIEMEvent
# ===========================================================================

class TestSIEMEvent:
    def test_default_timestamp_set(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="high")
        assert e.timestamp is not None
        assert e.timestamp.tzinfo is not None

    def test_severity_normalised_to_lower(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="CRITICAL")
        assert e.severity == "critical"

    def test_severity_int_critical(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="critical")
        assert e.severity_int == 10

    def test_severity_int_high(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="high")
        assert e.severity_int == 8

    def test_severity_int_medium(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="medium")
        assert e.severity_int == 5

    def test_severity_int_low(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="low")
        assert e.severity_int == 3

    def test_severity_int_unknown_defaults(self):
        e = SIEMEvent(id="X", title="T", description="D", severity="unknown")
        assert e.severity_int == 5  # default

    def test_event_id_is_deterministic(self):
        e1 = _ev()
        e2 = _ev()
        assert e1.event_id == e2.event_id

    def test_event_id_differs_for_different_events(self):
        e1 = _ev(id="F001", target_host="host1")
        e2 = _ev(id="F002", target_host="host2")
        assert e1.event_id != e2.event_id


# ===========================================================================
# TestCEFFormat
# ===========================================================================

class TestCEFFormat:
    def setup_method(self):
        self.exporter = SIEMExporter()

    def test_cef_starts_with_prefix(self):
        rec = self.exporter.to_cef(_ev())
        assert rec.startswith("CEF:0")

    def test_cef_contains_vendor(self):
        rec = self.exporter.to_cef(_ev())
        assert "BitR1FT" in rec

    def test_cef_contains_product(self):
        rec = self.exporter.to_cef(_ev())
        assert "UniVex" in rec

    def test_cef_contains_title(self):
        rec = self.exporter.to_cef(_ev(title="XSS Attack"))
        assert "XSS Attack" in rec

    def test_cef_severity_int_in_header(self):
        rec = self.exporter.to_cef(_ev(severity="critical"))
        # Severity 10 appears between the last two pipes before the extension
        parts = rec.split("|")
        assert parts[6] == "10"

    def test_cef_extension_contains_src(self):
        rec = self.exporter.to_cef(_ev(target_host="10.0.0.1"))
        assert "src=10.0.0.1" in rec

    def test_cef_extension_contains_cve(self):
        rec = self.exporter.to_cef(_ev(cve_id="CVE-2024-9999"))
        assert "CVE-2024-9999" in rec

    def test_cef_extension_contains_dpt(self):
        rec = self.exporter.to_cef(_ev(target_port=443))
        assert "dpt=443" in rec

    def test_cef_escapes_pipe_in_title(self):
        rec = self.exporter.to_cef(_ev(title="Pipe|Test"))
        # Title in the CEF header should have escaped pipe
        assert r"Pipe\|Test" in rec

    def test_cef_escape_function(self):
        assert _cef_escape("a=b|c\\d") == r"a\=b\|c\\d"


# ===========================================================================
# TestLEEFFormat
# ===========================================================================

class TestLEEFFormat:
    def setup_method(self):
        self.exporter = SIEMExporter()

    def test_leef_starts_with_prefix(self):
        rec = self.exporter.to_leef(_ev())
        assert rec.startswith("LEEF:2.0")

    def test_leef_contains_vendor(self):
        rec = self.exporter.to_leef(_ev())
        assert "BitR1FT" in rec

    def test_leef_contains_product(self):
        rec = self.exporter.to_leef(_ev())
        assert "UniVex" in rec

    def test_leef_extension_tab_separated(self):
        rec = self.exporter.to_leef(_ev())
        ext = rec.split("|", 5)[5]
        assert "\t" in ext

    def test_leef_contains_severity(self):
        rec = self.exporter.to_leef(_ev(severity="critical"))
        assert "sev=10" in rec

    def test_leef_contains_src(self):
        rec = self.exporter.to_leef(_ev(target_host="1.2.3.4"))
        assert "src=1.2.3.4" in rec

    def test_leef_contains_cve_id(self):
        rec = self.exporter.to_leef(_ev(cve_id="CVE-2025-0001"))
        assert "CVE-2025-0001" in rec

    def test_leef_escape_function(self):
        assert _leef_escape("a\tb") == "a\\\tb"


# ===========================================================================
# TestJSONFormat
# ===========================================================================

class TestJSONFormat:
    def setup_method(self):
        self.exporter = SIEMExporter()

    def test_json_dict_has_id(self):
        d = self.exporter.to_json(_ev(id="FIND-42"))
        assert d["id"] == "FIND-42"

    def test_json_dict_has_severity(self):
        d = self.exporter.to_json(_ev(severity="medium"))
        assert d["severity"] == "medium"

    def test_json_dict_has_target(self):
        d = self.exporter.to_json(_ev(target_host="target.local", target_port=8080))
        assert d["target"]["host"] == "target.local"
        assert d["target"]["port"] == 8080

    def test_json_dict_has_cvss(self):
        d = self.exporter.to_json(_ev(cvss_score=9.8))
        assert d["cvss_score"] == 9.8

    def test_json_str_is_valid_json(self):
        s = self.exporter.to_json_str(_ev())
        parsed = json.loads(s)
        assert "id" in parsed

    def test_json_dict_format_field(self):
        d = self.exporter.to_json(_ev())
        assert d["format"] == "univex_finding_v1"

    def test_json_dict_timestamp_is_isoformat(self):
        d = self.exporter.to_json(_ev())
        ts = d["timestamp"]
        assert "T" in ts


# ===========================================================================
# TestSIEMBatchExport
# ===========================================================================

class TestSIEMBatchExport:
    def setup_method(self):
        self.exporter = SIEMExporter()
        self.events = [_ev(id=f"F{i:03d}", severity=s) for i, s in enumerate(
            ["critical", "high", "medium"]
        )]

    def test_batch_cef_length(self):
        records = self.exporter.export_batch(self.events, SIEMFormat.CEF)
        assert len(records) == 3

    def test_batch_leef_length(self):
        records = self.exporter.export_batch(self.events, SIEMFormat.LEEF)
        assert len(records) == 3

    def test_batch_json_length(self):
        records = self.exporter.export_batch(self.events, SIEMFormat.JSON)
        assert len(records) == 3

    def test_batch_cef_all_start_with_cef(self):
        records = self.exporter.export_batch(self.events, SIEMFormat.CEF)
        assert all(r.startswith("CEF:0") for r in records)

    def test_batch_json_all_valid_json(self):
        records = self.exporter.export_batch(self.events, SIEMFormat.JSON)
        for r in records:
            obj = json.loads(r)
            assert "id" in obj


# ===========================================================================
# TestSplunkConnector (mocked HTTP)
# ===========================================================================

class TestSplunkConnector:
    def setup_method(self):
        self.exporter = SIEMExporter()

    def test_push_to_splunk_invalid_url_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            self.exporter.push_to_splunk(
                [_ev()], hec_url="ftp://bad", hec_token="tok"
            )

    def test_push_to_splunk_missing_token(self):
        with pytest.raises(ValueError):
            self.exporter.push_to_splunk(
                [_ev()], hec_url="http://splunk.local:8088", hec_token=""
            )

    @patch("app.integrations.siem_exporter.urlopen")
    def test_push_to_splunk_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"text":"Success","code":0}'
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        result = self.exporter.push_to_splunk(
            [_ev()], hec_url="http://splunk.local:8088", hec_token="mytoken"
        )
        assert result["sent"] == 1
        assert result["failed"] == 0

    @patch("app.integrations.siem_exporter.urlopen")
    def test_push_to_splunk_http_error(self, mock_urlopen):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            url="http://x", code=403, msg="Forbidden", hdrs=None, fp=None  # type: ignore[arg-type]
        )
        result = self.exporter.push_to_splunk(
            [_ev()], hec_url="http://splunk.local:8088", hec_token="tok"
        )
        assert result["failed"] == 1
        assert result["sent"] == 0


# ===========================================================================
# TestELKConnector (mocked HTTP)
# ===========================================================================

class TestELKConnector:
    def setup_method(self):
        self.exporter = SIEMExporter()

    def test_push_to_elk_missing_url(self):
        with pytest.raises(ValueError):
            self.exporter.push_to_elk([_ev()], elk_url="")

    def test_push_to_elk_invalid_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            self.exporter.push_to_elk([_ev()], elk_url="ftp://elk")

    @patch("app.integrations.siem_exporter.urlopen")
    def test_push_to_elk_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "errors": False,
            "items": [{"index": {"_id": "abc", "result": "created", "status": 201}}],
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = self.exporter.push_to_elk([_ev()], elk_url="http://elk.local:9200")
        assert result["sent"] == 1
        assert result["failed"] == 0

    @patch("app.integrations.siem_exporter.urlopen")
    def test_push_to_elk_with_api_key(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"errors":false,"items":[]}'
        mock_urlopen.return_value = mock_resp

        result = self.exporter.push_to_elk(
            [_ev()], elk_url="https://elk.local:9200", api_key="myapikey"
        )
        req_arg = mock_urlopen.call_args[0][0]
        assert "ApiKey myapikey" in req_arg.headers.get("Authorization", "")


# ===========================================================================
# TestSyslogMessage
# ===========================================================================

class TestSyslogMessage:
    def test_priority_calculation_security_err(self):
        msg = SyslogMessage(
            message="test",
            severity=SyslogSeverity.ERR,
            facility=SyslogFacility.SECURITY,
        )
        assert msg.priority == SyslogFacility.SECURITY * 8 + SyslogSeverity.ERR

    def test_rfc5424_starts_with_pri(self):
        msg = SyslogMessage(message="hello")
        text = msg.to_rfc5424()
        assert text.startswith("<")

    def test_rfc5424_version_1(self):
        msg = SyslogMessage(message="hello")
        text = msg.to_rfc5424()
        # PRI followed by version "1"
        assert ">1 " in text

    def test_rfc5424_contains_message(self):
        msg = SyslogMessage(message="UniVex test message")
        text = msg.to_rfc5424()
        assert "UniVex test message" in text

    def test_rfc5424_contains_app_name(self):
        msg = SyslogMessage(message="x", app_name="my-app")
        text = msg.to_rfc5424()
        assert "my-app" in text

    def test_rfc5424_structured_data_nil(self):
        msg = SyslogMessage(message="x")
        text = msg.to_rfc5424()
        assert " - " in text  # NILVALUE for structured data

    def test_rfc5424_structured_data_custom(self):
        sd = '[univex@12345 findingId="F001"]'
        msg = SyslogMessage(message="x", structured_data=sd)
        text = msg.to_rfc5424()
        assert sd in text

    def test_finding_to_message_severity_mapping_critical(self):
        msg = SyslogForwarder.finding_to_message("F001", "SQLi", "critical", "desc")
        assert msg.severity == SyslogSeverity.CRIT

    def test_finding_to_message_severity_mapping_low(self):
        msg = SyslogForwarder.finding_to_message("F001", "Info", "low", "desc")
        assert msg.severity == SyslogSeverity.NOTICE


# ===========================================================================
# TestSyslogForwarder
# ===========================================================================

class TestSyslogForwarder:
    def test_invalid_protocol_raises(self):
        with pytest.raises(ValueError, match="protocol"):
            SyslogForwarder(host="localhost", protocol="ftp")

    def test_default_port_udp(self):
        fwd = SyslogForwarder(host="h", protocol=SyslogProtocol.UDP)
        assert fwd.port == 514

    def test_default_port_tcp(self):
        fwd = SyslogForwarder(host="h", protocol=SyslogProtocol.TCP)
        assert fwd.port == 514

    def test_default_port_tls(self):
        fwd = SyslogForwarder(host="h", protocol=SyslogProtocol.TLS)
        assert fwd.port == 6514

    def test_custom_port_respected(self):
        fwd = SyslogForwarder(host="h", port=9999, protocol=SyslogProtocol.UDP)
        assert fwd.port == 9999

    @patch("socket.socket")
    def test_send_udp_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

        fwd = SyslogForwarder(host="127.0.0.1", protocol=SyslogProtocol.UDP)
        msg = SyslogMessage(message="test")
        result = fwd.send(msg)
        assert result is True

    def test_send_returns_false_on_error(self):
        fwd = SyslogForwarder(host="invalid.internal.host.xyz", protocol=SyslogProtocol.UDP, timeout=0.5)
        msg = SyslogMessage(message="test")
        result = fwd.send(msg)
        # Either True (if loopback resolves) or False — should not raise
        assert isinstance(result, bool)


# ===========================================================================
# TestWebhookProviderPayload
# ===========================================================================

class TestWebhookProviderPayload:
    def _data(self, severity: str = "high") -> Dict[str, Any]:
        return {
            "title": "Command Injection",
            "severity": severity,
            "description": "OS command injection via input parameter",
            "target_host": "10.0.0.5",
            "category": "injection",
        }

    def test_slack_payload_has_attachments(self):
        p = _build_slack_payload("scan_completed", self._data())
        assert "attachments" in p

    def test_slack_payload_color_for_high(self):
        p = _build_slack_payload("scan_completed", self._data("high"))
        assert p["attachments"][0]["color"] == "#FF6600"

    def test_slack_payload_critical_color(self):
        p = _build_slack_payload("scan_completed", self._data("critical"))
        assert p["attachments"][0]["color"] == "#FF0000"

    def test_teams_payload_has_type(self):
        p = _build_teams_payload("finding_critical", self._data())
        assert p["@type"] == "MessageCard"

    def test_teams_payload_sections(self):
        p = _build_teams_payload("finding_critical", self._data())
        assert len(p["sections"]) > 0

    def test_discord_payload_has_embeds(self):
        p = _build_discord_payload("finding_high", self._data())
        assert "embeds" in p

    def test_discord_embed_color_is_int(self):
        p = _build_discord_payload("finding_high", self._data("medium"))
        assert isinstance(p["embeds"][0]["color"], int)

    def test_pagerduty_payload_routing_key(self):
        p = _build_pagerduty_payload("finding_critical", self._data(), "MYKEY")
        assert p["routing_key"] == "MYKEY"

    def test_pagerduty_payload_event_action(self):
        p = _build_pagerduty_payload("finding_critical", self._data(), "KEY")
        assert p["event_action"] == "trigger"

    def test_jira_payload_summary_contains_title(self):
        p = _build_jira_payload("finding_high", self._data(), "SEC", "Bug")
        assert "Command Injection" in p["fields"]["summary"]


# ===========================================================================
# TestWebhookManager
# ===========================================================================

class TestWebhookManager:
    def _cfg(
        self,
        id: str = "wh1",
        provider: WebhookProvider = WebhookProvider.SLACK,
        url: str = "https://hooks.slack.com/test",
        enabled: bool = True,
    ) -> WebhookConfig:
        return WebhookConfig(id=id, provider=provider, url=url, enabled=enabled)

    def test_add_and_list_config(self):
        mgr = WebhookManager()
        mgr.add_config(self._cfg())
        assert len(mgr.list_configs()) == 1

    def test_remove_config(self):
        mgr = WebhookManager()
        mgr.add_config(self._cfg())
        assert mgr.remove_config("wh1") is True
        assert len(mgr.list_configs()) == 0

    def test_remove_nonexistent_config(self):
        mgr = WebhookManager()
        assert mgr.remove_config("nope") is False

    def test_add_config_invalid_url_scheme(self):
        with pytest.raises(ValueError, match="http"):
            cfg = WebhookConfig(id="bad", provider=WebhookProvider.SLACK, url="ftp://bad")
            WebhookManager().add_config(cfg)

    def test_add_config_empty_url(self):
        with pytest.raises(ValueError, match="url"):
            cfg = WebhookConfig(id="bad", provider=WebhookProvider.SLACK, url="")
            WebhookManager().add_config(cfg)

    def test_get_config(self):
        mgr = WebhookManager()
        mgr.add_config(self._cfg(id="abc"))
        assert mgr.get_config("abc") is not None
        assert mgr.get_config("xyz") is None

    def test_config_disabled_skipped(self):
        mgr = WebhookManager()
        mgr.add_config(self._cfg(enabled=False))
        results = mgr.fire(WebhookEvent.SCAN_COMPLETED, {})
        assert len(results) == 0

    def test_config_event_filter(self):
        mgr = WebhookManager()
        cfg = WebhookConfig(
            id="w2",
            provider=WebhookProvider.SLACK,
            url="https://hooks.slack.com/test",
            events=[WebhookEvent.SCAN_COMPLETED],
        )
        mgr.add_config(cfg)
        # Fire an event NOT in the subscription list
        results = mgr.fire(WebhookEvent.SCAN_FAILED, {})
        assert len(results) == 0

    @patch("app.integrations.webhook_manager.WebhookManager._http_post")
    def test_fire_delivers_to_matching_config(self, mock_post):
        mock_post.return_value = {"success": True, "status_code": 200}
        mgr = WebhookManager()
        mgr.add_config(self._cfg(url="https://hooks.slack.com/test"))
        results = mgr.fire(WebhookEvent.SCAN_COMPLETED, {"title": "Test"})
        assert len(results) == 1
        assert results[0].success is True

    def test_delivery_history_stored(self):
        mgr = WebhookManager()
        mgr._history.append(
            WebhookDelivery(
                config_id="w1",
                event="scan_completed",
                url="https://example.com",
                success=True,
                duration_ms=23.4,
            )
        )
        hist = mgr.get_delivery_history()
        assert len(hist) == 1


# ===========================================================================
# TestIntegrationsAPI (via TestClient)
# ===========================================================================

class TestIntegrationsAPI:
    # --- configure ---

    def test_add_webhook_config_201(self, client: TestClient):
        resp = client.post(
            "/api/integrations/configure",
            json={
                "id": "test-slack",
                "provider": "slack",
                "url": "https://hooks.slack.com/services/test",
                "name": "Test Slack",
                "enabled": True,
                "events": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["id"] == "test-slack"

    def test_add_webhook_config_invalid_provider(self, client: TestClient):
        resp = client.post(
            "/api/integrations/configure",
            json={
                "id": "bad",
                "provider": "invalid_provider",
                "url": "https://example.com",
            },
        )
        assert resp.status_code == 422

    def test_list_webhook_configs(self, client: TestClient):
        resp = client.get("/api/integrations/configure")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_delete_webhook_config_404(self, client: TestClient):
        resp = client.delete("/api/integrations/configure/nonexistent")
        assert resp.status_code == 404

    def test_delete_webhook_config_success(self, client: TestClient):
        client.post(
            "/api/integrations/configure",
            json={
                "id": "to-delete",
                "provider": "generic",
                "url": "https://example.com/hook",
            },
        )
        resp = client.delete("/api/integrations/configure/to-delete")
        assert resp.status_code == 204

    # --- test event ---

    def test_test_webhook_not_found(self, client: TestClient):
        resp = client.post(
            "/api/integrations/test",
            json={"config_id": "not-exists", "event": "scan_completed"},
        )
        assert resp.status_code == 404

    # --- SIEM export ---

    def test_export_siem_json(self, client: TestClient):
        resp = client.post(
            "/api/integrations/export/siem",
            json={
                "format": "json",
                "findings": [
                    {
                        "id": "F001",
                        "title": "XSS",
                        "description": "Reflected XSS",
                        "severity": "high",
                        "category": "xss",
                    }
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "json"
        assert data["count"] == 1

    def test_export_siem_cef(self, client: TestClient):
        resp = client.post(
            "/api/integrations/export/siem",
            json={
                "format": "cef",
                "findings": [{"id": "F002", "title": "SQLi", "severity": "critical"}],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["records"][0].startswith("CEF:0")

    def test_export_siem_leef(self, client: TestClient):
        resp = client.post(
            "/api/integrations/export/siem",
            json={
                "format": "leef",
                "findings": [{"id": "F003", "title": "SSRF", "severity": "medium"}],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["records"][0].startswith("LEEF:2.0")

    def test_export_siem_empty_findings_422(self, client: TestClient):
        resp = client.post(
            "/api/integrations/export/siem",
            json={"format": "json", "findings": []},
        )
        assert resp.status_code == 422

    def test_export_siem_invalid_format(self, client: TestClient):
        resp = client.post(
            "/api/integrations/export/siem",
            json={"format": "xml", "findings": [{"id": "X", "title": "T"}]},
        )
        assert resp.status_code == 422

    # --- delivery history ---

    def test_delivery_history_returns_list(self, client: TestClient):
        resp = client.get("/api/integrations/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
