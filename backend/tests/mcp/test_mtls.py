"""
Tests for mTLS infrastructure: CertManager, MTLSClient, MCPClientmTLS,
and MCPServer mTLS middleware.

Uses the real `cryptography` library for certificate operations, and
mocks httpx for network tests.
"""
from __future__ import annotations

import datetime
import os
import tempfile
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from cryptography.x509.oid import NameOID

from app.mcp.tls.cert_manager import CertConfig, CertManager
from app.mcp.tls.mtls_client import MCPClientmTLS, MTLSClient, MTLSConfig
from app.mcp.base_server import MCPServer, MCPTool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ca(mgr: CertManager, cn: str = "Test CA"):
    config = CertConfig(common_name=cn, validity_days=365, key_size=2048)
    return mgr.generate_ca(config)


def _make_server_cert(mgr, ca_key, ca_cert, name="server.example.com"):
    return mgr.generate_server_cert(name, ca_key, ca_cert)


def _make_client_cert(mgr, ca_key, ca_cert, name="client-1"):
    return mgr.generate_client_cert(name, ca_key, ca_cert)


class _ConcreteServer(MCPServer):
    """Minimal concrete MCPServer for middleware tests."""

    def __init__(self, mtls_enabled=False):
        super().__init__(
            name="test-server",
            description="Test MCP Server",
            port=19999,
            mtls_enabled=mtls_enabled,
        )

    def get_tools(self) -> List[MCPTool]:
        return []

    async def execute_tool(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"executed": name}


# ---------------------------------------------------------------------------
# TestCertManager
# ---------------------------------------------------------------------------


class TestCertManager:
    def test_generate_ca_returns_key_and_cert(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        assert ca_key is not None
        assert ca_cert is not None

    def test_ca_is_self_signed(self):
        mgr = CertManager()
        _, ca_cert = _make_ca(mgr)
        assert ca_cert.subject == ca_cert.issuer

    def test_ca_has_basic_constraints_ca_true(self):
        from cryptography import x509
        mgr = CertManager()
        _, ca_cert = _make_ca(mgr)
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_generate_server_cert_returns_key_and_cert(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        srv_key, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        assert srv_key is not None
        assert srv_cert is not None

    def test_server_cert_issuer_matches_ca(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        assert srv_cert.issuer == ca_cert.subject

    def test_server_cert_not_ca(self):
        from cryptography import x509
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        bc = srv_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_server_cert_has_server_auth_eku(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        eku = srv_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_server_cert_has_san(self):
        from cryptography import x509
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert, name="my.server.local")
        san = srv_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "my.server.local" in dns_names

    def test_generate_client_cert(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        cli_key, cli_cert = _make_client_cert(mgr, ca_key, ca_cert)
        assert cli_key is not None
        assert cli_cert is not None

    def test_client_cert_has_client_auth_eku(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, cli_cert = _make_client_cert(mgr, ca_key, ca_cert)
        eku = cli_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_client_cert_issuer_matches_ca(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, cli_cert = _make_client_cert(mgr, ca_key, ca_cert)
        assert cli_cert.issuer == ca_cert.subject

    def test_check_expiry_positive_for_future_cert(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr, cn="Expiry CA")
        days = mgr.check_expiry(ca_cert)
        assert days > 300  # issued with 365 days validity

    def test_is_expired_returns_false_for_valid(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        assert mgr.is_expired(ca_cert) is False

    def test_check_expiry_negative_for_expired(self):
        """check_expiry returns negative days for a cert that has already expired."""
        import datetime
        mgr = CertManager()
        mock_cert = MagicMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        mock_cert.not_valid_after_utc = past
        days = mgr.check_expiry(mock_cert)
        assert days < 0

    def test_is_expired_returns_true_for_expired(self):
        import datetime
        mgr = CertManager()
        mock_cert = MagicMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        mock_cert.not_valid_after_utc = past
        assert mgr.is_expired(mock_cert) is True

    def test_revoke_cert_adds_to_list(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        serial = ca_cert.serial_number
        mgr.revoke_cert(serial, "key_compromise")
        revoked = mgr.get_revocation_list()
        assert any(r["serial"] == serial for r in revoked)
        assert any(r["reason"] == "key_compromise" for r in revoked)

    def test_revoke_multiple_certs(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        mgr.revoke_cert(ca_cert.serial_number, "superseded")
        mgr.revoke_cert(srv_cert.serial_number, "unspecified")
        assert len(mgr.get_revocation_list()) == 2

    def test_get_revocation_list_empty_initially(self):
        mgr = CertManager()
        assert mgr.get_revocation_list() == []

    def test_rotate_cert_returns_new_cert(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, old_cert = _make_server_cert(mgr, ca_key, ca_cert, name="rotate.example.com")
        new_key, new_cert = mgr.rotate_cert("rotate.example.com", ca_key, ca_cert)
        assert new_cert is not None
        assert new_cert.serial_number != old_cert.serial_number

    def test_rotate_cert_is_valid(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, new_cert = mgr.rotate_cert("srv.example.com", ca_key, ca_cert)
        assert not mgr.is_expired(new_cert)

    def test_verify_cert_valid_chain(self):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        _, srv_cert = _make_server_cert(mgr, ca_key, ca_cert)
        assert mgr.verify_cert(srv_cert, ca_cert) is True

    def test_verify_cert_wrong_ca(self):
        mgr = CertManager()
        ca_key1, ca_cert1 = _make_ca(mgr, cn="CA 1")
        ca_key2, ca_cert2 = _make_ca(mgr, cn="CA 2")
        _, srv_cert = _make_server_cert(mgr, ca_key1, ca_cert1)
        assert mgr.verify_cert(srv_cert, ca_cert2) is False

    def test_save_and_load_cert(self, tmp_path):
        mgr = CertManager()
        ca_key, ca_cert = _make_ca(mgr)
        cert_path = str(tmp_path / "ca.pem")
        mgr.save_cert(ca_cert, cert_path)
        loaded = mgr.load_cert(cert_path)
        assert loaded.serial_number == ca_cert.serial_number

    def test_save_and_load_key(self, tmp_path):
        mgr = CertManager()
        ca_key, _ = _make_ca(mgr)
        key_path = str(tmp_path / "ca.key")
        mgr.save_key(ca_key, key_path)
        loaded_key = mgr.load_key(key_path)
        # Compare public key bytes as a proxy for equality
        from cryptography.hazmat.primitives import serialization
        orig_pub = ca_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded_pub = loaded_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert orig_pub == loaded_pub

    def test_save_key_with_password(self, tmp_path):
        mgr = CertManager()
        ca_key, _ = _make_ca(mgr)
        key_path = str(tmp_path / "enc.key")
        mgr.save_key(ca_key, key_path, password=b"secret")
        loaded = mgr.load_key(key_path, password=b"secret")
        assert loaded is not None

    def test_key_file_permissions(self, tmp_path):
        mgr = CertManager()
        ca_key, _ = _make_ca(mgr)
        key_path = str(tmp_path / "perm.key")
        mgr.save_key(ca_key, key_path)
        mode = oct(os.stat(key_path).st_mode)
        assert mode.endswith("600")

    def test_cert_config_defaults(self):
        config = CertConfig(common_name="test")
        assert config.organization == "UniVex"
        assert config.country == "US"
        assert config.validity_days == 365
        assert config.key_size == 2048

    def test_cert_config_custom_values(self):
        config = CertConfig(
            common_name="custom",
            organization="Acme",
            country="GB",
            validity_days=90,
            key_size=4096,
        )
        assert config.organization == "Acme"
        assert config.country == "GB"
        assert config.validity_days == 90
        assert config.key_size == 4096

    def test_generate_ca_with_custom_config(self):
        mgr = CertManager()
        config = CertConfig(common_name="Custom CA", organization="AcmeCorp", country="DE")
        ca_key, ca_cert = mgr.generate_ca(config)
        cn_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert any(a.value == "Custom CA" for a in cn_attrs)


# ---------------------------------------------------------------------------
# TestMTLSClient
# ---------------------------------------------------------------------------


class TestMTLSClient:
    def test_mtls_config_defaults(self):
        config = MTLSConfig(
            client_cert_path="/c.pem",
            client_key_path="/k.pem",
            ca_cert_path="/ca.pem",
        )
        assert config.verify_server is True
        assert config.timeout == 30.0

    def test_mtls_config_custom(self):
        config = MTLSConfig(
            client_cert_path="/c.pem",
            client_key_path="/k.pem",
            ca_cert_path="/ca.pem",
            verify_server=False,
            timeout=10.0,
        )
        assert config.verify_server is False
        assert config.timeout == 10.0

    def test_http_property_raises_when_not_entered(self):
        config = MTLSConfig("/c", "/k", "/ca")
        client = MTLSClient(config)
        with pytest.raises(RuntimeError, match="not entered"):
            _ = client._http

    @pytest.mark.asyncio
    async def test_context_manager_sets_client(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_http = AsyncMock()
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                assert client._client is not None
            assert client._client is None

    @pytest.mark.asyncio
    async def test_request_delegates_to_httpx(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                resp = await client.request("GET", "https://example.com/health")
            assert resp.status_code == 200
            mock_http.request.assert_called_once_with(
                "GET", "https://example.com/health"
            )

    @pytest.mark.asyncio
    async def test_request_passes_kwargs(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 201

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                resp = await client.request(
                    "POST", "https://example.com/rpc", content=b"data"
                )
            assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_call_tool_returns_result(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"output": "ok"}}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                result = await client.call_tool(
                    "https://srv.example.com", "scan", {"target": "1.2.3.4"}
                )
            assert result == {"output": "ok"}

    @pytest.mark.asyncio
    async def test_call_tool_raises_on_error_response(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": {"code": -32600, "message": "Invalid request"}
        }
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                with pytest.raises(RuntimeError, match="MCP error"):
                    await client.call_tool("https://srv.example.com", "bad_tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_sends_correct_payload(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {}}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        import json as _json

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MTLSClient(config) as client:
                await client.call_tool("https://srv", "my_tool", {"arg": "val"}, request_id="42")
            call_kwargs = mock_http.request.call_args
            content = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content")
            payload = _json.loads(content)
            assert payload["method"] == "tools/call"
            assert payload["params"]["name"] == "my_tool"
            assert payload["params"]["arguments"] == {"arg": "val"}
            assert payload["id"] == "42"

    @pytest.mark.asyncio
    async def test_build_client_with_verify_false(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem", verify_server=False)
        mock_http = AsyncMock()
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http) as mock_cls:
            async with MTLSClient(config) as client:
                pass
            call_kwargs = mock_cls.call_args
            # verify=False should be passed when verify_server is False
            verify = call_kwargs.kwargs.get("verify")
            assert verify is False

    @pytest.mark.asyncio
    async def test_mcp_client_mtls_raises_if_not_entered(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        client = MCPClientmTLS(server_url="https://srv", mtls_config=config)
        with pytest.raises(RuntimeError):
            await client.call_tool("tool", {})

    @pytest.mark.asyncio
    async def test_mcp_client_mtls_context_manager(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_http = AsyncMock()
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MCPClientmTLS(server_url="https://srv", mtls_config=config) as client:
                assert client._mtls_client is not None
            assert client._mtls_client is None

    @pytest.mark.asyncio
    async def test_mcp_client_mtls_call_tool(self):
        config = MTLSConfig("/c.pem", "/k.pem", "/ca.pem")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"data": "value"}}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            async with MCPClientmTLS(server_url="https://srv", mtls_config=config) as client:
                result = await client.call_tool("do_something", {"x": 1})
            assert result == {"data": "value"}


# ---------------------------------------------------------------------------
# TestMTLSBaseServer
# ---------------------------------------------------------------------------


class TestMTLSBaseServer:
    def test_health_exempt_from_mtls(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_missing_cert_header_returns_403(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
        )
        assert resp.status_code == 403

    def test_valid_cert_header_passes(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
            headers={"X-Client-Cert-CN": "trusted-client"},
        )
        assert resp.status_code == 200

    def test_empty_cert_header_returns_403(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
            headers={"X-Client-Cert-CN": "   "},
        )
        assert resp.status_code == 403

    def test_whitespace_only_cert_header_returns_403(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "ping", "id": "x"},
            headers={"X-Client-Cert-CN": "\t"},
        )
        assert resp.status_code == 403

    def test_mtls_disabled_no_cert_still_passes(self):
        server = _ConcreteServer(mtls_enabled=False)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
        )
        # No mTLS middleware — should not get 403
        assert resp.status_code != 403

    def test_403_response_has_error_detail(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "ping", "id": "1"},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert "error" in body
        assert "mTLS" in body["error"] or "certificate" in body["error"].lower()

    def test_health_endpoint_returns_server_name(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("server") == "test-server"

    def test_rpc_with_cert_tools_list(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        resp = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
            headers={"X-Client-Cert-CN": "client-cn"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "result" in data or "error" in data

    def test_server_has_mtls_enabled_attribute(self):
        server = _ConcreteServer(mtls_enabled=True)
        assert server._mtls_enabled is True

    def test_server_mtls_disabled_by_default(self):
        server = _ConcreteServer(mtls_enabled=False)
        assert server._mtls_enabled is False

    def test_multiple_requests_with_cert_all_pass(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        for _ in range(3):
            resp = client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
                headers={"X-Client-Cert-CN": "repeated-client"},
            )
            assert resp.status_code == 200

    def test_different_cn_values_all_accepted(self):
        server = _ConcreteServer(mtls_enabled=True)
        client = TestClient(server.app, raise_server_exceptions=False)
        for cn in ("client-a", "client-b", "service.internal"):
            resp = client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
                headers={"X-Client-Cert-CN": cn},
            )
            assert resp.status_code == 200
