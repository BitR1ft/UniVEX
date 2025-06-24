"""Tests for SessionNode and CredentialNode graph nodes."""

import pytest
from app.graph.nodes import SessionNode, CredentialNode


class TestSessionNode:
    """Tests for SessionNode."""

    def test_create_session_all_params(self, mock_neo4j_client):
        """Test creating a Session node with all parameters."""
        node = SessionNode(mock_neo4j_client)

        result = node.create(
            session_id="session-1",
            session_type="meterpreter",
            target_host="192.168.1.100",
            target_port=4444,
            status="active",
            user_id="user123",
            project_id="proj456",
        )

        assert result["id"] == "session-1"
        assert result["session_type"] == "meterpreter"
        assert result["target_host"] == "192.168.1.100"
        assert result["target_port"] == 4444
        assert result["status"] == "active"
        assert result["user_id"] == "user123"
        assert result["project_id"] == "proj456"
        assert "created_at" in result

        mock_neo4j_client.create_node.assert_called_once()
        call_args = mock_neo4j_client.create_node.call_args
        assert call_args[0][0] == "Session"

    def test_create_session_minimal_params(self, mock_neo4j_client):
        """Test creating a Session node with minimal parameters."""
        node = SessionNode(mock_neo4j_client)

        result = node.create(
            session_id="session-2",
            session_type="shell",
            target_host="10.0.0.5",
        )

        assert result["id"] == "session-2"
        assert result["session_type"] == "shell"
        assert result["target_host"] == "10.0.0.5"
        assert result["status"] == "active"
        assert "target_port" not in result
        assert "created_at" in result

    def test_create_session_default_status(self, mock_neo4j_client):
        """Test that session status defaults to 'active'."""
        node = SessionNode(mock_neo4j_client)

        result = node.create(
            session_id="session-3",
            session_type="meterpreter",
            target_host="10.0.0.6",
        )

        assert result["status"] == "active"

    def test_create_session_custom_status(self, mock_neo4j_client):
        """Test creating a Session node with custom status."""
        node = SessionNode(mock_neo4j_client)

        result = node.create(
            session_id="session-4",
            session_type="shell",
            target_host="10.0.0.7",
            status="closed",
        )

        assert result["status"] == "closed"

    def test_create_session_with_kwargs(self, mock_neo4j_client):
        """Test creating a Session node with extra kwargs."""
        node = SessionNode(mock_neo4j_client)

        result = node.create(
            session_id="session-5",
            session_type="meterpreter",
            target_host="10.0.0.8",
            exploit_module="exploit/unix/ftp/vsftpd_234_backdoor",
        )

        assert result["exploit_module"] == "exploit/unix/ftp/vsftpd_234_backdoor"


class TestCredentialNode:
    """Tests for CredentialNode."""

    def test_create_credential_all_params(self, mock_neo4j_client):
        """Test creating a Credential node with all parameters."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-1",
            username="admin",
            credential_type="password",
            service="ssh",
            target_host="192.168.1.100",
            source="brute_force",
            user_id="user123",
            project_id="proj456",
        )

        assert result["id"] == "cred-1"
        assert result["username"] == "admin"
        assert result["credential_type"] == "password"
        assert result["service"] == "ssh"
        assert result["target_host"] == "192.168.1.100"
        assert result["source"] == "brute_force"
        assert result["user_id"] == "user123"
        assert result["project_id"] == "proj456"
        assert "created_at" in result

        mock_neo4j_client.create_node.assert_called_once()
        call_args = mock_neo4j_client.create_node.call_args
        assert call_args[0][0] == "Credential"

    def test_create_credential_minimal_params(self, mock_neo4j_client):
        """Test creating a Credential node with minimal parameters."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-2",
            username="root",
        )

        assert result["id"] == "cred-2"
        assert result["username"] == "root"
        assert result["credential_type"] == "password"
        assert "service" not in result
        assert "target_host" not in result
        assert "source" not in result
        assert "created_at" in result

    def test_create_credential_default_type(self, mock_neo4j_client):
        """Test that credential_type defaults to 'password'."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-3",
            username="user",
        )

        assert result["credential_type"] == "password"

    def test_create_credential_hash_type(self, mock_neo4j_client):
        """Test creating a Credential node with hash type."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-4",
            username="admin",
            credential_type="hash",
            source="dump",
        )

        assert result["credential_type"] == "hash"
        assert result["source"] == "dump"

    def test_create_credential_token_type(self, mock_neo4j_client):
        """Test creating a Credential node with token type."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-5",
            username="service_account",
            credential_type="token",
            service="api",
        )

        assert result["credential_type"] == "token"
        assert result["service"] == "api"

    def test_create_credential_with_kwargs(self, mock_neo4j_client):
        """Test creating a Credential node with extra kwargs."""
        node = CredentialNode(mock_neo4j_client)

        result = node.create(
            credential_id="cred-6",
            username="admin",
            hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        )

        assert result["hash_value"] == "5f4dcc3b5aa765d61d8327deb882cf99"
