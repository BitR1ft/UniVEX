"""

Coverage:
  TestAzureBlobEnumTool  (10 tests)
  TestAzureADTool        (10 tests)
  TestAzureNSGAuditTool  (10 tests)
  TestCloudSummaryTool    (5 tests)

Total: 35 tests — all using mocked Azure SDK via unittest.mock
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.agent.tools.cloud.azure_tools import (
    AzureBlobEnumTool,
    AzureADTool,
    AzureNSGAuditTool,
    CloudSummaryTool,
    AzureBlobFinding,
    AzureADFinding,
    AzureNSGFinding,
    CloudFindingSeverity,
    AZURE_TOOLS,
    _get_azure_client,
    _get_msgraph_client,
    _get_azure_network_client,
)


# ---------------------------------------------------------------------------
# Helpers — Azure Storage
# ---------------------------------------------------------------------------

_RG_ID_TEMPLATE = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/{rg}"
    "/providers/Microsoft.Storage/storageAccounts/{name}"
)


def _make_account(
    name: str = "teststorage",
    https_only: bool = True,
    tls_version: str = "TLS1_2",
    network_rule_action: Optional[str] = "Deny",
    allow_public: bool = False,
    resource_group: str = "test-rg",
) -> MagicMock:
    account = MagicMock()
    account.name = name
    account.id = _RG_ID_TEMPLATE.format(rg=resource_group, name=name)
    account.enable_https_traffic_only = https_only
    account.minimum_tls_version = tls_version
    account.allow_blob_public_access = allow_public

    if network_rule_action is not None:
        nrs = MagicMock()
        nrs.default_action = network_rule_action
        account.network_rule_set = nrs
    else:
        account.network_rule_set = None

    return account


def _make_container(name: str = "mycontainer", public_access: Optional[str] = None) -> MagicMock:
    container = MagicMock()
    container.name = name
    container.public_access = public_access
    return container


def _make_storage_client(
    accounts: Optional[List[MagicMock]] = None,
    containers: Optional[List[MagicMock]] = None,
) -> MagicMock:
    client = MagicMock()
    client.storage_accounts.list.return_value = accounts or []
    client.blob_containers.list.return_value = containers or []
    return client


# ---------------------------------------------------------------------------
# Helpers — Azure AD / Graph
# ---------------------------------------------------------------------------

def _make_graph_client(
    users: Optional[List[MagicMock]] = None,
    groups: Optional[List[MagicMock]] = None,
    sps: Optional[List[MagicMock]] = None,
    auth_methods: Optional[List[MagicMock]] = None,
    group_members: Optional[List[MagicMock]] = None,
) -> MagicMock:
    client = MagicMock()

    users_resp = MagicMock()
    users_resp.value = users or []
    client.users.get.return_value = users_resp

    groups_resp = MagicMock()
    groups_resp.value = groups or []
    client.groups.get.return_value = groups_resp

    sps_resp = MagicMock()
    sps_resp.value = sps or []
    client.service_principals.get.return_value = sps_resp

    auth_resp = MagicMock()
    auth_resp.value = auth_methods or []
    client.users.by_user_id.return_value.authentication.methods.get.return_value = auth_resp

    members_resp = MagicMock()
    members_resp.value = group_members or []
    client.groups.by_group_id.return_value.members.get.return_value = members_resp

    return client


def _make_user(
    display_name: str = "Test User",
    user_type: str = "Member",
    account_enabled: bool = True,
    on_prem_sync: bool = False,
) -> MagicMock:
    user = MagicMock()
    user.display_name = display_name
    user.user_principal_name = f"{display_name.replace(' ', '')}@example.com"
    user.user_type = user_type
    user.account_enabled = account_enabled
    user.on_premises_sync_enabled = on_prem_sync
    user.id = "user-id-1"
    return user


def _make_sp(
    display_name: str = "My App",
    expire_days: Optional[int] = None,
    no_expiry: bool = False,
    app_roles: Optional[List[MagicMock]] = None,
) -> MagicMock:
    sp = MagicMock()
    sp.display_name = display_name
    sp.app_roles = app_roles or []

    if no_expiry:
        cred = MagicMock()
        cred.end_date_time = None
        sp.password_credentials = [cred]
    elif expire_days is not None:
        cred = MagicMock()
        cred.end_date_time = datetime.now(tz=timezone.utc) + timedelta(days=expire_days)
        sp.password_credentials = [cred]
    else:
        sp.password_credentials = []

    return sp


# ---------------------------------------------------------------------------
# Helpers — NSG
# ---------------------------------------------------------------------------

def _make_nsg_client(nsgs: Optional[List[MagicMock]] = None) -> MagicMock:
    client = MagicMock()
    client.network_security_groups.list_all.return_value = nsgs or []
    client.network_security_groups.list.return_value = nsgs or []
    return client


def _make_nsg(
    name: str = "test-nsg",
    rules: Optional[List[MagicMock]] = None,
    resource_group: str = "test-rg",
) -> MagicMock:
    nsg = MagicMock()
    nsg.name = name
    nsg.id = (
        f"/subscriptions/00000000/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
    )
    nsg.security_rules = rules or []
    nsg.default_security_rules = []
    return nsg


def _make_nsg_rule(
    name: str = "test-rule",
    direction: str = "Inbound",
    access: str = "Allow",
    priority: int = 100,
    source_prefix: str = "0.0.0.0/0",
    dest_port: str = "22",
    description: str = "Test rule",
) -> MagicMock:
    rule = MagicMock()
    rule.name = name
    rule.direction = direction
    rule.access = access
    rule.priority = priority
    rule.protocol = "Tcp"
    rule.source_address_prefix = source_prefix
    rule.destination_address_prefix = "*"
    rule.destination_port_range = dest_port
    rule.destination_port_ranges = []
    rule.description = description
    return rule


# ---------------------------------------------------------------------------
# TestAzureBlobEnumTool
# ---------------------------------------------------------------------------


class TestAzureBlobEnumTool:
    def setup_method(self):
        self.tool = AzureBlobEnumTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "azure_blob_enum"

    def test_public_container_access_flagged(self):
        account = _make_account(allow_public=True)
        container = _make_container(public_access="container")
        client = _make_storage_client(accounts=[account], containers=[container])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("container" in i.lower() for i in all_issues)

    def test_blob_access_flagged(self):
        account = _make_account(allow_public=True)
        container = _make_container(public_access="blob")
        client = _make_storage_client(accounts=[account], containers=[container])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("blob" in i.lower() for i in all_issues)

    def test_private_container_clean(self):
        # Completely clean account + private container → no findings
        account = _make_account(https_only=True, tls_version="TLS1_2", network_rule_action="Deny", allow_public=False)
        container = _make_container(public_access=None)
        client = _make_storage_client(accounts=[account], containers=[container])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        assert findings == []

    def test_https_only_disabled_flagged(self):
        account = _make_account(https_only=False)
        client = _make_storage_client(accounts=[account], containers=[])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        all_issues = [i for f in findings for i in f.issues]
        assert any("https" in i.lower() or "http" in i.lower() for i in all_issues)

    def test_old_tls_flagged(self):
        account = _make_account(tls_version="TLS1_0")
        client = _make_storage_client(accounts=[account], containers=[])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        all_issues = [i for f in findings for i in f.issues]
        assert any("TLS1_0" in i or "tls" in i.lower() for i in all_issues)

    def test_no_firewall_flagged(self):
        account = _make_account(network_rule_action=None)  # no network rule set
        client = _make_storage_client(accounts=[account], containers=[])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            findings = self.tool._run_scan(subscription_id="sub-id")
        all_issues = [i for f in findings for i in f.issues]
        assert any("network" in i.lower() or "firewall" in i.lower() for i in all_issues)

    def test_execute_returns_json(self):
        account = _make_account()
        client = _make_storage_client(accounts=[account], containers=[])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_client", return_value=client):
            result = asyncio.run(self.tool.execute(subscription_id="sub-id"))
        parsed = json.loads(result)
        assert "status" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.azure_tools._get_azure_client",
            side_effect=ImportError("azure-mgmt-storage not installed"),
        ):
            result = asyncio.run(self.tool.execute(subscription_id="sub-id"))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = AzureBlobFinding(
            account_name="myaccount",
            container_name="mycontainer",
            access_level="container",
            public_access_enabled=True,
            https_only=False,
            tls_version="TLS1_0",
            issues=["Public access enabled"],
            severity=CloudFindingSeverity.CRITICAL,
        )
        d = finding.to_dict()
        assert d["account_name"] == "myaccount"
        assert d["container_name"] == "mycontainer"
        assert "issues" in d
        assert "severity" in d
        assert "access_level" in d
        assert "public_access_enabled" in d


# ---------------------------------------------------------------------------
# TestAzureADTool
# ---------------------------------------------------------------------------


class TestAzureADTool:
    def setup_method(self):
        self.tool = AzureADTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "azure_ad_enum"

    def test_guest_user_flagged(self):
        user = _make_user(display_name="Guest Bob", user_type="Guest")
        client = _make_graph_client(users=[user])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            findings = self.tool._run_audit(entity_type="users")
        assert len(findings) > 0
        assert any("guest" in i.lower() for f in findings for i in f.issues)

    def test_expired_secret_flagged(self):
        sp = _make_sp(display_name="ExpiredApp", expire_days=-5)
        client = _make_graph_client(sps=[sp])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            findings = self.tool._run_audit(entity_type="service_principals")
        assert len(findings) > 0
        assert any("expired" in i.lower() for f in findings for i in f.issues)

    def test_no_secret_expiry_flagged(self):
        sp = _make_sp(display_name="NoExpiryApp", no_expiry=True)
        client = _make_graph_client(sps=[sp])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            findings = self.tool._run_audit(entity_type="service_principals")
        assert len(findings) > 0
        assert any("no expiration" in i.lower() or "expir" in i.lower() for f in findings for i in f.issues)

    def test_role_assignable_group_with_guest_flagged(self):
        group = MagicMock()
        group.display_name = "PrivGroup"
        group.group_types = []
        group.is_assignable_to_role = True
        group.mail_enabled = False
        group.security_enabled = True
        group.id = "group-id-1"

        guest_member = MagicMock()
        guest_member.display_name = "Guest Member"
        guest_member.user_type = "Guest"

        client = _make_graph_client(groups=[group], group_members=[guest_member])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            findings = self.tool._run_audit(entity_type="groups")
        assert len(findings) > 0
        assert any("guest" in i.lower() for f in findings for i in f.issues)

    def test_clean_user_no_issue(self):
        user = _make_user(display_name="Normal Alice", user_type="Member")
        client = _make_graph_client(users=[user], auth_methods=[])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            findings = self.tool._run_audit(entity_type="users")
        # Member user with no auth methods returned → no issues flagged (auth_methods empty → skipped)
        assert findings == []

    def test_execute_returns_json(self):
        client = _make_graph_client()
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            result = asyncio.run(self.tool.execute(entity_type="users"))
        parsed = json.loads(result)
        assert "status" in parsed
        assert "finding_count" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.azure_tools._get_msgraph_client",
            side_effect=ImportError("msgraph not installed"),
        ):
            result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = AzureADFinding(
            entity_type="user",
            entity_name="bob@example.com",
            issues=["Guest account"],
            severity=CloudFindingSeverity.MEDIUM,
        )
        d = finding.to_dict()
        assert "entity_type" in d
        assert "entity_name" in d
        assert "issues" in d
        assert "severity" in d

    def test_summary_counts(self):
        # Multiple SPs with issues → finding_count > 1 in JSON output
        sp1 = _make_sp(display_name="App1", no_expiry=True)
        sp2 = _make_sp(display_name="App2", expire_days=-1)
        client = _make_graph_client(sps=[sp1, sp2])
        with patch("app.agent.tools.cloud.azure_tools._get_msgraph_client", return_value=client):
            result = asyncio.run(self.tool.execute(entity_type="service_principals"))
        parsed = json.loads(result)
        assert "finding_count" in parsed
        assert parsed["finding_count"] >= 2


# ---------------------------------------------------------------------------
# TestAzureNSGAuditTool
# ---------------------------------------------------------------------------


class TestAzureNSGAuditTool:
    def setup_method(self):
        self.tool = AzureNSGAuditTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "azure_nsg_audit"

    def test_ssh_open_to_world_flagged(self):
        rule = _make_nsg_rule(dest_port="22", source_prefix="0.0.0.0/0")
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        assert len(findings) > 0
        assert any("SSH" in i or "22" in i for f in findings for i in f.issues)

    def test_rdp_open_to_world_flagged(self):
        rule = _make_nsg_rule(name="allow-rdp", dest_port="3389", source_prefix="0.0.0.0/0")
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        assert len(findings) > 0
        assert any("RDP" in i or "3389" in i for f in findings for i in f.issues)

    def test_any_port_rule_flagged(self):
        rule = _make_nsg_rule(name="allow-all", dest_port="*", source_prefix="0.0.0.0/0")
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        assert len(findings) > 0
        assert any("any" in i.lower() or "*" in i for f in findings for i in f.issues)

    def test_private_source_clean(self):
        rule = _make_nsg_rule(source_prefix="10.0.0.0/8", dest_port="22", description="Internal only")
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        # Private source should not be flagged for port-exposure
        assert all("SSH" not in i and "22" not in i for f in findings for i in f.issues)

    def test_deny_rule_not_flagged(self):
        rule = _make_nsg_rule(access="Deny", source_prefix="0.0.0.0/0", dest_port="22")
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        # Deny rules must never be flagged for port exposure
        assert findings == []

    def test_execute_returns_json(self):
        client = _make_nsg_client(nsgs=[])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            result = asyncio.run(self.tool.execute(subscription_id="sub-id"))
        parsed = json.loads(result)
        assert "status" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.azure_tools._get_azure_network_client",
            side_effect=ImportError("azure-mgmt-network not installed"),
        ):
            result = asyncio.run(self.tool.execute(subscription_id="sub-id"))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = AzureNSGFinding(
            nsg_name="my-nsg",
            resource_group="my-rg",
            issues=["SSH open"],
            severity=CloudFindingSeverity.CRITICAL,
            open_ports=[{"rule": "allow-ssh", "port": 22}],
        )
        d = finding.to_dict()
        assert "nsg_name" in d
        assert "resource_group" in d
        assert "issues" in d
        assert "severity" in d
        assert "open_ports" in d

    def test_high_priority_no_description_flagged(self):
        # Allow rule with priority < 1000 and empty description → flagged for missing description
        rule = _make_nsg_rule(
            name="mystery-rule",
            direction="Inbound",
            access="Allow",
            priority=150,
            source_prefix="10.0.0.0/8",  # private source, no port exposure
            dest_port="443",
            description="",             # no description
        )
        nsg = _make_nsg(rules=[rule])
        client = _make_nsg_client(nsgs=[nsg])
        with patch("app.agent.tools.cloud.azure_tools._get_azure_network_client", return_value=client):
            findings = self.tool._run_audit(subscription_id="sub-id")
        assert len(findings) > 0
        assert any("description" in i.lower() for f in findings for i in f.issues)


# ---------------------------------------------------------------------------
# TestCloudSummaryTool
# ---------------------------------------------------------------------------


class TestCloudSummaryTool:
    def setup_method(self):
        self.tool = CloudSummaryTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "cloud_summary"

    def test_empty_findings_clean(self):
        # No findings passed at all → "no_data" status
        result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert parsed["status"] == "no_data"

    def test_critical_finding_high_score(self):
        critical_findings = [
            {"severity": "critical", "bucket_name": "leaked-bucket", "issues": ["Public access enabled"]},
            {"severity": "critical", "bucket_name": "another-bucket", "issues": ["No encryption"]},
            {"severity": "critical", "bucket_name": "third-bucket", "issues": ["No logging"]},
            {"severity": "critical", "bucket_name": "fourth-bucket", "issues": ["Old TLS"]},
            {"severity": "critical", "bucket_name": "fifth-bucket", "issues": ["HTTP allowed"]},
            {"severity": "critical", "bucket_name": "sixth-bucket", "issues": ["No versioning"]},
        ]
        result = asyncio.run(self.tool.execute(aws_findings=critical_findings))
        parsed = json.loads(result)
        risk_level = parsed["provider_summaries"]["aws"]["risk_level"]
        assert risk_level in ("HIGH", "CRITICAL")

    def test_multi_provider_summary(self):
        aws = [{"severity": "high", "bucket_name": "s3-bucket", "issues": ["No logging"]}]
        azure = [{"severity": "medium", "account_name": "storage-acct", "issues": ["TLS 1.0"]}]
        gcp = [{"severity": "critical", "bucket_name": "gcs-bucket", "issues": ["Public access"]}]
        result = asyncio.run(self.tool.execute(aws_findings=aws, azure_findings=azure, gcp_findings=gcp))
        parsed = json.loads(result)
        assert "aws" in parsed["providers_scanned"]
        assert "azure" in parsed["providers_scanned"]
        assert "gcp" in parsed["providers_scanned"]

    def test_execute_json_structure(self):
        findings = [{"severity": "high", "entity_name": "bad-user", "issues": ["No MFA"]}]
        result = asyncio.run(self.tool.execute(azure_findings=findings))
        parsed = json.loads(result)
        assert "status" in parsed
        assert "providers_scanned" in parsed
        assert "provider_summaries" in parsed
        assert "azure" in parsed["provider_summaries"]
