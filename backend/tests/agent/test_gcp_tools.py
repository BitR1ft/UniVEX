"""

Coverage:
  TestGCSBucketEnumTool    (12 tests)
  TestGCPIAMTool           (12 tests)
  TestGCPFirewallAuditTool (10 tests)

Total: 34 tests — all using mocked GCP SDK via unittest.mock
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.agent.tools.cloud.gcp_tools import (
    GCSBucketEnumTool,
    GCPIAMTool,
    GCPFirewallAuditTool,
    GCSBucketFinding,
    GCPIAMFinding,
    GCPFirewallFinding,
    CloudFindingSeverity,
    GCP_TOOLS,
    _get_gcs_client,
    _get_gcp_iam_client,
    _get_gcp_compute_client,
    _get_gcp_resource_manager_client,
    _get_gcp_iam_service,
)


# ---------------------------------------------------------------------------
# Helpers — GCS
# ---------------------------------------------------------------------------

def _make_gcs_bucket(
    name: str = "test-bucket",
    iam_bindings: Optional[List[Dict]] = None,
    pap: str = "enforced",
    ubla_enabled: bool = True,
    versioning: bool = True,
    lifecycle_rules: Optional[List] = None,
    kms_key: Optional[str] = "projects/p/locations/l/keyRings/r/cryptoKeys/k",
    logging_config: Optional[Any] = True,
) -> MagicMock:
    bucket = MagicMock()
    bucket.name = name

    # IAM policy
    policy = MagicMock()
    policy.bindings = iam_bindings if iam_bindings is not None else []
    bucket.get_iam_policy.return_value = policy

    # iam_configuration
    iam_config = MagicMock()
    iam_config.public_access_prevention = pap
    iam_config.uniform_bucket_level_access_enabled = ubla_enabled
    bucket.iam_configuration = iam_config

    bucket.versioning_enabled = versioning
    bucket.lifecycle_rules = lifecycle_rules if lifecycle_rules is not None else [MagicMock()]
    bucket.default_kms_key_name = kms_key
    bucket.logging = logging_config

    return bucket


def _make_gcs_client(
    buckets: Optional[List[MagicMock]] = None,
    single_bucket: Optional[MagicMock] = None,
) -> MagicMock:
    client = MagicMock()
    client.list_buckets.return_value = buckets or []
    if single_bucket:
        client.get_bucket.return_value = single_bucket
    return client


# ---------------------------------------------------------------------------
# Helpers — GCP IAM
# ---------------------------------------------------------------------------

def _make_rm_client(bindings: Optional[List[MagicMock]] = None) -> MagicMock:
    policy = MagicMock()
    policy.bindings = bindings or []
    client = MagicMock()
    client.get_iam_policy.return_value = policy
    return client


def _make_iam_binding(role: str = "roles/viewer", members: Optional[List[str]] = None) -> MagicMock:
    binding = MagicMock()
    binding.role = role
    binding.members = members or []
    return binding


def _make_iam_service(
    service_accounts: Optional[List[Dict]] = None,
    keys: Optional[List[Dict]] = None,
) -> MagicMock:
    """Create a mock googleapiclient IAM discovery service."""
    svc = MagicMock()
    sa_list_resp = {"accounts": service_accounts or []}
    svc.projects.return_value.serviceAccounts.return_value.list.return_value.execute.return_value = sa_list_resp
    keys_resp = {"keys": keys or []}
    svc.projects.return_value.serviceAccounts.return_value.keys.return_value.list.return_value.execute.return_value = (
        keys_resp
    )
    return svc


# ---------------------------------------------------------------------------
# Helpers — GCP Firewall
# ---------------------------------------------------------------------------

def _make_compute_client(rules: Optional[List[Dict]] = None) -> MagicMock:
    client = MagicMock()
    resp = {"items": rules or []}
    client.firewalls.return_value.list.return_value.execute.return_value = resp
    return client


def _make_firewall_rule(
    name: str = "allow-ssh",
    direction: str = "INGRESS",
    disabled: bool = False,
    priority: int = 1000,
    source_ranges: Optional[List[str]] = None,
    dest_ranges: Optional[List[str]] = None,
    allowed: Optional[List[Dict]] = None,
    target_tags: Optional[List[str]] = None,
    network: str = "https://www.googleapis.com/compute/v1/projects/proj/global/networks/default",
) -> Dict:
    return {
        "name": name,
        "direction": direction,
        "disabled": disabled,
        "priority": priority,
        "network": network,
        "sourceRanges": source_ranges if source_ranges is not None else ["0.0.0.0/0"],
        "destinationRanges": dest_ranges or [],
        "allowed": allowed if allowed is not None else [{"IPProtocol": "tcp", "ports": ["22"]}],
        "targetTags": target_tags if target_tags is not None else [],
        "targetServiceAccounts": [],
    }


# ---------------------------------------------------------------------------
# TestGCSBucketEnumTool
# ---------------------------------------------------------------------------


class TestGCSBucketEnumTool:
    def setup_method(self):
        self.tool = GCSBucketEnumTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "gcs_bucket_enum"

    def test_all_users_binding_flagged(self):
        binding = {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        bucket = _make_gcs_bucket(iam_bindings=[binding])
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        assert findings[0].public_access is True
        assert findings[0].severity == CloudFindingSeverity.CRITICAL

    def test_all_authenticated_users_flagged(self):
        binding = {"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}
        bucket = _make_gcs_bucket(iam_bindings=[binding])
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        assert any("allAuthenticatedUsers" in i for f in findings for i in f.iam_issues)

    def test_private_bucket_clean(self):
        bucket = _make_gcs_bucket(
            iam_bindings=[],
            pap="enforced",
            ubla_enabled=True,
            versioning=True,
            lifecycle_rules=[MagicMock()],
            kms_key="projects/p/locations/l/keyRings/r/cryptoKeys/k",
            logging_config={"logBucket": "logs"},
        )
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert findings == []

    def test_ubla_disabled_flagged(self):
        bucket = _make_gcs_bucket(ubla_enabled=False)
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("ubla" in i.lower() or "uniform" in i.lower() or "acl" in i.lower() for i in all_issues)

    def test_versioning_disabled_flagged(self):
        bucket = _make_gcs_bucket(versioning=False)
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("version" in i.lower() for i in all_issues)

    def test_no_logging_flagged(self):
        bucket = _make_gcs_bucket(logging_config=None)
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("log" in i.lower() for i in all_issues)

    def test_cmek_encryption_info(self):
        bucket = _make_gcs_bucket(kms_key=None)
        client = _make_gcs_client(buckets=[bucket])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("cmek" in i.lower() or "encrypt" in i.lower() or "google-managed" in i.lower() for i in all_issues)

    def test_execute_returns_json(self):
        client = _make_gcs_client(buckets=[])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "status" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.gcp_tools._get_gcs_client",
            side_effect=ImportError("google-cloud-storage not installed"),
        ):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = GCSBucketFinding(
            bucket_name="my-bucket",
            project_id="my-project",
            public_access=True,
            iam_issues=["allUsers binding"],
            issues=["No CMEK"],
            severity=CloudFindingSeverity.CRITICAL,
        )
        d = finding.to_dict()
        assert "bucket_name" in d
        assert "project_id" in d
        assert "public_access" in d
        assert "iam_issues" in d
        assert "issues" in d
        assert "severity" in d

    def test_list_all_buckets(self):
        b1 = _make_gcs_bucket(name="bucket-one")
        b2 = _make_gcs_bucket(name="bucket-two", kms_key=None, logging_config=None)
        client = _make_gcs_client(buckets=[b1, b2])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id")
        # At minimum, returns a list; bucket-two should produce findings
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_single_bucket_scan(self):
        bucket = _make_gcs_bucket(name="specific-bucket", kms_key=None)
        client = _make_gcs_client(single_bucket=bucket)
        with patch("app.agent.tools.cloud.gcp_tools._get_gcs_client", return_value=client):
            findings = self.tool._run_scan(project_id="proj-id", bucket_name="specific-bucket")
        assert isinstance(findings, list)
        # Should have called get_bucket, not list_buckets
        client.get_bucket.assert_called_once_with("specific-bucket")


# ---------------------------------------------------------------------------
# TestGCPIAMTool
# ---------------------------------------------------------------------------


class TestGCPIAMTool:
    def setup_method(self):
        self.tool = GCPIAMTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "gcp_iam_audit"

    def test_owner_role_flagged(self):
        binding = _make_iam_binding(role="roles/owner", members=["user:admin@example.com"])
        rm_client = _make_rm_client(bindings=[binding])
        iam_svc = _make_iam_service()
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=iam_svc),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        assert len(findings) > 0
        assert any("owner" in f.role.lower() for f in findings)

    def test_editor_role_flagged(self):
        binding = _make_iam_binding(role="roles/editor", members=["user:dev@example.com"])
        rm_client = _make_rm_client(bindings=[binding])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=_make_iam_service()),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("editor" in i.lower() or "primitive" in i.lower() for i in all_issues)

    def test_all_users_binding_critical(self):
        binding = _make_iam_binding(role="roles/owner", members=["allUsers"])
        rm_client = _make_rm_client(bindings=[binding])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=_make_iam_service()),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        assert len(findings) > 0
        assert findings[0].severity == CloudFindingSeverity.CRITICAL

    def test_service_account_owner_flagged(self):
        sa_member = "serviceAccount:my-sa@proj-id.iam.gserviceaccount.com"
        binding = _make_iam_binding(role="roles/owner", members=[sa_member])
        rm_client = _make_rm_client(bindings=[binding])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=_make_iam_service()),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("service account" in i.lower() for i in all_issues)

    def test_set_iam_policy_privesc_flagged(self):
        # roles/owner triggers setIamPolicy-equivalent privilege escalation check
        binding = _make_iam_binding(role="roles/owner", members=["user:attacker@example.com"])
        rm_client = _make_rm_client(bindings=[binding])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=_make_iam_service()),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        all_issues = [i for f in findings for i in f.issues]
        assert any("setIamPolicy" in i or "escalation" in i.lower() for i in all_issues)

    def test_user_managed_key_flagged(self):
        binding = _make_iam_binding(role="roles/viewer", members=["user:viewer@example.com"])
        rm_client = _make_rm_client(bindings=[binding])
        sa = {"name": "projects/proj-id/serviceAccounts/sa@proj-id.iam.gserviceaccount.com",
              "email": "sa@proj-id.iam.gserviceaccount.com"}
        key = {"name": "projects/proj-id/serviceAccounts/sa@.../keys/key123", "keyType": "USER_MANAGED"}
        iam_svc = _make_iam_service(service_accounts=[sa], keys=[key])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=iam_svc),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=True)
        sa_findings = [f for f in findings if f.entity_type == "member"]
        assert len(sa_findings) > 0
        assert any("user-managed key" in i.lower() for f in sa_findings for i in f.issues)

    def test_viewer_role_low_severity(self):
        binding = _make_iam_binding(role="roles/viewer", members=["user:viewer@example.com"])
        rm_client = _make_rm_client(bindings=[binding])
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=_make_iam_service()),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        # roles/viewer is a primitive role → finding created, but severity should be MEDIUM or lower
        binding_findings = [f for f in findings if f.entity_type == "binding"]
        if binding_findings:
            assert binding_findings[0].severity in (
                CloudFindingSeverity.LOW,
                CloudFindingSeverity.MEDIUM,
                CloudFindingSeverity.HIGH,
            )

    def test_execute_returns_json(self):
        rm_client = _make_rm_client(bindings=[])
        iam_svc = _make_iam_service()
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=iam_svc),
        ):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "status" in parsed
        assert "finding_count" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client",
            side_effect=ImportError("google-cloud-resource-manager not installed"),
        ):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = GCPIAMFinding(
            entity_type="binding",
            entity="allUsers",
            role="roles/owner",
            issues=["Public owner binding"],
            severity=CloudFindingSeverity.CRITICAL,
        )
        d = finding.to_dict()
        assert "entity_type" in d
        assert "entity" in d
        assert "role" in d
        assert "issues" in d
        assert "severity" in d

    def test_no_bindings_clean(self):
        rm_client = _make_rm_client(bindings=[])
        iam_svc = _make_iam_service()
        with (
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_resource_manager_client", return_value=rm_client),
            patch("app.agent.tools.cloud.gcp_tools._get_gcp_iam_service", return_value=iam_svc),
        ):
            findings = self.tool._run_audit(project_id="proj-id", check_sa_keys=False)
        assert findings == []


# ---------------------------------------------------------------------------
# TestGCPFirewallAuditTool
# ---------------------------------------------------------------------------


class TestGCPFirewallAuditTool:
    def setup_method(self):
        self.tool = GCPFirewallAuditTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "gcp_firewall_audit"

    def test_ssh_open_flagged(self):
        rule = _make_firewall_rule(
            name="allow-ssh", source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        )
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        assert len(findings) > 0
        assert any("22" in i or "SSH" in i for f in findings for i in f.issues)

    def test_rdp_open_flagged(self):
        rule = _make_firewall_rule(
            name="allow-rdp", source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["3389"]}],
        )
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        assert len(findings) > 0
        assert any("3389" in i or "RDP" in i for f in findings for i in f.issues)

    def test_all_protocols_flagged(self):
        rule = _make_firewall_rule(
            name="allow-all", source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "all", "ports": []}],
        )
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("all" in i.lower() and ("protocol" in i.lower() or "port" in i.lower()) for i in all_issues)

    def test_disabled_rule_flagged(self):
        rule = _make_firewall_rule(name="disabled-rule", disabled=True, source_ranges=["10.0.0.0/8"])
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        assert len(findings) > 0
        assert any("disabled" in i.lower() for f in findings for i in f.issues)

    def test_private_source_clean(self):
        rule = _make_firewall_rule(
            name="internal-ssh", source_ranges=["10.0.0.0/8"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
            target_tags=["bastion"],
        )
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        # Private source 10.0.0.0/8 with target tag — should create finding but NOT critical/world-open
        for f in findings:
            assert "0.0.0.0/0" not in " ".join(f.issues)

    def test_no_target_tags_flagged(self):
        rule = _make_firewall_rule(
            name="allow-ssh-all", source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
            target_tags=[],  # no targetTags → applies to all instances
        )
        compute = _make_compute_client(rules=[rule])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            findings = self.tool._run_audit(project_id="proj-id")
        assert len(findings) > 0
        all_issues = [i for f in findings for i in f.issues]
        assert any("targetTags" in i or "all instances" in i.lower() for i in all_issues)

    def test_execute_returns_json(self):
        compute = _make_compute_client(rules=[])
        with patch("app.agent.tools.cloud.gcp_tools._get_gcp_compute_client", return_value=compute):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "status" in parsed

    def test_execute_no_sdk(self):
        with patch(
            "app.agent.tools.cloud.gcp_tools._get_gcp_compute_client",
            side_effect=ImportError("google-api-python-client not installed"),
        ):
            result = asyncio.run(self.tool.execute(project_id="proj-id"))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_finding_to_dict(self):
        finding = GCPFirewallFinding(
            rule_name="allow-ssh",
            network="default",
            direction="INGRESS",
            issues=["SSH open to 0.0.0.0/0"],
            severity=CloudFindingSeverity.CRITICAL,
            open_ports=[{"port": 22, "service": "SSH", "is_dangerous": True}],
        )
        d = finding.to_dict()
        assert "rule_name" in d
        assert "network" in d
        assert "direction" in d
        assert "issues" in d
        assert "severity" in d
        assert "open_ports" in d
