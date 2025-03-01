"""

Three agent tools for GCP security assessments:

  GCSBucketEnumTool    — Discover public / misconfigured GCS buckets
  GCPIAMTool           — Analyze GCP IAM bindings for privilege escalation paths
  GCPFirewallAuditTool — Check VPC firewall rules for dangerous misconfigurations

All tools are fully mockable for testing — GCP SDK calls are abstracted behind
`_get_gcs_client()`, `_get_gcp_iam_client()`, `_get_gcp_resource_manager_client()`,
`_get_gcp_iam_service()`, and `_get_gcp_compute_client()` helpers that tests can patch.

Tools are registered in `GCP_TOOLS` and may be added to the tool registry under
the CLOUD_SECURITY attack category alongside the AWS and Azure tools.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity classification (mirrors aws_tools.CloudFindingSeverity)
# ---------------------------------------------------------------------------


class CloudFindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Dangerous ports checked by firewall auditor
# ---------------------------------------------------------------------------

_DANGEROUS_PORTS: Dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# IAM primitive roles that grant broad access
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}

# Members that represent public/anonymous access
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}

# Maximum port range size to expand inline (larger ranges are sampled)
_MAX_PORT_RANGE_EXPANSION = 100

# Permissions that can be chained for privilege escalation
_PRIVESC_PERMISSIONS = {
    "iam.roles.update",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccountKeys.create",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "deploymentmanager.deployments.create",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "run.services.create",
    "compute.instances.create",
    "storage.hmacKeys.create",
}

# ---------------------------------------------------------------------------
# Mockable GCP SDK client helpers
# ---------------------------------------------------------------------------


def _get_gcs_client(**kwargs):
    """Return a google.cloud.storage Client; raises ImportError if SDK missing."""
    from google.cloud import storage  # type: ignore[import]

    return storage.Client(**kwargs)


def _get_gcp_iam_client(**kwargs):
    """Return a google.cloud.iam_admin_v1 IAMClient; raises ImportError if SDK missing."""
    from google.cloud import iam_admin_v1  # type: ignore[import]

    return iam_admin_v1.IAMClient(**kwargs)


def _get_gcp_resource_manager_client(**kwargs):
    """Return a google.cloud.resourcemanager_v3 ProjectsClient; raises ImportError if SDK missing."""
    from google.cloud import resourcemanager_v3  # type: ignore[import]

    return resourcemanager_v3.ProjectsClient(**kwargs)


def _get_gcp_iam_service(**kwargs):
    """Return a googleapiclient Resource for the IAM v1 API; raises ImportError if SDK missing."""
    from googleapiclient import discovery  # type: ignore[import]

    return discovery.build("iam", "v1", **kwargs)


def _get_gcp_compute_client(**kwargs):
    """Return a googleapiclient Resource for the Compute Engine v1 API; raises ImportError if SDK missing."""
    from googleapiclient import discovery  # type: ignore[import]

    return discovery.build("compute", "v1", **kwargs)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class GCSBucketFinding:
    bucket_name: str
    project_id: str
    public_access: bool
    iam_issues: List[str]
    issues: List[str]
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "project_id": self.project_id,
            "public_access": self.public_access,
            "iam_issues": self.iam_issues,
            "issues": self.issues,
            "severity": self.severity.value,
        }


@dataclass
class GCPIAMFinding:
    entity_type: str   # "member" | "binding"
    entity: str
    role: str
    issues: List[str]
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity": self.entity,
            "role": self.role,
            "issues": self.issues,
            "severity": self.severity.value,
        }


@dataclass
class GCPFirewallFinding:
    rule_name: str
    network: str
    direction: str
    issues: List[str]
    severity: CloudFindingSeverity
    open_ports: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "network": self.network,
            "direction": self.direction,
            "issues": self.issues,
            "severity": self.severity.value,
            "open_ports": self.open_ports,
        }


# ---------------------------------------------------------------------------
# GCSBucketEnumTool
# ---------------------------------------------------------------------------


class GCSBucketEnumTool(BaseTool):
    """
    Enumerate GCS buckets and detect public access or misconfigurations.

    Checks:
      - IAM policy for allUsers / allAuthenticatedUsers bindings
      - Bucket-level public access prevention setting
      - Versioning status
      - Object lifecycle policies
      - Uniform bucket-level access (UBLA)
      - Encryption type (CMEK vs Google-managed)
      - Bucket access logging
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gcs_bucket_enum",
            description="Discover public and misconfigured GCS buckets in a GCP project",
            parameters={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to scan",
                    },
                    "bucket_name": {
                        "type": "string",
                        "description": "Specific bucket name to scan (optional)",
                    },
                },
                "required": ["project_id"],
            },
        )

    async def execute(
        self,
        project_id: str,
        bucket_name: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_scan(project_id=project_id, bucket_name=bucket_name)
        except ImportError:
            return json.dumps({
                "error": "google-cloud-storage package is not installed",
                "install": "pip install google-cloud-storage google-cloud-resource-manager",
            })
        except Exception as exc:
            logger.error("GCSBucketEnumTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "findings_found" if findings else "clean",
            "project_id": project_id,
            "count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(
        self,
        project_id: str,
        bucket_name: Optional[str] = None,
    ) -> List[GCSBucketFinding]:
        client = _get_gcs_client()

        if bucket_name:
            buckets = [client.get_bucket(bucket_name)]
        else:
            try:
                buckets = list(client.list_buckets(project=project_id))
            except Exception as exc:
                logger.error("list_buckets failed for project %s: %s", project_id, exc)
                return []

        findings = []
        for bucket in buckets:
            finding = self._scan_bucket(bucket, project_id)
            if finding and (finding.issues or finding.iam_issues):
                findings.append(finding)
        return findings

    def _scan_bucket(self, bucket, project_id: str) -> Optional[GCSBucketFinding]:
        bucket_name = bucket.name
        issues: List[str] = []
        iam_issues: List[str] = []
        public_access = False

        # IAM policy — check for public bindings
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])
                for member in members:
                    if member in _PUBLIC_MEMBERS:
                        public_access = True
                        iam_issues.append(
                            f"IAM binding grants '{role}' to '{member}' — bucket is publicly accessible"
                        )
        except Exception as exc:
            logger.warning("Cannot read IAM policy for bucket %s: %s", bucket_name, exc)

        # Public access prevention
        try:
            iam_config = bucket.iam_configuration
            pap = getattr(iam_config, "public_access_prevention", None)
            if pap is None:
                issues.append("Cannot determine public access prevention status — missing iam_configuration attribute")
            elif pap == "inherited":
                issues.append(
                    "Public access prevention is 'inherited' — depends on org-level policy; consider enforcing explicitly"
                )
            elif pap != "enforced":
                issues.append(
                    f"Public access prevention is '{pap}' — set to 'enforced' to block all public access"
                )
        except Exception:
            issues.append("Cannot determine public access prevention status")

        # Uniform bucket-level access (UBLA)
        try:
            iam_config = bucket.iam_configuration
            ubla = getattr(iam_config, "uniform_bucket_level_access_enabled", None)
            if not ubla:
                issues.append(
                    "Uniform bucket-level access (UBLA) is disabled — ACL-based access controls are in effect"
                )
        except Exception:
            pass

        # Versioning
        try:
            versioning = bucket.versioning_enabled
            if not versioning:
                issues.append("Object versioning is not enabled — deleted/overwritten objects cannot be recovered")
        except Exception:
            pass

        # Lifecycle policies
        try:
            lifecycle = bucket.lifecycle_rules
            if not lifecycle:
                issues.append(
                    "No object lifecycle policies configured — objects may be retained indefinitely"
                )
        except Exception:
            pass

        # Encryption — CMEK vs Google-managed
        try:
            default_kms_key = bucket.default_kms_key_name
            if not default_kms_key:
                issues.append(
                    "Bucket uses Google-managed encryption — consider CMEK for compliance-sensitive workloads"
                )
        except Exception:
            pass

        # Access logging
        try:
            logging_config = bucket.logging
            if not logging_config:
                issues.append("Bucket access logging is not enabled — access patterns are not auditable")
        except Exception:
            pass

        if not issues and not iam_issues:
            return None

        # Severity classification
        if public_access:
            severity = CloudFindingSeverity.CRITICAL
        elif iam_issues:
            severity = CloudFindingSeverity.HIGH
        elif any("public access prevention" in i.lower() for i in issues):
            severity = CloudFindingSeverity.HIGH
        elif any("UBLA" in i or "ACL" in i for i in issues):
            severity = CloudFindingSeverity.MEDIUM
        else:
            severity = CloudFindingSeverity.LOW

        return GCSBucketFinding(
            bucket_name=bucket_name,
            project_id=project_id,
            public_access=public_access,
            iam_issues=iam_issues,
            issues=issues,
            severity=severity,
        )


# ---------------------------------------------------------------------------
# GCPIAMTool
# ---------------------------------------------------------------------------


class GCPIAMTool(BaseTool):
    """
    Analyze GCP IAM bindings for privilege escalation paths and overly permissive access.

    Checks:
      - Primitive roles (roles/owner, roles/editor, roles/viewer) at project level
      - allUsers or allAuthenticatedUsers bindings
      - Service accounts with owner or editor roles
      - Cross-project service account usage
      - Service account keys (not recommended for production)
      - Privilege escalation paths via sensitive IAM permissions (e.g., setIamPolicy)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gcp_iam_audit",
            description=(
                "Analyze GCP IAM bindings for primitive roles, public members, "
                "service account misuse, and privilege escalation paths"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to audit",
                    },
                    "check_sa_keys": {
                        "type": "boolean",
                        "default": True,
                        "description": "Check service accounts for user-managed keys",
                    },
                },
                "required": ["project_id"],
            },
        )

    async def execute(
        self,
        project_id: str,
        check_sa_keys: bool = True,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_audit(project_id=project_id, check_sa_keys=check_sa_keys)
        except ImportError:
            return json.dumps({
                "error": "google-cloud-resource-manager and google-api-python-client packages are not installed",
                "install": "pip install google-cloud-resource-manager google-api-python-client google-auth",
            })
        except Exception as exc:
            logger.error("GCPIAMTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "complete",
            "project_id": project_id,
            "finding_count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(self, project_id: str, check_sa_keys: bool = True) -> List[GCPIAMFinding]:
        rm_client = _get_gcp_resource_manager_client()
        findings: List[GCPIAMFinding] = []

        # Project-level IAM policy
        try:
            policy = rm_client.get_iam_policy(
                request={"resource": f"projects/{project_id}"}
            )
            findings.extend(self._audit_policy_bindings(policy, project_id))
        except Exception as exc:
            logger.error("get_iam_policy failed for project %s: %s", project_id, exc)
            findings.append(GCPIAMFinding(
                entity_type="project",
                entity=project_id,
                role="unknown",
                issues=[f"Cannot retrieve IAM policy: {exc}"],
                severity=CloudFindingSeverity.HIGH,
            ))

        # Service account key audit
        if check_sa_keys:
            findings.extend(self._audit_service_account_keys(project_id))

        return findings

    def _audit_policy_bindings(self, policy, project_id: str) -> List[GCPIAMFinding]:
        findings: List[GCPIAMFinding] = []
        bindings = getattr(policy, "bindings", []) or []

        for binding in bindings:
            role = getattr(binding, "role", "") or ""
            members = list(getattr(binding, "members", []) or [])
            issues: List[str] = []

            # Primitive roles
            if role in _PRIMITIVE_ROLES:
                issues.append(
                    f"Primitive role '{role}' grants broad permissions — use predefined or custom roles instead"
                )

            # Public members
            for member in members:
                if member in _PUBLIC_MEMBERS:
                    issues.append(
                        f"Role '{role}' is granted to '{member}' — this exposes the project to anonymous or any authenticated user"
                    )

            # Service accounts with owner/editor
            for member in members:
                if member.startswith("serviceAccount:"):
                    if role in ("roles/owner", "roles/editor"):
                        issues.append(
                            f"Service account '{member}' has '{role}' — service accounts should follow least-privilege"
                        )
                    # Cross-project SA usage
                    sa_project = self._extract_project_from_sa(member)
                    if sa_project and sa_project != project_id:
                        issues.append(
                            f"Service account '{member}' belongs to a different project ('{sa_project}') — cross-project SA usage is a lateral movement risk"
                        )

            # Privilege escalation via sensitive permissions
            privesc_issues = self._check_binding_privesc(role)
            issues.extend(privesc_issues)

            if not issues:
                continue

            # Severity
            any_public = any(m in _PUBLIC_MEMBERS for m in members)
            if any_public and role in ("roles/owner", "roles/editor"):
                severity = CloudFindingSeverity.CRITICAL
            elif any_public:
                severity = CloudFindingSeverity.HIGH
            elif role == "roles/owner":
                severity = CloudFindingSeverity.HIGH
            elif privesc_issues:
                severity = CloudFindingSeverity.HIGH
            elif role in _PRIMITIVE_ROLES:
                severity = CloudFindingSeverity.MEDIUM
            else:
                severity = CloudFindingSeverity.LOW

            findings.append(GCPIAMFinding(
                entity_type="binding",
                entity=", ".join(members) if members else "(no members)",
                role=role,
                issues=issues,
                severity=severity,
            ))

        return findings

    def _check_binding_privesc(self, role: str) -> List[str]:
        """Flag roles that contain known privilege escalation permissions."""
        # For roles/owner and roles/editor we know they contain setIamPolicy
        issues: List[str] = []
        if role in ("roles/owner", "roles/editor"):
            issues.append(
                f"Role '{role}' includes setIamPolicy-equivalent permissions — privilege escalation possible"
            )
        elif "setIamPolicy" in role or "admin" in role.lower():
            issues.append(
                f"Role '{role}' may include setIamPolicy permission — review for privilege escalation paths"
            )
        return issues

    @staticmethod
    def _extract_project_from_sa(member: str) -> Optional[str]:
        """Extract project ID from a service account member string."""
        # Format: serviceAccount:<sa-name>@<project-id>.iam.gserviceaccount.com
        _PREFIX = "serviceAccount:"
        _SUFFIX = ".iam.gserviceaccount.com"
        try:
            if not member.startswith(_PREFIX):
                return None
            email = member[len(_PREFIX):]
            domain = email.split("@", 1)[1]
            if domain.endswith(_SUFFIX):
                return domain[: -len(_SUFFIX)]
        except (IndexError, AttributeError):
            pass
        return None

    def _audit_service_account_keys(self, project_id: str) -> List[GCPIAMFinding]:
        """List service accounts and flag those with user-managed keys."""
        findings: List[GCPIAMFinding] = []
        try:
            iam_svc = _get_gcp_iam_service()
            sa_list_resp = (
                iam_svc.projects()
                .serviceAccounts()
                .list(name=f"projects/{project_id}")
                .execute()
            )
            service_accounts = sa_list_resp.get("accounts", [])
        except Exception as exc:
            logger.warning("Cannot list service accounts for project %s: %s", project_id, exc)
            return findings

        for sa in service_accounts:
            sa_email = sa.get("email", "unknown")
            sa_name = sa.get("name", "")
            issues: List[str] = []

            try:
                keys_resp = (
                    iam_svc.projects()
                    .serviceAccounts()
                    .keys()
                    .list(name=sa_name, keyTypes=["USER_MANAGED"])
                    .execute()
                )
                user_keys = keys_resp.get("keys", [])
                if user_keys:
                    issues.append(
                        f"Service account '{sa_email}' has {len(user_keys)} user-managed key(s) — "
                        "prefer Workload Identity Federation over long-lived keys"
                    )
            except Exception as exc:
                logger.warning("Cannot list keys for SA %s: %s", sa_email, exc)
                continue

            if issues:
                findings.append(GCPIAMFinding(
                    entity_type="member",
                    entity=sa_email,
                    role="(service account keys)",
                    issues=issues,
                    severity=CloudFindingSeverity.MEDIUM,
                ))

        return findings


# ---------------------------------------------------------------------------
# GCPFirewallAuditTool
# ---------------------------------------------------------------------------


class GCPFirewallAuditTool(BaseTool):
    """
    Audit VPC firewall rules for dangerous misconfigurations.

    Checks:
      - Rules allowing 0.0.0.0/0 inbound on dangerous ports (SSH, RDP, databases)
      - Rules with all protocols / all ports allowed
      - Disabled firewall rules (may be re-enabled accidentally)
      - Overly permissive egress rules
      - Rules without target tags or target service accounts (apply to all instances)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gcp_firewall_audit",
            description=(
                "Check GCP VPC firewall rules for dangerous inbound/egress rules, "
                "all-ports allowed policies, and rules without instance targeting"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to scan",
                    },
                    "network": {
                        "type": "string",
                        "description": "Restrict scan to a specific VPC network name (optional)",
                    },
                },
                "required": ["project_id"],
            },
        )

    async def execute(
        self,
        project_id: str,
        network: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_audit(project_id=project_id, network=network)
        except ImportError:
            return json.dumps({
                "error": "google-api-python-client package is not installed",
                "install": "pip install google-api-python-client google-auth",
            })
        except Exception as exc:
            logger.error("GCPFirewallAuditTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "findings_found" if findings else "clean",
            "project_id": project_id,
            "network_filter": network,
            "count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(
        self, project_id: str, network: Optional[str] = None
    ) -> List[GCPFirewallFinding]:
        compute = _get_gcp_compute_client()

        try:
            resp = compute.firewalls().list(project=project_id).execute()
            rules = resp.get("items", [])
        except Exception as exc:
            logger.error("firewalls.list failed for project %s: %s", project_id, exc)
            return []

        findings = []
        for rule in rules:
            # Optional network filter
            rule_network = rule.get("network", "")
            network_name = rule_network.rsplit("/", 1)[-1]
            if network and network_name != network:
                continue

            finding = self._audit_rule(rule, network_name)
            if finding and finding.issues:
                findings.append(finding)

        return findings

    def _audit_rule(self, rule: Dict[str, Any], network_name: str) -> Optional[GCPFirewallFinding]:
        rule_name = rule.get("name", "unknown")
        direction = rule.get("direction", "INGRESS")
        disabled = rule.get("disabled", False)
        rule.get("priority", 1000)
        issues: List[str] = []
        open_ports: List[Dict[str, Any]] = []

        # Disabled rules
        if disabled:
            issues.append(
                f"Firewall rule '{rule_name}' is disabled — it could be re-enabled, re-evaluate if still needed"
            )

        # Source/destination ranges
        source_ranges = rule.get("sourceRanges", [])
        dest_ranges = rule.get("destinationRanges", [])
        is_open_to_all = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges

        # Target tags and service accounts (absent = applies to all instances)
        target_tags = rule.get("targetTags", [])
        target_service_accounts = rule.get("targetServiceAccounts", [])
        no_target_scope = not target_tags and not target_service_accounts

        if direction == "INGRESS":
            issues.extend(
                self._audit_ingress(
                    rule_name=rule_name,
                    allowed=rule.get("allowed", []),
                    source_ranges=source_ranges,
                    is_open_to_all=is_open_to_all,
                    no_target_scope=no_target_scope,
                    open_ports=open_ports,
                )
            )
        elif direction == "EGRESS":
            issues.extend(
                self._audit_egress(
                    rule_name=rule_name,
                    allowed=rule.get("allowed", []),
                    dest_ranges=dest_ranges,
                    open_ports=open_ports,
                )
            )

        if not issues:
            return None

        # Severity classification
        has_dangerous_open = any(
            p.get("is_dangerous") for p in open_ports
        )
        all_open = any(
            p.get("all_ports") for p in open_ports
        )

        if is_open_to_all and (has_dangerous_open or all_open) and not disabled:
            severity = CloudFindingSeverity.CRITICAL
        elif is_open_to_all and not disabled:
            severity = CloudFindingSeverity.HIGH
        elif has_dangerous_open and not disabled:
            severity = CloudFindingSeverity.HIGH
        elif disabled:
            severity = CloudFindingSeverity.LOW
        else:
            severity = CloudFindingSeverity.MEDIUM

        return GCPFirewallFinding(
            rule_name=rule_name,
            network=network_name,
            direction=direction,
            issues=issues,
            severity=severity,
            open_ports=open_ports,
        )

    def _audit_ingress(
        self,
        rule_name: str,
        allowed: List[Dict[str, Any]],
        source_ranges: List[str],
        is_open_to_all: bool,
        no_target_scope: bool,
        open_ports: List[Dict[str, Any]],
    ) -> List[str]:
        issues: List[str] = []

        for allow_entry in allowed:
            protocol = allow_entry.get("IPProtocol", "")
            ports = allow_entry.get("ports", [])

            # All protocols allowed
            if protocol == "all":
                open_ports.append({"protocol": "all", "all_ports": True, "is_dangerous": True})
                if is_open_to_all:
                    issues.append(
                        f"Rule '{rule_name}' allows ALL protocols/ports from 0.0.0.0/0 — unrestricted inbound access"
                    )
                else:
                    issues.append(
                        f"Rule '{rule_name}' allows ALL protocols/ports — consider restricting to specific protocols"
                    )
                continue

            # No ports specified means all ports for that protocol
            if not ports:
                open_ports.append({"protocol": protocol, "all_ports": True, "is_dangerous": False})
                if is_open_to_all:
                    issues.append(
                        f"Rule '{rule_name}' allows all ports for protocol '{protocol}' from 0.0.0.0/0"
                    )
                continue

            # Check specific ports against dangerous list
            for port_spec in ports:
                port_ints = self._parse_port_spec(port_spec)
                for port_int in port_ints:
                    if port_int in _DANGEROUS_PORTS:
                        service = _DANGEROUS_PORTS[port_int]
                        open_ports.append({
                            "protocol": protocol,
                            "port": port_int,
                            "service": service,
                            "is_dangerous": True,
                            "all_ports": False,
                        })
                        if is_open_to_all:
                            issues.append(
                                f"Rule '{rule_name}' exposes port {port_int}/{protocol} ({service}) to 0.0.0.0/0"
                            )
                        else:
                            issues.append(
                                f"Rule '{rule_name}' allows port {port_int}/{protocol} ({service}) — verify source restriction"
                            )

        # No target tags or service accounts
        if no_target_scope and is_open_to_all and issues:
            issues.append(
                f"Rule '{rule_name}' has no targetTags or targetServiceAccounts — applies to ALL instances in the network"
            )

        return issues

    def _audit_egress(
        self,
        rule_name: str,
        allowed: List[Dict[str, Any]],
        dest_ranges: List[str],
        open_ports: List[Dict[str, Any]],
    ) -> List[str]:
        issues: List[str] = []
        egress_open_to_all = "0.0.0.0/0" in dest_ranges or "::/0" in dest_ranges or not dest_ranges

        for allow_entry in allowed:
            protocol = allow_entry.get("IPProtocol", "")
            ports = allow_entry.get("ports", [])

            if protocol == "all" and egress_open_to_all:
                open_ports.append({"protocol": "all", "all_ports": True, "is_dangerous": False})
                issues.append(
                    f"Egress rule '{rule_name}' allows ALL protocols to all destinations — "
                    "consider restricting egress to prevent data exfiltration"
                )
            elif not ports and egress_open_to_all:
                open_ports.append({"protocol": protocol, "all_ports": True, "is_dangerous": False})
                issues.append(
                    f"Egress rule '{rule_name}' allows all ports for '{protocol}' to all destinations"
                )

        return issues

    @staticmethod
    def _parse_port_spec(port_spec: str) -> List[int]:
        """Parse a GCP firewall port spec ('22', '8080-8090') into a list of port ints."""
        ports: List[int] = []
        try:
            if "-" in str(port_spec):
                start, end = port_spec.split("-", 1)
                start_int, end_int = int(start), int(end)
                # Only expand small ranges to avoid memory issues
                if end_int - start_int <= _MAX_PORT_RANGE_EXPANSION:
                    ports.extend(range(start_int, end_int + 1))
                else:
                    # For large ranges, check if any dangerous port falls within
                    for dangerous_port in _DANGEROUS_PORTS:
                        if start_int <= dangerous_port <= end_int:
                            ports.append(dangerous_port)
            else:
                ports.append(int(port_spec))
        except (ValueError, TypeError):
            pass
        return ports


# ---------------------------------------------------------------------------
# Public tool list
# ---------------------------------------------------------------------------

GCP_TOOLS: List[BaseTool] = [
    GCSBucketEnumTool(),
    GCPIAMTool(),
    GCPFirewallAuditTool(),
]

__all__ = [
    "GCSBucketEnumTool",
    "GCPIAMTool",
    "GCPFirewallAuditTool",
    "GCP_TOOLS",
    "GCSBucketFinding",
    "GCPIAMFinding",
    "GCPFirewallFinding",
    "CloudFindingSeverity",
    "_get_gcs_client",
    "_get_gcp_iam_client",
    "_get_gcp_resource_manager_client",
    "_get_gcp_iam_service",
    "_get_gcp_compute_client",
]
