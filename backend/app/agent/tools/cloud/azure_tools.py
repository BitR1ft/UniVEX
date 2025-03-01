"""

Four agent tools for Azure security assessments:

  AzureBlobEnumTool  — Discover public Azure Blob Storage containers and misconfigurations
  AzureADTool        — Enumerate Azure AD users, groups, and service principals
  AzureNSGAuditTool  — Check Network Security Groups for dangerous inbound/outbound rules
  CloudSummaryTool   — Cross-cloud risk summary comparing AWS / Azure / GCP findings

All tools are fully mockable for testing — Azure SDK calls are abstracted behind
`_get_azure_client()`, `_get_msgraph_client()`, and `_get_azure_network_client()`
helpers that tests can patch.

Tools are registered in `AZURE_TOOLS` and may be added to the tool registry under
the CLOUD_SECURITY attack category alongside the AWS tools.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
# Dangerous ports checked by NSG auditor
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

# ---------------------------------------------------------------------------
# Mockable Azure SDK client helpers
# ---------------------------------------------------------------------------


def _get_azure_client(subscription_id: str, **kwargs):
    """Return an azure.mgmt.storage StorageManagementClient; raises ImportError if SDK missing."""
    from azure.mgmt.storage import StorageManagementClient  # type: ignore[import]
    from azure.identity import DefaultAzureCredential  # type: ignore[import]

    credential = kwargs.get("credential") or DefaultAzureCredential()
    return StorageManagementClient(credential, subscription_id)


def _get_msgraph_client(**kwargs):
    """Return a msgraph GraphServiceClient; raises ImportError if SDK missing."""
    from msgraph import GraphServiceClient  # type: ignore[import]
    from azure.identity import DefaultAzureCredential  # type: ignore[import]

    credential = kwargs.get("credential") or DefaultAzureCredential()
    scopes = kwargs.get("scopes") or ["https://graph.microsoft.com/.default"]
    return GraphServiceClient(credential, scopes=scopes)


def _get_azure_network_client(subscription_id: str, **kwargs):
    """Return an azure.mgmt.network NetworkManagementClient; raises ImportError if SDK missing."""
    from azure.mgmt.network import NetworkManagementClient  # type: ignore[import]
    from azure.identity import DefaultAzureCredential  # type: ignore[import]

    credential = kwargs.get("credential") or DefaultAzureCredential()
    return NetworkManagementClient(credential, subscription_id)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class AzureBlobFinding:
    account_name: str
    container_name: str
    access_level: str          # "private" | "blob" | "container"
    public_access_enabled: bool
    https_only: bool
    tls_version: str
    issues: List[str]
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_name": self.account_name,
            "container_name": self.container_name,
            "access_level": self.access_level,
            "public_access_enabled": self.public_access_enabled,
            "https_only": self.https_only,
            "tls_version": self.tls_version,
            "issues": self.issues,
            "severity": self.severity.value,
        }


@dataclass
class AzureADFinding:
    entity_type: str   # "user" | "group" | "service_principal"
    entity_name: str
    issues: List[str]
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "issues": self.issues,
            "severity": self.severity.value,
        }


@dataclass
class AzureNSGFinding:
    nsg_name: str
    resource_group: str
    issues: List[str]
    severity: CloudFindingSeverity
    open_ports: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nsg_name": self.nsg_name,
            "resource_group": self.resource_group,
            "issues": self.issues,
            "severity": self.severity.value,
            "open_ports": self.open_ports,
        }


# ---------------------------------------------------------------------------
# AzureBlobEnumTool
# ---------------------------------------------------------------------------


class AzureBlobEnumTool(BaseTool):
    """
    Enumerate Azure Blob Storage accounts and containers for misconfigurations.

    Checks:
      - Storage account public access setting (AllowBlobPublicAccess)
      - Container-level access tiers (private / blob / container)
      - Anonymous blob access
      - HTTPS-only traffic enforcement
      - Minimum TLS version (TLS 1.2 required)
      - Storage firewall / network rule configuration
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="azure_blob_enum",
            description="Discover public Azure Blob Storage containers and account misconfigurations",
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": "string",
                        "description": "Azure subscription ID to scan",
                    },
                    "resource_group": {
                        "type": "string",
                        "description": "Restrict scan to a specific resource group (optional)",
                    },
                    "account_name": {
                        "type": "string",
                        "description": "Specific storage account to scan (optional)",
                    },
                },
                "required": ["subscription_id"],
            },
        )

    async def execute(
        self,
        subscription_id: str,
        resource_group: Optional[str] = None,
        account_name: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_scan(
                subscription_id=subscription_id,
                resource_group=resource_group,
                account_name=account_name,
            )
        except ImportError:
            return json.dumps({
                "error": "azure-mgmt-storage and azure-identity packages are not installed",
                "install": "pip install azure-mgmt-storage azure-identity",
            })
        except Exception as exc:
            logger.error("AzureBlobEnumTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "findings_found" if findings else "clean",
            "count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(
        self,
        subscription_id: str,
        resource_group: Optional[str] = None,
        account_name: Optional[str] = None,
    ) -> List[AzureBlobFinding]:
        client = _get_azure_client(subscription_id)

        if account_name and resource_group:
            accounts = [client.storage_accounts.get_properties(resource_group, account_name)]
        elif resource_group:
            accounts = list(client.storage_accounts.list_by_resource_group(resource_group))
        else:
            accounts = list(client.storage_accounts.list())

        findings = []
        for account in accounts:
            rg = self._extract_resource_group(account.id or "")
            account_findings = self._scan_account(client, account, rg)
            findings.extend(account_findings)
        return findings

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Parse resource group name from an Azure resource ID."""
        parts = resource_id.split("/")
        parts_lower = [p.lower() for p in parts]
        try:
            idx = parts_lower.index("resourcegroups")
            return parts[idx + 1]
        except (ValueError, IndexError):
            return "unknown"

    def _scan_account(self, client, account, resource_group: str) -> List[AzureBlobFinding]:
        account_name = account.name or "unknown"
        account_issues: List[str] = []

        # HTTPS-only
        https_only = bool(account.enable_https_traffic_only)
        if not https_only:
            account_issues.append("HTTPS-only traffic is not enforced — HTTP connections are permitted")

        # Minimum TLS version
        tls_version = getattr(account, "minimum_tls_version", None) or "TLS1_0"
        if tls_version not in ("TLS1_2", "TLS1_3"):
            account_issues.append(
                f"Minimum TLS version is {tls_version} — TLS 1.2 or higher is required"
            )

        # Storage firewall / network rules
        network_rule_set = getattr(account, "network_rule_set", None)
        if network_rule_set:
            default_action = getattr(network_rule_set, "default_action", "Allow")
            if str(default_action).lower() == "allow":
                account_issues.append(
                    "Storage firewall default action is 'Allow' — restrict access with network rules"
                )
        else:
            account_issues.append("No network rule set configured — storage accessible from all networks")

        # Public blob access at account level
        allow_public = getattr(account, "allow_blob_public_access", True)
        if allow_public is None:
            allow_public = True  # Older accounts default to enabled

        # Enumerate containers
        findings: List[AzureBlobFinding] = []
        try:
            blob_service = client.blob_containers.list(resource_group, account_name)
            containers = list(blob_service)
        except Exception as exc:
            logger.warning("Cannot list containers for %s: %s", account_name, exc)
            containers = []

        if not containers and account_issues:
            # Report account-level issues with a synthetic container entry
            sev = self._account_severity(account_issues, allow_public)
            findings.append(AzureBlobFinding(
                account_name=account_name,
                container_name="(account-level)",
                access_level="unknown",
                public_access_enabled=bool(allow_public),
                https_only=https_only,
                tls_version=tls_version,
                issues=account_issues,
                severity=sev,
            ))
            return findings

        for container in containers:
            container_name = container.name or "unknown"
            container_issues = list(account_issues)

            public_access = getattr(container, "public_access", None)
            access_level = str(public_access).lower() if public_access else "private"

            if access_level == "container":
                container_issues.append(
                    "Container access level is 'container' — anonymous listing and blob access allowed"
                )
            elif access_level == "blob":
                container_issues.append(
                    "Container access level is 'blob' — anonymous blob access allowed (no listing)"
                )

            if bool(allow_public) and access_level in ("container", "blob"):
                container_issues.append(
                    "Account-level public access is enabled — anonymous access is active on this container"
                )

            if not container_issues:
                continue

            sev = self._container_severity(container_issues, access_level, bool(allow_public))
            findings.append(AzureBlobFinding(
                account_name=account_name,
                container_name=container_name,
                access_level=access_level,
                public_access_enabled=bool(allow_public),
                https_only=https_only,
                tls_version=tls_version,
                issues=container_issues,
                severity=sev,
            ))

        return findings

    @staticmethod
    def _account_severity(issues: List[str], allow_public: bool) -> CloudFindingSeverity:
        if allow_public:
            return CloudFindingSeverity.HIGH
        if any("TLS" in i or "HTTPS" in i for i in issues):
            return CloudFindingSeverity.MEDIUM
        return CloudFindingSeverity.LOW

    @staticmethod
    def _container_severity(
        issues: List[str], access_level: str, account_public: bool
    ) -> CloudFindingSeverity:
        if access_level == "container" and account_public:
            return CloudFindingSeverity.CRITICAL
        if access_level == "blob" and account_public:
            return CloudFindingSeverity.HIGH
        if access_level == "container":
            return CloudFindingSeverity.HIGH
        if any("HTTPS" in i or "TLS" in i for i in issues):
            return CloudFindingSeverity.MEDIUM
        return CloudFindingSeverity.LOW


# ---------------------------------------------------------------------------
# AzureADTool
# ---------------------------------------------------------------------------


class AzureADTool(BaseTool):
    """
    Enumerate Azure AD (Entra ID) users, groups, and service principals.

    Checks:
      - Users: MFA status, legacy authentication, guest accounts with privileged roles
      - Groups: privileged group memberships, dynamic vs. assigned
      - Service principals / apps: client secret expiration, over-privileged API permissions
    """

    # Well-known Azure AD privileged role template IDs
    _PRIVILEGED_ROLE_IDS = {
        "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    }

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="azure_ad_enum",
            description=(
                "Enumerate Azure AD users, groups, and service principals; "
                "detect MFA gaps, secret expiry, and privileged access risks"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "enum": ["all", "users", "groups", "service_principals"],
                        "default": "all",
                        "description": "Entity category to enumerate",
                    },
                    "include_guests": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include guest user accounts in the scan",
                    },
                },
            },
        )

    async def execute(
        self,
        entity_type: str = "all",
        include_guests: bool = True,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_audit(entity_type=entity_type, include_guests=include_guests)
        except ImportError:
            return json.dumps({
                "error": "msgraph and azure-identity packages are not installed",
                "install": "pip install msgraph-sdk azure-identity",
            })
        except Exception as exc:
            logger.error("AzureADTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "complete",
            "entity_type": entity_type,
            "finding_count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(
        self, entity_type: str = "all", include_guests: bool = True
    ) -> List[AzureADFinding]:
        client = _get_msgraph_client()
        findings: List[AzureADFinding] = []

        if entity_type in ("all", "users"):
            findings.extend(self._audit_users(client, include_guests=include_guests))
        if entity_type in ("all", "groups"):
            findings.extend(self._audit_groups(client))
        if entity_type in ("all", "service_principals"):
            findings.extend(self._audit_service_principals(client))

        return findings

    def _audit_users(self, client, include_guests: bool = True) -> List[AzureADFinding]:
        findings: List[AzureADFinding] = []
        try:
            users_response = client.users.get()
            users = getattr(users_response, "value", []) or []
        except Exception as exc:
            logger.error("Graph users.get() failed: %s", exc)
            return findings

        for user in users:
            issues: List[str] = []
            display_name = getattr(user, "display_name", None) or getattr(user, "user_principal_name", "unknown")
            user_type = getattr(user, "user_type", "Member")
            account_enabled = getattr(user, "account_enabled", True)

            if not account_enabled:
                continue  # Skip disabled accounts

            # Guest accounts
            if user_type == "Guest":
                if not include_guests:
                    continue
                issues.append("Guest account — verify that privileged access is not assigned")

            # MFA: Graph reports registration details via separate endpoint
            # We flag users who have no strong auth methods registered
            auth_methods = []
            try:
                methods_resp = client.users.by_user_id(user.id).authentication.methods.get()
                auth_methods = getattr(methods_resp, "value", []) or []
            except Exception:
                pass  # Insufficient permissions or endpoint unavailable

            if auth_methods:
                # Exclude password-only authentication (odata type indicates phone/TOTP/FIDO etc.)
                strong_methods = [
                    m for m in auth_methods
                    if getattr(m, "odata_type", "") not in (
                        "#microsoft.graph.passwordAuthenticationMethod", ""
                    )
                ]
                if not strong_methods:
                    issues.append("No strong authentication (MFA) method registered — legacy auth risk")

            # On-premises sync: synced users may be subject to on-prem compromises
            on_prem_sync = getattr(user, "on_premises_sync_enabled", False)
            if on_prem_sync and user_type == "Guest":
                issues.append(
                    "Hybrid (on-prem synced) guest account — lateral movement risk from on-premises environment"
                )

            if not issues:
                continue

            sev = (
                CloudFindingSeverity.HIGH
                if "MFA" in " ".join(issues)
                else CloudFindingSeverity.MEDIUM
            )
            findings.append(AzureADFinding(
                entity_type="user",
                entity_name=display_name,
                issues=issues,
                severity=sev,
            ))

        return findings

    def _audit_groups(self, client) -> List[AzureADFinding]:
        findings: List[AzureADFinding] = []
        try:
            groups_response = client.groups.get()
            groups = getattr(groups_response, "value", []) or []
        except Exception as exc:
            logger.error("Graph groups.get() failed: %s", exc)
            return findings

        for group in groups:
            issues: List[str] = []
            display_name = getattr(group, "display_name", "unknown")
            group_types = getattr(group, "group_types", []) or []
            is_assignable = getattr(group, "is_assignable_to_role", False)
            mail_enabled = getattr(group, "mail_enabled", False)
            security_enabled = getattr(group, "security_enabled", False)

            # Dynamic groups with role assignment capability
            if "DynamicMembership" in group_types and is_assignable:
                issues.append(
                    "Dynamic membership group is role-assignable — membership rules may grant unintended privilege"
                )

            # Mail-enabled security groups can be targeted externally
            if mail_enabled and security_enabled:
                issues.append(
                    "Mail-enabled security group — external email delivery may expose membership or relay abuse"
                )

            # Check for members that are guests in privileged groups
            if is_assignable:
                try:
                    members_resp = client.groups.by_group_id(group.id).members.get()
                    members = getattr(members_resp, "value", []) or []
                    for member in members:
                        if getattr(member, "user_type", "") == "Guest":
                            issues.append(
                                f"Guest account '{getattr(member, 'display_name', 'unknown')}' "
                                "is a member of a role-assignable group — privileged access risk"
                            )
                except Exception:
                    pass

            if not issues:
                continue

            sev = (
                CloudFindingSeverity.HIGH
                if "role-assignable" in " ".join(issues)
                else CloudFindingSeverity.MEDIUM
            )
            findings.append(AzureADFinding(
                entity_type="group",
                entity_name=display_name,
                issues=issues,
                severity=sev,
            ))

        return findings

    def _audit_service_principals(self, client) -> List[AzureADFinding]:
        findings: List[AzureADFinding] = []
        now = datetime.now(tz=timezone.utc)

        try:
            sps_response = client.service_principals.get()
            sps = getattr(sps_response, "value", []) or []
        except Exception as exc:
            logger.error("Graph service_principals.get() failed: %s", exc)
            return findings

        for sp in sps:
            issues: List[str] = []
            display_name = getattr(sp, "display_name", "unknown")

            # Check client secrets expiration
            password_credentials = getattr(sp, "password_credentials", []) or []
            for cred in password_credentials:
                end_date = getattr(cred, "end_date_time", None)
                if end_date is None:
                    issues.append("Client secret has no expiration date — rotate immediately")
                    continue
                if isinstance(end_date, str):
                    try:
                        end_date = datetime.fromisoformat(end_date.rstrip("Z")).replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
                days_remaining = (end_date - now).days
                if days_remaining < 0:
                    issues.append(
                        f"Client secret expired {abs(days_remaining)} day(s) ago — "
                        "rotate and update dependent applications"
                    )
                elif days_remaining < 30:
                    issues.append(
                        f"Client secret expires in {days_remaining} day(s) — rotation required soon"
                    )

            # Check for overly-permissive app roles (e.g., Mail.ReadWrite.All, Directory.ReadWrite.All)
            app_roles = getattr(sp, "app_roles", []) or []
            dangerous_roles = {"Directory.ReadWrite.All", "Mail.ReadWrite.All", "Files.ReadWrite.All"}
            for role in app_roles:
                role_value = getattr(role, "value", "") or ""
                if role_value in dangerous_roles and getattr(role, "is_enabled", False):
                    issues.append(
                        f"Application role '{role_value}' is enabled — "
                        "over-permissive access to tenant data"
                    )

            if not issues:
                continue

            sev = (
                CloudFindingSeverity.CRITICAL
                if any("expired" in i.lower() or "ReadWrite.All" in i for i in issues)
                else CloudFindingSeverity.HIGH
            )
            findings.append(AzureADFinding(
                entity_type="service_principal",
                entity_name=display_name,
                issues=issues,
                severity=sev,
            ))

        return findings


# ---------------------------------------------------------------------------
# AzureNSGAuditTool
# ---------------------------------------------------------------------------


class AzureNSGAuditTool(BaseTool):
    """
    Audit Azure Network Security Groups for dangerous rule configurations.

    Flags:
      - Inbound rules allowing 0.0.0.0/0 on critical ports (SSH, RDP, databases)
      - Any-to-any rules (port * / all protocols)
      - Overly permissive outbound rules (e.g., allow-all outbound)
      - Rules without a meaningful description
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="azure_nsg_audit",
            description=(
                "Check Azure Network Security Groups for inbound/outbound misconfigurations "
                "including open dangerous ports and any-to-any rules"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": "string",
                        "description": "Azure subscription ID to scan",
                    },
                    "resource_group": {
                        "type": "string",
                        "description": "Restrict scan to a specific resource group (optional)",
                    },
                },
                "required": ["subscription_id"],
            },
        )

    async def execute(
        self,
        subscription_id: str,
        resource_group: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        try:
            findings = self._run_audit(
                subscription_id=subscription_id,
                resource_group=resource_group,
            )
        except ImportError:
            return json.dumps({
                "error": "azure-mgmt-network and azure-identity packages are not installed",
                "install": "pip install azure-mgmt-network azure-identity",
            })
        except Exception as exc:
            logger.error("AzureNSGAuditTool failed: %s", exc)
            return json.dumps({"error": str(exc)})

        result = {
            "status": "complete",
            "finding_count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(
        self,
        subscription_id: str,
        resource_group: Optional[str] = None,
    ) -> List[AzureNSGFinding]:
        network_client = _get_azure_network_client(subscription_id)

        if resource_group:
            nsgs = list(network_client.network_security_groups.list(resource_group))
        else:
            nsgs = list(network_client.network_security_groups.list_all())

        findings: List[AzureNSGFinding] = []
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            rg = self._extract_resource_group(nsg.id or "")
            finding = self._audit_nsg(nsg, nsg_name, rg)
            if finding and finding.issues:
                findings.append(finding)
        return findings

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        parts = resource_id.split("/")
        parts_lower = [p.lower() for p in parts]
        try:
            idx = parts_lower.index("resourcegroups")
            return parts[idx + 1]
        except (ValueError, IndexError):
            return "unknown"

    def _audit_nsg(self, nsg, nsg_name: str, resource_group: str) -> Optional[AzureNSGFinding]:
        issues: List[str] = []
        open_ports: List[Dict[str, Any]] = []

        security_rules = list(getattr(nsg, "security_rules", []) or [])
        default_security_rules = list(getattr(nsg, "default_security_rules", []) or [])
        all_rules = security_rules + default_security_rules

        for rule in all_rules:
            rule_name = getattr(rule, "name", "unnamed")
            direction = getattr(rule, "direction", "Inbound")
            access = getattr(rule, "access", "Allow")
            priority = getattr(rule, "priority", 0)
            getattr(rule, "protocol", "*")
            source_prefix = getattr(rule, "source_address_prefix", "") or ""
            dest_prefix = getattr(rule, "destination_address_prefix", "") or ""
            dest_port_range = getattr(rule, "destination_port_range", "") or ""
            dest_port_ranges = list(getattr(rule, "destination_port_ranges", []) or [])
            description = getattr(rule, "description", None) or ""

            if str(access).lower() != "allow":
                continue

            # Rules without descriptions are harder to audit
            if not description.strip() and priority < 1000:
                issues.append(
                    f"Rule '{rule_name}' (priority {priority}) has no description — "
                    "document the business justification"
                )

            # Inbound rules from any source
            if str(direction).lower() == "inbound" and source_prefix in ("*", "0.0.0.0/0", "Internet", "Any"):
                # Any-to-any
                if dest_port_range == "*" or (not dest_port_range and not dest_port_ranges):
                    issues.append(
                        f"Rule '{rule_name}': any-to-any inbound rule allows all traffic from the internet"
                    )
                    open_ports.append({
                        "rule": rule_name,
                        "direction": "Inbound",
                        "port_range": "*",
                        "source": source_prefix,
                        "priority": priority,
                    })
                else:
                    # Check individual dangerous ports
                    all_port_ranges = ([dest_port_range] if dest_port_range else []) + dest_port_ranges
                    for port_range in all_port_ranges:
                        flagged = self._check_port_range(port_range)
                        for port_num, service in flagged:
                            issues.append(
                                f"Rule '{rule_name}': {service} (port {port_num}) "
                                f"open to {source_prefix} — critical internet exposure"
                            )
                            open_ports.append({
                                "rule": rule_name,
                                "direction": "Inbound",
                                "port": port_num,
                                "service": service,
                                "source": source_prefix,
                                "priority": priority,
                            })

            # Outbound rules — flag allow-all outbound to the internet
            elif str(direction).lower() == "outbound" and dest_prefix in ("*", "0.0.0.0/0", "Internet", "Any"):
                if dest_port_range == "*" or (not dest_port_range and not dest_port_ranges):
                    issues.append(
                        f"Rule '{rule_name}': unrestricted outbound to the internet — "
                        "data exfiltration risk; apply egress filtering"
                    )

        if not issues:
            return None

        # Severity: any open dangerous port or any-to-any → CRITICAL
        has_critical = any(
            s in " ".join(issues) for s in [
                "any-to-any", "SSH", "RDP", "MSSQL", "MySQL", "PostgreSQL", "Redis", "MongoDB"
            ]
        )
        severity = CloudFindingSeverity.CRITICAL if has_critical else CloudFindingSeverity.HIGH

        return AzureNSGFinding(
            nsg_name=nsg_name,
            resource_group=resource_group,
            issues=issues,
            severity=severity,
            open_ports=open_ports,
        )

    @staticmethod
    def _check_port_range(port_range: str) -> List[tuple]:
        """Return list of (port_number, service_name) tuples that fall within a port range string."""
        flagged = []
        port_range = port_range.strip()
        if not port_range or port_range == "*":
            return [(p, s) for p, s in _DANGEROUS_PORTS.items()]
        try:
            if "-" in port_range:
                lo, hi = port_range.split("-", 1)
                lo_int, hi_int = int(lo), int(hi)
                for port_num, service in _DANGEROUS_PORTS.items():
                    if lo_int <= port_num <= hi_int:
                        flagged.append((port_num, service))
            else:
                port_num = int(port_range)
                if port_num in _DANGEROUS_PORTS:
                    flagged.append((port_num, _DANGEROUS_PORTS[port_num]))
        except ValueError:
            pass
        return flagged


# ---------------------------------------------------------------------------
# CloudSummaryTool
# ---------------------------------------------------------------------------


class CloudSummaryTool(BaseTool):
    """
    Cross-cloud risk summary aggregating findings from AWS, Azure, and/or GCP.

    Accepts raw finding lists (as dicts) per provider, calculates per-provider
    risk scores, ranks highest-risk areas, and returns a comparative report.

    Risk score formula:  critical×10 + high×5 + medium×2 + low×1
    """

    _SEVERITY_WEIGHTS: Dict[str, int] = {
        "critical": 10,
        "high": 5,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="cloud_summary",
            description=(
                "Generate a cross-cloud comparative risk summary from AWS, Azure, and/or GCP findings. "
                "Calculates risk scores and highlights highest-risk areas per provider."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "aws_findings": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of AWS finding dicts (each must have a 'severity' field)",
                        "default": [],
                    },
                    "azure_findings": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of Azure finding dicts (each must have a 'severity' field)",
                        "default": [],
                    },
                    "gcp_findings": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of GCP finding dicts (each must have a 'severity' field)",
                        "default": [],
                    },
                },
            },
        )

    async def execute(
        self,
        aws_findings: Optional[List[Dict[str, Any]]] = None,
        azure_findings: Optional[List[Dict[str, Any]]] = None,
        gcp_findings: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> str:
        providers: Dict[str, List[Dict[str, Any]]] = {}
        if aws_findings:
            providers["aws"] = aws_findings
        if azure_findings:
            providers["azure"] = azure_findings
        if gcp_findings:
            providers["gcp"] = gcp_findings

        if not providers:
            return json.dumps({
                "status": "no_data",
                "message": "No findings provided. Pass aws_findings, azure_findings, or gcp_findings.",
            })

        report = self._build_report(providers)
        return truncate_output(json.dumps(report, indent=2))

    def _build_report(self, providers: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        provider_summaries: Dict[str, Any] = {}
        overall_totals: Dict[str, int] = {s: 0 for s in self._SEVERITY_WEIGHTS}

        for provider, findings in providers.items():
            summary = self._summarise_provider(provider, findings)
            provider_summaries[provider] = summary
            for sev, count in summary["counts"].items():
                overall_totals[sev] = overall_totals.get(sev, 0) + count

        # Rank providers by risk score
        ranked = sorted(
            provider_summaries.items(),
            key=lambda kv: kv[1]["risk_score"],
            reverse=True,
        )
        highest_risk_provider = ranked[0][0] if ranked else "none"

        # Identify top issues across all providers
        all_issues: List[str] = []
        for findings in providers.values():
            for f in findings:
                sev = str(f.get("severity", "info")).lower()
                if sev in ("critical", "high"):
                    for issue in f.get("issues", []):
                        all_issues.append(issue)

        top_issues = list(dict.fromkeys(all_issues))[:10]  # deduplicate, keep order, cap at 10

        return {
            "status": "complete",
            "providers_scanned": list(providers.keys()),
            "highest_risk_provider": highest_risk_provider,
            "overall_totals": overall_totals,
            "overall_risk_score": sum(
                count * self._SEVERITY_WEIGHTS.get(sev, 0)
                for sev, count in overall_totals.items()
            ),
            "provider_summaries": provider_summaries,
            "top_critical_high_issues": top_issues,
        }

    def _summarise_provider(
        self, provider: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        counts: Dict[str, int] = {s: 0 for s in self._SEVERITY_WEIGHTS}
        highest_risk_areas: List[str] = []

        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

            if sev in ("critical", "high"):
                # Collect identifying info for top risks
                name = (
                    f.get("bucket_name")
                    or f.get("nsg_name")
                    or f.get("account_name")
                    or f.get("entity_name")
                    or f.get("function_name")
                    or f.get("group_id")
                    or "unknown"
                )
                area = f"{sev.upper()}: {name}"
                if area not in highest_risk_areas:
                    highest_risk_areas.append(area)

        risk_score = sum(
            counts[sev] * weight for sev, weight in self._SEVERITY_WEIGHTS.items()
        )

        return {
            "provider": provider,
            "total_findings": len(findings),
            "counts": counts,
            "risk_score": risk_score,
            "risk_level": self._score_to_level(risk_score),
            "highest_risk_areas": highest_risk_areas[:5],
        }

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 50:
            return "CRITICAL"
        if score >= 20:
            return "HIGH"
        if score >= 5:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "CLEAN"


# ---------------------------------------------------------------------------
# Public tool list
# ---------------------------------------------------------------------------

AZURE_TOOLS: List[BaseTool] = [
    AzureBlobEnumTool(),
    AzureADTool(),
    AzureNSGAuditTool(),
    CloudSummaryTool(),
]

__all__ = [
    "AzureBlobEnumTool",
    "AzureADTool",
    "AzureNSGAuditTool",
    "CloudSummaryTool",
    "AZURE_TOOLS",
    "AzureBlobFinding",
    "AzureADFinding",
    "AzureNSGFinding",
    "CloudFindingSeverity",
    "_get_azure_client",
    "_get_msgraph_client",
    "_get_azure_network_client",
]
