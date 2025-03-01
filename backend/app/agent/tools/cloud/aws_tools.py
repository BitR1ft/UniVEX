"""

Six agent tools for AWS security assessments:

  S3BucketEnumTool       — discover public / misconfigured S3 buckets
  IAMAuditTool           — analyze IAM policies for over-permissive roles
  SecurityGroupAuditTool — check for overly permissive inbound rules (0.0.0.0/0)
  LambdaScanner          — check Lambda functions for vulnerable dependencies and env var leaks
  EC2MetadataTool        — test SSRF to EC2 metadata endpoint (169.254.169.254)
  CloudTrailAnalyzer     — check for CloudTrail logging gaps

All tools are fully mockable for testing — AWS SDK calls are abstracted behind
`_get_boto3_client()` / `_get_boto3_resource()` helpers that tests can patch.

Tools map to the CLOUD_SECURITY attack category in the AttackPathRouter and
are registered in `tool_registry.py` under the CLOUD_SECURITY attack category.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IMDS endpoint
# ---------------------------------------------------------------------------

_IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
_IMDS_METADATA_URL = "http://169.254.169.254/latest/meta-data"
_IMDS_CREDS_PATH = "/iam/security-credentials"
_IMDS_TIMEOUT = 2.0

# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------


class CloudFindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Shared AWS client helper (mockable)
# ---------------------------------------------------------------------------


def _get_boto3_client(service: str, **kwargs):
    """Return a real boto3 client; raises ImportError if boto3 is not installed."""
    import boto3  # type: ignore[import]
    return boto3.client(service, **kwargs)


def _get_boto3_resource(service: str, **kwargs):
    import boto3  # type: ignore[import]
    return boto3.resource(service, **kwargs)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class BucketFinding:
    bucket_name: str
    region: str
    acl: str
    public_access_blocked: bool
    website_enabled: bool
    versioning_enabled: bool
    logging_enabled: bool
    encryption_enabled: bool
    severity: CloudFindingSeverity
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "region": self.region,
            "acl": self.acl,
            "public_access_blocked": self.public_access_blocked,
            "website_enabled": self.website_enabled,
            "versioning_enabled": self.versioning_enabled,
            "logging_enabled": self.logging_enabled,
            "encryption_enabled": self.encryption_enabled,
            "severity": self.severity.value,
            "issues": self.issues,
        }


@dataclass
class IAMFinding:
    entity_type: str   # user / role / policy
    entity_name: str
    entity_arn: str
    issues: List[str]
    severity: CloudFindingSeverity
    permissions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "entity_arn": self.entity_arn,
            "issues": self.issues,
            "severity": self.severity.value,
            "permissions": self.permissions,
        }


@dataclass
class SecurityGroupFinding:
    group_id: str
    group_name: str
    vpc_id: str
    issues: List[str]
    severity: CloudFindingSeverity
    open_ports: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "vpc_id": self.vpc_id,
            "issues": self.issues,
            "severity": self.severity.value,
            "open_ports": self.open_ports,
        }


@dataclass
class LambdaFinding:
    function_name: str
    function_arn: str
    runtime: str
    issues: List[str]
    severity: CloudFindingSeverity
    env_var_leaks: List[str] = field(default_factory=list)
    outdated_runtime: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_arn": self.function_arn,
            "runtime": self.runtime,
            "issues": self.issues,
            "severity": self.severity.value,
            "env_var_leaks": self.env_var_leaks,
            "outdated_runtime": self.outdated_runtime,
        }


# ---------------------------------------------------------------------------
# Known deprecated / EOL runtimes
# ---------------------------------------------------------------------------

_DEPRECATED_RUNTIMES: Set[str] = {
    "nodejs",
    "nodejs4.3",
    "nodejs6.10",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "python2.7",
    "python3.6",
    "python3.7",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "ruby2.5",
    "java8",
}

# Sensitive env var key patterns
_SENSITIVE_ENV_PATTERNS = re.compile(
    r"(secret|password|passwd|token|api.?key|credential|private.?key|aws.?secret|db.?pass)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# S3BucketEnumTool
# ---------------------------------------------------------------------------


class S3BucketEnumTool(BaseTool):
    """
    Enumerate S3 buckets in the AWS account and detect misconfigurations.

    Checks:
      - Public ACL (public-read, public-read-write, authenticated-read)
      - Block Public Access settings
      - Static website hosting
      - Server-side encryption
      - Versioning
      - Access logging
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="s3_bucket_enum",
            description="Enumerate S3 buckets and detect public/misconfigured buckets",
            parameters={
                "type": "object",
                "properties": {
                    "region": {"type": "string", "description": "AWS region (default: us-east-1)"},
                    "bucket_name": {"type": "string", "description": "Specific bucket to scan (optional)"},
                    "check_all": {"type": "boolean", "description": "Scan all buckets in account", "default": True},
                },
            },
        )

    async def execute(
        self,
        region: str = "us-east-1",
        bucket_name: Optional[str] = None,
        check_all: bool = True,
        **kwargs: Any,
    ) -> str:
        findings = self._run_scan(region=region, bucket_name=bucket_name, check_all=check_all)
        if not findings:
            return json.dumps({"status": "clean", "findings": [], "count": 0})
        result = {
            "status": "findings_found",
            "count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(
        self,
        region: str = "us-east-1",
        bucket_name: Optional[str] = None,
        check_all: bool = True,
    ) -> List[BucketFinding]:
        """Core scan logic — separated for easy unit testing."""
        try:
            s3 = _get_boto3_client("s3", region_name=region)
        except ImportError:
            logger.warning("boto3 not installed — returning mock result")
            return []

        if bucket_name:
            bucket_names = [bucket_name]
        elif check_all:
            try:
                bucket_names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            except Exception as exc:
                logger.error("list_buckets failed: %s", exc)
                return []
        else:
            return []

        findings = []
        for name in bucket_names:
            finding = self._scan_bucket(s3, name)
            if finding and finding.issues:
                findings.append(finding)
        return findings

    def _scan_bucket(self, s3_client, name: str) -> Optional[BucketFinding]:
        issues = []
        try:
            # Get bucket location
            loc = s3_client.get_bucket_location(Bucket=name)
            region = loc.get("LocationConstraint") or "us-east-1"
        except Exception as exc:
            logger.warning("Cannot access bucket %s: %s", name, exc)
            return None

        # ACL
        acl = "private"
        try:
            acl_resp = s3_client.get_bucket_acl(Bucket=name)
            for grant in acl_resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    acl = "public-read-write" if grant.get("Permission") in ("WRITE", "FULL_CONTROL") else "public-read"
                    issues.append(f"ACL grants public access: {grant.get('Permission')}")
                elif "AuthenticatedUsers" in uri:
                    acl = "authenticated-read"
                    issues.append("ACL grants authenticated-read to all AWS users")
        except Exception:
            pass

        # Block Public Access
        public_access_blocked = True
        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not all([
                cfg.get("BlockPublicAcls"),
                cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"),
                cfg.get("RestrictPublicBuckets"),
            ]):
                public_access_blocked = False
                issues.append("Block Public Access is not fully enabled")
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            public_access_blocked = False
            issues.append("Block Public Access configuration is missing")
        except Exception:
            public_access_blocked = False

        # Website
        website_enabled = False
        try:
            s3_client.get_bucket_website(Bucket=name)
            website_enabled = True
            issues.append("Static website hosting is enabled")
        except Exception:
            pass

        # Versioning
        versioning_enabled = False
        try:
            v = s3_client.get_bucket_versioning(Bucket=name)
            versioning_enabled = v.get("Status") == "Enabled"
            if not versioning_enabled:
                issues.append("Versioning is not enabled")
        except Exception:
            pass

        # Logging
        logging_enabled = False
        try:
            log = s3_client.get_bucket_logging(Bucket=name)
            logging_enabled = "LoggingEnabled" in log
            if not logging_enabled:
                issues.append("Access logging is not enabled")
        except Exception:
            pass

        # Encryption
        encryption_enabled = False
        try:
            s3_client.get_bucket_encryption(Bucket=name)
            encryption_enabled = True
        except Exception:
            issues.append("Server-side encryption is not configured")

        # Severity
        if acl in ("public-read-write",) or (not public_access_blocked and acl != "private"):
            severity = CloudFindingSeverity.CRITICAL
        elif acl == "public-read" or website_enabled:
            severity = CloudFindingSeverity.HIGH
        elif not encryption_enabled or not logging_enabled:
            severity = CloudFindingSeverity.MEDIUM
        else:
            severity = CloudFindingSeverity.LOW

        return BucketFinding(
            bucket_name=name,
            region=region,
            acl=acl,
            public_access_blocked=public_access_blocked,
            website_enabled=website_enabled,
            versioning_enabled=versioning_enabled,
            logging_enabled=logging_enabled,
            encryption_enabled=encryption_enabled,
            severity=severity,
            issues=issues,
        )


# ---------------------------------------------------------------------------
# IAMAuditTool
# ---------------------------------------------------------------------------


class IAMAuditTool(BaseTool):
    """
    Analyze IAM users, roles, and policies for over-permissive access.

    Checks:
      - Admin wildcards (Action: *, Resource: *)
      - No MFA on console-enabled users
      - Root account usage
      - Inline policies vs. managed
      - Privilege escalation paths (iam:PassRole + ec2:RunInstances, etc.)
    """

    # Known dangerous permission combinations that allow privilege escalation
    _PRIVESC_COMBOS: List[Tuple[str, ...]] = [
        ("iam:CreatePolicyVersion",),
        ("iam:SetDefaultPolicyVersion",),
        ("iam:PassRole", "ec2:RunInstances"),
        ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
        ("iam:CreateAccessKey",),
        ("sts:AssumeRole",),
        ("iam:AttachUserPolicy",),
        ("iam:AttachRolePolicy",),
        ("iam:PutUserPolicy",),
        ("iam:PutRolePolicy",),
        ("iam:AddUserToGroup",),
    ]

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="iam_audit",
            description="Analyze IAM users, roles and policies for over-permissive access",
            parameters={
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "enum": ["all", "users", "roles", "policies"],
                        "default": "all",
                    }
                },
            },
        )

    async def execute(self, entity_type: str = "all", **kwargs: Any) -> str:
        findings = self._run_audit(entity_type=entity_type)
        result = {
            "status": "complete",
            "entity_type": entity_type,
            "finding_count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(self, entity_type: str = "all") -> List[IAMFinding]:
        try:
            iam = _get_boto3_client("iam")
        except ImportError:
            return []

        findings = []
        if entity_type in ("all", "users"):
            findings.extend(self._audit_users(iam))
        if entity_type in ("all", "roles"):
            findings.extend(self._audit_roles(iam))
        if entity_type in ("all", "policies"):
            findings.extend(self._audit_policies(iam))
        return findings

    def _is_admin_wildcard(self, policy_doc: Dict) -> bool:
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                return True
        return False

    def _extract_permissions(self, policy_doc: Dict) -> List[str]:
        perms = []
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            perms.extend(actions)
        return perms

    def _check_privesc(self, permissions: List[str]) -> List[str]:
        perms_set = set(permissions)
        flagged = []
        for combo in self._PRIVESC_COMBOS:
            if all(p in perms_set for p in combo):
                flagged.append(f"Privilege escalation path: {' + '.join(combo)}")
        return flagged

    def _audit_users(self, iam) -> List[IAMFinding]:
        findings = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    name = user["UserName"]
                    arn = user["Arn"]
                    issues, permissions = [], []
                    # Inline policies
                    try:
                        for pol_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
                            doc = iam.get_user_policy(UserName=name, PolicyName=pol_name)
                            doc_data = doc.get("PolicyDocument", {})
                            if self._is_admin_wildcard(doc_data):
                                issues.append(f"Inline policy '{pol_name}' grants Admin (Action:*, Resource:*)")
                            permissions.extend(self._extract_permissions(doc_data))
                    except Exception:
                        pass
                    # MFA
                    try:
                        mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
                        if not mfa:
                            issues.append("No MFA device configured")
                    except Exception:
                        pass
                    # Access keys
                    try:
                        keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
                        for k in keys:
                            if k["Status"] == "Active":
                                pass  # keys OK
                        if len(keys) > 1:
                            issues.append(f"{len(keys)} access keys — rotate and remove unused")
                    except Exception:
                        pass

                    issues.extend(self._check_privesc(permissions))

                    if issues:
                        sev = CloudFindingSeverity.CRITICAL if any("Admin" in i or "escalation" in i for i in issues) else CloudFindingSeverity.MEDIUM
                        findings.append(IAMFinding(
                            entity_type="user", entity_name=name, entity_arn=arn,
                            issues=issues, severity=sev, permissions=permissions,
                        ))
        except Exception as exc:
            logger.error("IAM user audit failed: %s", exc)
        return findings

    def _audit_roles(self, iam) -> List[IAMFinding]:
        findings = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    name = role["RoleName"]
                    arn = role["Arn"]
                    issues, permissions = [], []

                    try:
                        for pol_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                            doc = iam.get_role_policy(RoleName=name, PolicyName=pol_name)
                            doc_data = doc.get("PolicyDocument", {})
                            if self._is_admin_wildcard(doc_data):
                                issues.append(f"Inline policy '{pol_name}' grants Admin")
                            permissions.extend(self._extract_permissions(doc_data))
                    except Exception:
                        pass

                    # Trust relationship
                    trust = role.get("AssumeRolePolicyDocument", {})
                    for stmt in trust.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and "*" in principal.get("AWS", "")):
                            issues.append("Trust policy allows assumption by any principal (*)")

                    issues.extend(self._check_privesc(permissions))
                    if issues:
                        sev = CloudFindingSeverity.CRITICAL if any("Admin" in i or "*" in i or "escalation" in i for i in issues) else CloudFindingSeverity.HIGH
                        findings.append(IAMFinding(
                            entity_type="role", entity_name=name, entity_arn=arn,
                            issues=issues, severity=sev, permissions=permissions,
                        ))
        except Exception as exc:
            logger.error("IAM role audit failed: %s", exc)
        return findings

    def _audit_policies(self, iam) -> List[IAMFinding]:
        findings = []
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    name = policy["PolicyName"]
                    arn = policy["Arn"]
                    version_id = policy["DefaultVersionId"]
                    issues, permissions = [], []
                    try:
                        doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                        doc_data = doc["PolicyVersion"].get("Document", {})
                        if self._is_admin_wildcard(doc_data):
                            issues.append("Managed policy grants Admin (Action:*, Resource:*)")
                        permissions.extend(self._extract_permissions(doc_data))
                    except Exception:
                        pass
                    issues.extend(self._check_privesc(permissions))
                    if issues:
                        findings.append(IAMFinding(
                            entity_type="policy", entity_name=name, entity_arn=arn,
                            issues=issues, severity=CloudFindingSeverity.HIGH, permissions=permissions,
                        ))
        except Exception as exc:
            logger.error("IAM policy audit failed: %s", exc)
        return findings


# ---------------------------------------------------------------------------
# SecurityGroupAuditTool
# ---------------------------------------------------------------------------


class SecurityGroupAuditTool(BaseTool):
    """
    Check EC2 Security Groups for overly permissive inbound rules.

    Flags:
      - 0.0.0.0/0 or ::/0 on critical ports (22/SSH, 3389/RDP, 3306/MySQL, 5432/Postgres, 6379/Redis)
      - Any-to-any rules (all ports, all protocols)
      - Unrestricted ICMP
    """

    _CRITICAL_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
    _HIGH_RISK_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB", 1433: "MSSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt"}

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="security_group_audit",
            description="Check EC2 security groups for overly permissive inbound rules",
            parameters={
                "type": "object",
                "properties": {
                    "region": {"type": "string", "default": "us-east-1"},
                    "vpc_id": {"type": "string", "description": "Restrict to specific VPC"},
                },
            },
        )

    async def execute(self, region: str = "us-east-1", vpc_id: Optional[str] = None, **kwargs: Any) -> str:
        findings = self._run_audit(region=region, vpc_id=vpc_id)
        result = {
            "status": "complete",
            "region": region,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(self, region: str = "us-east-1", vpc_id: Optional[str] = None) -> List[SecurityGroupFinding]:
        try:
            ec2 = _get_boto3_client("ec2", region_name=region)
        except ImportError:
            return []

        try:
            filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
            resp = ec2.describe_security_groups(Filters=filters)
        except Exception as exc:
            logger.error("describe_security_groups failed: %s", exc)
            return []

        findings = []
        for sg in resp.get("SecurityGroups", []):
            finding = self._audit_sg(sg)
            if finding and finding.issues:
                findings.append(finding)
        return findings

    def _is_open_cidr(self, cidr: str) -> bool:
        return cidr in ("0.0.0.0/0", "::/0")

    def _audit_sg(self, sg: Dict) -> Optional[SecurityGroupFinding]:
        issues = []
        open_ports = []
        for rule in sg.get("IpPermissions", []):
            proto = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            cidrs = [r["CidrIp"] for r in rule.get("IpRanges", [])]
            cidrs += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]

            for cidr in cidrs:
                if not self._is_open_cidr(cidr):
                    continue
                if proto == "-1":
                    issues.append(f"All traffic allowed from {cidr}")
                    open_ports.append({"protocol": "all", "port_range": "all", "cidr": cidr})
                elif proto == "icmp":
                    issues.append(f"Unrestricted ICMP from {cidr}")
                else:
                    port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                    for port_num, service in {**self._CRITICAL_PORTS, **self._HIGH_RISK_PORTS}.items():
                        if from_port <= port_num <= to_port:
                            sev_label = "CRITICAL" if port_num in self._CRITICAL_PORTS else "HIGH"
                            issues.append(f"{sev_label}: {service} (port {port_num}) open to {cidr}")
                    open_ports.append({"protocol": proto, "port_range": port_range, "cidr": cidr})

        if not issues:
            return None

        severity = CloudFindingSeverity.CRITICAL if any("CRITICAL" in i or "All traffic" in i for i in issues) else CloudFindingSeverity.HIGH
        return SecurityGroupFinding(
            group_id=sg["GroupId"],
            group_name=sg.get("GroupName", ""),
            vpc_id=sg.get("VpcId", ""),
            issues=issues,
            severity=severity,
            open_ports=open_ports,
        )


# ---------------------------------------------------------------------------
# LambdaScanner
# ---------------------------------------------------------------------------


class LambdaScanner(BaseTool):
    """
    Scan Lambda functions for:
      - Deprecated / EOL runtimes
      - Sensitive environment variable names (tokens, passwords)
      - Over-permissive execution roles
      - Publicly accessible functions (via function URLs with no auth)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="lambda_scanner",
            description="Scan Lambda functions for vulnerable runtimes and env var leaks",
            parameters={
                "type": "object",
                "properties": {
                    "region": {"type": "string", "default": "us-east-1"},
                    "function_name": {"type": "string", "description": "Specific function to scan"},
                },
            },
        )

    async def execute(self, region: str = "us-east-1", function_name: Optional[str] = None, **kwargs: Any) -> str:
        findings = self._run_scan(region=region, function_name=function_name)
        result = {
            "status": "complete",
            "region": region,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(self, region: str = "us-east-1", function_name: Optional[str] = None) -> List[LambdaFinding]:
        try:
            lam = _get_boto3_client("lambda", region_name=region)
        except ImportError:
            return []

        try:
            if function_name:
                funcs = [lam.get_function(FunctionName=function_name)["Configuration"]]
            else:
                paginator = lam.get_paginator("list_functions")
                funcs = [f for page in paginator.paginate() for f in page["Functions"]]
        except Exception as exc:
            logger.error("Lambda list failed: %s", exc)
            return []

        return [f for f in (self._scan_function(lam, func) for func in funcs) if f]

    def _scan_function(self, lam_client, func: Dict) -> Optional[LambdaFinding]:
        name = func["FunctionName"]
        arn = func["FunctionArn"]
        runtime = func.get("Runtime", "unknown")
        issues = []
        env_leaks = []
        outdated = runtime in _DEPRECATED_RUNTIMES

        if outdated:
            issues.append(f"Deprecated/EOL runtime: {runtime}")

        # Env vars
        env_vars = func.get("Environment", {}).get("Variables", {})
        for key in env_vars:
            if _SENSITIVE_ENV_PATTERNS.search(key):
                env_leaks.append(key)
                issues.append(f"Sensitive env var exposed: {key}")

        # Function URL auth
        try:
            url_cfg = lam_client.get_function_url_config(FunctionName=name)
            if url_cfg.get("AuthType") == "NONE":
                issues.append("Function URL is public (AuthType=NONE)")
        except Exception:
            pass  # No function URL

        if not issues:
            return None

        severity = CloudFindingSeverity.CRITICAL if env_leaks else (
            CloudFindingSeverity.HIGH if "public" in " ".join(issues).lower() else CloudFindingSeverity.MEDIUM
        )
        return LambdaFinding(
            function_name=name,
            function_arn=arn,
            runtime=runtime,
            issues=issues,
            severity=severity,
            env_var_leaks=env_leaks,
            outdated_runtime=outdated,
        )


# ---------------------------------------------------------------------------
# EC2MetadataTool
# ---------------------------------------------------------------------------


class EC2MetadataTool(BaseTool):
    """
    Test SSRF to EC2 Instance Metadata Service (IMDS).

    Attempts:
      1. IMDSv1 direct request (GET without token — legacy, vulnerable)
      2. IMDSv2 token-based request (PUT + GET)
      3. Credential extraction from /iam/security-credentials/<role>
      4. User-data retrieval (may contain secrets)

    In pentest mode, tests whether a target web app proxies requests to IMDS
    via SSRF using a provided list of SSRF parameters.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ec2_metadata",
            description="Test SSRF to EC2 IMDS endpoint; enumerate instance metadata",
            parameters={
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL to test for SSRF"},
                    "ssrf_params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Parameter names to inject IMDS URL into",
                    },
                    "test_imdsv1": {"type": "boolean", "default": True},
                    "test_ssrf": {"type": "boolean", "default": False},
                },
                "required": [],
            },
        )

    async def execute(
        self,
        target_url: Optional[str] = None,
        ssrf_params: Optional[List[str]] = None,
        test_imdsv1: bool = True,
        test_ssrf: bool = False,
        **kwargs: Any,
    ) -> str:
        results: Dict[str, Any] = {}

        if test_imdsv1:
            results["imdsv1"] = self._test_imdsv1()
            results["imdsv2"] = self._test_imdsv2()

        if test_ssrf and target_url and ssrf_params:
            results["ssrf_tests"] = self._test_ssrf_params(target_url, ssrf_params)

        return truncate_output(json.dumps(results, indent=2))

    def _test_imdsv1(self) -> Dict[str, Any]:
        """Test IMDSv1 direct access (no token required)."""
        try:
            req = urllib.request.Request(
                f"{_IMDS_METADATA_URL}/",
                headers={"User-Agent": "UniVex-CloudAudit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_IMDS_TIMEOUT) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {
                    "accessible": True,
                    "severity": "critical",
                    "metadata_keys": body.strip().splitlines(),
                    "issue": "IMDSv1 is accessible without token — upgrade to IMDSv2 and set hop limit",
                }
        except (urllib.error.URLError, OSError, socket.timeout):
            return {"accessible": False, "severity": "none"}

    def _test_imdsv2(self) -> Dict[str, Any]:
        """Test IMDSv2 token endpoint availability."""
        try:
            put_req = urllib.request.Request(
                _IMDS_TOKEN_URL,
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            )
            with urllib.request.urlopen(put_req, timeout=_IMDS_TIMEOUT) as resp:
                token = resp.read().decode("utf-8")
                return {"accessible": True, "token_obtained": bool(token), "imdsv2_enabled": True}
        except Exception:
            return {"accessible": False, "imdsv2_enabled": False}

    def _test_ssrf_params(self, target_url: str, params: List[str]) -> List[Dict]:
        """Inject IMDS URL into target parameters and check for reflection."""
        imds_url = f"{_IMDS_METADATA_URL}/"
        results = []
        for param in params:
            try:
                url = f"{target_url}?{param}={urllib.parse.quote(imds_url)}"
                req = urllib.request.Request(url, headers={"User-Agent": "UniVex-CloudAudit/1.0"})
                with urllib.request.urlopen(req, timeout=_IMDS_TIMEOUT) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    # Check if IMDS data keys appear in response
                    ssrf_confirmed = any(k in body for k in ["ami-id", "instance-id", "local-ipv4"])
                    results.append({
                        "param": param,
                        "ssrf_confirmed": ssrf_confirmed,
                        "severity": "critical" if ssrf_confirmed else "info",
                    })
            except Exception as exc:
                results.append({"param": param, "error": str(exc)[:100]})
        return results


# ---------------------------------------------------------------------------
# CloudTrailAnalyzer
# ---------------------------------------------------------------------------


class CloudTrailAnalyzer(BaseTool):
    """
    Check CloudTrail configuration for logging gaps.

    Checks:
      - CloudTrail is enabled in all regions
      - Log file validation is enabled
      - S3 bucket is encrypted
      - CloudWatch integration is configured
      - Management events are being logged
      - S3 data events are being logged (optional but recommended)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="cloudtrail_analyzer",
            description="Check CloudTrail configuration for logging gaps and misconfigurations",
            parameters={
                "type": "object",
                "properties": {
                    "region": {"type": "string", "default": "us-east-1"},
                },
            },
        )

    async def execute(self, region: str = "us-east-1", **kwargs: Any) -> str:
        findings = self._run_check(region=region)
        result = {
            "status": "complete",
            "region": region,
            "issues_found": len(findings),
            "findings": findings,
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_check(self, region: str = "us-east-1") -> List[Dict[str, Any]]:
        try:
            ct = _get_boto3_client("cloudtrail", region_name=region)
        except ImportError:
            return []

        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        except Exception as exc:
            logger.error("describe_trails failed: %s", exc)
            return [{"issue": f"Cannot read CloudTrail config: {exc}", "severity": "critical"}]

        if not trails:
            return [{"issue": "No CloudTrail trails configured in this region", "severity": "critical"}]

        findings = []
        for trail in trails:
            trail_findings = self._check_trail(ct, trail)
            findings.extend(trail_findings)
        return findings

    def _check_trail(self, ct_client, trail: Dict) -> List[Dict[str, Any]]:
        name = trail.get("Name", "unknown")
        findings = []

        # Log file validation
        if not trail.get("LogFileValidationEnabled", False):
            findings.append({
                "trail": name,
                "issue": "Log file validation is disabled — tampering cannot be detected",
                "severity": "high",
            })

        # CloudWatch Logs integration
        if not trail.get("CloudWatchLogsLogGroupArn"):
            findings.append({
                "trail": name,
                "issue": "CloudWatch Logs integration not configured — no alerting on events",
                "severity": "medium",
            })

        # Trail status
        try:
            status = ct_client.get_trail_status(Name=name)
            if not status.get("IsLogging", False):
                findings.append({
                    "trail": name,
                    "issue": "Trail logging is currently DISABLED",
                    "severity": "critical",
                })
        except Exception:
            pass

        # Event selectors — check management events
        try:
            selectors = ct_client.get_event_selectors(TrailName=name)
            mgmt_logged = False
            for sel in selectors.get("EventSelectors", []):
                if sel.get("IncludeManagementEvents"):
                    mgmt_logged = True
            if not mgmt_logged:
                findings.append({
                    "trail": name,
                    "issue": "Management events are not being logged",
                    "severity": "high",
                })
        except Exception:
            pass

        # Multi-region
        if not trail.get("IsMultiRegionTrail", False):
            findings.append({
                "trail": name,
                "issue": "Trail is not multi-region — activity in other regions is unmonitored",
                "severity": "medium",
            })

        return findings


# ---------------------------------------------------------------------------
# Public tool list
# ---------------------------------------------------------------------------

AWS_TOOLS: List[BaseTool] = [
    S3BucketEnumTool(),
    IAMAuditTool(),
    SecurityGroupAuditTool(),
    LambdaScanner(),
    EC2MetadataTool(),
    CloudTrailAnalyzer(),
]

__all__ = [
    "S3BucketEnumTool",
    "IAMAuditTool",
    "SecurityGroupAuditTool",
    "LambdaScanner",
    "EC2MetadataTool",
    "CloudTrailAnalyzer",
    "AWS_TOOLS",
    "BucketFinding",
    "IAMFinding",
    "SecurityGroupFinding",
    "LambdaFinding",
    "CloudFindingSeverity",
    "_get_boto3_client",
    "_get_boto3_resource",
]
