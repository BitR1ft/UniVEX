"""

Coverage:
  TestS3BucketEnumTool        (15 tests)
  TestIAMAuditTool             (15 tests)
  TestSecurityGroupAuditTool   (12 tests)
  TestLambdaScanner            (12 tests)
  TestEC2MetadataTool          (8 tests)
  TestCloudTrailAnalyzer       (10 tests)
  TestCloudMCPServer           (10 tests)

Total: 82 tests — all using mocked boto3 (moto-style) via unittest.mock
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from app.agent.tools.cloud.aws_tools import (
    AWS_TOOLS,
    BucketFinding,
    CloudFindingSeverity,
    CloudTrailAnalyzer,
    EC2MetadataTool,
    IAMAuditTool,
    IAMFinding,
    LambdaFinding,
    LambdaScanner,
    S3BucketEnumTool,
    SecurityGroupAuditTool,
    SecurityGroupFinding,
    _DEPRECATED_RUNTIMES,
    _SENSITIVE_ENV_PATTERNS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_s3_client(
    buckets: Optional[List[Dict]] = None,
    acl_grants: Optional[List[Dict]] = None,
    public_access_blocked: bool = True,
    website: bool = False,
    versioning: str = "Enabled",
    logging_enabled: bool = True,
    encryption: bool = True,
):
    """Build a mock S3 client for testing."""
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": buckets or [{"Name": "test-bucket"}]}
    client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

    grants = acl_grants or []
    client.get_bucket_acl.return_value = {"Grants": grants}

    if public_access_blocked:
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    else:
        exc_cls = type("NoSuchPublicAccessBlockConfiguration", (Exception,), {})
        client.exceptions = MagicMock()
        client.exceptions.NoSuchPublicAccessBlockConfiguration = exc_cls
        client.get_public_access_block.side_effect = exc_cls("Not configured")

    if website:
        client.get_bucket_website.return_value = {"WebsiteConfiguration": {}}
    else:
        client.get_bucket_website.side_effect = Exception("NoSuchWebsiteConfiguration")

    client.get_bucket_versioning.return_value = {"Status": versioning if versioning else "Suspended"}

    if logging_enabled:
        client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs-bucket"}}
    else:
        client.get_bucket_logging.return_value = {}

    if encryption:
        client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        }
    else:
        client.get_bucket_encryption.side_effect = Exception("ServerSideEncryptionConfigurationNotFoundError")

    return client


def _make_paginator(items: List[Dict], key: str):
    """Return a mock paginator with one page."""
    pag = MagicMock()
    pag.paginate.return_value = [{key: items}]
    return pag


def _policy_doc(allow_all: bool = False) -> Dict:
    if allow_all:
        return {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    return {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]}


# ---------------------------------------------------------------------------
# TestS3BucketEnumTool
# ---------------------------------------------------------------------------


class TestS3BucketEnumTool:
    def setup_method(self):
        self.tool = S3BucketEnumTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "s3_bucket_enum"

    def test_metadata_description_non_empty(self):
        assert len(self.tool.metadata.description) > 5

    def test_clean_bucket_no_findings(self):
        s3 = _make_s3_client(public_access_blocked=True, encryption=True, logging_enabled=True)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="clean-bucket")
        assert findings == [] or all(not f.issues for f in findings)

    def test_public_acl_flagged(self):
        grants = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]
        s3 = _make_s3_client(public_access_blocked=False, acl_grants=grants)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="public-bucket")
        assert len(findings) > 0
        assert any("public" in i.lower() or "acl" in i.lower() or "ACL" in i for f in findings for i in f.issues)

    def test_encryption_missing_flagged(self):
        s3 = _make_s3_client(encryption=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="no-enc-bucket")
        assert any("encryption" in i.lower() for f in findings for i in f.issues)

    def test_logging_missing_flagged(self):
        s3 = _make_s3_client(logging_enabled=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="no-log-bucket")
        assert any("logging" in i.lower() for f in findings for i in f.issues)

    def test_website_enabled_flagged(self):
        s3 = _make_s3_client(website=True)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="web-bucket")
        assert any("website" in i.lower() for f in findings for i in f.issues)

    def test_bucket_finding_to_dict(self):
        finding = BucketFinding(
            bucket_name="test", region="us-east-1", acl="private",
            public_access_blocked=False, website_enabled=False, versioning_enabled=True,
            logging_enabled=False, encryption_enabled=False,
            severity=CloudFindingSeverity.MEDIUM, issues=["No logging"],
        )
        d = finding.to_dict()
        assert d["bucket_name"] == "test"
        assert "issues" in d

    def test_inaccessible_bucket_skipped(self):
        s3 = _make_s3_client()
        s3.get_bucket_location.side_effect = Exception("Access Denied")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="forbidden-bucket")
        assert findings == []

    def test_list_all_buckets(self):
        s3 = _make_s3_client(buckets=[{"Name": "b1"}, {"Name": "b2"}])
        s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(check_all=True)
        # May or may not have findings depending on mock defaults
        assert isinstance(findings, list)

    def test_execute_returns_json(self):
        s3 = _make_s3_client()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            result = asyncio.run(self.tool.execute(bucket_name="test-bucket"))
        parsed = json.loads(result)
        assert "status" in parsed

    def test_execute_no_boto3(self):
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", side_effect=ImportError("No boto3")):
            result = asyncio.run(self.tool.execute(bucket_name="test"))
        parsed = json.loads(result)
        assert parsed["status"] in ("clean", "findings_found")

    def test_severity_public_readwrite_is_critical(self):
        grants = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "FULL_CONTROL"}]
        s3 = _make_s3_client(public_access_blocked=False, acl_grants=grants)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(bucket_name="rw-bucket")
        if findings:
            assert findings[0].severity == CloudFindingSeverity.CRITICAL

    def test_aws_tools_list(self):
        assert len(AWS_TOOLS) == 6

    def test_check_all_false_returns_empty(self):
        s3 = MagicMock()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(check_all=False)
        assert findings == []

    def test_list_buckets_error(self):
        s3 = MagicMock()
        s3.list_buckets.side_effect = Exception("Access Denied")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            findings = self.tool._run_scan(check_all=True)
        assert findings == []


# ---------------------------------------------------------------------------
# TestIAMAuditTool
# ---------------------------------------------------------------------------


class TestIAMAuditTool:
    def setup_method(self):
        self.tool = IAMAuditTool()

    def _make_iam(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator([], "Users")
        return iam

    def test_metadata_name(self):
        assert self.tool.metadata.name == "iam_audit"

    def test_admin_wildcard_detection(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        assert self.tool._is_admin_wildcard(doc) is True

    def test_restricted_policy_not_admin(self):
        doc = _policy_doc(allow_all=False)
        assert self.tool._is_admin_wildcard(doc) is False

    def test_extract_permissions(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}]}
        perms = self.tool._extract_permissions(doc)
        assert "s3:GetObject" in perms

    def test_extract_permissions_string_action(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}]}
        perms = self.tool._extract_permissions(doc)
        assert "iam:CreateAccessKey" in perms

    def test_privesc_createaccesskey(self):
        perms = ["iam:CreateAccessKey", "s3:GetObject"]
        issues = self.tool._check_privesc(perms)
        assert any("CreateAccessKey" in i for i in issues)

    def test_privesc_passrole_combo(self):
        perms = ["iam:PassRole", "ec2:RunInstances"]
        issues = self.tool._check_privesc(perms)
        assert any("escalation" in i.lower() for i in issues)

    def test_no_privesc_clean_perms(self):
        perms = ["s3:GetObject", "s3:ListBucket", "cloudwatch:GetMetricData"]
        issues = self.tool._check_privesc(perms)
        assert issues == []

    def test_audit_users_admin_policy(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator(
            [{"UserName": "admin", "Arn": "arn:aws:iam::123:user/admin"}], "Users"
        )
        iam.list_user_policies.return_value = {"PolicyNames": ["AdminPolicy"]}
        iam.get_user_policy.return_value = {"PolicyDocument": _policy_doc(allow_all=True)}
        iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:...", "UserName": "admin"}]}
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{"Status": "Active"}]}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=iam):
            findings = self.tool._run_audit(entity_type="users")
        assert len(findings) > 0
        assert findings[0].severity == CloudFindingSeverity.CRITICAL

    def test_audit_users_no_mfa(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator(
            [{"UserName": "user1", "Arn": "arn:aws:iam::123:user/user1"}], "Users"
        )
        iam.list_user_policies.return_value = {"PolicyNames": []}
        iam.list_mfa_devices.return_value = {"MFADevices": []}
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{"Status": "Active"}]}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=iam):
            findings = self.tool._run_audit(entity_type="users")
        assert any("MFA" in i for f in findings for i in f.issues)

    def test_audit_roles_wildcard_trust(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator(
            [{"RoleName": "open-role", "Arn": "arn:aws:iam::123:role/open-role",
              "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}}],
            "Roles"
        )
        iam.list_role_policies.return_value = {"PolicyNames": []}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=iam):
            findings = self.tool._run_audit(entity_type="roles")
        assert any("*" in i or "any principal" in i.lower() for f in findings for i in f.issues)

    def test_audit_policies_admin(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator(
            [{"PolicyName": "SuperAdmin", "Arn": "arn:aws:iam::123:policy/SuperAdmin", "DefaultVersionId": "v1"}],
            "Policies"
        )
        iam.get_policy_version.return_value = {"PolicyVersion": {"Document": _policy_doc(allow_all=True)}}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=iam):
            findings = self.tool._run_audit(entity_type="policies")
        assert len(findings) > 0

    def test_iam_finding_to_dict(self):
        f = IAMFinding(
            entity_type="user", entity_name="admin", entity_arn="arn:aws:iam::123:user/admin",
            issues=["Admin policy"], severity=CloudFindingSeverity.CRITICAL,
        )
        d = f.to_dict()
        assert d["entity_type"] == "user"
        assert "issues" in d

    def test_execute_returns_json(self):
        iam = MagicMock()
        iam.get_paginator.return_value = _make_paginator([], "Users")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=iam):
            result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert "status" in parsed

    def test_no_boto3_returns_empty(self):
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", side_effect=ImportError):
            findings = self.tool._run_audit()
        assert findings == []


# ---------------------------------------------------------------------------
# TestSecurityGroupAuditTool
# ---------------------------------------------------------------------------


def _make_ec2_client(security_groups: Optional[List[Dict]] = None):
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": security_groups or []}
    return ec2


def _open_sg(port: int, proto: str = "tcp") -> Dict:
    return {
        "GroupId": f"sg-{port:05d}",
        "GroupName": f"open-{port}",
        "VpcId": "vpc-12345",
        "IpPermissions": [{
            "IpProtocol": proto,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }],
    }


class TestSecurityGroupAuditTool:
    def setup_method(self):
        self.tool = SecurityGroupAuditTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "security_group_audit"

    def test_open_ssh_flagged(self):
        ec2 = _make_ec2_client([_open_sg(22)])
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert len(findings) > 0
        assert any("SSH" in i for f in findings for i in f.issues)

    def test_open_rdp_flagged(self):
        ec2 = _make_ec2_client([_open_sg(3389)])
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert any("RDP" in i for f in findings for i in f.issues)

    def test_all_traffic_critical(self):
        sg = {
            "GroupId": "sg-all", "GroupName": "all-traffic", "VpcId": "vpc-1",
            "IpPermissions": [{
                "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
            }],
        }
        ec2 = _make_ec2_client([sg])
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert findings[0].severity == CloudFindingSeverity.CRITICAL

    def test_restricted_sg_not_flagged(self):
        sg = {
            "GroupId": "sg-restricted", "GroupName": "restricted", "VpcId": "vpc-1",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": [],
            }],
        }
        ec2 = _make_ec2_client([sg])
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert findings == []

    def test_sg_finding_to_dict(self):
        f = SecurityGroupFinding(
            group_id="sg-1", group_name="test", vpc_id="vpc-1",
            issues=["SSH open"], severity=CloudFindingSeverity.HIGH,
        )
        d = f.to_dict()
        assert "group_id" in d and "issues" in d

    def test_is_open_cidr_ipv4(self):
        assert self.tool._is_open_cidr("0.0.0.0/0") is True

    def test_is_open_cidr_ipv6(self):
        assert self.tool._is_open_cidr("::/0") is True

    def test_is_open_cidr_private(self):
        assert self.tool._is_open_cidr("10.0.0.0/8") is False

    def test_execute_returns_json(self):
        ec2 = _make_ec2_client()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert "status" in parsed

    def test_open_mysql_flagged(self):
        ec2 = _make_ec2_client([_open_sg(3306)])
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert any("MySQL" in i or "3306" in i for f in findings for i in f.issues)

    def test_describe_sg_error(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.side_effect = Exception("Access Denied")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ec2):
            findings = self.tool._run_audit()
        assert findings == []

    def test_no_boto3_returns_empty(self):
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", side_effect=ImportError):
            findings = self.tool._run_audit()
        assert findings == []


# ---------------------------------------------------------------------------
# TestLambdaScanner
# ---------------------------------------------------------------------------


def _make_lambda_func(
    name: str = "test-fn",
    runtime: str = "python3.11",
    env_vars: Optional[Dict] = None,
) -> Dict:
    return {
        "FunctionName": name,
        "FunctionArn": f"arn:aws:lambda:us-east-1:123456789:function:{name}",
        "Runtime": runtime,
        "Environment": {"Variables": env_vars or {}},
    }


class TestLambdaScanner:
    def setup_method(self):
        self.tool = LambdaScanner()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "lambda_scanner"

    def test_deprecated_runtime_flagged(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func(runtime="python3.6")], "Functions"
        )
        lam.get_function_url_config.side_effect = Exception("No URL config")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        assert any("python3.6" in i or "Deprecated" in i for f in findings for i in f.issues)

    def test_modern_runtime_not_flagged(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func(runtime="python3.11")], "Functions"
        )
        lam.get_function_url_config.side_effect = Exception("No URL config")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        # Modern runtime — no runtime issue
        assert not any("python3.11" in i for f in findings for i in f.issues)

    def test_sensitive_env_var_flagged(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func(env_vars={"DB_PASSWORD": "secret123", "APP_NAME": "app"})], "Functions"
        )
        lam.get_function_url_config.side_effect = Exception("No URL config")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        assert any("DB_PASSWORD" in i for f in findings for i in f.issues)

    def test_api_key_env_var_flagged(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func(env_vars={"STRIPE_API_KEY": "sk_live_xyz"})], "Functions"
        )
        lam.get_function_url_config.side_effect = Exception("No URL config")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        assert any("STRIPE_API_KEY" in i for f in findings for i in f.issues)

    def test_public_url_flagged(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func()], "Functions"
        )
        lam.get_function_url_config.return_value = {"AuthType": "NONE"}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        assert any("public" in i.lower() or "NONE" in i for f in findings for i in f.issues)

    def test_clean_function_no_findings(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator(
            [_make_lambda_func(runtime="nodejs20.x", env_vars={"APP_ENV": "prod"})], "Functions"
        )
        lam.get_function_url_config.side_effect = Exception("No URL config")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan()
        assert findings == []

    def test_lambda_finding_to_dict(self):
        f = LambdaFinding(
            function_name="fn", function_arn="arn:...", runtime="python3.6",
            issues=["Deprecated runtime"], severity=CloudFindingSeverity.MEDIUM,
        )
        d = f.to_dict()
        assert d["function_name"] == "fn"

    def test_sensitive_env_patterns(self):
        assert _SENSITIVE_ENV_PATTERNS.search("DB_PASSWORD")
        assert _SENSITIVE_ENV_PATTERNS.search("AWS_SECRET_KEY")
        assert not _SENSITIVE_ENV_PATTERNS.search("APP_NAME")

    def test_deprecated_runtimes_set(self):
        assert "python2.7" in _DEPRECATED_RUNTIMES
        assert "nodejs8.10" in _DEPRECATED_RUNTIMES
        assert "python3.11" not in _DEPRECATED_RUNTIMES

    def test_execute_returns_json(self):
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator([], "Functions")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert "status" in parsed

    def test_no_boto3_returns_empty(self):
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", side_effect=ImportError):
            findings = self.tool._run_scan()
        assert findings == []

    def test_specific_function_scan(self):
        lam = MagicMock()
        lam.get_function.return_value = {"Configuration": _make_lambda_func(runtime="python2.7")}
        lam.get_function_url_config.side_effect = Exception("No URL")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=lam):
            findings = self.tool._run_scan(function_name="my-fn")
        assert any("python2.7" in i or "Deprecated" in i for f in findings for i in f.issues)


# ---------------------------------------------------------------------------
# TestEC2MetadataTool
# ---------------------------------------------------------------------------


class TestEC2MetadataTool:
    def setup_method(self):
        self.tool = EC2MetadataTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "ec2_metadata"

    def test_imdsv1_not_accessible(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            result = self.tool._test_imdsv1()
        assert result["accessible"] is False

    def test_imdsv1_accessible(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ami-id\ninstance-id\nlocal-ipv4"
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self.tool._test_imdsv1()
        assert result["accessible"] is True
        assert result["severity"] == "critical"

    def test_imdsv2_token_unavailable(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Timeout")):
            result = self.tool._test_imdsv2()
        assert result["accessible"] is False

    def test_execute_returns_json(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("No route")):
            result = asyncio.run(self.tool.execute(test_imdsv1=True))
        parsed = json.loads(result)
        assert "imdsv1" in parsed

    def test_ssrf_params_test_disabled(self):
        result = asyncio.run(self.tool.execute(test_ssrf=False))
        parsed = json.loads(result)
        assert "ssrf_tests" not in parsed

    def test_ssrf_no_target_url(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("No route")):
            result = asyncio.run(self.tool.execute(test_ssrf=True, ssrf_params=["url"]))
        # No target_url provided, ssrf tests skipped
        parsed = json.loads(result)
        assert "ssrf_tests" not in parsed

    def test_ssrf_confirmed(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ami-id: ami-12345\ninstance-id: i-abc"
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = self.tool._test_ssrf_params("http://target.com/proxy", ["url", "target"])
        assert any(r.get("ssrf_confirmed") for r in results)

    def test_metadata_phase_exploit(self):
        from app.mcp.servers.cloud_server import CloudMCPServer
        server = CloudMCPServer()
        tools = server.get_tools()
        ec2_tool = next((t for t in tools if t.name == "ec2_metadata"), None)
        assert ec2_tool is not None
        assert ec2_tool.phase == "exploit"
        assert ec2_tool.requires_approval is True


# ---------------------------------------------------------------------------
# TestCloudTrailAnalyzer
# ---------------------------------------------------------------------------


def _make_ct_client(
    trails: Optional[List[Dict]] = None,
    is_logging: bool = True,
    log_validation: bool = True,
    cloudwatch: bool = True,
    multi_region: bool = True,
    mgmt_events: bool = True,
):
    ct = MagicMock()
    default_trail = {
        "Name": "main-trail",
        "LogFileValidationEnabled": log_validation,
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123:log-group:trail" if cloudwatch else None,
        "IsMultiRegionTrail": multi_region,
    }
    ct.describe_trails.return_value = {"trailList": trails if trails is not None else [default_trail]}
    ct.get_trail_status.return_value = {"IsLogging": is_logging}
    if mgmt_events:
        ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]
        }
    else:
        ct.get_event_selectors.return_value = {"EventSelectors": [{"IncludeManagementEvents": False}]}
    return ct


class TestCloudTrailAnalyzer:
    def setup_method(self):
        self.tool = CloudTrailAnalyzer()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "cloudtrail_analyzer"

    def test_no_trails_critical(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("No CloudTrail" in f["issue"] for f in findings)
        assert findings[0]["severity"] == "critical"

    def test_trail_not_logging_critical(self):
        ct = _make_ct_client(is_logging=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("DISABLED" in f["issue"] for f in findings)

    def test_log_validation_disabled(self):
        ct = _make_ct_client(log_validation=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("validation" in f["issue"].lower() for f in findings)

    def test_no_cloudwatch_integration(self):
        ct = _make_ct_client(cloudwatch=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("CloudWatch" in f["issue"] for f in findings)

    def test_not_multi_region(self):
        ct = _make_ct_client(multi_region=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("multi-region" in f["issue"].lower() for f in findings)

    def test_mgmt_events_not_logged(self):
        ct = _make_ct_client(mgmt_events=False)
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("Management events" in f["issue"] for f in findings)

    def test_fully_configured_clean(self):
        ct = _make_ct_client(
            is_logging=True, log_validation=True, cloudwatch=True,
            multi_region=True, mgmt_events=True,
        )
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert findings == []

    def test_execute_returns_json(self):
        ct = _make_ct_client()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            result = asyncio.run(self.tool.execute())
        parsed = json.loads(result)
        assert "status" in parsed

    def test_no_boto3_returns_empty(self):
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", side_effect=ImportError):
            findings = self.tool._run_check()
        assert findings == []

    def test_describe_trails_error(self):
        ct = MagicMock()
        ct.describe_trails.side_effect = Exception("Access Denied")
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            findings = self.tool._run_check()
        assert any("Cannot read" in f["issue"] or "Access Denied" in f.get("issue", "") for f in findings)


# ---------------------------------------------------------------------------
# TestCloudMCPServer
# ---------------------------------------------------------------------------


class TestCloudMCPServer:
    def setup_method(self):
        from app.mcp.servers.cloud_server import CloudMCPServer
        self.server = CloudMCPServer()

    def test_tool_list_length(self):
        tools = self.server.get_tools()
        assert len(tools) == 8

    def test_tool_names(self):
        names = {t.name for t in self.server.get_tools()}
        assert "s3_bucket_enum" in names
        assert "iam_audit" in names
        assert "security_group_audit" in names
        assert "lambda_scanner" in names
        assert "ec2_metadata" in names
        assert "cloudtrail_analyzer" in names
        assert "prowler_scan" in names
        assert "scoutsuite_scan" in names

    def test_prowler_unavailable(self):
        with patch("shutil.which", return_value=None):
            result = asyncio.run(self.server._run_prowler())
        parsed = json.loads(result)
        assert parsed["status"] == "unavailable"

    def test_scoutsuite_unavailable(self):
        with patch("shutil.which", return_value=None):
            result = asyncio.run(self.server._run_scoutsuite())
        parsed = json.loads(result)
        assert parsed["status"] == "unavailable"

    def test_handle_tool_call_s3(self):
        s3 = _make_s3_client()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=s3):
            result = asyncio.run(self.server.execute_tool("s3_bucket_enum", {"bucket_name": "test"}))
        assert isinstance(result, str)

    def test_handle_tool_call_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            asyncio.run(self.server.execute_tool("nonexistent_tool", {}))

    def test_handle_cloudtrail(self):
        ct = _make_ct_client()
        with patch("app.agent.tools.cloud.aws_tools._get_boto3_client", return_value=ct):
            result = asyncio.run(self.server.execute_tool("cloudtrail_analyzer", {}))
        assert isinstance(result, str)

    def test_ec2_metadata_requires_approval(self):
        tools = {t.name: t for t in self.server.get_tools()}
        assert tools["ec2_metadata"].requires_approval is True

    def test_all_tools_have_phase(self):
        for tool in self.server.get_tools():
            assert tool.phase is not None

    def test_port_constant(self):
        from app.mcp.servers.cloud_server import PORT
        assert PORT == 8011
