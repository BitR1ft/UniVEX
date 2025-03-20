"""

Exposes the six AWS security tools as JSON-RPC MCP tools over HTTP.
Wraps Prowler / ScoutSuite for comprehensive cloud security audits.

Port: 8011

Tools:
  s3_bucket_enum        — discover public/misconfigured S3 buckets
  iam_audit             — analyze IAM policies for over-permissive roles
  security_group_audit  — check for overly permissive inbound rules
  lambda_scanner        — check Lambda functions for vulnerable deps and env leaks
  ec2_metadata          — test SSRF to EC2 IMDS endpoint
  cloudtrail_analyzer   — check CloudTrail logging gaps
  prowler_scan          — run Prowler cloud security benchmark (CIS, SOC2, PCI)
  scoutsuite_scan       — run ScoutSuite multi-cloud security assessment

Safety controls:
  - Credentials never logged
  - Rate limit: 5 req/min per IP (cloud APIs are rate-limited themselves)
  - All findings are sanitised before JSON serialisation
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Any, Dict, List

from app.mcp.base_server import MCPServer, MCPTool
from app.agent.tools.cloud.aws_tools import (
    S3BucketEnumTool,
    IAMAuditTool,
    SecurityGroupAuditTool,
    LambdaScanner,
    EC2MetadataTool,
    CloudTrailAnalyzer,
)

logger = logging.getLogger(__name__)

PORT = 8011


class CloudMCPServer(MCPServer):
    """
    MCP server wrapping cloud security assessment tools.

    In addition to the six core AWS tool adapters, this server provides
    thin wrappers around Prowler and ScoutSuite when those binaries are
    available in the container.
    """

    def __init__(self, port: int = PORT) -> None:
        super().__init__(
            name="cloud-security",
            description="AWS/Azure/GCP cloud security assessment tools",
            port=port,
        )
        self._s3 = S3BucketEnumTool()
        self._iam = IAMAuditTool()
        self._sg = SecurityGroupAuditTool()
        self._lambda = LambdaScanner()
        self._ec2_meta = EC2MetadataTool()
        self._cloudtrail = CloudTrailAnalyzer()

    # ------------------------------------------------------------------
    # MCPServer interface
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="s3_bucket_enum",
                description="Discover public / misconfigured S3 buckets",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "default": "us-east-1"},
                        "bucket_name": {"type": "string"},
                        "check_all": {"type": "boolean", "default": True},
                    },
                },
            ),
            MCPTool(
                name="iam_audit",
                description="Analyze IAM users, roles, and policies for over-permissive access",
                phase="recon",
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
            ),
            MCPTool(
                name="security_group_audit",
                description="Check EC2 security groups for overly permissive inbound rules (0.0.0.0/0)",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "default": "us-east-1"},
                        "vpc_id": {"type": "string"},
                    },
                },
            ),
            MCPTool(
                name="lambda_scanner",
                description="Scan Lambda functions for deprecated runtimes and env var leaks",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "default": "us-east-1"},
                        "function_name": {"type": "string"},
                    },
                },
            ),
            MCPTool(
                name="ec2_metadata",
                description="Test SSRF to EC2 IMDS; enumerate instance metadata",
                phase="exploit",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string"},
                        "ssrf_params": {"type": "array", "items": {"type": "string"}},
                        "test_imdsv1": {"type": "boolean", "default": True},
                        "test_ssrf": {"type": "boolean", "default": False},
                    },
                },
            ),
            MCPTool(
                name="cloudtrail_analyzer",
                description="Check CloudTrail configuration for logging gaps",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "default": "us-east-1"},
                    },
                },
            ),
            MCPTool(
                name="prowler_scan",
                description="Run Prowler cloud security benchmark (CIS, SOC2, PCI-DSS)",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
                        "compliance": {"type": "string", "default": "cis_level2_aws"},
                        "region": {"type": "string", "default": "us-east-1"},
                        "output_format": {"type": "string", "enum": ["json", "csv", "html"], "default": "json"},
                    },
                },
            ),
            MCPTool(
                name="scoutsuite_scan",
                description="Run ScoutSuite multi-cloud security assessment",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
                        "report_dir": {"type": "string", "default": "/tmp/scoutsuite-report"},
                    },
                },
            ),
        ]

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """Route tool calls to the appropriate handler."""
        if tool_name == "s3_bucket_enum":
            return await self._s3.execute(**params)
        if tool_name == "iam_audit":
            return await self._iam.execute(**params)
        if tool_name == "security_group_audit":
            return await self._sg.execute(**params)
        if tool_name == "lambda_scanner":
            return await self._lambda.execute(**params)
        if tool_name == "ec2_metadata":
            return await self._ec2_meta.execute(**params)
        if tool_name == "cloudtrail_analyzer":
            return await self._cloudtrail.execute(**params)
        if tool_name == "prowler_scan":
            return await self._run_prowler(**params)
        if tool_name == "scoutsuite_scan":
            return await self._run_scoutsuite(**params)
        raise ValueError(f"Unknown tool: {tool_name}")

    # ------------------------------------------------------------------
    # External tool wrappers
    # ------------------------------------------------------------------

    async def _run_prowler(
        self,
        provider: str = "aws",
        compliance: str = "cis_level2_aws",
        region: str = "us-east-1",
        output_format: str = "json",
        **_: Any,
    ) -> str:
        prowler_bin = shutil.which("prowler")
        if not prowler_bin:
            return json.dumps({
                "status": "unavailable",
                "message": "Prowler is not installed. Install with: pip install prowler",
                "docs": "https://docs.prowler.com/",
            })
        cmd = [
            prowler_bin, provider,
            "--compliance", compliance,
            "--region", region,
            "--output-formats", output_format,
            "--output-filename", "/tmp/prowler-output",
            "--no-banner",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            return json.dumps({
                "status": "complete",
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="replace")[:10_000],
                "stderr": stderr.decode("utf-8", errors="replace")[:2_000],
            })
        except asyncio.TimeoutError:
            return json.dumps({"status": "timeout", "message": "Prowler scan timed out after 5 minutes"})
        except Exception as exc:
            logger.error("Prowler execution error: %s", exc)
            return json.dumps({"status": "error", "message": str(exc)})

    async def _run_scoutsuite(
        self,
        provider: str = "aws",
        report_dir: str = "/tmp/scoutsuite-report",
        **_: Any,
    ) -> str:
        scout_bin = shutil.which("scout")
        if not scout_bin:
            return json.dumps({
                "status": "unavailable",
                "message": "ScoutSuite is not installed. Install with: pip install scoutsuite",
                "docs": "https://github.com/nccgroup/ScoutSuite",
            })
        cmd = [
            scout_bin, provider,
            "--report-dir", report_dir,
            "--no-browser",
            "--quiet",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            return json.dumps({
                "status": "complete",
                "returncode": proc.returncode,
                "report_dir": report_dir,
                "stdout": stdout.decode("utf-8", errors="replace")[:5_000],
            })
        except asyncio.TimeoutError:
            return json.dumps({"status": "timeout", "message": "ScoutSuite scan timed out after 10 minutes"})
        except Exception as exc:
            logger.error("ScoutSuite execution error: %s", exc)
            return json.dumps({"status": "error", "message": str(exc)})


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_cloud_server(port: int = PORT) -> CloudMCPServer:
    """Create and configure the Cloud MCP server."""
    return CloudMCPServer(port=port)


if __name__ == "__main__":
    import uvicorn

    server = create_cloud_server()
    app = server.create_app()
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
