"""
AutoChain v2 — cloud_assessment Template

Cloud security misconfiguration assessment chain:
  1. Cloud provider detection (AWS, Azure, GCP, etc.)
  2. S3/Blob/GCS bucket enumeration & access testing
  3. Cloud metadata endpoint probing
  4. IAM policy analysis
  5. Public IP/service exposure audit
  6. Kubernetes / container exposure detection
  7. Secrets in headers / environment disclosure
  8. Cloud-native SQL/NoSQL injection
  9. SSRF to cloud metadata
 10. Report generation
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CloudProvider(str, Enum):
    AUTO = "auto"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DO = "digitalocean"
    ORACLE = "oracle"


@dataclass
class CloudAssessmentConfig:
    """Configuration for the cloud assessment template."""
    # Provider
    provider: CloudProvider = CloudProvider.AUTO

    # Object storage
    test_s3_buckets: bool = True
    test_azure_blobs: bool = True
    test_gcs_buckets: bool = True
    bucket_name_patterns: List[str] = field(
        default_factory=lambda: ["{target}", "{target}-dev", "{target}-backup", "{target}-prod"]
    )

    # Metadata
    test_aws_metadata: bool = True
    test_azure_metadata: bool = True
    test_gcp_metadata: bool = True
    test_do_metadata: bool = True

    # IAM
    test_iam_exposure: bool = True

    # Kubernetes
    test_k8s_dashboard: bool = True
    test_k8s_api: bool = True

    # Secrets
    test_headers_disclosure: bool = True
    test_env_disclosure: bool = True

    # Injection
    test_cloud_sql_injection: bool = True
    test_nosql_injection: bool = True

    # SSRF to metadata
    ssrf_metadata_targets: List[str] = field(
        default_factory=lambda: [
            "http://169.254.169.254/",               # AWS/Azure
            "http://metadata.google.internal/",       # GCP
            "http://100.100.100.200/latest/meta-data/",  # Alibaba
        ]
    )

    # Output
    generate_report: bool = True
    report_format: str = "html"


class CloudAssessmentTemplate:
    """
    cloud_assessment — Cloud infrastructure security misconfiguration template.

    Targets misconfigurations commonly found in:
    - AWS (S3 buckets, IMDSv1, public EC2 instances, IAM policies)
    - Azure (storage accounts, SSRF via metadata, public blobs)
    - GCP (Cloud Storage, metadata server, public APIs)
    - Kubernetes dashboards and unauthenticated API servers
    - Cloud-native application injection vectors
    """

    TEMPLATE_ID = "cloud_assessment"
    NAME = "Cloud Security Assessment"
    DESCRIPTION = (
        "Cloud infrastructure misconfiguration assessment: S3/blob bucket "
        "enumeration, IMDS SSRF, K8s exposure, IAM disclosure, secrets "
        "in headers, and cloud-native injection."
    )
    VERSION = "1.0.0"
    ESTIMATED_DURATION_MINUTES = 75

    PHASE_ORDER: List[str] = [
        "provider_detect",
        "object_storage",
        "metadata_ssrf",
        "iam_analysis",
        "k8s_exposure",
        "secrets_disclosure",
        "cloud_injection",
        "public_exposure",
        "report",
    ]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "provider_detect": ["cloud_detect_tool", "httpx", "wappalyzer"],
        "object_storage": ["s3_bucket_tool", "azure_blob_tool", "gcs_bucket_tool"],
        "metadata_ssrf": ["ssrf_probe_tool", "ssrf_blind_tool", "cloud_metadata_tool"],
        "iam_analysis": ["iam_policy_tool", "aws_enum_tool"],
        "k8s_exposure": ["k8s_api_tool", "k8s_dashboard_tool", "docker_api_tool"],
        "secrets_disclosure": ["secrets_in_headers_tool", "env_disclosure_tool"],
        "cloud_injection": ["sqli_detect_tool", "nosql_inject_tool"],
        "public_exposure": ["naabu", "httpx", "nuclei"],
        "report": ["report_engine"],
    }

    # Cloud-specific checks metadata
    CLOUD_METADATA_ENDPOINTS: Dict[str, List[str]] = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
    }

    def __init__(
        self,
        target: str,
        *,
        config: Optional[CloudAssessmentConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "low",
    ) -> None:
        self.target = target
        self.config = config or CloudAssessmentConfig()
        self.project_id = project_id
        self.auto_approve_risk_level = auto_approve_risk_level

    def get_scan_plan(self) -> Dict[str, Any]:
        """Return orchestrator-compatible scan plan."""
        phases = []
        for phase_id in self.PHASE_ORDER:
            phases.append({
                "phase": phase_id,
                "name": self._phase_name(phase_id),
                "tools": self.PHASE_TOOLS.get(phase_id, []),
                "config": self._phase_config(phase_id),
                "on_failure": "continue",
                "description": self._phase_description(phase_id),
                "estimated_minutes": self._phase_estimate(phase_id),
            })
        return {
            "template_id": self.TEMPLATE_ID,
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
            "target": self.target,
            "project_id": self.project_id,
            "auto_approve_risk_level": self.auto_approve_risk_level,
            "estimated_duration_minutes": self.ESTIMATED_DURATION_MINUTES,
            "phases": phases,
            "cloud_metadata_endpoints": self.CLOUD_METADATA_ENDPOINTS,
            "provider": self.config.provider.value,
        }

    def get_all_tools(self) -> List[str]:
        tools: List[str] = []
        seen: set = set()
        for tlist in self.PHASE_TOOLS.values():
            for t in tlist:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_bucket_names(self, target: Optional[str] = None) -> List[str]:
        """Generate cloud storage bucket name candidates from target."""
        base = target or self.target
        # Strip scheme and path
        base = base.split("//")[-1].split("/")[0].split(".")[0]
        names = []
        for pattern in self.config.bucket_name_patterns:
            names.append(pattern.replace("{target}", base))
        return names

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        configs: Dict[str, Dict[str, Any]] = {
            "provider_detect": {"provider_hint": cfg.provider.value},
            "object_storage": {
                "s3": cfg.test_s3_buckets,
                "azure_blob": cfg.test_azure_blobs,
                "gcs": cfg.test_gcs_buckets,
                "bucket_patterns": cfg.bucket_name_patterns,
            },
            "metadata_ssrf": {
                "aws": cfg.test_aws_metadata,
                "azure": cfg.test_azure_metadata,
                "gcp": cfg.test_gcp_metadata,
                "do": cfg.test_do_metadata,
                "ssrf_targets": cfg.ssrf_metadata_targets,
            },
            "iam_analysis": {"enabled": cfg.test_iam_exposure},
            "k8s_exposure": {
                "dashboard": cfg.test_k8s_dashboard,
                "api": cfg.test_k8s_api,
            },
            "secrets_disclosure": {
                "headers": cfg.test_headers_disclosure,
                "env": cfg.test_env_disclosure,
            },
            "cloud_injection": {
                "sqli": cfg.test_cloud_sql_injection,
                "nosql": cfg.test_nosql_injection,
            },
            "public_exposure": {"provider": cfg.provider.value},
            "report": {
                "format": cfg.report_format,
                "cloud_specific": True,
            },
        }
        return configs.get(phase_id, {})

    @staticmethod
    def _phase_name(phase_id: str) -> str:
        names = {
            "provider_detect": "Cloud Provider Detection",
            "object_storage": "Object Storage Enumeration",
            "metadata_ssrf": "Cloud Metadata SSRF",
            "iam_analysis": "IAM Policy Analysis",
            "k8s_exposure": "Kubernetes / Container Exposure",
            "secrets_disclosure": "Secrets & Config Disclosure",
            "cloud_injection": "Cloud-Native Injection Testing",
            "public_exposure": "Public Surface Audit",
            "report": "Cloud Security Report",
        }
        return names.get(phase_id, phase_id)

    @staticmethod
    def _phase_description(phase_id: str) -> str:
        descs = {
            "provider_detect": "Identify cloud provider via IP ranges, headers, and response patterns.",
            "object_storage": "Enumerate S3, Azure Blob, GCS buckets; test public read/write access.",
            "metadata_ssrf": "Probe IMDS endpoints via SSRF vectors for credential and config exfiltration.",
            "iam_analysis": "Detect overly permissive IAM policies, public EC2 instance profiles.",
            "k8s_exposure": "Test for unauthenticated Kubernetes dashboard, API server, Docker daemon.",
            "secrets_disclosure": "Extract secrets from HTTP headers, error messages, environment dumps.",
            "cloud_injection": "Test SQL/NoSQL injection in cloud-native DB backends.",
            "public_exposure": "Enumerate publicly accessible ports and services on cloud IPs.",
            "report": "Generate cloud security assessment report with remediation guidance.",
        }
        return descs.get(phase_id, "")

    @staticmethod
    def _phase_estimate(phase_id: str) -> int:
        estimates = {
            "provider_detect": 5,
            "object_storage": 15,
            "metadata_ssrf": 10,
            "iam_analysis": 10,
            "k8s_exposure": 10,
            "secrets_disclosure": 5,
            "cloud_injection": 10,
            "public_exposure": 5,
            "report": 5,
        }
        return estimates.get(phase_id, 5)
