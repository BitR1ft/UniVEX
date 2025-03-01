"""
Cloud tools package — AWS, Azure, GCP, Container & Kubernetes security scanners.

         K8s RBAC audit, secret scan, Helm chart audit)
"""
from .aws_tools import (
    S3BucketEnumTool,
    IAMAuditTool,
    SecurityGroupAuditTool,
    LambdaScanner,
    EC2MetadataTool,
    CloudTrailAnalyzer,
    AWS_TOOLS,
    BucketFinding,
    IAMFinding,
    SecurityGroupFinding,
    LambdaFinding,
    CloudFindingSeverity,
)
from .azure_tools import (
    AzureBlobEnumTool,
    AzureADTool,
    AzureNSGAuditTool,
    CloudSummaryTool,
    AZURE_TOOLS,
    AzureBlobFinding,
    AzureADFinding,
    AzureNSGFinding,
)
from .gcp_tools import (
    GCSBucketEnumTool,
    GCPIAMTool,
    GCPFirewallAuditTool,
    GCP_TOOLS,
    GCSBucketFinding,
    GCPIAMFinding,
    GCPFirewallFinding,
)
from .container_tools import (
    DockerImageScanTool,
    DockerfileLintTool,
    ContainerEscapeTool,
    CONTAINER_TOOLS,
    ContainerImageFinding,
    DockerfileFinding,
    EscapeFinding,
)
from .k8s_tools import (
    K8sAuditTool,
    K8sSecretScanTool,
    HelmChartAuditTool,
    K8S_TOOLS,
    K8sFinding,
    K8sSecretFinding,
    HelmFinding,
)

# Combined list of all cloud security tools
ALL_CLOUD_TOOLS = AWS_TOOLS + AZURE_TOOLS + GCP_TOOLS + CONTAINER_TOOLS + K8S_TOOLS

__all__ = [
    # AWS
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
    # Azure
    "AzureBlobEnumTool",
    "AzureADTool",
    "AzureNSGAuditTool",
    "CloudSummaryTool",
    "AZURE_TOOLS",
    "AzureBlobFinding",
    "AzureADFinding",
    "AzureNSGFinding",
    # GCP
    "GCSBucketEnumTool",
    "GCPIAMTool",
    "GCPFirewallAuditTool",
    "GCP_TOOLS",
    "GCSBucketFinding",
    "GCPIAMFinding",
    "GCPFirewallFinding",
    # Container
    "DockerImageScanTool",
    "DockerfileLintTool",
    "ContainerEscapeTool",
    "CONTAINER_TOOLS",
    "ContainerImageFinding",
    "DockerfileFinding",
    "EscapeFinding",
    # Kubernetes
    "K8sAuditTool",
    "K8sSecretScanTool",
    "HelmChartAuditTool",
    "K8S_TOOLS",
    "K8sFinding",
    "K8sSecretFinding",
    "HelmFinding",
    # Combined
    "ALL_CLOUD_TOOLS",
]
