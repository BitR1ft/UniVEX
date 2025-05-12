"""
CIS Benchmarks for common platforms.

Provides mapping from pentest findings to CIS Benchmark sections
for Linux, Docker, Kubernetes, AWS, and Azure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class CISSection:
    section_id: str
    title: str
    level: int  # 1 or 2
    recommendation: str
    rationale: str
    finding_keywords: List[str]


@dataclass
class CISBenchmark:
    platform: str
    version: str
    sections: List[CISSection]


CIS_BENCHMARKS: Dict[str, CISBenchmark] = {
    "linux": CISBenchmark(
        platform="linux",
        version="CIS Benchmark for Linux v3.0",
        sections=[
            CISSection(
                section_id="1",
                title="Initial Setup — Filesystem Configuration",
                level=1,
                recommendation="Configure filesystem settings to reduce attack surface",
                rationale="Restricting filesystem mounts reduces the ability of attackers to introduce malicious code",
                finding_keywords=[
                    "noexec", "nosuid", "nodev", "world-writable", "sticky bit",
                    "filesystem permission", "tmp mount", "/tmp executable",
                ],
            ),
            CISSection(
                section_id="2",
                title="Services — Software Updates",
                level=1,
                recommendation="Ensure software updates and patches are applied promptly",
                rationale="Outdated software can introduce known vulnerabilities",
                finding_keywords=[
                    "outdated package", "unpatched linux", "software update",
                    "yum update", "apt update", "kernel vulnerability",
                ],
            ),
            CISSection(
                section_id="3",
                title="Network Configuration",
                level=1,
                recommendation="Configure network settings to reduce attack surface",
                rationale="Network configuration settings affect how packets are routed and accepted",
                finding_keywords=[
                    "ip forwarding", "icmp redirect", "source routing",
                    "tcp syn cookies", "ipv6", "network hardening linux",
                ],
            ),
            CISSection(
                section_id="4",
                title="Logging and Auditing",
                level=1,
                recommendation="Enable and configure logging and auditing",
                rationale="Collecting and reviewing logs allows detection of unauthorized activity",
                finding_keywords=[
                    "syslog", "rsyslog", "auditd", "linux logging",
                    "audit log linux", "log rotation",
                ],
            ),
            CISSection(
                section_id="5",
                title="Access, Authentication and Authorization",
                level=1,
                recommendation="Enforce strict access and authentication controls",
                rationale="Strong access controls prevent unauthorized system access",
                finding_keywords=[
                    "pam", "password aging", "password complexity linux",
                    "sudo", "root login", "ssh root", "ssh key", "empty password",
                    "no password", "linux authentication",
                ],
            ),
            CISSection(
                section_id="6",
                title="System Maintenance",
                level=1,
                recommendation="Regularly perform system maintenance tasks",
                rationale="System maintenance ensures security tools remain effective",
                finding_keywords=[
                    "cron job", "at command", "world-writable file",
                    "suid file", "sgid file", "unowned file",
                ],
            ),
        ],
    ),
    "docker": CISBenchmark(
        platform="docker",
        version="CIS Docker Benchmark v1.6",
        sections=[
            CISSection(
                section_id="1",
                title="Host Configuration",
                level=1,
                recommendation="Ensure the host operating system is configured securely",
                rationale="Docker host security directly impacts the security of all containers",
                finding_keywords=[
                    "docker host", "container host", "docker daemon socket",
                    "docker socket exposed",
                ],
            ),
            CISSection(
                section_id="2",
                title="Docker Daemon Configuration",
                level=1,
                recommendation="Configure Docker daemon with secure settings",
                rationale="Secure daemon configuration prevents common Docker misconfigurations",
                finding_keywords=[
                    "docker daemon", "docker.sock", "tcp docker", "unencrypted docker",
                    "docker daemon exposed", "docker api exposed",
                ],
            ),
            CISSection(
                section_id="3",
                title="Docker Daemon Configuration Files",
                level=1,
                recommendation="Ensure Docker configuration files have correct permissions",
                rationale="Protecting configuration files prevents unauthorized modification",
                finding_keywords=[
                    "docker config file", "docker.service permissions",
                    "docker config permission",
                ],
            ),
            CISSection(
                section_id="4",
                title="Container Images and Build File",
                level=1,
                recommendation="Use trusted base images and secure Dockerfiles",
                rationale="Secure images reduce the attack surface of containers",
                finding_keywords=[
                    "dockerfile", "base image", "root container", "container root",
                    "privileged container", "container as root", "setuid container",
                    "add instruction", "secret in dockerfile",
                ],
            ),
            CISSection(
                section_id="5",
                title="Container Runtime",
                level=1,
                recommendation="Apply runtime security controls to containers",
                rationale="Runtime controls prevent container escape and lateral movement",
                finding_keywords=[
                    "privileged mode", "--privileged", "capability", "cap-add",
                    "container escape", "host network", "host pid", "host ipc",
                    "read-only filesystem", "seccomp", "apparmor",
                ],
            ),
        ],
    ),
    "kubernetes": CISBenchmark(
        platform="kubernetes",
        version="CIS Kubernetes Benchmark v1.8",
        sections=[
            CISSection(
                section_id="1",
                title="Control Plane Components",
                level=1,
                recommendation="Secure Kubernetes control plane components",
                rationale="Control plane security is critical to cluster integrity",
                finding_keywords=[
                    "api server", "kube-apiserver", "anonymous authentication",
                    "insecure port", "kubernetes api", "control plane",
                ],
            ),
            CISSection(
                section_id="2",
                title="etcd",
                level=1,
                recommendation="Configure etcd securely",
                rationale="etcd stores all cluster state and must be protected",
                finding_keywords=[
                    "etcd", "etcd exposed", "etcd authentication",
                    "etcd encryption", "etcd backup",
                ],
            ),
            CISSection(
                section_id="3",
                title="Control Plane Configuration — Scheduler",
                level=1,
                recommendation="Configure the Kubernetes scheduler securely",
                rationale="Secure scheduler prevents unauthorized scheduling decisions",
                finding_keywords=[
                    "kube-scheduler", "scheduler", "scheduler profiling",
                ],
            ),
            CISSection(
                section_id="4",
                title="Worker Nodes",
                level=1,
                recommendation="Secure Kubernetes worker nodes",
                rationale="Worker node security affects the security of all running pods",
                finding_keywords=[
                    "kubelet", "worker node", "node security", "kubelet authentication",
                    "kubelet authorization", "anonymous kubelet",
                ],
            ),
            CISSection(
                section_id="5",
                title="Kubernetes Policies",
                level=1,
                recommendation="Apply Kubernetes security policies",
                rationale="Policies enforce security standards across the cluster",
                finding_keywords=[
                    "pod security", "network policy", "rbac kubernetes",
                    "cluster role", "service account", "namespace isolation",
                    "pod security policy", "psp", "admission controller",
                ],
            ),
        ],
    ),
    "aws": CISBenchmark(
        platform="aws",
        version="CIS AWS Foundations Benchmark v3.0",
        sections=[
            CISSection(
                section_id="1",
                title="Identity and Access Management",
                level=1,
                recommendation="Configure IAM with least privilege and MFA",
                rationale="IAM is the foundation of AWS security",
                finding_keywords=[
                    "iam", "aws iam", "root account", "root user", "mfa aws",
                    "access key", "aws credentials", "iam policy", "overprivileged iam",
                    "iam misconfiguration", "assume role",
                ],
            ),
            CISSection(
                section_id="2",
                title="Logging",
                level=1,
                recommendation="Enable comprehensive logging across AWS services",
                rationale="Logging enables detection and investigation of security events",
                finding_keywords=[
                    "cloudtrail", "cloudwatch", "vpc flow logs", "s3 access logs",
                    "aws logging", "elb logs", "load balancer logs",
                ],
            ),
            CISSection(
                section_id="3",
                title="Monitoring",
                level=1,
                recommendation="Implement monitoring and alerting for security events",
                rationale="Monitoring enables rapid response to security incidents",
                finding_keywords=[
                    "cloudwatch alarm", "aws monitoring", "sns notification",
                    "config rule", "aws config", "guardduty",
                ],
            ),
            CISSection(
                section_id="4",
                title="Networking",
                level=1,
                recommendation="Configure VPC networking securely",
                rationale="Network controls limit exposure of AWS resources",
                finding_keywords=[
                    "security group", "open security group", "0.0.0.0/0",
                    "vpc", "nacl", "public subnet", "s3 public", "open s3 bucket",
                    "aws networking", "internet gateway",
                ],
            ),
        ],
    ),
    "azure": CISBenchmark(
        platform="azure",
        version="CIS Azure Foundations Benchmark v2.0",
        sections=[
            CISSection(
                section_id="1",
                title="Identity and Access Management",
                level=1,
                recommendation="Secure Azure IAM and Active Directory settings",
                rationale="Identity is the primary security perimeter in Azure",
                finding_keywords=[
                    "azure iam", "azure ad", "entra id", "mfa azure",
                    "privileged identity", "azure rbac", "service principal",
                    "managed identity",
                ],
            ),
            CISSection(
                section_id="2",
                title="Microsoft Defender",
                level=1,
                recommendation="Enable Microsoft Defender for Cloud",
                rationale="Defender provides unified security management and threat protection",
                finding_keywords=[
                    "microsoft defender", "azure security center", "defender for cloud",
                    "azure defender", "security score",
                ],
            ),
            CISSection(
                section_id="3",
                title="Storage",
                level=1,
                recommendation="Configure Azure Storage accounts securely",
                rationale="Insecure storage can expose sensitive data",
                finding_keywords=[
                    "azure storage", "blob storage", "public blob", "open blob",
                    "storage account", "sas token", "storage key",
                ],
            ),
            CISSection(
                section_id="4",
                title="Database Services",
                level=1,
                recommendation="Configure Azure database services securely",
                rationale="Database security prevents unauthorized access to sensitive data",
                finding_keywords=[
                    "azure sql", "cosmos db", "azure database", "sql firewall",
                    "database encryption", "transparent data encryption",
                ],
            ),
            CISSection(
                section_id="5",
                title="Logging and Monitoring",
                level=1,
                recommendation="Enable logging and monitoring across Azure services",
                rationale="Logging enables detection and investigation of incidents",
                finding_keywords=[
                    "azure monitor", "activity log", "diagnostic log", "log analytics",
                    "azure logging", "azure audit",
                ],
            ),
            CISSection(
                section_id="6",
                title="Networking",
                level=1,
                recommendation="Configure Azure networking controls securely",
                rationale="Network security groups and firewalls limit attack surface",
                finding_keywords=[
                    "nsg", "network security group", "azure firewall",
                    "ddos protection", "azure networking", "open port azure",
                ],
            ),
            CISSection(
                section_id="7",
                title="Virtual Machines",
                level=1,
                recommendation="Secure Azure Virtual Machine configurations",
                rationale="VM security ensures compute workloads are protected",
                finding_keywords=[
                    "azure vm", "virtual machine", "just in time", "jit access",
                    "vm extension", "disk encryption azure",
                ],
            ),
            CISSection(
                section_id="8",
                title="Kubernetes Service (AKS)",
                level=1,
                recommendation="Configure AKS clusters securely",
                rationale="Secure AKS clusters prevent container escape and lateral movement",
                finding_keywords=[
                    "aks", "azure kubernetes", "azure container", "aks rbac",
                ],
            ),
        ],
    ),
}


def map_finding_to_cis(
    finding_title: str, finding_description: str, platform: str = ""
) -> List[str]:
    """
    Return list of CIS benchmark section IDs matching the finding.

    Returns identifiers in the form "<platform>/<section_id>".
    If platform is specified, only that platform is searched.
    """
    combined = (finding_title + " " + finding_description).lower()
    matched: List[str] = []
    benchmarks = (
        {platform.lower(): CIS_BENCHMARKS[platform.lower()]}
        if platform and platform.lower() in CIS_BENCHMARKS
        else CIS_BENCHMARKS
    )
    for plat_key, benchmark in benchmarks.items():
        for section in benchmark.sections:
            for keyword in section.finding_keywords:
                if keyword in combined:
                    matched.append(f"{plat_key}/{section.section_id}")
                    break
    return matched
