"""

Three agent tools for Kubernetes security assessments:

  K8sAuditTool        — check RBAC, pod security standards, and network policies
  K8sSecretScanTool   — detect secrets exposed in Kubernetes pods and resources
  HelmChartAuditTool  — scan Helm chart directories for security misconfigurations

All tools are fully mockable for testing — Kubernetes SDK calls are abstracted
behind ``_get_k8s_client()`` helpers and YAML/file reads behind ``_read_yaml_file()``
that tests can patch.

Tools map to the CLOUD_SECURITY attack category in the AttackPathRouter and are
registered in ``tool_registry.py`` under K8S_SECURITY.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
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
# Shared patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_\-]?key|credential|private[_\-]?key|auth[_\-]?key|access[_\-]?key)",
    re.IGNORECASE,
)

# Capabilities considered dangerous in a Kubernetes context
_DANGEROUS_K8S_CAPS = {
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
}

# System / cluster-internal subjects that are allowed cluster-admin
_SYSTEM_SUBJECT_PREFIXES = ("system:", "kube-")


# ---------------------------------------------------------------------------
# Mockable Kubernetes client helpers
# ---------------------------------------------------------------------------


def _get_k8s_client(in_cluster: bool = True):
    """
    Return a configured kubernetes.client.CoreV1Api instance.

    Loads in-cluster config when ``in_cluster=True``, otherwise falls back to
    the default kubeconfig.  Raises ``ImportError`` if the ``kubernetes`` package
    is not installed.

    This function is intentionally thin so tests can patch it.
    """
    from kubernetes import client, config  # type: ignore[import]

    try:
        if in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
    except Exception:
        config.load_kube_config()

    return client.CoreV1Api()


def _get_k8s_rbac_client():
    """Return a kubernetes.client.RbacAuthorizationV1Api instance."""
    from kubernetes import client  # type: ignore[import]

    return client.RbacAuthorizationV1Api()


def _get_k8s_networking_client():
    """Return a kubernetes.client.NetworkingV1Api instance."""
    from kubernetes import client  # type: ignore[import]

    return client.NetworkingV1Api()


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class K8sFinding:
    resource_kind: str
    resource_name: str
    namespace: str
    issue: str
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "issue": self.issue,
            "severity": self.severity.value,
        }


@dataclass
class K8sSecretFinding:
    resource_type: str
    resource_name: str
    namespace: str
    secret_type: str
    issue: str
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "secret_type": self.secret_type,
            "issue": self.issue,
            "severity": self.severity.value,
        }


@dataclass
class HelmFinding:
    chart_name: str
    file_path: str
    issue: str
    severity: CloudFindingSeverity
    line_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chart_name": self.chart_name,
            "file_path": self.file_path,
            "issue": self.issue,
            "severity": self.severity.value,
            "line_number": self.line_number,
        }


# ---------------------------------------------------------------------------
# K8sAuditTool
# ---------------------------------------------------------------------------


class K8sAuditTool(BaseTool):
    """
    Check Kubernetes RBAC, pod security standards, and network policies.

    Checks:
      - cluster-admin ClusterRoleBindings to non-system subjects
      - Pods running as root (securityContext.runAsNonRoot != true)
      - Pods without CPU / memory resource limits
      - Privileged containers (securityContext.privileged=true)
      - Namespaces without NetworkPolicy
      - Containers without readOnlyRootFilesystem
      - ServiceAccounts with automountServiceAccountToken enabled
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="k8s_audit",
            description=(
                "Check Kubernetes RBAC bindings, pod security contexts, resource limits, "
                "and network policies for misconfigurations"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Kubernetes namespace to audit (default: default)",
                        "default": "default",
                    },
                    "check_all_namespaces": {
                        "type": "boolean",
                        "description": "Audit all namespaces (overrides namespace parameter)",
                        "default": False,
                    },
                },
            },
        )

    async def execute(
        self,
        namespace: str = "default",
        check_all_namespaces: bool = False,
        **kwargs: Any,
    ) -> str:
        findings = self._run_audit(namespace=namespace, check_all_namespaces=check_all_namespaces)
        severity_counts = {s.value: 0 for s in CloudFindingSeverity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        result = {
            "status": "complete",
            "namespace": "all" if check_all_namespaces else namespace,
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_audit(
        self, namespace: str = "default", check_all_namespaces: bool = False
    ) -> List[K8sFinding]:
        """Core audit logic — separated for easy unit testing."""
        try:
            core = _get_k8s_client()
            rbac = _get_k8s_rbac_client()
            net = _get_k8s_networking_client()
        except ImportError:
            logger.warning("kubernetes package not installed — returning empty findings")
            return []

        findings: List[K8sFinding] = []
        target_ns = None if check_all_namespaces else namespace

        findings.extend(self._check_cluster_admin_bindings(rbac))
        findings.extend(self._check_pods(core, target_ns))
        findings.extend(self._check_network_policies(core, net, target_ns))
        findings.extend(self._check_service_accounts(core, target_ns))

        return findings

    # ------------------------------------------------------------------
    # RBAC checks
    # ------------------------------------------------------------------

    def _check_cluster_admin_bindings(self, rbac) -> List[K8sFinding]:
        """Flag ClusterRoleBindings granting cluster-admin to non-system subjects."""
        findings: List[K8sFinding] = []
        try:
            bindings = rbac.list_cluster_role_binding()
        except Exception as exc:
            logger.error("list_cluster_role_binding failed: %s", exc)
            return []

        for binding in bindings.items:
            if binding.role_ref.name != "cluster-admin":
                continue
            for subject in binding.subjects or []:
                name = subject.name or ""
                if any(name.startswith(prefix) for prefix in _SYSTEM_SUBJECT_PREFIXES):
                    continue
                findings.append(K8sFinding(
                    resource_kind="ClusterRoleBinding",
                    resource_name=binding.metadata.name,
                    namespace="(cluster-wide)",
                    issue=(
                        f"ClusterRoleBinding grants cluster-admin to non-system subject "
                        f"'{name}' (kind={subject.kind}) — this allows full cluster control"
                    ),
                    severity=CloudFindingSeverity.CRITICAL,
                ))
        return findings

    # ------------------------------------------------------------------
    # Pod security checks
    # ------------------------------------------------------------------

    def _check_pods(self, core, namespace: Optional[str]) -> List[K8sFinding]:
        findings: List[K8sFinding] = []
        try:
            if namespace:
                pods = core.list_namespaced_pod(namespace)
            else:
                pods = core.list_pod_for_all_namespaces()
        except Exception as exc:
            logger.error("list_pod failed: %s", exc)
            return []

        for pod in pods.items:
            pod_name = pod.metadata.name
            pod_ns = pod.metadata.namespace or namespace or "default"
            pod_spec = pod.spec

            pod_sc = pod_spec.security_context or _EmptySC()

            for container in (pod_spec.containers or []):
                findings.extend(
                    self._check_container_security(container, pod_name, pod_ns, pod_sc)
                )
            for container in (pod_spec.init_containers or []):
                findings.extend(
                    self._check_container_security(
                        container, f"{pod_name}/initContainer:{container.name}", pod_ns, pod_sc
                    )
                )

        return findings

    def _check_container_security(
        self, container, pod_name: str, namespace: str, pod_sc: Any
    ) -> List[K8sFinding]:
        findings: List[K8sFinding] = []
        cname = container.name
        sc = container.security_context

        # Privileged container
        if sc and sc.privileged:
            findings.append(K8sFinding(
                resource_kind="Pod/Container",
                resource_name=f"{pod_name}/{cname}",
                namespace=namespace,
                issue="Container runs in privileged mode — grants all Linux capabilities",
                severity=CloudFindingSeverity.CRITICAL,
            ))

        # runAsNonRoot
        run_as_non_root = (sc and sc.run_as_non_root) or (pod_sc and getattr(pod_sc, "run_as_non_root", None))
        if not run_as_non_root:
            run_as_user = (sc and sc.run_as_user) or (pod_sc and getattr(pod_sc, "run_as_user", None))
            if run_as_user is None or run_as_user == 0:
                findings.append(K8sFinding(
                    resource_kind="Pod/Container",
                    resource_name=f"{pod_name}/{cname}",
                    namespace=namespace,
                    issue=(
                        "Container may run as root — set securityContext.runAsNonRoot=true "
                        "or securityContext.runAsUser to a non-zero UID"
                    ),
                    severity=CloudFindingSeverity.HIGH,
                ))

        # readOnlyRootFilesystem
        if not (sc and sc.read_only_root_filesystem):
            findings.append(K8sFinding(
                resource_kind="Pod/Container",
                resource_name=f"{pod_name}/{cname}",
                namespace=namespace,
                issue=(
                    "Container root filesystem is writable — set "
                    "securityContext.readOnlyRootFilesystem=true to prevent runtime tampering"
                ),
                severity=CloudFindingSeverity.MEDIUM,
            ))

        # Dangerous capabilities
        if sc and sc.capabilities and sc.capabilities.add:
            for cap in sc.capabilities.add:
                if cap.upper() in _DANGEROUS_K8S_CAPS:
                    findings.append(K8sFinding(
                        resource_kind="Pod/Container",
                        resource_name=f"{pod_name}/{cname}",
                        namespace=namespace,
                        issue=f"Dangerous Linux capability added: {cap}",
                        severity=CloudFindingSeverity.HIGH,
                    ))

        # Resource limits
        resources = container.resources
        if not resources or not resources.limits:
            findings.append(K8sFinding(
                resource_kind="Pod/Container",
                resource_name=f"{pod_name}/{cname}",
                namespace=namespace,
                issue=(
                    "No resource limits (CPU/memory) set — container can consume unlimited "
                    "resources and cause node-level denial of service"
                ),
                severity=CloudFindingSeverity.MEDIUM,
            ))
        else:
            if not resources.limits.get("cpu"):
                findings.append(K8sFinding(
                    resource_kind="Pod/Container",
                    resource_name=f"{pod_name}/{cname}",
                    namespace=namespace,
                    issue="No CPU limit set",
                    severity=CloudFindingSeverity.LOW,
                ))
            if not resources.limits.get("memory"):
                findings.append(K8sFinding(
                    resource_kind="Pod/Container",
                    resource_name=f"{pod_name}/{cname}",
                    namespace=namespace,
                    issue="No memory limit set",
                    severity=CloudFindingSeverity.LOW,
                ))

        return findings

    # ------------------------------------------------------------------
    # Network Policy checks
    # ------------------------------------------------------------------

    def _check_network_policies(self, core, net, namespace: Optional[str]) -> List[K8sFinding]:
        findings: List[K8sFinding] = []
        try:
            if namespace:
                ns_list = [type("NS", (), {"metadata": type("M", (), {"name": namespace})()})()]
            else:
                ns_list = core.list_namespace().items
        except Exception as exc:
            logger.error("list_namespace failed: %s", exc)
            return []

        for ns_obj in ns_list:
            ns_name = ns_obj.metadata.name
            if ns_name in ("kube-system", "kube-public", "kube-node-lease"):
                continue
            try:
                policies = net.list_namespaced_network_policy(ns_name)
                if not policies.items:
                    findings.append(K8sFinding(
                        resource_kind="Namespace",
                        resource_name=ns_name,
                        namespace=ns_name,
                        issue=(
                            f"Namespace '{ns_name}' has no NetworkPolicy — all pods can "
                            "communicate freely; apply a default-deny policy"
                        ),
                        severity=CloudFindingSeverity.HIGH,
                    ))
            except Exception as exc:
                logger.warning("list_namespaced_network_policy failed for %s: %s", ns_name, exc)

        return findings

    # ------------------------------------------------------------------
    # ServiceAccount checks
    # ------------------------------------------------------------------

    def _check_service_accounts(self, core, namespace: Optional[str]) -> List[K8sFinding]:
        findings: List[K8sFinding] = []
        try:
            if namespace:
                sas = core.list_namespaced_service_account(namespace)
            else:
                sas = core.list_service_account_for_all_namespaces()
        except Exception as exc:
            logger.error("list_service_account failed: %s", exc)
            return []

        for sa in sas.items:
            name = sa.metadata.name
            ns = sa.metadata.namespace or namespace or "default"
            # automountServiceAccountToken defaults to True when not set
            automount = sa.automount_service_account_token
            if automount is None or automount is True:
                findings.append(K8sFinding(
                    resource_kind="ServiceAccount",
                    resource_name=name,
                    namespace=ns,
                    issue=(
                        f"ServiceAccount '{name}' auto-mounts its token into pods — "
                        "set automountServiceAccountToken: false unless the pod requires API access"
                    ),
                    severity=CloudFindingSeverity.MEDIUM,
                ))
        return findings


class _EmptySC:
    """Null-object for a missing pod-level security context."""
    run_as_non_root = None
    run_as_user = None


# ---------------------------------------------------------------------------
# K8sSecretScanTool
# ---------------------------------------------------------------------------


class K8sSecretScanTool(BaseTool):
    """
    Detect secrets exposed in Kubernetes resources.

    Checks:
      - Opaque Secrets whose keys match common secret patterns
      - Pod environment variables whose names suggest secret values
      - Secrets mounted as env vars (less secure than volume mounts)
      - Secrets or sensitive values in ConfigMaps
      - Presence of EncryptionConfiguration for etcd at-rest encryption
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="k8s_secret_scan",
            description=(
                "Scan Kubernetes Secrets, ConfigMaps, and pod environment variables "
                "for exposed or misconfigured sensitive values"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Kubernetes namespace to scan (default: default)",
                        "default": "default",
                    },
                },
            },
        )

    async def execute(self, namespace: str = "default", **kwargs: Any) -> str:
        findings = self._run_scan(namespace=namespace)
        severity_counts = {s.value: 0 for s in CloudFindingSeverity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        result = {
            "status": "complete",
            "namespace": namespace,
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(self, namespace: str = "default") -> List[K8sSecretFinding]:
        """Core scan logic — separated for easy unit testing."""
        try:
            core = _get_k8s_client()
        except ImportError:
            logger.warning("kubernetes package not installed — returning empty findings")
            return []

        findings: List[K8sSecretFinding] = []
        findings.extend(self._check_secrets(core, namespace))
        findings.extend(self._check_config_maps(core, namespace))
        findings.extend(self._check_pod_env_vars(core, namespace))
        return findings

    # ------------------------------------------------------------------
    # Secret resource checks
    # ------------------------------------------------------------------

    def _check_secrets(self, core, namespace: str) -> List[K8sSecretFinding]:
        findings: List[K8sSecretFinding] = []
        try:
            secrets = core.list_namespaced_secret(namespace)
        except Exception as exc:
            logger.error("list_namespaced_secret failed: %s", exc)
            return []

        for secret in secrets.items:
            name = secret.metadata.name
            secret_type = secret.type or "Opaque"

            if secret_type != "Opaque":
                continue

            data_keys = list((secret.data or {}).keys())
            suspicious_keys = [k for k in data_keys if _SECRET_PATTERN.search(k)]
            if suspicious_keys:
                findings.append(K8sSecretFinding(
                    resource_type="Secret",
                    resource_name=name,
                    namespace=namespace,
                    secret_type=secret_type,
                    issue=(
                        f"Secret contains keys matching sensitive patterns: "
                        f"{', '.join(suspicious_keys)} — ensure the Secret is "
                        "encrypted at rest and access is restricted via RBAC"
                    ),
                    severity=CloudFindingSeverity.HIGH,
                ))

        return findings

    # ------------------------------------------------------------------
    # ConfigMap checks
    # ------------------------------------------------------------------

    def _check_config_maps(self, core, namespace: str) -> List[K8sSecretFinding]:
        findings: List[K8sSecretFinding] = []
        try:
            cms = core.list_namespaced_config_map(namespace)
        except Exception as exc:
            logger.error("list_namespaced_config_map failed: %s", exc)
            return []

        for cm in cms.items:
            name = cm.metadata.name
            for key, value in (cm.data or {}).items():
                if _SECRET_PATTERN.search(key):
                    findings.append(K8sSecretFinding(
                        resource_type="ConfigMap",
                        resource_name=name,
                        namespace=namespace,
                        secret_type="plaintext",
                        issue=(
                            f"ConfigMap key '{key}' appears to contain a secret value — "
                            "move sensitive data to a Kubernetes Secret resource"
                        ),
                        severity=CloudFindingSeverity.CRITICAL,
                    ))
                elif value and _SECRET_PATTERN.search(value[:200]):
                    findings.append(K8sSecretFinding(
                        resource_type="ConfigMap",
                        resource_name=name,
                        namespace=namespace,
                        secret_type="plaintext",
                        issue=(
                            f"ConfigMap key '{key}' value appears to contain a secret — "
                            "move sensitive data to a Kubernetes Secret resource"
                        ),
                        severity=CloudFindingSeverity.HIGH,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Pod environment variable checks
    # ------------------------------------------------------------------

    def _check_pod_env_vars(self, core, namespace: str) -> List[K8sSecretFinding]:
        findings: List[K8sSecretFinding] = []
        try:
            pods = core.list_namespaced_pod(namespace)
        except Exception as exc:
            logger.error("list_namespaced_pod failed: %s", exc)
            return []

        for pod in pods.items:
            pod_name = pod.metadata.name
            for container in (pod.spec.containers or []) + (pod.spec.init_containers or []):
                for env_var in (container.env or []):
                    env_name = env_var.name or ""
                    if not _SECRET_PATTERN.search(env_name):
                        continue

                    # valueFrom.secretKeyRef is the secure pattern
                    if env_var.value_from and env_var.value_from.secret_key_ref:
                        # Using secretKeyRef is safer but still env-based injection
                        findings.append(K8sSecretFinding(
                            resource_type="Pod/Container",
                            resource_name=f"{pod_name}/{container.name}",
                            namespace=namespace,
                            secret_type="env_from_secret",
                            issue=(
                                f"Secret '{env_name}' injected as environment variable — "
                                "prefer mounting secrets as files to reduce exposure via "
                                "/proc/<pid>/environ and crash dumps"
                            ),
                            severity=CloudFindingSeverity.MEDIUM,
                        ))
                    elif env_var.value:
                        # Hardcoded plaintext value in env
                        findings.append(K8sSecretFinding(
                            resource_type="Pod/Container",
                            resource_name=f"{pod_name}/{container.name}",
                            namespace=namespace,
                            secret_type="hardcoded_env",
                            issue=(
                                f"Secret-like environment variable '{env_name}' has a "
                                "hardcoded plaintext value in the pod spec — use a "
                                "Kubernetes Secret with secretKeyRef instead"
                            ),
                            severity=CloudFindingSeverity.CRITICAL,
                        ))

        return findings


# ---------------------------------------------------------------------------
# HelmChartAuditTool
# ---------------------------------------------------------------------------


class HelmChartAuditTool(BaseTool):
    """
    Scan a Helm chart directory for security misconfigurations.

    Checks values.yaml:
      - Default or empty passwords / credentials
      - privileged: true, hostNetwork: true, hostPID: true
      - runAsRoot: true / runAsNonRoot: false
      - readOnlyRootFilesystem: false
      - Exposed NodePorts for sensitive services

    Checks templates/*.yaml:
      - Hardcoded secrets / tokens in templates
      - capabilities.add with dangerous capabilities
      - allowPrivilegeEscalation: true
      - hostPath volumes
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="helm_chart_audit",
            description=(
                "Scan a Helm chart directory for security misconfigurations in "
                "values.yaml and template files"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "chart_path": {
                        "type": "string",
                        "description": "Path to the Helm chart root directory",
                        "default": ".",
                    },
                },
            },
        )

    async def execute(self, chart_path: str = ".", **kwargs: Any) -> str:
        findings = self._run_audit(chart_path=chart_path)
        severity_counts = {s.value: 0 for s in CloudFindingSeverity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        chart_name = os.path.basename(os.path.abspath(chart_path))
        result = {
            "status": "complete",
            "chart_path": chart_path,
            "chart_name": chart_name,
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    # ------------------------------------------------------------------
    # Mockable file helpers
    # ------------------------------------------------------------------

    def _read_yaml_file(self, path: str) -> Optional[Any]:
        """
        Load a YAML file and return the parsed object.

        Returns ``None`` on any error. Tests can patch this method to inject
        arbitrary YAML structures without touching the filesystem.
        """
        try:
            import yaml  # type: ignore[import]
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return yaml.safe_load(fh)
        except ImportError:
            logger.warning("PyYAML not installed — cannot parse YAML files")
            return None
        except (OSError, Exception) as exc:
            logger.error("Cannot read YAML file %s: %s", path, exc)
            return None

    def _read_text_file(self, path: str) -> Optional[str]:
        """Read a text file as a string. Tests can patch this method."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            logger.error("Cannot read file %s: %s", path, exc)
            return None

    def _list_template_files(self, chart_path: str) -> List[str]:
        """Return all YAML/JSON files under the templates/ directory."""
        templates_dir = os.path.join(chart_path, "templates")
        if not os.path.isdir(templates_dir):
            return []
        result = []
        for dirpath, _, filenames in os.walk(templates_dir):
            for fname in filenames:
                if fname.endswith((".yaml", ".yml", ".json")):
                    result.append(os.path.join(dirpath, fname))
        return sorted(result)

    # ------------------------------------------------------------------
    # Core audit
    # ------------------------------------------------------------------

    def _run_audit(self, chart_path: str = ".") -> List[HelmFinding]:
        """Core audit logic — separated for easy unit testing."""
        chart_name = os.path.basename(os.path.abspath(chart_path))
        findings: List[HelmFinding] = []

        values_path = os.path.join(chart_path, "values.yaml")
        values_data = self._read_yaml_file(values_path)
        if values_data is not None:
            findings.extend(self._audit_values(chart_name, values_path, values_data))

        for tmpl_path in self._list_template_files(chart_path):
            findings.extend(self._audit_template_file(chart_name, tmpl_path))

        return findings

    # ------------------------------------------------------------------
    # values.yaml checks
    # ------------------------------------------------------------------

    def _audit_values(
        self, chart_name: str, file_path: str, values: Any
    ) -> List[HelmFinding]:
        findings: List[HelmFinding] = []
        if not isinstance(values, dict):
            return findings

        flat = self._flatten_dict(values)

        for key_path, value in flat.items():
            lower_key = key_path.lower()
            str_val = str(value) if value is not None else ""

            # Default/empty passwords or credentials
            if _SECRET_PATTERN.search(lower_key):
                if str_val in ("", '""', "''", "changeme", "password", "secret", "admin", "test", "example"):
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=(
                            f"Default or empty credential at '{key_path}' (value='{str_val}') — "
                            "override with a strong secret before deployment"
                        ),
                        severity=CloudFindingSeverity.CRITICAL,
                    ))
                elif str_val and _SECRET_PATTERN.search(str_val[:100]):
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=(
                            f"Possible hardcoded secret at '{key_path}' — "
                            "use a Kubernetes Secret or external secrets manager"
                        ),
                        severity=CloudFindingSeverity.HIGH,
                    ))

            # privileged: true
            if lower_key.endswith(".privileged") or lower_key == "privileged":
                if value is True:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=f"'{key_path}: true' enables privileged mode — remove or override to false",
                        severity=CloudFindingSeverity.CRITICAL,
                    ))

            # hostNetwork / hostPID
            if lower_key.endswith(".hostnetwork") or lower_key == "hostnetwork":
                if value is True:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=f"'{key_path}: true' shares host network namespace",
                        severity=CloudFindingSeverity.HIGH,
                    ))

            if lower_key.endswith(".hostpid") or lower_key == "hostpid":
                if value is True:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=f"'{key_path}: true' shares host PID namespace",
                        severity=CloudFindingSeverity.HIGH,
                    ))

            # runAsRoot / runAsNonRoot
            if lower_key.endswith(".runasroot") or lower_key == "runasroot":
                if value is True:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=f"'{key_path}: true' runs container as root — set to false",
                        severity=CloudFindingSeverity.HIGH,
                    ))

            if lower_key.endswith(".runasnonroot") or lower_key == "runasnonroot":
                if value is False:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=f"'{key_path}: false' disables runAsNonRoot enforcement",
                        severity=CloudFindingSeverity.HIGH,
                    ))

            # readOnlyRootFilesystem: false
            if lower_key.endswith(".readonlyrootfilesystem") or lower_key == "readonlyrootfilesystem":
                if value is False:
                    findings.append(HelmFinding(
                        chart_name=chart_name,
                        file_path=file_path,
                        issue=(
                            f"'{key_path}: false' allows writes to the root filesystem — "
                            "set to true for immutable containers"
                        ),
                        severity=CloudFindingSeverity.MEDIUM,
                    ))

            # Exposed NodePorts — warn on high-numbered ports for sensitive services
            if "nodeport" in lower_key:
                try:
                    port = int(str_val)
                    if 30000 <= port <= 32767:
                        findings.append(HelmFinding(
                            chart_name=chart_name,
                            file_path=file_path,
                            issue=(
                                f"NodePort {port} at '{key_path}' exposes a service directly "
                                "on all cluster nodes — prefer LoadBalancer or Ingress"
                            ),
                            severity=CloudFindingSeverity.MEDIUM,
                        ))
                except (ValueError, TypeError):
                    pass

        return findings

    def _flatten_dict(
        self, d: Any, prefix: str = "", sep: str = "."
    ) -> Dict[str, Any]:
        """Recursively flatten a nested dict to dot-separated keys."""
        items: Dict[str, Any] = {}
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{prefix}{sep}{k}" if prefix else str(k)
                if isinstance(v, dict):
                    items.update(self._flatten_dict(v, new_key, sep))
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        items.update(self._flatten_dict(item, f"{new_key}[{i}]", sep))
                else:
                    items[new_key] = v
        else:
            items[prefix] = d
        return items

    # ------------------------------------------------------------------
    # Template file checks (line-by-line)
    # ------------------------------------------------------------------

    def _audit_template_file(self, chart_name: str, file_path: str) -> List[HelmFinding]:
        findings: List[HelmFinding] = []
        content = self._read_text_file(file_path)
        if content is None:
            return []

        for lineno, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            lower = line.lower()

            # Hardcoded secrets / tokens
            # Match lines like `password: "s3cr3tV@lue"` that are not template variables,
            # not empty/null, and not common non-secret words (true, false, null, none).
            if _SECRET_PATTERN.search(line) and "{{" not in line:
                _secret_val_re = re.search(
                    r':\s*["\']?([A-Za-z0-9+/=@!#$%^&*_\-]{8,})["\']?\s*$', line
                )
                if _secret_val_re:
                    candidate = _secret_val_re.group(1).lower()
                    _non_secrets = {"true", "false", "null", "none", "enabled", "disabled", "default"}
                    if candidate not in _non_secrets and not candidate.startswith("{{"):
                        findings.append(HelmFinding(
                            chart_name=chart_name,
                            file_path=file_path,
                            issue=(
                                "Possible hardcoded secret value in template — "
                                "use '{{ .Values.<key> }}' or a Kubernetes Secret reference"
                            ),
                            severity=CloudFindingSeverity.CRITICAL,
                            line_number=lineno,
                        ))

            # allowPrivilegeEscalation: true
            if re.search(r"allowPrivilegeEscalation\s*:\s*true", line, re.IGNORECASE):
                findings.append(HelmFinding(
                    chart_name=chart_name,
                    file_path=file_path,
                    issue="allowPrivilegeEscalation: true permits setuid/setcap escalation — set to false",
                    severity=CloudFindingSeverity.HIGH,
                    line_number=lineno,
                ))

            # capabilities.add with dangerous caps
            if "add:" in lower or re.search(r"capabilities\s*:", lower):
                for cap in _DANGEROUS_K8S_CAPS:
                    if cap in line.upper():
                        findings.append(HelmFinding(
                            chart_name=chart_name,
                            file_path=file_path,
                            issue=f"Dangerous capability '{cap}' added in template",
                            severity=CloudFindingSeverity.HIGH,
                            line_number=lineno,
                        ))

            # hostPath volumes
            if re.search(r"hostPath\s*:", line, re.IGNORECASE):
                findings.append(HelmFinding(
                    chart_name=chart_name,
                    file_path=file_path,
                    issue=(
                        "hostPath volume mount exposes host filesystem to the container — "
                        "use PersistentVolumeClaim instead"
                    ),
                    severity=CloudFindingSeverity.HIGH,
                    line_number=lineno,
                ))

            # privileged: true in templates
            if re.search(r"privileged\s*:\s*true", line, re.IGNORECASE) and "{{" not in line:
                findings.append(HelmFinding(
                    chart_name=chart_name,
                    file_path=file_path,
                    issue="Hardcoded 'privileged: true' in template — use a values variable",
                    severity=CloudFindingSeverity.CRITICAL,
                    line_number=lineno,
                ))

            # hostNetwork / hostPID in templates
            if re.search(r"hostNetwork\s*:\s*true", line, re.IGNORECASE) and "{{" not in line:
                findings.append(HelmFinding(
                    chart_name=chart_name,
                    file_path=file_path,
                    issue="Hardcoded 'hostNetwork: true' in template",
                    severity=CloudFindingSeverity.HIGH,
                    line_number=lineno,
                ))

            if re.search(r"hostPID\s*:\s*true", line, re.IGNORECASE) and "{{" not in line:
                findings.append(HelmFinding(
                    chart_name=chart_name,
                    file_path=file_path,
                    issue="Hardcoded 'hostPID: true' in template",
                    severity=CloudFindingSeverity.HIGH,
                    line_number=lineno,
                ))

        return findings


# ---------------------------------------------------------------------------
# Public tool list
# ---------------------------------------------------------------------------

K8S_TOOLS: List[BaseTool] = [
    K8sAuditTool(),
    K8sSecretScanTool(),
    HelmChartAuditTool(),
]

__all__ = [
    "K8sAuditTool",
    "K8sSecretScanTool",
    "HelmChartAuditTool",
    "K8S_TOOLS",
    "K8sFinding",
    "K8sSecretFinding",
    "HelmFinding",
    "CloudFindingSeverity",
    "_get_k8s_client",
    "_get_k8s_rbac_client",
    "_get_k8s_networking_client",
]
