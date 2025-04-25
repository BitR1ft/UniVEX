"""
AutoChain v3 — Template registry.

Provides a unified interface for discovering and instantiating all
Python-based AutoChain templates. JSON templates (htb_easy, htb_medium)
are handled separately by the AutoChain orchestrator via from_template().

Usage
-----
>>> from app.autochain.templates import registry, get_template
>>> registry.list_templates()
>>> tpl = registry.create("web_app_full", target="https://example.com")
>>> plan = tpl.get_scan_plan()
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

from .web_app_full import WebAppFullTemplate, WebAppFullConfig
from .api_pentest import APIPentestTemplate, APIPentestConfig
from .owasp_top10 import OWASPTop10Template, OWASPTop10Config
from .wordpress_full import WordPressFullTemplate, WordPressConfig
from .cloud_assessment import CloudAssessmentTemplate, CloudAssessmentConfig

# v3 templates
from .bugbounty_full import BugBountyFullTemplate, BugBountyConfig
from .ad_full_chain import ADFullChainTemplate, ADFullChainConfig
from .internal_pentest import InternalPentestTemplate, InternalPentestConfig
from .web_app_deep import WebAppDeepTemplate, WebAppDeepConfig

# ---------------------------------------------------------------------------
# Registry entry type
# ---------------------------------------------------------------------------

TemplateClass = (
    Type[WebAppFullTemplate]
    | Type[APIPentestTemplate]
    | Type[OWASPTop10Template]
    | Type[WordPressFullTemplate]
    | Type[CloudAssessmentTemplate]
    | Type[BugBountyFullTemplate]
    | Type[ADFullChainTemplate]
    | Type[InternalPentestTemplate]
    | Type[WebAppDeepTemplate]
)


_REGISTRY: Dict[str, Dict[str, Any]] = {
    WebAppFullTemplate.TEMPLATE_ID: {
        "class": WebAppFullTemplate,
        "config_class": WebAppFullConfig,
        "name": WebAppFullTemplate.NAME,
        "description": WebAppFullTemplate.DESCRIPTION,
        "version": WebAppFullTemplate.VERSION,
        "estimated_minutes": WebAppFullTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "web_application",
        "tags": ["web", "owasp", "xss", "sqli", "api", "injection"],
    },
    APIPentestTemplate.TEMPLATE_ID: {
        "class": APIPentestTemplate,
        "config_class": APIPentestConfig,
        "name": APIPentestTemplate.NAME,
        "description": APIPentestTemplate.DESCRIPTION,
        "version": APIPentestTemplate.VERSION,
        "estimated_minutes": APIPentestTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "api",
        "tags": ["api", "rest", "graphql", "owasp-api", "jwt", "bola"],
    },
    OWASPTop10Template.TEMPLATE_ID: {
        "class": OWASPTop10Template,
        "config_class": OWASPTop10Config,
        "name": OWASPTop10Template.NAME,
        "description": OWASPTop10Template.DESCRIPTION,
        "version": OWASPTop10Template.VERSION,
        "estimated_minutes": OWASPTop10Template.ESTIMATED_DURATION_MINUTES,
        "category": "compliance",
        "tags": ["owasp", "compliance", "top10", "systematic"],
    },
    WordPressFullTemplate.TEMPLATE_ID: {
        "class": WordPressFullTemplate,
        "config_class": WordPressConfig,
        "name": WordPressFullTemplate.NAME,
        "description": WordPressFullTemplate.DESCRIPTION,
        "version": WordPressFullTemplate.VERSION,
        "estimated_minutes": WordPressFullTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "cms",
        "tags": ["wordpress", "cms", "plugins", "wpscan", "xmlrpc"],
    },
    CloudAssessmentTemplate.TEMPLATE_ID: {
        "class": CloudAssessmentTemplate,
        "config_class": CloudAssessmentConfig,
        "name": CloudAssessmentTemplate.NAME,
        "description": CloudAssessmentTemplate.DESCRIPTION,
        "version": CloudAssessmentTemplate.VERSION,
        "estimated_minutes": CloudAssessmentTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "cloud",
        "tags": ["cloud", "aws", "azure", "gcp", "s3", "iam", "kubernetes"],
    },
    # ── v3 templates ──────────────────────────────────────────────────────
    BugBountyFullTemplate.TEMPLATE_ID: {
        "class": BugBountyFullTemplate,
        "config_class": BugBountyConfig,
        "name": BugBountyFullTemplate.NAME,
        "description": BugBountyFullTemplate.DESCRIPTION,
        "version": BugBountyFullTemplate.VERSION,
        "estimated_minutes": BugBountyFullTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "bug_bounty",
        "tags": [
            "bug-bounty", "recon", "subdomain", "takeover", "nuclei",
            "xss", "sqli", "ssrf", "idor", "wayback", "js-analysis",
        ],
    },
    ADFullChainTemplate.TEMPLATE_ID: {
        "class": ADFullChainTemplate,
        "config_class": ADFullChainConfig,
        "name": ADFullChainTemplate.NAME,
        "description": ADFullChainTemplate.DESCRIPTION,
        "version": ADFullChainTemplate.VERSION,
        "estimated_minutes": ADFullChainTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "active_directory",
        "tags": [
            "active-directory", "kerberoast", "as-rep", "dcsync",
            "bloodhound", "golden-ticket", "silver-ticket", "mimikatz",
        ],
    },
    InternalPentestTemplate.TEMPLATE_ID: {
        "class": InternalPentestTemplate,
        "config_class": InternalPentestConfig,
        "name": InternalPentestTemplate.NAME,
        "description": InternalPentestTemplate.DESCRIPTION,
        "version": InternalPentestTemplate.VERSION,
        "estimated_minutes": InternalPentestTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "internal_network",
        "tags": [
            "internal", "network", "pivot", "lateral-movement", "ptes",
            "chisel", "ligolo", "brute-force", "post-exploitation",
        ],
    },
    WebAppDeepTemplate.TEMPLATE_ID: {
        "class": WebAppDeepTemplate,
        "config_class": WebAppDeepConfig,
        "name": WebAppDeepTemplate.NAME,
        "description": WebAppDeepTemplate.DESCRIPTION,
        "version": WebAppDeepTemplate.VERSION,
        "estimated_minutes": WebAppDeepTemplate.ESTIMATED_DURATION_MINUTES,
        "category": "web_application",
        "tags": [
            "web", "deep", "owasp", "wstg", "xss", "sqli", "ssrf", "csrf",
            "idor", "ssti", "xxe", "deserialization", "jwt", "api",
        ],
    },
}


class TemplateRegistry:
    """Central registry for all AutoChain v2/v3 Python templates."""

    def list_templates(self) -> List[Dict[str, Any]]:
        """Return metadata for all registered templates."""
        return [
            {
                "id": tid,
                "name": meta["name"],
                "description": meta["description"],
                "version": meta["version"],
                "estimated_minutes": meta["estimated_minutes"],
                "category": meta["category"],
                "tags": meta["tags"],
            }
            for tid, meta in _REGISTRY.items()
        ]

    def get_metadata(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Return metadata dict for a specific template."""
        entry = _REGISTRY.get(template_id)
        if not entry:
            return None
        return {
            "id": template_id,
            "name": entry["name"],
            "description": entry["description"],
            "version": entry["version"],
            "estimated_minutes": entry["estimated_minutes"],
            "category": entry["category"],
            "tags": entry["tags"],
        }

    def create(
        self,
        template_id: str,
        target: str,
        *,
        config: Optional[Any] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> Any:
        """
        Instantiate a template by ID.

        Parameters
        ----------
        template_id:
            One of the registered template IDs.
        target:
            Target URL or IP address.
        config:
            Optional pre-built config dataclass instance.
            If None the template's default config is used.
        project_id:
            Optional project association.
        auto_approve_risk_level:
            Risk level for auto-approval.

        Returns
        -------
        Template instance.

        Raises
        ------
        ValueError
            If the template_id is not registered.
        """
        entry = _REGISTRY.get(template_id)
        if not entry:
            available = list(_REGISTRY.keys())
            raise ValueError(
                f"Unknown template '{template_id}'. Available: {available}"
            )
        cls: TemplateClass = entry["class"]
        return cls(
            target=target,
            config=config,
            project_id=project_id,
            auto_approve_risk_level=auto_approve_risk_level,
        )

    def get_scan_plan(self, template_id: str, target: str, **kwargs: Any) -> Dict[str, Any]:
        """Convenience: create template and return its scan plan."""
        tpl = self.create(template_id, target, **kwargs)
        return tpl.get_scan_plan()

    def is_registered(self, template_id: str) -> bool:
        return template_id in _REGISTRY

    def list_categories(self) -> List[str]:
        return sorted({meta["category"] for meta in _REGISTRY.values()})

    def list_by_category(self, category: str) -> List[Dict[str, Any]]:
        return [
            self.get_metadata(tid)
            for tid, meta in _REGISTRY.items()
            if meta["category"] == category
        ]  # type: ignore[return-value]


# Singleton instance
registry = TemplateRegistry()


def get_template(template_id: str, target: str, **kwargs: Any) -> Any:
    """Module-level shortcut for ``registry.create()``."""
    return registry.create(template_id, target, **kwargs)


__all__ = [
    "registry",
    "get_template",
    "TemplateRegistry",
    # v2
    "WebAppFullTemplate",
    "WebAppFullConfig",
    "APIPentestTemplate",
    "APIPentestConfig",
    "OWASPTop10Template",
    "OWASPTop10Config",
    "WordPressFullTemplate",
    "WordPressConfig",
    "CloudAssessmentTemplate",
    "CloudAssessmentConfig",
    # v3
    "BugBountyFullTemplate",
    "BugBountyConfig",
    "ADFullChainTemplate",
    "ADFullChainConfig",
    "InternalPentestTemplate",
    "InternalPentestConfig",
    "WebAppDeepTemplate",
    "WebAppDeepConfig",
]
