"""
80+ tests covering the four AutoChain v3 templates:
  - BugBountyFullTemplate
  - ADFullChainTemplate
  - InternalPentestTemplate
  - WebAppDeepTemplate
  - TemplateRegistry v3 additions
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.autochain.templates import (
    registry,
    BugBountyFullTemplate,
    BugBountyConfig,
    ADFullChainTemplate,
    ADFullChainConfig,
    InternalPentestTemplate,
    InternalPentestConfig,
    WebAppDeepTemplate,
    WebAppDeepConfig,
)
from app.autochain.templates.bugbounty_full import BugBountyScope
from app.autochain.templates.ad_full_chain import ADPhase, HashType
from app.autochain.templates.internal_pentest import PivotMethod, AccessLevel
from app.autochain.templates.web_app_deep import WebAppTech, AuthType


# ===========================================================================
# Fixtures
# ===========================================================================

TARGET = "https://example.com"
AD_TARGET = "10.10.10.0/24"
INTERNAL_TARGET = "192.168.1.0/24"


@pytest.fixture
def bb_template() -> BugBountyFullTemplate:
    return BugBountyFullTemplate(TARGET)


@pytest.fixture
def bb_config() -> BugBountyConfig:
    return BugBountyConfig()


@pytest.fixture
def ad_template() -> ADFullChainTemplate:
    return ADFullChainTemplate(AD_TARGET)


@pytest.fixture
def ad_config() -> ADFullChainConfig:
    return ADFullChainConfig(domain="CORP.LOCAL", dc_ip="10.10.10.1")


@pytest.fixture
def internal_template() -> InternalPentestTemplate:
    return InternalPentestTemplate(INTERNAL_TARGET)


@pytest.fixture
def internal_config() -> InternalPentestConfig:
    return InternalPentestConfig(
        network_ranges=["192.168.1.0/24"],
        access_level=AccessLevel.VPN,
    )


@pytest.fixture
def deep_template() -> WebAppDeepTemplate:
    return WebAppDeepTemplate(TARGET)


@pytest.fixture
def deep_config() -> WebAppDeepConfig:
    return WebAppDeepConfig()


# ===========================================================================
# TemplateRegistry — v3 additions
# ===========================================================================

class TestRegistryV3:
    def test_nine_templates_registered(self) -> None:
        tpls = registry.list_templates()
        assert len(tpls) == 9

    def test_v3_template_ids_registered(self) -> None:
        for tid in ["bugbounty_full", "ad_full_chain", "internal_pentest", "web_app_deep"]:
            assert registry.is_registered(tid), f"{tid} should be registered"

    def test_new_categories_exist(self) -> None:
        cats = registry.list_categories()
        assert "bug_bounty" in cats
        assert "active_directory" in cats
        assert "internal_network" in cats

    def test_list_by_category_bug_bounty(self) -> None:
        items = registry.list_by_category("bug_bounty")
        assert len(items) == 1
        assert items[0]["id"] == "bugbounty_full"

    def test_list_by_category_ad(self) -> None:
        items = registry.list_by_category("active_directory")
        assert len(items) == 1
        assert items[0]["id"] == "ad_full_chain"

    def test_list_by_category_internal(self) -> None:
        items = registry.list_by_category("internal_network")
        assert len(items) == 1
        assert items[0]["id"] == "internal_pentest"

    def test_list_by_category_web_has_two(self) -> None:
        items = registry.list_by_category("web_application")
        ids = [i["id"] for i in items]
        assert "web_app_full" in ids
        assert "web_app_deep" in ids

    def test_create_bugbounty_template(self) -> None:
        tpl = registry.create("bugbounty_full", TARGET)
        assert isinstance(tpl, BugBountyFullTemplate)

    def test_create_ad_template(self) -> None:
        tpl = registry.create("ad_full_chain", AD_TARGET)
        assert isinstance(tpl, ADFullChainTemplate)

    def test_create_internal_template(self) -> None:
        tpl = registry.create("internal_pentest", INTERNAL_TARGET)
        assert isinstance(tpl, InternalPentestTemplate)

    def test_create_web_deep_template(self) -> None:
        tpl = registry.create("web_app_deep", TARGET)
        assert isinstance(tpl, WebAppDeepTemplate)

    def test_get_scan_plan_via_registry(self) -> None:
        for tid, tgt in [
            ("bugbounty_full", TARGET),
            ("ad_full_chain", AD_TARGET),
            ("internal_pentest", INTERNAL_TARGET),
            ("web_app_deep", TARGET),
        ]:
            plan = registry.get_scan_plan(tid, tgt)
            assert plan["template_id"] == tid
            assert plan["target"] == tgt
            assert "phases" in plan

    def test_v3_templates_have_version_3(self) -> None:
        for tid in ["bugbounty_full", "ad_full_chain", "internal_pentest", "web_app_deep"]:
            meta = registry.get_metadata(tid)
            assert meta is not None
            assert meta["version"].startswith("3."), f"{tid} version should be 3.x"

    def test_v3_templates_metadata_structure(self) -> None:
        for tid in ["bugbounty_full", "ad_full_chain", "internal_pentest", "web_app_deep"]:
            meta = registry.get_metadata(tid)
            assert meta is not None
            for key in ["id", "name", "description", "version", "estimated_minutes", "category", "tags"]:
                assert key in meta, f"Missing key '{key}' in {tid} metadata"
            assert len(meta["tags"]) >= 5, f"{tid} should have at least 5 tags"


# ===========================================================================
# BugBountyFullTemplate
# ===========================================================================

class TestBugBountyFullTemplate:
    def test_template_id(self, bb_template: BugBountyFullTemplate) -> None:
        assert bb_template.TEMPLATE_ID == "bugbounty_full"

    def test_version_is_3(self, bb_template: BugBountyFullTemplate) -> None:
        assert bb_template.VERSION.startswith("3.")

    def test_estimated_duration_reasonable(self, bb_template: BugBountyFullTemplate) -> None:
        assert bb_template.ESTIMATED_DURATION_MINUTES >= 60

    def test_phase_order_not_empty(self, bb_template: BugBountyFullTemplate) -> None:
        assert len(bb_template.PHASE_ORDER) >= 10

    def test_phase_order_starts_with_subdomain_enum(self, bb_template: BugBountyFullTemplate) -> None:
        assert bb_template.PHASE_ORDER[0] == "subdomain_enum"

    def test_phase_order_ends_with_report(self, bb_template: BugBountyFullTemplate) -> None:
        assert bb_template.PHASE_ORDER[-1] == "report"

    def test_phase_tools_all_phases_covered(self, bb_template: BugBountyFullTemplate) -> None:
        for phase_id in bb_template.PHASE_ORDER:
            assert phase_id in bb_template.PHASE_TOOLS, f"Phase '{phase_id}' missing from PHASE_TOOLS"
            assert len(bb_template.PHASE_TOOLS[phase_id]) >= 1

    def test_get_scan_plan_structure(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        assert plan["template_id"] == "bugbounty_full"
        assert plan["target"] == TARGET
        assert "phases" in plan
        assert len(plan["phases"]) == len(bb_template.PHASE_ORDER)

    def test_get_scan_plan_phase_fields(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        required = {"phase", "name", "tools", "config", "on_failure",
                    "description", "estimated_minutes", "skippable"}
        for phase in plan["phases"]:
            for field in required:
                assert field in phase, f"Phase '{phase['phase']}' missing field '{field}'"

    def test_get_scan_plan_has_scope(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        assert "scope" in plan
        assert plan["scope"] == BugBountyScope.WILDCARD.value

    def test_get_scan_plan_has_rate_limit(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        assert "rate_limit_rps" in plan
        assert plan["rate_limit_rps"] > 0

    def test_get_all_tools_no_duplicates(self, bb_template: BugBountyFullTemplate) -> None:
        tools = bb_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_get_all_tools_includes_nuclei(self, bb_template: BugBountyFullTemplate) -> None:
        assert "nuclei" in bb_template.get_all_tools()

    def test_get_all_tools_includes_sqlmap(self, bb_template: BugBountyFullTemplate) -> None:
        assert "sqlmap" in bb_template.get_all_tools()

    def test_get_nuclei_command(self, bb_template: BugBountyFullTemplate) -> None:
        cmd = bb_template.get_nuclei_command()
        assert "targets" in cmd
        assert "templates" in cmd
        assert "severity" in cmd
        assert isinstance(cmd["templates"], list)

    def test_get_enabled_phases_default_all_enabled(self, bb_template: BugBountyFullTemplate) -> None:
        enabled = bb_template.get_enabled_phases()
        # By default all phases are enabled
        assert len(enabled) == len(bb_template.PHASE_ORDER)

    def test_get_enabled_phases_respects_config(self) -> None:
        cfg = BugBountyConfig(xss_enabled=False, sqli_enabled=False)
        tpl = BugBountyFullTemplate(TARGET, config=cfg)
        enabled = tpl.get_enabled_phases()
        assert "xss" not in enabled
        assert "sqli" not in enabled

    def test_custom_config_rate_limit(self) -> None:
        cfg = BugBountyConfig(rate_limit_rps=50)
        tpl = BugBountyFullTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["rate_limit_rps"] == 50

    def test_custom_scope_single(self) -> None:
        cfg = BugBountyConfig(scope=BugBountyScope.SINGLE)
        tpl = BugBountyFullTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["scope"] == BugBountyScope.SINGLE.value

    def test_excluded_subdomains_in_plan(self) -> None:
        cfg = BugBountyConfig(excluded_subdomains=["staging.example.com", "dev.example.com"])
        tpl = BugBountyFullTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert "staging.example.com" in plan["excluded_subdomains"]

    def test_severity_cvss_mapping(self, bb_template: BugBountyFullTemplate) -> None:
        assert "critical" in bb_template.SEVERITY_CVSS
        assert "high" in bb_template.SEVERITY_CVSS
        assert "medium" in bb_template.SEVERITY_CVSS

    def test_out_of_scope_patterns_present(self, bb_template: BugBountyFullTemplate) -> None:
        assert len(bb_template.OUT_OF_SCOPE_PATTERNS) >= 3
        assert "localhost" in bb_template.OUT_OF_SCOPE_PATTERNS

    def test_project_id_passed_through(self) -> None:
        tpl = BugBountyFullTemplate(TARGET, project_id="proj-42")
        plan = tpl.get_scan_plan()
        assert plan["project_id"] == "proj-42"

    def test_nuclei_phase_config_has_severity(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        nuclei_phase = next(p for p in plan["phases"] if p["phase"] == "nuclei_scan")
        assert "severity" in nuclei_phase["config"]

    def test_report_phase_config_has_format(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        report_phase = next(p for p in plan["phases"] if p["phase"] == "report")
        assert "format" in report_phase["config"]

    def test_phase_estimates_sum(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        total = sum(p["estimated_minutes"] for p in plan["phases"])
        assert total > 0

    def test_skippable_phases(self, bb_template: BugBountyFullTemplate) -> None:
        plan = bb_template.get_scan_plan()
        non_skip = [p for p in plan["phases"] if not p["skippable"]]
        assert any(p["phase"] == "subdomain_enum" for p in non_skip)
        assert any(p["phase"] == "http_probe" for p in non_skip)


# ===========================================================================
# ADFullChainTemplate
# ===========================================================================

class TestADFullChainTemplate:
    def test_template_id(self, ad_template: ADFullChainTemplate) -> None:
        assert ad_template.TEMPLATE_ID == "ad_full_chain"

    def test_version_is_3(self, ad_template: ADFullChainTemplate) -> None:
        assert ad_template.VERSION.startswith("3.")

    def test_phase_order_count(self, ad_template: ADFullChainTemplate) -> None:
        assert len(ad_template.PHASE_ORDER) >= 12

    def test_phase_order_starts_with_network_scan(self, ad_template: ADFullChainTemplate) -> None:
        assert ad_template.PHASE_ORDER[0] == "network_scan"

    def test_phase_order_ends_with_report(self, ad_template: ADFullChainTemplate) -> None:
        assert ad_template.PHASE_ORDER[-1] == "report"

    def test_all_phases_have_tools(self, ad_template: ADFullChainTemplate) -> None:
        for phase_id in ad_template.PHASE_ORDER:
            assert phase_id in ad_template.PHASE_TOOLS
            assert len(ad_template.PHASE_TOOLS[phase_id]) >= 1

    def test_get_scan_plan_structure(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        assert plan["template_id"] == "ad_full_chain"
        assert plan["target"] == AD_TARGET
        assert "phases" in plan
        assert len(plan["phases"]) == len(ad_template.PHASE_ORDER)

    def test_get_scan_plan_has_mitre_mapping(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        assert "mitre_mapping" in plan
        assert len(plan["mitre_mapping"]) > 0

    def test_phase_has_mitre_techniques(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        for phase in plan["phases"]:
            assert "mitre_techniques" in phase

    def test_phase_has_requires_credentials(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        cred_phases = [p for p in plan["phases"] if p["requires_credentials"]]
        # DCSync, golden/silver ticket require credentials
        cred_ids = [p["phase"] for p in cred_phases]
        assert "dcsync" in cred_ids

    def test_get_all_tools_no_duplicates(self, ad_template: ADFullChainTemplate) -> None:
        tools = ad_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_get_all_tools_includes_bloodhound(self, ad_template: ADFullChainTemplate) -> None:
        tools = ad_template.get_all_tools()
        assert any("bloodhound" in t for t in tools)

    def test_get_attack_path_queries(self, ad_template: ADFullChainTemplate) -> None:
        queries = ad_template.get_attack_path_queries()
        assert len(queries) >= 4
        for q in queries:
            assert "name" in q
            assert "query" in q

    def test_get_enabled_phases_respects_config(self) -> None:
        cfg = ADFullChainConfig(golden_ticket_enabled=False, silver_ticket_enabled=False)
        tpl = ADFullChainTemplate(AD_TARGET, config=cfg)
        enabled = tpl.get_enabled_phases()
        assert "golden_ticket" not in enabled
        assert "silver_ticket" not in enabled

    def test_config_domain_dc_ip_in_plan(self) -> None:
        cfg = ADFullChainConfig(domain="CORP.LOCAL", dc_ip="10.10.10.1")
        tpl = ADFullChainTemplate(AD_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["domain"] == "CORP.LOCAL"
        assert plan["dc_ip"] == "10.10.10.1"

    def test_dcsync_phase_config(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        dcsync = next(p for p in plan["phases"] if p["phase"] == "dcsync")
        assert "target_user" in dcsync["config"]
        assert dcsync["config"]["target_user"] == "krbtgt"

    def test_bloodhound_phase_has_collection_method(self) -> None:
        cfg = ADFullChainConfig(bloodhound_collection_method="DCOnly")
        tpl = ADFullChainTemplate(AD_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        bh = next(p for p in plan["phases"] if p["phase"] == "bloodhound")
        assert bh["config"]["method"] == "DCOnly"

    def test_hash_crack_phase_config(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        hc = next(p for p in plan["phases"] if p["phase"] == "hash_crack")
        assert "wordlist" in hc["config"]
        assert "modes" in hc["config"]
        assert HashType.NTLM.value in hc["config"]["modes"]

    def test_kerbrute_phase_present(self, ad_template: ADFullChainTemplate) -> None:
        phases = [p["phase"] for p in ad_template.get_scan_plan()["phases"]]
        assert "kerbrute" in phases

    def test_asrep_kerberoast_phases_present(self, ad_template: ADFullChainTemplate) -> None:
        phases = [p["phase"] for p in ad_template.get_scan_plan()["phases"]]
        assert "asrep_roast" in phases
        assert "kerberoast" in phases

    def test_default_auto_approve_risk_high(self, ad_template: ADFullChainTemplate) -> None:
        plan = ad_template.get_scan_plan()
        assert plan["auto_approve_risk_level"] == "high"


# ===========================================================================
# InternalPentestTemplate
# ===========================================================================

class TestInternalPentestTemplate:
    def test_template_id(self, internal_template: InternalPentestTemplate) -> None:
        assert internal_template.TEMPLATE_ID == "internal_pentest"

    def test_version_is_3(self, internal_template: InternalPentestTemplate) -> None:
        assert internal_template.VERSION.startswith("3.")

    def test_phase_order_count(self, internal_template: InternalPentestTemplate) -> None:
        assert len(internal_template.PHASE_ORDER) >= 10

    def test_phase_order_starts_host_discovery(self, internal_template: InternalPentestTemplate) -> None:
        assert internal_template.PHASE_ORDER[0] == "host_discovery"

    def test_phase_order_ends_with_report(self, internal_template: InternalPentestTemplate) -> None:
        assert internal_template.PHASE_ORDER[-1] == "report"

    def test_all_phases_have_tools(self, internal_template: InternalPentestTemplate) -> None:
        for phase_id in internal_template.PHASE_ORDER:
            assert phase_id in internal_template.PHASE_TOOLS
            assert len(internal_template.PHASE_TOOLS[phase_id]) >= 1

    def test_get_scan_plan_structure(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        assert plan["template_id"] == "internal_pentest"
        assert plan["target"] == INTERNAL_TARGET
        assert "phases" in plan

    def test_get_scan_plan_has_network_ranges(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        assert "network_ranges" in plan
        assert isinstance(plan["network_ranges"], list)

    def test_get_scan_plan_has_pivot_method(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        assert "pivot_method" in plan
        assert plan["pivot_method"] == PivotMethod.CHISEL.value

    def test_ptes_mapping_in_plan(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        assert "ptes_mapping" in plan
        for phase in plan["phases"]:
            assert "ptes_phase" in phase

    def test_get_pivot_config(self, internal_template: InternalPentestTemplate) -> None:
        pivot = internal_template.get_pivot_config()
        assert "method" in pivot
        assert "listener_port" in pivot
        assert "socks_port" in pivot

    def test_custom_pivot_method(self) -> None:
        cfg = InternalPentestConfig(pivot_method=PivotMethod.LIGOLO)
        tpl = InternalPentestTemplate(INTERNAL_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["pivot_method"] == PivotMethod.LIGOLO.value

    def test_get_all_tools_no_duplicates(self, internal_template: InternalPentestTemplate) -> None:
        tools = internal_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_get_all_tools_includes_nmap(self, internal_template: InternalPentestTemplate) -> None:
        assert "nmap" in internal_template.get_all_tools()

    def test_get_enabled_phases_respects_config(self) -> None:
        cfg = InternalPentestConfig(pivot_enabled=False, exploit_enabled=False)
        tpl = InternalPentestTemplate(INTERNAL_TARGET, config=cfg)
        enabled = tpl.get_enabled_phases()
        assert "pivot_setup" not in enabled
        assert "initial_access" not in enabled

    def test_brute_services_configurable(self) -> None:
        cfg = InternalPentestConfig(brute_services=["ssh", "ftp"])
        tpl = InternalPentestTemplate(INTERNAL_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        brute = next(p for p in plan["phases"] if p["phase"] == "credential_bruteforce")
        assert brute["config"]["services"] == ["ssh", "ftp"]

    def test_vuln_scan_cve_checks(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        vuln = next(p for p in plan["phases"] if p["phase"] == "vuln_scan")
        assert "eternalblue" in vuln["config"]
        assert "log4shell" in vuln["config"]

    def test_internal_scan_via_pivot(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        internal = next(p for p in plan["phases"] if p["phase"] == "internal_scan")
        assert internal["config"].get("via_pivot") is True

    def test_sensitive_data_patterns_configurable(self) -> None:
        cfg = InternalPentestConfig(sensitive_patterns=["*.key", ".env"])
        tpl = InternalPentestTemplate(INTERNAL_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        data = next(p for p in plan["phases"] if p["phase"] == "sensitive_data")
        assert "*.key" in data["config"]["patterns"]

    def test_access_level_default_vpn(self, internal_template: InternalPentestTemplate) -> None:
        plan = internal_template.get_scan_plan()
        assert plan["access_level"] == AccessLevel.VPN.value

    def test_access_level_domain_admin(self) -> None:
        cfg = InternalPentestConfig(access_level=AccessLevel.DOMAIN_ADMIN)
        tpl = InternalPentestTemplate(INTERNAL_TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["access_level"] == AccessLevel.DOMAIN_ADMIN.value

    def test_estimated_duration_over_2hrs(self, internal_template: InternalPentestTemplate) -> None:
        assert internal_template.ESTIMATED_DURATION_MINUTES >= 120


# ===========================================================================
# WebAppDeepTemplate
# ===========================================================================

class TestWebAppDeepTemplate:
    def test_template_id(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.TEMPLATE_ID == "web_app_deep"

    def test_version_is_3(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.VERSION.startswith("3.")

    def test_phase_order_count(self, deep_template: WebAppDeepTemplate) -> None:
        assert len(deep_template.PHASE_ORDER) >= 15

    def test_phase_order_starts_with_crawl(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.PHASE_ORDER[0] == "crawl"

    def test_phase_order_ends_with_report(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.PHASE_ORDER[-1] == "report"

    def test_all_phases_have_tools(self, deep_template: WebAppDeepTemplate) -> None:
        for phase_id in deep_template.PHASE_ORDER:
            assert phase_id in deep_template.PHASE_TOOLS
            assert len(deep_template.PHASE_TOOLS[phase_id]) >= 1

    def test_get_scan_plan_structure(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        assert plan["template_id"] == "web_app_deep"
        assert plan["target"] == TARGET
        assert "phases" in plan
        assert len(plan["phases"]) == len(deep_template.PHASE_ORDER)

    def test_owasp_mapping_in_plan(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        assert "owasp_top10_mapping" in plan
        assert len(plan["owasp_top10_mapping"]) > 0

    def test_wstg_mapping_in_plan(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        assert "wstg_mapping" in plan
        assert len(plan["wstg_mapping"]) > 0

    def test_phase_has_owasp_and_wstg_fields(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        for phase in plan["phases"]:
            assert "owasp_mapping" in phase
            assert "wstg_mapping" in phase

    def test_get_all_tools_no_duplicates(self, deep_template: WebAppDeepTemplate) -> None:
        tools = deep_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_get_all_tools_includes_sqlmap(self, deep_template: WebAppDeepTemplate) -> None:
        assert "sqlmap" in deep_template.get_all_tools()

    def test_get_all_tools_includes_jwt_tool(self, deep_template: WebAppDeepTemplate) -> None:
        assert "jwt_tool" in deep_template.get_all_tools()

    def test_get_payload_set_xss(self, deep_template: WebAppDeepTemplate) -> None:
        payloads = deep_template.get_payload_set("xss")
        assert len(payloads) >= 3
        assert any("<script>" in p for p in payloads)

    def test_get_payload_set_sqli(self, deep_template: WebAppDeepTemplate) -> None:
        payloads = deep_template.get_payload_set("sqli")
        assert len(payloads) >= 2

    def test_get_payload_set_ssti(self, deep_template: WebAppDeepTemplate) -> None:
        payloads = deep_template.get_payload_set("ssti")
        assert "{{7*7}}" in payloads

    def test_get_payload_set_unknown_returns_empty(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.get_payload_set("nonexistent") == []

    def test_get_enabled_phases_respects_config(self) -> None:
        cfg = WebAppDeepConfig(jwt_enabled=False, xxe_enabled=False)
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        enabled = tpl.get_enabled_phases()
        assert "jwt_attacks" not in enabled
        assert "xxe" not in enabled

    def test_app_tech_configurable(self) -> None:
        cfg = WebAppDeepConfig(app_tech=WebAppTech.JAVA)
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["app_tech"] == WebAppTech.JAVA.value

    def test_auth_type_in_plan(self) -> None:
        cfg = WebAppDeepConfig(auth_type=AuthType.JWT, valid_token="Bearer abc123")
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["auth_type"] == AuthType.JWT.value

    def test_jwt_phase_config_with_token(self) -> None:
        cfg = WebAppDeepConfig(auth_type=AuthType.JWT, valid_token="eyJhbGci...")
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        jwt_phase = next(p for p in plan["phases"] if p["phase"] == "jwt_attacks")
        assert jwt_phase["config"]["token"] == "eyJhbGci..."

    def test_sqli_level_risk_configurable(self) -> None:
        cfg = WebAppDeepConfig(sqli_level=5, sqli_risk=3)
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        sqli = next(p for p in plan["phases"] if p["phase"] == "sqli")
        assert sqli["config"]["level"] == 5
        assert sqli["config"]["risk"] == 3

    def test_ssti_engines_configurable(self) -> None:
        cfg = WebAppDeepConfig(ssti_engines=["jinja2", "twig"])
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        ssti = next(p for p in plan["phases"] if p["phase"] == "ssti")
        assert "jinja2" in ssti["config"]["engines"]

    def test_crawl_phase_config(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        crawl = next(p for p in plan["phases"] if p["phase"] == "crawl")
        assert "depth" in crawl["config"]
        assert "max_urls" in crawl["config"]

    def test_deserialization_phase_present(self, deep_template: WebAppDeepTemplate) -> None:
        phases = [p["phase"] for p in deep_template.get_scan_plan()["phases"]]
        assert "deserialization" in phases

    def test_auth_bypass_phase_present(self, deep_template: WebAppDeepTemplate) -> None:
        phases = [p["phase"] for p in deep_template.get_scan_plan()["phases"]]
        assert "auth_bypass" in phases

    def test_owasp_ssrf_mapped(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        ssrf = next(p for p in plan["phases"] if p["phase"] == "ssrf")
        assert "A10:2021-Server-Side Request Forgery" in ssrf["owasp_mapping"]

    def test_wstg_xss_mapped(self, deep_template: WebAppDeepTemplate) -> None:
        plan = deep_template.get_scan_plan()
        xss = next(p for p in plan["phases"] if p["phase"] == "xss")
        assert any("WSTG-INPV" in m for m in xss["wstg_mapping"])

    def test_project_id_in_plan(self) -> None:
        tpl = WebAppDeepTemplate(TARGET, project_id="proj-99")
        assert tpl.get_scan_plan()["project_id"] == "proj-99"

    def test_blind_xss_callback_configurable(self) -> None:
        cfg = WebAppDeepConfig(
            xss_blind=True,
            blind_xss_callback="https://xss.hunter/payload",
        )
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        xss = next(p for p in plan["phases"] if p["phase"] == "xss")
        assert xss["config"]["blind_callback"] == "https://xss.hunter/payload"

    def test_waf_bypass_level_configurable(self) -> None:
        cfg = WebAppDeepConfig(waf_bypass_level=5)
        tpl = WebAppDeepTemplate(TARGET, config=cfg)
        plan = tpl.get_scan_plan()
        waf = next(p for p in plan["phases"] if p["phase"] == "waf_detect")
        assert waf["config"]["bypass_level"] == 5

    def test_estimated_duration_over_2hrs(self, deep_template: WebAppDeepTemplate) -> None:
        assert deep_template.ESTIMATED_DURATION_MINUTES >= 120


# ===========================================================================
# Cross-template v3 consistency
# ===========================================================================

@pytest.mark.parametrize("template_id,target", [
    ("bugbounty_full", TARGET),
    ("ad_full_chain", AD_TARGET),
    ("internal_pentest", INTERNAL_TARGET),
    ("web_app_deep", TARGET),
])
class TestCrossTemplateV3:
    def test_scan_plan_has_required_keys(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        required = {
            "template_id", "name", "description", "version",
            "target", "estimated_duration_minutes", "phases",
        }
        for key in required:
            assert key in plan, f"Plan for {template_id} missing key '{key}'"

    def test_phase_names_are_strings(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["name"], str)
            assert len(phase["name"]) > 0

    def test_phase_descriptions_are_strings(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["description"], str)

    def test_phase_tools_are_lists(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["tools"], list)

    def test_phase_configs_are_dicts(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["config"], dict)

    def test_on_failure_is_continue(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert phase["on_failure"] == "continue"

    def test_version_starts_with_3(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["version"].startswith("3."), f"{template_id} version should be 3.x"

    def test_estimated_duration_positive(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["estimated_duration_minutes"] > 0

    def test_last_phase_is_report(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["phases"][-1]["phase"] == "report"

    def test_get_all_tools_returns_list(self, template_id: str, target: str) -> None:
        tpl = registry.create(template_id, target)
        tools = tpl.get_all_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_get_enabled_phases_subset_of_all(self, template_id: str, target: str) -> None:
        tpl = registry.create(template_id, target)
        enabled = tpl.get_enabled_phases()
        all_phases = tpl.PHASE_ORDER
        for p in enabled:
            assert p in all_phases
