"""
80+ tests covering:
  - WebAppFullTemplate
  - APIPentestTemplate
  - OWASPTop10Template
  - WordPressFullTemplate
  - CloudAssessmentTemplate
  - TemplateRegistry
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from app.autochain.templates import (
    TemplateRegistry,
    get_template,
    registry,
    WebAppFullTemplate,
    WebAppFullConfig,
    APIPentestTemplate,
    APIPentestConfig,
    OWASPTop10Template,
    OWASPTop10Config,
    WordPressFullTemplate,
    WordPressConfig,
    CloudAssessmentTemplate,
    CloudAssessmentConfig,
)
from app.autochain.templates.web_app_full import WebPhase, TemplateRunResult
from app.autochain.templates.owasp_top10 import OWASPA
from app.autochain.templates.cloud_assessment import CloudProvider


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def web_target() -> str:
    return "https://example.com"


@pytest.fixture
def api_target() -> str:
    return "https://api.example.com"


@pytest.fixture
def wp_target() -> str:
    return "https://blog.example.com"


@pytest.fixture
def cloud_target() -> str:
    return "https://app.example.com"


@pytest.fixture
def web_template(web_target: str) -> WebAppFullTemplate:
    return WebAppFullTemplate(web_target)


@pytest.fixture
def api_template(api_target: str) -> APIPentestTemplate:
    return APIPentestTemplate(api_target)


@pytest.fixture
def owasp_template(web_target: str) -> OWASPTop10Template:
    return OWASPTop10Template(web_target)


@pytest.fixture
def wp_template(wp_target: str) -> WordPressFullTemplate:
    return WordPressFullTemplate(wp_target)


@pytest.fixture
def cloud_template(cloud_target: str) -> CloudAssessmentTemplate:
    return CloudAssessmentTemplate(cloud_target)


# ===========================================================================
# TemplateRegistry tests
# ===========================================================================

class TestTemplateRegistry:
    def test_singleton_instance(self) -> None:
        assert registry is not None
        assert isinstance(registry, TemplateRegistry)

    def test_list_templates_returns_five(self) -> None:
        tpls = registry.list_templates()
        # v2: 5 templates; v3 adds 4 more → 9 total
        assert len(tpls) == 9

    def test_list_templates_structure(self) -> None:
        for tpl in registry.list_templates():
            assert "id" in tpl
            assert "name" in tpl
            assert "description" in tpl
            assert "version" in tpl
            assert "estimated_minutes" in tpl
            assert "category" in tpl
            assert "tags" in tpl

    def test_is_registered_known(self) -> None:
        for tid in ["web_app_full", "api_pentest", "owasp_top10", "wordpress_full", "cloud_assessment"]:
            assert registry.is_registered(tid), f"{tid} should be registered"

    def test_is_registered_unknown(self) -> None:
        assert not registry.is_registered("does_not_exist")

    def test_list_categories(self) -> None:
        cats = registry.list_categories()
        assert "web_application" in cats
        assert "api" in cats
        assert "compliance" in cats
        assert "cms" in cats
        assert "cloud" in cats

    def test_list_by_category_web(self) -> None:
        items = registry.list_by_category("web_application")
        # web_app_full (v2) + web_app_deep (v3)
        assert len(items) == 2
        ids = [i["id"] for i in items]
        assert "web_app_full" in ids
        assert "web_app_deep" in ids

    def test_list_by_category_api(self) -> None:
        items = registry.list_by_category("api")
        assert len(items) == 1
        assert items[0]["id"] == "api_pentest"

    def test_list_by_category_unknown(self) -> None:
        items = registry.list_by_category("nonexistent")
        assert items == []

    def test_create_web_app_full(self, web_target: str) -> None:
        tpl = registry.create("web_app_full", web_target)
        assert isinstance(tpl, WebAppFullTemplate)

    def test_create_api_pentest(self, api_target: str) -> None:
        tpl = registry.create("api_pentest", api_target)
        assert isinstance(tpl, APIPentestTemplate)

    def test_create_owasp_top10(self, web_target: str) -> None:
        tpl = registry.create("owasp_top10", web_target)
        assert isinstance(tpl, OWASPTop10Template)

    def test_create_wordpress_full(self, wp_target: str) -> None:
        tpl = registry.create("wordpress_full", wp_target)
        assert isinstance(tpl, WordPressFullTemplate)

    def test_create_cloud_assessment(self, cloud_target: str) -> None:
        tpl = registry.create("cloud_assessment", cloud_target)
        assert isinstance(tpl, CloudAssessmentTemplate)

    def test_create_unknown_raises_value_error(self, web_target: str) -> None:
        with pytest.raises(ValueError, match="Unknown template"):
            registry.create("nonexistent", web_target)

    def test_get_metadata_known(self) -> None:
        meta = registry.get_metadata("web_app_full")
        assert meta is not None
        assert meta["id"] == "web_app_full"

    def test_get_metadata_unknown_returns_none(self) -> None:
        assert registry.get_metadata("nonexistent") is None

    def test_get_scan_plan_shortcut(self, web_target: str) -> None:
        plan = registry.get_scan_plan("web_app_full", web_target)
        assert plan["template_id"] == "web_app_full"
        assert "phases" in plan

    def test_module_level_get_template(self, web_target: str) -> None:
        tpl = get_template("web_app_full", web_target)
        assert isinstance(tpl, WebAppFullTemplate)


# ===========================================================================
# WebAppFullTemplate tests
# ===========================================================================

class TestWebAppFullTemplate:
    def test_template_id(self, web_template: WebAppFullTemplate) -> None:
        assert web_template.TEMPLATE_ID == "web_app_full"

    def test_version(self, web_template: WebAppFullTemplate) -> None:
        assert web_template.VERSION == "2.0.0"

    def test_phase_order(self, web_template: WebAppFullTemplate) -> None:
        phases = web_template.PHASE_ORDER
        assert phases[0] == WebPhase.RECON
        assert phases[-1] == WebPhase.REPORT
        assert len(phases) == 10

    def test_scan_plan_keys(self, web_template: WebAppFullTemplate) -> None:
        plan = web_template.get_scan_plan()
        for key in ["template_id", "name", "description", "version", "target", "phases", "config"]:
            assert key in plan, f"Key '{key}' missing from scan plan"

    def test_scan_plan_target(self, web_template: WebAppFullTemplate, web_target: str) -> None:
        plan = web_template.get_scan_plan()
        assert plan["target"] == web_target

    def test_scan_plan_phases_count(self, web_template: WebAppFullTemplate) -> None:
        plan = web_template.get_scan_plan()
        assert len(plan["phases"]) == 10

    def test_phase_has_required_fields(self, web_template: WebAppFullTemplate) -> None:
        plan = web_template.get_scan_plan()
        for phase in plan["phases"]:
            for field in ["phase", "name", "tools", "config", "description", "estimated_minutes"]:
                assert field in phase, f"Phase missing field '{field}'"

    def test_get_phase_tools_recon(self, web_template: WebAppFullTemplate) -> None:
        tools = web_template.get_phase_tools(WebPhase.RECON)
        assert "naabu" in tools

    def test_get_phase_tools_xss(self, web_template: WebAppFullTemplate) -> None:
        tools = web_template.get_phase_tools(WebPhase.XSS)
        assert "dalfox" in tools

    def test_get_all_tools_no_duplicates(self, web_template: WebAppFullTemplate) -> None:
        tools = web_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_get_all_tools_not_empty(self, web_template: WebAppFullTemplate) -> None:
        assert len(web_template.get_all_tools()) > 0

    def test_owasp_coverage(self, web_template: WebAppFullTemplate) -> None:
        coverage = web_template.get_owasp_coverage()
        assert len(coverage) >= 10
        assert "A03:2021-Injection" in coverage

    def test_custom_config(self, web_target: str) -> None:
        cfg = WebAppFullConfig(sqli_risk_level=3, crawl_depth=5, requests_per_second=5.0)
        tpl = WebAppFullTemplate(web_target, config=cfg)
        plan = tpl.get_scan_plan()
        crawl_phase = next(p for p in plan["phases"] if p["phase"] == "crawl")
        assert crawl_phase["config"]["depth"] == 5

    def test_estimated_duration(self, web_template: WebAppFullTemplate) -> None:
        assert web_template.ESTIMATED_DURATION_MINUTES == 120

    def test_project_id_in_plan(self, web_target: str) -> None:
        tpl = WebAppFullTemplate(web_target, project_id="proj-123")
        plan = tpl.get_scan_plan()
        assert plan["project_id"] == "proj-123"

    def test_auto_approve_level(self, web_target: str) -> None:
        tpl = WebAppFullTemplate(web_target, auto_approve_risk_level="high")
        plan = tpl.get_scan_plan()
        assert plan["auto_approve_risk_level"] == "high"

    def test_template_run_result_finish(self) -> None:
        result = TemplateRunResult(template_id="web_app_full", target="example.com")
        result.all_findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "info"},
        ]
        result.finish()
        assert result.total_findings == 4
        assert result.critical_findings == 1
        assert result.high_findings == 1
        assert result.medium_findings == 1
        assert result.info_findings == 1
        assert result.completed_at is not None


# ===========================================================================
# APIPentestTemplate tests
# ===========================================================================

class TestAPIPentestTemplate:
    def test_template_id(self, api_template: APIPentestTemplate) -> None:
        assert api_template.TEMPLATE_ID == "api_pentest"

    def test_scan_plan_keys(self, api_template: APIPentestTemplate) -> None:
        plan = api_template.get_scan_plan()
        assert "owasp_api_coverage" in plan

    def test_owasp_api_coverage_completeness(self, api_template: APIPentestTemplate) -> None:
        plan = api_template.get_scan_plan()
        coverage = plan["owasp_api_coverage"]
        assert "API1:2023-BOLA" in coverage
        assert "API5:2023-BFLA" in coverage
        assert len(coverage) == 10

    def test_phase_order(self, api_template: APIPentestTemplate) -> None:
        assert api_template.PHASE_ORDER[0] == "api_discovery"
        assert api_template.PHASE_ORDER[-1] == "report"

    def test_phases_count(self, api_template: APIPentestTemplate) -> None:
        plan = api_template.get_scan_plan()
        assert len(plan["phases"]) == 9

    def test_auth_phase_tools(self, api_template: APIPentestTemplate) -> None:
        tools = api_template.PHASE_TOOLS["auth_testing"]
        assert "jwt_decode_tool" in tools
        assert "jwt_forge_tool" in tools

    def test_custom_config_openapi_url(self, api_target: str) -> None:
        cfg = APIPentestConfig(openapi_url="https://api.example.com/openapi.json")
        tpl = APIPentestTemplate(api_target, config=cfg)
        plan = tpl.get_scan_plan()
        discovery_phase = next(p for p in plan["phases"] if p["phase"] == "api_discovery")
        assert discovery_phase["config"]["openapi_url"] == "https://api.example.com/openapi.json"

    def test_get_all_tools_unique(self, api_template: APIPentestTemplate) -> None:
        tools = api_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_bola_config(self, api_target: str) -> None:
        cfg = APIPentestConfig(bola_max_ids=50)
        tpl = APIPentestTemplate(api_target, config=cfg)
        plan = tpl.get_scan_plan()
        bola_phase = next(p for p in plan["phases"] if p["phase"] == "bola_bfla")
        assert bola_phase["config"]["max_ids"] == 50

    def test_estimated_duration(self, api_template: APIPentestTemplate) -> None:
        assert api_template.ESTIMATED_DURATION_MINUTES == 90


# ===========================================================================
# OWASPTop10Template tests
# ===========================================================================

class TestOWASPTop10Template:
    def test_template_id(self, owasp_template: OWASPTop10Template) -> None:
        assert owasp_template.TEMPLATE_ID == "owasp_top10"

    def test_phases_cover_all_ten(self, owasp_template: OWASPTop10Template) -> None:
        plan = owasp_template.get_scan_plan()
        owasp_ids = plan["owasp_categories"]
        # All A01–A10 should be present
        for i in range(1, 11):
            expected = f"A0{i}:2021" if i < 10 else "A10:2021"
            assert expected in owasp_ids, f"{expected} not covered"

    def test_compliance_matrix_keys(self, owasp_template: OWASPTop10Template) -> None:
        matrix = owasp_template.get_compliance_matrix()
        assert len(matrix) == 10
        for owasp_id, entry in matrix.items():
            assert "name" in entry
            assert "tools" in entry
            assert "enabled" in entry
            assert "status" in entry

    def test_default_all_phases_enabled(self, owasp_template: OWASPTop10Template) -> None:
        matrix = owasp_template.get_compliance_matrix()
        for owasp_id, entry in matrix.items():
            assert entry["enabled"], f"{owasp_id} should be enabled by default"

    def test_disable_sqli_disables_a03(self, web_target: str) -> None:
        cfg = OWASPTop10Config(test_sqli=False, test_nosql=False)
        tpl = OWASPTop10Template(web_target, config=cfg)
        matrix = tpl.get_compliance_matrix()
        assert not matrix["A03:2021"]["enabled"]

    def test_get_all_tools_not_empty(self, owasp_template: OWASPTop10Template) -> None:
        assert len(owasp_template.get_all_tools()) > 0

    def test_scan_plan_includes_owasp_categories(self, owasp_template: OWASPTop10Template) -> None:
        plan = owasp_template.get_scan_plan()
        assert "owasp_categories" in plan

    def test_phases_have_owasp_field(self, owasp_template: OWASPTop10Template) -> None:
        plan = owasp_template.get_scan_plan()
        for phase in plan["phases"]:
            assert "owasp" in phase

    def test_estimated_duration_at_least_100(self, owasp_template: OWASPTop10Template) -> None:
        assert owasp_template.ESTIMATED_DURATION_MINUTES >= 100

    def test_owaspa_enum_values(self) -> None:
        assert OWASPA.A01_ACCESS_CONTROL.value == "A01:2021"
        assert OWASPA.A10_SSRF.value == "A10:2021"


# ===========================================================================
# WordPressFullTemplate tests
# ===========================================================================

class TestWordPressFullTemplate:
    def test_template_id(self, wp_template: WordPressFullTemplate) -> None:
        assert wp_template.TEMPLATE_ID == "wordpress_full"

    def test_phases_count(self, wp_template: WordPressFullTemplate) -> None:
        plan = wp_template.get_scan_plan()
        assert len(plan["phases"]) == len(WordPressFullTemplate.PHASE_ORDER)

    def test_wordpress_specific_in_plan(self, wp_template: WordPressFullTemplate) -> None:
        plan = wp_template.get_scan_plan()
        assert "wordpress_specific" in plan
        assert plan["wordpress_specific"]["xmlrpc_enabled_check"] is True

    def test_common_cves_not_empty(self, wp_template: WordPressFullTemplate) -> None:
        assert len(wp_template.COMMON_WP_CVES) > 0

    def test_wpscan_in_fingerprint(self, wp_template: WordPressFullTemplate) -> None:
        assert "wpscan" in wp_template.PHASE_TOOLS["fingerprint"]

    def test_brute_force_disabled_by_default(self, wp_template: WordPressFullTemplate) -> None:
        plan = wp_template.get_scan_plan()
        auth_phase = next(p for p in plan["phases"] if p["phase"] == "auth_testing")
        assert auth_phase["config"]["brute_force"] is False

    def test_custom_config_aggressive(self, wp_target: str) -> None:
        cfg = WordPressConfig(aggressive_detection=True)
        tpl = WordPressFullTemplate(wp_target, config=cfg)
        plan = tpl.get_scan_plan()
        fp_phase = next(p for p in plan["phases"] if p["phase"] == "fingerprint")
        assert fp_phase["config"]["aggressive"] is True

    def test_owasp_coverage_keys(self, wp_template: WordPressFullTemplate) -> None:
        coverage = wp_template.get_owasp_coverage()
        assert "A03:2021-Injection" in coverage
        assert "A07:2021-Identification and Authentication Failures" in coverage

    def test_get_all_tools_unique(self, wp_template: WordPressFullTemplate) -> None:
        tools = wp_template.get_all_tools()
        assert len(tools) == len(set(tools))

    def test_wpscan_api_token_propagated(self, wp_target: str) -> None:
        cfg = WordPressConfig(wpscan_api_token="test-token-123")
        tpl = WordPressFullTemplate(wp_target, config=cfg)
        plan = tpl.get_scan_plan()
        plugin_phase = next(p for p in plan["phases"] if p["phase"] == "plugin_scan")
        assert plugin_phase["config"]["api_token"] == "test-token-123"


# ===========================================================================
# CloudAssessmentTemplate tests
# ===========================================================================

class TestCloudAssessmentTemplate:
    def test_template_id(self, cloud_template: CloudAssessmentTemplate) -> None:
        assert cloud_template.TEMPLATE_ID == "cloud_assessment"

    def test_phases_count(self, cloud_template: CloudAssessmentTemplate) -> None:
        plan = cloud_template.get_scan_plan()
        assert len(plan["phases"]) == len(CloudAssessmentTemplate.PHASE_ORDER)

    def test_cloud_metadata_endpoints_in_plan(self, cloud_template: CloudAssessmentTemplate) -> None:
        plan = cloud_template.get_scan_plan()
        assert "cloud_metadata_endpoints" in plan
        assert "aws" in plan["cloud_metadata_endpoints"]
        assert "gcp" in plan["cloud_metadata_endpoints"]
        assert "azure" in plan["cloud_metadata_endpoints"]

    def test_get_bucket_names(self, cloud_template: CloudAssessmentTemplate) -> None:
        names = cloud_template.get_bucket_names("https://company.example.com")
        assert "company" in names
        assert "company-dev" in names

    def test_get_bucket_names_default_target(self, cloud_target: str) -> None:
        tpl = CloudAssessmentTemplate(cloud_target)
        names = tpl.get_bucket_names()
        assert len(names) > 0

    def test_provider_auto_in_plan(self, cloud_template: CloudAssessmentTemplate) -> None:
        plan = cloud_template.get_scan_plan()
        assert plan["provider"] == "auto"

    def test_custom_provider_aws(self, cloud_target: str) -> None:
        cfg = CloudAssessmentConfig(provider=CloudProvider.AWS)
        tpl = CloudAssessmentTemplate(cloud_target, config=cfg)
        plan = tpl.get_scan_plan()
        assert plan["provider"] == "aws"

    def test_object_storage_tools(self, cloud_template: CloudAssessmentTemplate) -> None:
        tools = cloud_template.PHASE_TOOLS["object_storage"]
        assert "s3_bucket_tool" in tools
        assert "azure_blob_tool" in tools

    def test_ssrf_targets_in_metadata_config(self, cloud_template: CloudAssessmentTemplate) -> None:
        plan = cloud_template.get_scan_plan()
        meta_phase = next(p for p in plan["phases"] if p["phase"] == "metadata_ssrf")
        ssrf_targets = meta_phase["config"]["ssrf_targets"]
        assert any("169.254.169.254" in t for t in ssrf_targets)

    def test_auto_approve_low_default(self, cloud_target: str) -> None:
        tpl = CloudAssessmentTemplate(cloud_target)
        assert tpl.auto_approve_risk_level == "low"

    def test_get_all_tools_not_empty(self, cloud_template: CloudAssessmentTemplate) -> None:
        assert len(cloud_template.get_all_tools()) > 0

    def test_cloud_provider_enum_values(self) -> None:
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.GCP.value == "gcp"


# ===========================================================================
# Cross-template tests
# ===========================================================================

class TestCrossTemplate:
    """Tests that apply to all templates."""

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_scan_plans_have_template_id(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["template_id"] == template_id

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_scan_plans_have_phases(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert len(plan["phases"]) > 0

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_templates_have_tools(self, template_id: str, target: str) -> None:
        tpl = get_template(template_id, target)
        assert len(tpl.get_all_tools()) > 0

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_plan_phases_have_tools_list(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["tools"], list)

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_plan_phases_have_config(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["config"], dict)

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_plan_phases_have_estimated_minutes(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        for phase in plan["phases"]:
            assert isinstance(phase["estimated_minutes"], int)
            assert phase["estimated_minutes"] > 0

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_all_templates_set_version_2(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["version"].startswith("2."), f"{template_id} version should be 2.x"

    @pytest.mark.parametrize(
        "template_id,target",
        [
            ("web_app_full", "https://example.com"),
            ("api_pentest", "https://api.example.com"),
            ("owasp_top10", "https://example.com"),
            ("wordpress_full", "https://blog.example.com"),
            ("cloud_assessment", "https://app.example.com"),
        ],
    )
    def test_target_propagated_to_plan(self, template_id: str, target: str) -> None:
        plan = registry.get_scan_plan(template_id, target)
        assert plan["target"] == target
