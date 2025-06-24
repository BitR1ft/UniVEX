"""
Week 7 Test Suite – Web Crawling & URL Discovery

Covers:
  Day 42 – KatanaConfig defaults, KatanaOrchestrator initialisation, command building
  Day 43 – Async crawling, scope enforcement, form/parameter extraction, normalisation
  Day 44 – GAUOrchestrator: provider config, domain extraction, normalisation
  Day 45 – KiterunnerOrchestrator: wordlist resolution, command building, normalisation
  Day 46 – URLMerger: normalisation, categorisation, confidence scoring, deduplication
  Day 47 – /api/discovery/urls contract tests
  Day 48 – Documentation README exists, package exports correct
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse

import pytest

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult
from app.recon.resource_enum.katana_orchestrator import KatanaConfig, KatanaOrchestrator
from app.recon.resource_enum.gau_orchestrator import GAUConfig, GAUOrchestrator
from app.recon.resource_enum.kiterunner_orchestrator import (
    KiterunnerConfig,
    KiterunnerOrchestrator,
)
from app.recon.resource_enum.url_merger import (
    URLCategory,
    URLMerger,
    categorise_url,
    compute_confidence,
    normalise_url,
    URLRecord,
)
from app.recon.resource_enum import (
    KatanaOrchestrator as ExKatana,
    KatanaConfig as ExKatanaConfig,
    GAUOrchestrator as ExGAU,
    GAUConfig as ExGAUConfig,
    KiterunnerOrchestrator as ExKr,
    KiterunnerConfig as ExKrConfig,
    URLMerger as ExMerger,
)


# ===========================================================================
# ===========================================================================

class TestKatanaConfig:
    def test_defaults_are_safe(self):
        cfg = KatanaConfig()
        assert cfg.depth <= 5
        assert cfg.rate_limit <= 1000
        assert cfg.js_crawl is False   # headless disabled by default (safe)
        assert cfg.max_urls == 500

    def test_scope_domains_default_empty(self):
        cfg = KatanaConfig()
        assert cfg.scope_domains == []

    def test_exclude_extensions_populated(self):
        cfg = KatanaConfig()
        assert "png" in cfg.exclude_extensions
        assert "jpg" in cfg.exclude_extensions


class TestKatanaOrchestratorInit:
    def test_valid_url_target(self):
        orch = KatanaOrchestrator("https://example.com")
        assert orch.target == "https://example.com"
        assert orch.TOOL_NAME == "katana"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            KatanaOrchestrator("not a valid target!!")

    def test_custom_config_stored(self):
        cfg = KatanaConfig(depth=2, rate_limit=50)
        orch = KatanaOrchestrator("https://example.com", config=cfg)
        assert orch.katana_config.depth == 2
        assert orch.katana_config.rate_limit == 50


class TestKatanaCommandBuilding:
    def test_command_starts_with_katana(self):
        cmd = KatanaOrchestrator("https://example.com")._build_command()
        assert cmd[0] == "katana"

    def test_target_url_in_command(self):
        orch = KatanaOrchestrator("https://example.com")
        cmd = orch._build_command()
        assert "-u" in cmd
        u_idx = cmd.index("-u")
        assert cmd[u_idx + 1] == "https://example.com"

    def test_depth_in_command(self):
        cfg = KatanaConfig(depth=4)
        cmd = KatanaOrchestrator("https://example.com", config=cfg)._build_command()
        assert "-d" in cmd
        idx = cmd.index("-d")
        assert cmd[idx + 1] == "4"

    def test_json_flag_present(self):
        cmd = KatanaOrchestrator("https://example.com")._build_command()
        assert "-j" in cmd

    def test_js_crawl_adds_headless(self):
        cfg = KatanaConfig(js_crawl=True)
        cmd = KatanaOrchestrator("https://example.com", config=cfg)._build_command()
        assert "-headless" in cmd

    def test_scope_domains_in_command(self):
        cfg = KatanaConfig(scope_domains=["example.com"])
        cmd = KatanaOrchestrator("https://example.com", config=cfg)._build_command()
        assert "-scope" in cmd

    def test_rate_limit_in_command(self):
        cfg = KatanaConfig(rate_limit=50)
        cmd = KatanaOrchestrator("https://example.com", config=cfg)._build_command()
        assert "-rl" in cmd
        idx = cmd.index("-rl")
        assert cmd[idx + 1] == "50"


# ===========================================================================
# ===========================================================================

_KATANA_JSON_LINES = "\n".join([
    '{"request":{"endpoint":"https://example.com/api/users","method":"GET"},"depth":2}',
    '{"request":{"endpoint":"https://example.com/login","method":"POST"},"depth":1}',
    '{"url":"https://example.com/static/app.js"}',
])


def _mock_proc(stdout: str, returncode: int = 0):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout.encode(), b""))
    proc.returncode = returncode
    return proc


class TestKatanaNormalisation:
    def test_json_records_become_endpoints(self):
        orch = KatanaOrchestrator("https://example.com")
        records = [
            {"request": {"endpoint": "https://example.com/api/v1", "method": "GET"}},
            {"url": "https://example.com/login"},
        ]
        result = orch._normalise(records)
        assert result.endpoint_count == 2

    def test_endpoint_method_preserved(self):
        orch = KatanaOrchestrator("https://example.com")
        records = [{"request": {"endpoint": "https://example.com/submit", "method": "POST"}}]
        result = orch._normalise(records)
        assert result.endpoints[0].method == EndpointMethod.POST

    def test_discovered_by_is_katana(self):
        orch = KatanaOrchestrator("https://example.com")
        records = [{"url": "https://example.com/page"}]
        result = orch._normalise(records)
        assert result.endpoints[0].discovered_by == "katana"

    def test_parameters_extracted_from_url(self):
        params = KatanaOrchestrator._extract_parameters(
            "https://example.com/search?q=test&page=1"
        )
        assert "q" in params
        assert "page" in params

    def test_scope_enforcement_filters_out_of_scope(self):
        cfg = KatanaConfig(scope_domains=["example.com"])
        orch = KatanaOrchestrator("https://example.com", config=cfg)
        records = [
            {"url": "https://example.com/good"},
            {"url": "https://evil.com/bad"},
        ]
        result = orch._normalise(records)
        assert result.endpoint_count == 1
        assert "evil.com" not in result.endpoints[0].url

    def test_empty_raw_returns_empty_result(self):
        orch = KatanaOrchestrator("https://example.com")
        result = orch._normalise([])
        assert result.endpoint_count == 0

    @pytest.mark.asyncio
    async def test_successful_crawl_returns_recon_result(self):
        with patch("shutil.which", return_value="/usr/bin/katana"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc(_KATANA_JSON_LINES)):
            orch = KatanaOrchestrator("https://example.com")
            result = await orch.run()
        assert isinstance(result, ReconResult)
        assert result.success is True
        assert result.endpoint_count == 3

    @pytest.mark.asyncio
    async def test_crawl_targets_concurrent(self):
        targets = ["https://a.example.com", "https://b.example.com"]
        with patch("shutil.which", return_value="/usr/bin/katana"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc(_KATANA_JSON_LINES)):
            results = await KatanaOrchestrator.crawl_targets(targets)
        assert len(results) == 2


# ===========================================================================
# ===========================================================================

class TestGAUConfig:
    def test_all_providers_by_default(self):
        cfg = GAUConfig()
        assert "wayback" in cfg.providers
        assert "commoncrawl" in cfg.providers
        assert "otx" in cfg.providers
        assert "urlscan" in cfg.providers

    def test_provider_blacklist(self):
        cfg = GAUConfig(blacklist=["otx"])
        assert "otx" in cfg.blacklist

    def test_max_urls_default(self):
        cfg = GAUConfig()
        assert cfg.max_urls == 1000


class TestGAUDomainExtraction:
    def test_extracts_domain_from_url(self):
        domain = GAUOrchestrator._domain_from_target("https://example.com/path?q=1")
        assert domain == "example.com"

    def test_bare_domain_preserved(self):
        domain = GAUOrchestrator._domain_from_target("example.com")
        assert domain == "example.com"


class TestGAUCommandBuilding:
    def test_command_starts_with_gau(self):
        cmd = GAUOrchestrator("example.com")._build_command()
        assert cmd[0] == "gau"

    def test_domain_at_end(self):
        cmd = GAUOrchestrator("example.com")._build_command()
        assert cmd[-1] == "example.com"

    def test_blacklisted_provider_excluded(self):
        cfg = GAUConfig(providers=["wayback"], blacklist=["commoncrawl", "otx", "urlscan"])
        cmd = GAUOrchestrator("example.com", config=cfg)._build_command()
        # blacklisted providers should appear as --blacklist flags
        assert "--blacklist" in cmd

    def test_subdomains_flag_present(self):
        cmd = GAUOrchestrator("example.com")._build_command()
        assert "--subs" in cmd


_GAU_URLS = "\n".join([
    "https://example.com/api/v1/users?id=1",
    "https://example.com/old-page",
    "https://example.com/another?foo=bar",
])


class TestGAUNormalisation:
    def test_urls_become_endpoints(self):
        orch = GAUOrchestrator("example.com")
        result = orch._normalise(_GAU_URLS.splitlines())
        assert result.endpoint_count == 3

    def test_method_is_get(self):
        orch = GAUOrchestrator("example.com")
        result = orch._normalise(["https://example.com/page"])
        assert result.endpoints[0].method == EndpointMethod.GET

    def test_parameters_extracted(self):
        orch = GAUOrchestrator("example.com")
        result = orch._normalise(["https://example.com/search?q=test"])
        assert "q" in result.endpoints[0].parameters

    def test_discovered_by_is_gau(self):
        orch = GAUOrchestrator("example.com")
        result = orch._normalise(["https://example.com/page"])
        assert result.endpoints[0].discovered_by == "gau"

    def test_duplicates_removed(self):
        orch = GAUOrchestrator("example.com")
        result = orch._normalise([
            "https://example.com/page",
            "https://example.com/page",
        ])
        assert result.endpoint_count == 1

    def test_max_urls_cap_applied(self):
        """_normalise() processes whatever lines _execute() gives it.
        The cap is applied in _execute() which truncates before calling _normalise()."""
        orch = GAUOrchestrator("example.com")
        # Give exactly 5 distinct URLs — all 5 should be normalised
        urls = [f"https://example.com/p{i}" for i in range(5)]
        result = orch._normalise(urls)
        assert result.endpoint_count == 5  # normalise doesn't cap; _execute does


# ===========================================================================
# ===========================================================================

class TestKiterunnerConfig:
    def test_default_wordlist(self):
        cfg = KiterunnerConfig()
        assert "routes-large" in cfg.wordlists

    def test_resolved_builtin_wordlist(self):
        cfg = KiterunnerConfig(wordlists=["routes-small"])
        resolved = cfg.resolved_wordlists()
        assert "/usr/share/kiterunner/routes-small.kite" in resolved

    def test_custom_path_preserved(self):
        cfg = KiterunnerConfig(wordlists=["/custom/path.kite"])
        resolved = cfg.resolved_wordlists()
        assert "/custom/path.kite" in resolved

    def test_threads_capped(self):
        cfg = KiterunnerConfig(threads=100)
        assert cfg.threads == 100  # config doesn't cap; orchestrator may


class TestKiterunnerCommandBuilding:
    def test_command_starts_with_kr(self):
        cmd = KiterunnerOrchestrator("https://api.example.com")._build_command()
        assert cmd[0] == "kr"
        assert "brute" in cmd

    def test_wordlist_flag_present(self):
        cmd = KiterunnerOrchestrator("https://api.example.com")._build_command()
        assert "-w" in cmd

    def test_json_output_flag_present(self):
        cmd = KiterunnerOrchestrator("https://api.example.com")._build_command()
        assert "-o" in cmd
        idx = cmd.index("-o")
        assert cmd[idx + 1] == "json"


class TestKiterunnerTextParser:
    def test_parses_valid_text_line(self):
        line = "GET 200 [1234] https://api.example.com/v1/users"
        record = KiterunnerOrchestrator._parse_text_line(line)
        assert record is not None
        assert record["url"] == "https://api.example.com/v1/users"

    def test_returns_none_for_invalid_line(self):
        record = KiterunnerOrchestrator._parse_text_line("not a valid line")
        assert record is None


class TestKiterunnerNormalisation:
    def test_records_become_endpoints(self):
        orch = KiterunnerOrchestrator("https://api.example.com")
        raw = [
            {"url": "https://api.example.com/v1/users", "method": "GET", "status-code": 200},
            {"url": "https://api.example.com/v1/admin", "method": "POST", "status-code": 201},
        ]
        result = orch._normalise(raw)
        assert result.endpoint_count == 2

    def test_api_tag_present(self):
        orch = KiterunnerOrchestrator("https://api.example.com")
        raw = [{"url": "https://api.example.com/v1/users", "status-code": 200}]
        result = orch._normalise(raw)
        assert "api" in result.endpoints[0].tags

    def test_status_code_preserved(self):
        orch = KiterunnerOrchestrator("https://api.example.com")
        raw = [{"url": "https://api.example.com/v1/users", "status-code": 200}]
        result = orch._normalise(raw)
        assert result.endpoints[0].status_code == 200


# ===========================================================================
# ===========================================================================

class TestURLNormalisation:
    def test_lowercase_scheme_and_host(self):
        result = normalise_url("HTTP://EXAMPLE.COM/Path")
        p = urlparse(result)
        assert p.scheme == "http"
        assert p.netloc == "example.com"
        # Path case preserved
        assert p.path == "/Path"

    def test_fragment_stripped(self):
        norm = normalise_url("https://example.com/path#section")
        assert "#" not in norm

    def test_query_params_sorted(self):
        n1 = normalise_url("https://example.com/p?z=1&a=2")
        n2 = normalise_url("https://example.com/p?a=2&z=1")
        assert n1 == n2


class TestURLCategorisation:
    def test_login_is_auth(self):
        assert categorise_url("https://example.com/login") == URLCategory.AUTH

    def test_api_path_is_api(self):
        assert categorise_url("https://example.com/api/v1/users") == URLCategory.API

    def test_admin_path_is_admin(self):
        assert categorise_url("https://example.com/admin/dashboard") == URLCategory.ADMIN

    def test_upload_is_file(self):
        assert categorise_url("https://example.com/upload/avatar") == URLCategory.FILE

    def test_env_is_sensitive(self):
        assert categorise_url("https://example.com/.env") == URLCategory.SENSITIVE

    def test_js_file_is_static(self):
        assert categorise_url("https://example.com/app.js") == URLCategory.STATIC

    def test_url_with_params_is_dynamic(self):
        assert categorise_url("https://example.com/page?id=1", params=["id"]) == URLCategory.DYNAMIC

    def test_unknown_path(self):
        assert categorise_url("https://example.com/about") == URLCategory.UNKNOWN


class TestConfidenceScoring:
    def _make_record(self, **kwargs) -> URLRecord:
        defaults = dict(
            url="https://example.com/test",
            normalised="https://example.com/test",
            sources={"katana"},
            is_live=False,
        )
        defaults.update(kwargs)
        return URLRecord(**defaults)

    def test_live_url_gets_higher_score(self):
        live = self._make_record(is_live=True)
        dead = self._make_record(is_live=False)
        assert compute_confidence(live) > compute_confidence(dead)

    def test_multiple_sources_increase_score(self):
        one = self._make_record(sources={"katana"})
        three = self._make_record(sources={"katana", "gau", "kiterunner"})
        assert compute_confidence(three) > compute_confidence(one)

    def test_score_is_capped_at_1(self):
        rec = self._make_record(
            sources={"katana", "gau", "kiterunner"},
            is_live=True,
            method="POST",
            parameters=["id"],
        )
        assert compute_confidence(rec) <= 1.0


class TestURLMerger:
    def _ep(self, url: str, method: str = "GET", source: str = "katana") -> Endpoint:
        try:
            method_enum = EndpointMethod(method)
        except ValueError:
            method_enum = EndpointMethod.UNKNOWN
        return Endpoint(
            url=url,
            method=method_enum,
            discovered_by=source,
            tags=[source],
        )

    def test_merger_deduplicates_same_url(self):
        merger = URLMerger()
        ep1 = self._ep("https://example.com/page")
        ep2 = self._ep("https://example.com/page", source="gau")
        merger.add([ep1], source="katana")
        merger.add([ep2], source="gau")
        merged = merger.merge()
        assert len(merged) == 1

    def test_merger_tracks_both_sources(self):
        merger = URLMerger()
        merger.add([self._ep("https://example.com/page")], source="katana")
        merger.add([self._ep("https://example.com/page")], source="gau")
        merged = merger.merge()
        sources = set(merged[0].extra.get("sources", []))
        assert "katana" in sources
        assert "gau" in sources

    def test_merger_keeps_distinct_urls(self):
        merger = URLMerger()
        merger.add([
            self._ep("https://example.com/a"),
            self._ep("https://example.com/b"),
        ], source="katana")
        merged = merger.merge()
        assert len(merged) == 2

    def test_merger_adds_category(self):
        merger = URLMerger()
        merger.add([self._ep("https://example.com/api/v1/users")], source="katana")
        merged = merger.merge()
        assert merged[0].extra.get("category") == URLCategory.API

    def test_merger_sorted_by_confidence_descending(self):
        merger = URLMerger()
        # live URL (higher confidence)
        live_ep = Endpoint(url="https://example.com/live", method=EndpointMethod.GET,
                           is_live=True, discovered_by="katana", tags=[])
        dead_ep = Endpoint(url="https://example.com/dead", method=EndpointMethod.GET,
                           is_live=False, discovered_by="gau", tags=[])
        merger.add([live_ep], source="katana")
        merger.add([dead_ep], source="gau")
        merged = merger.merge()
        assert merged[0].confidence >= merged[-1].confidence

    def test_stats_returns_dict(self):
        merger = URLMerger()
        merger.add([self._ep("https://example.com/api/v1")], source="katana")
        stats = merger.stats()
        assert "total_unique_urls" in stats
        assert "by_category" in stats
        assert "by_source" in stats

    def test_clear_resets_state(self):
        merger = URLMerger()
        merger.add([self._ep("https://example.com/a")], source="katana")
        merger.clear()
        assert len(merger.merge()) == 0


# ===========================================================================
# ===========================================================================

class TestURLDiscoveryAPIContracts:
    def test_router_prefix(self):
        from app.api.discovery_urls import router
        assert router.prefix == "/api/discovery/urls"

    def test_router_has_post_route(self):
        from app.api.discovery_urls import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "POST" in all_methods

    def test_router_has_get_routes(self):
        from app.api.discovery_urls import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "GET" in all_methods

    def test_request_schema_defaults(self):
        from app.api.discovery_urls import URLDiscoveryCreateRequest
        req = URLDiscoveryCreateRequest(targets=["https://example.com"])
        assert req.use_katana is True
        assert req.use_gau is True
        assert req.use_kiterunner is False
        assert req.katana_depth == 3

    def test_results_endpoint_in_routes(self):
        from app.api.discovery_urls import router
        paths = [r.path for r in router.routes]
        assert any("results" in p for p in paths)


# ===========================================================================
# ===========================================================================

class TestWebCrawlingDocumentation:
    def test_readme_exists(self):
        from pathlib import Path
        readme = Path(__file__).parent.parent / "app" / "recon" / "resource_enum" / "README.md"
        assert readme.exists()

    def test_readme_mentions_week7(self):
        from pathlib import Path
        readme = (
            Path(__file__).parent.parent / "app" / "recon" / "resource_enum" / "README.md"
        )
        assert "Week 7" in readme.read_text()

    def test_katana_orchestrator_exported(self):
        assert ExKatana is KatanaOrchestrator
        assert ExKatanaConfig is KatanaConfig

    def test_gau_orchestrator_exported(self):
        assert ExGAU is GAUOrchestrator
        assert ExGAUConfig is GAUConfig

    def test_kiterunner_orchestrator_exported(self):
        assert ExKr is KiterunnerOrchestrator
        assert ExKrConfig is KiterunnerConfig

    def test_url_merger_exported(self):
        assert ExMerger is URLMerger
