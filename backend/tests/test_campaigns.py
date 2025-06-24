"""
70+ tests covering CampaignEngine, TargetManager, CampaignScheduler,
CampaignAggregator, and the REST API.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import textwrap
from datetime import datetime, timedelta
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.campaigns.campaign_engine import (
    Campaign,
    CampaignConfig,
    CampaignEngine,
    CampaignFinding,
    CampaignStatus,
    CampaignTarget,
    FindingSeverity,
    TargetStatus,
)
from app.campaigns.target_manager import ImportResult, ParsedTarget, TargetManager
from app.campaigns.scheduler import CampaignScheduler, Priority, ScheduledJob
from app.campaigns.aggregator import CampaignAggregator, CorrelationGroup


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> CampaignEngine:
    return CampaignEngine()


@pytest.fixture
def campaign(engine: CampaignEngine) -> Campaign:
    return engine.create_campaign("Test Campaign", description="A test campaign")


@pytest.fixture
def populated_campaign(engine: CampaignEngine) -> Campaign:
    c = engine.create_campaign("Populated Campaign")
    engine.add_target(c.id, host="example.com")
    engine.add_target(c.id, host="api.example.com", port=8443, protocol="https")
    engine.add_target(c.id, host="192.168.1.1")
    return c


@pytest.fixture
def tm() -> TargetManager:
    return TargetManager()


@pytest.fixture
def aggregator() -> CampaignAggregator:
    return CampaignAggregator()


@pytest.fixture
def scheduler(engine: CampaignEngine) -> CampaignScheduler:
    return CampaignScheduler(engine, max_concurrent=2)


def _make_finding(
    title: str = "SQL Injection",
    severity: FindingSeverity = FindingSeverity.HIGH,
    cve_id: str | None = None,
    owasp_category: str | None = None,
    target_id: str = "t1",
) -> CampaignFinding:
    return CampaignFinding(
        title=title,
        description="Test finding",
        severity=severity,
        cvss_score=7.5,
        cve_id=cve_id,
        owasp_category=owasp_category or "A03:2021 – Injection",
        affected_component="/login",
        remediation="Use parameterised queries",
        target_id=target_id,
    )


# ===========================================================================
# CampaignEngine Tests
# ===========================================================================

class TestCampaignEngineCreate:
    def test_create_campaign_returns_campaign(self, engine: CampaignEngine) -> None:
        c = engine.create_campaign("Alpha")
        assert c.name == "Alpha"
        assert c.id
        assert c.status == CampaignStatus.DRAFT

    def test_create_campaign_with_config(self, engine: CampaignEngine) -> None:
        cfg = CampaignConfig(max_concurrent_targets=5, scan_timeout_seconds=120)
        c = engine.create_campaign("Beta", config=cfg)
        assert c.config.max_concurrent_targets == 5
        assert c.config.scan_timeout_seconds == 120

    def test_create_campaign_stored(self, engine: CampaignEngine) -> None:
        c = engine.create_campaign("Gamma")
        assert engine.get_campaign(c.id) is c

    def test_create_multiple_campaigns(self, engine: CampaignEngine) -> None:
        ids = {engine.create_campaign(f"C{i}").id for i in range(5)}
        assert len(ids) == 5

    def test_get_nonexistent_campaign(self, engine: CampaignEngine) -> None:
        assert engine.get_campaign("nope") is None


class TestCampaignEngineCRUD:
    def test_list_campaigns_empty(self, engine: CampaignEngine) -> None:
        assert engine.list_campaigns() == []

    def test_list_campaigns_sorted_newest_first(self, engine: CampaignEngine) -> None:
        c1 = engine.create_campaign("First")
        c2 = engine.create_campaign("Second")
        listed = engine.list_campaigns()
        assert listed[0].id == c2.id

    def test_list_campaigns_filter_by_status(self, engine: CampaignEngine) -> None:
        c1 = engine.create_campaign("Draft")
        c2 = engine.create_campaign("Sched")
        c2.status = CampaignStatus.SCHEDULED
        drafts = engine.list_campaigns(status=CampaignStatus.DRAFT)
        assert all(c.status == CampaignStatus.DRAFT for c in drafts)

    def test_delete_campaign(self, engine: CampaignEngine, campaign: Campaign) -> None:
        assert engine.delete_campaign(campaign.id)
        assert engine.get_campaign(campaign.id) is None

    def test_delete_nonexistent_campaign(self, engine: CampaignEngine) -> None:
        assert not engine.delete_campaign("ghost")

    def test_update_campaign_name(self, engine: CampaignEngine, campaign: Campaign) -> None:
        updated = engine.update_campaign(campaign.id, name="New Name")
        assert updated is not None
        assert updated.name == "New Name"

    def test_update_campaign_nonexistent(self, engine: CampaignEngine) -> None:
        assert engine.update_campaign("missing", name="X") is None


class TestCampaignEngineTargets:
    def test_add_target(self, engine: CampaignEngine, campaign: Campaign) -> None:
        t = engine.add_target(campaign.id, host="example.com")
        assert t is not None
        assert t.host == "example.com"
        assert len(campaign.targets) == 1

    def test_add_target_with_port(self, engine: CampaignEngine, campaign: Campaign) -> None:
        t = engine.add_target(campaign.id, host="api.example.com", port=8443)
        assert t.port == 8443
        assert t.url == "https://api.example.com:8443"

    def test_add_target_nonexistent_campaign(self, engine: CampaignEngine) -> None:
        assert engine.add_target("nope", host="x.com") is None

    def test_remove_target(self, engine: CampaignEngine, campaign: Campaign) -> None:
        t = engine.add_target(campaign.id, host="example.com")
        assert engine.remove_target(campaign.id, t.id)
        assert len(campaign.targets) == 0

    def test_remove_nonexistent_target(self, engine: CampaignEngine, campaign: Campaign) -> None:
        assert not engine.remove_target(campaign.id, "ghost")

    def test_get_target(self, engine: CampaignEngine, campaign: Campaign) -> None:
        t = engine.add_target(campaign.id, host="example.com")
        assert engine.get_target(campaign.id, t.id) is t

    def test_bulk_add_targets(self, engine: CampaignEngine, campaign: Campaign) -> None:
        targets = [{"host": f"host{i}.com"} for i in range(5)]
        count = engine.add_targets_bulk(campaign.id, targets)
        assert count == 5
        assert len(campaign.targets) == 5

    def test_campaign_progress_percent(self, engine: CampaignEngine, campaign: Campaign) -> None:
        t1 = engine.add_target(campaign.id, host="a.com")
        t2 = engine.add_target(campaign.id, host="b.com")
        t1.status = TargetStatus.COMPLETED
        assert campaign.progress_percent == 50.0


class TestCampaignEngineExecution:
    def test_run_campaign_no_targets(self, engine: CampaignEngine, campaign: Campaign) -> None:
        result = asyncio.run(engine.run_campaign(campaign.id))
        assert result.status == CampaignStatus.COMPLETED
        assert result.total_findings == 0

    def test_run_campaign_with_noop_scan(
        self, engine: CampaignEngine, populated_campaign: Campaign
    ) -> None:
        result = asyncio.run(engine.run_campaign(populated_campaign.id))
        assert result.status == CampaignStatus.COMPLETED
        assert all(t.status == TargetStatus.COMPLETED for t in result.targets)

    def test_run_campaign_with_custom_scan(
        self, engine: CampaignEngine, campaign: Campaign
    ) -> None:
        engine.add_target(campaign.id, host="vuln.example.com")

        async def _scan(target: CampaignTarget) -> List[CampaignFinding]:
            return [_make_finding(target_id=target.id)]

        result = asyncio.run(engine.run_campaign(campaign.id, scan_fn=_scan))
        assert result.total_findings == 1
        assert result.critical_findings == 0
        assert result.high_findings == 1

    def test_run_campaign_sets_timestamps(
        self, engine: CampaignEngine, campaign: Campaign
    ) -> None:
        asyncio.run(engine.run_campaign(campaign.id))
        assert campaign.started_at is not None
        assert campaign.completed_at is not None

    def test_run_campaign_invalid_status_raises(
        self, engine: CampaignEngine, campaign: Campaign
    ) -> None:
        campaign.status = CampaignStatus.COMPLETED
        with pytest.raises(RuntimeError):
            asyncio.run(engine.run_campaign(campaign.id))

    def test_campaign_nonexistent_raises(self, engine: CampaignEngine) -> None:
        with pytest.raises(ValueError):
            asyncio.run(engine.run_campaign("ghost"))

    def test_pause_running_campaign(self, engine: CampaignEngine, campaign: Campaign) -> None:
        campaign.status = CampaignStatus.RUNNING
        assert engine.pause_campaign(campaign.id)
        assert campaign.status == CampaignStatus.PAUSED

    def test_cancel_scheduled_campaign(self, engine: CampaignEngine, campaign: Campaign) -> None:
        campaign.status = CampaignStatus.SCHEDULED
        assert engine.cancel_campaign(campaign.id)
        assert campaign.status == CampaignStatus.CANCELLED

    def test_cancel_draft_campaign_fails(self, engine: CampaignEngine, campaign: Campaign) -> None:
        assert not engine.cancel_campaign(campaign.id)


class TestCampaignEngineRiskScoring:
    def test_risk_level_critical(self, engine: CampaignEngine) -> None:
        findings = [_make_finding(severity=FindingSeverity.CRITICAL) for _ in range(5)]
        score = CampaignEngine._calculate_campaign_risk(findings)
        assert CampaignEngine._risk_level(score) == "critical"

    def test_risk_level_info(self, engine: CampaignEngine) -> None:
        findings = [_make_finding(severity=FindingSeverity.INFO)]
        score = CampaignEngine._calculate_campaign_risk(findings)
        assert CampaignEngine._risk_level(score) == "informational"

    def test_risk_score_empty(self, engine: CampaignEngine) -> None:
        assert CampaignEngine._calculate_campaign_risk([]) == 0.0

    def test_get_campaign_summary(
        self, engine: CampaignEngine, campaign: Campaign
    ) -> None:
        summary = engine.get_campaign_summary(campaign.id)
        assert summary is not None
        assert summary["id"] == campaign.id
        assert "risk_score" in summary


# ===========================================================================
# TargetManager Tests
# ===========================================================================

class TestTargetManagerCSV:
    def test_import_simple_csv(self, tm: TargetManager) -> None:
        csv_text = "host,port,protocol\nexample.com,443,https\napi.test.com,,http\n"
        result = tm.import_csv(csv_text)
        assert result.success_count == 2
        assert result.error_count == 0

    def test_import_csv_missing_host(self, tm: TargetManager) -> None:
        csv_text = "host,port\n,443\n"
        result = tm.import_csv(csv_text)
        assert result.error_count >= 1

    def test_import_csv_with_tags(self, tm: TargetManager) -> None:
        csv_text = "host,tags\nexample.com,web,api\n"
        result = tm.import_csv(csv_text)
        # tags column "web,api" is just one cell; parse_tags splits by comma
        assert result.success_count == 1

    def test_import_csv_deduplication(self, tm: TargetManager) -> None:
        csv_text = "host\nexample.com\nexample.com\n"
        result = tm.import_csv(csv_text)
        assert result.success_count == 1
        assert result.duplicates_removed == 1


class TestTargetManagerJSON:
    def test_import_json_array(self, tm: TargetManager) -> None:
        data = json.dumps([{"host": "example.com"}, {"host": "api.example.com", "port": 8080}])
        result = tm.import_json(data)
        assert result.success_count == 2

    def test_import_json_invalid(self, tm: TargetManager) -> None:
        result = tm.import_json("not json")
        assert result.error_count >= 1

    def test_import_json_not_array(self, tm: TargetManager) -> None:
        result = tm.import_json('{"host": "example.com"}')
        assert result.error_count >= 1

    def test_import_json_missing_host(self, tm: TargetManager) -> None:
        data = json.dumps([{"port": 80}])
        result = tm.import_json(data)
        assert result.error_count >= 1

    def test_import_json_with_tags_list(self, tm: TargetManager) -> None:
        data = json.dumps([{"host": "example.com", "tags": ["web", "prod"]}])
        result = tm.import_json(data)
        assert result.success_count == 1
        assert "web" in result.parsed[0].tags


class TestTargetManagerText:
    def test_import_text_simple(self, tm: TargetManager) -> None:
        result = tm.import_text("example.com\napi.example.com\n")
        assert result.success_count == 2

    def test_import_text_skip_comments(self, tm: TargetManager) -> None:
        result = tm.import_text("# comment\nexample.com\n")
        assert result.success_count == 1

    def test_import_text_skip_empty(self, tm: TargetManager) -> None:
        result = tm.import_text("\nexample.com\n\n")
        assert result.success_count == 1

    def test_import_text_url_stripping(self, tm: TargetManager) -> None:
        result = tm.import_text("https://example.com/path?q=1\n")
        assert result.success_count == 1
        assert result.parsed[0].host == "example.com"

    def test_import_auto_detects_json(self, tm: TargetManager) -> None:
        data = json.dumps([{"host": "example.com"}])
        result = tm.import_auto(data)
        assert result.success_count == 1


class TestTargetManagerCIDR:
    def test_expand_cidr(self, tm: TargetManager) -> None:
        hosts = tm.expand_cidr("10.0.0.0/30")
        assert len(hosts) == 2  # /30 has 2 usable hosts

    def test_expand_cidr_invalid(self, tm: TargetManager) -> None:
        with pytest.raises(ValueError):
            tm.expand_cidr("not-a-cidr")

    def test_import_text_with_cidr(self, tm: TargetManager) -> None:
        result = tm.import_text("10.10.10.0/30\n")
        assert result.success_count == 2  # 2 usable hosts

    def test_cidr_max_hosts_truncation(self) -> None:
        tm_small = TargetManager(max_cidr_hosts=4)
        hosts = tm_small.expand_cidr("192.168.0.0/24")
        assert len(hosts) == 4


class TestTargetManagerScope:
    def test_whitelist_allows_matching(self) -> None:
        tm = TargetManager(scope_whitelist=[r"example\.com$"])
        ok, reason = tm.validate_scope("sub.example.com")
        assert ok

    def test_whitelist_blocks_non_matching(self) -> None:
        tm = TargetManager(scope_whitelist=[r"example\.com$"])
        ok, reason = tm.validate_scope("other.com")
        assert not ok

    def test_blacklist_blocks_matching(self) -> None:
        tm = TargetManager(scope_blacklist=[r"evil\.com$"])
        ok, reason = tm.validate_scope("evil.com")
        assert not ok

    def test_loopback_blocked(self, tm: TargetManager) -> None:
        ok, reason = tm.validate_scope("127.0.0.1")
        assert not ok

    def test_valid_ip(self, tm: TargetManager) -> None:
        ok, reason = tm.validate_scope("8.8.8.8")
        assert ok

    def test_invalid_host_rejected(self, tm: TargetManager) -> None:
        result = tm.import_text("not_a_valid_host!@#\n")
        assert result.error_count >= 1


# ===========================================================================
# CampaignScheduler Tests
# ===========================================================================

class TestCampaignScheduler:
    def test_schedule_adds_to_queue(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        job = scheduler.schedule(campaign.id)
        assert scheduler.queue_depth() == 1
        assert job.campaign_id == campaign.id

    def test_schedule_sets_campaign_status(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        scheduler.schedule(campaign.id)
        assert campaign.status == CampaignStatus.SCHEDULED

    def test_cancel_scheduled(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        scheduler.schedule(campaign.id)
        assert scheduler.cancel_scheduled(campaign.id)
        assert scheduler.queue_depth() == 0

    def test_priority_ordering(
        self, engine: CampaignEngine, scheduler: CampaignScheduler
    ) -> None:
        c_low = engine.create_campaign("Low")
        c_high = engine.create_campaign("High")
        scheduler.schedule(c_low.id, priority=Priority.LOW)
        scheduler.schedule(c_high.id, priority=Priority.HIGH)
        queue = scheduler.get_queue()
        assert queue[0].campaign_id == c_high.id

    def test_run_next_executes_job(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        scheduler.schedule(campaign.id)
        job = asyncio.run(scheduler.run_next())
        assert job is not None
        assert campaign.status == CampaignStatus.COMPLETED

    def test_run_all_processes_queue(
        self, engine: CampaignEngine, scheduler: CampaignScheduler
    ) -> None:
        campaigns = [engine.create_campaign(f"C{i}") for i in range(3)]
        for c in campaigns:
            scheduler.schedule(c.id)
        completed = asyncio.run(scheduler.run_all())
        assert len(completed) == 3

    def test_schedule_in_future(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        job = scheduler.schedule_in(campaign.id, delay=timedelta(hours=1))
        assert job.run_at is not None
        assert not job.is_ready

    def test_stats(
        self, engine: CampaignEngine, campaign: Campaign, scheduler: CampaignScheduler
    ) -> None:
        scheduler.schedule(campaign.id)
        stats = scheduler.stats()
        assert stats["queued"] == 1
        assert stats["max_concurrent"] == 2


# ===========================================================================
# CampaignAggregator Tests
# ===========================================================================

class TestCampaignAggregator:
    def _campaign_with_findings(self, engine: CampaignEngine) -> Campaign:
        c = engine.create_campaign("Agg Test")
        t1 = engine.add_target(c.id, host="host1.com")
        t2 = engine.add_target(c.id, host="host2.com")
        t1.status = TargetStatus.COMPLETED
        t2.status = TargetStatus.COMPLETED
        t1.findings = [
            _make_finding("SQLi", FindingSeverity.CRITICAL, cve_id="CVE-2021-0001", target_id=t1.id),
            _make_finding("XSS", FindingSeverity.MEDIUM, target_id=t1.id),
        ]
        t2.findings = [
            _make_finding("SQLi", FindingSeverity.CRITICAL, cve_id="CVE-2021-0001", target_id=t2.id),
            _make_finding("CSRF", FindingSeverity.LOW, target_id=t2.id),
        ]
        return c

    def test_aggregate_finding_counts(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        report = aggregator.aggregate(c)
        assert report.total_findings == 4

    def test_aggregate_severity_breakdown(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        report = aggregator.aggregate(c)
        assert report.severity_breakdown["critical"] == 2
        assert report.severity_breakdown["medium"] == 1
        assert report.severity_breakdown["low"] == 1

    def test_aggregate_deduplication(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        report = aggregator.aggregate(c)
        # "SQLi" appears on both hosts → 1 unique, 1 duplicate
        assert report.duplicate_count >= 1

    def test_correlate_returns_cross_target_groups(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        groups = aggregator.correlate(c)
        assert len(groups) >= 1
        assert groups[0].host_count >= 2

    def test_owasp_coverage(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        report = aggregator.aggregate(c)
        assert "A03:2021 – Injection" in report.owasp_coverage

    def test_highest_risk_target(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        report = aggregator.aggregate(c)
        assert report.highest_risk_target is not None

    def test_top_findings(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = self._campaign_with_findings(engine)
        top = aggregator.top_findings(c, n=2)
        assert len(top) == 2
        assert top[0].severity_score <= top[1].severity_score

    def test_compare_campaigns(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c1 = self._campaign_with_findings(engine)
        c2 = engine.create_campaign("Empty")
        comparison = aggregator.compare_campaigns(c1, c2)
        assert comparison["delta_findings"]["total"] > 0

    def test_empty_campaign_aggregate(
        self, engine: CampaignEngine, aggregator: CampaignAggregator
    ) -> None:
        c = engine.create_campaign("Empty")
        report = aggregator.aggregate(c)
        assert report.total_findings == 0
        assert report.risk_score == 0.0
        assert report.risk_level == "informational"


# ===========================================================================
# Campaign REST API Tests
# ===========================================================================

@pytest.fixture
def client() -> TestClient:
    from app.main import app
    return TestClient(app)


class TestCampaignAPI:
    def test_create_campaign(self, client: TestClient) -> None:
        resp = client.post("/api/campaigns", json={"name": "API Test", "description": "Test"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "API Test"
        assert data["status"] == "draft"

    def test_list_campaigns(self, client: TestClient) -> None:
        client.post("/api/campaigns", json={"name": "L1"})
        resp = client.get("/api/campaigns")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_campaign(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "GetTest"})
        cid = create.json()["id"]
        resp = client.get(f"/api/campaigns/{cid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == cid

    def test_get_nonexistent_campaign(self, client: TestClient) -> None:
        resp = client.get("/api/campaigns/doesnotexist")
        assert resp.status_code == 404

    def test_update_campaign(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "Old"})
        cid = create.json()["id"]
        resp = client.patch(f"/api/campaigns/{cid}", json={"name": "New"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "New"

    def test_delete_campaign(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "ToDelete"})
        cid = create.json()["id"]
        resp = client.delete(f"/api/campaigns/{cid}")
        assert resp.status_code == 204

    def test_add_target(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "TargetTest"})
        cid = create.json()["id"]
        resp = client.post(f"/api/campaigns/{cid}/targets", json={"host": "example.com"})
        assert resp.status_code == 201
        assert resp.json()["host"] == "example.com"

    def test_remove_target(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "RemoveTarget"})
        cid = create.json()["id"]
        t = client.post(f"/api/campaigns/{cid}/targets", json={"host": "del.com"}).json()
        resp = client.delete(f"/api/campaigns/{cid}/targets/{t['id']}")
        assert resp.status_code == 204

    def test_import_targets_json(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "ImportTest"})
        cid = create.json()["id"]
        payload = json.dumps([{"host": "a.com"}, {"host": "b.com"}])
        resp = client.post(
            f"/api/campaigns/{cid}/targets/import",
            json={"content": payload, "format": "json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success_count"] == 2
        assert data["added_to_campaign"] == 2

    def test_import_targets_csv(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "CSVImport"})
        cid = create.json()["id"]
        csv_text = "host\nfoo.com\nbar.com\n"
        resp = client.post(
            f"/api/campaigns/{cid}/targets/import",
            json={"content": csv_text, "format": "csv"},
        )
        assert resp.status_code == 200
        assert resp.json()["added_to_campaign"] == 2

    def test_import_targets_text(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "TextImport"})
        cid = create.json()["id"]
        resp = client.post(
            f"/api/campaigns/{cid}/targets/import",
            json={"content": "host1.com\nhost2.com\n", "format": "text"},
        )
        assert resp.status_code == 200
        assert resp.json()["added_to_campaign"] == 2

    def test_campaign_summary(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "Summary"})
        cid = create.json()["id"]
        resp = client.get(f"/api/campaigns/{cid}/summary")
        assert resp.status_code == 200
        assert "risk_score" in resp.json()

    def test_campaign_aggregate(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "AggAPI"})
        cid = create.json()["id"]
        resp = client.get(f"/api/campaigns/{cid}/aggregate")
        assert resp.status_code == 200
        data = resp.json()
        assert "severity_breakdown" in data
        assert "owasp_coverage" in data

    def test_campaign_correlations(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "Corr"})
        cid = create.json()["id"]
        resp = client.get(f"/api/campaigns/{cid}/correlations")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_start_campaign(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "Start"})
        cid = create.json()["id"]
        resp = client.post(f"/api/campaigns/{cid}/start")
        assert resp.status_code == 200

    def test_cancel_campaign(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "Cancel"})
        cid = create.json()["id"]
        # Must be running/paused/scheduled to cancel
        client.post(f"/api/campaigns/{cid}/start")
        resp = client.post(f"/api/campaigns/{cid}/cancel")
        assert resp.status_code == 200

    def test_filter_campaigns_by_status(self, client: TestClient) -> None:
        resp = client.get("/api/campaigns?status=draft")
        assert resp.status_code == 200

    def test_filter_campaigns_invalid_status(self, client: TestClient) -> None:
        resp = client.get("/api/campaigns?status=bananas")
        assert resp.status_code == 400

    def test_target_findings_empty(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "FindTest"})
        cid = create.json()["id"]
        t = client.post(f"/api/campaigns/{cid}/targets", json={"host": "x.com"}).json()
        resp = client.get(f"/api/campaigns/{cid}/targets/{t['id']}/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_add_target_invalid_port(self, client: TestClient) -> None:
        create = client.post("/api/campaigns", json={"name": "BadPort"})
        cid = create.json()["id"]
        resp = client.post(
            f"/api/campaigns/{cid}/targets",
            json={"host": "example.com", "port": 99999},
        )
        assert resp.status_code == 422

    def test_list_campaigns_pagination(self, client: TestClient) -> None:
        for i in range(5):
            client.post("/api/campaigns", json={"name": f"Page{i}"})
        resp = client.get("/api/campaigns?limit=2&offset=0")
        assert resp.status_code == 200
        assert len(resp.json()) <= 2
