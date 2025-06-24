"""
Day 19 GraphQL API Tests

Covers:
  - Schema introspection
  - All query fields (projects, scans, findings, campaigns, reports, agents, tools, me, findingStats)
  - All mutation fields (create/update/delete for projects, scans, findings, campaigns, reports)
  - Subscription types registration
  - DataLoader builder functions
  - Type enums and edge cases
  - Error handling and graceful degradation
  - Router integration

Total: 80+ tests
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import strawberry

# ---------------------------------------------------------------------------
# Import GraphQL modules directly (no heavy app/__init__ chain)
# ---------------------------------------------------------------------------

from app.graphql.types import (
    Project, ProjectStatus,
    Scan, ScanStatus,
    Finding, FindingSeverity, FindingStatus, Evidence,
    Campaign, CampaignStatus, CampaignTarget,
    Report, ReportFormat,
    AgentExecution, AgentRole,
    ToolInfo, User, UserRole,
    PageInfo, ProjectConnection, FindingConnection,
    OperationError, ProjectResult, FindingResult, DeleteResult,
    ScanStatusEvent, FindingDiscoveredEvent, AgentProgressEvent,
    CreateProjectInput, UpdateProjectInput,
    CreateFindingInput, UpdateFindingInput,
    CreateCampaignInput, GenerateReportInput, CreateScanInput,
)
from app.graphql.dataloaders import (
    build_mock_project,
    build_mock_scan,
    build_mock_finding,
    build_mock_campaign,
    build_mock_report,
)
from app.graphql.schema import schema


# ===========================================================================
# Helpers
# ===========================================================================

def run(coro):
    return asyncio.run(coro)


def _gql(query: str, variables: Dict[str, Any] | None = None):
    """Execute a GraphQL query synchronously and return (data, errors)."""
    result = run(schema.execute(query, variable_values=variables or {}))
    return result.data, result.errors


NOW = datetime.utcnow()
SAMPLE_ID = str(uuid.uuid4())


# ===========================================================================
# 1. Schema Introspection Tests
# ===========================================================================

class TestSchemaIntrospection:
    def test_schema_compiles(self):
        assert schema is not None

    def test_query_type_exists(self):
        data, errors = _gql("{ __schema { queryType { name } } }")
        assert errors is None
        assert data["__schema"]["queryType"]["name"] == "Query"

    def test_mutation_type_exists(self):
        data, errors = _gql("{ __schema { mutationType { name } } }")
        assert errors is None
        assert data["__schema"]["mutationType"]["name"] == "Mutation"

    def test_subscription_type_exists(self):
        data, errors = _gql("{ __schema { subscriptionType { name } } }")
        assert errors is None
        assert data["__schema"]["subscriptionType"]["name"] == "Subscription"

    def test_query_fields_present(self):
        data, errors = _gql("{ __schema { queryType { fields { name } } } }")
        assert errors is None
        field_names = {f["name"] for f in data["__schema"]["queryType"]["fields"]}
        expected = {
            "projects", "project", "scans", "scan",
            "findings", "finding", "campaigns", "campaign",
            "reports", "report", "agents", "tools", "me", "findingStats"
        }
        assert expected.issubset(field_names)

    def test_mutation_fields_present(self):
        data, errors = _gql("{ __schema { mutationType { fields { name } } } }")
        assert errors is None
        field_names = {f["name"] for f in data["__schema"]["mutationType"]["fields"]}
        expected = {
            "createProject", "updateProject", "deleteProject",
            "createScan", "cancelScan",
            "createFinding", "updateFinding", "deleteFinding",
            "bulkDeleteFindings", "triageFinding",
            "createCampaign", "startCampaign", "pauseCampaign",
            "cancelCampaign", "deleteCampaign",
            "generateReport", "deleteReport",
        }
        assert expected.issubset(field_names)

    def test_subscription_fields_present(self):
        data, errors = _gql("{ __schema { subscriptionType { fields { name } } } }")
        assert errors is None
        field_names = {f["name"] for f in data["__schema"]["subscriptionType"]["fields"]}
        assert {"onScanStatusChange", "onFindingDiscovered", "onAgentProgress"}.issubset(field_names)

    def test_project_type_fields(self):
        data, _ = _gql("""
        {
          __type(name: "Project") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"id", "name", "target", "status", "createdAt"}.issubset(fields)

    def test_finding_type_fields(self):
        data, _ = _gql("""
        {
          __type(name: "Finding") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"id", "title", "severity", "status", "cvssScore", "cveId"}.issubset(fields)

    def test_campaign_type_fields(self):
        data, _ = _gql("""
        {
          __type(name: "Campaign") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"id", "name", "status", "targets", "totalFindings"}.issubset(fields)


# ===========================================================================
# 2. DataLoader / Builder Tests
# ===========================================================================

class TestDataLoaders:
    def test_build_project_defaults(self):
        p = build_mock_project({})
        assert isinstance(p, Project)
        assert p.status == ProjectStatus.ACTIVE
        assert p.id == ""

    def test_build_project_full(self):
        p = build_mock_project({
            "id": SAMPLE_ID,
            "name": "TestProject",
            "target": "example.com",
            "project_type": "web",
            "status": "completed",
            "created_at": NOW,
            "updated_at": NOW,
            "user_id": "u1",
            "enable_port_scan": True,
        })
        assert p.id == SAMPLE_ID
        assert p.name == "TestProject"
        assert p.status == ProjectStatus.COMPLETED
        assert p.enable_port_scan is True

    def test_build_project_invalid_status_fallback(self):
        p = build_mock_project({"status": "INVALID_STATUS"})
        assert p.status == ProjectStatus.ACTIVE

    def test_build_scan_defaults(self):
        s = build_mock_scan({})
        assert isinstance(s, Scan)
        assert s.status == ScanStatus.PENDING

    def test_build_scan_full(self):
        s = build_mock_scan({
            "id": SAMPLE_ID,
            "project_id": "p1",
            "scan_type": "port",
            "target": "10.0.0.1",
            "status": "running",
            "created_at": NOW,
            "findings_count": 5,
        })
        assert s.status == ScanStatus.RUNNING
        assert s.findings_count == 5
        assert s.started_at is None

    def test_build_finding_defaults(self):
        f = build_mock_finding({})
        assert isinstance(f, Finding)
        assert f.severity == FindingSeverity.INFO
        assert f.status == FindingStatus.OPEN

    def test_build_finding_with_evidence(self):
        f = build_mock_finding({
            "id": SAMPLE_ID,
            "title": "SQL Injection",
            "severity": "critical",
            "status": "open",
            "created_at": NOW,
            "updated_at": NOW,
            "evidence": [
                {"id": "e1", "type": "screenshot", "content": "base64data", "filename": "poc.png"}
            ],
        })
        assert f.severity == FindingSeverity.CRITICAL
        assert len(f.evidence) == 1
        assert f.evidence[0].type == "screenshot"

    def test_build_finding_invalid_severity_fallback(self):
        f = build_mock_finding({"severity": "super_critical"})
        assert f.severity == FindingSeverity.INFO

    def test_build_campaign_defaults(self):
        c = build_mock_campaign({})
        assert isinstance(c, Campaign)
        assert c.status == CampaignStatus.PENDING
        assert c.targets == []

    def test_build_campaign_with_targets(self):
        c = build_mock_campaign({
            "id": "c1",
            "name": "Campaign A",
            "status": "running",
            "created_at": NOW,
            "updated_at": NOW,
            "targets": [
                {"id": "t1", "target": "192.168.1.1", "status": "completed", "findings_count": 3}
            ],
        })
        assert c.status == CampaignStatus.RUNNING
        assert len(c.targets) == 1
        assert c.targets[0].findings_count == 3

    def test_build_report_defaults(self):
        r = build_mock_report({})
        assert isinstance(r, Report)
        assert r.format == ReportFormat.PDF

    def test_build_report_full(self):
        r = build_mock_report({
            "id": SAMPLE_ID,
            "project_id": "p1",
            "format": "html",
            "title": "Q1 Report",
            "created_at": NOW,
            "download_url": "https://example.com/report.html",
            "findings_count": 12,
        })
        assert r.format == ReportFormat.HTML
        assert r.findings_count == 12
        assert r.download_url is not None


# ===========================================================================
# 3. Type / Enum Tests
# ===========================================================================

class TestTypes:
    def test_project_status_enum(self):
        assert ProjectStatus.ACTIVE.value == "active"
        assert ProjectStatus.COMPLETED.value == "completed"
        assert ProjectStatus.ARCHIVED.value == "archived"
        assert ProjectStatus.PAUSED.value == "paused"

    def test_finding_severity_enum(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_finding_status_enum(self):
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.RESOLVED.value == "resolved"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"

    def test_campaign_status_enum(self):
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.PAUSED.value == "paused"
        assert CampaignStatus.CANCELLED.value == "cancelled"

    def test_agent_role_enum_all_values(self):
        roles = {r.value for r in AgentRole}
        assert "planner" in roles
        assert "recon" in roles
        assert "exploit" in roles
        assert "webapp" in roles
        assert "coder" in roles
        assert len(roles) == 13  # 13 agent roles

    def test_page_info_has_next(self):
        pi = PageInfo(total=100, page=1, page_size=20, has_next=True, has_prev=False)
        assert pi.has_next is True
        assert pi.has_prev is False

    def test_operation_error(self):
        err = OperationError(message="Not found", code="NOT_FOUND", field="id")
        assert err.code == "NOT_FOUND"
        assert err.field == "id"

    def test_create_project_input(self):
        inp = CreateProjectInput(name="Test", target="example.com")
        assert inp.project_type == "web"
        assert inp.enable_port_scan is False

    def test_create_finding_input_defaults(self):
        inp = CreateFindingInput(title="XSS")
        assert inp.severity == FindingSeverity.INFO
        assert inp.references == []
        assert inp.tags == []

    def test_update_finding_input_optional_fields(self):
        inp = UpdateFindingInput()
        assert inp.title is None
        assert inp.severity is None

    def test_scan_status_event(self):
        ev = ScanStatusEvent(
            scan_id="s1",
            project_id="p1",
            status=ScanStatus.COMPLETED,
        )
        assert ev.status == ScanStatus.COMPLETED
        assert isinstance(ev.timestamp, datetime)

    def test_finding_discovered_event(self):
        ev = FindingDiscoveredEvent(
            finding_id="f1",
            project_id="p1",
            scan_id=None,
            title="SQLi",
            severity=FindingSeverity.CRITICAL,
        )
        assert ev.severity == FindingSeverity.CRITICAL

    def test_agent_progress_event(self):
        ev = AgentProgressEvent(
            agent_role=AgentRole.RECON,
            phase="port_scan",
            message="Scanning ports",
            progress_pct=25.0,
        )
        assert ev.progress_pct == 25.0


# ===========================================================================
# 4. Query Execution Tests (with graceful DB-less fallback)
# ===========================================================================

class TestQueryExecution:
    def test_projects_query_returns_connection(self):
        data, errors = _gql("""
        {
          projects {
            pageInfo { total page pageSize hasNext hasPrev }
            items { id name target }
          }
        }
        """)
        assert errors is None
        assert "projects" in data
        assert "pageInfo" in data["projects"]
        assert isinstance(data["projects"]["items"], list)

    def test_projects_query_pagination_defaults(self):
        data, _ = _gql("{ projects { pageInfo { page pageSize } } }")
        assert data["projects"]["pageInfo"]["page"] == 1
        assert data["projects"]["pageInfo"]["pageSize"] == 20

    def test_project_by_id_unknown_returns_null(self):
        data, errors = _gql('{ project(id: "nonexistent-id") { id name } }')
        assert errors is None
        assert data["project"] is None

    def test_scans_query_returns_connection(self):
        data, errors = _gql("""
        {
          scans {
            pageInfo { total }
            items { id scanType status target }
          }
        }
        """)
        assert errors is None
        assert "scans" in data

    def test_findings_query_returns_connection(self):
        data, errors = _gql("""
        {
          findings {
            pageInfo { total page }
            items { id title severity status }
          }
        }
        """)
        assert errors is None
        assert "findings" in data
        assert isinstance(data["findings"]["items"], list)

    def test_findings_query_with_filters(self):
        data, errors = _gql("""
        {
          findings(severity: CRITICAL, status: OPEN, search: "injection") {
            pageInfo { total }
            items { id title severity }
          }
        }
        """)
        assert errors is None

    def test_finding_by_id_returns_none_when_missing(self):
        data, errors = _gql('{ finding(id: "no-such-id") { id title } }')
        assert errors is None
        assert data["finding"] is None

    def test_campaigns_query_returns_connection(self):
        data, errors = _gql("""
        {
          campaigns {
            pageInfo { total }
            items { id name status }
          }
        }
        """)
        assert errors is None
        assert "campaigns" in data

    def test_campaign_by_id_returns_none(self):
        data, errors = _gql('{ campaign(id: "missing") { id name } }')
        assert errors is None
        assert data["campaign"] is None

    def test_reports_query(self):
        data, errors = _gql("""
        {
          reports {
            pageInfo { total }
            items { id title format }
          }
        }
        """)
        assert errors is None
        assert "reports" in data

    def test_report_by_id_returns_none(self):
        data, errors = _gql('{ report(id: "nope") { id title } }')
        assert errors is None
        assert data["report"] is None

    def test_agents_query_returns_list(self):
        data, errors = _gql("{ agents { id role status } }")
        assert errors is None
        assert isinstance(data["agents"], list)

    def test_tools_query_returns_list(self):
        data, errors = _gql("{ tools { name description phase enabled } }")
        assert errors is None
        assert isinstance(data["tools"], list)

    def test_me_query_no_auth_returns_null(self):
        data, errors = _gql("{ me { id username email role } }")
        assert errors is None
        assert data["me"] is None

    def test_finding_stats_query(self):
        data, errors = _gql("{ findingStats }")
        assert errors is None
        # Returns JSON scalar — dict or empty dict
        assert data["findingStats"] is not None


# ===========================================================================
# 5. Mutation Execution Tests
# ===========================================================================

class TestMutationExecution:
    def test_create_project_mutation(self):
        data, errors = _gql("""
        mutation {
          createProject(input: {
            name: "Test Project",
            target: "example.com",
            projectType: "web",
            enablePortScan: true
          }) {
            success
            error { message code }
            project {
              id name target enablePortScan
            }
          }
        }
        """)
        assert errors is None
        result = data["createProject"]
        assert result["success"] is True
        assert result["error"] is None
        assert result["project"]["name"] == "Test Project"
        assert result["project"]["target"] == "example.com"
        assert result["project"]["enablePortScan"] is True

    def test_create_project_mutation_with_description(self):
        data, errors = _gql("""
        mutation {
          createProject(input: {
            name: "Pentest Alpha",
            target: "192.168.1.0/24",
            description: "Internal network test"
          }) {
            success
            project { name description }
          }
        }
        """)
        assert errors is None
        assert data["createProject"]["success"] is True
        assert data["createProject"]["project"]["description"] == "Internal network test"

    def test_update_project_mutation(self):
        data, errors = _gql("""
        mutation {
          updateProject(id: "p1", input: { name: "Updated Name" }) {
            success
            project { id }
          }
        }
        """)
        assert errors is None
        assert data["updateProject"]["success"] is True

    def test_delete_project_mutation(self):
        data, errors = _gql("""
        mutation {
          deleteProject(id: "p-to-delete") {
            id success
          }
        }
        """)
        assert errors is None
        assert data["deleteProject"]["success"] is True
        assert data["deleteProject"]["id"] == "p-to-delete"

    def test_create_scan_mutation(self):
        data, errors = _gql("""
        mutation {
          createScan(input: {
            projectId: "p1",
            scanType: "port",
            target: "10.0.0.1"
          }) {
            success
            scan { id projectId scanType target status }
          }
        }
        """)
        assert errors is None
        result = data["createScan"]
        assert result["success"] is True
        assert result["scan"]["scanType"] == "port"
        assert result["scan"]["status"] == "PENDING"

    def test_cancel_scan_mutation(self):
        data, errors = _gql("""
        mutation {
          cancelScan(id: "scan-1") {
            success
            scan { id status }
          }
        }
        """)
        assert errors is None
        assert data["cancelScan"]["success"] is True
        assert data["cancelScan"]["scan"]["status"] == "CANCELLED"

    def test_create_finding_mutation(self):
        data, errors = _gql("""
        mutation {
          createFinding(input: {
            title: "SQL Injection in login",
            severity: CRITICAL,
            description: "Classic SQLi via user param",
            cveId: "CVE-2023-1234",
            cvssScore: 9.8
          }) {
            success
            finding { id title severity cvssScore cveId }
          }
        }
        """)
        assert errors is None
        result = data["createFinding"]
        assert result["success"] is True
        assert result["finding"]["title"] == "SQL Injection in login"
        assert result["finding"]["severity"] == "CRITICAL"
        assert result["finding"]["cvssScore"] == 9.8

    def test_create_finding_with_all_fields(self):
        data, errors = _gql("""
        mutation {
          createFinding(input: {
            title: "XSS in search",
            severity: HIGH,
            description: "Reflected XSS",
            cweId: "CWE-79",
            owaspCategory: "A03:2021",
            affectedUrl: "https://example.com/search",
            affectedParameter: "q",
            affectedMethod: "GET",
            remediation: "Sanitize input",
            tags: ["xss", "frontend"]
          }) {
            success
            finding { cweId owaspCategory affectedUrl tags }
          }
        }
        """)
        assert errors is None
        f = data["createFinding"]["finding"]
        assert f["cweId"] == "CWE-79"
        assert "xss" in f["tags"]

    def test_update_finding_mutation(self):
        data, errors = _gql("""
        mutation {
          updateFinding(id: "f1", input: {
            status: RESOLVED,
            severity: LOW
          }) {
            success
            finding { id }
          }
        }
        """)
        assert errors is None
        assert data["updateFinding"]["success"] is True

    def test_delete_finding_mutation(self):
        data, errors = _gql("""
        mutation {
          deleteFinding(id: "f1") {
            id success
          }
        }
        """)
        assert errors is None
        assert data["deleteFinding"]["success"] is True

    def test_bulk_delete_findings_mutation(self):
        data, errors = _gql("""
        mutation {
          bulkDeleteFindings(ids: ["f1", "f2", "f3"]) {
            id success
          }
        }
        """)
        assert errors is None
        results = data["bulkDeleteFindings"]
        assert len(results) == 3
        assert all(r["success"] for r in results)

    def test_triage_finding_mutation(self):
        data, errors = _gql("""
        mutation {
          triageFinding(id: "f1", status: FALSE_POSITIVE, note: "Verified manually") {
            success
            finding { id }
          }
        }
        """)
        assert errors is None
        assert data["triageFinding"]["success"] is True

    def test_create_campaign_mutation(self):
        data, errors = _gql("""
        mutation {
          createCampaign(input: {
            name: "Internal Network Sweep",
            description: "Q2 internal assessment",
            targets: ["10.0.0.1", "10.0.0.2"]
          }) {
            success
            campaign { id name status targets { target } }
          }
        }
        """)
        assert errors is None
        result = data["createCampaign"]
        assert result["success"] is True
        assert result["campaign"]["name"] == "Internal Network Sweep"
        assert len(result["campaign"]["targets"]) == 2

    def test_start_campaign_mutation(self):
        data, errors = _gql("""
        mutation {
          startCampaign(id: "c1") {
            success
            campaign { id status }
          }
        }
        """)
        assert errors is None
        assert data["startCampaign"]["success"] is True

    def test_pause_campaign_mutation(self):
        data, errors = _gql("""
        mutation {
          pauseCampaign(id: "c1") {
            success
            campaign { id status }
          }
        }
        """)
        assert errors is None
        assert data["pauseCampaign"]["success"] is True

    def test_cancel_campaign_mutation(self):
        data, errors = _gql("""
        mutation {
          cancelCampaign(id: "c1") {
            success
            campaign { id status }
          }
        }
        """)
        assert errors is None
        assert data["cancelCampaign"]["success"] is True

    def test_delete_campaign_mutation(self):
        data, errors = _gql("""
        mutation {
          deleteCampaign(id: "c1") {
            id success
          }
        }
        """)
        assert errors is None
        assert data["deleteCampaign"]["success"] is True

    def test_generate_report_mutation(self):
        data, errors = _gql("""
        mutation {
          generateReport(input: {
            projectId: "p1",
            format: PDF,
            title: "Q2 Security Report"
          }) {
            success
            report { id title format }
          }
        }
        """)
        assert errors is None
        result = data["generateReport"]
        assert result["success"] is True
        assert result["report"]["format"] == "PDF"
        assert result["report"]["title"] == "Q2 Security Report"

    def test_generate_report_markdown_format(self):
        data, errors = _gql("""
        mutation {
          generateReport(input: {
            projectId: "p1",
            format: MARKDOWN
          }) {
            success
            report { format }
          }
        }
        """)
        assert errors is None
        assert data["generateReport"]["report"]["format"] == "MARKDOWN"

    def test_delete_report_mutation(self):
        data, errors = _gql("""
        mutation {
          deleteReport(id: "r1") {
            id success
          }
        }
        """)
        assert errors is None
        assert data["deleteReport"]["success"] is True


# ===========================================================================
# 6. Subscription Registration Tests
# ===========================================================================

class TestSubscriptions:
    def test_subscription_type_registered(self):
        """Subscriptions are defined in the schema."""
        data, _ = _gql("""
        {
          __schema {
            subscriptionType {
              fields { name description }
            }
          }
        }
        """)
        fields = {f["name"] for f in data["__schema"]["subscriptionType"]["fields"]}
        assert "onScanStatusChange" in fields
        assert "onFindingDiscovered" in fields
        assert "onAgentProgress" in fields

    def test_on_scan_status_change_args(self):
        data, _ = _gql("""
        {
          __type(name: "Subscription") {
            fields {
              name
              args { name type { name kind } }
            }
          }
        }
        """)
        sub_fields = {f["name"]: f for f in data["__type"]["fields"]}
        scan_sub = sub_fields.get("onScanStatusChange")
        assert scan_sub is not None
        arg_names = {a["name"] for a in scan_sub["args"]}
        assert "scanId" in arg_names

    def test_on_finding_discovered_args(self):
        data, _ = _gql("""
        {
          __type(name: "Subscription") {
            fields {
              name
              args { name }
            }
          }
        }
        """)
        sub_fields = {f["name"]: f for f in data["__type"]["fields"]}
        finding_sub = sub_fields.get("onFindingDiscovered")
        assert finding_sub is not None
        arg_names = {a["name"] for a in finding_sub["args"]}
        assert "projectId" in arg_names

    def test_subscription_event_types_have_correct_fields(self):
        data, _ = _gql("""
        {
          __type(name: "ScanStatusEvent") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"scanId", "projectId", "status", "message", "timestamp"}.issubset(fields)

    def test_finding_event_type_fields(self):
        data, _ = _gql("""
        {
          __type(name: "FindingDiscoveredEvent") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"findingId", "title", "severity", "timestamp"}.issubset(fields)

    def test_agent_progress_event_type_fields(self):
        data, _ = _gql("""
        {
          __type(name: "AgentProgressEvent") {
            fields { name }
          }
        }
        """)
        fields = {f["name"] for f in data["__type"]["fields"]}
        assert {"agentRole", "phase", "message", "progressPct", "timestamp"}.issubset(fields)

    def test_publish_scan_event(self):
        """Publish an event to the broker without errors."""
        from app.graphql.subscriptions import _publish_scan_event
        from app.graphql.types import ScanStatus

        event = ScanStatusEvent(
            scan_id="s-test",
            project_id="p-test",
            status=ScanStatus.COMPLETED,
            message="done",
        )
        asyncio.run(_publish_scan_event(event))

    def test_publish_finding_event(self):
        """Publish a finding event without errors."""
        from app.graphql.subscriptions import _publish_finding_event
        event = FindingDiscoveredEvent(
            finding_id="f-test",
            project_id="p-test",
            scan_id=None,
            title="SQLi",
            severity=FindingSeverity.HIGH,
        )
        asyncio.run(_publish_finding_event(event))


# ===========================================================================
# 7. Error Handling Tests
# ===========================================================================

class TestErrorHandling:
    def test_invalid_field_name_returns_error(self):
        data, errors = _gql("{ nonExistentField }")
        assert errors is not None
        assert len(errors) > 0

    def test_invalid_enum_value_returns_error(self):
        data, errors = _gql("""
        mutation {
          createFinding(input: { title: "test", severity: SUPER_CRITICAL }) {
            success
          }
        }
        """)
        assert errors is not None

    def test_missing_required_field_returns_error(self):
        # createProject requires name and target
        data, errors = _gql("""
        mutation {
          createProject(input: { name: "NoTarget" }) {
            success
          }
        }
        """)
        assert errors is not None

    def test_project_result_error_field(self):
        result = ProjectResult(error=OperationError(message="DB down", code="DB_ERROR"), success=False)
        assert result.success is False
        assert result.error.code == "DB_ERROR"

    def test_delete_result_with_error(self):
        result = DeleteResult(id="x", success=False, error=OperationError(message="Not found"))
        assert result.success is False
        assert result.error is not None


# ===========================================================================
# 8. Router Integration Test
# ===========================================================================

class TestRouterIntegration:
    def test_graphql_router_importable(self):
        from app.graphql.router import graphql_router
        assert graphql_router is not None

    def test_graphql_router_has_routes(self):
        from app.graphql.router import graphql_router
        routes = graphql_router.routes
        assert len(routes) > 0

    def test_graphql_module_exports(self):
        from app.graphql import schema as s, graphql_router as r
        assert s is not None
        assert r is not None
