"""

Endpoints:
  GET  /api/analytics/stats              — aggregate lifetime statistics
  GET  /api/analytics/trend              — time-series trend for a metric
  GET  /api/analytics/cost-report        — LLM cost breakdown by provider/model
  GET  /api/analytics/tool-performance   — tool success rate & avg duration
  GET  /api/analytics/findings           — finding counts by severity/category
  GET  /api/analytics/agent-performance  — per-agent-role performance metrics
  POST /api/analytics/record/agent-run   — record an agent run event
  POST /api/analytics/record/tool-exec   — record a tool execution event
  POST /api/analytics/record/finding     — record a security finding event
  POST /api/analytics/record/llm-call    — record an LLM API call event
  POST /api/analytics/record/scan-session— record a scan session event
  GET  /api/analytics/health             — ClickHouse connectivity health check
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.analytics.clickhouse_client import get_clickhouse_client
from app.analytics.pentest_analytics import PentestAnalytics, get_pentest_analytics

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AgentRunRequest(BaseModel):
    agent_role: str = Field(..., description="Agent role identifier")
    duration_ms: int = Field(..., ge=0, description="Execution duration in milliseconds")
    prompt_tokens: int = Field(0, ge=0)
    completion_tokens: int = Field(0, ge=0)
    cost_usd: float = Field(0.0, ge=0.0)
    success: bool = Field(True)
    session_id: str = Field("", description="Parent session ID")
    campaign_id: str = Field("")
    target: str = Field("")
    model_name: str = Field("")
    provider: str = Field("")
    error_type: str = Field("")
    output_length: int = Field(0, ge=0)


class ToolExecRequest(BaseModel):
    tool_name: str = Field(..., description="Tool name (e.g. naabu, nuclei)")
    target: str = Field(..., description="Target host/URL")
    duration_ms: int = Field(..., ge=0)
    result_code: int = Field(0)
    findings_count: int = Field(0, ge=0)
    result_size_bytes: int = Field(0, ge=0)
    success: bool = Field(True)
    campaign_id: str = Field("")
    command_args: str = Field("{}")
    tool_version: str = Field("")
    mcp_server_port: int = Field(0, ge=0, le=65535)


class FindingRequest(BaseModel):
    severity: str = Field(..., description="critical|high|medium|low|info")
    category: str = Field(..., description="sqli|xss|rce|ssrf|etc.")
    owasp_tag: str = Field("", description="e.g. A03")
    campaign_id: str = Field("")
    target: str = Field("")
    affected_component: str = Field("")
    cve_id: str = Field("")
    cwe_id: str = Field("")
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    fingerprint: str = Field("")


class LLMCallRequest(BaseModel):
    provider: str = Field(..., description="openai|anthropic|groq|etc.")
    model: str = Field(..., description="Model identifier")
    prompt_tokens: int = Field(..., ge=0)
    completion_tokens: int = Field(..., ge=0)
    cost_usd: float = Field(..., ge=0.0)
    latency_ms: int = Field(0, ge=0)
    total_time_ms: int = Field(0, ge=0)
    success: bool = Field(True)
    session_id: str = Field("")
    cached_tokens: int = Field(0, ge=0)
    error_code: str = Field("")
    finish_reason: str = Field("stop")
    prompt_cost_usd: float = Field(0.0, ge=0.0)
    completion_cost_usd: float = Field(0.0, ge=0.0)


class ScanSessionRequest(BaseModel):
    session_id: str = Field(..., description="Unique session UUID")
    campaign_id: str = Field("")
    target: str = Field(..., description="Primary scan target")
    scan_type: str = Field("full", description="full|quick|targeted|compliance")
    initiated_by: str = Field("")
    status: str = Field("running", description="running|completed|failed|cancelled")
    total_findings: int = Field(0, ge=0)
    critical_count: int = Field(0, ge=0)
    high_count: int = Field(0, ge=0)
    medium_count: int = Field(0, ge=0)
    low_count: int = Field(0, ge=0)
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    duration_seconds: int = Field(0, ge=0)
    total_tokens: int = Field(0, ge=0)
    total_cost_usd: float = Field(0.0, ge=0.0)


class RecordResponse(BaseModel):
    id: str
    status: str = "recorded"


class AggregateStatsResponse(BaseModel):
    total_agent_runs: int
    total_tool_executions: int
    total_findings: int
    total_llm_calls: int
    total_cost_usd: float
    total_tokens: int
    critical_findings: int
    high_findings: int


# ---------------------------------------------------------------------------
# Dependency helper
# ---------------------------------------------------------------------------

def _analytics() -> PentestAnalytics:
    return get_pentest_analytics()


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def analytics_health() -> Dict[str, Any]:
    """Check ClickHouse connectivity."""
    try:
        ch = await get_clickhouse_client()
        reachable = await ch.ping()
        return {
            "status": "healthy" if reachable else "degraded",
            "clickhouse": "reachable" if reachable else "unreachable",
        }
    except Exception as exc:
        logger.warning("Analytics health check failed: %s", exc)
        return {"status": "degraded", "clickhouse": "unreachable", "error": str(exc)}


@router.get("/stats", response_model=AggregateStatsResponse)
async def get_aggregate_stats() -> AggregateStatsResponse:
    """Return aggregate lifetime statistics across all pentest sessions."""
    try:
        stats = await _analytics().query_aggregate_stats()
        return AggregateStatsResponse(**stats)
    except Exception as exc:
        logger.error("Failed to query aggregate stats: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


@router.get("/trend")
async def get_trend(
    metric: str = Query(
        "agent_runs",
        description="Metric to trend: agent_runs|tool_executions|findings|llm_calls",
    ),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
) -> List[Dict[str, Any]]:
    """Return daily event counts for the requested metric."""
    valid_metrics = {"agent_runs", "tool_executions", "findings", "llm_calls"}
    if metric not in valid_metrics:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric '{metric}'. Choose from: {sorted(valid_metrics)}",
        )
    try:
        return await _analytics().query_trend(metric=metric, days=days)
    except Exception as exc:
        logger.error("Failed to query trend: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


@router.get("/cost-report")
async def get_cost_report(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
) -> List[Dict[str, Any]]:
    """Return LLM cost breakdown by provider and model."""
    try:
        return await _analytics().query_cost_report(days=days)
    except Exception as exc:
        logger.error("Failed to query cost report: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


@router.get("/tool-performance")
async def get_tool_performance() -> List[Dict[str, Any]]:
    """Return tool success rate, average duration, and total findings per tool."""
    try:
        return await _analytics().query_tool_performance()
    except Exception as exc:
        logger.error("Failed to query tool performance: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


@router.get("/findings")
async def get_findings_by_severity(
    campaign_id: Optional[str] = Query(None, description="Filter to a specific campaign"),
) -> List[Dict[str, Any]]:
    """Return finding counts grouped by severity and category."""
    try:
        return await _analytics().query_findings_by_severity(campaign_id=campaign_id)
    except Exception as exc:
        logger.error("Failed to query findings: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


@router.get("/agent-performance")
async def get_agent_performance(
    days: int = Query(30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return per-agent-role performance statistics."""
    try:
        return await _analytics().query_agent_performance(days=days)
    except Exception as exc:
        logger.error("Failed to query agent performance: %s", exc)
        raise HTTPException(status_code=500, detail="Analytics query failed") from exc


# ---------------------------------------------------------------------------
# Write endpoints (ingest)
# ---------------------------------------------------------------------------

@router.post("/record/agent-run", response_model=RecordResponse, status_code=201)
async def record_agent_run(body: AgentRunRequest) -> RecordResponse:
    """Record an agent run event into ClickHouse."""
    try:
        run_id = await _analytics().record_agent_run(
            agent_role=body.agent_role,
            duration_ms=body.duration_ms,
            prompt_tokens=body.prompt_tokens,
            completion_tokens=body.completion_tokens,
            cost_usd=body.cost_usd,
            success=body.success,
            session_id=body.session_id,
            campaign_id=body.campaign_id,
            target=body.target,
            model_name=body.model_name,
            provider=body.provider,
            error_type=body.error_type,
            output_length=body.output_length,
        )
        return RecordResponse(id=run_id)
    except Exception as exc:
        logger.error("Failed to record agent run: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record event") from exc


@router.post("/record/tool-exec", response_model=RecordResponse, status_code=201)
async def record_tool_execution(body: ToolExecRequest) -> RecordResponse:
    """Record a tool execution event into ClickHouse."""
    try:
        eid = await _analytics().record_tool_execution(
            tool_name=body.tool_name,
            target=body.target,
            duration_ms=body.duration_ms,
            result_code=body.result_code,
            findings_count=body.findings_count,
            result_size_bytes=body.result_size_bytes,
            success=body.success,
            campaign_id=body.campaign_id,
            command_args=body.command_args,
            tool_version=body.tool_version,
            mcp_server_port=body.mcp_server_port,
        )
        return RecordResponse(id=eid)
    except Exception as exc:
        logger.error("Failed to record tool execution: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record event") from exc


@router.post("/record/finding", response_model=RecordResponse, status_code=201)
async def record_finding(body: FindingRequest) -> RecordResponse:
    """Record a security finding into ClickHouse."""
    try:
        fid = await _analytics().record_finding(
            severity=body.severity,
            category=body.category,
            owasp_tag=body.owasp_tag,
            campaign_id=body.campaign_id,
            target=body.target,
            affected_component=body.affected_component,
            cve_id=body.cve_id,
            cwe_id=body.cwe_id,
            cvss_score=body.cvss_score,
            fingerprint=body.fingerprint,
        )
        return RecordResponse(id=fid)
    except Exception as exc:
        logger.error("Failed to record finding: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record event") from exc


@router.post("/record/llm-call", response_model=RecordResponse, status_code=201)
async def record_llm_call(body: LLMCallRequest) -> RecordResponse:
    """Record an LLM API call into ClickHouse."""
    try:
        cid = await _analytics().record_llm_call(
            provider=body.provider,
            model=body.model,
            prompt_tokens=body.prompt_tokens,
            completion_tokens=body.completion_tokens,
            cost_usd=body.cost_usd,
            latency_ms=body.latency_ms,
            total_time_ms=body.total_time_ms,
            success=body.success,
            session_id=body.session_id,
            cached_tokens=body.cached_tokens,
            error_code=body.error_code,
            finish_reason=body.finish_reason,
            prompt_cost_usd=body.prompt_cost_usd,
            completion_cost_usd=body.completion_cost_usd,
        )
        return RecordResponse(id=cid)
    except Exception as exc:
        logger.error("Failed to record LLM call: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record event") from exc


@router.post("/record/scan-session", response_model=RecordResponse, status_code=201)
async def record_scan_session(body: ScanSessionRequest) -> RecordResponse:
    """Record or update a scan session in ClickHouse."""
    try:
        await _analytics().record_scan_session(
            session_id=body.session_id,
            campaign_id=body.campaign_id,
            target=body.target,
            scan_type=body.scan_type,
            initiated_by=body.initiated_by,
            status=body.status,
            total_findings=body.total_findings,
            critical_count=body.critical_count,
            high_count=body.high_count,
            medium_count=body.medium_count,
            low_count=body.low_count,
            risk_score=body.risk_score,
            duration_seconds=body.duration_seconds,
            total_tokens=body.total_tokens,
            total_cost_usd=body.total_cost_usd,
        )
        return RecordResponse(id=body.session_id)
    except Exception as exc:
        logger.error("Failed to record scan session: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record event") from exc
