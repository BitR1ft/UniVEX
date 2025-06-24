# UniVex — Observability Guide (v1.0.0)

> **Last updated:** v1.0.0 — March 2026 · Author: BitR1FT

---

## Table of Contents

1. [Stack Overview](#1-stack-overview)
2. [Quick Start](#2-quick-start)
3. [Metrics — Prometheus + VictoriaMetrics](#3-metrics--prometheus--victoriametrics)
4. [LLM Observability — Langfuse](#4-llm-observability--langfuse)
5. [Log Aggregation — Loki + Promtail](#5-log-aggregation--loki--promtail)
6. [Distributed Tracing — Jaeger](#6-distributed-tracing--jaeger)
7. [Analytics — ClickHouse](#7-analytics--clickhouse)
8. [Artifact Storage — MinIO](#8-artifact-storage--minio)
9. [Dashboards — Grafana](#9-dashboards--grafana)
10. [Alert Rules](#10-alert-rules)
11. [Isolated Observability Stack](#11-isolated-observability-stack)
12. [Environment Variables Reference](#12-environment-variables-reference)

---

## 1. Stack Overview

| Component | Port | Purpose |
|-----------|------|---------|
| **Prometheus** | 9090 | Metrics scraping + short-term storage |
| **VictoriaMetrics** | 8428 | Long-term metrics storage (Prometheus remote-write target) |
| **Grafana** | 3001 | Dashboards, alerting, Loki data source |
| **Langfuse** | 3002 | LLM cost, latency, and token analytics per agent call |
| **Loki** | 3100 | Log aggregation (Promtail → Loki) |
| **Promtail** | — | Log collector (Docker container logs → Loki) |
| **Jaeger** | 16686 (UI), 14268 (ingest) | Distributed tracing — request spans across services |
| **ClickHouse** | 9000 (native), 8123 (HTTP) | Pentest analytics, vulnerability trend analysis |
| **MinIO** | 9000 (API), 9001 (console) | S3-compatible artifact storage (reports, screenshots) |
| **OpenTelemetry Collector** | — | Unified span export to Jaeger + metrics |

---

## 2. Quick Start

```bash
# Start core services including full observability stack
cp .env.example .env
# Fill in GRAFANA_PASSWORD, LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, etc.
docker compose up -d

# Or start only observability services (isolated)
docker compose -f docker-compose-observability.yml up -d
```

**Service URLs after startup:**

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3001 | admin / `GRAFANA_PASSWORD` |
| Langfuse | http://localhost:3002 | Set up on first visit |
| Jaeger UI | http://localhost:16686 | No auth |
| MinIO Console | http://localhost:9001 | `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` |
| Prometheus | http://localhost:9090 | No auth |
| VictoriaMetrics | http://localhost:8428 | No auth |

---

## 3. Metrics — Prometheus + VictoriaMetrics

### Prometheus Configuration

Prometheus scrapes all UniVex services and ships metrics to VictoriaMetrics via
remote-write for long-term retention.

Config: `docker/monitoring/prometheus.yml`

```yaml
remote_write:
  - url: http://victoriametrics:8428/api/v1/write
```

### Application Metrics Exposed at `/metrics`

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `http_requests_total` | Counter | `method`, `endpoint`, `status_code` | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | `method`, `endpoint` | Request latency |
| `tool_executions_total` | Counter | `tool_name`, `status` | MCP tool executions |
| `active_scans_total` | Gauge | — | Currently running scans |
| `queued_jobs_total` | Gauge | — | Jobs awaiting worker dispatch |
| `llm_tokens_total` | Counter | `provider`, `model`, `agent_role` | Tokens consumed by LLM calls |
| `llm_request_duration_seconds` | Histogram | `provider`, `model` | LLM call latency |
| `agent_task_duration_seconds` | Histogram | `agent_role` | Agent task completion time |
| `memory_captures_total` | Counter | `memory_type` | AutoCapture middleware ingestions |
| `worker_dispatches_total` | Counter | `status` | Worker job dispatches |
| `oob_callbacks_total` | Counter | `protocol` | OOB listener callbacks received |

### VictoriaMetrics

VictoriaMetrics provides 90-day metric retention with significantly lower memory
usage than Prometheus native storage.

```bash
# Query VictoriaMetrics directly
curl 'http://localhost:8428/api/v1/query?query=http_requests_total'

# Use the MetricsQL dialect (superset of PromQL)
curl 'http://localhost:8428/api/v1/query_range' \
  --data 'query=rate(tool_executions_total[5m])&start=2h&step=60'
```

---

## 4. LLM Observability — Langfuse

Langfuse tracks every LLM call made by UniVex agents — cost, latency, token count,
prompt quality, and output classification.

### Configuration

```dotenv
LANGFUSE_ENABLED=true
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=http://langfuse:3002
```

### What is Tracked

| Event | Data Captured |
|-------|--------------|
| LLM call | provider, model, prompt, completion, tokens, latency |
| Agent task | agent_role, flow_id, tool calls, total cost |
| Tool execution | tool_name, input, output, duration |
| Context summarization | original_length, compressed_length, model |

### Cost Dashboard

Langfuse automatically calculates cost per LLM call based on provider pricing tables.
Access the cost breakdown at `http://localhost:3002/project/<id>/costs`.

---

## 5. Log Aggregation — Loki + Promtail

All container logs are collected by Promtail and forwarded to Loki. Grafana
provides a LogQL query interface.

### Architecture

```
Docker containers → Promtail (file tailing) → Loki → Grafana (LogQL)
```

Config: `docker/monitoring/promtail-config.yml`

### Query Examples

```logql
# All backend errors in the last hour
{container="univex-backend"} |= "ERROR"

# Agent decisions for a specific flow
{container="univex-backend", agent_role="exploit"} | json | flow_id="abc123"

# Tool execution failures
{container="univex-backend"} | json | level="ERROR" | tool_name != ""

# LLM response latency > 5s
{container="univex-backend"} | json | duration_ms > 5000
```

---

## 6. Distributed Tracing — Jaeger

Jaeger provides end-to-end request tracing across all UniVex services via
OpenTelemetry.

### Configuration

```dotenv
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
```

### Span Hierarchy

```
HTTP Request → FastAPI handler
   Agent orchestration (agent_role, flow_id)
       LLM call (provider, model, tokens)
       Tool execution (tool_name, mcp_server)
          Worker dispatch (worker_url, job_id)
       Memory query (memory_type, result_count)
```

Open the Jaeger UI at **http://localhost:16686** and search by:
- Service: `univex-backend`
- Tag: `agent_role=exploit` or `flow_id=<uuid>`

---

## 7. Analytics — ClickHouse

ClickHouse stores historical pentest analytics for trend analysis and reporting.

### Schema

```sql
-- Vulnerability findings over time
SELECT
    toStartOfDay(created_at) AS day,
    severity,
    count() AS count
FROM univex.findings
GROUP BY day, severity
ORDER BY day DESC

-- Most exploited CVEs
SELECT cve_id, count() AS exploits
FROM univex.exploit_attempts
WHERE status = 'success'
GROUP BY cve_id
ORDER BY exploits DESC
LIMIT 20

-- Agent performance by role
SELECT
    agent_role,
    avg(duration_ms) AS avg_duration,
    quantile(0.95)(duration_ms) AS p95_duration
FROM univex.agent_tasks
GROUP BY agent_role
```

### HTTP API

```bash
# Query via ClickHouse HTTP interface
curl 'http://localhost:8123/?query=SELECT+count()+FROM+univex.findings'
```

### REST API

```bash
# UniVex analytics API endpoints
curl http://localhost:8000/api/analytics/findings?from=2026-01-01&to=2026-03-31
curl http://localhost:8000/api/analytics/agent-performance
curl http://localhost:8000/api/analytics/tool-usage
```

---

## 8. Artifact Storage — MinIO

MinIO stores generated reports, browser screenshots, and tool output files.

### Configuration

```dotenv
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=univex
MINIO_SECRET_KEY=<strong-secret>
MINIO_BUCKET=univex-artifacts
MINIO_SECURE=false
```

### Object Path Convention

```
univex-artifacts/
 reports/<report_id>/<format>.pdf
 reports/<report_id>/<format>.html
 screenshots/<flow_id>/<timestamp>_<url>.png
 tool-output/<flow_id>/<tool_name>_<timestamp>.json
```

### Presigned Download URLs

All report downloads use presigned URLs (1-hour expiry by default):

```bash
# Request a presigned download URL
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/api/reports/<id>/download?format=pdf"
# Returns: { "url": "http://minio:9000/univex-artifacts/reports/.../report.pdf?X-Amz-..." }
```

Access the MinIO console at **http://localhost:9001**.

---

## 9. Dashboards — Grafana

Grafana at **http://localhost:3001** includes pre-built dashboards:

| Dashboard | Description |
|-----------|-------------|
| **UniVex Overview** | Active scans, request rate, error rate, tool executions |
| **Agent Performance** | LLM latency, token usage, cost per agent role |
| **Tool Execution** | MCP tool call rates, success/failure, duration histogram |
| **Security Events** | Failed logins, lockouts, IP allowlist blocks |
| **Worker Node** | Job dispatch rate, circuit breaker state, worker latency |
| **OOB Callbacks** | HTTP/DNS/SMTP callback counts by flow |

Dashboard JSON files: `docker/monitoring/grafana/dashboards/`

---

## 10. Alert Rules

Alert rules: `docker/monitoring/prometheus-alerts.yml`

| Alert | Severity | Condition |
|-------|----------|-----------|
| `BackendDown` | Critical | `up{job="backend"} == 0` for > 1m |
| `HighErrorRate` | Warning | `rate(http_requests_total{status_code=~"5.."}[5m]) > 0.1` |
| `LLMHighLatency` | Warning | `p95(llm_request_duration_seconds) > 10` |
| `WorkerCircuitOpen` | Warning | `worker_circuit_breaker_state == 1` |
| `OOBCallbackSpike` | Info | `rate(oob_callbacks_total[5m]) > 10` |
| `DiskSpaceLow` | Warning | `disk_free_percent < 15` |

---

## 11. Isolated Observability Stack

Run only the observability services without the full platform:

```bash
docker compose -f docker-compose-observability.yml up -d
```

Includes: Prometheus, VictoriaMetrics, Grafana, Loki, Promtail, Jaeger, ClickHouse, MinIO.

---

## 12. Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `LANGFUSE_ENABLED` | `false` | Enable Langfuse LLM analytics |
| `LANGFUSE_PUBLIC_KEY` | — | Langfuse project public key |
| `LANGFUSE_SECRET_KEY` | — | Langfuse project secret key |
| `LANGFUSE_HOST` | `http://langfuse:3002` | Langfuse service URL |
| `LOKI_URL` | `http://loki:3100` | Loki push API URL |
| `JAEGER_ENDPOINT` | `http://jaeger:14268/api/traces` | Jaeger trace ingest |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTel collector endpoint |
| `VICTORIA_METRICS_URL` | `http://victoriametrics:8428` | VictoriaMetrics URL |
| `CLICKHOUSE_HOST` | `clickhouse` | ClickHouse host |
| `CLICKHOUSE_PORT` | `9000` | ClickHouse native port |
| `CLICKHOUSE_DATABASE` | `univex` | ClickHouse database |
| `CLICKHOUSE_USER` | `univex` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | — | ClickHouse password |
| `MINIO_ENDPOINT` | `minio:9000` | MinIO endpoint |
| `MINIO_ACCESS_KEY` | `univex` | MinIO access key |
| `MINIO_SECRET_KEY` | — | MinIO secret key |
| `MINIO_BUCKET` | `univex-artifacts` | MinIO artifact bucket |
| `MINIO_SECURE` | `false` | MinIO HTTPS |
| `GRAFANA_PASSWORD` | — | Grafana admin password |

---

*UniVex v1.0.0 Observability Guide | BitR1FT*
