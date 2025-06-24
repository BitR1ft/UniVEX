-- ==============================================================================
-- UniVex ClickHouse Analytics Schema
-- Day 13: Columnar analytics database for historical pentest data
--
-- Tables:
--   agent_runs        — LangGraph agent execution records
--   tool_executions   — MCP tool call records
--   findings          — Security findings timeline
--   scan_sessions     — Scan campaign sessions
--   llm_calls         — LLM API call cost & performance tracking
--
-- All tables use the MergeTree family for high-performance time-series queries.
-- TTL policies ensure data is automatically aged out per retention requirements.
-- ==============================================================================

-- Create database
CREATE DATABASE IF NOT EXISTS univex;

-- Use the analytics database
USE univex;

-- ==============================================================================
-- agent_runs — tracks each LangGraph agent invocation
-- ==============================================================================
CREATE TABLE IF NOT EXISTS agent_runs
(
    -- Identity
    run_id          UUID          DEFAULT generateUUIDv4() COMMENT 'Unique run identifier',
    session_id      String        COMMENT 'Parent session / campaign ID',
    campaign_id     String        COMMENT 'Campaign this run belongs to',

    -- Agent metadata
    agent_role      LowCardinality(String)  COMMENT 'Agent role: planner, recon, exploit, etc.',
    agent_version   String        DEFAULT '2.1.0',

    -- Timing
    started_at      DateTime64(3, 'UTC')    COMMENT 'Run start timestamp (ms precision)',
    completed_at    DateTime64(3, 'UTC')    COMMENT 'Run completion timestamp',
    duration_ms     UInt32        COMMENT 'Execution duration in milliseconds',

    -- LLM usage
    prompt_tokens   UInt32        DEFAULT 0  COMMENT 'Prompt tokens consumed',
    completion_tokens UInt32      DEFAULT 0  COMMENT 'Completion tokens generated',
    total_tokens    UInt32        DEFAULT 0  COMMENT 'Total tokens (prompt + completion)',
    cost_usd        Float32       DEFAULT 0.0 COMMENT 'Estimated cost in USD',

    -- Outcome
    success         UInt8         COMMENT '1 = success, 0 = failure',
    error_type      LowCardinality(String)  DEFAULT '' COMMENT 'Error class if failed',
    output_length   UInt32        DEFAULT 0  COMMENT 'Characters in agent output',

    -- Context
    target          String        COMMENT 'Target host/URL/IP',
    model_name      LowCardinality(String)  COMMENT 'LLM model used',
    provider        LowCardinality(String)  COMMENT 'LLM provider: openai, anthropic, etc.'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (agent_role, started_at, run_id)
-- 1-year TTL: agent run records are operational data; older entries are aggregated
-- in mv_daily_agent_stats and can be dropped from the raw table after 12 months.
TTL started_at + INTERVAL 1 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ==============================================================================
-- tool_executions — tracks each MCP tool call
-- ==============================================================================
CREATE TABLE IF NOT EXISTS tool_executions
(
    -- Identity
    execution_id    UUID          DEFAULT generateUUIDv4(),
    run_id          UUID          COMMENT 'Parent agent run ID (FK to agent_runs)',
    campaign_id     String,

    -- Tool metadata
    tool_name       LowCardinality(String)  COMMENT 'e.g. naabu, nuclei, ffuf, sqlmap',
    tool_version    String        DEFAULT '',
    mcp_server_port UInt16        DEFAULT 0,

    -- Execution
    started_at      DateTime64(3, 'UTC'),
    duration_ms     UInt32,
    target          String,
    command_args    String        COMMENT 'Serialized tool arguments (JSON)',

    -- Result
    result_code     Int16         COMMENT 'Exit/result code (0 = success)',
    result_size_bytes UInt32      DEFAULT 0,
    findings_count  UInt16        DEFAULT 0  COMMENT 'Number of findings returned',
    success         UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (tool_name, started_at, execution_id)
TTL started_at + INTERVAL 1 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ==============================================================================
-- findings — security findings timeline
-- ==============================================================================
CREATE TABLE IF NOT EXISTS findings
(
    -- Identity
    finding_id      UUID          DEFAULT generateUUIDv4(),
    campaign_id     String,
    run_id          UUID,

    -- Classification
    severity        LowCardinality(String)  COMMENT 'critical, high, medium, low, info',
    category        LowCardinality(String)  COMMENT 'sqli, xss, rce, ssrf, etc.',
    owasp_tag       LowCardinality(String)  COMMENT 'e.g. A03 — Injection',
    cve_id          String        DEFAULT '',
    cwe_id          String        DEFAULT '',
    cvss_score      Float32       DEFAULT 0.0,

    -- Target context
    target          String,
    affected_component String     DEFAULT '',

    -- Timing
    discovered_at   DateTime64(3, 'UTC'),

    -- Deduplication
    fingerprint     FixedString(16) COMMENT 'SHA-256[:16] for dedup'
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(discovered_at)
ORDER BY (campaign_id, fingerprint, discovered_at)
-- 2-year TTL: findings are compliance artefacts that may need to be referenced
-- during annual audits; they are retained twice as long as operational records.
TTL discovered_at + INTERVAL 2 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ==============================================================================
-- scan_sessions — top-level scan campaign sessions
-- ==============================================================================
CREATE TABLE IF NOT EXISTS scan_sessions
(
    -- Identity
    session_id      String        COMMENT 'Unique session UUID',
    campaign_id     String,

    -- Metadata
    target          String,
    scan_type       LowCardinality(String)  COMMENT 'full, quick, targeted, compliance',
    initiated_by    String        COMMENT 'User ID or API key ID',

    -- Timing
    started_at      DateTime64(3, 'UTC'),
    completed_at    DateTime64(3, 'UTC')   DEFAULT '1970-01-01 00:00:00',
    duration_seconds UInt32       DEFAULT 0,

    -- Outcome
    status          LowCardinality(String)  COMMENT 'running, completed, failed, cancelled',
    total_findings  UInt32        DEFAULT 0,
    critical_count  UInt16        DEFAULT 0,
    high_count      UInt16        DEFAULT 0,
    medium_count    UInt16        DEFAULT 0,
    low_count       UInt16        DEFAULT 0,
    risk_score      Float32       DEFAULT 0.0,

    -- Cost tracking
    total_tokens    UInt32        DEFAULT 0,
    total_cost_usd  Float32       DEFAULT 0.0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (campaign_id, started_at, session_id)
TTL started_at + INTERVAL 2 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ==============================================================================
-- llm_calls — per-call LLM cost and performance tracking
-- ==============================================================================
CREATE TABLE IF NOT EXISTS llm_calls
(
    -- Identity
    call_id         UUID          DEFAULT generateUUIDv4(),
    run_id          UUID,
    session_id      String,

    -- Provider / Model
    provider        LowCardinality(String)  COMMENT 'openai, anthropic, groq, etc.',
    model           LowCardinality(String)  COMMENT 'gpt-4o, claude-3-5-sonnet, etc.',
    api_endpoint    String        DEFAULT '',

    -- Timing
    called_at       DateTime64(3, 'UTC'),
    latency_ms      UInt32        COMMENT 'Time to first token (ms)',
    total_time_ms   UInt32        COMMENT 'Total response time (ms)',

    -- Token usage
    prompt_tokens   UInt32        DEFAULT 0,
    completion_tokens UInt32      DEFAULT 0,
    cached_tokens   UInt32        DEFAULT 0  COMMENT 'Tokens served from provider cache',

    -- Cost (USD)
    cost_usd        Float32       DEFAULT 0.0,
    prompt_cost_usd Float32       DEFAULT 0.0,
    completion_cost_usd Float32   DEFAULT 0.0,

    -- Outcome
    success         UInt8,
    error_code      String        DEFAULT '',
    finish_reason   LowCardinality(String)  DEFAULT '' COMMENT 'stop, length, tool_calls, error'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(called_at)
ORDER BY (provider, model, called_at, call_id)
TTL called_at + INTERVAL 1 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ==============================================================================
-- Materialized views for common aggregations
-- ==============================================================================

-- Daily agent performance summary
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_agent_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, agent_role)
AS SELECT
    toDate(started_at)   AS day,
    agent_role,
    count()              AS run_count,
    sum(success)         AS success_count,
    avg(duration_ms)     AS avg_duration_ms,
    sum(total_tokens)    AS total_tokens,
    sum(cost_usd)        AS total_cost_usd
FROM agent_runs
GROUP BY day, agent_role;

-- Daily cost breakdown by LLM provider
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_llm_cost
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, provider, model)
AS SELECT
    toDate(called_at)    AS day,
    provider,
    model,
    count()              AS call_count,
    sum(prompt_tokens)   AS prompt_tokens,
    sum(completion_tokens) AS completion_tokens,
    sum(cost_usd)        AS total_cost_usd,
    avg(latency_ms)      AS avg_latency_ms
FROM llm_calls
GROUP BY day, provider, model;

-- Daily findings severity breakdown
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_findings
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, severity, category)
AS SELECT
    toDate(discovered_at) AS day,
    severity,
    category,
    count()               AS finding_count,
    avg(cvss_score)       AS avg_cvss
FROM findings
GROUP BY day, severity, category;

-- Tool performance summary
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_tool_performance
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, tool_name)
AS SELECT
    toDate(started_at)   AS day,
    tool_name,
    count()              AS execution_count,
    sum(success)         AS success_count,
    avg(duration_ms)     AS avg_duration_ms,
    sum(findings_count)  AS total_findings
FROM tool_executions
GROUP BY day, tool_name;
