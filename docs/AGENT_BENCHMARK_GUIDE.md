# Agent Benchmark Guide — `ctester`

> Agent Benchmarking CLI

`ctester` is UniVex's built-in agent benchmarking tool, inspired by PentAGI's `ctester -report`. It evaluates all 13 UniVex agent roles against standardised test groups, tracks pass rates over time, generates reports, and detects regressions between runs.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Commands](#commands)
3. [Test Groups](#test-groups)
4. [Benchmark Metrics](#benchmark-metrics)
5. [Report Formats](#report-formats)
6. [Historical Tracking](#historical-tracking)
7. [Regression Detection](#regression-detection)
8. [Authoring Test Groups](#authoring-test-groups)
9. [CI Integration](#ci-integration)
10. [Architecture](#architecture)

---

## Quick Start

```bash
# Run all benchmarks
python backend/tools/ctester.py run

# Run only recon agent benchmarks
python backend/tools/ctester.py run --agent recon

# Run only the exploitation test group
python backend/tools/ctester.py run --group group_exploit

# List all agents and test groups
python backend/tools/ctester.py list

# Generate an HTML report from the last run
python backend/tools/ctester.py report --format html --output report.html

# Compare two runs for regression detection
python backend/tools/ctester.py compare <run_id_a> <run_id_b>

# Show historical benchmark results
python backend/tools/ctester.py history --limit 10
```

---

## Commands

### `ctester run`

Run benchmarks for one or all agents.

```
ctester run [--agent <role>] [--group <group_name>] [--groups-file <path>]
```

| Flag | Description |
|------|-------------|
| `--agent` | Filter by agent role (e.g. `recon`, `exploit`, `report`) |
| `--group` | Filter by test group name (e.g. `group_recon`) |
| `--groups-file` | Path to custom `test_groups.yaml` (default: `backend/tests/agent/benchmark/test_groups.yaml`) |

**Exit codes:**
- `0` — ≥50% of tasks passed
- `1` — <50% of tasks passed (or invalid agent name)

**Example output:**
```
   Starting benchmark run
  → Agent filter: recon

  Run ID: 4f7c2a1b-8d3e-4f0a-9b2c-1d4e5f6a7b8c

  [group_recon] ✓ Port scan 192.168.1.1 (1234ms, acc=1.00, tokens=70)
  [group_recon] ✓ Subdomain enumeration for example.com (987ms, acc=0.75, tokens=90)
  ...

   Summary 
  8/10 passed (80.0%)
  Avg latency:  1150ms
  Total tokens: 800
  Est. cost:    $0.0240
```

---

### `ctester list`

List all 13 UniVex agent roles and all available test groups with task counts.

```
ctester list
```

---

### `ctester report`

Generate a formatted benchmark report.

```
ctester report [--run-id <id>] [--format markdown|json|html] [--output <file>]
```

| Flag | Description |
|------|-------------|
| `--run-id` | Specific run ID to report on |
| `--format` | Output format: `markdown` (default), `json`, or `html` |
| `--output` | Write report to file instead of stdout |

---

### `ctester compare`

Compare two benchmark runs to detect regressions.

```
ctester compare <run_id_a> <run_id_b>
```

**Example output:**
```

  UniVex Benchmark Comparison

  Run A: abc123...
  Run B: def456...

  Pass rate:   +5.0%
  Avg latency: -200ms
  Cost delta:  +$0.00020

  ✓ Improvements:
    • Pass rate improved by 5.0%
    • Avg latency reduced by 200ms

  Regressed tasks: 0
  Fixed tasks:     2

```

---

### `ctester history`

Show historical benchmark results from PostgreSQL.

```
ctester history [--agent <role>] [--limit <n>]
```

Requires `DATABASE_URL` environment variable to be set.

---

## Test Groups

UniVex ships with **4 standardised test groups** covering the full penetration testing lifecycle:

### `group_recon` — 10 tasks

Covers passive and active reconnaissance:

| Task | Agent | Description |
|------|-------|-------------|
| recon-01-port-scan | recon | Full TCP port scan with service banners |
| recon-02-subdomain-enum | recon | Passive subdomain discovery via DNS |
| recon-03-http-probe | recon | HTTP probing with status codes and headers |
| recon-04-web-search-osint | recon | OSINT web search for target organisation |
| recon-05-tech-fingerprint | recon | Web technology and CMS fingerprinting |
| recon-06-directory-fuzz | recon | Directory and file fuzzing |
| recon-07-snmp-enum | recon | SNMP community string enumeration |
| recon-08-wpscan | recon | WordPress vulnerability scanning |
| recon-09-graph-query | recon | Knowledge graph query for stored recon data |
| recon-10-ldap-enum | recon | LDAP enumeration on Active Directory |

### `group_exploit` — 10 tasks

Covers OWASP Top 10 exploitation scenarios:

| Task | Agent | OWASP Category |
|------|-------|----------------|
| exploit-01-sqli | exploit | A03:2021 – Injection |
| exploit-02-xss | exploit | A03:2021 – Injection |
| exploit-03-idor | exploit | A01:2021 – Broken Access Control |
| exploit-04-command-injection | exploit | A03:2021 – Injection |
| exploit-05-broken-auth | exploit | A07:2021 – Identification and Authentication Failures |
| exploit-06-ssrf | exploit | A10:2021 – SSRF |
| exploit-07-xxe | exploit | A05:2021 – Security Misconfiguration |
| exploit-08-path-traversal | exploit | A01:2021 – Broken Access Control |
| exploit-09-deserialization | exploit | A08:2021 – Software and Data Integrity Failures |
| exploit-10-csrf | exploit | A01:2021 – Broken Access Control |

### `group_report` — 5 tasks

Covers structured security reporting:

| Task | Agent | Description |
|------|-------|-------------|
| report-01-executive-summary | report | C-suite executive summary |
| report-02-technical-findings | report | CVSS-scored technical findings |
| report-03-remediation-roadmap | report | Prioritised remediation with timelines |
| report-04-compliance-mapping | report | OWASP/CWE compliance mapping |
| report-05-proof-of-concept | report | PoC reproduction steps |

### `group_reasoning` — 5 tasks

Covers complex multi-step reasoning:

| Task | Agent | Description |
|------|-------|-------------|
| reasoning-01-attack-chain | orchestrator | Full attack chain planning |
| reasoning-02-tool-selection | orchestrator | Adaptive tool selection under constraints |
| reasoning-03-false-positive-triage | reflector | Scanner alert triage |
| reasoning-04-risk-assessment | adviser | Contextual risk assessment |
| reasoning-05-payload-refinement | refiner | Multi-round WAF bypass refinement |

---

## Benchmark Metrics

For each task, `ctester` records:

| Metric | Description |
|--------|-------------|
| **Pass/Fail** | Whether required keywords are present in the response (≥50% threshold) |
| **Accuracy score** | Fraction of expected keywords found (0.0–1.0) |
| **Latency (ms)** | Wall-clock time for the agent response |
| **Token usage** | Prompt tokens, completion tokens, and total |
| **Cost estimate (USD)** | Estimated API cost based on GPT-4-turbo pricing |
| **Tool calls** | Number and names of tools invoked by the agent |

---

## Report Formats

### Markdown (default)

Human-readable report with summary table and per-group results. Suitable for GitHub comments, wikis, and documentation.

```bash
ctester report --format markdown
ctester report --format markdown --output BENCHMARK_REPORT.md
```

### JSON

Machine-readable structured output for integration with dashboards, CI pipelines, and custom analysis tools.

```bash
ctester report --format json | jq '.summary'
```

### HTML

Self-contained dark-themed HTML report with summary cards and results table. Suitable for sharing with stakeholders or embedding in CI artifacts.

```bash
ctester report --format html --output report.html
```

---

## Historical Tracking

`ctester` persists all benchmark results to the `agent_benchmarks` PostgreSQL table:

```sql
CREATE TABLE agent_benchmarks (
    id SERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    task_name TEXT NOT NULL,
    agent_role TEXT NOT NULL,
    group_name TEXT NOT NULL,
    passed BOOLEAN NOT NULL,
    latency_ms DOUBLE PRECISION NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    cost_estimate_usd DOUBLE PRECISION DEFAULT 0,
    tool_calls_count INTEGER DEFAULT 0,
    accuracy_score DOUBLE PRECISION DEFAULT 0,
    error TEXT,
    response_snippet TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

Set `DATABASE_URL` to enable persistence:

```bash
export DATABASE_URL=postgresql://user:pass@localhost/univex
ctester run
ctester history --limit 20
```

---

## Regression Detection

Use `ctester compare` to detect regressions between benchmark runs:

```bash
# Run benchmark before your change
ctester run --group group_exploit > /dev/null
RUN_A=$(ctester history --limit 1 | awk 'NR==4{print $1}')

# Make your changes...

# Run benchmark after your change
ctester run --group group_exploit > /dev/null
RUN_B=$(ctester history --limit 1 | awk 'NR==4{print $1}')

# Compare
ctester compare $RUN_A $RUN_B
```

The comparator flags:
- **Regressions**: pass rate drops >5%, latency increases >1000ms
- **Improvements**: pass rate improves >5%, latency reduces >500ms
- **Per-task diffs**: tasks that changed from pass→fail (regressed) or fail→pass (fixed)

---

## Authoring Test Groups

To add your own test groups, create a YAML file following this schema:

```yaml
groups:
  - name: my_custom_group
    description: "My custom benchmark group"
    tasks:
      - id: my-task-01                    # Stable unique ID (kebab-case)
        name: "Task human-readable name"
        description: "What this tests"
        agent_role: recon                  # Any of the 13 UniVex agent roles
        input_prompt: >
          The exact prompt sent to the agent.
          Can be multi-line.
        expected_keywords:                 # Strings that MUST appear in response
          - keyword1
          - keyword2
        expected_tool_calls:               # Tool names expected to be invoked (optional)
          - naabu
        max_latency_ms: 20000             # Fail if response exceeds this
        tags:                             # Free-form labels for filtering
          - custom
          - my-category
```

### Best practices for test authoring:

1. **Use stable IDs** — use kebab-case format like `mygroup-01-task-name`
2. **Keep expected_keywords broad** — too specific → fragile tests
3. **Set realistic latency limits** — complex tasks need more time
4. **Cover multiple agent roles** — each group can mix roles
5. **Use tags for filtering** — tag by OWASP category, tool, or severity

Run with your custom file:
```bash
ctester run --groups-file path/to/my_groups.yaml
```

---

## CI Integration

### GitHub Actions

```yaml
- name: Run Agent Benchmarks
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
  run: |
    cd backend
    python tools/ctester.py run --group group_report
    python tools/ctester.py report --format markdown >> $GITHUB_STEP_SUMMARY

- name: Regression Check
  run: |
    python tools/ctester.py compare $BASELINE_RUN_ID $CURRENT_RUN_ID
```

### Without a live LLM (CI/CD without API keys)

Without `OPENAI_API_KEY` or a live LLM provider, `ctester` uses a deterministic stub response. This is useful for:
- Testing the benchmark infrastructure itself
- CI pipelines that should not incur API costs
- Unit testing with the built-in test suite

---

## Architecture

```
backend/tools/ctester.py
 BenchmarkTask         — Single benchmark task data model
 BenchmarkGroup        — Collection of tasks
 TaskResult            — Execution result with all metrics
 BenchmarkRun          — Aggregate run result with summary
 BenchmarkRunner       — Loads YAML, executes tasks, persists to DB
 ReportGenerator       — Generates markdown/json/html reports
 RunComparator         — Compares two runs for regressions
 CtesterCLI            — CLI command implementations

backend/tests/agent/benchmark/
 test_groups.yaml      — 4 test groups, 30 total tasks
 test_agent_benchmarks.py — 50+ unit tests
```

The benchmark runner is fully injectable — all dependencies (LLM provider, database connection, test groups file) can be overridden in tests. No real API calls or database connections are required for the test suite.
