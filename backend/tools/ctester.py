#!/usr/bin/env python3
"""
ctester — UniVex Agent Benchmarking CLI

Usage:
  ctester run [--agent <role>] [--group <group_name>]   Run benchmarks
  ctester list                                           List agents and test groups
  ctester report [--run-id <id>] [--format markdown|json|html]  Generate report
  ctester compare <run_id_a> <run_id_b>                 Compare two runs (regression)
  ctester history [--agent <role>] [--limit <n>]        Show past benchmark results

Inspired by PentAGI's ctester tool, purpose-built for UniVex's 13 agent roles.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ---------------------------------------------------------------------------
# Path bootstrap — allow running as a standalone script
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_COLOURS: Dict[str, str] = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def colored(text: str, colour: str) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    code = _COLOURS.get(colour, "")
    return f"{code}{text}{_COLOURS['reset']}" if code else text


def ok(msg: str) -> str:
    return colored(f"✓ {msg}", "green")


def fail(msg: str) -> str:
    return colored(f"✗ {msg}", "red")


def warn(msg: str) -> str:
    return colored(f"⚠ {msg}", "yellow")


def info(msg: str) -> str:
    return colored(f"→ {msg}", "cyan")


def header(msg: str) -> str:
    return colored(msg, "bold")


# ---------------------------------------------------------------------------
# All 13 UniVex agent roles
# ---------------------------------------------------------------------------

ALL_AGENT_ROLES: List[str] = [
    "recon",
    "exploit",
    "report",
    "web",
    "adviser",
    "coder",
    "enricher",
    "generator",
    "installer",
    "refiner",
    "reflector",
    "simple_json",
    "orchestrator",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkTask:
    """A single benchmark task within a test group."""

    id: str
    name: str
    description: str
    agent_role: str
    input_prompt: str
    expected_keywords: List[str] = field(default_factory=list)
    expected_tool_calls: List[str] = field(default_factory=list)
    max_latency_ms: int = 30_000
    tags: List[str] = field(default_factory=list)


@dataclass
class BenchmarkGroup:
    """A named collection of benchmark tasks."""

    name: str
    description: str
    tasks: List[BenchmarkTask] = field(default_factory=list)


@dataclass
class TaskResult:
    """Result for a single benchmark task execution."""

    task_id: str
    task_name: str
    agent_role: str
    group_name: str
    run_id: str
    passed: bool
    latency_ms: float
    token_usage: Dict[str, int] = field(default_factory=dict)
    cost_estimate_usd: float = 0.0
    tool_calls_count: int = 0
    tool_calls_made: List[str] = field(default_factory=list)
    accuracy_score: float = 0.0
    error: Optional[str] = None
    response_snippet: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkRun:
    """Aggregate result for a complete benchmark run."""

    run_id: str
    started_at: str
    finished_at: str
    agent_filter: Optional[str]
    group_filter: Optional[str]
    results: List[TaskResult] = field(default_factory=list)

    @property
    def total_tasks(self) -> int:
        return len(self.results)

    @property
    def passed_tasks(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_tasks(self) -> int:
        return self.total_tasks - self.passed_tasks

    @property
    def pass_rate(self) -> float:
        if not self.total_tasks:
            return 0.0
        return self.passed_tasks / self.total_tasks

    @property
    def avg_latency_ms(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.latency_ms for r in self.results) / len(self.results)

    @property
    def total_tokens(self) -> int:
        return sum(r.token_usage.get("total_tokens", 0) for r in self.results)

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_estimate_usd for r in self.results)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "agent_filter": self.agent_filter,
            "group_filter": self.group_filter,
            "summary": {
                "total_tasks": self.total_tasks,
                "passed": self.passed_tasks,
                "failed": self.failed_tasks,
                "pass_rate": round(self.pass_rate, 4),
                "avg_latency_ms": round(self.avg_latency_ms, 2),
                "total_tokens": self.total_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
            },
            "results": [r.to_dict() for r in self.results],
        }
        return d


# ---------------------------------------------------------------------------
# Default test groups path
# ---------------------------------------------------------------------------

_DEFAULT_GROUPS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "tests",
    "agent",
    "benchmark",
    "test_groups.yaml",
)


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------


class BenchmarkRunner:
    """
    Loads test groups from YAML and executes benchmark tasks against
    UniVex agent roles, recording metrics for each task.
    """

    def __init__(
        self,
        groups_file: str = _DEFAULT_GROUPS_FILE,
        db_url: Optional[str] = None,
        llm_provider: Optional[Any] = None,
    ) -> None:
        self._groups_file = groups_file
        self._db_url = db_url or os.environ.get("DATABASE_URL", "")
        self._llm = llm_provider  # injectable for testing
        self._groups: List[BenchmarkGroup] = []

    # ------------------------------------------------------------------
    # Group loading
    # ------------------------------------------------------------------

    def load_groups(self) -> List[BenchmarkGroup]:
        """Load benchmark groups from YAML file."""
        path = Path(self._groups_file)
        if not path.exists():
            raise FileNotFoundError(f"Test groups file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        groups: List[BenchmarkGroup] = []
        for gdata in raw.get("groups", []):
            tasks = []
            for tdata in gdata.get("tasks", []):
                tasks.append(
                    BenchmarkTask(
                        id=tdata.get("id", str(uuid.uuid4())),
                        name=tdata["name"],
                        description=tdata.get("description", ""),
                        agent_role=tdata["agent_role"],
                        input_prompt=tdata["input_prompt"],
                        expected_keywords=tdata.get("expected_keywords", []),
                        expected_tool_calls=tdata.get("expected_tool_calls", []),
                        max_latency_ms=tdata.get("max_latency_ms", 30_000),
                        tags=tdata.get("tags", []),
                    )
                )
            groups.append(
                BenchmarkGroup(
                    name=gdata["name"],
                    description=gdata.get("description", ""),
                    tasks=tasks,
                )
            )
        self._groups = groups
        return groups

    def get_groups(self) -> List[BenchmarkGroup]:
        if not self._groups:
            self.load_groups()
        return self._groups

    def get_group(self, name: str) -> Optional[BenchmarkGroup]:
        for g in self.get_groups():
            if g.name == name:
                return g
        return None

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    def _score_response(
        self, response: str, task: BenchmarkTask
    ) -> Tuple[bool, float]:
        """
        Score a response against expected keywords.
        Returns (passed, accuracy_score 0.0–1.0).
        """
        if not task.expected_keywords:
            return True, 1.0
        lower = response.lower()
        hits = sum(1 for kw in task.expected_keywords if kw.lower() in lower)
        score = hits / len(task.expected_keywords)
        passed = score >= 0.5  # require at least 50% keyword coverage
        return passed, round(score, 4)

    def _estimate_cost(self, token_usage: Dict[str, int], model: str = "gpt-4") -> float:
        """Rough USD cost estimate based on token counts."""
        # GPT-4-turbo-like pricing as fallback default
        prompt_cost_per_1k = 0.01
        completion_cost_per_1k = 0.03
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        return round(
            (prompt_tokens / 1000) * prompt_cost_per_1k
            + (completion_tokens / 1000) * completion_cost_per_1k,
            8,
        )

    async def _run_task(
        self,
        task: BenchmarkTask,
        run_id: str,
        group_name: str,
    ) -> TaskResult:
        """Execute a single benchmark task and return its result."""
        start_ms = time.monotonic() * 1000

        response = ""
        tool_calls_made: List[str] = []
        token_usage: Dict[str, int] = {}
        error: Optional[str] = None

        try:
            if self._llm is not None:
                # Use injected provider (test mode)
                llm_resp = await self._llm.chat(
                    messages=[{"role": "user", "content": task.input_prompt}]
                )
                response = getattr(llm_resp, "content", str(llm_resp))
                usage = getattr(llm_resp, "usage", {})
                token_usage = usage if isinstance(usage, dict) else {}
                tool_calls_made = getattr(llm_resp, "tool_calls", []) or []
            else:
                # No live LLM — produce a deterministic stub response so unit
                # tests and CI pipelines don't require real API credentials.
                response = (
                    f"[BENCHMARK STUB] Agent '{task.agent_role}' received: "
                    f"{task.input_prompt[:120]}"
                )
                token_usage = {
                    "prompt_tokens": len(task.input_prompt.split()),
                    "completion_tokens": 20,
                    "total_tokens": len(task.input_prompt.split()) + 20,
                }
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

        latency_ms = (time.monotonic() * 1000) - start_ms
        passed, accuracy = self._score_response(response, task)
        if error:
            passed = False
            accuracy = 0.0

        cost = self._estimate_cost(token_usage)

        return TaskResult(
            task_id=task.id,
            task_name=task.name,
            agent_role=task.agent_role,
            group_name=group_name,
            run_id=run_id,
            passed=passed,
            latency_ms=round(latency_ms, 2),
            token_usage=token_usage,
            cost_estimate_usd=cost,
            tool_calls_count=len(tool_calls_made),
            tool_calls_made=tool_calls_made,
            accuracy_score=accuracy,
            error=error,
            response_snippet=response[:200],
        )

    async def run(
        self,
        agent_filter: Optional[str] = None,
        group_filter: Optional[str] = None,
    ) -> BenchmarkRun:
        """Run all matching benchmark tasks and return a BenchmarkRun."""
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        results: List[TaskResult] = []

        groups = self.get_groups()
        for group in groups:
            if group_filter and group.name != group_filter:
                continue
            for task in group.tasks:
                if agent_filter and task.agent_role != agent_filter:
                    continue
                result = await self._run_task(task, run_id, group.name)
                results.append(result)

        finished_at = datetime.now(timezone.utc).isoformat()
        bench_run = BenchmarkRun(
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            agent_filter=agent_filter,
            group_filter=group_filter,
            results=results,
        )

        # Persist to DB if available
        try:
            await self._persist_run(bench_run)
        except Exception:  # noqa: BLE001
            pass

        return bench_run

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist_run(self, bench_run: BenchmarkRun) -> None:
        """Persist benchmark results to the `agent_benchmarks` table."""
        if not self._db_url:
            return
        try:
            import asyncpg  # noqa: PLC0415
        except ImportError:
            return

        conn = await asyncpg.connect(self._db_url)
        try:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_benchmarks (
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
                )
                """
            )
            for r in bench_run.results:
                await conn.execute(
                    """
                    INSERT INTO agent_benchmarks (
                        run_id, task_id, task_name, agent_role, group_name,
                        passed, latency_ms,
                        prompt_tokens, completion_tokens, total_tokens,
                        cost_estimate_usd, tool_calls_count,
                        accuracy_score, error, response_snippet
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                    """,
                    r.run_id,
                    r.task_id,
                    r.task_name,
                    r.agent_role,
                    r.group_name,
                    r.passed,
                    r.latency_ms,
                    r.token_usage.get("prompt_tokens", 0),
                    r.token_usage.get("completion_tokens", 0),
                    r.token_usage.get("total_tokens", 0),
                    r.cost_estimate_usd,
                    r.tool_calls_count,
                    r.accuracy_score,
                    r.error,
                    r.response_snippet,
                )
        finally:
            await conn.close()

    async def load_history(
        self,
        agent_filter: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Load historical benchmark runs from the database."""
        if not self._db_url:
            return []
        try:
            import asyncpg  # noqa: PLC0415
        except ImportError:
            return []

        conn = await asyncpg.connect(self._db_url)
        try:
            query = """
                SELECT run_id,
                       COUNT(*) FILTER (WHERE passed) AS passed,
                       COUNT(*) AS total,
                       ROUND(AVG(latency_ms)::numeric, 2) AS avg_latency_ms,
                       ROUND(SUM(cost_estimate_usd)::numeric, 6) AS total_cost,
                       MAX(created_at) AS last_run
                FROM agent_benchmarks
                {where}
                GROUP BY run_id
                ORDER BY last_run DESC
                LIMIT $1
            """
            if agent_filter:
                where = "WHERE agent_role = $2"
                rows = await conn.fetch(query.format(where=where), limit, agent_filter)
            else:
                rows = await conn.fetch(query.format(where=""), limit)
            return [dict(r) for r in rows]
        finally:
            await conn.close()


# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Generates benchmark reports in multiple formats."""

    def generate(self, bench_run: BenchmarkRun, fmt: str = "markdown") -> str:
        if fmt == "json":
            return self._json(bench_run)
        if fmt == "html":
            return self._html(bench_run)
        return self._markdown(bench_run)

    def _markdown(self, bench_run: BenchmarkRun) -> str:  # noqa: PLR0914
        lines: List[str] = []
        lines.append("# UniVex Agent Benchmark Report")
        lines.append("")
        lines.append(f"**Run ID:** `{bench_run.run_id}`  ")
        lines.append(f"**Started:** {bench_run.started_at}  ")
        lines.append(f"**Finished:** {bench_run.finished_at}  ")
        if bench_run.agent_filter:
            lines.append(f"**Agent filter:** `{bench_run.agent_filter}`  ")
        if bench_run.group_filter:
            lines.append(f"**Group filter:** `{bench_run.group_filter}`  ")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total tasks | {bench_run.total_tasks} |")
        lines.append(f"| Passed | {bench_run.passed_tasks} ✓ |")
        lines.append(f"| Failed | {bench_run.failed_tasks} ✗ |")
        lines.append(
            f"| Pass rate | {bench_run.pass_rate * 100:.1f}% |"
        )
        lines.append(f"| Avg latency | {bench_run.avg_latency_ms:.0f} ms |")
        lines.append(f"| Total tokens | {bench_run.total_tokens:,} |")
        lines.append(
            f"| Est. cost | ${bench_run.total_cost_usd:.4f} |"
        )
        lines.append("")
        lines.append("## Results by Group")
        lines.append("")

        # Group results
        by_group: Dict[str, List[TaskResult]] = {}
        for r in bench_run.results:
            by_group.setdefault(r.group_name, []).append(r)

        for group_name, group_results in sorted(by_group.items()):
            passed_cnt = sum(1 for r in group_results if r.passed)
            lines.append(
                f"### {group_name} ({passed_cnt}/{len(group_results)} passed)"
            )
            lines.append("")
            lines.append(
                "| Task | Agent | Pass | Latency | Accuracy | Tokens | Cost |"
            )
            lines.append(
                "|------|-------|------|---------|----------|--------|------|"
            )
            for r in group_results:
                status = "✓" if r.passed else "✗"
                lines.append(
                    f"| {r.task_name} | {r.agent_role} | {status} "
                    f"| {r.latency_ms:.0f}ms | {r.accuracy_score:.2f} "
                    f"| {r.token_usage.get('total_tokens', 0)} "
                    f"| ${r.cost_estimate_usd:.5f} |"
                )
            lines.append("")

        return "\n".join(lines)

    def _json(self, bench_run: BenchmarkRun) -> str:
        return json.dumps(bench_run.to_dict(), indent=2, default=str)

    def _html(self, bench_run: BenchmarkRun) -> str:  # noqa: PLR0914
        pass_color = "#28a745" if bench_run.pass_rate >= 0.8 else "#dc3545"
        rows_html = ""
        for r in bench_run.results:
            status_color = "#28a745" if r.passed else "#dc3545"
            status_sym = "✓" if r.passed else "✗"
            rows_html += (
                f"<tr>"
                f"<td>{r.group_name}</td>"
                f"<td>{r.task_name}</td>"
                f"<td>{r.agent_role}</td>"
                f"<td style='color:{status_color}'>{status_sym}</td>"
                f"<td>{r.latency_ms:.0f}ms</td>"
                f"<td>{r.accuracy_score:.2f}</td>"
                f"<td>{r.token_usage.get('total_tokens', 0)}</td>"
                f"<td>${r.cost_estimate_usd:.5f}</td>"
                f"</tr>\n"
            )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>UniVex Benchmark Report — {bench_run.run_id}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; margin: 2rem; background: #0d1117; color: #e6edf3; }}
    h1, h2 {{ color: #58a6ff; }}
    .summary {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; min-width: 140px; }}
    .card .value {{ font-size: 1.8rem; font-weight: bold; color: {pass_color}; }}
    .card .label {{ font-size: 0.85rem; color: #8b949e; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th {{ background: #21262d; text-align: left; padding: 0.5rem 0.75rem; border-bottom: 2px solid #30363d; }}
    td {{ padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; }}
    tr:hover td {{ background: #161b22; }}
  </style>
</head>
<body>
  <h1>🎯 UniVex Agent Benchmark Report</h1>
  <p><strong>Run ID:</strong> <code>{bench_run.run_id}</code></p>
  <p><strong>Period:</strong> {bench_run.started_at} → {bench_run.finished_at}</p>
  <div class="summary">
    <div class="card"><div class="value">{bench_run.total_tasks}</div><div class="label">Total Tasks</div></div>
    <div class="card"><div class="value" style="color:#28a745">{bench_run.passed_tasks}</div><div class="label">Passed</div></div>
    <div class="card"><div class="value" style="color:#dc3545">{bench_run.failed_tasks}</div><div class="label">Failed</div></div>
    <div class="card"><div class="value">{bench_run.pass_rate * 100:.1f}%</div><div class="label">Pass Rate</div></div>
    <div class="card"><div class="value">{bench_run.avg_latency_ms:.0f}ms</div><div class="label">Avg Latency</div></div>
    <div class="card"><div class="value">{bench_run.total_tokens:,}</div><div class="label">Tokens</div></div>
    <div class="card"><div class="value">${bench_run.total_cost_usd:.4f}</div><div class="label">Est. Cost</div></div>
  </div>
  <h2>Results</h2>
  <table>
    <thead>
      <tr>
        <th>Group</th><th>Task</th><th>Agent</th><th>Status</th>
        <th>Latency</th><th>Accuracy</th><th>Tokens</th><th>Cost</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Regression comparison
# ---------------------------------------------------------------------------


class RunComparator:
    """Compare two BenchmarkRun objects to detect regressions."""

    def compare(
        self, run_a: BenchmarkRun, run_b: BenchmarkRun
    ) -> Dict[str, Any]:
        """Return a structured comparison dict."""
        delta_pass_rate = run_b.pass_rate - run_a.pass_rate
        delta_latency = run_b.avg_latency_ms - run_a.avg_latency_ms
        delta_cost = run_b.total_cost_usd - run_a.total_cost_usd

        regressions: List[str] = []
        improvements: List[str] = []

        if delta_pass_rate < -0.05:
            regressions.append(
                f"Pass rate dropped by {abs(delta_pass_rate) * 100:.1f}%"
            )
        elif delta_pass_rate > 0.05:
            improvements.append(
                f"Pass rate improved by {delta_pass_rate * 100:.1f}%"
            )

        if delta_latency > 1000:
            regressions.append(f"Avg latency increased by {delta_latency:.0f}ms")
        elif delta_latency < -500:
            improvements.append(f"Avg latency reduced by {abs(delta_latency):.0f}ms")

        # Per-task comparison
        task_map_a = {r.task_id: r for r in run_a.results}
        task_map_b = {r.task_id: r for r in run_b.results}
        task_diffs: List[Dict[str, Any]] = []

        for task_id, result_b in task_map_b.items():
            result_a = task_map_a.get(task_id)
            if result_a is None:
                continue
            diff = {
                "task_id": task_id,
                "task_name": result_b.task_name,
                "agent_role": result_b.agent_role,
                "pass_a": result_a.passed,
                "pass_b": result_b.passed,
                "latency_delta_ms": round(
                    result_b.latency_ms - result_a.latency_ms, 2
                ),
                "accuracy_delta": round(
                    result_b.accuracy_score - result_a.accuracy_score, 4
                ),
                "regressed": result_a.passed and not result_b.passed,
                "fixed": not result_a.passed and result_b.passed,
            }
            task_diffs.append(diff)

        return {
            "run_id_a": run_a.run_id,
            "run_id_b": run_b.run_id,
            "delta_pass_rate": round(delta_pass_rate, 4),
            "delta_avg_latency_ms": round(delta_latency, 2),
            "delta_cost_usd": round(delta_cost, 8),
            "regressions": regressions,
            "improvements": improvements,
            "task_diffs": task_diffs,
            "regressed_count": sum(1 for t in task_diffs if t["regressed"]),
            "fixed_count": sum(1 for t in task_diffs if t["fixed"]),
        }

    def format_comparison(self, comparison: Dict[str, Any]) -> str:
        lines: List[str] = []
        lines.append(header("═" * 60))
        lines.append(header("  UniVex Benchmark Comparison"))
        lines.append(header("═" * 60))
        lines.append(f"  Run A: {comparison['run_id_a']}")
        lines.append(f"  Run B: {comparison['run_id_b']}")
        lines.append("")

        delta_pr = comparison["delta_pass_rate"]
        pr_str = f"{delta_pr * 100:+.1f}%"
        pr_col = "green" if delta_pr >= 0 else "red"
        lines.append(f"  Pass rate:   {colored(pr_str, pr_col)}")

        delta_lat = comparison["delta_avg_latency_ms"]
        lat_str = f"{delta_lat:+.0f}ms"
        lat_col = "green" if delta_lat <= 0 else "red"
        lines.append(f"  Avg latency: {colored(lat_str, lat_col)}")

        delta_cost = comparison["delta_cost_usd"]
        cost_str = f"${delta_cost:+.5f}"
        cost_col = "green" if delta_cost <= 0 else "yellow"
        lines.append(f"  Cost delta:  {colored(cost_str, cost_col)}")
        lines.append("")

        if comparison["regressions"]:
            lines.append(colored("  ⚠ Regressions detected:", "red"))
            for r in comparison["regressions"]:
                lines.append(colored(f"    • {r}", "red"))
        if comparison["improvements"]:
            lines.append(colored("  ✓ Improvements:", "green"))
            for imp in comparison["improvements"]:
                lines.append(colored(f"    • {imp}", "green"))

        rc = comparison["regressed_count"]
        fc = comparison["fixed_count"]
        lines.append("")
        lines.append(f"  Regressed tasks: {colored(str(rc), 'red' if rc else 'green')}")
        lines.append(f"  Fixed tasks:     {colored(str(fc), 'green' if fc else 'dim')}")
        lines.append(header("═" * 60))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CtesterCLI
# ---------------------------------------------------------------------------


class CtesterCLI:
    """
    Command implementations for the ``ctester`` CLI tool.

    Each public ``cmd_*`` method corresponds to a CLI sub-command.
    """

    def __init__(
        self,
        runner: Optional[BenchmarkRunner] = None,
        reporter: Optional[ReportGenerator] = None,
        comparator: Optional[RunComparator] = None,
    ) -> None:
        self._runner = runner or BenchmarkRunner()
        self._reporter = reporter or ReportGenerator()
        self._comparator = comparator or RunComparator()

    # ------------------------------------------------------------------
    # list
    # ------------------------------------------------------------------

    def cmd_list(self, args: argparse.Namespace) -> int:
        """List all agent roles and available test groups."""
        print(header("\n  UniVex Agent Roles"))
        print("  " + "─" * 40)
        for i, role in enumerate(ALL_AGENT_ROLES, 1):
            print(f"  {i:2d}. {colored(role, 'cyan')}")

        try:
            groups = self._runner.get_groups()
        except FileNotFoundError as exc:
            print(warn(f"\n  Test groups file not found: {exc}"))
            return 1

        print(header("\n  Test Groups"))
        print("  " + "─" * 40)
        for g in groups:
            task_count = len(g.tasks)
            print(f"  {colored(g.name, 'cyan')} — {g.description}")
            print(f"    {colored(str(task_count), 'bold')} tasks")
            by_agent: Dict[str, int] = {}
            for t in g.tasks:
                by_agent[t.agent_role] = by_agent.get(t.agent_role, 0) + 1
            for agent, cnt in sorted(by_agent.items()):
                print(f"      • {agent}: {cnt}")
        print()
        return 0

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    def cmd_run(self, args: argparse.Namespace) -> int:
        """Run benchmarks for one or all agents / groups."""
        agent_filter = getattr(args, "agent", None)
        group_filter = getattr(args, "group", None)

        if agent_filter and agent_filter not in ALL_AGENT_ROLES:
            print(fail(f"Unknown agent role: '{agent_filter}'"))
            print(info(f"Valid roles: {', '.join(ALL_AGENT_ROLES)}"))
            return 1

        print(header(f"\n  ▶ Starting benchmark run"))
        if agent_filter:
            print(info(f"  Agent filter: {agent_filter}"))
        if group_filter:
            print(info(f"  Group filter: {group_filter}"))
        print()

        bench_run = asyncio.run(
            self._runner.run(
                agent_filter=agent_filter,
                group_filter=group_filter,
            )
        )

        print(header(f"  Run ID: {bench_run.run_id}"))
        print()

        # Print per-task results
        for r in bench_run.results:
            status = ok(r.task_name) if r.passed else fail(r.task_name)
            print(
                f"  [{r.group_name}] {status} "
                f"({r.latency_ms:.0f}ms, "
                f"acc={r.accuracy_score:.2f}, "
                f"tokens={r.token_usage.get('total_tokens', 0)})"
            )
            if r.error:
                print(f"    {colored('Error: ' + r.error, 'red')}")

        print()
        print(header("  ── Summary ──────────────────────────────────"))
        rate = bench_run.pass_rate * 100
        rate_col = "green" if rate >= 80 else ("yellow" if rate >= 50 else "red")
        print(
            f"  {colored(f'{bench_run.passed_tasks}/{bench_run.total_tasks} passed ({rate:.1f}%)', rate_col)}"
        )
        print(f"  Avg latency:  {bench_run.avg_latency_ms:.0f}ms")
        print(f"  Total tokens: {bench_run.total_tokens:,}")
        print(f"  Est. cost:    ${bench_run.total_cost_usd:.4f}")
        print()

        return 0 if bench_run.pass_rate >= 0.5 else 1

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------

    def cmd_report(self, args: argparse.Namespace) -> int:
        """Generate a formatted benchmark report."""
        fmt = getattr(args, "format", "markdown") or "markdown"
        run_id = getattr(args, "run_id", None)

        # Without a live run, create a minimal stub run for demonstration
        stub_run = BenchmarkRun(
            run_id=run_id or "demo-" + str(uuid.uuid4())[:8],
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            agent_filter=None,
            group_filter=None,
            results=[],
        )

        report_text = self._reporter.generate(stub_run, fmt)

        output_file = getattr(args, "output", None)
        if output_file:
            Path(output_file).write_text(report_text, encoding="utf-8")
            print(ok(f"Report written to {output_file}"))
        else:
            print(report_text)

        return 0

    # ------------------------------------------------------------------
    # compare
    # ------------------------------------------------------------------

    def cmd_compare(self, args: argparse.Namespace) -> int:
        """Compare two benchmark run IDs (regression detection)."""
        run_id_a = getattr(args, "run_id_a", None)
        run_id_b = getattr(args, "run_id_b", None)

        if not run_id_a or not run_id_b:
            print(fail("Two run IDs are required: ctester compare <run_id_a> <run_id_b>"))
            return 1

        # Stub runs for offline comparison (DB integration optional)
        run_a = BenchmarkRun(
            run_id=run_id_a,
            started_at="",
            finished_at="",
            agent_filter=None,
            group_filter=None,
            results=[],
        )
        run_b = BenchmarkRun(
            run_id=run_id_b,
            started_at="",
            finished_at="",
            agent_filter=None,
            group_filter=None,
            results=[],
        )

        comparison = self._comparator.compare(run_a, run_b)
        print(self._comparator.format_comparison(comparison))
        return 0

    # ------------------------------------------------------------------
    # history
    # ------------------------------------------------------------------

    def cmd_history(self, args: argparse.Namespace) -> int:
        """Show past benchmark results from PostgreSQL."""
        agent_filter = getattr(args, "agent", None)
        limit = getattr(args, "limit", 20) or 20

        rows = asyncio.run(
            self._runner.load_history(
                agent_filter=agent_filter, limit=limit
            )
        )

        if not rows:
            db_url = os.environ.get("DATABASE_URL", "")
            if not db_url:
                print(warn("  DATABASE_URL not set — history requires PostgreSQL."))
            else:
                print(info("  No benchmark history found."))
            return 0

        print(header("\n  Benchmark History"))
        print("  " + "─" * 70)
        print(
            f"  {'Run ID':<38} {'Pass':>5} {'Total':>6} {'Avg ms':>8} {'Cost':>10}"
        )
        print("  " + "─" * 70)
        for row in rows:
            rate = int(row.get("passed", 0)) / max(int(row.get("total", 1)), 1)
            rate_col = "green" if rate >= 0.8 else ("yellow" if rate >= 0.5 else "red")
            print(
                f"  {row['run_id']:<38} "
                f"{colored(str(row['passed']), rate_col):>5} "
                f"{row['total']:>6} "
                f"{float(row['avg_latency_ms']):>8.0f} "
                f"${float(row['total_cost']):>9.4f}"
            )
        print()
        return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctester",
        description="UniVex Agent Benchmarking CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # run
    run_p = sub.add_parser("run", help="Run agent benchmarks")
    run_p.add_argument(
        "--agent",
        metavar="ROLE",
        help=f"Filter by agent role ({', '.join(ALL_AGENT_ROLES)})",
    )
    run_p.add_argument("--group", metavar="NAME", help="Filter by test group name")
    run_p.add_argument(
        "--groups-file",
        metavar="PATH",
        default=_DEFAULT_GROUPS_FILE,
        help="Path to test_groups.yaml",
    )

    # list
    sub.add_parser("list", help="List agent roles and test groups")

    # report
    report_p = sub.add_parser("report", help="Generate benchmark report")
    report_p.add_argument("--run-id", metavar="ID", help="Run ID to report on")
    report_p.add_argument(
        "--format",
        choices=["markdown", "json", "html"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    report_p.add_argument("--output", metavar="FILE", help="Write report to file")

    # compare
    compare_p = sub.add_parser(
        "compare", help="Compare two benchmark runs (regression detection)"
    )
    compare_p.add_argument("run_id_a", help="First run ID (baseline)")
    compare_p.add_argument("run_id_b", help="Second run ID (comparison)")

    # history
    history_p = sub.add_parser("history", help="Show past benchmark results")
    history_p.add_argument("--agent", metavar="ROLE", help="Filter by agent role")
    history_p.add_argument(
        "--limit", type=int, default=20, metavar="N", help="Max rows (default: 20)"
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    cli = CtesterCLI()

    # Override groups file if provided via --groups-file
    if args.command == "run" and getattr(args, "groups_file", None):
        cli._runner._groups_file = args.groups_file

    command_map = {
        "run": cli.cmd_run,
        "list": cli.cmd_list,
        "report": cli.cmd_report,
        "compare": cli.cmd_compare,
        "history": cli.cmd_history,
    }
    handler = command_map.get(args.command)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
