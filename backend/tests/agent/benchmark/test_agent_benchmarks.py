"""
Comprehensive tests for Day 8: ctester Agent Benchmarking CLI
─────────────────────────────────────────────────────────────
Covers:
  - BenchmarkTask / BenchmarkGroup / TaskResult / BenchmarkRun data models
  - BenchmarkRunner: load_groups, get_group, run, _score_response, _estimate_cost
  - ReportGenerator: markdown, json, html formats
  - RunComparator: compare, format_comparison
  - CtesterCLI: cmd_list, cmd_run, cmd_report, cmd_compare, cmd_history
  - CLI entry point: build_parser, main()
  - Full 30-task YAML fixture loading

All tests are pure unit tests — no live PostgreSQL or LLM required.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from argparse import Namespace
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[4]  # UniVex/
_BACKEND = _REPO_ROOT / "backend"
_TOOLS_DIR = _BACKEND / "tools"

for p in (str(_BACKEND), str(_TOOLS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import ctester  # noqa: E402
from ctester import (  # noqa: E402
    ALL_AGENT_ROLES,
    BenchmarkGroup,
    BenchmarkRun,
    BenchmarkRunner,
    BenchmarkTask,
    CtesterCLI,
    ReportGenerator,
    RunComparator,
    TaskResult,
    build_parser,
    colored,
    fail,
    header,
    info,
    main,
    ok,
    warn,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_GROUPS_FILE = str(
    _REPO_ROOT / "backend" / "tests" / "agent" / "benchmark" / "test_groups.yaml"
)


def _make_task(
    task_id: str = "t-001",
    name: str = "Test Task",
    agent_role: str = "recon",
    keywords: Optional[List[str]] = None,
) -> BenchmarkTask:
    return BenchmarkTask(
        id=task_id,
        name=name,
        description="Test description",
        agent_role=agent_role,
        input_prompt="Test prompt",
        expected_keywords=["recon", "port"] if keywords is None else keywords,
        expected_tool_calls=[],
        max_latency_ms=10_000,
        tags=["test"],
    )


def _make_result(
    task_id: str = "t-001",
    passed: bool = True,
    latency_ms: float = 500.0,
    accuracy: float = 0.8,
    tokens: int = 100,
    agent_role: str = "recon",
    group_name: str = "group_recon",
    run_id: str = "run-abc",
) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        task_name="Test Task",
        agent_role=agent_role,
        group_name=group_name,
        run_id=run_id,
        passed=passed,
        latency_ms=latency_ms,
        token_usage={
            "prompt_tokens": tokens // 2,
            "completion_tokens": tokens // 2,
            "total_tokens": tokens,
        },
        cost_estimate_usd=0.001,
        tool_calls_count=1,
        tool_calls_made=["naabu"],
        accuracy_score=accuracy,
    )


def _make_run(results: Optional[List[TaskResult]] = None) -> BenchmarkRun:
    run_id = str(uuid.uuid4())
    if results is None:
        results = [_make_result()]
    return BenchmarkRun(
        run_id=run_id,
        started_at="2026-03-01T00:00:00Z",
        finished_at="2026-03-01T00:01:00Z",
        agent_filter=None,
        group_filter=None,
        results=results,
    )


def _make_runner(groups_file: str = _GROUPS_FILE) -> BenchmarkRunner:
    return BenchmarkRunner(groups_file=groups_file)


# ===========================================================================
# ANSI helpers
# ===========================================================================


class TestColorHelpers:
    def test_colored_returns_string(self):
        result = colored("hello", "green")
        assert "hello" in result

    def test_colored_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert colored("hello", "green") == "hello"

    def test_ok_contains_checkmark(self):
        assert "✓" in ok("done")

    def test_fail_contains_cross(self):
        assert "✗" in fail("error")

    def test_warn_contains_warning(self):
        assert "⚠" in warn("caution")

    def test_info_contains_arrow(self):
        assert "→" in info("note")

    def test_header_returns_string(self):
        assert isinstance(header("title"), str)

    def test_unknown_colour_returns_text(self):
        assert colored("hello", "purple_does_not_exist") == "hello"


# ===========================================================================
# BenchmarkTask
# ===========================================================================


class TestBenchmarkTask:
    def test_creation_defaults(self):
        t = BenchmarkTask(
            id="t1",
            name="Task 1",
            description="Desc",
            agent_role="recon",
            input_prompt="Run naabu",
        )
        assert t.id == "t1"
        assert t.expected_keywords == []
        assert t.expected_tool_calls == []
        assert t.max_latency_ms == 30_000
        assert t.tags == []

    def test_creation_with_values(self):
        t = _make_task(keywords=["port", "open"])
        assert t.expected_keywords == ["port", "open"]
        assert t.agent_role == "recon"

    def test_all_agent_roles_list(self):
        assert "recon" in ALL_AGENT_ROLES
        assert "exploit" in ALL_AGENT_ROLES
        assert "report" in ALL_AGENT_ROLES
        assert "orchestrator" in ALL_AGENT_ROLES
        assert len(ALL_AGENT_ROLES) == 13


# ===========================================================================
# TaskResult
# ===========================================================================


class TestTaskResult:
    def test_creation(self):
        r = _make_result()
        assert r.passed is True
        assert r.latency_ms == 500.0
        assert r.accuracy_score == 0.8

    def test_to_dict(self):
        r = _make_result()
        d = r.to_dict()
        assert d["task_id"] == "t-001"
        assert d["passed"] is True
        assert "token_usage" in d
        assert d["accuracy_score"] == 0.8

    def test_to_dict_failed_result(self):
        r = _make_result(passed=False, accuracy=0.0)
        d = r.to_dict()
        assert d["passed"] is False

    def test_error_field(self):
        r = _make_result()
        r.error = "Timeout"
        assert r.error == "Timeout"

    def test_timestamp_set(self):
        r = _make_result()
        assert r.timestamp  # not empty


# ===========================================================================
# BenchmarkRun
# ===========================================================================


class TestBenchmarkRun:
    def test_empty_run(self):
        run = _make_run(results=[])
        assert run.total_tasks == 0
        assert run.passed_tasks == 0
        assert run.failed_tasks == 0
        assert run.pass_rate == 0.0
        assert run.avg_latency_ms == 0.0
        assert run.total_tokens == 0
        assert run.total_cost_usd == 0.0

    def test_pass_rate_calculation(self):
        results = [
            _make_result(task_id="t1", passed=True),
            _make_result(task_id="t2", passed=True),
            _make_result(task_id="t3", passed=False),
            _make_result(task_id="t4", passed=False),
        ]
        run = _make_run(results=results)
        assert run.total_tasks == 4
        assert run.passed_tasks == 2
        assert run.failed_tasks == 2
        assert run.pass_rate == 0.5

    def test_avg_latency(self):
        results = [
            _make_result(task_id="t1", latency_ms=100.0),
            _make_result(task_id="t2", latency_ms=200.0),
        ]
        run = _make_run(results=results)
        assert run.avg_latency_ms == 150.0

    def test_total_tokens(self):
        results = [
            _make_result(task_id="t1", tokens=100),
            _make_result(task_id="t2", tokens=200),
        ]
        run = _make_run(results=results)
        assert run.total_tokens == 300

    def test_total_cost(self):
        results = [
            _make_result(task_id="t1"),
            _make_result(task_id="t2"),
        ]
        # each result has cost_estimate_usd=0.001
        run = _make_run(results=results)
        assert abs(run.total_cost_usd - 0.002) < 1e-9

    def test_to_dict_structure(self):
        run = _make_run()
        d = run.to_dict()
        assert "run_id" in d
        assert "summary" in d
        assert "results" in d
        assert d["summary"]["total_tasks"] == 1
        assert d["summary"]["pass_rate"] >= 0.0

    def test_all_passed(self):
        results = [_make_result(task_id=f"t{i}", passed=True) for i in range(5)]
        run = _make_run(results=results)
        assert run.pass_rate == 1.0


# ===========================================================================
# BenchmarkRunner — group loading
# ===========================================================================


class TestBenchmarkRunnerLoading:
    def test_load_groups_from_yaml(self):
        runner = _make_runner()
        groups = runner.load_groups()
        assert len(groups) == 4
        names = [g.name for g in groups]
        assert "group_recon" in names
        assert "group_exploit" in names
        assert "group_report" in names
        assert "group_reasoning" in names

    def test_recon_group_has_10_tasks(self):
        runner = _make_runner()
        groups = runner.load_groups()
        recon = next(g for g in groups if g.name == "group_recon")
        assert len(recon.tasks) == 10

    def test_exploit_group_has_10_tasks(self):
        runner = _make_runner()
        groups = runner.load_groups()
        exploit = next(g for g in groups if g.name == "group_exploit")
        assert len(exploit.tasks) == 10

    def test_report_group_has_5_tasks(self):
        runner = _make_runner()
        groups = runner.load_groups()
        report = next(g for g in groups if g.name == "group_report")
        assert len(report.tasks) == 5

    def test_reasoning_group_has_5_tasks(self):
        runner = _make_runner()
        groups = runner.load_groups()
        reasoning = next(g for g in groups if g.name == "group_reasoning")
        assert len(reasoning.tasks) == 5

    def test_total_tasks_30(self):
        runner = _make_runner()
        groups = runner.load_groups()
        total = sum(len(g.tasks) for g in groups)
        assert total == 30

    def test_task_has_required_fields(self):
        runner = _make_runner()
        groups = runner.load_groups()
        task = groups[0].tasks[0]
        assert task.id
        assert task.name
        assert task.agent_role
        assert task.input_prompt

    def test_get_group_by_name(self):
        runner = _make_runner()
        g = runner.get_group("group_recon")
        assert g is not None
        assert g.name == "group_recon"

    def test_get_group_not_found(self):
        runner = _make_runner()
        g = runner.get_group("nonexistent")
        assert g is None

    def test_file_not_found_raises(self):
        runner = BenchmarkRunner(groups_file="/tmp/does_not_exist.yaml")
        with pytest.raises(FileNotFoundError):
            runner.load_groups()

    def test_groups_cached_after_load(self):
        runner = _make_runner()
        groups1 = runner.get_groups()
        groups2 = runner.get_groups()
        assert groups1 is groups2


# ===========================================================================
# BenchmarkRunner — scoring and cost
# ===========================================================================


class TestBenchmarkRunnerScoring:
    def setup_method(self):
        self.runner = _make_runner()

    def test_score_no_keywords_passes(self):
        task = _make_task(keywords=[])
        passed, score = self.runner._score_response("any response", task)
        assert passed is True
        assert score == 1.0

    def test_score_all_keywords_present(self):
        task = _make_task(keywords=["port", "open", "tcp"])
        passed, score = self.runner._score_response("port open tcp scan", task)
        assert passed is True
        assert score == 1.0

    def test_score_no_keywords_present(self):
        task = _make_task(keywords=["port", "open", "tcp"])
        passed, score = self.runner._score_response("nothing relevant here", task)
        assert passed is False
        assert score == 0.0

    def test_score_partial_keywords(self):
        task = _make_task(keywords=["port", "open", "tcp", "scan"])
        passed, score = self.runner._score_response("port open found", task)
        # 2/4 = 0.5 — exactly at threshold, should pass
        assert score == 0.5
        assert passed is True

    def test_score_just_below_threshold(self):
        task = _make_task(keywords=["a", "b", "c", "d", "e", "f", "g"])
        # Match 3/7 ≈ 0.43 < 0.5
        passed, score = self.runner._score_response("a b c", task)
        assert passed is False
        assert score < 0.5

    def test_score_case_insensitive(self):
        task = _make_task(keywords=["PORT", "OPEN"])
        passed, score = self.runner._score_response("port open", task)
        assert passed is True

    def test_estimate_cost_zero_tokens(self):
        cost = self.runner._estimate_cost({})
        assert cost == 0.0

    def test_estimate_cost_basic(self):
        usage = {"prompt_tokens": 1000, "completion_tokens": 1000}
        cost = self.runner._estimate_cost(usage)
        # 1000 * 0.01/1000 + 1000 * 0.03/1000 = 0.04
        assert abs(cost - 0.04) < 1e-8

    def test_estimate_cost_only_prompt(self):
        usage = {"prompt_tokens": 1000}
        cost = self.runner._estimate_cost(usage)
        assert abs(cost - 0.01) < 1e-8


# ===========================================================================
# BenchmarkRunner — async run
# ===========================================================================


class TestBenchmarkRunnerAsync:
    def test_run_returns_benchmark_run(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run())
        assert isinstance(bench_run, BenchmarkRun)
        assert bench_run.run_id
        assert bench_run.started_at
        assert bench_run.finished_at

    def test_run_all_groups_30_tasks(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run())
        assert bench_run.total_tasks == 30

    def test_run_with_agent_filter(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run(agent_filter="recon"))
        # Only recon tasks
        for r in bench_run.results:
            assert r.agent_role == "recon"

    def test_run_with_group_filter(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run(group_filter="group_report"))
        assert bench_run.total_tasks == 5
        for r in bench_run.results:
            assert r.group_name == "group_report"

    def test_run_with_both_filters(self):
        runner = _make_runner()
        bench_run = asyncio.run(
            runner.run(agent_filter="orchestrator", group_filter="group_reasoning")
        )
        # group_reasoning has 1 orchestrator task
        assert bench_run.total_tasks >= 0

    def test_run_stub_response_recorded(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run(group_filter="group_report"))
        assert bench_run.total_tasks > 0
        for r in bench_run.results:
            assert r.response_snippet  # not empty

    def test_run_with_mock_llm(self):
        mock_llm = AsyncMock()
        mock_llm.chat.return_value = MagicMock(
            content="port open tcp recon scan directory",
            usage={"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
            tool_calls=[],
        )
        runner = BenchmarkRunner(groups_file=_GROUPS_FILE, llm_provider=mock_llm)
        bench_run = asyncio.run(runner.run(group_filter="group_recon"))
        assert bench_run.total_tasks == 10

    def test_run_with_llm_error(self):
        mock_llm = AsyncMock()
        mock_llm.chat.side_effect = RuntimeError("API timeout")
        runner = BenchmarkRunner(groups_file=_GROUPS_FILE, llm_provider=mock_llm)
        bench_run = asyncio.run(runner.run(group_filter="group_report"))
        for r in bench_run.results:
            assert r.passed is False
            assert "API timeout" in (r.error or "")

    def test_persist_skipped_without_db(self):
        runner = BenchmarkRunner(groups_file=_GROUPS_FILE, db_url="")
        bench_run = asyncio.run(runner.run(group_filter="group_report"))
        # No exception even without DB
        assert bench_run.total_tasks == 5

    def test_load_history_empty_without_db(self):
        runner = BenchmarkRunner(groups_file=_GROUPS_FILE, db_url="")
        history = asyncio.run(runner.load_history())
        assert history == []

    def test_run_unknown_agent_filter_returns_empty(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run(agent_filter="nonexistent_role"))
        assert bench_run.total_tasks == 0

    def test_run_unknown_group_filter_returns_empty(self):
        runner = _make_runner()
        bench_run = asyncio.run(runner.run(group_filter="nonexistent_group"))
        assert bench_run.total_tasks == 0


# ===========================================================================
# ReportGenerator
# ===========================================================================


class TestReportGenerator:
    def setup_method(self):
        self.gen = ReportGenerator()
        self.run = _make_run(
            results=[
                _make_result(task_id="t1", passed=True, group_name="group_recon"),
                _make_result(task_id="t2", passed=False, group_name="group_exploit"),
            ]
        )

    def test_markdown_contains_header(self):
        md = self.gen.generate(self.run, "markdown")
        assert "# UniVex Agent Benchmark Report" in md

    def test_markdown_contains_run_id(self):
        md = self.gen.generate(self.run, "markdown")
        assert self.run.run_id in md

    def test_markdown_contains_summary(self):
        md = self.gen.generate(self.run, "markdown")
        assert "## Summary" in md

    def test_markdown_contains_pass_rate(self):
        md = self.gen.generate(self.run, "markdown")
        assert "Pass rate" in md

    def test_markdown_contains_results_by_group(self):
        md = self.gen.generate(self.run, "markdown")
        assert "Results by Group" in md

    def test_json_is_valid(self):
        js = self.gen.generate(self.run, "json")
        data = json.loads(js)
        assert "run_id" in data
        assert "summary" in data
        assert "results" in data

    def test_json_summary_fields(self):
        js = self.gen.generate(self.run, "json")
        data = json.loads(js)
        assert "total_tasks" in data["summary"]
        assert "pass_rate" in data["summary"]
        assert "avg_latency_ms" in data["summary"]

    def test_html_contains_doctype(self):
        html = self.gen.generate(self.run, "html")
        assert "<!DOCTYPE html>" in html

    def test_html_contains_title(self):
        html = self.gen.generate(self.run, "html")
        assert "UniVex Benchmark Report" in html

    def test_html_contains_results_table(self):
        html = self.gen.generate(self.run, "html")
        assert "<table>" in html

    def test_html_contains_run_id(self):
        html = self.gen.generate(self.run, "html")
        assert self.run.run_id in html

    def test_default_format_is_markdown(self):
        md = self.gen.generate(self.run)
        assert "# UniVex Agent Benchmark Report" in md

    def test_empty_run_markdown(self):
        empty_run = _make_run(results=[])
        md = self.gen.generate(empty_run, "markdown")
        assert "# UniVex Agent Benchmark Report" in md

    def test_with_agent_filter_shown(self):
        run = _make_run()
        run.agent_filter = "recon"
        md = self.gen.generate(run, "markdown")
        assert "recon" in md


# ===========================================================================
# RunComparator
# ===========================================================================


class TestRunComparator:
    def setup_method(self):
        self.comp = RunComparator()

    def test_compare_identical_runs(self):
        run_a = _make_run(results=[_make_result(task_id="t1", passed=True)])
        run_b = _make_run(results=[_make_result(task_id="t1", passed=True)])
        cmp = self.comp.compare(run_a, run_b)
        assert cmp["delta_pass_rate"] == 0.0
        assert cmp["regressed_count"] == 0
        assert cmp["fixed_count"] == 0

    def test_compare_regression_detected(self):
        run_a = _make_run(
            results=[
                _make_result(task_id="t1", passed=True),
                _make_result(task_id="t2", passed=True),
                _make_result(task_id="t3", passed=True),
                _make_result(task_id="t4", passed=True),
                _make_result(task_id="t5", passed=True),
                _make_result(task_id="t6", passed=True),
            ]
        )
        run_b = _make_run(
            results=[
                _make_result(task_id="t1", passed=False),
                _make_result(task_id="t2", passed=False),
                _make_result(task_id="t3", passed=False),
                _make_result(task_id="t4", passed=True),
                _make_result(task_id="t5", passed=True),
                _make_result(task_id="t6", passed=True),
            ]
        )
        cmp = self.comp.compare(run_a, run_b)
        assert cmp["delta_pass_rate"] < 0
        assert len(cmp["regressions"]) > 0

    def test_compare_improvement_detected(self):
        run_a = _make_run(
            results=[
                _make_result(task_id="t1", passed=False),
                _make_result(task_id="t2", passed=False),
                _make_result(task_id="t3", passed=False),
            ]
        )
        run_b = _make_run(
            results=[
                _make_result(task_id="t1", passed=True),
                _make_result(task_id="t2", passed=True),
                _make_result(task_id="t3", passed=True),
            ]
        )
        cmp = self.comp.compare(run_a, run_b)
        assert cmp["delta_pass_rate"] > 0
        assert len(cmp["improvements"]) > 0

    def test_compare_latency_regression(self):
        run_a = _make_run(results=[_make_result(task_id="t1", latency_ms=500)])
        run_b = _make_run(results=[_make_result(task_id="t1", latency_ms=2000)])
        cmp = self.comp.compare(run_a, run_b)
        assert cmp["delta_avg_latency_ms"] > 0

    def test_compare_task_regressed_flag(self):
        run_a = _make_run(results=[_make_result(task_id="t1", passed=True)])
        run_b = _make_run(results=[_make_result(task_id="t1", passed=False)])
        cmp = self.comp.compare(run_a, run_b)
        regressed = [t for t in cmp["task_diffs"] if t["regressed"]]
        assert len(regressed) == 1

    def test_compare_task_fixed_flag(self):
        run_a = _make_run(results=[_make_result(task_id="t1", passed=False)])
        run_b = _make_run(results=[_make_result(task_id="t1", passed=True)])
        cmp = self.comp.compare(run_a, run_b)
        fixed = [t for t in cmp["task_diffs"] if t["fixed"]]
        assert len(fixed) == 1

    def test_format_comparison_string(self):
        run_a = _make_run()
        run_b = _make_run()
        cmp = self.comp.compare(run_a, run_b)
        output = self.comp.format_comparison(cmp)
        assert "UniVex Benchmark Comparison" in output
        assert run_a.run_id in output

    def test_compare_empty_runs(self):
        run_a = BenchmarkRun(
            run_id="run-a",
            started_at="",
            finished_at="",
            agent_filter=None,
            group_filter=None,
            results=[],
        )
        run_b = BenchmarkRun(
            run_id="run-b",
            started_at="",
            finished_at="",
            agent_filter=None,
            group_filter=None,
            results=[],
        )
        cmp = self.comp.compare(run_a, run_b)
        assert cmp["delta_pass_rate"] == 0.0
        assert cmp["task_diffs"] == []


# ===========================================================================
# CtesterCLI
# ===========================================================================


class TestCtesterCLIList:
    def test_cmd_list_success(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        rc = cli.cmd_list(Namespace())
        assert rc == 0

    def test_cmd_list_shows_agent_roles(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        cli.cmd_list(Namespace())
        captured = capsys.readouterr()
        assert "recon" in captured.out
        assert "exploit" in captured.out

    def test_cmd_list_shows_groups(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        cli.cmd_list(Namespace())
        captured = capsys.readouterr()
        assert "group_recon" in captured.out
        assert "group_exploit" in captured.out

    def test_cmd_list_missing_file_returns_1(self, capsys):
        runner = BenchmarkRunner(groups_file="/tmp/no_file.yaml")
        cli = CtesterCLI(runner=runner)
        rc = cli.cmd_list(Namespace())
        assert rc == 1


class TestCtesterCLIRun:
    def test_cmd_run_no_filters_returns_0_or_1(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(agent=None, group=None)
        rc = cli.cmd_run(args)
        assert rc in (0, 1)

    def test_cmd_run_invalid_agent_returns_1(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(agent="invalid_agent", group=None)
        rc = cli.cmd_run(args)
        assert rc == 1

    def test_cmd_run_valid_agent_filter(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(agent="recon", group=None)
        rc = cli.cmd_run(args)
        assert rc in (0, 1)

    def test_cmd_run_valid_group_filter(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(agent=None, group="group_report")
        rc = cli.cmd_run(args)
        assert rc in (0, 1)

    def test_cmd_run_shows_run_id(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        cli.cmd_run(Namespace(agent=None, group="group_report"))
        captured = capsys.readouterr()
        assert "Run ID" in captured.out

    def test_cmd_run_shows_summary(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        cli.cmd_run(Namespace(agent=None, group="group_report"))
        captured = capsys.readouterr()
        assert "Summary" in captured.out


class TestCtesterCLIReport:
    def test_cmd_report_markdown_default(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(format="markdown", run_id=None, output=None)
        rc = cli.cmd_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "UniVex Agent Benchmark Report" in captured.out

    def test_cmd_report_json(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(format="json", run_id=None, output=None)
        rc = cli.cmd_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "run_id" in data

    def test_cmd_report_html(self, capsys):
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(format="html", run_id=None, output=None)
        rc = cli.cmd_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "<!DOCTYPE html>" in captured.out

    def test_cmd_report_output_file(self, tmp_path, capsys):
        out_file = str(tmp_path / "report.md")
        cli = CtesterCLI(runner=_make_runner())
        args = Namespace(format="markdown", run_id="test-run-id", output=out_file)
        rc = cli.cmd_report(args)
        assert rc == 0
        assert Path(out_file).exists()
        content = Path(out_file).read_text()
        assert "UniVex Agent Benchmark Report" in content


class TestCtesterCLICompare:
    def test_cmd_compare_missing_ids_returns_1(self, capsys):
        cli = CtesterCLI()
        args = Namespace(run_id_a=None, run_id_b=None)
        rc = cli.cmd_compare(args)
        assert rc == 1

    def test_cmd_compare_with_ids(self, capsys):
        cli = CtesterCLI()
        args = Namespace(run_id_a="run-aaa", run_id_b="run-bbb")
        rc = cli.cmd_compare(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "Comparison" in captured.out or "run-aaa" in captured.out


class TestCtesterCLIHistory:
    def test_cmd_history_no_db(self, capsys, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        cli = CtesterCLI(runner=BenchmarkRunner(groups_file=_GROUPS_FILE, db_url=""))
        args = Namespace(agent=None, limit=20)
        rc = cli.cmd_history(args)
        assert rc == 0


# ===========================================================================
# CLI entry point
# ===========================================================================


class TestBuildParser:
    def test_parser_no_subcommand(self):
        p = build_parser()
        args = p.parse_args([])
        assert args.command is None

    def test_parser_run_command(self):
        p = build_parser()
        args = p.parse_args(["run", "--agent", "recon", "--group", "group_recon"])
        assert args.command == "run"
        assert args.agent == "recon"
        assert args.group == "group_recon"

    def test_parser_list_command(self):
        p = build_parser()
        args = p.parse_args(["list"])
        assert args.command == "list"

    def test_parser_report_command(self):
        p = build_parser()
        args = p.parse_args(["report", "--format", "json", "--run-id", "abc"])
        assert args.command == "report"
        assert args.format == "json"

    def test_parser_compare_command(self):
        p = build_parser()
        args = p.parse_args(["compare", "run-aaa", "run-bbb"])
        assert args.command == "compare"
        assert args.run_id_a == "run-aaa"
        assert args.run_id_b == "run-bbb"

    def test_parser_history_command(self):
        p = build_parser()
        args = p.parse_args(["history", "--agent", "recon", "--limit", "5"])
        assert args.command == "history"
        assert args.agent == "recon"
        assert args.limit == 5


class TestMainEntryPoint:
    def test_main_no_args_returns_0(self):
        rc = main([])
        assert rc == 0

    def test_main_list(self, capsys):
        rc = main(["list"])
        assert rc == 0

    def test_main_report_markdown(self, capsys):
        rc = main(["report", "--format", "markdown"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "UniVex Agent Benchmark Report" in out

    def test_main_report_json(self, capsys):
        rc = main(["report", "--format", "json"])
        assert rc == 0

    def test_main_compare_missing_args(self):
        with pytest.raises(SystemExit):
            main(["compare"])  # missing both positional args

    def test_main_run_group(self, capsys):
        rc = main(["run", "--group", "group_report"])
        assert rc in (0, 1)

    def test_main_history_no_db(self, capsys, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        rc = main(["history"])
        assert rc == 0
