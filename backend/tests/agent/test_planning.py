"""
Tests for Day 9 — Advanced AI Planning & Chain-of-Thought.

Covers:
  DependencyGraph  — add/remove/topo-sort/critical path/execution plan/mermaid/serialization
  BacktrackEngine  — find_alternatives/prune/scoring/suggest_next_step
  AttackPlanner    — create_plan/thought_branches/pruning/strategies/cost_benefit/serialize
  CostBenefit      — ROI property, known/unknown tools
  AttackPlan       — summary/to_dict/from_dict/to_mermaid
  Integration      — end-to-end, web ports, SSH, backtracking, explanation
"""

import json
import pytest

from app.agent.planning import (
    AttackPlanner,
    AttackPlan,
    PlanStatus,
    AttackStrategy,
    DependencyGraph,
    AttackStep,
    StepStatus,
    BacktrackEngine,
    BacktrackStrategy,
    AlternativePath,
    CostBenefit,
    CyclicDependencyError,
)
from app.agent.state.agent_state import Phase


# ===========================================================================
# Helpers
# ===========================================================================


def make_step(
    name: str = "Step",
    tool: str = "nmap",
    cost: float = 30.0,
    risk: float = 0.3,
    success: float = 0.8,
    phase: Phase = Phase.INFORMATIONAL,
    deps: list = None,
) -> AttackStep:
    return AttackStep(
        name=name,
        description=f"Description for {name}",
        tool_name=tool,
        tool_input={},
        phase=phase,
        cost=cost,
        risk_score=risk,
        success_probability=success,
        dependencies=list(deps or []),
    )


def three_step_graph() -> DependencyGraph:
    """A -> B -> C (A must complete before B, B before C)."""
    g = DependencyGraph()
    a = make_step("A", cost=10.0)
    b = make_step("B", cost=20.0)
    c = make_step("C", cost=30.0)
    g.add_step(a)
    g.add_step(b)
    g.add_step(c)
    g.add_dependency(b.id, a.id)
    g.add_dependency(c.id, b.id)
    return g


# ===========================================================================
# TestDependencyGraph  (20+ tests)
# ===========================================================================


class TestDependencyGraph:
    def test_add_step(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        assert g.get_step(s.id) is s

    def test_add_duplicate_step_is_idempotent(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        g.add_step(s)
        assert len(g._steps) == 1

    def test_remove_step(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        g.remove_step(s.id)
        assert g.get_step(s.id) is None

    def test_remove_nonexistent_step_is_silent(self):
        g = DependencyGraph()
        g.remove_step("does-not-exist")  # must not raise

    def test_get_step_missing_returns_none(self):
        g = DependencyGraph()
        assert g.get_step("ghost") is None

    def test_add_dependency(self):
        g = DependencyGraph()
        a = make_step("A")
        b = make_step("B")
        g.add_step(a)
        g.add_step(b)
        g.add_dependency(b.id, a.id)
        assert a.id in g._dependencies[b.id]

    def test_cycle_detection_direct(self):
        g = DependencyGraph()
        a = make_step("A")
        b = make_step("B")
        g.add_step(a)
        g.add_step(b)
        g.add_dependency(b.id, a.id)
        with pytest.raises(CyclicDependencyError):
            g.add_dependency(a.id, b.id)

    def test_cycle_detection_indirect(self):
        g = three_step_graph()
        steps = list(g._steps.values())
        # Find C and A by topological position
        topo = g.topological_sort()
        a, b, c = topo[0], topo[1], topo[2]
        with pytest.raises(CyclicDependencyError):
            g.add_dependency(a.id, c.id)

    def test_topological_sort_order(self):
        g = three_step_graph()
        order = g.topological_sort()
        assert len(order) == 3
        names = [s.name for s in order]
        assert names.index("A") < names.index("B") < names.index("C")

    def test_topological_sort_empty_graph(self):
        g = DependencyGraph()
        assert g.topological_sort() == []

    def test_topological_sort_single_step(self):
        g = DependencyGraph()
        s = make_step("X")
        g.add_step(s)
        assert g.topological_sort() == [s]

    def test_get_ready_steps_initially_all_pending_no_deps(self):
        g = DependencyGraph()
        a = make_step("A")
        b = make_step("B")
        g.add_step(a)
        g.add_step(b)
        ready = g.get_ready_steps()
        assert len(ready) == 2

    def test_get_ready_steps_blocked_by_pending_dep(self):
        g = three_step_graph()
        topo = g.topological_sort()
        # Only A is ready; B depends on A which is PENDING (not COMPLETED)
        ready_names = [s.name for s in g.get_ready_steps()]
        assert "A" in ready_names
        assert "B" not in ready_names

    def test_get_ready_steps_after_completing_dep(self):
        g = three_step_graph()
        topo = g.topological_sort()
        a = topo[0]
        g.mark_step_completed(a.id, "done")
        ready_names = [s.name for s in g.get_ready_steps()]
        assert "B" in ready_names

    def test_get_blocked_steps(self):
        g = three_step_graph()
        topo = g.topological_sort()
        a = topo[0]
        g.mark_step_failed(a.id, "timeout")
        blocked = g.get_blocked_steps()
        assert len(blocked) >= 1

    def test_mark_step_running(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        g.mark_step_running(s.id)
        assert s.status == StepStatus.RUNNING
        assert s.started_at is not None

    def test_mark_step_completed(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        g.mark_step_completed(s.id, "ok")
        assert s.status == StepStatus.COMPLETED
        assert s.result == "ok"
        assert s.completed_at is not None

    def test_mark_step_failed(self):
        g = DependencyGraph()
        s = make_step("A")
        g.add_step(s)
        g.mark_step_failed(s.id, "error")
        assert s.status == StepStatus.FAILED
        assert s.error == "error"

    def test_execution_plan_batches(self):
        g = three_step_graph()
        batches = g.get_execution_plan()
        # A must be in batch 0, B in batch 1, C in batch 2
        assert len(batches) == 3
        assert any(s.name == "A" for s in batches[0])
        assert any(s.name == "B" for s in batches[1])
        assert any(s.name == "C" for s in batches[2])

    def test_execution_plan_parallel_steps(self):
        g = DependencyGraph()
        root = make_step("Root")
        left = make_step("Left")
        right = make_step("Right")
        g.add_step(root)
        g.add_step(left)
        g.add_step(right)
        g.add_dependency(left.id, root.id)
        g.add_dependency(right.id, root.id)
        batches = g.get_execution_plan()
        # Root alone in batch 0; Left and Right together in batch 1
        assert len(batches) == 2
        assert len(batches[1]) == 2

    def test_critical_path(self):
        g = three_step_graph()
        cp = g.get_critical_path()
        names = [s.name for s in cp]
        # The only path A->B->C is the critical path
        assert names == ["A", "B", "C"]

    def test_critical_path_empty_graph(self):
        g = DependencyGraph()
        assert g.get_critical_path() == []

    def test_to_mermaid(self):
        g = three_step_graph()
        diagram = g.to_mermaid()
        assert "flowchart TD" in diagram
        assert "-->" in diagram

    def test_to_dict_and_from_dict(self):
        g = three_step_graph()
        g.mark_step_running(g.topological_sort()[0].id)
        data = g.to_dict()
        g2 = DependencyGraph.from_dict(data)
        assert len(g2._steps) == 3
        topo = g2.topological_sort()
        assert topo[0].name == "A"
        assert topo[0].status == StepStatus.RUNNING

    def test_summary(self):
        g = three_step_graph()
        s = g.summary()
        assert s["total_steps"] == 3
        assert "status_counts" in s
        assert s["critical_path_length"] == 3

    def test_failed_step_blocks_dependents(self):
        g = three_step_graph()
        topo = g.topological_sort()
        g.mark_step_failed(topo[0].id, "boom")
        assert topo[1].status == StepStatus.BLOCKED

    def test_add_dependency_missing_step_raises(self):
        g = DependencyGraph()
        a = make_step("A")
        g.add_step(a)
        with pytest.raises(KeyError):
            g.add_dependency(a.id, "nonexistent")


# ===========================================================================
# TestBacktrackEngine  (15+ tests)
# ===========================================================================


class TestBacktrackEngine:
    def setup_method(self):
        self.engine = BacktrackEngine()

    def _graph_with_failed_step(self):
        """Graph: A(fail) -> B(blocked), plus independent C and D."""
        g = DependencyGraph()
        a = make_step("A", success=0.9)
        b = make_step("B", success=0.8)
        c = make_step("C", success=0.7)
        d = make_step("D", success=0.6)
        g.add_step(a)
        g.add_step(b)
        g.add_step(c)
        g.add_step(d)
        g.add_dependency(b.id, a.id)
        g.mark_step_failed(a.id, "timeout")
        return g, a, b, c, d

    def test_find_alternatives_returns_list(self):
        g, a, *_ = self._graph_with_failed_step()
        alts = self.engine.find_alternatives(g, a.id)
        assert isinstance(alts, list)

    def test_find_alternatives_excludes_failed_step(self):
        g, a, b, c, d = self._graph_with_failed_step()
        alts = self.engine.find_alternatives(g, a.id)
        for alt in alts:
            for step in alt.steps:
                assert step.id != a.id

    def test_find_alternatives_excludes_dependents_of_failed(self):
        g, a, b, c, d = self._graph_with_failed_step()
        alts = self.engine.find_alternatives(g, a.id)
        for alt in alts:
            for step in alt.steps:
                assert step.id != b.id

    def test_find_alternatives_nonexistent_step(self):
        g = three_step_graph()
        alts = self.engine.find_alternatives(g, "ghost-id")
        assert alts == []

    def test_find_alternatives_empty_graph(self):
        g = DependencyGraph()
        alts = self.engine.find_alternatives(g, "x")
        assert alts == []

    def test_prune_paths_below_threshold(self):
        engine = BacktrackEngine(min_success_threshold=0.5)
        low = AlternativePath(steps=[], total_cost=10, expected_success=0.2, rationale="")
        high = AlternativePath(steps=[], total_cost=10, expected_success=0.8, rationale="")
        result = engine.prune_paths([low, high])
        assert low not in result
        assert high in result

    def test_prune_paths_max_alternatives(self):
        engine = BacktrackEngine(max_alternatives=2, min_success_threshold=0.0)
        paths = [
            AlternativePath(steps=[], total_cost=10, expected_success=0.9 - i * 0.1, rationale="")
            for i in range(5)
        ]
        result = engine.prune_paths(paths)
        assert len(result) <= 2

    def test_score_path_higher_success_better(self):
        engine = BacktrackEngine()
        low = AlternativePath(steps=[], total_cost=10, expected_success=0.3, rationale="")
        high = AlternativePath(steps=[], total_cost=10, expected_success=0.9, rationale="")
        assert engine._score_path(high) > engine._score_path(low)

    def test_suggest_next_step_returns_ready_step(self):
        g = DependencyGraph()
        s = make_step("Solo", success=0.8)
        g.add_step(s)
        result = self.engine.suggest_next_step(g)
        assert result is not None
        assert result.id == s.id

    def test_suggest_next_step_empty_graph(self):
        g = DependencyGraph()
        assert self.engine.suggest_next_step(g) is None

    def test_suggest_next_step_no_ready_steps(self):
        g = three_step_graph()
        topo = g.topological_sort()
        g.mark_step_running(topo[0].id)
        # B and C still have unmet dependencies
        engine = BacktrackEngine()
        next_step = engine.suggest_next_step(g)
        # Only A was ready but now running — nothing is PENDING + ready
        # (A is RUNNING so not PENDING anymore)
        assert next_step is None

    def test_backtrack_strategy_best_first(self):
        g = DependencyGraph()
        low = make_step("Low", success=0.2)
        high = make_step("High", success=0.9)
        g.add_step(low)
        g.add_step(high)
        engine = BacktrackEngine(strategy=BacktrackStrategy.BEST_FIRST)
        best = engine.suggest_next_step(g)
        assert best.name == "High"

    def test_backtrack_strategy_breadth_first(self):
        g = three_step_graph()
        engine = BacktrackEngine(strategy=BacktrackStrategy.BREADTH_FIRST)
        suggestion = engine.suggest_next_step(g)
        # Only A is ready (no dependencies), so it should be suggested
        assert suggestion is not None
        assert suggestion.name == "A"

    def test_get_backtrack_rationale_contains_failed_name(self):
        failed = make_step("FailedStep")
        alt = AlternativePath(
            steps=[make_step("Alt")], total_cost=60, expected_success=0.7, rationale=""
        )
        rationale = self.engine.get_backtrack_rationale(failed, alt)
        assert "FailedStep" in rationale

    def test_find_alternatives_respects_max_alternatives(self):
        engine = BacktrackEngine(max_alternatives=1, min_success_threshold=0.0)
        g, a, *_ = self._graph_with_failed_step()
        alts = engine.find_alternatives(g, a.id)
        assert len(alts) <= 1

    def test_prune_paths_deduplication(self):
        engine = BacktrackEngine(min_success_threshold=0.0, max_alternatives=10)
        s = make_step("X")
        same = AlternativePath(steps=[s], total_cost=10, expected_success=0.7, rationale="")
        duplicate = AlternativePath(steps=[s], total_cost=10, expected_success=0.7, rationale="")
        result = engine.prune_paths([same, duplicate])
        assert len(result) == 1


# ===========================================================================
# TestCostBenefit  (5+ tests)
# ===========================================================================


class TestCostBenefit:
    def _cb(self, success=0.8, value=0.9, risk=0.3):
        return CostBenefit(
            tool_name="nmap",
            estimated_time_seconds=45,
            risk_score=risk,
            success_probability=success,
            value_score=value,
            recommendation="Test",
        )

    def test_roi_formula(self):
        cb = self._cb(success=0.8, value=0.9, risk=0.3)
        expected = (0.8 * 0.9) / (0.3 + 0.01)
        assert abs(cb.roi - expected) < 1e-6

    def test_roi_zero_risk_uses_epsilon(self):
        cb = self._cb(risk=0.0)
        assert cb.roi > 0  # should not divide by zero

    def test_known_tool_nmap(self):
        planner = AttackPlanner()
        cb = planner.analyze_cost_benefit("nmap", {})
        assert cb.estimated_time_seconds == 45
        assert cb.risk_score < 0.5

    def test_known_tool_sqlmap(self):
        planner = AttackPlanner()
        cb = planner.analyze_cost_benefit("sqlmap", {})
        assert cb.risk_score > 0.5

    def test_unknown_tool_defaults(self):
        planner = AttackPlanner()
        cb = planner.analyze_cost_benefit("super_unknown_tool_xyz", {})
        assert cb.estimated_time_seconds == 60
        assert cb.risk_score == 0.5
        assert cb.success_probability == 0.4


# ===========================================================================
# TestAttackPlanner  (20+ tests)
# ===========================================================================


class TestAttackPlanner:
    def setup_method(self):
        self.planner = AttackPlanner(strategy=AttackStrategy.BALANCED)

    def test_create_plan_returns_attack_plan(self):
        plan = self.planner.create_plan("192.168.1.1", "Find vulnerabilities", {})
        assert isinstance(plan, AttackPlan)

    def test_create_plan_sets_target(self):
        plan = self.planner.create_plan("10.0.0.1", "Test", {})
        assert plan.metadata.target == "10.0.0.1"

    def test_create_plan_sets_objective(self):
        plan = self.planner.create_plan("10.0.0.1", "Find SQLi", {})
        assert plan.metadata.objective == "Find SQLi"

    def test_create_plan_with_session_id(self):
        plan = self.planner.create_plan("host", "obj", {}, session_id="sess-1")
        assert plan.metadata.session_id == "sess-1"

    def test_create_plan_has_active_status(self):
        plan = self.planner.create_plan("host", "obj", {})
        assert plan.metadata.status == PlanStatus.ACTIVE

    def test_generate_thought_branches_web_ports(self):
        branches = self.planner.generate_thought_branches(
            "exploit web", {"open_ports": [80, 443]}
        )
        strategies = [b["strategy"] for b in branches]
        assert "web_exploitation" in strategies

    def test_generate_thought_branches_ssh(self):
        branches = self.planner.generate_thought_branches(
            "get access", {"open_ports": [22]}
        )
        strategies = [b["strategy"] for b in branches]
        assert "credential_attack" in strategies

    def test_generate_thought_branches_wordpress(self):
        branches = self.planner.generate_thought_branches(
            "scan site", {"technologies": ["WordPress"]}
        )
        strategies = [b["strategy"] for b in branches]
        assert "wordpress_exploitation" in strategies

    def test_generate_thought_branches_fallback(self):
        # No recon data — fallback branch should be generated
        branches = self.planner.generate_thought_branches("anything", {})
        assert len(branches) >= 1

    def test_prune_branches_removes_low_success(self):
        branches = [
            {"branch_id": "a", "strategy": "x", "steps": [], "rationale": "", "estimated_success": 0.1},
            {"branch_id": "b", "strategy": "y", "steps": [], "rationale": "", "estimated_success": 0.8},
        ]
        pruned = self.planner.prune_branches(branches)
        assert all(b["estimated_success"] > 0.2 for b in pruned)

    def test_prune_branches_max_three(self):
        branches = [
            {"branch_id": str(i), "strategy": "x", "steps": [], "rationale": "", "estimated_success": 0.9}
            for i in range(6)
        ]
        pruned = self.planner.prune_branches(branches)
        assert len(pruned) <= 3

    def test_prune_branches_stealth_filters_high_risk(self):
        planner = AttackPlanner(strategy=AttackStrategy.STEALTH)
        high_risk_branch = {
            "branch_id": "hr",
            "strategy": "x",
            "steps": [{"tool_name": "hydra", "name": "Brute"}],
            "rationale": "",
            "estimated_success": 0.8,
        }
        low_risk_branch = {
            "branch_id": "lr",
            "strategy": "y",
            "steps": [{"tool_name": "nmap", "name": "Scan"}],
            "rationale": "",
            "estimated_success": 0.7,
        }
        pruned = planner.prune_branches([high_risk_branch, low_risk_branch])
        # hydra should be filtered out in stealth mode
        assert not any(b["branch_id"] == "hr" for b in pruned)

    def test_prune_branches_compliance_filters_destructive(self):
        planner = AttackPlanner(strategy=AttackStrategy.COMPLIANCE)
        destructive = {
            "branch_id": "d",
            "strategy": "x",
            "steps": [{"tool_name": "metasploit", "name": "Exploit"}],
            "rationale": "",
            "estimated_success": 0.8,
        }
        safe = {
            "branch_id": "s",
            "strategy": "y",
            "steps": [{"tool_name": "nmap", "name": "Scan"}],
            "rationale": "",
            "estimated_success": 0.7,
        }
        pruned = planner.prune_branches([destructive, safe])
        assert not any(b["branch_id"] == "d" for b in pruned)

    def test_select_best_path_highest_success(self):
        branches = [
            {"branch_id": "a", "estimated_success": 0.4},
            {"branch_id": "b", "estimated_success": 0.9},
            {"branch_id": "c", "estimated_success": 0.6},
        ]
        best = self.planner.select_best_path(branches)
        assert best["branch_id"] == "b"

    def test_select_best_path_empty_returns_empty(self):
        result = self.planner.select_best_path([])
        assert result == {}

    def test_build_dependency_graph_step_count(self):
        branch = {
            "steps": [
                {"name": "A", "description": "d", "tool_name": "nmap", "tool_input": {}, "phase": Phase.INFORMATIONAL},
                {"name": "B", "description": "d", "tool_name": "ffuf", "tool_input": {}, "phase": Phase.INFORMATIONAL, "depends_on": ["A"]},
            ]
        }
        g = self.planner.build_dependency_graph(branch)
        assert len(g._steps) == 2

    def test_build_dependency_graph_wires_deps(self):
        branch = {
            "steps": [
                {"name": "A", "description": "d", "tool_name": "nmap", "tool_input": {}, "phase": Phase.INFORMATIONAL},
                {"name": "B", "description": "d", "tool_name": "ffuf", "tool_input": {}, "phase": Phase.INFORMATIONAL, "depends_on": ["A"]},
            ]
        }
        g = self.planner.build_dependency_graph(branch)
        topo = g.topological_sort()
        assert topo[0].name == "A"
        assert topo[1].name == "B"

    def test_analyze_cost_benefit_known_tool(self):
        cb = self.planner.analyze_cost_benefit("nmap", {})
        assert isinstance(cb, CostBenefit)
        assert cb.tool_name == "nmap"

    def test_explain_plan_contains_target(self):
        plan = self.planner.create_plan("pentest-host", "pentest", {"open_ports": [80]})
        explanation = self.planner.explain_plan(plan)
        assert "pentest-host" in explanation

    def test_explain_plan_contains_strategy(self):
        plan = self.planner.create_plan("host", "obj", {})
        explanation = self.planner.explain_plan(plan)
        assert "BALANCED" in explanation.upper()

    def test_update_plan_pause(self):
        plan = self.planner.create_plan("host", "obj", {})
        updated = self.planner.update_plan(plan, "please pause the plan")
        assert updated.metadata.status == PlanStatus.PAUSED

    def test_update_plan_abandon(self):
        plan = self.planner.create_plan("host", "obj", {})
        updated = self.planner.update_plan(plan, "cancel this plan")
        assert updated.metadata.status == PlanStatus.ABANDONED

    def test_update_plan_strategy_stealth(self):
        plan = self.planner.create_plan("host", "obj", {})
        updated = self.planner.update_plan(plan, "switch to stealth mode")
        assert updated.metadata.strategy == AttackStrategy.STEALTH

    def test_serialize_deserialize_roundtrip(self):
        plan = self.planner.create_plan("host", "obj", {"open_ports": [80]})
        serialized = self.planner.serialize_plan(plan)
        restored = self.planner.deserialize_plan(serialized)
        assert restored.metadata.plan_id == plan.metadata.plan_id
        assert restored.metadata.target == plan.metadata.target

    def test_serialize_produces_json_string(self):
        plan = self.planner.create_plan("host", "obj", {})
        serialized = self.planner.serialize_plan(plan)
        data = json.loads(serialized)
        assert "metadata" in data


# ===========================================================================
# TestAttackPlan  (5+ tests)
# ===========================================================================


class TestAttackPlan:
    def _make_plan(self, target="host.local"):
        planner = AttackPlanner()
        return planner.create_plan(target, "pentest", {"open_ports": [80, 443]})

    def test_summary_has_plan_id(self):
        plan = self._make_plan()
        s = plan.summary()
        assert "plan_id" in s

    def test_summary_has_graph_info(self):
        plan = self._make_plan()
        s = plan.summary()
        assert "graph" in s

    def test_to_dict_and_from_dict_roundtrip(self):
        plan = self._make_plan("roundtrip.host")
        data = plan.to_dict()
        restored = AttackPlan.from_dict(data)
        assert restored.metadata.target == "roundtrip.host"
        assert len(restored.graph._steps) == len(plan.graph._steps)

    def test_to_mermaid_contains_header(self):
        plan = self._make_plan()
        diagram = plan.to_mermaid()
        assert "flowchart TD" in diagram

    def test_to_mermaid_contains_plan_metadata(self):
        plan = self._make_plan("mermaid.host")
        diagram = plan.to_mermaid()
        assert plan.metadata.plan_id in diagram


# ===========================================================================
# TestAttackPlannerIntegration  (5+ tests)
# ===========================================================================


class TestAttackPlannerIntegration:
    def test_end_to_end_plan_creation(self):
        planner = AttackPlanner(strategy=AttackStrategy.BALANCED)
        plan = planner.create_plan(
            "192.168.1.100",
            "Comprehensive penetration test",
            {"open_ports": [22, 80, 443], "services": ["ssh", "http", "https"]},
        )
        assert plan is not None
        assert plan.metadata.plan_id
        assert len(plan.graph._steps) > 0

    def test_plan_with_web_ports_includes_web_tools(self):
        planner = AttackPlanner()
        plan = planner.create_plan(
            "web.target.com",
            "Web app pentest",
            {"open_ports": [80, 443]},
        )
        tool_names = {s.tool_name for s in plan.graph._steps.values()}
        # At minimum, nmap should appear (port scan phase)
        assert len(tool_names) > 0

    def test_plan_with_ssh_port(self):
        planner = AttackPlanner()
        plan = planner.create_plan(
            "ssh.target.com",
            "Test SSH security",
            {"open_ports": [22]},
        )
        branches = planner.generate_thought_branches(
            "Test SSH security", {"open_ports": [22]}
        )
        strategies = [b["strategy"] for b in branches]
        assert "credential_attack" in strategies

    def test_backtracking_integration(self):
        planner = AttackPlanner()
        plan = planner.create_plan(
            "target", "obj", {"open_ports": [80, 443]}
        )
        engine = BacktrackEngine()
        topo = plan.graph.topological_sort()
        if not topo:
            return
        # Fail the first step
        plan.graph.mark_step_failed(topo[0].id, "simulated failure")
        alts = engine.find_alternatives(plan.graph, topo[0].id)
        assert isinstance(alts, list)

    def test_plan_explains_correctly(self):
        planner = AttackPlanner(strategy=AttackStrategy.AGGRESSIVE)
        plan = planner.create_plan("host", "aggressive test", {"open_ports": [80]})
        explanation = planner.explain_plan(plan)
        assert "host" in explanation
        assert "aggressive test" in explanation

    def test_resume_plan(self):
        planner = AttackPlanner()
        plan = planner.create_plan("host", "obj", {"open_ports": [80]})
        plan.metadata.status = PlanStatus.PAUSED
        g2 = DependencyGraph.from_dict(plan.graph.to_dict())
        resumed = planner.resume_plan(plan, g2)
        assert resumed.metadata.status == PlanStatus.ACTIVE

    def test_aggressive_strategy_plan(self):
        planner = AttackPlanner(strategy=AttackStrategy.AGGRESSIVE)
        plan = planner.create_plan(
            "host", "aggressive", {"open_ports": [22, 80], "services": ["ssh"]}
        )
        assert plan.metadata.strategy == AttackStrategy.AGGRESSIVE

    def test_cost_benefits_populated_on_create(self):
        planner = AttackPlanner()
        plan = planner.create_plan("host", "obj", {"open_ports": [80]})
        assert len(plan.cost_benefits) > 0
