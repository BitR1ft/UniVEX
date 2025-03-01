"""
Backtracking Engine

Automatically explores alternative attack paths when the primary path fails.
Implements tree-search with pruning based on cost-benefit analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .dependency_graph import AttackStep, DependencyGraph, StepStatus


class BacktrackStrategy(str, Enum):
    DEPTH_FIRST = "depth_first"
    BREADTH_FIRST = "breadth_first"
    BEST_FIRST = "best_first"


@dataclass
class PathNode:
    step_id: str
    parent_id: Optional[str]
    depth: int
    cumulative_cost: float
    cumulative_success_prob: float
    path: List[str] = field(default_factory=list)


@dataclass
class AlternativePath:
    steps: List[AttackStep]
    total_cost: float
    expected_success: float
    rationale: str


class BacktrackEngine:
    """
    Explores alternative attack paths when the primary path fails.
    """

    def __init__(
        self,
        max_depth: int = 10,
        max_alternatives: int = 5,
        min_success_threshold: float = 0.3,
        strategy: BacktrackStrategy = BacktrackStrategy.BEST_FIRST,
    ) -> None:
        self.max_depth = max_depth
        self.max_alternatives = max_alternatives
        self.min_success_threshold = min_success_threshold
        self.strategy = strategy

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_alternatives(
        self, graph: DependencyGraph, failed_step_id: str
    ) -> List[AlternativePath]:
        """
        Find alternative paths that bypass the failed step.

        Walks the graph and collects sequences of non-failed steps that
        don't depend on the failed step.
        """
        failed_step = graph.get_step(failed_step_id)
        if failed_step is None:
            return []

        # Collect all steps that are NOT blocked/failed AND do not
        # transitively depend on the failed step.
        eligible = self._eligible_steps(graph, failed_step_id)
        if not eligible:
            return []

        # Build paths from eligible steps
        raw_paths = self._build_paths(eligible, graph)
        alternatives = []
        for path_steps in raw_paths:
            if not path_steps:
                continue
            total_cost = sum(s.cost for s in path_steps)
            # joint probability (product) — simplified heuristic
            expected_success = 1.0
            for s in path_steps:
                expected_success *= s.success_probability
            rationale = self.get_backtrack_rationale(
                failed_step,
                AlternativePath(
                    steps=path_steps,
                    total_cost=total_cost,
                    expected_success=expected_success,
                    rationale="",
                ),
            )
            alternatives.append(
                AlternativePath(
                    steps=path_steps,
                    total_cost=total_cost,
                    expected_success=expected_success,
                    rationale=rationale,
                )
            )

        return self.prune_paths(alternatives)

    def _score_path(self, path: AlternativePath) -> float:
        """Score = success_prob / (1 + cost normalized to a 300s reference)."""
        return path.expected_success / (1 + path.total_cost / 300.0)

    def prune_paths(
        self, paths: List[AlternativePath]
    ) -> List[AlternativePath]:
        """Remove paths below success threshold, deduplicate, return top-N."""
        filtered = [p for p in paths if p.expected_success >= self.min_success_threshold]

        # Deduplicate by step-id tuple
        seen: set = set()
        unique = []
        for p in filtered:
            key = tuple(s.id for s in p.steps)
            if key not in seen:
                seen.add(key)
                unique.append(p)

        # Sort by score
        unique.sort(key=self._score_path, reverse=True)
        return unique[: self.max_alternatives]

    def suggest_next_step(self, graph: DependencyGraph) -> Optional[AttackStep]:
        """Get the best next step considering current graph state."""
        ready = graph.get_ready_steps()
        if not ready:
            return None
        if self.strategy == BacktrackStrategy.BEST_FIRST:
            return max(
                ready,
                key=lambda s: s.success_probability / (1 + s.cost / max(s.cost, 1)),
            )
        if self.strategy == BacktrackStrategy.DEPTH_FIRST:
            # Prefer steps with most completed prerequisites (deepest in graph)
            return max(ready, key=lambda s: len(s.dependencies))
        # BREADTH_FIRST — prefer steps with fewest prerequisites
        return min(ready, key=lambda s: len(s.dependencies))

    def get_backtrack_rationale(
        self, failed_step: AttackStep, alternative: AlternativePath
    ) -> str:
        """Explain why the alternative path is suggested."""
        step_names = ", ".join(s.name for s in alternative.steps)
        return (
            f"Step '{failed_step.name}' failed. "
            f"Alternative path [{step_names}] offers "
            f"{alternative.expected_success:.0%} expected success "
            f"at {alternative.total_cost:.0f}s estimated cost, "
            f"bypassing the failed step."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _eligible_steps(
        self, graph: DependencyGraph, failed_step_id: str
    ) -> List[AttackStep]:
        """Return steps that do not transitively depend on the failed step."""
        tainted: set = {failed_step_id}
        changed = True
        while changed:
            changed = False
            for step in graph._steps.values():
                if step.id in tainted:
                    continue
                if any(d in tainted for d in step.dependencies):
                    tainted.add(step.id)
                    changed = True

        return [
            s
            for s in graph._steps.values()
            if s.id not in tainted
            and s.status not in (StepStatus.FAILED, StepStatus.BLOCKED)
        ]

    def _build_paths(
        self, eligible: List[AttackStep], graph: DependencyGraph
    ) -> List[List[AttackStep]]:
        """
        Build candidate paths from eligible steps using the selected strategy.
        Each path is an ordered list of steps that respects dependencies.
        """
        if not eligible:
            return []

        eligible_ids = {s.id for s in eligible}

        # Topological order restricted to eligible steps
        ordered = []
        visited: set = set()

        def visit(step: AttackStep) -> None:
            if step.id in visited:
                return
            visited.add(step.id)
            for dep_id in step.dependencies:
                dep = graph.get_step(dep_id)
                if dep and dep.id in eligible_ids:
                    visit(dep)
            ordered.append(step)

        for s in eligible:
            visit(s)

        if not ordered:
            return []

        # Return the single path as one alternative (full eligible sequence)
        # and also each individual pending step as a single-step alternative.
        paths: List[List[AttackStep]] = [ordered]
        for s in eligible:
            if s.status == StepStatus.PENDING and [s] != ordered:
                paths.append([s])

        # Truncate by max_depth
        return [p[: self.max_depth] for p in paths]
