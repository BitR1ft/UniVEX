"""
Attack Dependency Graph

Directed acyclic graph (DAG) of attack steps with dependency tracking,
topological ordering, and critical path analysis.
"""

from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from ..state.agent_state import Phase


def _utc_now_naive() -> datetime:
    """Return a naive UTC datetime (timezone info stripped for DB compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CyclicDependencyError(Exception):
    """Raised when adding a dependency would create a cycle in the DAG."""


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class AttackStep:
    name: str
    description: str
    tool_name: str
    tool_input: Dict = field(default_factory=dict)
    phase: Phase = Phase.INFORMATIONAL
    dependencies: List[str] = field(default_factory=list)
    cost: float = 30.0
    risk_score: float = 0.5
    success_probability: float = 0.7
    status: StepStatus = StepStatus.PENDING
    result: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "phase": self.phase.value,
            "dependencies": self.dependencies,
            "cost": self.cost,
            "risk_score": self.risk_score,
            "success_probability": self.success_probability,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackStep":
        step = cls(
            name=data["name"],
            description=data["description"],
            tool_name=data["tool_name"],
            tool_input=data.get("tool_input", {}),
            phase=Phase(data.get("phase", Phase.INFORMATIONAL.value)),
            dependencies=data.get("dependencies", []),
            cost=data.get("cost", 30.0),
            risk_score=data.get("risk_score", 0.5),
            success_probability=data.get("success_probability", 0.7),
            status=StepStatus(data.get("status", StepStatus.PENDING.value)),
            result=data.get("result"),
            error=data.get("error"),
        )
        step.id = data["id"]
        if data.get("started_at"):
            step.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("completed_at"):
            step.completed_at = datetime.fromisoformat(data["completed_at"])
        return step


class DependencyGraph:
    """
    Directed acyclic graph (DAG) tracking attack steps and their dependencies.
    """

    def __init__(self) -> None:
        self._steps: Dict[str, AttackStep] = {}
        # adjacency: step_id -> set of step_ids that depend ON it
        self._dependents: Dict[str, set] = {}
        # reverse: step_id -> set of step_ids it depends ON
        self._dependencies: Dict[str, set] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_step(self, step: AttackStep) -> None:
        if step.id in self._steps:
            return
        self._steps[step.id] = step
        self._dependents[step.id] = set()
        self._dependencies[step.id] = set(step.dependencies)
        # Wire existing edges from step.dependencies
        for dep_id in step.dependencies:
            if dep_id in self._dependents:
                self._dependents[dep_id].add(step.id)

    def add_dependency(self, step_id: str, depends_on: str) -> None:
        """Add an edge step_id -> depends_on (step_id depends on depends_on)."""
        if step_id not in self._steps or depends_on not in self._steps:
            raise KeyError(f"Step not found: {step_id!r} or {depends_on!r}")
        if self._would_create_cycle(step_id, depends_on):
            raise CyclicDependencyError(
                f"Adding dependency {step_id!r} -> {depends_on!r} would create a cycle"
            )
        self._dependencies[step_id].add(depends_on)
        self._dependents[depends_on].add(step_id)
        if depends_on not in self._steps[step_id].dependencies:
            self._steps[step_id].dependencies.append(depends_on)

    def remove_step(self, step_id: str) -> None:
        if step_id not in self._steps:
            return
        # Remove from all dependents/dependencies structures
        for dep_id in self._dependencies[step_id]:
            self._dependents[dep_id].discard(step_id)
        for dep_id in self._dependents[step_id]:
            self._dependencies[dep_id].discard(step_id)
            if step_id in self._steps.get(dep_id, AttackStep("", "", "")).dependencies:
                self._steps[dep_id].dependencies.remove(step_id)
        del self._steps[step_id]
        del self._dependents[step_id]
        del self._dependencies[step_id]

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_step(self, step_id: str) -> Optional[AttackStep]:
        return self._steps.get(step_id)

    def get_ready_steps(self) -> List[AttackStep]:
        """Steps whose every dependency is COMPLETED and that are still PENDING."""
        ready = []
        for step in self._steps.values():
            if step.status != StepStatus.PENDING:
                continue
            deps = self._dependencies[step.id]
            if all(
                self._steps[d].status == StepStatus.COMPLETED
                for d in deps
                if d in self._steps
            ):
                ready.append(step)
        return ready

    def get_blocked_steps(self) -> List[AttackStep]:
        """Steps that have at least one FAILED dependency."""
        blocked = []
        for step in self._steps.values():
            if step.status not in (StepStatus.PENDING, StepStatus.BLOCKED):
                continue
            deps = self._dependencies[step.id]
            if any(
                self._steps[d].status == StepStatus.FAILED
                for d in deps
                if d in self._steps
            ):
                blocked.append(step)
        return blocked

    def topological_sort(self) -> List[AttackStep]:
        """Kahn's algorithm — raises CyclicDependencyError if graph has a cycle."""
        in_degree: Dict[str, int] = {sid: 0 for sid in self._steps}
        for sid in self._steps:
            for dep in self._dependencies[sid]:
                if dep in in_degree:
                    in_degree[sid] += 1

        queue: deque = deque(sid for sid, deg in in_degree.items() if deg == 0)
        order: List[AttackStep] = []

        while queue:
            sid = queue.popleft()
            order.append(self._steps[sid])
            for dependent in self._dependents[sid]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(order) != len(self._steps):
            raise CyclicDependencyError("Graph contains a cycle; topological sort failed")
        return order

    def get_critical_path(self) -> List[AttackStep]:
        """Longest path by accumulated cost — dynamic programming on topological order."""
        if not self._steps:
            return []
        sorted_steps = self.topological_sort()
        # dp[sid] = (max_cost, predecessor_id)
        dp: Dict[str, float] = {s.id: s.cost for s in sorted_steps}
        pred: Dict[str, Optional[str]] = {s.id: None for s in sorted_steps}

        for step in sorted_steps:
            for dep_id in self._dependencies[step.id]:
                if dep_id in dp:
                    candidate = dp[dep_id] + step.cost
                    if candidate > dp[step.id]:
                        dp[step.id] = candidate
                        pred[step.id] = dep_id

        # Find end of critical path
        end_id = max(dp, key=lambda k: dp[k])
        path_ids: List[str] = []
        current: Optional[str] = end_id
        while current is not None:
            path_ids.append(current)
            current = pred[current]
        path_ids.reverse()
        return [self._steps[sid] for sid in path_ids if sid in self._steps]

    def get_execution_plan(self) -> List[List[AttackStep]]:
        """
        Return parallel batches — steps in the same batch have no inter-dependencies
        and can run concurrently.
        """
        if not self._steps:
            return []
        sorted_steps = self.topological_sort()
        # Assign level to each step (max level of any predecessor + 1)
        levels: Dict[str, int] = {}
        for step in sorted_steps:
            dep_levels = [levels[d] for d in self._dependencies[step.id] if d in levels]
            levels[step.id] = (max(dep_levels) + 1) if dep_levels else 0

        max_level = max(levels.values())
        batches: List[List[AttackStep]] = [[] for _ in range(max_level + 1)]
        for step in sorted_steps:
            batches[levels[step.id]].append(step)
        return [b for b in batches if b]

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def mark_step_running(self, step_id: str) -> None:
        step = self._get_or_raise(step_id)
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now(timezone.utc).replace(tzinfo=None)

    def mark_step_completed(self, step_id: str, result: str) -> None:
        step = self._get_or_raise(step_id)
        step.status = StepStatus.COMPLETED
        step.result = result
        step.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    def mark_step_failed(self, step_id: str, error: str) -> None:
        step = self._get_or_raise(step_id)
        step.status = StepStatus.FAILED
        step.error = error
        step.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        # Mark dependents as BLOCKED
        self._propagate_blocked(step_id)

    # ------------------------------------------------------------------
    # Serialization / visualization
    # ------------------------------------------------------------------

    def to_mermaid(self) -> str:
        lines = ["flowchart TD"]
        for step in self._steps.values():
            label = step.name.replace('"', "'")
            lines.append(f'    {step.id[:8]}["{label}"]')
        for step in self._steps.values():
            for dep_id in self._dependencies[step.id]:
                if dep_id in self._steps:
                    lines.append(f"    {dep_id[:8]} --> {step.id[:8]}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "steps": [s.to_dict() for s in self._steps.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DependencyGraph":
        graph = cls()
        for step_data in data.get("steps", []):
            step = AttackStep.from_dict(step_data)
            # Temporarily clear dependencies — add_step wires them
            graph._steps[step.id] = step
            graph._dependents[step.id] = set()
            graph._dependencies[step.id] = set(step.dependencies)
        # Wire dependents now that all steps are loaded
        for step in graph._steps.values():
            for dep_id in step.dependencies:
                if dep_id in graph._dependents:
                    graph._dependents[dep_id].add(step.id)
        return graph

    def summary(self) -> dict:
        counts = {s.value: 0 for s in StepStatus}
        for step in self._steps.values():
            counts[step.status.value] += 1
        cp = self.get_critical_path() if self._steps else []
        return {
            "total_steps": len(self._steps),
            "status_counts": counts,
            "critical_path_length": len(cp),
            "critical_path_cost": sum(s.cost for s in cp),
            "total_cost": sum(s.cost for s in self._steps.values()),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, step_id: str) -> AttackStep:
        step = self._steps.get(step_id)
        if step is None:
            raise KeyError(f"Step not found: {step_id!r}")
        return step

    def _would_create_cycle(self, step_id: str, new_dep: str) -> bool:
        """Return True if adding step_id -> new_dep would create a cycle.
        
        Adding step_id -> new_dep means step_id depends on new_dep.
        A cycle exists if new_dep already (transitively) depends on step_id.
        """
        visited: set = set()
        queue: deque = deque([new_dep])
        while queue:
            current = queue.popleft()
            if current == step_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            for dep in self._dependencies.get(current, set()):
                queue.append(dep)
        return False

    def _propagate_blocked(self, failed_id: str) -> None:
        """Recursively mark all transitive dependents as BLOCKED."""
        queue: deque = deque(self._dependents.get(failed_id, set()))
        visited: set = set()
        while queue:
            sid = queue.popleft()
            if sid in visited:
                continue
            visited.add(sid)
            step = self._steps.get(sid)
            if step and step.status == StepStatus.PENDING:
                step.status = StepStatus.BLOCKED
            queue.extend(self._dependents.get(sid, set()))
