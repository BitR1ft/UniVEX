"""
Attack Planner

Generates structured, multi-phase attack plans with tree-of-thought reasoning,
cost-benefit analysis, and Mermaid visualization.
Supports PostgreSQL persistence for cross-session plan resumption.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ..state.agent_state import Phase
from .dependency_graph import AttackStep, DependencyGraph


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PlanStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class AttackStrategy(str, Enum):
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    COMPLIANCE = "compliance"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CostBenefit:
    tool_name: str
    estimated_time_seconds: float
    risk_score: float
    success_probability: float
    value_score: float
    recommendation: str

    @property
    def roi(self) -> float:
        return (self.success_probability * self.value_score) / (self.risk_score + 0.01)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "estimated_time_seconds": self.estimated_time_seconds,
            "risk_score": self.risk_score,
            "success_probability": self.success_probability,
            "value_score": self.value_score,
            "recommendation": self.recommendation,
            "roi": self.roi,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CostBenefit":
        return cls(
            tool_name=data["tool_name"],
            estimated_time_seconds=data["estimated_time_seconds"],
            risk_score=data["risk_score"],
            success_probability=data["success_probability"],
            value_score=data["value_score"],
            recommendation=data["recommendation"],
        )


@dataclass
class PlanMetadata:
    plan_id: str
    target: str
    objective: str
    strategy: AttackStrategy
    created_at: datetime
    updated_at: datetime
    status: PlanStatus
    session_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "objective": self.objective,
            "strategy": self.strategy.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "status": self.status.value,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PlanMetadata":
        return cls(
            plan_id=data["plan_id"],
            target=data["target"],
            objective=data["objective"],
            strategy=AttackStrategy(data["strategy"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            status=PlanStatus(data["status"]),
            session_id=data.get("session_id"),
        )


@dataclass
class AttackPlan:
    metadata: PlanMetadata
    graph: DependencyGraph
    thought_tree: List[dict] = field(default_factory=list)
    cost_benefits: Dict[str, CostBenefit] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "graph": self.graph.to_dict(),
            "thought_tree": self.thought_tree,
            "cost_benefits": {k: v.to_dict() for k, v in self.cost_benefits.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackPlan":
        return cls(
            metadata=PlanMetadata.from_dict(data["metadata"]),
            graph=DependencyGraph.from_dict(data["graph"]),
            thought_tree=data.get("thought_tree", []),
            cost_benefits={
                k: CostBenefit.from_dict(v)
                for k, v in data.get("cost_benefits", {}).items()
            },
        )

    def to_mermaid(self) -> str:
        header = (
            f"%%{{init: {{'theme':'dark'}}}}%%\n"
            f"%% Plan: {self.metadata.plan_id}\n"
            f"%% Target: {self.metadata.target}\n"
            f"%% Strategy: {self.metadata.strategy.value}\n"
        )
        return header + self.graph.to_mermaid()

    def summary(self) -> dict:
        graph_summary = self.graph.summary()
        top_tools = sorted(
            self.cost_benefits.values(),
            key=lambda cb: cb.roi,
            reverse=True,
        )[:3]
        return {
            "plan_id": self.metadata.plan_id,
            "target": self.metadata.target,
            "objective": self.metadata.objective,
            "strategy": self.metadata.strategy.value,
            "status": self.metadata.status.value,
            "graph": graph_summary,
            "top_recommended_tools": [t.tool_name for t in top_tools],
        }


# ---------------------------------------------------------------------------
# Known tool profiles for cost-benefit analysis
# ---------------------------------------------------------------------------

_TOOL_PROFILES: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "time": 45,
        "risk": 0.2,
        "success": 0.9,
        "value": 0.9,
        "recommendation": "Essential for port/service enumeration",
    },
    "ffuf": {
        "time": 120,
        "risk": 0.3,
        "success": 0.7,
        "value": 0.8,
        "recommendation": "Effective for directory/endpoint discovery",
    },
    "sqlmap": {
        "time": 180,
        "risk": 0.7,
        "success": 0.6,
        "value": 0.9,
        "recommendation": "High-value but noisy — use with caution",
    },
    "hydra": {
        "time": 300,
        "risk": 0.8,
        "success": 0.5,
        "value": 0.8,
        "recommendation": "Brute-force — only when no other options remain",
    },
    "gobuster": {
        "time": 90,
        "risk": 0.25,
        "success": 0.75,
        "value": 0.7,
        "recommendation": "Good directory brute-forcer",
    },
    "nikto": {
        "time": 60,
        "risk": 0.3,
        "success": 0.65,
        "value": 0.7,
        "recommendation": "Web vulnerability scanner",
    },
    "metasploit": {
        "time": 120,
        "risk": 0.85,
        "success": 0.6,
        "value": 0.95,
        "recommendation": "Powerful exploitation framework — high risk",
    },
    "curl": {
        "time": 5,
        "risk": 0.05,
        "success": 0.95,
        "value": 0.5,
        "recommendation": "Low-risk HTTP inspection",
    },
    "ssh_bruteforce": {
        "time": 240,
        "risk": 0.75,
        "success": 0.4,
        "value": 0.85,
        "recommendation": "SSH credential attack — very noisy",
    },
    "wpscan": {
        "time": 90,
        "risk": 0.3,
        "success": 0.7,
        "value": 0.75,
        "recommendation": "WordPress-specific scanner",
    },
}

# Attack step templates for rule-based planning
_STEP_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "web_exploitation": [
        {
            "name": "Port Scan",
            "description": "Identify open ports and services",
            "tool_name": "nmap",
            "tool_input": {"flags": "-sV -sC"},
            "phase": Phase.INFORMATIONAL,
            "cost": 45,
            "risk_score": 0.2,
            "success_probability": 0.9,
        },
        {
            "name": "Directory Enumeration",
            "description": "Discover web endpoints",
            "tool_name": "ffuf",
            "tool_input": {"wordlist": "common.txt"},
            "phase": Phase.INFORMATIONAL,
            "cost": 120,
            "risk_score": 0.3,
            "success_probability": 0.7,
            "depends_on": ["Port Scan"],
        },
        {
            "name": "Web Vulnerability Scan",
            "description": "Scan for common web vulnerabilities",
            "tool_name": "nikto",
            "tool_input": {},
            "phase": Phase.INFORMATIONAL,
            "cost": 60,
            "risk_score": 0.3,
            "success_probability": 0.65,
            "depends_on": ["Port Scan"],
        },
        {
            "name": "SQL Injection Test",
            "description": "Test for SQL injection vulnerabilities",
            "tool_name": "sqlmap",
            "tool_input": {"level": 3},
            "phase": Phase.EXPLOITATION,
            "cost": 180,
            "risk_score": 0.7,
            "success_probability": 0.6,
            "depends_on": ["Directory Enumeration"],
        },
    ],
    "credential_attack": [
        {
            "name": "Port Scan",
            "description": "Identify open ports and services",
            "tool_name": "nmap",
            "tool_input": {"flags": "-sV"},
            "phase": Phase.INFORMATIONAL,
            "cost": 45,
            "risk_score": 0.2,
            "success_probability": 0.9,
        },
        {
            "name": "SSH Brute Force",
            "description": "Attempt SSH credential brute-force",
            "tool_name": "hydra",
            "tool_input": {"service": "ssh"},
            "phase": Phase.EXPLOITATION,
            "cost": 300,
            "risk_score": 0.8,
            "success_probability": 0.5,
            "depends_on": ["Port Scan"],
        },
    ],
    "service_exploitation": [
        {
            "name": "Service Scan",
            "description": "Deep service version detection",
            "tool_name": "nmap",
            "tool_input": {"flags": "-sV --script=vuln"},
            "phase": Phase.INFORMATIONAL,
            "cost": 60,
            "risk_score": 0.25,
            "success_probability": 0.85,
        },
        {
            "name": "Exploitation",
            "description": "Exploit identified service vulnerabilities",
            "tool_name": "metasploit",
            "tool_input": {},
            "phase": Phase.EXPLOITATION,
            "cost": 120,
            "risk_score": 0.85,
            "success_probability": 0.55,
            "depends_on": ["Service Scan"],
        },
    ],
    "wordpress_exploitation": [
        {
            "name": "Port Scan",
            "description": "Identify open ports and services",
            "tool_name": "nmap",
            "tool_input": {"flags": "-sV"},
            "phase": Phase.INFORMATIONAL,
            "cost": 45,
            "risk_score": 0.2,
            "success_probability": 0.9,
        },
        {
            "name": "WordPress Scan",
            "description": "Scan WordPress installation for vulnerabilities",
            "tool_name": "wpscan",
            "tool_input": {},
            "phase": Phase.INFORMATIONAL,
            "cost": 90,
            "risk_score": 0.3,
            "success_probability": 0.7,
            "depends_on": ["Port Scan"],
        },
    ],
}

_HIGH_RISK_TOOLS = {"hydra", "sqlmap", "metasploit", "ssh_bruteforce"}
_DESTRUCTIVE_TOOLS = {"metasploit", "hydra", "sqlmap"}


class AttackPlanner:
    """
    Generates structured, multi-phase attack plans using tree-of-thought reasoning.
    """

    def __init__(
        self,
        strategy: AttackStrategy = AttackStrategy.BALANCED,
        max_depth: int = 5,
        llm_client: Any = None,
    ) -> None:
        self.strategy = strategy
        self.max_depth = max_depth
        self.llm_client = llm_client  # optional; if None, uses rule-based planning

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_plan(
        self,
        target: str,
        objective: str,
        recon_data: dict,
        session_id: Optional[str] = None,
    ) -> AttackPlan:
        """
        Create an attack plan using tree-of-thought reasoning.

        Steps:
        1. generate_thought_branches()
        2. prune_branches()
        3. select_best_path()
        4. build_dependency_graph()
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        plan_id = str(uuid.uuid4())

        branches = self.generate_thought_branches(objective, recon_data)
        pruned = self.prune_branches(branches)
        best = self.select_best_path(pruned) if pruned else {}
        graph = self.build_dependency_graph(best) if best else DependencyGraph()

        # Collect cost-benefit for all tools in the graph
        cost_benefits: Dict[str, CostBenefit] = {}
        for step in graph._steps.values():
            if step.tool_name not in cost_benefits:
                cost_benefits[step.tool_name] = self.analyze_cost_benefit(
                    step.tool_name, {"strategy": self.strategy.value}
                )

        metadata = PlanMetadata(
            plan_id=plan_id,
            target=target,
            objective=objective,
            strategy=self.strategy,
            created_at=now,
            updated_at=now,
            status=PlanStatus.ACTIVE,
            session_id=session_id,
        )

        return AttackPlan(
            metadata=metadata,
            graph=graph,
            thought_tree=pruned,
            cost_benefits=cost_benefits,
        )

    def generate_thought_branches(
        self, objective: str, recon_data: dict
    ) -> List[dict]:
        """
        Rule-based: analyse recon_data to select relevant attack categories.
        Returns thought branches, each representing one attack approach.
        """
        branches: List[dict] = []
        obj_lower = objective.lower()

        open_ports: List[int] = recon_data.get("open_ports", [])
        services: List[str] = [s.lower() for s in recon_data.get("services", [])]
        technologies: List[str] = [t.lower() for t in recon_data.get("technologies", [])]

        web_ports = {80, 443, 8080, 8443, 8000, 3000}
        has_web = bool(set(open_ports) & web_ports) or any(
            s in ("http", "https") for s in services
        )
        has_ssh = 22 in open_ports or "ssh" in services
        has_wordpress = any("wordpress" in t or "wp" in t for t in technologies)
        any(
            s in ("mysql", "postgresql", "mssql", "oracle") for s in services
        )

        # Branch 1 — web exploitation (if web services detected)
        if has_web or "web" in obj_lower:
            branches.append(
                {
                    "branch_id": "web_exploitation",
                    "strategy": "web_exploitation",
                    "steps": _STEP_TEMPLATES["web_exploitation"],
                    "rationale": "Web services detected — enumerate and exploit web attack surface",
                    "estimated_success": 0.65,
                }
            )

        # Branch 2 — WordPress-specific
        if has_wordpress:
            branches.append(
                {
                    "branch_id": "wordpress_exploitation",
                    "strategy": "wordpress_exploitation",
                    "steps": _STEP_TEMPLATES["wordpress_exploitation"],
                    "rationale": "WordPress detected — targeted CMS scanning",
                    "estimated_success": 0.7,
                }
            )

        # Branch 3 — credential attack (SSH)
        if has_ssh or "credential" in obj_lower or "ssh" in obj_lower:
            branches.append(
                {
                    "branch_id": "credential_attack",
                    "strategy": "credential_attack",
                    "steps": _STEP_TEMPLATES["credential_attack"],
                    "rationale": "SSH service detected — attempt credential attack",
                    "estimated_success": 0.45,
                }
            )

        # Branch 4 — service exploitation (generic)
        if open_ports or services:
            branches.append(
                {
                    "branch_id": "service_exploitation",
                    "strategy": "service_exploitation",
                    "steps": _STEP_TEMPLATES["service_exploitation"],
                    "rationale": "Services detected — check for known vulnerabilities",
                    "estimated_success": 0.55,
                }
            )

        # Fallback
        if not branches:
            branches.append(
                {
                    "branch_id": "web_exploitation",
                    "strategy": "web_exploitation",
                    "steps": _STEP_TEMPLATES["web_exploitation"],
                    "rationale": "Default web exploitation approach",
                    "estimated_success": 0.5,
                }
            )

        return branches

    def prune_branches(self, branches: List[dict]) -> List[dict]:
        """
        Remove low-confidence branches, apply strategy filters, return top-3.
        """
        filtered = [b for b in branches if b.get("estimated_success", 0) > 0.2]

        if self.strategy == AttackStrategy.STEALTH:
            # Remove branches with high-risk tools
            result = []
            for branch in filtered:
                steps = branch.get("steps", [])
                if not any(s.get("tool_name") in _HIGH_RISK_TOOLS for s in steps):
                    result.append(branch)
            filtered = result if result else filtered[:1]

        elif self.strategy == AttackStrategy.COMPLIANCE:
            # Remove branches with destructive tools
            result = []
            for branch in filtered:
                steps = branch.get("steps", [])
                if not any(s.get("tool_name") in _DESTRUCTIVE_TOOLS for s in steps):
                    result.append(branch)
            filtered = result if result else []

        filtered.sort(key=lambda b: b.get("estimated_success", 0), reverse=True)
        return filtered[:3]

    def select_best_path(self, branches: List[dict]) -> dict:
        """Pick the branch with the highest estimated_success."""
        if not branches:
            return {}
        return max(branches, key=lambda b: b.get("estimated_success", 0))

    def build_dependency_graph(self, branch: dict) -> DependencyGraph:
        """Convert branch step templates to AttackStep objects and wire deps."""
        graph = DependencyGraph()
        name_to_id: Dict[str, str] = {}

        for step_template in branch.get("steps", []):
            step_template.get("depends_on", [])
            step = AttackStep(
                name=step_template["name"],
                description=step_template["description"],
                tool_name=step_template["tool_name"],
                tool_input=dict(step_template.get("tool_input", {})),
                phase=step_template.get("phase", Phase.INFORMATIONAL),
                cost=step_template.get("cost", 30.0),
                risk_score=step_template.get("risk_score", 0.5),
                success_probability=step_template.get("success_probability", 0.7),
            )
            graph.add_step(step)
            name_to_id[step.name] = step.id

        # Wire dependencies by name
        for step_template in branch.get("steps", []):
            step_id = name_to_id.get(step_template["name"])
            if step_id is None:
                continue
            for dep_name in step_template.get("depends_on", []):
                dep_id = name_to_id.get(dep_name)
                if dep_id:
                    graph.add_dependency(step_id, dep_id)

        return graph

    def analyze_cost_benefit(self, tool_name: str, context: dict) -> CostBenefit:
        """Return cost-benefit analysis for a given tool."""
        profile = _TOOL_PROFILES.get(
            tool_name,
            {
                "time": 60,
                "risk": 0.5,
                "success": 0.4,
                "value": 0.5,
                "recommendation": "Unknown tool — apply default estimates",
            },
        )
        return CostBenefit(
            tool_name=tool_name,
            estimated_time_seconds=profile["time"],
            risk_score=profile["risk"],
            success_probability=profile["success"],
            value_score=profile["value"],
            recommendation=profile["recommendation"],
        )

    def explain_plan(self, plan: AttackPlan) -> str:
        """Return a human-readable plan explanation."""
        lines = [
            f"=== Attack Plan: {plan.metadata.plan_id} ===",
            f"Target   : {plan.metadata.target}",
            f"Objective: {plan.metadata.objective}",
            f"Strategy : {plan.metadata.strategy.value.upper()} mode",
            f"Status   : {plan.metadata.status.value}",
            "",
            "Ordered Attack Steps:",
        ]
        try:
            steps = plan.graph.topological_sort()
        except Exception:
            steps = list(plan.graph._steps.values())

        for i, step in enumerate(steps, 1):
            cb = plan.cost_benefits.get(step.tool_name)
            roi_str = f"ROI={cb.roi:.2f}" if cb else ""
            lines.append(
                f"  {i}. [{step.phase.value}] {step.name} "
                f"(tool: {step.tool_name}, cost: {step.cost}s) {roi_str}"
            )
            lines.append(f"     {step.description}")

        return "\n".join(lines)

    def update_plan(self, plan: AttackPlan, user_feedback: str) -> AttackPlan:
        """Apply modifications based on textual feedback keywords."""
        feedback_lower = user_feedback.lower()
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if "pause" in feedback_lower:
            plan.metadata.status = PlanStatus.PAUSED
        elif "abandon" in feedback_lower or "cancel" in feedback_lower:
            plan.metadata.status = PlanStatus.ABANDONED
        elif "resume" in feedback_lower or "continue" in feedback_lower:
            plan.metadata.status = PlanStatus.ACTIVE
        elif "complete" in feedback_lower or "done" in feedback_lower:
            plan.metadata.status = PlanStatus.COMPLETED

        if "stealth" in feedback_lower:
            plan.metadata.strategy = AttackStrategy.STEALTH
        elif "aggressive" in feedback_lower:
            plan.metadata.strategy = AttackStrategy.AGGRESSIVE
        elif "compliance" in feedback_lower:
            plan.metadata.strategy = AttackStrategy.COMPLIANCE

        plan.metadata.updated_at = now
        return plan

    def serialize_plan(self, plan: AttackPlan) -> str:
        """Serialize to JSON string for PostgreSQL storage."""
        return json.dumps(plan.to_dict())

    def deserialize_plan(self, data: str) -> AttackPlan:
        """Restore from JSON string."""
        return AttackPlan.from_dict(json.loads(data))

    def resume_plan(self, plan: AttackPlan, graph: DependencyGraph) -> AttackPlan:
        """Update plan with current graph state (for cross-session resumption)."""
        plan.graph = graph
        plan.metadata.status = PlanStatus.ACTIVE
        plan.metadata.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        return plan
