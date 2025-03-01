"""
Orchestrator Agent — Multi-Agent Pipeline Coordinator

The OrchestratorAgent decomposes a penetration test target into discrete
work items, dispatches each item to the appropriate specialised sub-agent,
and merges all results into a final OrchestratorResult.

Pipeline:
  decompose_target() → [WorkItem, …]
      ↓  (asyncio.gather for parallel items)
  _dispatch_workitem() per WorkItem
      ↓
  _merge_results() → OrchestratorResult

Dangerous tool calls (exploit, scan, shell) are routed to the remote worker
node via WorkerClient; safe calls remain local.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.agent.agents import MultiAgentState
from app.agent.agents.adviser_agent import AdviserAgent
from app.agent.agents.coder_agent import CoderAgent
from app.agent.agents.enricher_agent import EnricherAgent
from app.agent.agents.exploit_agent import ExploitAgent
from app.agent.agents.generator_agent import GeneratorAgent
from app.agent.agents.installer_agent import InstallerAgent
from app.agent.agents.recon_agent import ReconAgent
from app.agent.agents.refiner_agent import RefinerAgent
from app.agent.agents.reflector_agent import ReflectorAgent
from app.agent.agents.report_agent import ReportAgent
from app.agent.agents.simple_json_agent import SimpleJSONAgent
from app.agent.agents.web_agent import WebAppAgent
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class WorkItem(dict):
    """
    A typed work item dispatched to a sub-agent.

    Keys:
        agent      — sub-agent name ("recon", "webapp", "exploit", "report")
        task       — natural language task description
        priority   — 1 (highest) to 5 (lowest)
        depends_on — list of agent names that must complete first
    """

    def __init__(
        self,
        agent: str,
        task: str,
        priority: int = 3,
        depends_on: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            agent=agent,
            task=task,
            priority=priority,
            depends_on=depends_on or [],
        )

    @property
    def agent(self) -> str:
        return self["agent"]

    @property
    def task(self) -> str:
        return self["task"]

    @property
    def priority(self) -> int:
        return self["priority"]

    @property
    def depends_on(self) -> List[str]:
        return self["depends_on"]


class OrchestratorResult(dict):
    """
    Aggregated result from a full orchestration run.

    Keys:
        target         — original target string
        workstreams    — list of WorkItem dicts executed
        agent_results  — per-agent raw result dicts
        final_report   — Markdown report produced by ReportAgent
        total_findings — total deduplicated finding count
        critical_count — number of critical findings
        high_count     — number of high findings
    """

    def __init__(
        self,
        target: str,
        workstreams: List[WorkItem],
        agent_results: Dict[str, Any],
        final_report: str,
        total_findings: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
    ) -> None:
        super().__init__(
            target=target,
            workstreams=workstreams,
            agent_results=agent_results,
            final_report=final_report,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
        )

    @property
    def target(self) -> str:
        return self["target"]

    @property
    def workstreams(self) -> List[WorkItem]:
        return self["workstreams"]

    @property
    def agent_results(self) -> Dict[str, Any]:
        return self["agent_results"]

    @property
    def final_report(self) -> str:
        return self["final_report"]

    @property
    def total_findings(self) -> int:
        return self["total_findings"]

    @property
    def critical_count(self) -> int:
        return self["critical_count"]

    @property
    def high_count(self) -> int:
        return self["high_count"]


# ---------------------------------------------------------------------------
# OrchestratorAgent
# ---------------------------------------------------------------------------


class OrchestratorAgent:
    """
    Top-level coordinator that decomposes targets and delegates to sub-agents.

    Execution model:
      1. ``decompose_target()`` produces an ordered list of WorkItems.
      2. WorkItems without dependencies are executed in parallel via
         ``asyncio.gather()``.
      3. Each dependent workitem waits for its prerequisites to complete.
      4. The ReportAgent always runs last, after all other agents.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
        job_dispatcher: Optional[Any] = None,
    ) -> None:
        self.registry = registry
        self.llm = llm
        self.config = config or {}

        self._job_dispatcher = job_dispatcher

        self._agents: Dict[str, Any] = {
            ReconAgent.AGENT_NAME: ReconAgent(registry, llm, config),
            WebAppAgent.AGENT_NAME: WebAppAgent(registry, llm, config),
            ExploitAgent.AGENT_NAME: ExploitAgent(registry, llm, config),
            ReportAgent.AGENT_NAME: ReportAgent(registry, llm, config),
            RefinerAgent.AGENT_NAME: RefinerAgent(registry, llm, config),
            GeneratorAgent.AGENT_NAME: GeneratorAgent(registry, llm, config),
            AdviserAgent.AGENT_NAME: AdviserAgent(registry, llm, config),
            ReflectorAgent.AGENT_NAME: ReflectorAgent(registry, llm, config),
            EnricherAgent.AGENT_NAME: EnricherAgent(registry, llm, config),
            CoderAgent.AGENT_NAME: CoderAgent(registry, llm, config),
            InstallerAgent.AGENT_NAME: InstallerAgent(registry, llm, config),
            SimpleJSONAgent.AGENT_NAME: SimpleJSONAgent(registry, llm, config),
        }

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def get_job_dispatcher(self) -> Optional[Any]:
        """Return the attached JobDispatcher (may be None if not configured)."""
        return self._job_dispatcher

    def set_job_dispatcher(self, dispatcher: Any) -> None:
        """Attach a JobDispatcher for routing tool calls to the worker node."""
        self._job_dispatcher = dispatcher
        logger.info("OrchestratorAgent: JobDispatcher attached (%s)", type(dispatcher).__name__)

    async def dispatch_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        phase: Optional[Phase] = None,
        server_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Route a tool call through the JobDispatcher if configured.

        Falls back to direct local execution if no dispatcher is set.
        """
        if self._job_dispatcher is not None:
            return await self._job_dispatcher.dispatch(
                tool_name=tool_name,
                params=params,
                phase=phase,
                server_name=server_name,
                timeout=timeout,
            )
        # Fallback: direct local execution
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": False,
                "error": f"Tool '{tool_name}' not found in registry",
            }
        try:
            raw = await tool.execute(**params)
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": True,
                "result": raw,
                "error": None,
            }
        except Exception as exc:
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": False,
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_registered_agent_names(self) -> List[str]:
        """Return the names of all registered sub-agents."""
        return list(self._agents.keys())

    def decompose_target(
        self,
        target: str,
        scope: Optional[List[str]] = None,
    ) -> List[WorkItem]:
        """
        Break a target engagement into an ordered list of WorkItems.

        Recon always runs first (priority 1, no dependencies).
        WebApp and Exploit run in parallel after recon (priority 2).
        Report always runs last (priority 3, depends on all others).

        Args:
            target: IP, hostname, or URL to test.
            scope:  Optional list of in-scope paths / hostnames.

        Returns:
            Ordered list of WorkItem dicts.
        """
        scope_note = f" (scope: {', '.join(scope)})" if scope else ""
        base_task = f"Assess {target}{scope_note}"

        workitems: List[WorkItem] = [
            WorkItem(
                agent=ReconAgent.AGENT_NAME,
                task=f"Perform reconnaissance on {target}{scope_note}",
                priority=1,
                depends_on=[],
            ),
            WorkItem(
                agent=WebAppAgent.AGENT_NAME,
                task=f"Test web application vulnerabilities on {target}{scope_note}",
                priority=2,
                depends_on=[ReconAgent.AGENT_NAME],
            ),
            WorkItem(
                agent=ExploitAgent.AGENT_NAME,
                task=f"Exploit identified vulnerabilities on {target}{scope_note}",
                priority=2,
                depends_on=[ReconAgent.AGENT_NAME],
            ),
            WorkItem(
                agent=ReportAgent.AGENT_NAME,
                task=f"Generate penetration test report for {base_task}",
                priority=3,
                depends_on=[
                    ReconAgent.AGENT_NAME,
                    WebAppAgent.AGENT_NAME,
                    ExploitAgent.AGENT_NAME,
                ],
            ),
        ]

        return sorted(workitems, key=lambda w: w.priority)

    async def run(
        self,
        target: str,
        scope: Optional[List[str]] = None,
    ) -> OrchestratorResult:
        """
        Execute the full multi-agent pipeline against *target*.

        Args:
            target: IP, hostname, or URL.
            scope:  Optional list of in-scope URIs / subnets.

        Returns:
            OrchestratorResult with all findings and the final report.
        """
        logger.info("OrchestratorAgent starting pipeline for target: %s", target)

        workitems = self.decompose_target(target, scope)

        state: MultiAgentState = self._build_initial_state(target)
        state["workstreams"] = [dict(w) for w in workitems]

        agent_results: Dict[str, Any] = {}

        # --- Phase 1: priority-1 workitems (no dependencies) --------------
        phase1 = [w for w in workitems if not w.depends_on]
        await self._run_parallel(phase1, state, agent_results)

        # --- Phase 2: priority-2 workitems (depend on phase 1) ------------
        phase2 = [
            w for w in workitems
            if w.depends_on and all(d in agent_results for d in w.depends_on)
        ]
        await self._run_parallel(phase2, state, agent_results)

        # --- Phase 3: remaining workitems (report, depends on all) --------
        phase3 = [w for w in workitems if w.agent not in agent_results]
        for workitem in phase3:
            state["agent_results"] = agent_results
            result = await self._dispatch_workitem(workitem, state)
            agent_results[workitem.agent] = result

        state["agent_results"] = agent_results

        return self._merge_results(target, workitems, agent_results)

    async def _dispatch_workitem(
        self,
        workitem: WorkItem,
        state: MultiAgentState,
    ) -> Dict[str, Any]:
        """
        Route a WorkItem to the correct sub-agent and return its result.

        Args:
            workitem: WorkItem describing the task.
            state:    Current shared state.

        Returns:
            Raw result dict from the sub-agent.
        """
        agent_name = workitem.agent
        agent = self._agents.get(agent_name)

        if agent is None:
            logger.warning("No agent registered for '%s'", agent_name)
            return {"agent": agent_name, "error": f"No agent for '{agent_name}'"}

        logger.info(
            "Dispatching workitem to %s: %s", agent_name, workitem.task[:80]
        )

        try:
            return await agent.run(state, workitem.task)
        except Exception as exc:
            logger.error("Agent '%s' raised an exception: %s", agent_name, exc)
            return {
                "agent": agent_name,
                "error": str(exc),
                "findings": [],
            }

    def _merge_results(
        self,
        target: str,
        workstreams: List[WorkItem],
        agent_results: Dict[str, Any],
    ) -> OrchestratorResult:
        """
        Aggregate per-agent results into a single OrchestratorResult.

        Args:
            target:       Original target string.
            workstreams:  All WorkItems executed.
            agent_results: Raw results keyed by agent name.

        Returns:
            OrchestratorResult.
        """
        final_report = (
            agent_results.get(ReportAgent.AGENT_NAME, {}).get("report", "")
        )
        report_summary = (
            agent_results.get(ReportAgent.AGENT_NAME, {}).get("summary", {})
        )

        total_findings = report_summary.get("total_findings", 0)
        critical_count = report_summary.get("critical", 0)
        high_count = report_summary.get("high", 0)

        # Fallback: count directly from all non-report agent findings
        if total_findings == 0:
            for agent_name, result in agent_results.items():
                if agent_name == ReportAgent.AGENT_NAME:
                    continue
                if isinstance(result, dict):
                    total_findings += len(result.get("findings", []))

        return OrchestratorResult(
            target=target,
            workstreams=workstreams,
            agent_results=agent_results,
            final_report=final_report,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _run_parallel(
        self,
        workitems: List[WorkItem],
        state: MultiAgentState,
        agent_results: Dict[str, Any],
    ) -> None:
        """Execute *workitems* in parallel and update *agent_results*."""
        if not workitems:
            return

        tasks = [self._dispatch_workitem(w, state) for w in workitems]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for workitem, result in zip(workitems, results):
            if isinstance(result, Exception):
                logger.error(
                    "Parallel workitem '%s' failed: %s", workitem.agent, result
                )
                agent_results[workitem.agent] = {
                    "agent": workitem.agent,
                    "error": str(result),
                    "findings": [],
                }
            else:
                agent_results[workitem.agent] = result

    @staticmethod
    def _build_initial_state(target: str) -> MultiAgentState:
        """Construct a minimal MultiAgentState for the pipeline."""
        return {
            # AgentState required fields
            "messages": [],
            "current_phase": Phase.INFORMATIONAL,
            "tool_outputs": {},
            "project_id": None,
            "thread_id": "orchestrator",
            "next_action": "think",
            "selected_tool": None,
            "tool_input": None,
            "observation": None,
            "should_stop": False,
            "pending_approval": None,
            "guidance": None,
            "progress": None,
            "checkpoint": None,
            # MultiAgentState extensions
            "active_agents": [],
            "agent_results": {},
            "orchestrator_plan": None,
            "target_info": {"target": target},
            "workstreams": None,
        }

    # ------------------------------------------------------------------
    # Convenience helpers for new specialist agents
    # ------------------------------------------------------------------

    async def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of findings using the EnricherAgent.

        Args:
            findings: Raw finding dicts to enrich.

        Returns:
            List of enriched finding dicts.
        """
        enricher: EnricherAgent = self._agents[EnricherAgent.AGENT_NAME]
        state: MultiAgentState = self._build_initial_state("enrichment")
        state["agent_results"] = {"source": {"findings": findings}}
        result = await enricher.run(state, "Enrich all findings")
        return result.get("enriched_findings", findings)

    async def reflect_on_session(
        self,
        state: MultiAgentState,
    ) -> Dict[str, Any]:
        """
        Run the ReflectorAgent against the current session state.

        Args:
            state: Shared multi-agent state with completed agent results.

        Returns:
            Reflection dict from the ReflectorAgent.
        """
        reflector: ReflectorAgent = self._agents[ReflectorAgent.AGENT_NAME]
        return await reflector.run(state, "Reflect on all completed steps")

    async def generate_payload(
        self,
        payload_type: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a payload using the GeneratorAgent.

        Args:
            payload_type: Type of payload (e.g. "xss", "sqli").
            context:      Target context for payload generation.

        Returns:
            Result dict from the GeneratorAgent.
        """
        generator: GeneratorAgent = self._agents[GeneratorAgent.AGENT_NAME]
        state: MultiAgentState = self._build_initial_state(
            context.get("target", "payload_gen")
        )
        state["target_info"] = context
        return await generator.run(state, f"Generate {payload_type} payload")


__all__ = ["WorkItem", "OrchestratorResult", "OrchestratorAgent"]
