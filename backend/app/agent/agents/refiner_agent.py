"""
Refiner Agent — Iterative Output Quality Refinement

Takes raw agent output and iteratively refines it (grammar, structure,
completeness) until a quality threshold is met.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class RefinerAgent(BaseAgent):
    """
    Sub-agent that refines raw agent output to meet a quality threshold.

    Iterates up to ``max_iterations`` times, scoring and improving the text
    on each pass.  Stops early when the quality score meets or exceeds
    ``quality_threshold``.
    """

    AGENT_NAME = "refiner"
    PREFERRED_TOOLS: List[str] = ["web_search", "query_graph"]

    quality_threshold: float = 0.8
    max_iterations: int = 3

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(registry, llm, config)

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def get_phase(self) -> Phase:
        return Phase.COMPLETE

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Refiner Agent, an expert in output quality "
            "improvement for penetration test reports and findings.\n\n"
            "Your responsibilities:\n"
            "  1. Evaluate completeness, structure, and grammar of text.\n"
            "  2. Iteratively refine output until quality standards are met.\n"
            "  3. Ensure findings are actionable and clearly communicated.\n"
            "  4. Verify technical accuracy using available search tools.\n"
            "  5. Maintain the original meaning while improving presentation.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return structured output with quality scores and refined content."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Refine the provided output or state agent results.

        Args:
            state: Shared multi-agent state.
            task:  Text to refine or description of what to refine.

        Returns:
            ``{"agent": "refiner", "refined_output": str, "quality_score": float,
               "iterations": int, "issues": list}``
        """
        agent_results = state.get("agent_results") or {}

        # Use task as the text to refine; fall back to stringified results
        text_to_refine = task
        if not text_to_refine and agent_results:
            text_to_refine = str(agent_results)

        logger.info("RefinerAgent starting refinement, length=%d", len(text_to_refine))

        refined, score, iterations, issues = await self._iterative_refine(text_to_refine)

        return {
            "agent": self.AGENT_NAME,
            "refined_output": refined,
            "quality_score": score,
            "iterations": iterations,
            "issues": issues,
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def _iterative_refine(
        self, text: str
    ) -> tuple[str, float, int, List[str]]:
        """Iterate refinement until threshold met or max_iterations reached."""
        current = text
        iterations = 0
        issues: List[str] = []

        for i in range(self.max_iterations):
            score = self._score_quality(current)
            logger.debug("Iteration %d quality score: %.2f", i, score)

            if score >= self.quality_threshold:
                break

            issues = self._identify_issues(current)
            current = self._refine_once(current, issues)
            iterations = i + 1

        final_score = self._score_quality(current)
        return current, final_score, iterations, issues

    def _score_quality(self, text: str) -> float:
        """
        Score text quality from 0.0 to 1.0 based on length, structure,
        and completeness heuristics.

        Args:
            text: Text to evaluate.

        Returns:
            Float in [0.0, 1.0].
        """
        if not text or not text.strip():
            return 0.0

        score = 0.0

        # Length component (up to 0.3): penalise very short responses
        length = len(text.strip())
        if length >= 500:
            score += 0.3
        elif length >= 200:
            score += 0.2
        elif length >= 50:
            score += 0.1

        # Structure component (up to 0.4): check for headings, lists, code
        has_heading = bool(re.search(r"^#{1,4}\s", text, re.MULTILINE))
        has_list = bool(re.search(r"^[\-\*]\s", text, re.MULTILINE))
        has_code = "```" in text or "`" in text
        has_numbered = bool(re.search(r"^\d+\.\s", text, re.MULTILINE))

        structure_hits = sum([has_heading, has_list, has_code, has_numbered])
        score += min(0.4, structure_hits * 0.1)

        # Completeness component (up to 0.3): key pentest terms present
        completeness_terms = [
            "finding", "vulnerability", "severity", "recommendation",
            "risk", "impact", "remediation", "CVE", "exploit", "target",
        ]
        found = sum(1 for t in completeness_terms if t.lower() in text.lower())
        score += min(0.3, found * 0.03)

        return min(1.0, score)

    def _identify_issues(self, text: str) -> List[str]:
        """Return a list of identified quality issues in the text."""
        issues: List[str] = []
        if len(text.strip()) < 200:
            issues.append("Output is too short; add more detail.")
        if not re.search(r"^#{1,4}\s", text, re.MULTILINE):
            issues.append("Missing section headings; add structured headers.")
        if not re.search(r"^[\-\*]\s|\d+\.\s", text, re.MULTILINE):
            issues.append("No lists found; organise information with bullet points.")
        if "recommendation" not in text.lower() and "remediation" not in text.lower():
            issues.append("Missing recommendations or remediation guidance.")
        return issues

    def _refine_once(self, text: str, issues: List[str]) -> str:
        """
        Apply one refinement pass to address identified issues.

        Args:
            text:   Current text to refine.
            issues: List of issues to address.

        Returns:
            Refined text string.
        """
        refined = text

        # Add a header if missing
        if "Missing section headings" in str(issues):
            if not refined.startswith("#"):
                refined = "## Penetration Test Findings\n\n" + refined

        # Add recommendations section if missing
        if "Missing recommendations" in str(issues):
            if "recommendation" not in refined.lower():
                refined += (
                    "\n\n## Recommendations\n\n"
                    "- Review and address all identified findings.\n"
                    "- Apply patches and configuration hardening.\n"
                    "- Re-test after remediation is complete.\n"
                )

        return refined


__all__ = ["RefinerAgent"]
