"""
Agent Configuration System.

Provides:
  - AgentConfig: per-agent runtime configuration dataclass
  - PhaseConfig: per-phase tool/behaviour settings
  - AgentConfigManager: loads, validates, and merges configurations
  - DEFAULT_CONFIG: sensible out-of-the-box configuration for all phases
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from app.agent.state.agent_state import Phase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase-specific configuration
# ---------------------------------------------------------------------------


@dataclass
class PhaseConfig:
    """
    Configuration for a single agent operational phase.

    Attributes:
        phase: The Phase enum value this config applies to.
        allowed_tools: Tool names available in this phase.  An empty list
            means *all* registered tools are permitted.
        max_iterations: Maximum ReAct iterations before forcing an end.
        require_approval_for: Tool names that require human approval.
        auto_advance: Whether the agent may advance to the next phase
            automatically without human confirmation.
        temperature: LLM temperature override for this phase.
        max_tokens: LLM max_tokens override for this phase.
    """

    phase: Phase
    allowed_tools: List[str] = field(default_factory=list)
    max_iterations: int = 20
    require_approval_for: List[str] = field(default_factory=list)
    auto_advance: bool = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PhaseConfig":
        data = dict(data)
        data["phase"] = Phase(data["phase"])
        return cls(**data)


# ---------------------------------------------------------------------------
# Top-level agent configuration
# ---------------------------------------------------------------------------


@dataclass
class AgentConfig:
    """
    Complete configuration for the AI agent.

    Attributes:
        model_provider: LLM provider ('openai' or 'anthropic').
        model_name: LLM model identifier.
        enable_memory: Whether LangGraph MemorySaver is enabled.
        default_temperature: Default LLM temperature (can be overridden per phase).
        default_max_tokens: Default LLM max_tokens.
        global_max_iterations: Hard cap on iterations across all phases.
        phases: Per-phase PhaseConfig instances, keyed by Phase value.
        metadata: Arbitrary key/value metadata (version, description, etc.).
    """

    model_provider: str = "openai"
    model_name: str = "gpt-4o"
    enable_memory: bool = True
    default_temperature: float = 0.7
    default_max_tokens: int = 2000
    global_max_iterations: int = 50
    phases: Dict[str, PhaseConfig] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── Accessor helpers ────────────────────────────────────────────────────

    def get_phase_config(self, phase: Phase) -> PhaseConfig:
        """
        Return the PhaseConfig for *phase*, falling back to a safe default.

        Args:
            phase: Agent operational phase

        Returns:
            PhaseConfig for the requested phase
        """
        cfg = self.phases.get(phase.value)
        if cfg is None:
            logger.warning(
                f"No phase config found for '{phase.value}', using defaults."
            )
            cfg = PhaseConfig(phase=phase)
        return cfg

    def get_temperature(self, phase: Phase) -> float:
        """Return the effective temperature for a phase."""
        pc = self.get_phase_config(phase)
        return pc.temperature if pc.temperature is not None else self.default_temperature

    def get_max_tokens(self, phase: Phase) -> int:
        """Return the effective max_tokens for a phase."""
        pc = self.get_phase_config(phase)
        return pc.max_tokens if pc.max_tokens is not None else self.default_max_tokens

    def get_max_iterations(self, phase: Phase) -> int:
        """Return the effective max iterations for a phase."""
        return self.get_phase_config(phase).max_iterations

    def is_tool_allowed(self, tool_name: str, phase: Phase) -> bool:
        """
        Check whether *tool_name* is allowed in *phase* according to the config.

        If allowed_tools is empty, ALL tools are permitted.
        """
        pc = self.get_phase_config(phase)
        if not pc.allowed_tools:
            return True
        return tool_name in pc.allowed_tools

    def requires_approval(self, tool_name: str, phase: Phase) -> bool:
        """Return True if *tool_name* requires human approval in *phase*."""
        return tool_name in self.get_phase_config(phase).require_approval_for

    # ── Serialization ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "enable_memory": self.enable_memory,
            "default_temperature": self.default_temperature,
            "default_max_tokens": self.default_max_tokens,
            "global_max_iterations": self.global_max_iterations,
            "phases": {k: v.to_dict() for k, v in self.phases.items()},
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentConfig":
        data = dict(data)
        raw_phases = data.pop("phases", {})
        cfg = cls(**data)
        cfg.phases = {
            k: PhaseConfig.from_dict(v) for k, v in raw_phases.items()
        }
        return cfg

    @classmethod
    def from_json(cls, json_str: str) -> "AgentConfig":
        return cls.from_dict(json.loads(json_str))


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

#: Out-of-the-box configuration used when no custom config is provided.
DEFAULT_CONFIG = AgentConfig(
    model_provider="openai",
    model_name="gpt-4o",
    enable_memory=True,
    default_temperature=0.7,
    default_max_tokens=2000,
    global_max_iterations=50,
    phases={
        Phase.INFORMATIONAL.value: PhaseConfig(
            phase=Phase.INFORMATIONAL,
            allowed_tools=[
                "echo",
                "calculator",
                "query_graph",
                "web_search",
                "naabu",
                "curl",
                "nuclei",
            ],
            max_iterations=25,
            require_approval_for=[],
            auto_advance=False,
        ),
        Phase.EXPLOITATION.value: PhaseConfig(
            phase=Phase.EXPLOITATION,
            allowed_tools=[
                "query_graph",
                "web_search",
                "curl",
                "nuclei",
                "metasploit_search",
                "exploit_execute",
                "brute_force",
                "session_manager",
                "system_enumeration",
            ],
            max_iterations=30,
            require_approval_for=["exploit_execute", "brute_force", "metasploit_search"],
            auto_advance=False,
            temperature=0.5,
        ),
        Phase.POST_EXPLOITATION.value: PhaseConfig(
            phase=Phase.POST_EXPLOITATION,
            allowed_tools=[
                "query_graph",
                "session_manager",
                "file_operations",
                "system_enumeration",
                "privilege_escalation",
            ],
            max_iterations=20,
            require_approval_for=["privilege_escalation", "file_operations"],
            auto_advance=False,
            temperature=0.5,
        ),
        Phase.COMPLETE.value: PhaseConfig(
            phase=Phase.COMPLETE,
            allowed_tools=["query_graph"],
            max_iterations=5,
            require_approval_for=[],
            auto_advance=False,
        ),
    },
    metadata={
        "version": "1.0",
        "description": "Default UniVex agent configuration",
    },
)


# ---------------------------------------------------------------------------
# Configuration manager
# ---------------------------------------------------------------------------


class AgentConfigManager:
    """
    Manages agent configurations: loading, validation, merging, and
    per-session overrides.

    Usage::

        manager = AgentConfigManager()
        config = manager.get_config()            # default
        config = manager.load_from_dict({...})   # custom
        manager.update_phase(Phase.EXPLOITATION, temperature=0.3)
    """

    def __init__(self, base_config: Optional[AgentConfig] = None):
        self._config: AgentConfig = base_config or AgentConfig(
            **{
                k: v
                for k, v in DEFAULT_CONFIG.__dict__.items()
                if k != "phases"
            }
        )
        # Deep-copy phase configs so mutations don't affect DEFAULT_CONFIG
        self._config.phases = {
            k: PhaseConfig.from_dict(v.to_dict())
            for k, v in DEFAULT_CONFIG.phases.items()
        }

    # ── Loading ─────────────────────────────────────────────────────────────

    def load_from_dict(self, data: Dict[str, Any]) -> AgentConfig:
        """
        Replace current config with one built from *data*.

        Validation is performed before applying the new config.

        Args:
            data: Configuration dictionary (matches AgentConfig.to_dict() schema)

        Returns:
            The validated AgentConfig instance

        Raises:
            ValueError: if the config data is invalid
        """
        try:
            cfg = AgentConfig.from_dict(data)
        except (TypeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid configuration: {e}") from e

        self._validate(cfg)
        self._config = cfg
        logger.info(
            f"Loaded agent config: provider={cfg.model_provider}, "
            f"model={cfg.model_name}, phases={list(cfg.phases.keys())}"
        )
        return self._config

    def load_from_json(self, json_str: str) -> AgentConfig:
        """Load configuration from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e
        return self.load_from_dict(data)

    # ── Getters ─────────────────────────────────────────────────────────────

    def get_config(self) -> AgentConfig:
        """Return the current AgentConfig."""
        return self._config

    def get_phase_config(self, phase: Phase) -> PhaseConfig:
        """Convenience: return PhaseConfig for *phase*."""
        return self._config.get_phase_config(phase)

    # ── Updates ─────────────────────────────────────────────────────────────

    def update_phase(self, phase: Phase, **kwargs: Any) -> PhaseConfig:
        """
        Update individual fields on the PhaseConfig for *phase*.

        Args:
            phase: Phase to update
            **kwargs: Any PhaseConfig field names and new values

        Returns:
            Updated PhaseConfig
        """
        pc = self._config.get_phase_config(phase)
        for key, value in kwargs.items():
            if not hasattr(pc, key):
                raise ValueError(
                    f"PhaseConfig has no field '{key}'. "
                    f"Valid fields: {list(pc.__dataclass_fields__.keys())}"
                )
            setattr(pc, key, value)
        self._config.phases[phase.value] = pc
        return pc

    def set_model(self, provider: str, model_name: str) -> None:
        """Change the LLM provider and model."""
        allowed_providers = {"openai", "anthropic", "google", "groq", "openrouter"}
        if provider not in allowed_providers:
            raise ValueError(
                f"Unknown provider '{provider}'. Allowed: {allowed_providers}"
            )
        self._config.model_provider = provider
        self._config.model_name = model_name
        logger.info(f"Model updated to {provider}/{model_name}")

    def add_approved_tool(self, tool_name: str, phase: Phase) -> None:
        """Allow *tool_name* in *phase* without requiring approval."""
        pc = self._config.get_phase_config(phase)
        if tool_name not in pc.allowed_tools:
            pc.allowed_tools.append(tool_name)
        if tool_name in pc.require_approval_for:
            pc.require_approval_for.remove(tool_name)
        self._config.phases[phase.value] = pc

    # ── Validation ──────────────────────────────────────────────────────────

    @staticmethod
    def _validate(cfg: AgentConfig) -> None:
        """
        Validate a configuration, raising ValueError on problems.

        Args:
            cfg: AgentConfig to validate

        Raises:
            ValueError: describing the first problem found
        """
        allowed_providers = {"openai", "anthropic", "google", "groq", "openrouter"}
        if cfg.model_provider not in allowed_providers:
            raise ValueError(
                f"model_provider must be one of {allowed_providers}, "
                f"got '{cfg.model_provider}'"
            )
        if not cfg.model_name:
            raise ValueError("model_name must not be empty")
        if not (0.0 <= cfg.default_temperature <= 2.0):
            raise ValueError(
                f"default_temperature must be in [0.0, 2.0], "
                f"got {cfg.default_temperature}"
            )
        if cfg.default_max_tokens < 1:
            raise ValueError(
                f"default_max_tokens must be >= 1, got {cfg.default_max_tokens}"
            )
        if cfg.global_max_iterations < 1:
            raise ValueError(
                f"global_max_iterations must be >= 1, "
                f"got {cfg.global_max_iterations}"
            )
        for phase_key, pc in cfg.phases.items():
            if pc.max_iterations < 1:
                raise ValueError(
                    f"max_iterations for phase '{phase_key}' must be >= 1"
                )
            if pc.temperature is not None and not (0.0 <= pc.temperature <= 2.0):
                raise ValueError(
                    f"temperature for phase '{phase_key}' must be in [0.0, 2.0]"
                )

    def validate(self) -> bool:
        """
        Validate the current configuration.

        Returns:
            True if valid

        Raises:
            ValueError: if invalid
        """
        self._validate(self._config)
        return True


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_default_manager: Optional[AgentConfigManager] = None


def get_default_config_manager() -> AgentConfigManager:
    """Return (or create) the module-level AgentConfigManager singleton."""
    global _default_manager
    if _default_manager is None:
        _default_manager = AgentConfigManager()
    return _default_manager
