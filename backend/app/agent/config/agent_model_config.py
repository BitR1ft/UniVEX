"""
AgentModelConfig — Per-Agent Model Configuration System

Enables fine-grained LLM model selection per agent role via:
  1. Environment variables  (e.g. ``PLANNER_MODEL=gpt-4o``)
  2. YAML configuration file  (``agents.yaml``)
  3. Programmatic override via ``AgentModelConfigManager``

Priority order: environment variable > YAML file > built-in default.

Supported configuration keys per agent role::

    model          – LLM model identifier (e.g. "gpt-4o", "claude-3-5-sonnet")
    temperature    – Sampling temperature (0.0 – 2.0)
    max_tokens     – Maximum tokens in response
    system_prompt  – Custom system prompt override (optional)
    provider       – LLM provider name (openai | anthropic | groq | openrouter | …)

Environment variable naming convention::

    {AGENT_ROLE_UPPER}_MODEL         e.g. PLANNER_MODEL, RECON_MODEL
    {AGENT_ROLE_UPPER}_TEMPERATURE   e.g. EXPLOIT_TEMPERATURE
    {AGENT_ROLE_UPPER}_MAX_TOKENS    e.g. REPORT_MAX_TOKENS
    {AGENT_ROLE_UPPER}_PROVIDER      e.g. RECON_PROVIDER
    {AGENT_ROLE_UPPER}_SYSTEM_PROMPT e.g. PLANNER_SYSTEM_PROMPT

Global overrides::

    AGENT_MAX_TOKENS        – Default max_tokens for all agents
    AGENT_SUMMARY_THRESHOLD – Token % at which context summarisation is triggered
    PROXY_URL               – SOCKS5/HTTP proxy for all LLM API calls
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Built-in default model for each agent role
_DEFAULT_MODELS: Dict[str, str] = {
    "planner": "gpt-4o",
    "recon": "gpt-4o-mini",
    "exploit": "claude-3-5-sonnet-20241022",
    "webapp": "gpt-4o",
    "report": "gpt-4o-mini",
    "refiner": "gpt-4o",
    "generator": "gpt-4o",
    "adviser": "claude-3-5-sonnet-20241022",
    "reflector": "gpt-4o",
    "enricher": "gpt-4o-mini",
    "coder": "claude-3-5-sonnet-20241022",
    "installer": "gpt-4o-mini",
    "simple_json": "gpt-4o-mini",
}

_DEFAULT_TEMPERATURES: Dict[str, float] = {
    "planner": 0.2,
    "recon": 0.1,
    "exploit": 0.1,
    "webapp": 0.1,
    "report": 0.3,
    "refiner": 0.2,
    "generator": 0.7,
    "adviser": 0.3,
    "reflector": 0.4,
    "enricher": 0.0,
    "coder": 0.1,
    "installer": 0.2,
    "simple_json": 0.0,
}

_DEFAULT_MAX_TOKENS: int = 4096

# Default token percentage threshold for context summarisation (75%)
_DEFAULT_SUMMARY_THRESHOLD: float = 0.75

# Roles that all UniVex agents can have
ALL_AGENT_ROLES: List[str] = list(_DEFAULT_MODELS.keys())


# ---------------------------------------------------------------------------
# AgentModelConfig — single agent's model configuration
# ---------------------------------------------------------------------------


@dataclass
class AgentModelConfig:
    """
    Complete model configuration for a single agent role.

    Attributes:
        agent_role      – Identifier matching BaseAgent.AGENT_NAME.
        model           – LLM model identifier.
        provider        – LLM provider (openai, anthropic, groq, …).
        temperature     – Sampling temperature.
        max_tokens      – Maximum response tokens.
        system_prompt   – Optional system prompt override.
        extra           – Additional provider-specific kwargs.
    """

    agent_role: str
    model: str
    provider: str = "openai"
    temperature: float = 0.2
    max_tokens: int = _DEFAULT_MAX_TOKENS
    system_prompt: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_role": self.agent_role,
            "model": self.model,
            "provider": self.provider,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "system_prompt": self.system_prompt,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentModelConfig":
        return cls(
            agent_role=data["agent_role"],
            model=data.get("model", "gpt-4o"),
            provider=data.get("provider", "openai"),
            temperature=float(data.get("temperature", 0.2)),
            max_tokens=int(data.get("max_tokens", _DEFAULT_MAX_TOKENS)),
            system_prompt=data.get("system_prompt"),
            extra=data.get("extra", {}),
        )

    @classmethod
    def default_for(cls, agent_role: str) -> "AgentModelConfig":
        """Build a default config for the given agent role using built-in defaults."""
        return cls(
            agent_role=agent_role,
            model=_DEFAULT_MODELS.get(agent_role, "gpt-4o"),
            provider="openai",
            temperature=_DEFAULT_TEMPERATURES.get(agent_role, 0.2),
            max_tokens=int(os.getenv("AGENT_MAX_TOKENS", str(_DEFAULT_MAX_TOKENS))),
        )


# ---------------------------------------------------------------------------
# AgentModelConfigManager — resolves per-agent config from env + YAML
# ---------------------------------------------------------------------------


class AgentModelConfigManager:
    """
    Resolves per-agent model configuration from multiple sources.

    Priority order (highest → lowest):
    1. Environment variables  (e.g. ``PLANNER_MODEL``)
    2. YAML configuration file  (``agents.yaml``)
    3. Built-in defaults

    Usage::

        manager = AgentModelConfigManager()
        cfg = manager.get("recon")
        # cfg.model = "gpt-4o-mini" (from env or yaml or default)

        manager = AgentModelConfigManager(config_path="configs/agents.yaml")
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        env_prefix: str = "",
    ) -> None:
        self._env_prefix = env_prefix
        self._yaml_configs: Dict[str, Dict[str, Any]] = {}
        self._cache: Dict[str, AgentModelConfig] = {}

        if config_path:
            self._load_yaml(config_path)

    # ------------------------------------------------------------------
    # YAML loading
    # ------------------------------------------------------------------

    def _load_yaml(self, path: str) -> None:
        """Load agent configurations from a YAML file."""
        try:
            import yaml  # Optional dependency — graceful fallback
        except ImportError:
            logger.warning("PyYAML not installed — YAML config loading skipped")
            return

        p = Path(path)
        if not p.exists():
            logger.warning("Agent config YAML not found: %s", path)
            return

        try:
            with p.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            # Support both top-level agents key and bare dict format
            agents_data = raw.get("agents") or raw
            if isinstance(agents_data, dict):
                for role, cfg in agents_data.items():
                    if isinstance(cfg, dict):
                        self._yaml_configs[role] = cfg
            logger.info("Loaded agent model config from %s (%d roles)", path, len(self._yaml_configs))
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse agent config YAML %s: %s", path, exc)

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def get(self, agent_role: str) -> AgentModelConfig:
        """
        Resolve the complete ``AgentModelConfig`` for an agent role.

        Results are cached for the lifetime of this manager instance.
        """
        if agent_role in self._cache:
            return self._cache[agent_role]

        cfg = self._resolve(agent_role)
        self._cache[agent_role] = cfg
        return cfg

    def _resolve(self, agent_role: str) -> AgentModelConfig:
        """Apply priority chain: env → yaml → default."""
        # Start with built-in defaults
        base = AgentModelConfig.default_for(agent_role)
        role_upper = agent_role.upper()

        # Layer 1: YAML overrides
        yaml_cfg = self._yaml_configs.get(agent_role, {})
        if yaml_cfg:
            base.model = yaml_cfg.get("model", base.model)
            base.provider = yaml_cfg.get("provider", base.provider)
            base.temperature = float(yaml_cfg.get("temperature", base.temperature))
            base.max_tokens = int(yaml_cfg.get("max_tokens", base.max_tokens))
            if "system_prompt" in yaml_cfg:
                base.system_prompt = yaml_cfg["system_prompt"]
            base.extra.update(yaml_cfg.get("extra", {}))

        # Layer 2: Environment variable overrides (highest priority)
        env_model = os.getenv(f"{role_upper}_MODEL")
        if env_model:
            base.model = env_model

        env_provider = os.getenv(f"{role_upper}_PROVIDER")
        if env_provider:
            base.provider = env_provider

        env_temp = os.getenv(f"{role_upper}_TEMPERATURE")
        if env_temp:
            try:
                base.temperature = float(env_temp)
            except ValueError:
                logger.warning("Invalid temperature '%s' for agent %s — ignoring", env_temp, agent_role)

        env_tokens = os.getenv(f"{role_upper}_MAX_TOKENS") or os.getenv("AGENT_MAX_TOKENS")
        if env_tokens:
            try:
                base.max_tokens = int(env_tokens)
            except ValueError:
                logger.warning("Invalid max_tokens '%s' for agent %s — ignoring", env_tokens, agent_role)

        env_prompt = os.getenv(f"{role_upper}_SYSTEM_PROMPT")
        if env_prompt:
            base.system_prompt = env_prompt

        logger.debug(
            "Resolved config for agent '%s': model=%s provider=%s temperature=%.2f max_tokens=%d",
            agent_role, base.model, base.provider, base.temperature, base.max_tokens,
        )
        return base

    def get_all(self) -> Dict[str, AgentModelConfig]:
        """Resolve and return configs for all known agent roles."""
        return {role: self.get(role) for role in ALL_AGENT_ROLES}

    def summary(self) -> List[Dict[str, Any]]:
        """Return a human-readable list of all resolved configs."""
        return [cfg.to_dict() for cfg in self.get_all().values()]

    # ------------------------------------------------------------------
    # Global settings
    # ------------------------------------------------------------------

    @staticmethod
    def get_summary_threshold() -> float:
        """
        Return the context summarisation trigger threshold.

        When the conversation history occupies more than this fraction of
        the model's context window, ``ContextSummarizer`` is invoked.
        Configured via ``AGENT_SUMMARY_THRESHOLD`` (default: 0.75).
        """
        raw = os.getenv("AGENT_SUMMARY_THRESHOLD", str(_DEFAULT_SUMMARY_THRESHOLD))
        try:
            val = float(raw)
            return max(0.1, min(1.0, val))
        except ValueError:
            return _DEFAULT_SUMMARY_THRESHOLD

    @staticmethod
    def get_proxy_url() -> Optional[str]:
        """
        Return the global LLM proxy URL (``PROXY_URL`` env var).

        Supports SOCKS5 (``socks5://…``) and HTTP/HTTPS (``http://…``) proxies.
        Returns ``None`` when no proxy is configured.
        """
        return os.getenv("PROXY_URL") or None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

#: Shared singleton — resolves configs from the default ``agents.yaml`` path
#: and environment variables.  Import and use directly in agent classes.
_default_manager: Optional[AgentModelConfigManager] = None


def get_agent_model_config_manager(
    config_path: Optional[str] = None,
) -> AgentModelConfigManager:
    """
    Return the shared ``AgentModelConfigManager`` singleton.

    On first call, reads ``AGENTS_CONFIG_PATH`` env var (defaults to
    ``examples/configs/agents/agents.yaml`` relative to the repo root)
    and the supplied ``config_path`` override.
    """
    global _default_manager  # noqa: PLW0603
    if _default_manager is None:
        resolved_path = config_path or os.getenv(
            "AGENTS_CONFIG_PATH",
            str(Path(__file__).parents[4] / "examples" / "configs" / "agents" / "agents.yaml"),
        )
        _default_manager = AgentModelConfigManager(config_path=resolved_path)
    return _default_manager
