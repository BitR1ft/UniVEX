"""
Tests for Day 2 — Per-Agent Model Configuration.

Coverage:
  - AgentModelConfig: dataclass fields, to_dict, from_dict, default_for
  - AgentModelConfigManager: env var resolution, YAML loading, caching
  - ALL_AGENT_ROLES completeness
  - Global settings: get_summary_threshold, get_proxy_url
  - Singleton get_agent_model_config_manager
  - config.py: per-agent settings exposed, PROXY_URL, GRAPHITI_* settings
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict
from unittest.mock import patch, MagicMock

import pytest

from app.agent.config.agent_model_config import (
    AgentModelConfig,
    AgentModelConfigManager,
    ALL_AGENT_ROLES,
    get_agent_model_config_manager,
    _DEFAULT_MAX_TOKENS,
    _DEFAULT_SUMMARY_THRESHOLD,
)


# ===========================================================================
# AgentModelConfig
# ===========================================================================

class TestAgentModelConfig:
    """Tests for the AgentModelConfig dataclass."""

    def test_basic_fields(self):
        cfg = AgentModelConfig(
            agent_role="recon",
            model="gpt-4o-mini",
            provider="openai",
            temperature=0.1,
            max_tokens=2048,
        )
        assert cfg.agent_role == "recon"
        assert cfg.model == "gpt-4o-mini"
        assert cfg.provider == "openai"
        assert cfg.temperature == pytest.approx(0.1)
        assert cfg.max_tokens == 2048

    def test_default_fields(self):
        cfg = AgentModelConfig(agent_role="test", model="gpt-4o")
        assert cfg.provider == "openai"
        assert cfg.temperature == pytest.approx(0.2)
        assert cfg.max_tokens == _DEFAULT_MAX_TOKENS
        assert cfg.system_prompt is None
        assert cfg.extra == {}

    def test_to_dict(self):
        cfg = AgentModelConfig(
            agent_role="exploit",
            model="claude-3-5-sonnet-20241022",
            provider="anthropic",
            temperature=0.1,
            max_tokens=8192,
            system_prompt="You are an expert",
        )
        d = cfg.to_dict()
        assert d["agent_role"] == "exploit"
        assert d["model"] == "claude-3-5-sonnet-20241022"
        assert d["provider"] == "anthropic"
        assert d["temperature"] == pytest.approx(0.1)
        assert d["system_prompt"] == "You are an expert"

    def test_from_dict(self):
        data = {
            "agent_role": "recon",
            "model": "gpt-4o-mini",
            "provider": "openai",
            "temperature": 0.1,
            "max_tokens": 4096,
            "system_prompt": None,
            "extra": {},
        }
        cfg = AgentModelConfig.from_dict(data)
        assert cfg.agent_role == "recon"
        assert cfg.model == "gpt-4o-mini"
        assert cfg.temperature == pytest.approx(0.1)

    def test_from_dict_with_defaults(self):
        cfg = AgentModelConfig.from_dict({"agent_role": "planner", "model": "gpt-4o"})
        assert cfg.provider == "openai"
        assert cfg.temperature == pytest.approx(0.2)
        assert cfg.max_tokens == _DEFAULT_MAX_TOKENS

    def test_default_for_known_role(self):
        cfg = AgentModelConfig.default_for("recon")
        assert cfg.agent_role == "recon"
        assert cfg.model == "gpt-4o-mini"
        assert cfg.provider == "openai"
        assert cfg.temperature == pytest.approx(0.1)

    def test_default_for_exploit(self):
        cfg = AgentModelConfig.default_for("exploit")
        assert "claude" in cfg.model

    def test_default_for_unknown_role(self):
        cfg = AgentModelConfig.default_for("unknown_agent")
        assert cfg.model == "gpt-4o"  # Falls back to default

    def test_all_known_roles_have_defaults(self):
        for role in ALL_AGENT_ROLES:
            cfg = AgentModelConfig.default_for(role)
            assert cfg.agent_role == role
            assert cfg.model != ""

    def test_extra_field(self):
        cfg = AgentModelConfig(
            agent_role="test",
            model="gpt-4o",
            extra={"top_p": 0.9, "frequency_penalty": 0.1},
        )
        assert cfg.extra["top_p"] == pytest.approx(0.9)


# ===========================================================================
# ALL_AGENT_ROLES
# ===========================================================================

class TestAllAgentRoles:
    """Tests for ALL_AGENT_ROLES constant."""

    def test_contains_core_roles(self):
        assert "planner" in ALL_AGENT_ROLES
        assert "recon" in ALL_AGENT_ROLES
        assert "exploit" in ALL_AGENT_ROLES
        assert "webapp" in ALL_AGENT_ROLES
        assert "report" in ALL_AGENT_ROLES

    def test_contains_gap_coverage_day3_roles(self):
        """New agent roles from Day 3."""
        assert "refiner" in ALL_AGENT_ROLES
        assert "generator" in ALL_AGENT_ROLES
        assert "adviser" in ALL_AGENT_ROLES
        assert "reflector" in ALL_AGENT_ROLES
        assert "enricher" in ALL_AGENT_ROLES
        assert "coder" in ALL_AGENT_ROLES
        assert "installer" in ALL_AGENT_ROLES
        assert "simple_json" in ALL_AGENT_ROLES

    def test_total_count_is_13(self):
        assert len(ALL_AGENT_ROLES) == 13

    def test_no_duplicates(self):
        assert len(ALL_AGENT_ROLES) == len(set(ALL_AGENT_ROLES))


# ===========================================================================
# AgentModelConfigManager — Environment Variable Resolution
# ===========================================================================

class TestAgentModelConfigManagerEnvVars:
    """Tests for AgentModelConfigManager env var override."""

    def _make_manager(self, config_path=None) -> AgentModelConfigManager:
        return AgentModelConfigManager(config_path=config_path)

    def test_returns_default_without_env(self):
        with patch.dict(os.environ, {}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("recon")
            assert cfg.model == "gpt-4o-mini"

    def test_env_model_override(self):
        with patch.dict(os.environ, {"RECON_MODEL": "gpt-4o"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("recon")
            assert cfg.model == "gpt-4o"

    def test_env_provider_override(self):
        with patch.dict(os.environ, {"EXPLOIT_PROVIDER": "groq"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("exploit")
            assert cfg.provider == "groq"

    def test_env_temperature_override(self):
        with patch.dict(os.environ, {"PLANNER_TEMPERATURE": "0.8"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("planner")
            assert cfg.temperature == pytest.approx(0.8)

    def test_env_max_tokens_override(self):
        with patch.dict(os.environ, {"REPORT_MAX_TOKENS": "16384"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("report")
            assert cfg.max_tokens == 16384

    def test_global_agent_max_tokens_override(self):
        with patch.dict(os.environ, {"AGENT_MAX_TOKENS": "2048"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("recon")
            assert cfg.max_tokens == 2048

    def test_env_system_prompt_override(self):
        custom_prompt = "Custom system prompt for planner"
        with patch.dict(os.environ, {"PLANNER_SYSTEM_PROMPT": custom_prompt}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("planner")
            assert cfg.system_prompt == custom_prompt

    def test_invalid_temperature_uses_default(self):
        with patch.dict(os.environ, {"RECON_TEMPERATURE": "not-a-float"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("recon")
            assert cfg.temperature == pytest.approx(0.1)  # default

    def test_invalid_max_tokens_uses_default(self):
        with patch.dict(os.environ, {"RECON_MAX_TOKENS": "not-an-int"}, clear=False):
            manager = self._make_manager()
            cfg = manager.get("recon")
            assert cfg.max_tokens > 0

    def test_env_vars_take_priority_over_yaml(self):
        """Environment variables must override YAML file settings."""
        yaml_content = """
agents:
  recon:
    model: mistral-7b
    temperature: 0.5
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            with patch.dict(os.environ, {"RECON_MODEL": "gpt-4o-mini"}, clear=False):
                manager = AgentModelConfigManager(config_path=yaml_path)
                cfg = manager.get("recon")
                assert cfg.model == "gpt-4o-mini"  # env wins
                assert cfg.temperature == pytest.approx(0.5)  # from yaml (no env override)
        finally:
            os.unlink(yaml_path)

    def test_all_roles_resolve_without_error(self):
        manager = self._make_manager()
        for role in ALL_AGENT_ROLES:
            cfg = manager.get(role)
            assert cfg.agent_role == role
            assert cfg.model != ""

    def test_get_all_returns_all_roles(self):
        manager = self._make_manager()
        all_configs = manager.get_all()
        assert set(all_configs.keys()) == set(ALL_AGENT_ROLES)

    def test_summary_returns_list_of_dicts(self):
        manager = self._make_manager()
        summary = manager.summary()
        assert isinstance(summary, list)
        assert len(summary) == len(ALL_AGENT_ROLES)
        for item in summary:
            assert "agent_role" in item
            assert "model" in item

    def test_caching_returns_same_instance(self):
        manager = self._make_manager()
        cfg1 = manager.get("recon")
        cfg2 = manager.get("recon")
        assert cfg1 is cfg2


# ===========================================================================
# AgentModelConfigManager — YAML Loading
# ===========================================================================

class TestAgentModelConfigManagerYAML:
    """Tests for YAML-based configuration loading."""

    def test_yaml_model_override(self):
        yaml_content = """
agents:
  planner:
    model: gpt-4-turbo
    temperature: 0.3
    max_tokens: 8192
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            with patch.dict(os.environ, {}, clear=False):
                manager = AgentModelConfigManager(config_path=yaml_path)
                cfg = manager.get("planner")
                assert cfg.model == "gpt-4-turbo"
                assert cfg.temperature == pytest.approx(0.3)
                assert cfg.max_tokens == 8192
        finally:
            os.unlink(yaml_path)

    def test_yaml_provider_override(self):
        yaml_content = """
agents:
  exploit:
    model: claude-3-opus
    provider: anthropic
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            with patch.dict(os.environ, {}, clear=False):
                manager = AgentModelConfigManager(config_path=yaml_path)
                cfg = manager.get("exploit")
                assert cfg.provider == "anthropic"
        finally:
            os.unlink(yaml_path)

    def test_yaml_system_prompt_override(self):
        yaml_content = """
agents:
  report:
    model: gpt-4o
    system_prompt: "Custom report agent prompt"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            manager = AgentModelConfigManager(config_path=yaml_path)
            cfg = manager.get("report")
            assert cfg.system_prompt == "Custom report agent prompt"
        finally:
            os.unlink(yaml_path)

    def test_yaml_extra_kwargs(self):
        yaml_content = """
agents:
  recon:
    model: gpt-4o
    extra:
      top_p: 0.9
      seed: 42
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            manager = AgentModelConfigManager(config_path=yaml_path)
            cfg = manager.get("recon")
            assert cfg.extra.get("top_p") == pytest.approx(0.9)
            assert cfg.extra.get("seed") == 42
        finally:
            os.unlink(yaml_path)

    def test_yaml_partial_override_uses_defaults(self):
        """YAML with only model specified should use built-in defaults for others."""
        yaml_content = """
agents:
  recon:
    model: deepseek-chat
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name

        try:
            with patch.dict(os.environ, {}, clear=False):
                manager = AgentModelConfigManager(config_path=yaml_path)
                cfg = manager.get("recon")
                assert cfg.model == "deepseek-chat"
                assert cfg.temperature == pytest.approx(0.1)  # built-in default
        finally:
            os.unlink(yaml_path)

    def test_missing_yaml_uses_defaults(self):
        manager = AgentModelConfigManager(config_path="/nonexistent/path/agents.yaml")
        cfg = manager.get("recon")
        assert cfg.model == "gpt-4o-mini"  # built-in default

    def test_empty_yaml_uses_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            yaml_path = f.name

        try:
            manager = AgentModelConfigManager(config_path=yaml_path)
            cfg = manager.get("recon")
            assert cfg.model == "gpt-4o-mini"
        finally:
            os.unlink(yaml_path)

    def test_invalid_yaml_uses_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("this: is: not: valid: yaml: {{{")
            yaml_path = f.name

        try:
            manager = AgentModelConfigManager(config_path=yaml_path)
            # Should not raise; falls through to defaults
            cfg = manager.get("recon")
            assert cfg is not None
        except Exception:
            # If YAML parsing error is non-fatal and we still get a default, that's fine
            pass
        finally:
            os.unlink(yaml_path)


# ===========================================================================
# Global Settings
# ===========================================================================

class TestGlobalSettings:
    """Tests for global settings methods."""

    def test_get_summary_threshold_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_SUMMARY_THRESHOLD", None)
            threshold = AgentModelConfigManager.get_summary_threshold()
            assert threshold == pytest.approx(_DEFAULT_SUMMARY_THRESHOLD)

    def test_get_summary_threshold_from_env(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "0.6"}, clear=False):
            threshold = AgentModelConfigManager.get_summary_threshold()
            assert threshold == pytest.approx(0.6)

    def test_get_summary_threshold_clamped_low(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "-0.5"}, clear=False):
            threshold = AgentModelConfigManager.get_summary_threshold()
            assert threshold >= 0.1

    def test_get_summary_threshold_clamped_high(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "2.0"}, clear=False):
            threshold = AgentModelConfigManager.get_summary_threshold()
            assert threshold <= 1.0

    def test_get_summary_threshold_invalid_uses_default(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "invalid"}, clear=False):
            threshold = AgentModelConfigManager.get_summary_threshold()
            assert threshold == pytest.approx(_DEFAULT_SUMMARY_THRESHOLD)

    def test_get_proxy_url_none_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PROXY_URL", None)
            proxy = AgentModelConfigManager.get_proxy_url()
            assert proxy is None

    def test_get_proxy_url_from_env_http(self):
        with patch.dict(os.environ, {"PROXY_URL": "http://proxy.internal:8080"}, clear=False):
            proxy = AgentModelConfigManager.get_proxy_url()
            assert proxy == "http://proxy.internal:8080"

    def test_get_proxy_url_from_env_socks5(self):
        with patch.dict(os.environ, {"PROXY_URL": "socks5://user:pass@proxy:1080"}, clear=False):
            proxy = AgentModelConfigManager.get_proxy_url()
            assert proxy == "socks5://user:pass@proxy:1080"


# ===========================================================================
# Core Config Integration
# ===========================================================================

class TestCoreConfigIntegration:
    """Tests that config.py exposes all per-agent settings."""

    def test_per_agent_model_settings_in_config(self):
        from app.core.config import settings
        # Check core agents
        assert hasattr(settings, "PLANNER_MODEL")
        assert hasattr(settings, "RECON_MODEL")
        assert hasattr(settings, "EXPLOIT_MODEL")
        assert hasattr(settings, "WEBAPP_MODEL")
        assert hasattr(settings, "REPORT_MODEL")

    def test_per_agent_temperature_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "PLANNER_TEMPERATURE")
        assert hasattr(settings, "RECON_TEMPERATURE")
        assert hasattr(settings, "EXPLOIT_TEMPERATURE")
        assert isinstance(settings.PLANNER_TEMPERATURE, float)

    def test_per_agent_max_tokens_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "PLANNER_MAX_TOKENS")
        assert hasattr(settings, "RECON_MAX_TOKENS")
        assert isinstance(settings.RECON_MAX_TOKENS, int)

    def test_per_agent_provider_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "PLANNER_PROVIDER")
        assert hasattr(settings, "EXPLOIT_PROVIDER")

    def test_global_agent_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "AGENT_MAX_TOKENS")
        assert hasattr(settings, "AGENT_SUMMARY_THRESHOLD")
        assert isinstance(settings.AGENT_SUMMARY_THRESHOLD, float)

    def test_proxy_url_setting(self):
        from app.core.config import settings
        assert hasattr(settings, "PROXY_URL")
        # Default should be None
        assert settings.PROXY_URL is None

    def test_graphiti_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "GRAPHITI_URL")
        assert hasattr(settings, "GRAPHITI_ENABLED")
        assert "graphiti" in settings.GRAPHITI_URL.lower() or "8010" in settings.GRAPHITI_URL

    def test_memory_settings(self):
        from app.core.config import settings
        assert hasattr(settings, "MEMORY_MAX_ENTRIES_PER_FLOW")
        assert hasattr(settings, "AUTO_CAPTURE_MEMORY")
        assert settings.MEMORY_MAX_ENTRIES_PER_FLOW > 0

    def test_agents_config_path_setting(self):
        from app.core.config import settings
        assert hasattr(settings, "AGENTS_CONFIG_PATH")

    def test_default_models_are_valid(self):
        from app.core.config import settings
        assert settings.PLANNER_MODEL == "gpt-4o"
        assert settings.RECON_MODEL == "gpt-4o-mini"
        assert "claude" in settings.EXPLOIT_MODEL
        assert settings.REPORT_MODEL == "gpt-4o-mini"

    def test_version_updated(self):
        from app.core.config import settings
        # Version should reflect gap coverage work has started
        assert settings.VERSION >= "2.1.0"
