"""
LLM Provider Registry

Central registry for all LLM providers. Supports YAML-based provider definitions
so users can add custom providers without code changes.

Usage:
    registry = ProviderRegistry()
    provider = registry.get_provider("deepseek")
    response = await provider.chat(messages)

    # Or load from YAML:
    registry.load_from_yaml("examples/configs/providers/custom.yaml")
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Type

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from app.llm.base_provider import BaseLLMProvider, ProviderConfig
from app.llm.providers.bedrock_provider import BedrockProvider
from app.llm.providers.deepseek_provider import DeepSeekProvider
from app.llm.providers.glm_provider import GLMProvider
from app.llm.providers.kimi_provider import KimiProvider
from app.llm.providers.qwen_provider import QwenProvider
from app.llm.providers.vllm_provider import VLLMProvider

logger = logging.getLogger(__name__)

_BUILTIN_PROVIDERS: Dict[str, Type[BaseLLMProvider]] = {
    "bedrock": BedrockProvider,
    "deepseek": DeepSeekProvider,
    "qwen": QwenProvider,
    "glm": GLMProvider,
    "kimi": KimiProvider,
    "vllm": VLLMProvider,
}


class ProviderRegistry:
    """
    Centralized registry for LLM providers.

    Supports:
    - Built-in providers (bedrock, deepseek, qwen, glm, kimi, vllm)
    - Dynamic registration of custom providers
    - YAML-based provider configuration
    - Environment variable detection for auto-registration
    """

    def __init__(self) -> None:
        self._providers: Dict[str, BaseLLMProvider] = {}
        self._provider_classes: Dict[str, Type[BaseLLMProvider]] = dict(_BUILTIN_PROVIDERS)
        self._auto_register_available()

    def _auto_register_available(self) -> None:
        """Auto-register providers whose API keys / URLs are set in the environment."""
        env_map: Dict[str, str] = {
            "deepseek": "DEEPSEEK_API_KEY",
            "qwen": "QWEN_API_KEY",
            "glm": "GLM_API_KEY",
            "kimi": "KIMI_API_KEY",
            "vllm": "VLLM_BASE_URL",
        }
        for provider_name, env_var in env_map.items():
            if os.environ.get(env_var):
                try:
                    self.register(provider_name)
                except Exception as exc:
                    logger.debug("Auto-register %s failed: %s", provider_name, exc)

        if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
            try:
                self.register("bedrock")
            except Exception as exc:
                logger.debug("Auto-register bedrock failed: %s", exc)

    def register(
        self,
        provider_name: str,
        config: Optional[ProviderConfig] = None,
    ) -> BaseLLMProvider:
        """Register and return a provider instance."""
        if provider_name not in self._provider_classes:
            raise ValueError(
                f"Unknown provider: '{provider_name}'. "
                f"Available: {list(self._provider_classes)}"
            )
        cls = self._provider_classes[provider_name]
        instance = cls(config) if config else cls()
        self._providers[provider_name] = instance
        logger.info("Registered LLM provider: %s", provider_name)
        return instance

    def register_custom(
        self,
        name: str,
        provider_class: Type[BaseLLMProvider],
        config: Optional[ProviderConfig] = None,
    ) -> BaseLLMProvider:
        """Register a custom provider class."""
        self._provider_classes[name] = provider_class
        return self.register(name, config)

    def get_provider(self, name: str) -> Optional[BaseLLMProvider]:
        """Get a registered provider by name. Returns None if not registered."""
        return self._providers.get(name)

    def get_or_register(
        self, name: str, config: Optional[ProviderConfig] = None
    ) -> BaseLLMProvider:
        """Get an existing provider or register it if not yet registered."""
        if name not in self._providers:
            return self.register(name, config)
        return self._providers[name]

    def list_registered(self) -> List[str]:
        """List all currently registered provider names."""
        return list(self._providers.keys())

    def list_available(self) -> List[str]:
        """List all available provider names (built-ins + custom registered classes)."""
        return list(self._provider_classes.keys())

    def load_from_yaml(self, path: str) -> BaseLLMProvider:
        """
        Load and register a provider from a YAML config file.

        YAML format::

            provider: deepseek
            name: my-deepseek
            base_url: https://api.deepseek.com/v1
            api_key: ${DEEPSEEK_API_KEY}
            default_model: deepseek-chat
            available_models: [deepseek-chat, deepseek-coder]
            max_tokens: 8192
            temperature: 0.7
        """
        if not HAS_YAML:
            raise ImportError("PyYAML required: pip install pyyaml")
        with open(path) as fh:
            data = yaml.safe_load(fh)
        return self.load_from_dict(data)

    def load_from_dict(self, data: Dict[str, Any]) -> BaseLLMProvider:
        """Register a provider from a config dict (supports env var substitution)."""
        provider_type_name = data.get("provider", data.get("name", ""))
        resolved = self._resolve_env_vars(data)

        config = ProviderConfig(
            name=resolved.get("name", provider_type_name),
            base_url=resolved.get("base_url"),
            api_key=resolved.get("api_key"),
            default_model=resolved.get("default_model", "default"),
            available_models=resolved.get("available_models", []),
            max_tokens=resolved.get("max_tokens", 4096),
            temperature=resolved.get("temperature", 0.7),
            timeout=resolved.get("timeout", 60),
            extra_params=resolved.get("extra_params", {}),
        )

        provider_class_name = resolved.get("provider", provider_type_name)
        if provider_class_name not in self._provider_classes:
            raise ValueError(f"Unknown provider class: '{provider_class_name}'")

        cls = self._provider_classes[provider_class_name]
        instance = cls(config)
        self._providers[config.name] = instance
        logger.info("Loaded provider '%s' from config dict", config.name)
        return instance

    def _resolve_env_vars(self, data: Any) -> Any:
        """Recursively resolve ``${VAR_NAME}`` references in config values."""
        if isinstance(data, str):
            if data.startswith("${") and data.endswith("}"):
                var_name = data[2:-1]
                return os.environ.get(var_name, "")
            return data
        if isinstance(data, dict):
            return {k: self._resolve_env_vars(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._resolve_env_vars(item) for item in data]
        return data

    def unregister(self, name: str) -> None:
        """Remove a provider from the active registry."""
        self._providers.pop(name, None)


# Module-level singleton
_registry: Optional[ProviderRegistry] = None


def get_provider_registry() -> ProviderRegistry:
    """Return the global :class:`ProviderRegistry` singleton."""
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry
