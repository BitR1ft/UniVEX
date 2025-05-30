"""
Base LLM Provider

Abstract base class and shared data models for all LLM providers.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional


class ProviderType(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    BEDROCK = "bedrock"
    CUSTOM = "custom"


@dataclass
class ProviderConfig:
    name: str
    provider_type: ProviderType = ProviderType.OPENAI_COMPATIBLE
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    default_model: str = "default"
    available_models: List[str] = field(default_factory=list)
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: int = 60
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = "stop"
    raw: Optional[Dict[str, Any]] = None


class BaseLLMProvider(ABC):
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @property
    @abstractmethod
    def supported_models(self) -> List[str]: ...

    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse: ...

    @abstractmethod
    async def stream_chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]: ...

    def validate_model(self, model: str) -> bool:
        if not self.supported_models:
            return True
        return model in self.supported_models

    def get_default_model(self) -> str:
        if self.config.default_model and self.config.default_model != "default":
            return self.config.default_model
        return self.supported_models[0] if self.supported_models else "default"

    def get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
