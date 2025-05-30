"""
Moonshot AI Kimi Provider

OpenAI-compatible API for Kimi models known for long-context handling.
Documentation: https://platform.moonshot.cn/docs
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.llm.base_provider import BaseLLMProvider, LLMResponse, ProviderConfig, ProviderType

logger = logging.getLogger(__name__)


class KimiProvider(BaseLLMProvider):
    """Moonshot AI Kimi provider (OpenAI-compatible). Excellent for long-context tasks."""

    BASE_URL = "https://api.moonshot.cn/v1"
    DEFAULT_MODEL = "moonshot-v1-8k"
    SUPPORTED_MODELS = ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"]

    def __init__(self, config: Optional[ProviderConfig] = None) -> None:
        if config is None:
            config = ProviderConfig(
                name="kimi",
                provider_type=ProviderType.OPENAI_COMPATIBLE,
                base_url=self.BASE_URL,
                api_key=os.environ.get("KIMI_API_KEY", ""),
                default_model=self.DEFAULT_MODEL,
                available_models=self.SUPPORTED_MODELS,
            )
        super().__init__(config)

    @property
    def provider_name(self) -> str:
        return "kimi"

    @property
    def supported_models(self) -> List[str]:
        return self.SUPPORTED_MODELS

    def _build_payload(
        self,
        messages: List[Dict[str, str]],
        model: str,
        stream: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        return {
            "model": model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": stream,
            **{k: v for k, v in self.config.extra_params.items()},
        }

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        model = model or self.get_default_model()
        base_url = self.config.base_url or self.BASE_URL
        url = f"{base_url.rstrip('/')}/chat/completions"
        payload = self._build_payload(messages, model, stream=False, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self.get_headers())

        if response.status_code == 401:
            raise PermissionError(f"Kimi API authentication failed: {response.text}")
        if response.status_code == 429:
            raise RuntimeError(f"Kimi API rate limit exceeded: {response.text}")
        response.raise_for_status()

        data = response.json()
        choice = data["choices"][0]
        usage = data.get("usage", {})
        return LLMResponse(
            content=choice["message"]["content"],
            model=data.get("model", model),
            provider=self.provider_name,
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
            },
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )

    async def stream_chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        model = model or self.get_default_model()
        base_url = self.config.base_url or self.BASE_URL
        url = f"{base_url.rstrip('/')}/chat/completions"
        payload = self._build_payload(messages, model, stream=True, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST", url, json=payload, headers=self.get_headers()
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            text = delta.get("content", "")
                            if text:
                                yield text
                        except Exception:
                            continue
