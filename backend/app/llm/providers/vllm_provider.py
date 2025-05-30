"""
vLLM Self-Hosted Inference Provider

Connects to a locally running vLLM server (OpenAI-compatible API).
Documentation: https://docs.vllm.ai

GPU Requirements (approximate):
    7B parameters   → 1× RTX 4090 (24 GB VRAM)
    13B parameters  → 2× RTX 5090 (48 GB VRAM total)
    70B parameters  → 4× RTX 5090 or 2× A100 80GB
    405B parameters → 16× H100 80GB

Quickstart:
    pip install vllm
    vllm serve mistralai/Mistral-7B-Instruct-v0.3 --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.llm.base_provider import BaseLLMProvider, LLMResponse, ProviderConfig, ProviderType

logger = logging.getLogger(__name__)

GPU_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "7b": {
        "vram_gb": 14,
        "recommended_gpus": ["RTX 4090", "A100 40GB"],
        "min_gpus": 1,
    },
    "13b": {
        "vram_gb": 26,
        "recommended_gpus": ["RTX 5090", "A100 80GB"],
        "min_gpus": 2,
    },
    "70b": {
        "vram_gb": 140,
        "recommended_gpus": ["4× RTX 5090", "8× A100 80GB"],
        "min_gpus": 4,
    },
    "405b": {
        "vram_gb": 810,
        "recommended_gpus": ["16× H100 80GB"],
        "min_gpus": 8,
    },
}


class VLLMProvider(BaseLLMProvider):
    """vLLM local inference provider (OpenAI-compatible)."""

    DEFAULT_BASE_URL = "http://localhost:8000/v1"

    def __init__(self, config: Optional[ProviderConfig] = None) -> None:
        if config is None:
            base_url = os.environ.get("VLLM_BASE_URL", self.DEFAULT_BASE_URL)
            api_key = os.environ.get("VLLM_API_KEY", "")
            config = ProviderConfig(
                name="vllm",
                provider_type=ProviderType.OPENAI_COMPATIBLE,
                base_url=base_url,
                api_key=api_key,
                default_model="",
                available_models=[],
            )
        super().__init__(config)

    @property
    def provider_name(self) -> str:
        return "vllm"

    @property
    def supported_models(self) -> List[str]:
        # vLLM can serve any model; the list is fetched dynamically
        return self.config.available_models or []

    def get_default_model(self) -> str:
        if self.config.default_model:
            return self.config.default_model
        if self.config.available_models:
            return self.config.available_models[0]
        return ""

    @staticmethod
    def get_gpu_requirements(model_size: str) -> Dict[str, Any]:
        """Return GPU requirements for a given model size (e.g. '7b', '70b')."""
        key = model_size.lower()
        if key not in GPU_REQUIREMENTS:
            raise ValueError(
                f"Unknown model size '{model_size}'. "
                f"Known sizes: {list(GPU_REQUIREMENTS)}"
            )
        return GPU_REQUIREMENTS[key]

    async def list_available_models(self) -> List[str]:
        """Fetch the list of deployed models from the vLLM server's /v1/models endpoint."""
        base_url = self.config.base_url or self.DEFAULT_BASE_URL
        url = f"{base_url.rstrip('/')}/models"
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.get(url, headers=self.get_headers())
        response.raise_for_status()
        data = response.json()
        models = [m["id"] for m in data.get("data", [])]
        self.config.available_models = models
        return models

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
        base_url = self.config.base_url or self.DEFAULT_BASE_URL
        url = f"{base_url.rstrip('/')}/chat/completions"
        payload = self._build_payload(messages, model, stream=False, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self.get_headers())

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
        base_url = self.config.base_url or self.DEFAULT_BASE_URL
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
