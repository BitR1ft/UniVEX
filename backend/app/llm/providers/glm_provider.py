"""
Zhipu AI GLM Provider

OpenAI-compatible API for GLM-4 models.
Authentication uses a JWT token derived from the API key (format: "id.secret").
Documentation: https://open.bigmodel.cn/dev/api
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.llm.base_provider import BaseLLMProvider, LLMResponse, ProviderConfig, ProviderType

logger = logging.getLogger(__name__)


class GLMProvider(BaseLLMProvider):
    """Zhipu AI GLM provider with JWT-based authentication."""

    BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
    DEFAULT_MODEL = "glm-4"
    SUPPORTED_MODELS = ["glm-4", "glm-4-air", "glm-4-flash", "glm-4v"]

    def __init__(self, config: Optional[ProviderConfig] = None) -> None:
        if config is None:
            config = ProviderConfig(
                name="glm",
                provider_type=ProviderType.OPENAI_COMPATIBLE,
                base_url=self.BASE_URL,
                api_key=os.environ.get("GLM_API_KEY", ""),
                default_model=self.DEFAULT_MODEL,
                available_models=self.SUPPORTED_MODELS,
            )
        super().__init__(config)

    @property
    def provider_name(self) -> str:
        return "glm"

    @property
    def supported_models(self) -> List[str]:
        return self.SUPPORTED_MODELS

    def _generate_jwt_token(self, api_key: str) -> str:
        """Generate a JWT token for Zhipu AI API authentication.

        The API key is formatted as "id.secret"; if it has no dot it is
        treated as an already-issued token and returned unchanged.
        """
        try:
            key_id, secret = api_key.split(".", 1)
        except ValueError:
            return api_key  # already a plain token

        timestamp = int(time.time() * 1000)
        payload = {
            "api_key": key_id,
            "exp": timestamp + 3_600_000,
            "timestamp": timestamp,
        }

        header_b64 = (
            base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "sign_type": "SIGN"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        body_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode())
            .rstrip(b"=")
            .decode()
        )
        signing_input = f"{header_b64}.{body_b64}"
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    secret.encode(),
                    signing_input.encode(),
                    hashlib.sha256,
                ).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        return f"{header_b64}.{body_b64}.{signature}"

    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            token = self._generate_jwt_token(self.config.api_key)
            headers["Authorization"] = f"Bearer {token}"
        return headers

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
            raise PermissionError(f"GLM API authentication failed: {response.text}")
        if response.status_code == 429:
            raise RuntimeError(f"GLM API rate limit exceeded: {response.text}")
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
