"""
AWS Bedrock LLM Provider

Supports: Anthropic Claude, Amazon Titan, AI21 Jurassic/Jamba, Cohere Command
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncIterator, Dict, List, Optional

from app.llm.base_provider import BaseLLMProvider, LLMResponse, ProviderConfig, ProviderType

logger = logging.getLogger(__name__)

# Bedrock model IDs
CLAUDE_MODELS = [
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0",
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-v2:1",
]
TITAN_MODELS = [
    "amazon.titan-text-premier-v1:0",
    "amazon.titan-text-express-v1",
    "amazon.titan-text-lite-v1",
]
AI21_MODELS = [
    "ai21.jamba-1-5-large-v1:0",
    "ai21.jamba-1-5-mini-v1:0",
    "ai21.j2-ultra-v1",
    "ai21.j2-mid-v1",
]
COHERE_MODELS = [
    "cohere.command-r-plus-v1:0",
    "cohere.command-r-v1:0",
    "cohere.command-text-v14",
]

ALL_BEDROCK_MODELS = CLAUDE_MODELS + TITAN_MODELS + AI21_MODELS + COHERE_MODELS


class BedrockProvider(BaseLLMProvider):
    """AWS Bedrock LLM provider supporting multiple model families."""

    def __init__(self, config: Optional[ProviderConfig] = None) -> None:
        if config is None:
            config = ProviderConfig(
                name="bedrock",
                provider_type=ProviderType.BEDROCK,
                default_model=CLAUDE_MODELS[0],
                available_models=ALL_BEDROCK_MODELS,
            )
        super().__init__(config)

        try:
            import boto3  # type: ignore[import-untyped]
            self._boto3 = boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for the Bedrock provider. "
                "Install it with: pip install boto3"
            ) from exc

        region = os.environ.get("AWS_REGION", "us-east-1")
        kwargs: Dict[str, Any] = {"region_name": region}
        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if access_key:
            kwargs["aws_access_key_id"] = access_key
        if secret_key:
            kwargs["aws_secret_access_key"] = secret_key

        self._client = boto3.client("bedrock-runtime", **kwargs)

    @property
    def provider_name(self) -> str:
        return "bedrock"

    @property
    def supported_models(self) -> List[str]:
        return ALL_BEDROCK_MODELS

    # ------------------------------------------------------------------ helpers

    def _get_model_family(self, model_id: str) -> str:
        if model_id.startswith("anthropic."):
            return "claude"
        if model_id.startswith("amazon."):
            return "titan"
        if model_id.startswith("ai21."):
            return "ai21"
        if model_id.startswith("cohere."):
            return "cohere"
        return "unknown"

    def _messages_to_prompt(self, messages: List[Dict[str, str]]) -> str:
        """Flatten messages list into a single prompt string for non-Claude models."""
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"{role.capitalize()}: {content}")
        return "\n".join(parts)

    def _build_claude_request(
        self, messages: List[Dict[str, str]], model: str, **kwargs: Any
    ) -> Dict[str, Any]:
        # Separate system messages for the Anthropic Messages API
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        user_messages = [m for m in messages if m.get("role") != "system"]
        body: Dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "messages": user_messages,
        }
        if system_parts:
            body["system"] = "\n".join(system_parts)
        return body

    def _build_titan_request(
        self, messages: List[Dict[str, str]], model: str, **kwargs: Any
    ) -> Dict[str, Any]:
        return {
            "inputText": self._messages_to_prompt(messages),
            "textGenerationConfig": {
                "maxTokenCount": kwargs.get("max_tokens", self.config.max_tokens),
                "temperature": kwargs.get("temperature", self.config.temperature),
                "topP": kwargs.get("top_p", 0.9),
            },
        }

    def _build_ai21_request(
        self, messages: List[Dict[str, str]], model: str, **kwargs: Any
    ) -> Dict[str, Any]:
        # Jamba models use the messages format; legacy J2 uses prompt
        if "jamba" in model:
            return {
                "messages": messages,
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
                "temperature": kwargs.get("temperature", self.config.temperature),
            }
        return {
            "prompt": self._messages_to_prompt(messages),
            "maxTokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
        }

    def _build_cohere_request(
        self, messages: List[Dict[str, str]], model: str, **kwargs: Any
    ) -> Dict[str, Any]:
        return {
            "message": messages[-1]["content"] if messages else "",
            "chat_history": [
                {"role": m["role"].upper(), "message": m["content"]}
                for m in messages[:-1]
            ],
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
        }

    def _parse_claude_response(self, response_body: Dict[str, Any], model: str) -> LLMResponse:
        content = ""
        if response_body.get("content"):
            content = response_body["content"][0].get("text", "")
        usage = response_body.get("usage", {})
        return LLMResponse(
            content=content,
            model=model,
            provider=self.provider_name,
            usage={
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
            },
            finish_reason=response_body.get("stop_reason", "stop"),
            raw=response_body,
        )

    def _parse_titan_response(self, response_body: Dict[str, Any], model: str) -> LLMResponse:
        results = response_body.get("results", [{}])
        content = results[0].get("outputText", "") if results else ""
        return LLMResponse(
            content=content,
            model=model,
            provider=self.provider_name,
            usage={
                "prompt_tokens": response_body.get("inputTextTokenCount", 0),
                "completion_tokens": results[0].get("tokenCount", 0) if results else 0,
            },
            finish_reason=results[0].get("completionReason", "stop") if results else "stop",
            raw=response_body,
        )

    def _parse_ai21_response(self, response_body: Dict[str, Any], model: str) -> LLMResponse:
        # Jamba vs J2 format
        if "choices" in response_body:
            content = response_body["choices"][0].get("message", {}).get("content", "")
            usage = response_body.get("usage", {})
            return LLMResponse(
                content=content,
                model=model,
                provider=self.provider_name,
                usage={
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                },
                raw=response_body,
            )
        completions = response_body.get("completions", [{}])
        content = completions[0].get("data", {}).get("text", "") if completions else ""
        return LLMResponse(
            content=content,
            model=model,
            provider=self.provider_name,
            raw=response_body,
        )

    def _parse_cohere_response(self, response_body: Dict[str, Any], model: str) -> LLMResponse:
        return LLMResponse(
            content=response_body.get("text", ""),
            model=model,
            provider=self.provider_name,
            raw=response_body,
        )

    # ------------------------------------------------------------------ public

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        model = model or self.get_default_model()
        family = self._get_model_family(model)

        build_map = {
            "claude": self._build_claude_request,
            "titan": self._build_titan_request,
            "ai21": self._build_ai21_request,
            "cohere": self._build_cohere_request,
        }
        parse_map = {
            "claude": self._parse_claude_response,
            "titan": self._parse_titan_response,
            "ai21": self._parse_ai21_response,
            "cohere": self._parse_cohere_response,
        }

        if family not in build_map:
            raise ValueError(f"Unsupported Bedrock model family for model: {model}")

        body = build_map[family](messages, model, **kwargs)
        response = self._client.invoke_model(
            modelId=model,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )
        response_body = json.loads(response["body"].read())
        return parse_map[family](response_body, model)

    async def stream_chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        model = model or self.get_default_model()
        family = self._get_model_family(model)

        build_map = {
            "claude": self._build_claude_request,
            "titan": self._build_titan_request,
            "ai21": self._build_ai21_request,
            "cohere": self._build_cohere_request,
        }
        if family not in build_map:
            raise ValueError(f"Unsupported Bedrock model family for model: {model}")

        body = build_map[family](messages, model, **kwargs)
        response = self._client.invoke_model_with_response_stream(
            modelId=model,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )

        for event in response.get("body", []):
            chunk = event.get("chunk", {})
            if chunk:
                chunk_data = json.loads(chunk.get("bytes", b"{}"))
                # Claude streaming format
                if chunk_data.get("type") == "content_block_delta":
                    delta = chunk_data.get("delta", {})
                    text = delta.get("text", "")
                    if text:
                        yield text
                # Titan streaming format
                elif "outputText" in chunk_data:
                    yield chunk_data["outputText"]
                # Generic fallback
                elif "text" in chunk_data:
                    yield chunk_data["text"]
