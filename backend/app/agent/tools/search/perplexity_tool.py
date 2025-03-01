"""
Perplexity AI Search Tool

AI-powered search using Perplexity's sonar-pro model with real-time web retrieval.
"""

import logging
import os
from typing import Any

import httpx

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
PERPLEXITY_MODEL = "sonar-pro"


class PerplexityTool(BaseTool):
    """
    Tool for AI-powered search using Perplexity's sonar-pro model.

    Combines LLM reasoning with real-time web search for detailed, cited answers.
    Requires PERPLEXITY_API_KEY environment variable.
    """

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("PERPLEXITY_API_KEY", "")

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="perplexity_search",
            description="""AI-powered search using Perplexity sonar-pro model with real-time web retrieval.

Returns detailed, cited answers combining LLM reasoning with live web data.

Examples:
- "What are the latest exploits for CVE-2024-1234?"
- "Explain SSRF vulnerabilities and mitigation strategies"
- "Recent zero-days in enterprise software 2024"

Requires PERPLEXITY_API_KEY environment variable.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query or question",
                    },
                    "system_prompt": {
                        "type": "string",
                        "description": "Optional system prompt to guide the response",
                        "default": "You are a cybersecurity expert. Provide detailed, accurate information about security topics, vulnerabilities, and exploits.",
                    },
                    "max_tokens": {
                        "type": "integer",
                        "description": "Maximum tokens in response (default: 1024)",
                        "default": 1024,
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(
        self,
        query: str,
        system_prompt: str = "You are a cybersecurity expert. Provide detailed, accurate information about security topics, vulnerabilities, and exploits.",
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> str:
        """
        Execute AI-powered search via Perplexity API.

        Args:
            query: Search query or question
            system_prompt: System prompt to guide response style
            max_tokens: Maximum response tokens

        Returns:
            AI-generated answer with citations as formatted string
        """
        if not self.api_key:
            return "Error: PERPLEXITY_API_KEY not configured. Please set the environment variable."

        try:
            payload = {
                "model": PERPLEXITY_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": query},
                ],
                "max_tokens": max_tokens,
            }

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(PERPLEXITY_API_URL, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            return self._format_results(data, query)

        except httpx.HTTPStatusError as e:
            logger.error(f"Perplexity HTTP error: {e}", exc_info=True)
            return f"Error querying Perplexity (HTTP {e.response.status_code}): {e.response.text[:200]}"
        except httpx.RequestError as e:
            logger.error(f"Perplexity request error: {e}", exc_info=True)
            return f"Error connecting to Perplexity: {str(e)}"
        except Exception as e:
            logger.error(f"Perplexity unexpected error: {e}", exc_info=True)
            return f"Error querying Perplexity: {str(e)}"

    def _format_results(self, data: dict, query: str) -> str:
        """Format Perplexity API response into a readable string."""
        choices = data.get("choices", [])
        if not choices:
            return f"No response from Perplexity for query: '{query}'"

        message = choices[0].get("message", {})
        content = message.get("content", "")

        citations = data.get("citations", [])
        usage = data.get("usage", {})

        output = [f"Perplexity AI search results for '{query}':\n"]
        output.append(content)

        if citations:
            output.append("\n\nSources:")
            for i, citation in enumerate(citations, 1):
                output.append(f"  [{i}] {citation}")

        if usage:
            tokens_used = usage.get("total_tokens", 0)
            output.append(f"\n[Tokens used: {tokens_used}]")

        return "\n".join(output)
