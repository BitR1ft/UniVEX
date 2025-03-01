"""
Traversaal Ares AI Search Tool

Real-time AI search via Traversaal's Ares API.
"""

import logging
import os
from typing import Any

import httpx

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

TRAVERSAAL_API_URL = "https://api-ares.traversaal.ai/live/predict"


class TraversaalTool(BaseTool):
    """
    Tool for real-time AI search using Traversaal Ares API.

    Returns AI-synthesized answers grounded in current web data.
    Requires TRAVERSAAL_API_KEY environment variable.
    """

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("TRAVERSAAL_API_KEY", "")

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="traversaal_search",
            description="""Real-time AI search using Traversaal Ares API with current web grounding.

Returns synthesized, up-to-date answers for security and technical queries.

Examples:
- "Latest Log4Shell exploitation techniques"
- "Active ransomware groups targeting healthcare 2024"
- "Zero-day vulnerabilities disclosed this week"

Requires TRAVERSAAL_API_KEY environment variable.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query or question",
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(self, query: str, **kwargs: Any) -> str:
        """
        Execute search via Traversaal Ares API.

        Args:
            query: Search query or question

        Returns:
            AI-synthesized answer as formatted string
        """
        if not self.api_key:
            return "Error: TRAVERSAAL_API_KEY not configured. Please set the environment variable."

        try:
            payload = {"query": [query]}

            headers = {
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(TRAVERSAAL_API_URL, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            return self._format_results(data, query)

        except httpx.HTTPStatusError as e:
            logger.error(f"Traversaal HTTP error: {e}", exc_info=True)
            return f"Error querying Traversaal (HTTP {e.response.status_code}): {e.response.text[:200]}"
        except httpx.RequestError as e:
            logger.error(f"Traversaal request error: {e}", exc_info=True)
            return f"Error connecting to Traversaal: {str(e)}"
        except Exception as e:
            logger.error(f"Traversaal unexpected error: {e}", exc_info=True)
            return f"Error querying Traversaal: {str(e)}"

    def _format_results(self, data: dict, query: str) -> str:
        """Format Traversaal API response into a readable string."""
        # Traversaal response may vary; handle common structures
        response_text = data.get("response_text", "")
        web_url = data.get("web_url", [])

        if not response_text and not web_url:
            return f"No response from Traversaal for query: '{query}'"

        output = [f"Traversaal Ares AI search results for '{query}':\n"]

        if response_text:
            output.append(response_text)

        if web_url:
            output.append("\nSources:")
            for i, url in enumerate(web_url, 1):
                output.append(f"  [{i}] {url}")

        return "\n".join(output)
