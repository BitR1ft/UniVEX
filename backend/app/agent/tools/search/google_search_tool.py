"""
Google Custom Search Tool

Searches the web using Google Custom Search Engine (CSE) API.
"""

import logging
import os
from typing import Any

import httpx

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

GOOGLE_CSE_URL = "https://www.googleapis.com/customsearch/v1"


class GoogleCustomSearchTool(BaseTool):
    """
    Tool for web search using Google Custom Search Engine API.

    Returns titles, links, and snippets for matching pages.
    Requires GOOGLE_CSE_ID and GOOGLE_API_KEY environment variables.
    """

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("GOOGLE_API_KEY", "")
        self.cse_id = os.getenv("GOOGLE_CSE_ID", "")

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="google_search",
            description="""Search the web using Google Custom Search Engine API.

Returns title, link, and snippet for each matching result.

Examples:
- "CVE-2024-21413 Microsoft Outlook exploit"
- "Spring4Shell remote code execution PoC"
- "OWASP API security top 10"

Requires GOOGLE_API_KEY and GOOGLE_CSE_ID environment variables.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "num": {
                        "type": "integer",
                        "description": "Number of results (1-10, default: 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(self, query: str, num: int = 10, **kwargs: Any) -> str:
        """
        Execute Google Custom Search.

        Args:
            query: Search query string
            num: Number of results (1-10)

        Returns:
            Formatted search results as string
        """
        if not self.api_key:
            return "Error: GOOGLE_API_KEY not configured. Please set the environment variable."
        if not self.cse_id:
            return "Error: GOOGLE_CSE_ID not configured. Please set the environment variable."

        try:
            params = {
                "key": self.api_key,
                "cx": self.cse_id,
                "q": query,
                "num": min(max(1, num), 10),
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(GOOGLE_CSE_URL, params=params)
                response.raise_for_status()
                data = response.json()

            return self._format_results(data, query)

        except httpx.HTTPStatusError as e:
            logger.error(f"Google CSE HTTP error: {e}", exc_info=True)
            return f"Error querying Google CSE (HTTP {e.response.status_code}): {e.response.text[:200]}"
        except httpx.RequestError as e:
            logger.error(f"Google CSE request error: {e}", exc_info=True)
            return f"Error connecting to Google CSE: {str(e)}"
        except Exception as e:
            logger.error(f"Google CSE unexpected error: {e}", exc_info=True)
            return f"Error querying Google CSE: {str(e)}"

    def _format_results(self, data: dict, query: str) -> str:
        """Format Google CSE response into a readable string."""
        items = data.get("items", [])
        search_info = data.get("searchInformation", {})
        total_results = search_info.get("formattedTotalResults", str(len(items)))

        if not items:
            return f"No results found on Google CSE for query: '{query}'"

        output = [f"Google search results for '{query}' ({total_results} total):\n"]

        for i, item in enumerate(items, 1):
            title = item.get("title", "No title")
            link = item.get("link", "")
            snippet = item.get("snippet", "")

            output.append(f"{i}. {title}")
            if link:
                output.append(f"   URL: {link}")
            if snippet:
                clean_snippet = snippet.replace("\n", " ")
                output.append(f"   {clean_snippet}")
            output.append("")

        return "\n".join(output)
