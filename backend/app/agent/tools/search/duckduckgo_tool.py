"""
DuckDuckGo Search Tool

Privacy-preserving web search using the duckduckgo_search library.
No API key required.
"""

import logging
from typing import Any

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)


class DuckDuckGoTool(BaseTool):
    """
    Tool for privacy-preserving web search via DuckDuckGo.

    Supports region filtering, safe search levels, and time-limited results.
    Requires no API key.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="duckduckgo_search",
            description="""Search the web using DuckDuckGo — privacy-preserving search with no API key required.

Supports region, safesearch, and time-limit controls.

Examples:
- "Apache Struts RCE CVE"
- "Linux privilege escalation techniques 2024"
- "OWASP Top 10 vulnerabilities"

Returns titles, URLs, and snippets for each result.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 10)",
                        "default": 10,
                    },
                    "region": {
                        "type": "string",
                        "description": "Region code, e.g. 'us-en', 'uk-en' (default: 'wt-wt')",
                        "default": "wt-wt",
                    },
                    "safesearch": {
                        "type": "string",
                        "description": "Safe search level: 'on', 'moderate', 'off' (default: 'off')",
                        "enum": ["on", "moderate", "off"],
                        "default": "off",
                    },
                    "timelimit": {
                        "type": "string",
                        "description": "Time limit: 'd' (day), 'w' (week), 'm' (month), 'y' (year), or None",
                        "default": None,
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(
        self,
        query: str,
        max_results: int = 10,
        region: str = "wt-wt",
        safesearch: str = "off",
        timelimit: str = None,
        **kwargs: Any,
    ) -> str:
        """
        Execute DuckDuckGo web search.

        Args:
            query: Search query
            max_results: Maximum number of results
            region: Region code
            safesearch: Safe search level
            timelimit: Time limit filter

        Returns:
            Formatted search results as string
        """
        try:
            from duckduckgo_search import DDGS

            results = []
            with DDGS() as ddgs:
                for result in ddgs.text(
                    query,
                    region=region,
                    safesearch=safesearch,
                    timelimit=timelimit,
                    max_results=max_results,
                ):
                    results.append(result)

            if not results:
                return f"No results found on DuckDuckGo for query: '{query}'"

            return self._format_results(results, query)

        except ImportError:
            logger.error("duckduckgo_search library not installed")
            return "Error: duckduckgo_search library not installed. Run: pip install duckduckgo-search>=6.0.0"
        except Exception as e:
            logger.error(f"DuckDuckGo search error: {e}", exc_info=True)
            return f"Error executing DuckDuckGo search: {str(e)}"

    def _format_results(self, results: list, query: str) -> str:
        """Format DuckDuckGo results into a readable string."""
        output = [f"DuckDuckGo search results for '{query}':\n"]

        for i, result in enumerate(results, 1):
            title = result.get("title", "No title")
            href = result.get("href", "")
            body = result.get("body", "")

            output.append(f"{i}. {title}")
            if href:
                output.append(f"   URL: {href}")
            if body:
                snippet = body[:250] + "..." if len(body) > 250 else body
                output.append(f"   {snippet}")
            output.append("")

        return "\n".join(output)
