"""
Sploitus Search Tool

Queries the Sploitus exploit database for PoC code, CVE details, and exploit rankings.
"""

import logging
import os
from typing import Any

import httpx

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

SPLOITUS_API_URL = "https://sploitus.com/search"


class SploitusTool(BaseTool):
    """
    Tool for searching Sploitus exploit database.

    Supports queries by CVE identifier, software name, or keyword.
    Returns ranked results with CVSS scores, GitHub links, and PoC snippets.
    """

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("SPLOITUS_API_KEY", "")

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sploitus_search",
            description="""Search Sploitus exploit database for PoC code, CVE exploits, and vulnerability details.

Examples:
- "CVE-2023-44487 exploit"
- "Apache Log4j RCE"
- "WordPress file upload vulnerability"

Returns ranked exploits with CVSS scores, GitHub links, and PoC snippets.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "CVE ID, software name, or vulnerability keyword",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Pagination offset (default: 0)",
                        "default": 0,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to display (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(self, query: str, offset: int = 0, max_results: int = 10, **kwargs: Any) -> str:
        """
        Search Sploitus for exploits matching the query.

        Args:
            query: CVE ID, software name, or keyword
            offset: Pagination offset
            max_results: Maximum results to return

        Returns:
            Formatted string of exploit results
        """
        try:
            payload = {
                "query": query,
                "type": "exploits",
                "sort": "default",
                "offset": offset,
            }

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(SPLOITUS_API_URL, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            return self._format_results(data, query, max_results)

        except httpx.HTTPStatusError as e:
            logger.error(f"Sploitus HTTP error: {e}", exc_info=True)
            return f"Error querying Sploitus (HTTP {e.response.status_code}): {e.response.text[:200]}"
        except httpx.RequestError as e:
            logger.error(f"Sploitus request error: {e}", exc_info=True)
            return f"Error connecting to Sploitus: {str(e)}"
        except Exception as e:
            logger.error(f"Sploitus unexpected error: {e}", exc_info=True)
            return f"Error querying Sploitus: {str(e)}"

    def _format_results(self, data: dict, query: str, max_results: int) -> str:
        """Format Sploitus API response into a readable string."""
        exploits = data.get("exploits", [])
        total = data.get("total", {})
        total_count = total.get("value", len(exploits)) if isinstance(total, dict) else len(exploits)

        if not exploits:
            return f"No exploits found on Sploitus for query: '{query}'"

        output = [f"Sploitus exploit search results for '{query}' ({total_count} total):\n"]

        for i, exploit in enumerate(exploits[:max_results], 1):
            title = exploit.get("title", "Unknown")
            exploit_type = exploit.get("type", "exploit")
            score = exploit.get("score", "N/A")
            cvss = exploit.get("cvss", {})
            cvss_score = cvss.get("score", "N/A") if isinstance(cvss, dict) else "N/A"
            source = exploit.get("source", "")
            href = exploit.get("href", "")
            published = exploit.get("published", "")
            reporter = exploit.get("reporter", "")

            output.append(f"{i}. [{exploit_type.upper()}] {title}")
            if cvss_score != "N/A":
                output.append(f"   CVSS Score: {cvss_score}")
            if score != "N/A":
                output.append(f"   Relevance Score: {score}")
            if published:
                output.append(f"   Published: {published}")
            if reporter:
                output.append(f"   Reporter: {reporter}")
            if source:
                output.append(f"   Source: {source}")
            if href:
                output.append(f"   Link: {href}")
            output.append("")

        return "\n".join(output)
