"""Example Shodan Plugin — demonstrates the UniVex plugin interface."""

from __future__ import annotations

from typing import Any, Dict, List

from app.plugins.base_plugin import BasePlugin, PluginManifest
from app.plugins.plugin_tool import PluginTool, PluginToolMetadata


class ShodanSearchTool(PluginTool):
    """Stub tool: search Shodan for hosts matching a query."""

    def _define_metadata(self) -> PluginToolMetadata:
        return PluginToolMetadata(
            name="shodan_search",
            description="Search Shodan.io for hosts matching a dork query.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Shodan dork query"},
                },
                "required": ["query"],
            },
        )

    async def execute(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        return f"[Shodan stub] Search results for: {query}"


class ShodanHostLookupTool(PluginTool):
    """Stub tool: look up a host on Shodan by IP address."""

    def _define_metadata(self) -> PluginToolMetadata:
        return PluginToolMetadata(
            name="shodan_host_lookup",
            description="Look up detailed information about an IP address on Shodan.",
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to look up"},
                },
                "required": ["ip"],
            },
        )

    async def execute(self, **kwargs) -> str:
        ip = kwargs.get("ip", "")
        return f"[Shodan stub] Host info for: {ip}"


class ShodanPlugin(BasePlugin):
    """Example plugin: Shodan.io integration for host intelligence."""

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            name="shodan",
            version="1.0.0",
            description="Shodan.io integration for host intelligence",
            author="UniVex Community",
            tags=["recon", "osint", "shodan"],
        )

    def register_tools(self) -> List[Any]:
        return [ShodanSearchTool(), ShodanHostLookupTool()]

    def register_mcp_servers(self) -> List[Dict[str, Any]]:
        return [{"name": "shodan-mcp", "host": "localhost", "port": 9100}]

    def register_api_routes(self) -> List[Any]:
        return []

    def health_check(self) -> Dict[str, Any]:
        return {
            "healthy": True,
            "message": "Shodan API key required",
            "requires_config": ["SHODAN_API_KEY"],
        }


def get_plugin() -> ShodanPlugin:
    """Factory function required by PluginLoader."""
    return ShodanPlugin()
