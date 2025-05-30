"""Example Censys Plugin — demonstrates the UniVex plugin interface."""

from __future__ import annotations

from typing import Any, Dict, List

from app.plugins.base_plugin import BasePlugin, PluginManifest
from app.plugins.plugin_tool import PluginTool, PluginToolMetadata


class CensysSearchTool(PluginTool):
    """Stub tool: search Censys for hosts/certificates matching a query."""

    def _define_metadata(self) -> PluginToolMetadata:
        return PluginToolMetadata(
            name="censys_search",
            description="Search Censys.io for hosts or services matching a query.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Censys search query"},
                    "index": {
                        "type": "string",
                        "description": "Index to search: hosts or certificates",
                        "enum": ["hosts", "certificates"],
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        index = kwargs.get("index", "hosts")
        return f"[Censys stub] {index} search results for: {query}"


class CensysCertsTool(PluginTool):
    """Stub tool: look up TLS certificates for a domain on Censys."""

    def _define_metadata(self) -> PluginToolMetadata:
        return PluginToolMetadata(
            name="censys_certs",
            description="Retrieve TLS certificate information for a domain from Censys.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to look up"},
                },
                "required": ["domain"],
            },
        )

    async def execute(self, **kwargs) -> str:
        domain = kwargs.get("domain", "")
        return f"[Censys stub] Certificates for: {domain}"


class CensysPlugin(BasePlugin):
    """Example plugin: Censys.io integration for internet-wide scanning data."""

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            name="censys",
            version="1.0.0",
            description="Censys.io integration for internet-wide scanning and certificate data",
            author="UniVex Community",
            tags=["recon", "osint", "censys"],
        )

    def register_tools(self) -> List[Any]:
        return [CensysSearchTool(), CensysCertsTool()]

    def register_mcp_servers(self) -> List[Dict[str, Any]]:
        return [{"name": "censys-mcp", "host": "localhost", "port": 9101}]

    def register_api_routes(self) -> List[Any]:
        return []

    def health_check(self) -> Dict[str, Any]:
        return {
            "healthy": True,
            "message": "Censys API credentials required",
            "requires_config": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
        }


def get_plugin() -> CensysPlugin:
    """Factory function required by PluginLoader."""
    return CensysPlugin()
