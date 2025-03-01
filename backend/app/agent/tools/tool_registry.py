"""
Tool Registry System

Manages dynamic tool loading and phase-based access control.
"""

from typing import Dict, List, Optional, Type
from app.agent.tools.base_tool import BaseTool
from app.agent.state.agent_state import Phase
import logging

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Registry for managing agent tools with phase-based access control.
    """

    # Maps query intent to preferred tools in priority order
    SEARCH_TOOL_PRIORITY: Dict[str, List[str]] = {
        "exploit_search": ["sploitus_search", "web_search", "duckduckgo_search"],
        "cve_lookup": ["sploitus_search", "perplexity_search", "web_search"],
        "general_osint": ["searxng_search", "duckduckgo_search", "google_search"],
        "ai_analysis": ["perplexity_search", "traversaal_search"],
        "real_time_news": ["traversaal_search", "perplexity_search", "duckduckgo_search"],
        "technical_docs": ["google_search", "duckduckgo_search", "searxng_search"],
    }

    def __init__(self):
        """Initialize tool registry"""
        self._tools: Dict[str, BaseTool] = {}
        self._tool_phases: Dict[str, List[Phase]] = {}
        self._tool_classes: Dict[str, Type[BaseTool]] = {}
    
    def register_tool(
        self, 
        tool: BaseTool, 
        allowed_phases: Optional[List[Phase]] = None
    ):
        """
        Register a tool with optional phase restrictions.
        
        Args:
            tool: Tool instance to register
            allowed_phases: List of phases where tool is available (None = all phases)
        """
        tool_name = tool.name
        self._tools[tool_name] = tool
        self._tool_phases[tool_name] = allowed_phases or list(Phase)
        self._tool_classes[tool_name] = type(tool)
        
        logger.info(f"Registered tool '{tool_name}' for phases: {[p.value for p in self._tool_phases[tool_name]]}")
    
    def unregister_tool(self, tool_name: str):
        """
        Remove a tool from registry.
        
        Args:
            tool_name: Name of tool to remove
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            del self._tool_phases[tool_name]
            del self._tool_classes[tool_name]
            logger.info(f"Unregistered tool '{tool_name}'")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """
        Get a tool by name.
        
        Args:
            tool_name: Name of tool
            
        Returns:
            Tool instance or None
        """
        return self._tools.get(tool_name)
    
    def get_tools_for_phase(self, phase: Phase) -> Dict[str, BaseTool]:
        """
        Get all tools available for a specific phase.
        
        Args:
            phase: Current agent phase
            
        Returns:
            Dictionary of tool name -> tool instance
        """
        available_tools = {}
        
        for tool_name, tool in self._tools.items():
            allowed_phases = self._tool_phases.get(tool_name, [])
            if phase in allowed_phases:
                available_tools[tool_name] = tool
        
        return available_tools
    
    def is_tool_allowed(self, tool_name: str, phase: Phase) -> bool:
        """
        Check if a tool is allowed in a specific phase.
        
        Args:
            tool_name: Name of tool
            phase: Current phase
            
        Returns:
            True if tool is allowed
        """
        if tool_name not in self._tool_phases:
            return False
        
        allowed_phases = self._tool_phases[tool_name]
        return phase in allowed_phases
    
    def list_all_tools(self) -> List[str]:
        """
        List all registered tool names.
        
        Returns:
            List of tool names
        """
        return list(self._tools.keys())
    
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict]:
        """
        Get tool metadata.
        
        Args:
            tool_name: Name of tool
            
        Returns:
            Tool metadata dictionary or None
        """
        tool = self.get_tool(tool_name)
        if tool:
            return {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.metadata.parameters,
                "allowed_phases": [p.value for p in self._tool_phases.get(tool_name, [])]
            }
        return None
    
    def get_all_tool_metadata(self, phase: Optional[Phase] = None) -> List[Dict]:
        """
        Get metadata for all tools, optionally filtered by phase.
        
        Args:
            phase: Optional phase filter
            
        Returns:
            List of tool metadata dictionaries
        """
        if phase:
            tools = self.get_tools_for_phase(phase)
        else:
            tools = self._tools
        
        return [
            self.get_tool_metadata(tool_name)
            for tool_name in tools.keys()
        ]

    def register_search_tools(self) -> None:
        """
        Register search engine and OSINT source tools.

        Registers the following tools under the osint_and_recon phase
        (INFORMATIONAL and EXPLOITATION phases):
          - sploitus_search   — exploit DB / PoC search
          - duckduckgo_search — privacy-preserving web search
          - perplexity_search — AI-powered search (requires PERPLEXITY_API_KEY)
          - searxng_search    — self-hosted meta-search (requires running SearXNG)
          - traversaal_search — Traversaal Ares AI search (requires TRAVERSAAL_API_KEY)
          - google_search     — Google CSE (requires GOOGLE_API_KEY + GOOGLE_CSE_ID)
          - web_search        — existing Tavily-backed web search
        """
        from app.agent.tools.search.sploitus_tool import SploitusTool
        from app.agent.tools.search.duckduckgo_tool import DuckDuckGoTool
        from app.agent.tools.search.perplexity_tool import PerplexityTool
        from app.agent.tools.search.searxng_tool import SearxngTool
        from app.agent.tools.search.traversaal_tool import TraversaalTool
        from app.agent.tools.search.google_search_tool import GoogleCustomSearchTool
        from app.agent.tools.web_search_tool import WebSearchTool

        osint_phases = [Phase.INFORMATIONAL, Phase.EXPLOITATION]

        self.register_tool(SploitusTool(), allowed_phases=osint_phases)
        self.register_tool(DuckDuckGoTool(), allowed_phases=osint_phases)
        self.register_tool(PerplexityTool(), allowed_phases=osint_phases)
        self.register_tool(SearxngTool(), allowed_phases=osint_phases)
        self.register_tool(TraversaalTool(), allowed_phases=osint_phases)
        self.register_tool(GoogleCustomSearchTool(), allowed_phases=osint_phases)
        self.register_tool(WebSearchTool(), allowed_phases=osint_phases)

        logger.info("Registered search tools (osint_and_recon phase)")


def create_default_registry() -> ToolRegistry:
    """
    Create default tool registry with standard tools.
    
    Returns:
        Configured ToolRegistry instance
    """
    from app.agent.tools import (
        EchoTool, 
        CalculatorTool, 
        QueryGraphTool, 
        WebSearchTool,
        NaabuTool,
        CurlTool,
        NucleiTool,
        MetasploitTool,
        ExploitExecuteTool,
        BruteForceTool,
        SessionManagerTool,
        FileOperationsTool,
        SystemEnumerationTool,
        PrivilegeEscalationTool,
        FfufFuzzDirsTool,
        FfufFuzzFilesTool,
        FfufFuzzParamsTool,
        SQLMapDetectTool,
        SQLMapDatabasesTool,
        SQLMapTablesTool,
        SQLMapColumnsTool,
        SQLMapDumpTool,
        LinPEASTool,
        WinPEASTool,
        HashCrackTool,
        CredentialReuseTool,
        FlagCaptureTool,
        SearchSploitTool,
        WPScanTool,
        NiktoAgentTool,
        SSHLoginTool,
        SSHKeyExtractTool,
        ReverseShellTool,
        SNMPTool,
        AnonymousFTPTool,
        KerbrouteTool,
        Enum4LinuxTool,
        ASREPRoastTool,
        KerberoastTool,
        PassTheHashTool,
        LDAPEnumTool,
        CrackMapExecTool,
        # XSS tools
        ReflectedXSSTool,
        StoredXSSTool,
        DOMXSSTool,
        # CSRF / SSRF / Open Redirect tools
        CSRFDetectTool,
        CSRFExploitTool,
        SSRFProbeTool,
        SSRFBlindTool,
        OpenRedirectTool,
        # IDOR & Access Control tools
        IDORDetectTool,
        IDORExploitTool,
        PrivilegeEscalationWebTool,
        AuthBypassTool,
        SessionPuzzlingTool,
        RateLimitBypassTool,
        # JWT, OAuth & Token Attack tools
        JWTAnalyzeTool,
        JWTBruteForceTool,
        JWTForgeTool,
        OAuthFlowTool,
        OAuthTokenLeakTool,
        APIKeyLeakTool,
        # API Security Testing (REST, GraphQL, gRPC)
        OpenAPIParserTool,
        APIFuzzTool,
        MassAssignmentTool,
        GraphQLIntrospectionTool,
        GraphQLInjectionTool,
        GraphQLIDORTool,
        APIRateLimitTool,
        CORSMisconfigTool,
        # Advanced Web Injection (NoSQL, SSTI, LDAP, XXE, Command Injection)
        NoSQLInjectionTool,
        SSTIDetectTool,
        SSTIExploitTool,
        LDAPInjectionTool,
        XXETool,
        CommandInjectionTool,
        HeaderInjectionTool,
    )
    
    registry = ToolRegistry()
    
    # Development/testing tools (all phases)
    registry.register_tool(
        EchoTool(),
        allowed_phases=list(Phase)
    )
    
    registry.register_tool(
        CalculatorTool(),
        allowed_phases=list(Phase)
    )
    
    # Information gathering tools (INFORMATIONAL phase)
    registry.register_tool(
        QueryGraphTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        WebSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        NaabuTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    
    registry.register_tool(
        CurlTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        NucleiTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    # Exploitation tools (EXPLOITATION phase only)
    registry.register_tool(
        MetasploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        ExploitExecuteTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        BruteForceTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        SessionManagerTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    # Post-exploitation tools
    registry.register_tool(
        FileOperationsTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        SystemEnumerationTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        PrivilegeEscalationTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )

    registry.register_tool(
        FfufFuzzDirsTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        FfufFuzzFilesTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        FfufFuzzParamsTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        SQLMapDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapDatabasesTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapTablesTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapColumnsTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapDumpTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )

    registry.register_tool(
        LinPEASTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        WinPEASTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        HashCrackTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        CredentialReuseTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        FlagCaptureTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )

    registry.register_tool(
        SearchSploitTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        WPScanTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        NiktoAgentTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        SSHLoginTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        SSHKeyExtractTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        ReverseShellTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SNMPTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    registry.register_tool(
        AnonymousFTPTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        KerbrouteTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        Enum4LinuxTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    registry.register_tool(
        ASREPRoastTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        KerberoastTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        PassTheHashTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        LDAPEnumTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        CrackMapExecTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )

    # XSS Detection & Exploitation Engine
    registry.register_tool(
        ReflectedXSSTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        StoredXSSTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        DOMXSSTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # CSRF, SSRF & Request Forgery Toolkit
    registry.register_tool(
        CSRFDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        CSRFExploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSRFProbeTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSRFBlindTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        OpenRedirectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # IDOR & Access Control Testing Suite
    registry.register_tool(
        IDORDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        IDORExploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        PrivilegeEscalationWebTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        AuthBypassTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SessionPuzzlingTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        RateLimitBypassTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # JWT, OAuth & Token Attack Suite
    registry.register_tool(
        JWTAnalyzeTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        JWTBruteForceTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        JWTForgeTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        OAuthFlowTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        OAuthTokenLeakTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        APIKeyLeakTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # API Security Testing (REST, GraphQL, gRPC)
    registry.register_tool(
        OpenAPIParserTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        APIFuzzTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        MassAssignmentTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        GraphQLIntrospectionTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        GraphQLInjectionTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        GraphQLIDORTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        APIRateLimitTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        CORSMisconfigTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # Advanced Web Injection (NoSQL, SSTI, LDAP, XXE, Command Injection)
    registry.register_tool(
        NoSQLInjectionTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSTIDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSTIExploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        LDAPInjectionTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        XXETool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        CommandInjectionTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        HeaderInjectionTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    from app.agent.tools.browser_tool import (
        BrowserTool,
        BrowserScreenshotTool,
        BrowserExtractTextTool,
        BrowserClickTool,
        BrowserFillFormTool,
        BrowserGetCookiesTool,
        BrowserGetLocalStorageTool,
    )
    from app.agent.tools.oob_tool import (
        OOBGenerateURLTool,
        OOBCheckTool,
        OOBWaitTool,
        OOBStatsTool,
    )
    registry.register_tool(
        BrowserTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserScreenshotTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserExtractTextTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserClickTool(),
        allowed_phases=[Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserFillFormTool(),
        allowed_phases=[Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserGetCookiesTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        BrowserGetLocalStorageTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        OOBGenerateURLTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        OOBCheckTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        OOBWaitTool(),
        allowed_phases=[Phase.EXPLOITATION],
    )
    registry.register_tool(
        OOBStatsTool(),
        allowed_phases=list(Phase),
    )

    from app.agent.tools.subdomain_tools import (
        SubdomainTakeoverTool,
        DanglingCNAMEDetectTool,
        DNSZoneTransferTool,
        DNSCacheSnoopTool,
    )
    registry.register_tool(
        SubdomainTakeoverTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        DanglingCNAMEDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        DNSZoneTransferTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        DNSCacheSnoopTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )

    from app.agent.tools.js_analysis_tools import (
        JSEndpointExtractTool,
        JSSecretFinderTool,
        JSLibVulnTool,
        SourceMapAnalyzeTool,
        DOMSinkAnalyzerTool,
    )
    registry.register_tool(
        JSEndpointExtractTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        JSSecretFinderTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        JSLibVulnTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        SourceMapAnalyzeTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        DOMSinkAnalyzerTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )

    from app.agent.tools.recon_extended_tools import (
        WaybackUrlsTool,
        GAUTool,
        ParamSpiderTool,
        KatanaCrawlerTool,
        WebArchiveSearchTool,
    )
    registry.register_tool(
        WaybackUrlsTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        GAUTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        ParamSpiderTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        KatanaCrawlerTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        WebArchiveSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )

    from app.agent.tools.osint_tools import (
        ShodanSearchTool,
        ShodanHostTool,
        CensysSearchTool,
        CensysCertSearchTool,
        FOFASearchTool,
        PassiveDNSTool,
    )
    registry.register_tool(
        ShodanSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        ShodanHostTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        CensysSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        CensysCertSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )
    registry.register_tool(
        FOFASearchTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        PassiveDNSTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )

    from app.agent.tools.waf_tools import (
        WAFDetectTool,
        WAFBypassTool,
        PayloadEncoderTool,
        WAFFingerprintTool,
    )
    registry.register_tool(
        WAFDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        WAFBypassTool(),
        allowed_phases=[Phase.EXPLOITATION],
    )
    registry.register_tool(
        PayloadEncoderTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        WAFFingerprintTool(),
        allowed_phases=[Phase.INFORMATIONAL],
    )

    from app.agent.tools.packet_tools import (
        PacketCaptureTool,
        PcapAnalyzeTool,
        CredentialSnifferTool,
        ProtocolAnalyzerTool,
    )
    registry.register_tool(
        PacketCaptureTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        PcapAnalyzeTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        CredentialSnifferTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        ProtocolAnalyzerTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )

    from app.agent.tools.webshell_tools import (
        WebShellDeployTool,
        WebShellInteractTool,
    )
    from app.agent.tools.upload_tools import (
        FileUploadBypassTool,
        CORSExploitChainTool,
        CacheDeceptionTool,
    )
    registry.register_tool(
        WebShellDeployTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        WebShellInteractTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION],
    )
    registry.register_tool(
        FileUploadBypassTool(),
        allowed_phases=[Phase.EXPLOITATION],
    )
    registry.register_tool(
        CORSExploitChainTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )
    registry.register_tool(
        CacheDeceptionTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION],
    )

    logger.info(f"Created default tool registry with {len(registry.list_all_tools())} tools")
    
    return registry


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_global_registry() -> ToolRegistry:
    """
    Get or create the global tool registry.
    
    Returns:
        Global ToolRegistry instance
    """
    global _global_registry
    
    if _global_registry is None:
        _global_registry = create_default_registry()
    
    return _global_registry
