"""Agent tools"""

from .base_tool import BaseTool, ToolMetadata
from .error_handling import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolValidationError,
    ToolRateLimitError,
    ErrorCategory,
    ToolErrorReporter,
    default_reporter,
    categorise_error,
    get_recovery_hint,
    truncate_output,
    with_timeout,
    with_error_context,
    with_retry,
)
from .echo_tool import EchoTool
from .calculator_tool import CalculatorTool
from .query_graph_tool import QueryGraphTool
from .web_search_tool import WebSearchTool
from .mcp_tools import NaabuTool, CurlTool, NucleiTool, MetasploitTool
from .exploitation_tools import ExploitExecuteTool, BruteForceTool, SessionManagerTool
from .post_exploitation_tools import FileOperationsTool, SystemEnumerationTool, PrivilegeEscalationTool

from .tool_adapters import (
    DomainDiscoveryTool,
    PortScanTool,
    HttpProbeTool,
    TechDetectionTool,
    EndpointEnumerationTool,
    NucleiTemplateSelectTool,
    NucleiScanTool,
    AttackSurfaceQueryTool,
    VulnerabilityLookupTool,
    ExploitSearchTool,
    CVELookupTool,
)

from .ffuf_tool import FfufFuzzDirsTool, FfufFuzzFilesTool, FfufFuzzParamsTool

from .sqlmap_tool import (
    SQLMapDetectTool,
    SQLMapDatabasesTool,
    SQLMapTablesTool,
    SQLMapColumnsTool,
    SQLMapDumpTool,
)

from .post_exploitation_extended import (
    LinPEASTool,
    WinPEASTool,
    HashCrackTool,
    CredentialReuseTool,
    FlagCaptureTool,
)

from .searchsploit_tool import SearchSploitTool
from .cms_tools import WPScanTool, NiktoAgentTool

from .network_service_tools import (
    SSHLoginTool,
    SSHKeyExtractTool,
    ReverseShellTool,
    SNMPTool,
    AnonymousFTPTool,
)

from .active_directory_tools import (
    KerbrouteTool,
    Enum4LinuxTool,
    ASREPRoastTool,
    KerberoastTool,
    PassTheHashTool,
    LDAPEnumTool,
    CrackMapExecTool,
)

# XSS Detection & Exploitation Engine
from .xss_tools import ReflectedXSSTool, StoredXSSTool, DOMXSSTool

# CSRF, SSRF & Request Forgery Toolkit
from .csrf_tools import CSRFDetectTool, CSRFExploitTool
from .ssrf_tools import SSRFProbeTool, SSRFBlindTool, OpenRedirectTool

# IDOR & Access Control Testing Suite
from .idor_tools import IDORDetectTool, IDORExploitTool, PrivilegeEscalationWebTool
from .auth_bypass_tools import AuthBypassTool, SessionPuzzlingTool, RateLimitBypassTool

# JWT, OAuth & Token Attack Suite
from .jwt_tools import JWTAnalyzeTool, JWTBruteForceTool, JWTForgeTool
from .oauth_tools import OAuthFlowTool, OAuthTokenLeakTool, APIKeyLeakTool

# API Security Testing (REST, GraphQL, gRPC)
from .api_security_tools import (
    OpenAPIParserTool,
    APIFuzzTool,
    MassAssignmentTool,
    GraphQLIntrospectionTool,
    GraphQLInjectionTool,
    GraphQLIDORTool,
    APIRateLimitTool,
    CORSMisconfigTool,
)

# Advanced Web Injection (NoSQL, SSTI, LDAP, XXE, Command Injection)
from .injection_tools import (
    NoSQLInjectionTool,
    SSTIDetectTool,
    SSTIExploitTool,
    LDAPInjectionTool,
    XXETool,
    CommandInjectionTool,
    HeaderInjectionTool,
)

from .subdomain_tools import (
    SubdomainTakeoverTool,
    DanglingCNAMEDetectTool,
    DNSZoneTransferTool,
    DNSCacheSnoopTool,
)

__all__ = [
    # Base
    "BaseTool",
    "ToolMetadata",
    # Error handling
    "ToolExecutionError",
    "ToolTimeoutError",
    "ToolValidationError",
    "ToolRateLimitError",
    "ErrorCategory",
    "ToolErrorReporter",
    "default_reporter",
    "categorise_error",
    "get_recovery_hint",
    "truncate_output",
    "with_timeout",
    "with_error_context",
    "with_retry",
    # Core tools
    "EchoTool",
    "CalculatorTool",
    "QueryGraphTool",
    "WebSearchTool",
    "NaabuTool",
    "CurlTool",
    "NucleiTool",
    "MetasploitTool",
    "ExploitExecuteTool",
    "BruteForceTool",
    "SessionManagerTool",
    "FileOperationsTool",
    "SystemEnumerationTool",
    "PrivilegeEscalationTool",
    "DomainDiscoveryTool",
    "PortScanTool",
    "HttpProbeTool",
    "TechDetectionTool",
    "EndpointEnumerationTool",
    "NucleiTemplateSelectTool",
    "NucleiScanTool",
    "AttackSurfaceQueryTool",
    "VulnerabilityLookupTool",
    "ExploitSearchTool",
    "CVELookupTool",
    "FfufFuzzDirsTool",
    "FfufFuzzFilesTool",
    "FfufFuzzParamsTool",
    "SQLMapDetectTool",
    "SQLMapDatabasesTool",
    "SQLMapTablesTool",
    "SQLMapColumnsTool",
    "SQLMapDumpTool",
    "LinPEASTool",
    "WinPEASTool",
    "HashCrackTool",
    "CredentialReuseTool",
    "FlagCaptureTool",
    "SearchSploitTool",
    "WPScanTool",
    "NiktoAgentTool",
    "SSHLoginTool",
    "SSHKeyExtractTool",
    "ReverseShellTool",
    "SNMPTool",
    "AnonymousFTPTool",
    "KerbrouteTool",
    "Enum4LinuxTool",
    "ASREPRoastTool",
    "KerberoastTool",
    "PassTheHashTool",
    "LDAPEnumTool",
    "CrackMapExecTool",
    # XSS tools
    "ReflectedXSSTool",
    "StoredXSSTool",
    "DOMXSSTool",
    # CSRF / SSRF / Open Redirect tools
    "CSRFDetectTool",
    "CSRFExploitTool",
    "SSRFProbeTool",
    "SSRFBlindTool",
    "OpenRedirectTool",
    # IDOR & Access Control tools
    "IDORDetectTool",
    "IDORExploitTool",
    "PrivilegeEscalationWebTool",
    "AuthBypassTool",
    "SessionPuzzlingTool",
    "RateLimitBypassTool",
    # JWT, OAuth & Token Attack tools
    "JWTAnalyzeTool",
    "JWTBruteForceTool",
    "JWTForgeTool",
    "OAuthFlowTool",
    "OAuthTokenLeakTool",
    "APIKeyLeakTool",
    # API Security Testing
    "OpenAPIParserTool",
    "APIFuzzTool",
    "MassAssignmentTool",
    "GraphQLIntrospectionTool",
    "GraphQLInjectionTool",
    "GraphQLIDORTool",
    "APIRateLimitTool",
    "CORSMisconfigTool",
    # Advanced Web Injection
    "NoSQLInjectionTool",
    "SSTIDetectTool",
    "SSTIExploitTool",
    "LDAPInjectionTool",
    "XXETool",
    "CommandInjectionTool",
    "HeaderInjectionTool",
    # Subdomain Takeover & DNS tools
    "SubdomainTakeoverTool",
    "DanglingCNAMEDetectTool",
    "DNSZoneTransferTool",
    "DNSCacheSnoopTool",
]
