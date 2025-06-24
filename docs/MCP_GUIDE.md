# UniVex — MCP Tool Server Guide

> Complete guide to the MCP (Model Context Protocol) tool servers that
> expose security tools to the AI agent and frontend.

---

## Overview

UniVex implements the **Model Context Protocol (MCP)** to expose
security tools as structured, typed functions callable by the AI agent.

Each tool server is a lightweight Python service that:
1. Wraps a security tool (naabu, nuclei, httpx, metasploit)
2. Implements the MCP protocol for tool discovery and invocation
3. Normalizes tool output to structured JSON
4. Enforces rate limiting and input validation

---

## MCP Architecture

```
AI Agent
   
    MCP Protocol (JSON-RPC 2.0)
   
    Naabu Server  (port 8000) — Port discovery
    Httpx Server  (port 8001) — HTTP probing
    Nuclei Server (port 8002) — Vulnerability scanning
    MSF Server    (port 8003) — Metasploit exploitation
```

---

## Code Structure

```
backend/app/mcp/
 __init__.py
 base_server.py     # Base MCP server implementation
 protocol.py        # MCP JSON-RPC protocol handling
 phase_control.py   # Phase-based tool access control
 testing.py         # MCP test utilities
 servers/
     naabu.py       # Naabu port scanner MCP server
     curl.py        # Curl/httpx HTTP probe MCP server
     nuclei.py      # Nuclei vulnerability scanner server
     metasploit.py  # Metasploit framework server
```

---

## MCP Protocol

### Tool Discovery

```json
// Request: List available tools
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "naabu_scan",
        "description": "Fast port scanner for discovering open ports",
        "inputSchema": {
          "type": "object",
          "properties": {
            "target": {
              "type": "string",
              "description": "Target host or CIDR range"
            },
            "ports": {
              "type": "string",
              "description": "Port range (e.g., '80,443,8080-8090')"
            },
            "rate": {
              "type": "integer",
              "description": "Packets per second (default: 1000)"
            }
          },
          "required": ["target"]
        }
      }
    ]
  },
  "id": 1
}
```

### Tool Execution

```json
// Request: Call a tool
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "naabu_scan",
    "arguments": {
      "target": "example.com",
      "ports": "80,443,8080,8443",
      "rate": 500
    }
  },
  "id": 2
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"open_ports\": [{\"port\": 80, \"host\": \"93.184.216.34\", \"protocol\": \"tcp\"}, {\"port\": 443, \"host\": \"93.184.216.34\", \"protocol\": \"tcp\"}]}"
      }
    ]
  },
  "id": 2
}
```

---

## Available Tools

### Naabu Server (Port Discovery)

**Base URL:** `http://localhost:8000` (in Docker: service `kali-tools`)

| Tool | Description | Risk Level |
|------|-------------|------------|
| `naabu_scan` | Fast port scan on target | MEDIUM |
| `naabu_scan_all` | Full port scan (1-65535) | MEDIUM |
| `naabu_cdncheck` | Check if target is behind CDN | LOW |

**Example call:**
```python
from app.mcp.protocol import MCPClient

client = MCPClient("http://localhost:8000")
result = await client.call_tool("naabu_scan", {
    "target": "example.com",
    "ports": "top-1000",
    "rate": 1000
})
# result.ports = [{"port": 80, "host": "...", "protocol": "tcp"}]
```

---

### Httpx Server (HTTP Probing)

| Tool | Description | Risk Level |
|------|-------------|------------|
| `httpx_probe` | Probe URLs for live HTTP services | LOW |
| `httpx_screenshot` | Take screenshots of web pages | LOW |
| `httpx_tech_detect` | Detect technologies via fingerprinting | LOW |
| `httpx_crawl` | Crawl web application | MEDIUM |

**Example call:**
```python
result = await client.call_tool("httpx_probe", {
    "urls": ["http://example.com", "https://example.com"],
    "follow_redirects": True,
    "include_headers": True
})
# result.live_hosts = [{"url": "https://example.com", "status_code": 200, "title": "..."}]
```

---

### Nuclei Server (Vulnerability Scanning)

| Tool | Description | Risk Level |
|------|-------------|------------|
| `nuclei_scan` | Run Nuclei templates against target | HIGH |
| `nuclei_list_templates` | List available templates | LOW |
| `nuclei_update_templates` | Update Nuclei template database | LOW |

**Example call:**
```python
result = await client.call_tool("nuclei_scan", {
    "target": "https://example.com",
    "severity": ["critical", "high", "medium"],
    "tags": ["cve", "misconfig"],
    "rate_limit": 150
})
# result.findings = [{"template_id": "CVE-2024-...", "severity": "high", ...}]
```

---

### Metasploit Server (Exploitation — CRITICAL risk)

> ⚠️ **All Metasploit tools require explicit human approval before execution.**

| Tool | Description | Risk Level |
|------|-------------|------------|
| `msf_search` | Search for exploit modules | LOW |
| `msf_module_info` | Get module details | LOW |
| `msf_run_exploit` | Execute an exploit | CRITICAL |
| `msf_generate_payload` | Generate payload | HIGH |

---

## Phase Control

The `phase_control.py` module restricts which tools are available based on
the current scan phase:

```
Phase 1 (RECON):    Naabu + Httpx only
Phase 2 (SCAN):     Naabu + Httpx + Nuclei
Phase 3 (EXPLOIT):  All tools (Metasploit requires approval)
```

```python
from app.mcp.phase_control import PhaseController, ScanPhase

controller = PhaseController(ScanPhase.RECON)
allowed = controller.get_allowed_tools()
# ["naabu_scan", "naabu_cdncheck", "httpx_probe", "httpx_tech_detect"]
```

---

## Testing MCP Servers

### Unit Tests

```python
# backend/app/mcp/testing.py
from app.mcp.testing import MockMCPServer, MockToolResult

server = MockMCPServer()
server.register_response("naabu_scan", MockToolResult(
    success=True,
    data={"open_ports": [{"port": 80}]}
))

result = await server.call_tool("naabu_scan", {"target": "test.com"})
assert result.data["open_ports"][0]["port"] == 80
```

### Integration Test

```bash
# Start MCP server
python -m app.mcp.servers.naabu --port 8000

# Test tool discovery
curl -X POST http://localhost:8000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# Test tool execution (dry run)
curl -X POST http://localhost:8000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"naabu_scan","arguments":{"target":"127.0.0.1"}},"id":2}'
```

---

## MCP Metrics

| Metric | Description |
|--------|-------------|
| `mcp_tool_calls_total{tool, status}` | Total tool invocations |
| `mcp_tool_duration_seconds{tool}` | Tool execution duration |
| `mcp_tool_errors_total{tool, error_type}` | Tool error counts |
| `mcp_approval_pending_total` | Currently pending approvals |

---

## Security Controls

1. **Input Validation**: All tool arguments validated against JSON schema
2. **Scope Enforcement**: Tools only scan IPs/domains registered in the project
3. **Rate Limiting**: Per-tool rate limits prevent resource exhaustion
4. **Audit Logging**: Every tool call logged with user and project context
5. **Network Isolation**: MCP servers run in isolated Docker network
6. **Approval Gate**: High-risk tools blocked until human approves

---

## Adding a New MCP Tool Server

```python
# 1. Create server file
# backend/app/mcp/servers/my_tool.py

from app.mcp.base_server import BaseMCPServer, Tool, ToolResult

class MyToolServer(BaseMCPServer):
    def get_tools(self) -> list[Tool]:
        return [
            Tool(
                name="my_tool_run",
                description="Run my security tool",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"}
                    },
                    "required": ["target"]
                },
                risk_level="MEDIUM"
            )
        ]

    async def call_tool(self, name: str, args: dict) -> ToolResult:
        if name == "my_tool_run":
            target = args["target"]
            # Run tool subprocess
            output = await self._run_subprocess(["my-tool", target])
            return ToolResult(success=True, data=self._parse_output(output))

# 2. Register in docker-compose.yml
# 3. Add to agent's tool list
# 4. Write tests in tests/mcp/
```

---

