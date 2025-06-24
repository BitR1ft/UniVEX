# UniVex — Agent Architecture Documentation

> Complete documentation of the AI agent foundation including architecture,
> session management, tool system, safety model, and streaming.

---

## Overview

UniVex uses a **LLM-powered AI agent** that orchestrates all
reconnaissance and vulnerability assessment tools. The agent can:

1. **Plan** attack surface assessment strategies
2. **Execute** security tools through MCP tool servers
3. **Analyze** results and identify vulnerabilities
4. **Report** findings with actionable recommendations

The agent operates within a **human-in-the-loop** model for dangerous
operations — tool calls flagged as high-risk require explicit user approval.

---

## Architecture

```

                         USER / FRONTEND                          
    Chat UI   SSE Stream  Approval UI            

                                   HTTP + SSE

                     FastAPI Backend (Agent API)                   
                                                                   
  POST /api/agent/chat           AgentSession                  
  GET  /api/agent/sessions/{id}  SessionManager               
  POST /api/agent/approve        ApprovalGate                  
  POST /api/agent/reject         ApprovalGate                  

                                  

                           Agent Core                              
                                                                   
       
     LLM Core       Session         Safety Gate           
    (GPT-4/         Manager       (approval workflows)    
    Claude)                                               
       
                                                               
   
                      Tool Orchestrator                         
      Selects and calls appropriate MCP tool servers            
    

                                   MCP Protocol

                        MCP Tool Servers                           
       
    Naabu      Nuclei     Httpx       Metasploit        
   (ports)    (vulns)    (web)      (exploitation)      
       

```

---

## Code Structure

```
backend/app/agent/
 __init__.py
 config.py              # Agent configuration (model, temperature, limits)
 session_manager.py     # Session lifecycle management
 attack_path_router.py  # Attack path planning and routing
 testing.py             # Agent test utilities
 core/
    agent_loop.py      # Main ReAct agent loop
    streaming.py       # SSE streaming output
    state/
        agent_state.py # Agent state machine
        memory.py      # Conversation memory
 prompts/
    system.py          # System prompt templates
    tools.py           # Tool description prompts
 state/                 # State persistence
 tools/
     base.py            # Tool adapter base class
     recon_tools.py     # Subdomain/DNS tool adapters
     scan_tools.py      # Port/vuln scan adapters
     graph_tools.py     # Graph query tool adapters
```

---

## Agent Execution Flow

### ReAct Loop (Reasoning + Acting)

```
User Message
     
     

  Observe    ← Previous tool results
 (Context)  

      
      

   Think     ← LLM generates reasoning
  (Reason)  

      
      

    Act      ← Select and call tool
 (Tool Use) 

      
       Low-risk tool? → Execute immediately
      
       High-risk tool? → Wait for human approval
               
                Approved → Execute
                Rejected → Return to Think
```

### Session State Machine

```
CREATED → ACTIVE → WAITING_APPROVAL → ACTIVE → COMPLETED
                        
     FAILED
```

---

## Safety Model

### Risk Levels

| Level | Description | Requires Approval? |
|-------|-------------|-------------------|
| LOW | Read-only recon | No |
| MEDIUM | Non-destructive scanning | No |
| HIGH | Potentially impactful scans | Yes |
| CRITICAL | Exploitation / system changes | Always |

### High-Risk Tool Categories

Tools that always require human approval:

- `metasploit_exploit` — Running Metasploit modules
- `sqlmap_run` — SQL injection exploitation
- `bruteforce_*` — Password brute forcing
- `file_write` — Writing files to target systems
- `shell_execute` — Direct shell command execution

### Approval Workflow

```python
# Example: Agent requests a high-risk tool call
{
    "session_id": "sess-uuid",
    "pending_call": {
        "tool": "metasploit_exploit",
        "args": {
            "module": "exploit/multi/handler",
            "target": "192.168.1.1"
        },
        "risk_level": "CRITICAL",
        "reason": "Agent wants to test exploit CVE-2024-12345"
    }
}

# User approves via frontend:
POST /api/agent/approve
{
    "session_id": "sess-uuid",
    "call_id": "call-uuid"
}

# Or rejects:
POST /api/agent/reject
{
    "session_id": "sess-uuid",
    "call_id": "call-uuid",
    "reason": "Not in scope"
}
```

---

## Streaming Output

The agent streams its output using **Server-Sent Events (SSE)**:

```
GET /api/agent/sessions/{id}/stream
Accept: text/event-stream

event: thinking
data: {"type": "thinking", "content": "Analyzing open ports..."}

event: tool_call
data: {"type": "tool_call", "tool": "naabu", "args": {"target": "example.com"}}

event: tool_result
data: {"type": "tool_result", "tool": "naabu", "result": {"ports": [80, 443, 8080]}}

event: approval_required
data: {"type": "approval_required", "tool": "metasploit_exploit", "risk": "CRITICAL"}

event: message
data: {"type": "message", "content": "Found 3 open ports. Port 8080 running outdated Apache."}

event: done
data: {"type": "done", "session_id": "sess-uuid"}
```

---

## Configuration

```python
# backend/app/agent/config.py (simplified)

AGENT_CONFIG = {
    "model": os.environ.get("AGENT_MODEL", "gpt-4-turbo"),
    "temperature": 0.2,           # Low temperature for consistent reasoning
    "max_tokens": 4096,           # Max tokens per LLM response
    "max_iterations": 50,         # Maximum ReAct loop iterations
    "timeout_seconds": 300,       # Session timeout
    "approval_timeout_seconds": 600,  # Time to wait for human approval
    "memory_window": 20,          # Conversation history window (messages)
}
```

---

## Testing the Agent

```python
# backend/app/agent/testing.py
from app.agent.testing import MockAgent, AgentTestRunner

# Unit test an agent interaction
async def test_recon_planning():
    agent = MockAgent()
    response = await agent.chat(
        message="Map the attack surface of example.com",
        project_id="proj-1",
        user_id="user-1"
    )
    assert "subdomain" in response.lower()
    assert agent.tool_calls[0]["tool"] == "subfinder"
```

---

## Agent Metrics

Tracked metrics:

| Metric | Description |
|--------|-------------|
| `agent_sessions_total` | Total sessions created |
| `agent_tool_calls_total{tool, status}` | Tool call success/failure |
| `agent_approval_wait_seconds` | Time waiting for approval |
| `agent_iteration_count` | ReAct iterations per session |
| `agent_token_usage{type}` | LLM token consumption |

---

