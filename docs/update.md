# Engineering Specification: UniVex Autonomous Penetration Testing Enhancements (HTB Hard Profile)

**Document Version:** 1.0
**Target Release:** v1.1.0
**Primary Objective:** Elevate autonomous completion rate for complex, non-standard vulnerability environments (e.g., HTB Hard) from current ~15-25% to target 60-70%.

---

## 1. Executive Summary
The UniVex v1.0.0 architecture excels in environments where known CVEs and existing Metasploit modules can be leveraged. However, when faced with custom applications, multi-step exploitation chains, and interactive post-exploitation requirements, the autonomous agent loop breaks down. This specification outlines a comprehensive engineering plan to refactor the agentic reasoning loop, introduce interactive PTY session management, enable dynamic LLM-driven exploit generation, and improve context management.

## 2. Current State & Gap Analysis
Based on the operational baseline against HTB Hard profiles, several critical gaps exist in the current implementation:

| Capability | Current State | Impact | Root Cause |
| :--- | :--- | :--- | :--- |
| **LLM Reasoning** | Highly variable / hallucinates tools | **CRITICAL** | `temperature=0.7` used for tool-selection nodes. |
| **Interactive Shells** | Fails on interactive prompts (`sudo`, `su`) | **CRITICAL** | Lack of PTY allocation; reliance on standard streams. |
| **Custom Exploits** | Outputs empty templates with `# TODO` | **CRITICAL** | `CoderAgent` uses static string formatting instead of LLM generation. |
| **Execution Loop** | Infinite retry loops | **HIGH** | No graph iteration limits defined in `AgentState`. |
| **Source Code Review**| Missing entirely | **HIGH** | No capability to ingest and parse local backend code. |
| **Context Window** | Cuts off critical findings | **HIGH** | Flat 3000-character truncation in `error_handling.py`. |
| **Recon Handoff** | Fails to map ports to exploits | **MEDIUM** | Metasploit dispatch receives only the IP address. |

---

## 3. Architecture & Technical Design

### 3.1. Phase 1: Core Reasoning & Determinism (Immediate Mitigation)

#### 3.1.1. Deterministic Tool Calling
* **Target:** `backend/app/agent/core/react_nodes.py`
* **Implementation:** The `think` node must operate deterministically to ensure reliable tool selection and JSON parameter generation. 
    * Update `_initialize_llm` to instantiate providers with `temperature=0.0`.
    * Increase `max_tokens` (and `max_output_tokens`) from `2000` to `4000` to accommodate deep reasoning chains required for complex pivoting.

#### 3.1.2. Graph Iteration Limits
* **Target:** `backend/app/agent/state/agent_state.py` & `backend/app/agent/core/graph.py`
* **Implementation:** Prevent infinite loops caused by repeated tool failures.
    * Inject `iteration_count: int` into `AgentState`.
    * Update the `should_continue` edge router in `graph.py` to increment the counter. If `iteration_count >= 50`, trigger a forceful transition to `END` via `should_stop = True`.

### 3.2. Phase 2: Execution & State Management

#### 3.2.1. PTY Session Management
* **Target:** `backend/app/mcp/servers/shell_server.py` (New / Refactor)
* **Implementation:** Raw shells hang on interactive applications. We will introduce a pseudo-terminal (PTY) abstraction layer.
    * Implement `PTYSessionManager` using the `pexpect` library.
    * **Methods:**
        * `spawn_shell(command: str) -> str`: Allocates a PTY and returns the initial buffer.
        * `send_and_expect(session_id: str, command: str, expect_pattern: str) -> str`: Allows the agent to look for regex patterns (e.g., `(?i)password:`) and feed subsequent payloads without blocking.

#### 3.2.2. Generic Shell Interaction Tool
* **Target:** `backend/app/agent/tools/post_exploitation_tools.py`
* **Implementation:** The agent must interact seamlessly across Meterpreter, raw netcat, and SSH.
    * Create `ShellCommandTool(BaseTool)`.
    * Implement routing logic based on `session_type`.
    * Expose the `send_and_expect` primitive to the ReAct agent, allowing it to navigate complex TTY menus.

### 3.3. Phase 3: Autonomous Exploit Lifecycle

#### 3.3.1. LLM-Driven Exploit Generation
* **Target:** `backend/app/agent/agents/coder_agent.py`
* **Implementation:** Transition from static templates to dynamic generation.
    * Refactor `generate_exploit()` to compile a strict system prompt containing `vuln_type`, `target_context`, and `service_info`.
    * Enforce output constraints: fully functional code, rigorous error handling, no placeholders, structured markdown response.

#### 3.3.2. Sandboxed Code Execution Tool
* **Target:** `backend/app/agent/tools/exploitation_tools.py`
* **Implementation:** Close the feedback loop by allowing the agent to test generated exploits.
    * Create `CodeExecutorTool(BaseTool)`.
    * **Flow:** Agent generates code -> `CodeExecutorTool` writes to a temporary filesystem inside the Kali MCP container -> executes via `python3` or `bash` -> captures and returns `stdout/stderr` back to the ReAct `observe` node.

### 3.4. Phase 4: Enhanced Analysis & Reasoning Context

#### 3.4.1. Source Code Analysis Tool
* **Target:** `backend/app/agent/tools/source_code_tools.py`
* **Implementation:** 
    * Integrate file download capabilities and reverse-engineering utilities (e.g., `cfr-decompiler` for `.jar`/`.class`).
    * Implement `SourceCodeAnalyzerTool` to read local file contents and construct an analysis prompt tailored for SSTI, deserialization, LFI, and hardcoded secrets.

#### 3.4.2. Smart Context Truncation
* **Target:** `backend/app/agent/tools/error_handling.py`
* **Implementation:** 
    * Replace `truncate_output` with `smart_truncate(output: str, tool_name: str, max_chars: int = 8000)`.
    * **Heuristics:** 
        * `linpeas`: Grep for `SUID`, `sudo`, and `cron` sections.
        * `nmap`/`naabu`: Extract service banners and open ports.
        * `nuclei`: Filter for `[high]` and `[critical]` tags.
        * Fallback: Head (4000) + Tail (4000).

#### 3.4.3. Reflection & Self-Critique Loop
* **Target:** `backend/app/agent/core/react_nodes.py`
* **Implementation:** 
    * Create a `reflect` node in `graph.py`.
    * Trigger condition: `iteration_count % 10 == 0`.
    * Inject a highly weighted system prompt: *"You have attempted X, Y, and Z. All failed. Analyze the overarching strategy and suggest a pivot."*

### 3.5. Phase 5: Data Flow Corrections

#### 3.5.1. Recon to Exploit Data Handoff
* **Target:** `backend/app/agent/agents/exploit_agent.py`
* **Implementation:** 
    * Modify `_run_service_exploitation(self, target: str, recon_results: dict)`.
    * Iterate through `recon_results.get("services", [])`.
    * Thread the extracted `port`, `name`, and `version` into the Metasploit dispatch call, ensuring modules are properly configured.

---

## 4. Implementation Phasing & Milestones

### Phase 1: Foundation (Days 1-2)
- **Goal:** Stabilize agent behavior and execution safety.
- **Tasks:** Temperature adjustments, token limits, iteration counters, and Recon -> Exploit handoff logic.
- **Success Criteria:** Agent stops looping infinitely and correctly utilizes recon data.

### Phase 2: Execution (Days 3-5)
- **Goal:** Enable interactive shell access.
- **Tasks:** `PTYSessionManager`, `ShellCommandTool`.
- **Success Criteria:** Agent successfully upgrades a reverse shell to a fully interactive TTY and reads a root flag requiring `sudo`.

### Phase 3: Generation & Feedback (Days 6-8)
- **Goal:** Dynamic exploit creation.
- **Tasks:** `CoderAgent` LLM integration, `CodeExecutorTool`.
- **Success Criteria:** Agent writes, tests, debugs, and successfully executes a custom Python exploit.

### Phase 4: Advanced Reasoning (Days 9-10)
- **Goal:** Deep context comprehension.
- **Tasks:** `SourceCodeAnalyzerTool`, `smart_truncate`, Reflection node.
- **Success Criteria:** Agent successfully audits a downloaded PHP file and identifies an authentication bypass.

---

## 5. Rollback & Risk Mitigation
* **Risk:** The LLM-generated exploit code (`CodeExecutorTool`) could inadvertently harm the host system.
* **Mitigation:** The executor tool operates strictly inside the isolated Kali Linux MCP Docker container. Volumes are mounted read-only where appropriate.
* **Risk:** High LLM token costs due to larger context windows.
* **Mitigation:** The `smart_truncate` utility acts as a strict firewall on token usage, combined with the hard 50-iteration cutoff limit.

## 6. Testing Strategy
* Unit tests for `smart_truncate` parsing heuristics.
* Mocked LLM interactions for testing the `reflect` node execution path.
* Integration test using an internal HTB-style vulnerable Docker container specifically requiring a custom Python PoC and an interactive `su` prompt.
