"""
ReAct Pattern Nodes

Implements the Reasoning, Action, and Observation nodes for the agent.
Enhanced with structured reasoning, multi-line parsing, context summarization,
and error recovery guidance.
"""

import json
import logging
from typing import Dict, Any, List
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq

from ..state.agent_state import AgentState, Phase
from ..prompts.system_prompts import get_system_prompt
from ..tools.error_handling import truncate_output, ToolExecutionError, ToolTimeoutError

logger = logging.getLogger(__name__)

# Maximum number of messages before triggering context summarization
MAX_CONTEXT_MESSAGES = 20

# Truncation limits for context summarization
MAX_FINDING_SUMMARY_LENGTH = 200
MAX_TOOL_OUTPUT_SUMMARY_LENGTH = 150

# Common tool errors mapped to recovery suggestions
TOOL_ERROR_RECOVERY: Dict[str, str] = {
    "timeout": "The tool timed out. Try reducing the scope (fewer ports, smaller wordlist) or increasing the timeout.",
    "connection": "Connection failed. Verify the target is reachable and the service is running.",
    "permission": "Permission denied. Check if you have the required access level or try a different approach.",
    "not_found": "Resource not found. Verify the target path, module name, or CVE identifier.",
    "parse": "Failed to parse tool output. The target may have returned unexpected data.",
}


class ReActNodes:
    """
    ReAct pattern implementation with think, act, and observe nodes.
    Enhanced with context summarization, structured error recovery,
    and multi-line LLM response parsing.
    """
    
    def __init__(self, model_provider: str = "openai", model_name: str = "gpt-4"):
        """
        Initialize ReAct nodes with LLM.
        
        Args:
            model_provider: "openai", "anthropic", "google", "groq", or "openrouter"
            model_name: Model identifier (e.g., "gpt-4o", "claude-3-5-sonnet-20241022",
                        "gemini-1.5-flash", "llama-3.3-70b-versatile",
                        "anthropic/claude-3.5-sonnet")
        """
        self.model_provider = model_provider
        self.model_name = model_name
        self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize the LLM based on provider"""
        if self.model_provider == "openai":
            self.llm = ChatOpenAI(
                model=self.model_name,
                temperature=0.7,
                max_tokens=2000,
            )
        elif self.model_provider == "anthropic":
            self.llm = ChatAnthropic(
                model=self.model_name,
                temperature=0.7,
                max_tokens=2000,
            )
        elif self.model_provider == "google":
            self.llm = ChatGoogleGenerativeAI(
                model=self.model_name,
                temperature=0.7,
                max_output_tokens=2000,
            )
        elif self.model_provider == "groq":
            self.llm = ChatGroq(
                model=self.model_name,
                temperature=0.7,
                max_tokens=2000,
            )
        elif self.model_provider == "openrouter":
            self.llm = ChatOpenAI(
                model=self.model_name,
                temperature=0.7,
                max_tokens=2000,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "https://github.com/BitR1ft/UniVex",
                    "X-Title": "UniVex",
                },
            )
        else:
            raise ValueError(f"Unknown model provider: {self.model_provider}")
    
    def _summarize_context(self, messages: List) -> List:
        """
        Summarize older messages when context grows too large.
        
        Keeps the system prompt, a summary of older messages, and recent messages
        to prevent context overflow while preserving key findings.
        
        Args:
            messages: Full list of conversation messages
            
        Returns:
            Condensed message list with summary
        """
        if len(messages) <= MAX_CONTEXT_MESSAGES:
            return messages
        
        # Keep system messages at the beginning
        system_msgs = [m for m in messages if isinstance(m, SystemMessage)]
        non_system = [m for m in messages if not isinstance(m, SystemMessage)]
        
        # Keep recent messages (last 10)
        recent = non_system[-10:]
        older = non_system[:-10]
        
        # Build a summary of older messages
        findings = []
        tools_used = []
        for msg in older:
            content = msg.content if hasattr(msg, 'content') else str(msg)
            if "THOUGHT:" in content:
                findings.append(content.split("THOUGHT:")[-1].strip()[:MAX_FINDING_SUMMARY_LENGTH])
            if "Tool output:" in content:
                tools_used.append(content[:MAX_TOOL_OUTPUT_SUMMARY_LENGTH])
        
        summary_parts = []
        if findings:
            summary_parts.append("Key reasoning steps:\n- " + "\n- ".join(findings[-5:]))
        if tools_used:
            summary_parts.append("Recent tool results:\n- " + "\n- ".join(tools_used[-3:]))
        
        summary_text = "\n\n".join(summary_parts) if summary_parts else "Previous conversation history (summarized)"
        
        summary_msg = AIMessage(
            content=f"[CONTEXT SUMMARY - {len(older)} earlier messages condensed]\n{summary_text}"
        )
        
        return system_msgs + [summary_msg] + recent
    
    def _get_error_recovery_hint(self, error_message: str) -> str:
        """
        Get a recovery suggestion based on the error type.
        
        Args:
            error_message: The error message from tool execution
            
        Returns:
            Recovery hint string
        """
        error_lower = error_message.lower()
        for keyword, hint in TOOL_ERROR_RECOVERY.items():
            if keyword in error_lower:
                return f"\n\nRecovery suggestion: {hint}"
        return "\n\nRecovery suggestion: Review the error details and try alternative parameters or a different tool."
    
    async def think(self, state: AgentState) -> Dict[str, Any]:
        """
        THINK node: Agent reasons about what to do next.
        
        Analyzes the current state and decides:
        - Which tool to use (if any)
        - What parameters to pass
        - Whether to stop
        
        Returns:
            Updated state with next_action, selected_tool, tool_input
        """
        # Get system prompt for current phase
        system_prompt = get_system_prompt(state["current_phase"])
        
        # Build message history with context summarization
        raw_messages = [SystemMessage(content=system_prompt)] + state["messages"]
        messages = self._summarize_context(raw_messages)
        
        # If we have an observation from previous action, add it
        if state.get("observation"):
            messages.append(AIMessage(content=f"OBSERVATION: {state['observation']}"))
        
        # Include live guidance if provided
        if state.get("guidance"):
            messages.append(HumanMessage(
                content=f"[USER GUIDANCE]: {state['guidance']}"
            ))
        
        # Get available tools for current phase
        from ..tools.tool_registry import get_global_registry
        
        registry = get_global_registry()
        available_tools = registry.get_tools_for_phase(state["current_phase"])
        
        tool_descriptions = []
        for tool_name, tool in available_tools.items():
            meta = registry.get_tool_metadata(tool_name)
            params_info = ""
            if meta and meta.get("parameters"):
                params_info = f" | Parameters: {json.dumps(meta['parameters'])}"
            tool_descriptions.append(f"- {tool_name}: {tool.description}{params_info}")
        
        tools_list = "\n".join(tool_descriptions) if tool_descriptions else "No tools available"
        
        thinking_prompt = f"""
Based on the conversation and any observations, think about what to do next.

Follow this structured reasoning process:
1. Assess what you currently know and what gaps remain
2. Decide if you need to use a tool or can respond directly
3. If using a tool, justify your choice and specify parameters
4. If a previous tool failed, consider why and try a different approach

Available tools in {state["current_phase"].value} phase:
{tools_list}

Format your response as:
THOUGHT: [Your detailed reasoning about the current situation and next steps]
ACTION: [tool_name or "respond"]
TOOL_INPUT: [JSON parameters if using a tool, or your response text if responding directly]
"""
        
        messages.append(HumanMessage(content=thinking_prompt))
        
        # Get LLM response
        response = await self.llm.ainvoke(messages)
        response_text = response.content
        
        # Parse the response to extract action and tool info
        thought, action, tool_input = self._parse_llm_response(response_text)
        
        logger.info(f"Agent thought: {thought[:100]}... | Action: {action}")
        
        # Update state
        updates = {
            "messages": state["messages"] + [AIMessage(content=f"THOUGHT: {thought}")],
        }
        
        if action == "respond":
            # Agent wants to respond directly, not use a tool
            updates["next_action"] = "end"
            updates["should_stop"] = True
            updates["messages"].append(AIMessage(content=tool_input))
        else:
            # Agent wants to use a tool
            updates["next_action"] = "act"
            updates["selected_tool"] = action
            updates["tool_input"] = tool_input
        
        # Clear guidance after it's been consumed
        if state.get("guidance"):
            updates["guidance"] = None
        
        return updates
    
    async def act(self, state: AgentState) -> Dict[str, Any]:
        """
        ACT node: Execute the selected tool.
        
        Takes the tool selection from the think node and executes it.
        Includes structured error handling with recovery suggestions.
        
        Returns:
            Updated state with tool outputs and next_action set to "observe"
        """
        tool_name = state.get("selected_tool")
        tool_input = state.get("tool_input", {})
        
        if not tool_name:
            return {
                "next_action": "think",
                "observation": "No tool was selected. Let me think again."
            }
        
        # Get tool from registry
        from ..tools.tool_registry import get_global_registry
        
        registry = get_global_registry()
        current_phase = state.get("current_phase", Phase.INFORMATIONAL)
        
        # Check if tool is allowed in current phase
        if not registry.is_tool_allowed(tool_name, current_phase):
            return {
                "next_action": "think",
                "observation": (
                    f"Tool '{tool_name}' is not available in {current_phase.value} phase. "
                    f"Available tools: {', '.join(registry.get_tools_for_phase(current_phase).keys())}"
                )
            }
        
        tool = registry.get_tool(tool_name)
        if not tool:
            available = registry.list_all_tools()
            return {
                "next_action": "think",
                "observation": (
                    f"Unknown tool: {tool_name}. "
                    f"Available tools: {', '.join(available)}"
                )
            }
        
        # Ensure tool_input is a dict for **kwargs unpacking
        if not isinstance(tool_input, dict):
            logger.warning(
                f"Tool input for '{tool_name}' is not a dict (got {type(tool_input).__name__}), "
                f"wrapping as {{'input': ...}}"
            )
            tool_input = {"input": tool_input} if tool_input else {}
        
        # Execute the tool with structured error handling
        try:
            logger.info(f"Executing tool '{tool_name}' with input: {str(tool_input)[:200]}")
            output = await tool.execute(**tool_input)
            # Truncate if too long
            output = truncate_output(output, max_chars=3000)
        except ToolTimeoutError as e:
            error_msg = f"Tool '{tool_name}' timed out: {str(e)}"
            output = error_msg + self._get_error_recovery_hint(str(e))
            logger.warning(error_msg)
        except ToolExecutionError as e:
            error_msg = f"Tool '{tool_name}' execution failed: {str(e)}"
            output = error_msg + self._get_error_recovery_hint(str(e))
            logger.warning(error_msg)
        except Exception as e:
            error_msg = f"Tool '{tool_name}' error: {type(e).__name__}: {str(e)}"
            output = error_msg + self._get_error_recovery_hint(str(e))
            logger.error(error_msg, exc_info=True)
        
        # Store tool output
        tool_outputs = state.get("tool_outputs", {})
        tool_outputs[tool_name] = output
        
        return {
            "tool_outputs": tool_outputs,
            "observation": output,
            "next_action": "observe"
        }
    
    async def observe(self, state: AgentState) -> Dict[str, Any]:
        """
        OBSERVE node: Process tool output and decide next step.
        
        Analyzes the tool output and updates the agent's understanding.
        
        Returns:
            Updated state with next_action set to "think" (continue loop)
        """
        observation = state.get("observation", "")
        
        # Add observation to messages
        updates = {
            "messages": state["messages"] + [
                AIMessage(content=f"Tool output: {observation}")
            ],
            "next_action": "think",  # Continue the ReAct loop
        }
        
        return updates
    
    def _parse_llm_response(self, response: str) -> tuple:
        """
        Parse LLM response to extract thought, action, and tool input.
        
        Handles multi-line content for each field by collecting all lines
        between field markers. Supports JSON spread across multiple lines.
        
        Returns:
            (thought, action, tool_input)
        """
        lines = response.strip().split("\n")
        
        thought_lines = []
        action = "respond"
        tool_input_lines = []
        
        current_field = None
        
        for line in lines:
            stripped = line.strip()
            
            if stripped.startswith("THOUGHT:"):
                current_field = "thought"
                thought_lines.append(stripped.replace("THOUGHT:", "", 1).strip())
            elif stripped.startswith("ACTION:"):
                current_field = "action"
                action = stripped.replace("ACTION:", "", 1).strip()
            elif stripped.startswith("TOOL_INPUT:"):
                current_field = "tool_input"
                tool_input_lines.append(stripped.replace("TOOL_INPUT:", "", 1).strip())
            elif current_field == "thought":
                thought_lines.append(stripped)
            elif current_field == "tool_input":
                tool_input_lines.append(stripped)
        
        thought = " ".join(thought_lines).strip()
        tool_input_str = "\n".join(tool_input_lines).strip()
        
        # Parse tool input - try JSON first, fall back to string
        tool_input = {}
        if tool_input_str:
            try:
                tool_input = json.loads(tool_input_str)
            except (json.JSONDecodeError, ValueError):
                # If action is "respond", keep as string for direct response
                tool_input = tool_input_str if action == "respond" else {}
        
        return thought, action, tool_input
