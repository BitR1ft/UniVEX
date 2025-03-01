"""
Agent State Definition

Defines the state structure for the LangGraph agent using TypedDict.
"""

from enum import Enum
from typing import TypedDict, List, Dict, Any, Optional
from langchain_core.messages import BaseMessage


class Phase(str, Enum):
    """Agent operation phases"""
    INFORMATIONAL = "informational"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    COMPLETE = "complete"


class AgentState(TypedDict):
    """
    State structure for the LangGraph agent.
    
    This state is passed between nodes in the ReAct pattern.
    """
    # Conversation messages (user input + agent thoughts)
    messages: List[BaseMessage]
    
    # Current operational phase
    current_phase: Phase
    
    # Tool execution outputs
    tool_outputs: Dict[str, Any]
    
    # Project context (target, configuration, etc.)
    project_id: Optional[str]
    
    # Session tracking
    thread_id: str
    
    # Agent's next action (think, act, observe, end)
    next_action: str
    
    # Tool to execute (populated by think node)
    selected_tool: Optional[str]
    
    # Tool input parameters
    tool_input: Optional[Dict[str, Any]]
    
    # Observation from tool execution
    observation: Optional[str]
    
    # Stop flag
    should_stop: bool
    
    # Approval workflow
    pending_approval: Optional[Dict[str, Any]]
    
    # Live guidance from user
    guidance: Optional[str]
    
    # Progress tracking
    progress: Optional[Dict[str, Any]]
    
    # Checkpoint for resume
    checkpoint: Optional[Dict[str, Any]]
