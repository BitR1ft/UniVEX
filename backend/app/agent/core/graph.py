"""
LangGraph Agent Graph

Creates the state graph for the ReAct agent.
"""

from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from ..state.agent_state import AgentState
from .react_nodes import ReActNodes


def should_continue(state: AgentState) -> str:
    """
    Routing function to determine next node in the graph.
    
    Returns:
        Name of the next node to execute
    """
    if state.get("should_stop", False):
        return "end"
    
    next_action = state.get("next_action", "think")
    
    if next_action == "end":
        return "end"
    elif next_action == "act":
        return "act"
    elif next_action == "approval":
        return "approval"
    elif next_action == "observe":
        return "observe"
    else:
        return "think"


async def approval_gate(state: AgentState) -> Dict[str, Any]:
    """
    Approval gate node: pauses execution for dangerous operations.
    
    If pending_approval is set and not yet approved, holds execution.
    """
    approval = state.get("pending_approval")
    
    if approval and approval.get("status") == "approved":
        return {
            "pending_approval": None,
            "next_action": "act",
        }
    elif approval and approval.get("status") == "rejected":
        from langchain_core.messages import AIMessage
        return {
            "pending_approval": None,
            "next_action": "end",
            "should_stop": True,
            "messages": state["messages"] + [
                AIMessage(content="Operation rejected by user. Stopping execution.")
            ],
        }
    
    # Still pending - keep waiting
    return {"next_action": "end", "should_stop": True}


def create_agent_graph(
    model_provider: str = "openai",
    model_name: str = "gpt-4",
    enable_memory: bool = True
):
    """
    Create the LangGraph state machine for the agent.
    
    Args:
        model_provider: "openai" or "anthropic"
        model_name: Model identifier
        enable_memory: Whether to enable state persistence with MemorySaver
        
    Returns:
        Compiled LangGraph graph
    """
    # Initialize ReAct nodes
    react_nodes = ReActNodes(model_provider=model_provider, model_name=model_name)
    
    # Create state graph
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("think", react_nodes.think)
    workflow.add_node("act", react_nodes.act)
    workflow.add_node("observe", react_nodes.observe)
    workflow.add_node("approval", approval_gate)
    
    # Set entry point
    workflow.set_entry_point("think")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "think",
        should_continue,
        {
            "act": "act",
            "approval": "approval",
            "end": END,
        }
    )
    
    workflow.add_conditional_edges(
        "act",
        should_continue,
        {
            "observe": "observe",
            "think": "think",
        }
    )
    
    workflow.add_conditional_edges(
        "observe",
        should_continue,
        {
            "think": "think",
            "end": END,
        }
    )
    
    workflow.add_conditional_edges(
        "approval",
        should_continue,
        {
            "act": "act",
            "end": END,
        }
    )
    
    # Add memory if enabled
    memory = MemorySaver() if enable_memory else None
    
    # Compile graph
    graph = workflow.compile(checkpointer=memory)
    
    return graph
