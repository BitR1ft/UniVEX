"""
Agent Class

High-level interface for the AI agent.
"""

import uuid
from typing import TYPE_CHECKING, Optional, Dict, Any, AsyncIterator
from langchain_core.messages import HumanMessage

from ..state.agent_state import AgentState, Phase
from .graph import create_agent_graph

if TYPE_CHECKING:
    from ..planning import AttackPlanner, AttackPlan


class Agent:
    """
    AI Agent for autonomous penetration testing.
    
    Uses LangGraph with ReAct pattern for reasoning and tool execution.
    """
    
    def __init__(
        self,
        model_provider: str = "openai",
        model_name: str = "gpt-4",
        enable_memory: bool = True,
        enable_planning: bool = False,
    ):
        """
        Initialize the agent.
        
        Args:
            model_provider: "openai" or "anthropic"
            model_name: Model identifier
            enable_memory: Whether to enable state persistence
            enable_planning: Whether to enable the attack planner
        """
        self.model_provider = model_provider
        self.model_name = model_name
        self.graph = create_agent_graph(
            model_provider=model_provider,
            model_name=model_name,
            enable_memory=enable_memory
        )
        self.planner: Optional["AttackPlanner"] = None
        if enable_planning:
            from ..planning import AttackPlanner
            self.planner = AttackPlanner()
    
    def create_initial_state(
        self,
        thread_id: Optional[str] = None,
        project_id: Optional[str] = None,
        phase: Phase = Phase.INFORMATIONAL
    ) -> AgentState:
        """
        Create initial state for a new conversation.
        
        Args:
            thread_id: Thread ID for conversation (generated if not provided)
            project_id: Project ID for context
            phase: Initial operational phase
            
        Returns:
            Initial AgentState
        """
        if not thread_id:
            thread_id = str(uuid.uuid4())
        
        return AgentState(
            messages=[],
            current_phase=phase,
            tool_outputs={},
            project_id=project_id,
            thread_id=thread_id,
            next_action="think",
            selected_tool=None,
            tool_input=None,
            observation=None,
            should_stop=False,
            pending_approval=None,
            guidance=None,
            progress=None,
            checkpoint=None,
        )
    
    async def chat(
        self,
        message: str,
        state: Optional[AgentState] = None,
        thread_id: Optional[str] = None
    ) -> AgentState:
        """
        Send a message to the agent and get a response.
        
        Args:
            message: User message
            state: Current state (creates new if not provided)
            thread_id: Thread ID for memory persistence
            
        Returns:
            Updated AgentState with agent's response
        """
        # Create initial state if not provided
        if state is None:
            state = self.create_initial_state(thread_id=thread_id)
        
        # Add user message to state
        state["messages"].append(HumanMessage(content=message))
        
        # Prepare config for memory
        config = {"configurable": {"thread_id": state["thread_id"]}}
        
        # Run the graph
        result = await self.graph.ainvoke(state, config=config)
        
        return result
    
    async def stream_chat(
        self,
        message: str,
        state: Optional[AgentState] = None,
        thread_id: Optional[str] = None
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream agent's thinking process and responses.
        
        Args:
            message: User message
            state: Current state (creates new if not provided)
            thread_id: Thread ID for memory persistence
            
        Yields:
            State updates as they occur
        """
        # Create initial state if not provided
        if state is None:
            state = self.create_initial_state(thread_id=thread_id)
        
        # Add user message to state
        state["messages"].append(HumanMessage(content=message))
        
        # Prepare config for memory
        config = {"configurable": {"thread_id": state["thread_id"]}}
        
        # Stream the graph execution
        async for chunk in self.graph.astream(state, config=config):
            yield chunk

    # ------------------------------------------------------------------
    # Planning methods
    # ------------------------------------------------------------------

    def create_plan(
        self,
        target: str,
        objective: str,
        recon_data: dict,
        session_id: Optional[str] = None,
    ) -> "AttackPlan":
        """Create an attack plan using the planner."""
        if self.planner is None:
            raise RuntimeError("Planning is not enabled. Pass enable_planning=True.")
        return self.planner.create_plan(target, objective, recon_data, session_id)

    def explain_plan(self, plan: "AttackPlan") -> str:
        """Return a human-readable explanation of the plan."""
        if self.planner is None:
            raise RuntimeError("Planning is not enabled. Pass enable_planning=True.")
        return self.planner.explain_plan(plan)

    def get_plan_diagram(self, plan: "AttackPlan") -> str:
        """Return the Mermaid diagram for the plan."""
        return plan.to_mermaid()
