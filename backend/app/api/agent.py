"""
AI Agent API Endpoints

Provides REST and WebSocket endpoints for agent interactions.

Security: ALL endpoints require a valid JWT bearer token.
Rate limiting: POST /chat is limited to 20 messages/min/user to prevent LLM cost runaway.
Isolation: active_agents dict is keyed by (user_id, thread_id) so users cannot
  control each other's agent threads.
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel, Field
from typing import Optional, Dict
import logging
import uuid

from ..agent import Agent
from ..websocket.manager import get_connection_manager, ConnectionManager
from app.api.auth import get_current_user_id
from app.core.rate_limit import agent_limiter
from app.core.security import decode_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])


# Request/Response Models
class ChatRequest(BaseModel):
    """Chat request model"""
    message: str = Field(..., description="User message to send to the agent")
    thread_id: Optional[str] = Field(None, description="Thread ID for conversation continuity")
    project_id: Optional[str] = Field(None, description="Project ID for context")
    model_provider: str = Field("openai", description="LLM provider (openai, anthropic, google, groq, or openrouter)")
    model_name: str = Field("gpt-4", description="Model name")


class ChatResponse(BaseModel):
    """Chat response model"""
    response: str = Field(..., description="Agent's response")
    thread_id: str = Field(..., description="Thread ID for this conversation")
    phase: str = Field(..., description="Current operational phase")


class AgentStatus(BaseModel):
    """Agent status model"""
    available: bool = Field(..., description="Whether agent is available")
    model_providers: list = Field(..., description="Available LLM providers")
    default_model: str = Field(..., description="Default model name")


class StopRequest(BaseModel):
    """Stop agent request model"""
    thread_id: str = Field(..., description="Thread ID of the agent to stop")


class StopResponse(BaseModel):
    """Stop agent response model"""
    thread_id: str = Field(..., description="Thread ID of the stopped agent")
    status: str = Field(..., description="Stop status")


class ResumeRequest(BaseModel):
    """Resume agent request model"""
    thread_id: str = Field(..., description="Thread ID of the agent to resume")
    message: Optional[str] = Field(None, description="Optional message to send on resume")


class ResumeResponse(BaseModel):
    """Resume agent response model"""
    thread_id: str = Field(..., description="Thread ID of the resumed agent")
    status: str = Field(..., description="Resume status")


class GuidanceRequest(BaseModel):
    """Guidance request model"""
    thread_id: str = Field(..., description="Thread ID of the agent")
    guidance: str = Field(..., description="Guidance text to send to the agent")


class GuidanceResponse(BaseModel):
    """Guidance response model"""
    thread_id: str = Field(..., description="Thread ID of the agent")
    status: str = Field(..., description="Guidance status")


class ApproveRequest(BaseModel):
    """Approve/reject operation request model"""
    thread_id: str = Field(..., description="Thread ID of the agent")
    approved: bool = Field(..., description="Whether the operation is approved")


class ApproveResponse(BaseModel):
    """Approve/reject operation response model"""
    thread_id: str = Field(..., description="Thread ID of the agent")
    status: str = Field(..., description="Approval status")


# ---------------------------------------------------------------------------
# Per-user agent registry
# Structure: { user_id: { thread_id: Agent } }
# ---------------------------------------------------------------------------
_active_agents: Dict[str, Dict[str, Agent]] = {}


def _get_user_agents(user_id: str) -> Dict[str, Agent]:
    """Return the agent thread dict for user_id, creating it if necessary."""
    if user_id not in _active_agents:
        _active_agents[user_id] = {}
    return _active_agents[user_id]


def _get_agent(user_id: str, thread_id: str) -> Optional[Agent]:
    return _get_user_agents(user_id).get(thread_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=AgentStatus)
async def get_agent_status(
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Get agent availability status. Requires authentication.

    Returns information about available LLM providers and models.
    """
    return AgentStatus(
        available=True,
        model_providers=["openai", "anthropic", "google", "groq", "openrouter"],
        default_model="gpt-4"
    )


@router.post("/chat", response_model=ChatResponse)
async def chat_with_agent(
    request: ChatRequest,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Send a message to the agent and get a response (non-streaming).

    Requires authentication. Rate-limited to 20 messages per user per minute.
    For streaming responses, use the WebSocket endpoint.
    """
    # Rate limit: 20 agent messages per user per minute
    agent_limiter.check(current_user_id)

    try:
        thread_id = request.thread_id or str(uuid.uuid4())
        user_agents = _get_user_agents(current_user_id)

        if thread_id not in user_agents:
            user_agents[thread_id] = Agent(
                model_provider=request.model_provider,
                model_name=request.model_name,
                enable_memory=True
            )

        agent = user_agents[thread_id]

        result = await agent.chat(
            message=request.message,
            thread_id=thread_id
        )

        agent_messages = [
            msg.content for msg in result["messages"]
            if msg.type == "ai" and not msg.content.startswith("THOUGHT:")
        ]

        response_text = agent_messages[-1] if agent_messages else "No response generated."

        return ChatResponse(
            response=response_text,
            thread_id=thread_id,
            phase=result["current_phase"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop", response_model=StopResponse)
async def stop_agent(
    request: StopRequest,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Stop a running agent owned by the authenticated user.

    Sets should_stop=True on the agent state and stores checkpoint.
    """
    try:
        thread_id = request.thread_id
        user_agents = _get_user_agents(current_user_id)

        if thread_id not in user_agents:
            raise HTTPException(status_code=404, detail=f"No active agent found for thread {thread_id}")

        agent = user_agents[thread_id]
        agent.state["should_stop"] = True

        return StopResponse(
            thread_id=thread_id,
            status="stopped"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping agent: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/resume", response_model=ResumeResponse)
async def resume_agent(
    request: ResumeRequest,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Resume a stopped agent owned by the authenticated user from checkpoint.
    """
    try:
        thread_id = request.thread_id
        user_agents = _get_user_agents(current_user_id)

        if thread_id not in user_agents:
            raise HTTPException(status_code=404, detail=f"No active agent found for thread {thread_id}")

        agent = user_agents[thread_id]
        agent.state["should_stop"] = False

        return ResumeResponse(
            thread_id=thread_id,
            status="resumed"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resuming agent: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/guidance", response_model=GuidanceResponse)
async def send_guidance(
    request: GuidanceRequest,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Send live guidance to an active agent owned by the authenticated user.

    Stores guidance in the agent state.
    """
    try:
        thread_id = request.thread_id
        user_agents = _get_user_agents(current_user_id)

        if thread_id not in user_agents:
            raise HTTPException(status_code=404, detail=f"No active agent found for thread {thread_id}")

        agent = user_agents[thread_id]
        agent.state["guidance"] = request.guidance

        return GuidanceResponse(
            thread_id=thread_id,
            status="guidance_received"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending guidance: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approve", response_model=ApproveResponse)
async def approve_operation(
    request: ApproveRequest,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Approve or reject a pending agent operation for the authenticated user's thread.

    Updates pending_approval status in the agent state.
    """
    try:
        thread_id = request.thread_id
        user_agents = _get_user_agents(current_user_id)

        if thread_id not in user_agents:
            raise HTTPException(status_code=404, detail=f"No active agent found for thread {thread_id}")

        agent = user_agents[thread_id]
        approval_status = "approved" if request.approved else "rejected"
        agent.state["pending_approval"] = {"status": approval_status}

        return ApproveResponse(
            thread_id=thread_id,
            status=approval_status
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing approval: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/{client_id}")
async def agent_websocket(
    websocket: WebSocket,
    client_id: str,
    token: Optional[str] = Query(None, description="JWT access token for WebSocket auth"),
    connection_manager: ConnectionManager = Depends(get_connection_manager),
):
    """
    WebSocket endpoint for streaming agent interactions.

    Authentication: pass ``?token=<access_token>`` as a query parameter.
    The token is validated on connection; unauthenticated connections are
    immediately closed with code 4001.

    Provides real-time streaming of:
    - Agent thoughts (reasoning)
    - Tool executions
    - Final responses

    Expected message format from client:
    {
        "type": "chat",
        "message": "Your message here",
        "thread_id": "optional-thread-id",
        "project_id": "optional-project-id",
        "model_provider": "openai",
        "model_name": "gpt-4"
    }
    """
    # --- WebSocket Auth ---
    current_user_id: Optional[str] = None
    if token:
        try:
            payload = decode_token(token)
            current_user_id = payload.get("sub")
        except Exception:
            pass

    if not current_user_id:
        await websocket.close(code=4001, reason="Unauthorized: valid ?token= required")
        return

    await websocket.accept()

    try:
        await websocket.send_json({
            "type": "connected",
            "client_id": client_id,
            "message": "Agent WebSocket connected"
        })

        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "chat":
                # Rate-check WebSocket chat messages too
                if not agent_limiter.is_allowed(current_user_id):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Rate limit exceeded. Max 20 messages per minute."
                    })
                    continue

                user_message = data.get("message")
                thread_id = data.get("thread_id") or str(uuid.uuid4())
                model_provider = data.get("model_provider", "openai")
                model_name = data.get("model_name", "gpt-4")

                user_agents = _get_user_agents(current_user_id)
                if thread_id not in user_agents:
                    user_agents[thread_id] = Agent(
                        model_provider=model_provider,
                        model_name=model_name,
                        enable_memory=True
                    )

                agent = user_agents[thread_id]

                try:
                    async for chunk in agent.stream_chat(
                        message=user_message,
                        thread_id=thread_id
                    ):
                        await websocket.send_json({
                            "type": "agent_update",
                            "thread_id": thread_id,
                            "data": {
                                "node": list(chunk.keys())[0] if chunk else "unknown",
                                "state_update": {
                                    k: str(v) if not isinstance(v, (dict, list, str, int, float, bool, type(None))) else v
                                    for k, v in (list(chunk.values())[0] if chunk else {}).items()
                                }
                            }
                        })

                    await websocket.send_json({
                        "type": "agent_complete",
                        "thread_id": thread_id,
                        "message": "Agent processing complete"
                    })

                except Exception as e:
                    logger.error(f"Error in agent streaming: {e}", exc_info=True)
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })

            elif message_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif message_type == "stop":
                thread_id = data.get("thread_id", "")
                user_agents = _get_user_agents(current_user_id)
                if thread_id in user_agents:
                    user_agents[thread_id].state["should_stop"] = True
                    await websocket.send_json({
                        "type": "agent_stopped",
                        "thread_id": thread_id,
                        "message": "Agent execution stopped"
                    })

            elif message_type == "guidance":
                thread_id = data.get("thread_id", "")
                guidance_text = data.get("guidance", "")
                user_agents = _get_user_agents(current_user_id)
                if thread_id in user_agents:
                    user_agents[thread_id].state["guidance"] = guidance_text
                await websocket.send_json({
                    "type": "guidance_received",
                    "thread_id": thread_id,
                    "guidance": guidance_text
                })

            elif message_type == "approve":
                thread_id = data.get("thread_id", "")
                approved = data.get("approved", False)
                approval_status = "approved" if approved else "rejected"
                user_agents = _get_user_agents(current_user_id)
                if thread_id in user_agents:
                    user_agents[thread_id].state["pending_approval"] = {"status": approval_status}
                await websocket.send_json({
                    "type": "approval_response",
                    "thread_id": thread_id,
                    "status": approval_status
                })

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown message type: {message_type}"
                })

    except WebSocketDisconnect:
        logger.info(f"Agent WebSocket disconnected: client_id={client_id} user={current_user_id}")
    except Exception as e:
        logger.error(f"Error in agent WebSocket: {e}", exc_info=True)
    finally:
        pass
