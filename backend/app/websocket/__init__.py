"""
WebSocket endpoints for real-time communication
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.websocket.manager import connection_manager as connection_manager, get_connection_manager
import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    client_id: str,
    project_id: str = Query(None),
    token: str = Query(None)
):
    """
    WebSocket endpoint for real-time updates
    
    Args:
        websocket: WebSocket connection
        client_id: Unique client identifier
        project_id: Optional project ID for room-based messaging
        token: Optional JWT token for authentication
    """
    manager = get_connection_manager()
    
    # Optional: Verify token if provided
    # if token:
    #     try:
    #         verify_token(token)
    #     except Exception as e:
    #         logger.warning(f"WebSocket authentication failed for {client_id}: {e}")
    #         await websocket.close(code=1008, reason="Authentication failed")
    #         return
    
    # Connect client
    await manager.connect(websocket, client_id, project_id)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle different message types
                message_type = message.get('type')
                
                if message_type == 'ping':
                    # Respond to ping with pong
                    await manager.send_personal_message({
                        'type': 'pong',
                        'timestamp': message.get('timestamp')
                    }, client_id)
                
                elif message_type == 'broadcast':
                    # Broadcast message to all clients in project
                    if project_id:
                        await manager.broadcast_to_project(
                            {
                                'type': 'message',
                                'from': client_id,
                                'content': message.get('content'),
                                'timestamp': message.get('timestamp')
                            },
                            project_id,
                            exclude_client=client_id
                        )
                
                elif message_type == 'subscribe':
                    # Subscribe to a specific project
                    new_project_id = message.get('project_id')
                    if new_project_id:
                        # Disconnect from current project and connect to new one
                        manager.disconnect(client_id)
                        await manager.connect(websocket, client_id, new_project_id)
                
                else:
                    logger.warning(f"Unknown message type from {client_id}: {message_type}")
            
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from {client_id}: {data}")
                await manager.send_personal_message({
                    'type': 'error',
                    'message': 'Invalid JSON format'
                }, client_id)
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected")
    
    except Exception as e:
        logger.error(f"Error in WebSocket connection for {client_id}: {e}", exc_info=True)
        manager.disconnect(client_id)


@router.get("/ws/status")
async def websocket_status():
    """
    Get WebSocket connection manager status
    """
    manager = get_connection_manager()
    return manager.get_status()
