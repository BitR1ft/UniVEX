"""
WebSocket Connection Manager
Handles bidirectional real-time communication for scan updates and agent interactions
"""
from fastapi import WebSocket
from typing import Dict, Set
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates
    Supports room-based messaging for project-specific updates
    """
    
    def __init__(self):
        # Store active connections
        self.active_connections: Dict[str, WebSocket] = {}
        
        # Store connections by project ID (rooms)
        self.project_rooms: Dict[str, Set[str]] = {}
        
        # Store connection metadata
        self.connection_metadata: Dict[str, Dict] = {}
    
    async def connect(
        self, 
        websocket: WebSocket, 
        client_id: str,
        project_id: str = None
    ) -> None:
        """
        Accept and register a new WebSocket connection
        
        Args:
            websocket: WebSocket connection
            client_id: Unique client identifier
            project_id: Optional project ID for room-based messaging
        """
        await websocket.accept()
        
        # Store connection
        self.active_connections[client_id] = websocket
        
        # Store metadata
        self.connection_metadata[client_id] = {
            'connected_at': datetime.utcnow().isoformat(),
            'project_id': project_id
        }
        
        # Join project room if specified
        if project_id:
            if project_id not in self.project_rooms:
                self.project_rooms[project_id] = set()
            self.project_rooms[project_id].add(client_id)
        
        logger.info(f"WebSocket client connected: {client_id} (Project: {project_id})")
        
        # Send connection confirmation
        await self.send_personal_message({
            'type': 'connection_established',
            'client_id': client_id,
            'project_id': project_id,
            'timestamp': datetime.utcnow().isoformat()
        }, client_id)
    
    def disconnect(self, client_id: str) -> None:
        """
        Remove a WebSocket connection
        
        Args:
            client_id: Client identifier to disconnect
        """
        if client_id in self.active_connections:
            # Remove from project room
            metadata = self.connection_metadata.get(client_id, {})
            project_id = metadata.get('project_id')
            
            if project_id and project_id in self.project_rooms:
                self.project_rooms[project_id].discard(client_id)
                
                # Clean up empty rooms
                if not self.project_rooms[project_id]:
                    del self.project_rooms[project_id]
            
            # Remove connection
            del self.active_connections[client_id]
            
            # Remove metadata
            if client_id in self.connection_metadata:
                del self.connection_metadata[client_id]
            
            logger.info(f"WebSocket client disconnected: {client_id}")
    
    async def send_personal_message(self, message: dict, client_id: str) -> None:
        """
        Send a message to a specific client
        
        Args:
            message: Message dictionary to send
            client_id: Target client identifier
        """
        if client_id in self.active_connections:
            try:
                websocket = self.active_connections[client_id]
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict, exclude_client: str = None) -> None:
        """
        Broadcast a message to all connected clients
        
        Args:
            message: Message dictionary to broadcast
            exclude_client: Optional client ID to exclude from broadcast
        """
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            if client_id == exclude_client:
                continue
                
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def broadcast_to_project(
        self, 
        message: dict, 
        project_id: str,
        exclude_client: str = None
    ) -> None:
        """
        Broadcast a message to all clients in a project room
        
        Args:
            message: Message dictionary to broadcast
            project_id: Project room identifier
            exclude_client: Optional client ID to exclude from broadcast
        """
        if project_id not in self.project_rooms:
            return
        
        disconnected_clients = []
        
        for client_id in self.project_rooms[project_id]:
            if client_id == exclude_client:
                continue
            
            if client_id in self.active_connections:
                try:
                    websocket = self.active_connections[client_id]
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id} in project {project_id}: {e}")
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def send_scan_update(
        self, 
        project_id: str, 
        scan_type: str, 
        status: str, 
        data: dict = None
    ) -> None:
        """
        Send scan progress update to project room
        
        Args:
            project_id: Project identifier
            scan_type: Type of scan (e.g., 'subdomain_enum', 'port_scan')
            status: Scan status (e.g., 'started', 'progress', 'completed', 'failed')
            data: Additional data to include in update
        """
        message = {
            'type': 'scan_update',
            'project_id': project_id,
            'scan_type': scan_type,
            'status': status,
            'data': data or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast_to_project(message, project_id)
    
    async def send_agent_message(
        self,
        project_id: str,
        agent_type: str,
        message_text: str,
        level: str = 'info'
    ) -> None:
        """
        Send AI agent message to project room
        
        Args:
            project_id: Project identifier
            agent_type: Type of agent (e.g., 'recon', 'exploit', 'post_exploit')
            message_text: Agent message text
            level: Message level ('info', 'warning', 'error', 'success')
        """
        message = {
            'type': 'agent_message',
            'project_id': project_id,
            'agent_type': agent_type,
            'message': message_text,
            'level': level,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast_to_project(message, project_id)
    
    def get_active_connections_count(self) -> int:
        """Get total number of active connections"""
        return len(self.active_connections)
    
    def get_project_connections_count(self, project_id: str) -> int:
        """Get number of connections for a specific project"""
        return len(self.project_rooms.get(project_id, set()))
    
    async def send_approval_request(
        self,
        project_id: str,
        attack_plan: dict,
        thread_id: str
    ) -> None:
        """
        Send approval request to project room.
        """
        message = {
            'type': 'approval_request',
            'project_id': project_id,
            'thread_id': thread_id,
            'attack_plan': attack_plan,
            'timestamp': datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(message, project_id)

    async def send_progress_update(
        self,
        project_id: str,
        progress: dict
    ) -> None:
        """
        Send progress update to project room.
        """
        message = {
            'type': 'progress_update',
            'project_id': project_id,
            'progress': progress,
            'timestamp': datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(message, project_id)

    async def send_guidance_ack(
        self,
        project_id: str,
        guidance: str
    ) -> None:
        """
        Acknowledge guidance received.
        """
        message = {
            'type': 'guidance_ack',
            'project_id': project_id,
            'guidance': guidance,
            'timestamp': datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(message, project_id)

    def get_status(self) -> dict:
        """Get connection manager status"""
        return {
            'total_connections': self.get_active_connections_count(),
            'active_projects': len(self.project_rooms),
            'project_connections': {
                project_id: len(clients)
                for project_id, clients in self.project_rooms.items()
            }
        }


# Global connection manager instance
connection_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Dependency injection for connection manager"""
    return connection_manager
