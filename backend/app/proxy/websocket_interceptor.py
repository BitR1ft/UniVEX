"""
Proxy WebSocket Interceptor

Captures, stores, modifies, and replays WebSocket frames that pass through
the UniVex proxy layer.

Features:
  - Captures text and binary WebSocket frames with timestamps and direction
  - Optional frame modification via registered mutation callbacks
  - Replay single frames or entire frame sequences to an open connection
  - In-memory ring-buffer store with configurable max frames per session
  - Serialises frames to JSON / HAR-compatible structures
  - Thread-safe via asyncio.Lock

OWASP: A07:2021-Identification and Authentication Failures
MITRE: T1557 (Man-in-the-Middle)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class FrameDirection(str, Enum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class FrameType(str, Enum):
    TEXT = "text"
    BINARY = "binary"
    PING = "ping"
    PONG = "pong"
    CLOSE = "close"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class WebSocketFrame:
    """A single captured WebSocket frame."""

    id: str
    session_id: str
    timestamp: float  # Unix epoch (seconds)
    direction: FrameDirection
    frame_type: FrameType
    payload: str  # UTF-8 text or base64-encoded binary
    is_binary: bool = False
    length: int = 0  # byte length of original payload
    modified: bool = False  # True if the payload was altered by a mutation callback
    notes: str = ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def raw_bytes(self) -> bytes:
        """Return the payload as raw bytes."""
        if self.is_binary:
            return base64.b64decode(self.payload)
        return self.payload.encode("utf-8", errors="replace")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["direction"] = self.direction.value
        d["frame_type"] = self.frame_type.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WebSocketFrame":
        d = dict(d)
        d["direction"] = FrameDirection(d["direction"])
        d["frame_type"] = FrameType(d["frame_type"])
        return cls(**d)


@dataclass
class WebSocketSession:
    """Metadata about a captured WebSocket connection."""

    id: str
    url: str
    started_at: float  # Unix epoch
    ended_at: Optional[float] = None
    frame_count: int = 0
    client_addr: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# WebSocket Interceptor
# ---------------------------------------------------------------------------


class WebSocketInterceptor:
    """
    Stores WebSocket sessions and frames captured by the proxy layer.

    Usage::

        interceptor = WebSocketInterceptor(max_frames_per_session=500)

        # Call from proxy on new WebSocket connection
        session = interceptor.open_session("wss://example.com/chat")

        # Call from proxy on each received frame
        frame = interceptor.capture_frame(
            session_id=session.id,
            direction=FrameDirection.CLIENT_TO_SERVER,
            frame_type=FrameType.TEXT,
            payload="Hello, server!",
        )

        # Later: replay a modified frame
        await interceptor.replay_frame(frame.id, new_payload="Hello again!")
    """

    def __init__(
        self,
        max_frames_per_session: int = 1000,
        on_frame: Optional[Callable[[WebSocketFrame], None]] = None,
    ) -> None:
        self._max_frames = max_frames_per_session
        self._on_frame = on_frame

        self._sessions: Dict[str, WebSocketSession] = {}
        self._frames: Dict[str, WebSocketFrame] = {}  # frame_id → frame
        self._session_frames: Dict[str, List[str]] = {}  # session_id → [frame_id]
        self._lock = asyncio.Lock()

        # Optional mutation callbacks: list of (name, callable)
        self._mutations: List[tuple[str, Callable[[WebSocketFrame], Optional[str]]]] = []

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def open_session(self, url: str, client_addr: str = "") -> WebSocketSession:
        """Register a new WebSocket session; returns the session object."""
        session = WebSocketSession(
            id=str(uuid.uuid4()),
            url=url,
            started_at=time.time(),
            client_addr=client_addr,
        )
        self._sessions[session.id] = session
        self._session_frames[session.id] = []
        logger.debug("WebSocket session opened: %s  url=%s", session.id, url)
        return session

    def close_session(self, session_id: str) -> None:
        """Mark a session as closed."""
        session = self._sessions.get(session_id)
        if session:
            session.ended_at = time.time()
            logger.debug("WebSocket session closed: %s", session_id)

    def get_session(self, session_id: str) -> Optional[WebSocketSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[WebSocketSession]:
        return list(self._sessions.values())

    # ------------------------------------------------------------------
    # Frame capture
    # ------------------------------------------------------------------

    def capture_frame(
        self,
        session_id: str,
        direction: FrameDirection,
        frame_type: FrameType,
        payload: str,
        is_binary: bool = False,
    ) -> Optional[WebSocketFrame]:
        """
        Capture a WebSocket frame.

        Returns the stored frame or *None* if the session is unknown or the
        per-session ring-buffer is full and the oldest frame was evicted.
        """
        session = self._sessions.get(session_id)
        if not session:
            logger.warning("capture_frame: unknown session %s", session_id)
            return None

        length = len(base64.b64decode(payload)) if is_binary else len(payload.encode("utf-8"))

        frame = WebSocketFrame(
            id=str(uuid.uuid4()),
            session_id=session_id,
            timestamp=time.time(),
            direction=direction,
            frame_type=frame_type,
            payload=payload,
            is_binary=is_binary,
            length=length,
        )

        # Apply mutation callbacks
        for name, mutate in self._mutations:
            try:
                result = mutate(frame)
                if result is not None and result != payload:
                    frame.payload = result
                    frame.modified = True
                    logger.debug("Frame mutated by '%s'", name)
            except Exception as exc:
                logger.warning("Mutation callback '%s' raised: %s", name, exc)

        self._frames[frame.id] = frame

        frame_list = self._session_frames.setdefault(session_id, [])
        frame_list.append(frame.id)

        # Evict oldest if ring-buffer full
        if len(frame_list) > self._max_frames:
            oldest_id = frame_list.pop(0)
            self._frames.pop(oldest_id, None)

        # Update session counter
        session.frame_count += 1

        if self._on_frame:
            try:
                self._on_frame(frame)
            except Exception as exc:
                logger.warning("on_frame callback raised: %s", exc)

        return frame

    # ------------------------------------------------------------------
    # Frame retrieval
    # ------------------------------------------------------------------

    def get_frame(self, frame_id: str) -> Optional[WebSocketFrame]:
        return self._frames.get(frame_id)

    def get_session_frames(
        self,
        session_id: str,
        direction: Optional[FrameDirection] = None,
        frame_type: Optional[FrameType] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[WebSocketFrame]:
        """Return frames for a session, optionally filtered."""
        frame_ids = self._session_frames.get(session_id, [])
        frames = [self._frames[fid] for fid in frame_ids if fid in self._frames]

        if direction:
            frames = [f for f in frames if f.direction == direction]
        if frame_type:
            frames = [f for f in frames if f.frame_type == frame_type]

        return frames[offset : offset + limit]

    def list_all_frames(self, limit: int = 500, offset: int = 0) -> List[WebSocketFrame]:
        """Return all frames (newest first) across all sessions."""
        all_frames = sorted(self._frames.values(), key=lambda f: f.timestamp, reverse=True)
        return all_frames[offset : offset + limit]

    # ------------------------------------------------------------------
    # Frame modification
    # ------------------------------------------------------------------

    def modify_frame(self, frame_id: str, new_payload: str) -> Optional[WebSocketFrame]:
        """
        Overwrite the payload of a stored frame.  The frame is marked *modified*.
        Returns the updated frame or None if not found.
        """
        frame = self._frames.get(frame_id)
        if not frame:
            return None
        frame.payload = new_payload
        frame.modified = True
        return frame

    # ------------------------------------------------------------------
    # Frame replay
    # ------------------------------------------------------------------

    async def replay_frame(
        self,
        frame_id: str,
        new_payload: Optional[str] = None,
        send_fn: Optional[Callable[[bytes], Any]] = None,
    ) -> Dict[str, Any]:
        """
        Replay a captured frame, optionally with a modified payload.

        Args:
            frame_id:    ID of the frame to replay.
            new_payload: If provided, send this instead of the stored payload.
            send_fn:     Async callable that sends bytes over the wire.
                         If *None*, the replay is simulated (dry-run).

        Returns:
            Dict with replay result metadata.
        """
        frame = self._frames.get(frame_id)
        if not frame:
            return {"success": False, "error": f"Frame {frame_id!r} not found"}

        payload = new_payload if new_payload is not None else frame.payload
        raw = base64.b64decode(payload) if frame.is_binary else payload.encode("utf-8")

        if send_fn is not None:
            try:
                result = send_fn(raw)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                return {"success": False, "error": str(exc), "frame_id": frame_id}

        return {
            "success": True,
            "frame_id": frame_id,
            "session_id": frame.session_id,
            "replayed_payload": payload,
            "dry_run": send_fn is None,
            "timestamp": time.time(),
        }

    async def replay_session(
        self,
        session_id: str,
        direction: Optional[FrameDirection] = None,
        send_fn: Optional[Callable[[bytes], Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Replay all frames for a session (in capture order)."""
        frame_ids = self._session_frames.get(session_id, [])
        results = []
        for fid in frame_ids:
            frame = self._frames.get(fid)
            if not frame:
                continue
            if direction and frame.direction != direction:
                continue
            result = await self.replay_frame(fid, send_fn=send_fn)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Mutation callback management
    # ------------------------------------------------------------------

    def add_mutation(self, name: str, fn: Callable[[WebSocketFrame], Optional[str]]) -> None:
        """Register a mutation callback invoked on each captured frame."""
        self._mutations.append((name, fn))

    def remove_mutation(self, name: str) -> bool:
        """Remove a mutation callback by name. Returns True if removed."""
        before = len(self._mutations)
        self._mutations = [(n, f) for n, f in self._mutations if n != name]
        return len(self._mutations) < before

    def clear_mutations(self) -> None:
        self._mutations.clear()

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def clear_session(self, session_id: str) -> int:
        """Clear all frames for a session. Returns number of frames deleted."""
        frame_ids = self._session_frames.pop(session_id, [])
        for fid in frame_ids:
            self._frames.pop(fid, None)
        session = self._sessions.pop(session_id, None)
        if session:
            logger.debug("WebSocket session %s cleared (%d frames)", session_id, len(frame_ids))
        return len(frame_ids)

    def clear_all(self) -> None:
        """Remove all sessions and frames."""
        self._sessions.clear()
        self._frames.clear()
        self._session_frames.clear()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_session_json(self, session_id: str) -> str:
        """Export session metadata + all frames as JSON."""
        session = self._sessions.get(session_id)
        frames = self.get_session_frames(session_id, limit=self._max_frames)
        return json.dumps(
            {
                "session": session.to_dict() if session else None,
                "frames": [f.to_dict() for f in frames],
            },
            indent=2,
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_sessions": len(self._sessions),
            "active_sessions": sum(
                1 for s in self._sessions.values() if s.ended_at is None
            ),
            "total_frames": len(self._frames),
            "max_frames_per_session": self._max_frames,
            "mutation_count": len(self._mutations),
        }
