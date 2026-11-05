"""Real-Time WebSocket Event Hub for Dashboard & Terminal Streams."""
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from fastapi import WebSocket


class WebSocketEventHub:
    def __init__(self):
        self._event_clients: Set[WebSocket] = set()
        self._terminal_clients: Dict[str, Set[WebSocket]] = {}
        self._recent_events: List[Dict[str, Any]] = []

    async def connect_events(self, websocket: WebSocket):
        await websocket.accept()
        self._event_clients.add(websocket)

    def disconnect_events(self, websocket: WebSocket):
        self._event_clients.discard(websocket)

    async def connect_terminal(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        if session_id not in self._terminal_clients:
            self._terminal_clients[session_id] = set()
        self._terminal_clients[session_id].add(websocket)

    def disconnect_terminal(self, session_id: str, websocket: WebSocket):
        if session_id in self._terminal_clients:
            self._terminal_clients[session_id].discard(websocket)

    async def publish_event(self, event_type: str, payload: Dict[str, Any]):
        message = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        self._recent_events.append(message)
        if len(self._recent_events) > 100:
            self._recent_events = self._recent_events[-100:]

        stale: List[WebSocket] = []
        for ws in list(self._event_clients):
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self._event_clients.discard(ws)

    def publish_event_sync(self, event_type: str, payload: Dict[str, Any]):
        """Fire-and-forget helper when called from synchronous service code."""
        message = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        self._recent_events.append(message)
        if len(self._recent_events) > 100:
            self._recent_events = self._recent_events[-100:]

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish_event(event_type, payload))
        except RuntimeError:
            pass

    async def stream_terminal_line(self, session_id: str, line: str, level: str = "INFO"):
        packet = {
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "line": line,
        }
        clients = self._terminal_clients.get(session_id, set())
        stale: List[WebSocket] = []
        for ws in list(clients):
            try:
                await ws.send_json(packet)
            except Exception:
                stale.append(ws)
        for ws in stale:
            clients.discard(ws)


ws_hub = WebSocketEventHub()

