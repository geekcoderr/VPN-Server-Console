from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict
import json
import asyncio

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # We use a copy to avoid "set changed size during iteration" errors
        for connection in self.active_connections[:]:
            try:
                await connection.send_json(message)
            except Exception:
                self.active_connections.remove(connection)

manager = ConnectionManager()
