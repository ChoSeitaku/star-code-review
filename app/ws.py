"""WebSocket 实时推送中心。

对外广播 §1.4.11 规定的 8 种消息类型：
project_status / stage_status / worker_status / chat_message /
runtime_log / resource_usage / vulnerability_found / report_ready

每条消息统一包裹为 `{"type": <消息类型>, "data": {...}, "ts": <时间>}`，
`data` 内字段满足 §1.4.11 的最低字段要求。
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from fastapi import WebSocket

from .utils import now_str


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[int, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, project_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[project_id].add(websocket)

    async def disconnect(self, project_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections[project_id].discard(websocket)
            if not self._connections[project_id]:
                self._connections.pop(project_id, None)

    def connection_count(self, project_id: int) -> int:
        return len(self._connections.get(project_id, ()))

    async def broadcast(self, project_id: int, message_type: str, data: dict) -> None:
        """向订阅了该项目的所有连接推送一条消息。"""
        async with self._lock:
            targets = list(self._connections.get(project_id, ()))

        if not targets:
            return

        payload = {"type": message_type, "data": data, "ts": now_str()}
        dead: list[WebSocket] = []
        for websocket in targets:
            try:
                await websocket.send_json(payload)
            except Exception:
                dead.append(websocket)

        if dead:
            async with self._lock:
                for websocket in dead:
                    self._connections[project_id].discard(websocket)

    async def broadcast_project_deleted(self, project_id: int) -> None:
        """项目被删除时通知订阅者，随后关闭连接。"""
        async with self._lock:
            targets = list(self._connections.get(project_id, ()))
            self._connections.pop(project_id, None)

        payload = {
            "type": "project_deleted",
            "data": {"project_id": project_id},
            "ts": now_str(),
        }
        for websocket in targets:
            try:
                await websocket.send_json(payload)
                await websocket.close()
            except Exception:
                pass


manager = ConnectionManager()
