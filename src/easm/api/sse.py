from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class FindingStream:
    """In-memory pub/sub for real-time finding streaming via SSE."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        logger.info("sse subscriber added", extra={"total": len(self._subscribers)})
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)
        logger.info("sse subscriber removed", extra={"total": len(self._subscribers)})

    def publish(self, finding: dict[str, Any]) -> None:
        for q in self._subscribers:
            try:
                q.put_nowait(finding)
            except asyncio.QueueFull:
                # Drop oldest message to make room
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                q.put_nowait(finding)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


_stream = FindingStream()


def get_finding_stream() -> FindingStream:
    return _stream
