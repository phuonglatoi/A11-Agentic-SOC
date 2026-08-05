from __future__ import annotations

import asyncio
import logging

from app.database import Database
from app.pipeline import SOCPipeline

logger = logging.getLogger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        database: Database,
        pipeline: SOCPipeline,
        *,
        queue_maxsize: int = 2000,
        worker_count: int = 2,
    ):
        self.database = database
        self.pipeline = pipeline
        self.queue: asyncio.Queue[tuple[str, tuple]] = asyncio.Queue(
            maxsize=max(1, queue_maxsize)
        )
        self.worker_count = max(1, worker_count)
        self.workers: list[asyncio.Task] = []
        self.received = 0
        self.processed = 0
        self.dropped = 0

    def connection_made(self, transport) -> None:
        self.workers = [
            asyncio.create_task(self._worker(index))
            for index in range(self.worker_count)
        ]

    def datagram_received(self, data: bytes, addr) -> None:
        message = data.decode("utf-8", errors="replace").strip()
        self.received += 1
        try:
            self.queue.put_nowait((message, addr))
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                logger.warning(
                    "Syslog queue is full; dropped=%s received=%s queued=%s",
                    self.dropped,
                    self.received,
                    self.queue.qsize(),
                )

    def connection_lost(self, exc) -> None:
        for worker in self.workers:
            worker.cancel()

    def stats(self) -> dict[str, int]:
        return {
            "queue_size": self.queue.qsize(),
            "queue_maxsize": self.queue.maxsize,
            "worker_count": self.worker_count,
            "received": self.received,
            "processed": self.processed,
            "dropped": self.dropped,
        }

    async def _worker(self, index: int) -> None:
        logger.info("Syslog worker %s started", index)
        while True:
            message, addr = await self.queue.get()
            try:
                await self._process(message, addr)
                self.processed += 1
            finally:
                self.queue.task_done()

    async def _process(self, message: str, addr) -> None:
        with self.database.session_factory() as db:
            try:
                alert = await self.pipeline.process(
                    db,
                    message,
                    source_hint="syslog",
                    metadata={"remote_ip": addr[0]},
                )
                logger.info(
                    "Received syslog datagram from %s; alert_id=%s severity=%s",
                    addr[0],
                    alert.id,
                    alert.severity,
                )
            except Exception:
                logger.exception("Failed to process a syslog datagram from %s", addr)
