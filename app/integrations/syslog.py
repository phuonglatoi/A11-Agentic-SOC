from __future__ import annotations

import asyncio
import logging

from app.database import Database
from app.pipeline import SOCPipeline

logger = logging.getLogger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, database: Database, pipeline: SOCPipeline):
        self.database = database
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr) -> None:
        message = data.decode("utf-8", errors="replace").strip()
        asyncio.create_task(self._process(message, addr))

    async def _process(self, message: str, addr) -> None:
        with self.database.session_factory() as db:
            try:
                await self.pipeline.process(
                    db,
                    message,
                    source_hint="syslog",
                    metadata={"remote_ip": addr[0]},
                )
            except Exception:
                logger.exception("Failed to process a syslog datagram from %s", addr)
