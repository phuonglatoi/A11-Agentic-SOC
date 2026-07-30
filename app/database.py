from __future__ import annotations

import logging
import time
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, url: str):
        connect_args = (
            {"check_same_thread": False}
            if url.startswith("sqlite")
            else {"connect_timeout": 10}
        )
        self.engine = create_engine(
            url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
            class_=Session,
        )

    def initialize(self, attempts: int = 30, delay_seconds: float = 2.0) -> None:
        for attempt in range(1, attempts + 1):
            try:
                Base.metadata.create_all(self.engine)
                if attempt > 1:
                    logger.info("Database initialized after %s attempts.", attempt)
                return
            except OperationalError as exc:
                if attempt == attempts:
                    raise
                logger.warning(
                    "Database is not ready yet (%s/%s): %s",
                    attempt,
                    attempts,
                    str(exc).splitlines()[0],
                )
                time.sleep(delay_seconds)

    def session(self) -> Iterator[Session]:
        db = self.session_factory()
        try:
            yield db
        finally:
            db.close()

    def close(self) -> None:
        self.engine.dispose()
