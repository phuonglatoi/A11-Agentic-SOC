from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import require_admin, require_ingest, require_stream_ticket
from app.config import Settings
from app.database import Database
from app.event_bus import EventBus
from app.integrations.syslog import SyslogProtocol
from app.models import (
    Alert,
    AuditEvent,
    Incident,
    ResponseAction,
    SecurityEvent,
    utcnow_iso,
)
from app.pipeline import SOCPipeline
from app.schemas import (
    ActionOut,
    AlertOut,
    AutomationAuditRequest,
    AuditOut,
    DecisionRequest,
    IncidentOut,
    IngestRequest,
    KnowledgeHitOut,
    KnowledgeSearchRequest,
    SecurityEventOut,
    StatusUpdate,
)

logger = logging.getLogger("a11-soc")
logging.basicConfig(level=logging.INFO)


def _db(request: Request):
    yield from request.app.state.database.session()


def _decode_json_stream(raw: bytes) -> list[dict[str, Any]]:
    text = raw.decode("utf-8").strip()
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value, index = decoder.raw_decode(text, index)
        if not isinstance(value, dict):
            raise ValueError("Each HEC payload must be a JSON object.")
        objects.append(value)
    return objects


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    database = Database(settings.database_url)
    bus = EventBus()
    pipeline = SOCPipeline(settings, bus)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        app.state.syslog_transport = None
        for warning in settings.validate_safety():
            logger.warning(warning)
        if settings.syslog_enabled:
            try:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: SyslogProtocol(database, pipeline),
                    local_addr=(settings.syslog_host, settings.syslog_port),
                )
                app.state.syslog_transport = transport
                logger.info(
                    "Syslog UDP collector listening on %s:%s",
                    settings.syslog_host,
                    settings.syslog_port,
                )
            except OSError as exc:
                logger.warning("Syslog collector could not start: %s", exc)
        yield
        if app.state.syslog_transport:
            app.state.syslog_transport.close()
        database.close()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Local-first real-time Agentic SOC automation platform.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.bus = bus
    app.state.pipeline = pipeline
    app.state.stream_tickets = {}
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "response_mode": settings.response_mode,
            "ollama_enabled": settings.ollama_enabled,
            "warnings": settings.validate_safety(),
        }

    @app.get("/api/v1/runtime", dependencies=[Depends(require_admin)])
    def runtime() -> dict[str, Any]:
        return {
            "environment": settings.environment,
            "response_mode": settings.response_mode,
            "ollama_enabled": settings.ollama_enabled,
            "ollama_model": settings.ollama_model,
            "syslog": {
                "enabled": settings.syslog_enabled,
                "host": settings.syslog_host,
                "port": settings.syslog_port,
            },
            "knowledge": pipeline.knowledge.stats(),
            "warnings": settings.validate_safety(),
        }

    @app.get("/api/v1/knowledge", dependencies=[Depends(require_admin)])
    def knowledge_inventory(request: Request) -> dict[str, Any]:
        return request.app.state.pipeline.knowledge.stats()

    @app.post(
        "/api/v1/knowledge/search",
        response_model=list[KnowledgeHitOut],
        dependencies=[Depends(require_admin)],
    )
    def knowledge_search(
        payload: KnowledgeSearchRequest,
        request: Request,
    ):
        return request.app.state.pipeline.knowledge.search(
            payload.query, limit=payload.limit
        )

    @app.post("/api/v1/ingest", dependencies=[Depends(require_ingest)])
    async def ingest(
        payload: IngestRequest,
        request: Request,
        db: Session = Depends(_db),
    ) -> dict[str, Any]:
        values = payload.events or ([payload.event] if payload.event is not None else [])
        if not values:
            raise HTTPException(status_code=422, detail="event or events is required.")
        results = []
        metadata = {
            "sourcetype": payload.sourcetype,
            "host": payload.host,
            **payload.fields,
        }
        for value in values[:500]:
            alert = await request.app.state.pipeline.process(
                db, value, source_hint=payload.source, metadata=metadata
            )
            results.append({"alert_id": alert.id, "severity": alert.severity})
        return {"accepted": len(results), "results": results}

    @app.post("/services/collector/event", dependencies=[Depends(require_ingest)])
    @app.post("/services/collector", dependencies=[Depends(require_ingest)])
    async def hec_event(request: Request, db: Session = Depends(_db)):
        try:
            payloads = _decode_json_stream(await request.body())
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return JSONResponse(
                status_code=400, content={"text": str(exc), "code": 6}
            )
        for payload in payloads[:500]:
            event = payload.get("event")
            if event is None:
                return JSONResponse(
                    status_code=400,
                    content={"text": "HEC event field is required.", "code": 6},
                )
            await request.app.state.pipeline.process(
                db,
                event,
                source_hint=payload.get("source") or payload.get("sourcetype"),
                metadata={
                    "sourcetype": payload.get("sourcetype"),
                    "host": payload.get("host"),
                    **(payload.get("fields") or {}),
                },
            )
        return {"text": "Success", "code": 0}

    @app.post("/services/collector/raw", dependencies=[Depends(require_ingest)])
    async def hec_raw(
        request: Request,
        db: Session = Depends(_db),
        source: str | None = Query(default=None),
        sourcetype: str | None = Query(default=None),
    ):
        raw = (await request.body()).decode("utf-8", errors="replace")
        lines = [line for line in raw.splitlines() if line.strip()]
        for line in lines[:500]:
            await request.app.state.pipeline.process(
                db,
                line,
                source_hint=source or sourcetype,
                metadata={"sourcetype": sourcetype},
            )
        return {"text": "Success", "code": 0}

    @app.get(
        "/api/v1/alerts",
        response_model=list[AlertOut],
        dependencies=[Depends(require_admin)],
    )
    def list_alerts(
        severity: str | None = None,
        status: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(_db),
    ):
        query = select(Alert)
        if severity:
            query = query.where(Alert.severity == severity.lower())
        if status:
            query = query.where(Alert.status == status.lower())
        return db.scalars(query.order_by(Alert.last_seen.desc()).limit(limit)).all()

    @app.get(
        "/api/v1/alerts/{alert_id}",
        response_model=AlertOut,
        dependencies=[Depends(require_admin)],
    )
    def get_alert(alert_id: str, db: Session = Depends(_db)):
        alert = db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return alert

    @app.get(
        "/api/v1/alerts/{alert_id}/events",
        response_model=list[SecurityEventOut],
        dependencies=[Depends(require_admin)],
    )
    def get_alert_events(
        alert_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(_db),
    ):
        if not db.get(Alert, alert_id):
            raise HTTPException(status_code=404, detail="Alert not found.")
        return db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.alert_id == alert_id)
            .order_by(SecurityEvent.received_at.desc())
            .limit(limit)
        ).all()

    @app.patch(
        "/api/v1/alerts/{alert_id}/status",
        response_model=AlertOut,
        dependencies=[Depends(require_admin)],
    )
    async def update_alert_status(
        alert_id: str,
        payload: StatusUpdate,
        request: Request,
        db: Session = Depends(_db),
    ):
        alert = db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found.")
        alert.status = payload.status
        alert.updated_at = utcnow_iso()
        db.add(
            AuditEvent(
                actor=payload.analyst,
                action="alert.status_changed",
                object_type="alert",
                object_id=alert.id,
                outcome="success",
                detail={"status": payload.status},
            )
        )
        db.commit()
        db.refresh(alert)
        await request.app.state.bus.publish(
            {"type": "alert_status", "data": {"id": alert.id, "status": alert.status}}
        )
        return alert

    @app.get(
        "/api/v1/incidents",
        response_model=list[IncidentOut],
        dependencies=[Depends(require_admin)],
    )
    def list_incidents(
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(_db),
    ):
        return db.scalars(
            select(Incident).order_by(Incident.created_at.desc()).limit(limit)
        ).all()

    @app.get(
        "/api/v1/incidents/{incident_id}/report",
        dependencies=[Depends(require_admin)],
        response_class=PlainTextResponse,
    )
    def incident_report(incident_id: str, db: Session = Depends(_db)):
        incident = db.get(Incident, incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return PlainTextResponse(
            incident.report_markdown, media_type="text/markdown; charset=utf-8"
        )

    @app.get(
        "/api/v1/actions",
        response_model=list[ActionOut],
        dependencies=[Depends(require_admin)],
    )
    def list_actions(
        status: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(_db),
    ):
        query = select(ResponseAction)
        if status:
            query = query.where(ResponseAction.status == status)
        return db.scalars(
            query.order_by(ResponseAction.created_at.desc()).limit(limit)
        ).all()

    @app.post(
        "/api/v1/actions/{action_id}/decision",
        response_model=ActionOut,
        dependencies=[Depends(require_admin)],
    )
    async def decide_action(
        action_id: str,
        payload: DecisionRequest,
        request: Request,
        db: Session = Depends(_db),
    ):
        action = db.get(ResponseAction, action_id)
        if not action:
            raise HTTPException(status_code=404, detail="Action not found.")
        if action.status != "pending":
            raise HTTPException(status_code=409, detail="Action is not pending.")
        action.approved_by = payload.analyst
        action.decided_at = utcnow_iso()
        if payload.decision == "reject":
            action.status = "rejected"
            action.result = {"ok": False, "reason": payload.reason}
        else:
            action.status = "approved"
            result = await request.app.state.pipeline.executor.execute(
                action.action_type, action.target, action.payload
            )
            action.result = result
            action.status = "executed" if result.get("ok") else "failed"
            action.executed_at = utcnow_iso()
        db.add(
            AuditEvent(
                actor=payload.analyst,
                action=f"response.{payload.decision}d",
                object_type="response_action",
                object_id=action.id,
                outcome=action.status,
                detail={"reason": payload.reason, "result": action.result},
            )
        )
        db.commit()
        db.refresh(action)
        await request.app.state.bus.publish(
            {
                "type": "action",
                "data": {
                    "id": action.id,
                    "status": action.status,
                    "result": action.result,
                },
            }
        )
        return action

    @app.get(
        "/api/v1/audit",
        response_model=list[AuditOut],
        dependencies=[Depends(require_admin)],
    )
    def list_audit(
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(_db),
    ):
        return db.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
        ).all()

    @app.post(
        "/api/v1/automation/audit",
        response_model=AuditOut,
        dependencies=[Depends(require_admin)],
    )
    async def automation_audit(
        payload: AutomationAuditRequest,
        request: Request,
        db: Session = Depends(_db),
    ):
        audit = AuditEvent(
            actor=payload.actor,
            action=payload.action,
            object_type=payload.object_type,
            object_id=payload.object_id,
            outcome=payload.outcome,
            detail=payload.detail,
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        await request.app.state.bus.publish(
            {
                "type": "audit",
                "data": {
                    "id": audit.id,
                    "actor": audit.actor,
                    "action": audit.action,
                    "object_type": audit.object_type,
                    "object_id": audit.object_id,
                    "outcome": audit.outcome,
                },
            }
        )
        return audit

    @app.get("/api/v1/stats", dependencies=[Depends(require_admin)])
    def stats(db: Session = Depends(_db)):
        severity_rows = db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        ).all()
        open_incidents = db.scalar(
            select(func.count(Incident.id)).where(Incident.status != "closed")
        )
        pending_actions = db.scalar(
            select(func.count(ResponseAction.id)).where(
                ResponseAction.status == "pending"
            )
        )
        total_events = db.scalar(select(func.sum(Alert.event_count))) or 0
        return {
            "alerts_by_severity": dict(severity_rows),
            "open_incidents": open_incidents or 0,
            "pending_actions": pending_actions or 0,
            "correlated_events": total_events,
        }

    @app.post("/api/v1/demo/generate", dependencies=[Depends(require_admin)])
    async def generate_demo(request: Request, db: Session = Depends(_db)):
        events: list[tuple[str, dict[str, Any] | str]] = [
            (
                "apache",
                '203.0.113.66 - - [28/Jul/2026:15:31:11 +0000] '
                '"GET /.env HTTP/1.1" 404 512 "-" "dirb/2.22"',
            ),
            (
                "suricata",
                {
                    "timestamp": "2026-07-28T15:31:12.000000+00:00",
                    "event_type": "alert",
                    "src_ip": "93.184.216.34",
                    "src_port": 45000,
                    "dest_ip": "192.168.1.100",
                    "dest_port": 80,
                    "proto": "TCP",
                    "alert": {
                        "severity": 2,
                        "signature_id": 2009582,
                        "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                        "category": "Attempted Information Leak",
                    },
                },
            ),
            (
                "windows",
                {
                    "EventID": 1102,
                    "Computer": "WIN-ENDPOINT-01",
                    "TargetUserName": "lab-admin",
                    "Message": "The audit log was cleared.",
                    "TimeCreated": "2026-07-28T15:31:13Z",
                },
            ),
        ]
        output = []
        for source, event in events:
            alert = await request.app.state.pipeline.process(
                db, event, source_hint=source
            )
            output.append(alert.id)
        return {"generated": len(output), "alert_ids": output}

    @app.post("/api/v1/stream-ticket", dependencies=[Depends(require_admin)])
    def stream_ticket(request: Request):
        now = time.time()
        request.app.state.stream_tickets = {
            ticket: expiry
            for ticket, expiry in request.app.state.stream_tickets.items()
            if expiry > now
        }
        ticket = secrets.token_urlsafe(32)
        expires_in = 8 * 60 * 60
        request.app.state.stream_tickets[ticket] = now + expires_in
        return {"ticket": ticket, "expires_in": expires_in}

    @app.get("/api/v1/stream")
    async def stream(
        _: str = Depends(require_stream_ticket),
    ):
        async def generate() -> AsyncIterator[str]:
            async for event in bus.subscribe():
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    static_dir = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="dashboard")
    return app


app = create_app()
