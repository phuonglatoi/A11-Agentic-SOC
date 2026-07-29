from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.enrichment import EnrichmentAgent
from app.agents.llm import LocalLLMAgent
from app.agents.rag import LocalKnowledgeBase
from app.agents.report import build_report
from app.agents.response import propose_actions
from app.agents.triage import SEVERITY_RANK, triage_event
from app.config import Settings
from app.event_bus import EventBus
from app.integrations.response_executor import ResponseExecutor
from app.models import (
    Alert,
    AuditEvent,
    Incident,
    ResponseAction,
    SecurityEvent,
    utcnow_iso,
)
from app.parsers import normalize_event


def alert_dict(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "fingerprint": alert.fingerprint,
        "source": alert.source,
        "event_type": alert.event_type,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.status,
        "event_count": alert.event_count,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "dst_port": alert.dst_port,
        "username": alert.username,
        "asset": alert.asset,
        "mitre": alert.mitre,
        "normalized_event": alert.normalized_event,
        "raw_event": alert.raw_event,
        "triage": alert.triage,
        "enrichment": alert.enrichment,
        "ai_analysis": alert.ai_analysis,
        "recommendations": alert.recommendations,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }


class SOCPipeline:
    def __init__(self, settings: Settings, bus: EventBus):
        self.settings = settings
        self.bus = bus
        self.enrichment = EnrichmentAgent(settings.data_dir)
        self.knowledge = LocalKnowledgeBase(settings.knowledge_dir)
        self.llm = LocalLLMAgent(settings)
        self.executor = ResponseExecutor(settings)

    async def process(
        self,
        db: Session,
        raw: dict[str, Any] | str,
        source_hint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Alert:
        normalized = normalize_event(raw, source_hint=source_hint, metadata=metadata)
        enriched = self.enrichment.enrich(normalized)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        cutoff = (
            now - timedelta(seconds=self.settings.correlation_window_seconds)
        ).isoformat()
        existing = db.scalar(
            select(Alert)
            .where(
                Alert.fingerprint == normalized["fingerprint"],
                Alert.status.not_in(["closed", "false_positive"]),
                Alert.last_seen >= cutoff,
            )
            .order_by(Alert.last_seen.desc())
        )
        old_severity = existing.severity if existing else "low"
        event_count = (existing.event_count + 1) if existing else 1
        triage = triage_event(normalized, event_count=event_count, enrichment=enriched)
        query = " ".join(
            [
                normalized.get("event_type", ""),
                normalized.get("title", ""),
                normalized.get("message", ""),
                " ".join(item.get("id", "") for item in triage["mitre"]),
            ]
        )
        knowledge = self.knowledge.search(query)
        ai_analysis = await self.llm.analyze(
            normalized, triage, enriched, knowledge
        )
        triage["knowledge"] = knowledge

        if existing:
            alert = existing
            alert.event_count = event_count
            alert.last_seen = now_iso
            alert.updated_at = now_iso
            alert.severity = triage["severity"]
            alert.confidence = max(alert.confidence, triage["confidence"])
            alert.title = triage["title"]
            alert.description = triage["description"]
            alert.normalized_event = {
                key: value for key, value in normalized.items() if key != "raw"
            }
            alert.raw_event = normalized["raw"]
            alert.triage = triage
            alert.enrichment = enriched
            alert.ai_analysis = ai_analysis
            alert.mitre = triage["mitre"]
            alert.recommendations = triage["recommendations"]
            alert.asset = (enriched.get("asset") or {}).get("name")
        else:
            alert = Alert(
                fingerprint=normalized["fingerprint"],
                source=normalized["source"],
                event_type=normalized["event_type"],
                title=triage["title"],
                description=triage["description"],
                severity=triage["severity"],
                confidence=triage["confidence"],
                event_count=1,
                src_ip=normalized.get("src_ip"),
                dst_ip=normalized.get("dst_ip"),
                dst_port=normalized.get("dst_port"),
                username=normalized.get("username"),
                asset=(enriched.get("asset") or {}).get("name"),
                mitre=triage["mitre"],
                normalized_event={
                    key: value for key, value in normalized.items() if key != "raw"
                },
                raw_event=normalized["raw"],
                triage=triage,
                enrichment=enriched,
                ai_analysis=ai_analysis,
                recommendations=triage["recommendations"],
                first_seen=now_iso,
                last_seen=now_iso,
                created_at=now_iso,
                updated_at=now_iso,
            )
            db.add(alert)
            db.flush()

        db.add(
            SecurityEvent(
                alert_id=alert.id,
                source=normalized["source"],
                event_type=normalized["event_type"],
                event_timestamp=normalized["timestamp"],
                raw_event=normalized["raw"],
                normalized_event={
                    key: value for key, value in normalized.items() if key != "raw"
                },
                received_at=now_iso,
            )
        )
        escalated = SEVERITY_RANK[triage["severity"]] > SEVERITY_RANK[old_severity]
        incident = self._ensure_incident(db, alert, now_iso)
        await self._ensure_actions(db, alert, normalized, triage, enriched)
        db.add(
            AuditEvent(
                actor="soc-pipeline",
                action="alert.correlated" if existing else "alert.created",
                object_type="alert",
                object_id=alert.id,
                outcome="success",
                detail={
                    "severity": alert.severity,
                    "event_count": alert.event_count,
                    "escalated": escalated,
                    "llm_status": ai_analysis.get("status"),
                },
            )
        )
        if incident:
            incident.timeline = [
                *incident.timeline,
                {
                    "timestamp": now_iso,
                    "event": (
                        f"Correlated event #{alert.event_count}; severity "
                        f"{alert.severity.upper()}."
                    ),
                },
            ][-100:]
            incident.updated_at = now_iso
            incident.report_markdown = build_report(alert, incident.timeline)

        db.commit()
        db.refresh(alert)
        await self.bus.publish({"type": "alert", "data": alert_dict(alert)})
        if incident:
            await self.bus.publish(
                {
                    "type": "incident",
                    "data": {
                        "id": incident.id,
                        "alert_id": alert.id,
                        "priority": incident.priority,
                        "status": incident.status,
                    },
                }
            )
        return alert

    def _ensure_incident(
        self, db: Session, alert: Alert, now_iso: str
    ) -> Incident | None:
        if alert.severity not in {"high", "critical"}:
            return None
        incident = db.scalar(
            select(Incident)
            .where(Incident.alert_id == alert.id, Incident.status != "closed")
            .order_by(Incident.created_at.desc())
        )
        if incident:
            incident.priority = alert.severity
            return incident
        incident = Incident(
            alert_id=alert.id,
            title=alert.title,
            priority=alert.severity,
            summary=alert.description,
            timeline=[
                {
                    "timestamp": now_iso,
                    "event": f"Incident opened from alert {alert.id}.",
                }
            ],
        )
        db.add(incident)
        db.flush()
        return incident

    async def _ensure_actions(
        self,
        db: Session,
        alert: Alert,
        normalized: dict[str, Any],
        triage: dict[str, Any],
        enrichment: dict[str, Any],
    ) -> None:
        for proposal in propose_actions(alert.id, normalized, triage, enrichment):
            duplicate = db.scalar(
                select(ResponseAction).where(
                    ResponseAction.alert_id == alert.id,
                    ResponseAction.action_type == proposal["action_type"],
                    ResponseAction.target == proposal["target"],
                    ResponseAction.status.in_(["pending", "approved", "executed"]),
                )
            )
            if duplicate:
                continue
            action = ResponseAction(**proposal)
            db.add(action)
            db.flush()
            if not action.approval_required:
                result = await self.executor.execute(
                    action.action_type, action.target, action.payload
                )
                action.result = result
                action.status = "executed" if result.get("ok") else "failed"
                action.executed_at = utcnow_iso()
                db.add(
                    AuditEvent(
                        actor="response-agent",
                        action="response.executed",
                        object_type="response_action",
                        object_id=action.id,
                        outcome=action.status,
                        detail=result,
                    )
                )
            else:
                db.add(
                    AuditEvent(
                        actor="response-agent",
                        action="response.requested",
                        object_type="response_action",
                        object_id=action.id,
                        outcome="pending",
                        detail={
                            "action_type": action.action_type,
                            "target": action.target,
                            "risk": action.risk,
                        },
                    )
                )
