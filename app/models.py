from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=lambda: new_id("alt")
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(96), index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    asset: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    normalized_event: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict)
    triage: Mapped[dict] = mapped_column(JSON, default=dict)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[str] = mapped_column(String(40), default=utcnow_iso)
    last_seen: Mapped[str] = mapped_column(String(40), default=utcnow_iso, index=True)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso)

    incidents: Mapped[list["Incident"]] = relationship(back_populates="alert")
    actions: Mapped[list["ResponseAction"]] = relationship(back_populates="alert")
    events: Mapped[list["SecurityEvent"]] = relationship(back_populates="alert")

    __table_args__ = (
        Index("ix_alert_correlation", "fingerprint", "status", "last_seen"),
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=lambda: new_id("evt")
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(96), index=True)
    event_timestamp: Mapped[str] = mapped_column(String(64))
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_event: Mapped[dict] = mapped_column(JSON, default=dict)
    received_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso, index=True)

    alert: Mapped[Alert] = relationship(back_populates="events")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=lambda: new_id("inc")
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    priority: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    report_markdown: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso)

    alert: Mapped[Alert] = relationship(back_populates="incidents")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=lambda: new_id("act")
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="response-agent")
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso)
    decided_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    executed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)

    alert: Mapped[Alert] = relationship(back_populates="actions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=lambda: new_id("aud")
    )
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), index=True)
    object_type: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow_iso, index=True)
