from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class IngestRequest(BaseModel):
    source: str | None = None
    event: dict[str, Any] | str | None = None
    events: list[dict[str, Any] | str] | None = None
    sourcetype: str | None = None
    host: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    fingerprint: str
    source: str
    event_type: str
    title: str
    description: str
    severity: str
    confidence: float
    status: str
    event_count: int
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    username: str | None
    asset: str | None
    mitre: list
    normalized_event: dict
    raw_event: dict
    triage: dict
    enrichment: dict
    ai_analysis: dict
    recommendations: list
    first_seen: str
    last_seen: str
    created_at: str
    updated_at: str


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    source: str
    event_type: str
    event_timestamp: str
    raw_event: dict
    normalized_event: dict
    received_at: str


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    title: str
    priority: str
    status: str
    assignee: str | None
    summary: str
    timeline: list
    report_markdown: str
    created_at: str
    updated_at: str


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    action_type: str
    target: str | None
    risk: str
    status: str
    approval_required: bool
    requested_by: str
    approved_by: str | None
    payload: dict
    result: dict
    created_at: str
    decided_at: str | None
    executed_at: str | None


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    analyst: str = Field(min_length=2, max_length=128)
    reason: str = Field(default="", max_length=500)


class StatusUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "closed", "false_positive"]
    analyst: str = Field(min_length=2, max_length=128)


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=2000)
    limit: int = Field(default=3, ge=1, le=10)


class KnowledgeHitOut(BaseModel):
    name: str
    title: str
    score: float
    tags: list[str]
    path: str
    excerpt: str


class AutomationAuditRequest(BaseModel):
    actor: str = Field(default="n8n", min_length=2, max_length=128)
    action: str = Field(default="automation.executed", min_length=2, max_length=128)
    object_type: str = Field(default="automation", min_length=2, max_length=64)
    object_id: str = Field(default="n8n-workflow", min_length=2, max_length=128)
    outcome: str = Field(default="success", min_length=2, max_length=32)
    detail: dict[str, Any] = Field(default_factory=dict)


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor: str
    action: str
    object_type: str
    object_id: str
    outcome: str
    detail: dict
    created_at: str
