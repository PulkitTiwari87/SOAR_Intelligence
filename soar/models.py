"""SQLAlchemy ORM models. PostgreSQL is the durable store in Docker; SQLite for local dev/tests."""
from __future__ import annotations

import uuid
from datetime import datetime, UTC

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
                        String, Table, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class UTCDateTime(TypeDecorator):
    """Store naive UTC, return timezone-aware UTC (portable across SQLite/PostgreSQL)."""
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, dialect):  # noqa: ANN001
        return None if value is None else value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: UTCDateTime, dict: JSON, list: JSON}


def _pk() -> Mapped[str]:
    return mapped_column(String(32), primary_key=True, default=new_id)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _pk()
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), default="VIEWER")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(nullable=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column()


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = _pk()
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    os: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1 (low) .. 10 (crown jewel)
    agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")  # manual | wazuh | seed
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class AssetLink(Base):
    """Directed network relationship: `src` can reach `dst` (flow / access path)."""
    __tablename__ = "asset_links"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "protocol", "port"),)
    id: Mapped[str] = _pk()
    src_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(32), default="tcp")
    port: Mapped[int] = mapped_column(Integer, default=0)


incident_iocs = Table(
    "incident_iocs", Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = _pk()
    number: Mapped[str] = mapped_column(String(24), unique=True, index=True)  # INC-2026-0001
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    severity: Mapped[int] = mapped_column(Integer, default=1, index=True)  # 1..4
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    category: Mapped[str] = mapped_column(String(64), default="unknown")
    summary: Mapped[str] = mapped_column(Text, default="")
    primary_source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    primary_host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    primary_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entities: Mapped[dict] = mapped_column(JSON, default=dict)  # ips/hosts/users/hashes/domains
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_event_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    detected_at: Mapped[datetime] = mapped_column(default=utcnow)  # incident creation time
    resolved_at: Mapped[datetime | None] = mapped_column(nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    auto_handled: Mapped[bool] = mapped_column(Boolean, default=False)
    report_file: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    events: Mapped[list["Event"]] = relationship(back_populates="incident")
    timeline: Mapped[list["TimelineEntry"]] = relationship(
        back_populates="incident", order_by="TimelineEntry.timestamp")
    mitre: Mapped[list["MitreMapping"]] = relationship(back_populates="incident")
    predictions: Mapped[list["ModelPrediction"]] = relationship(
        back_populates="incident", order_by="ModelPrediction.created_at")
    iocs: Mapped[list["IOC"]] = relationship(secondary=incident_iocs, back_populates="incidents")


class Event(Base):
    """A normalized security event (Wazuh alert, auth log, network event, email, ...)."""
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_incident_ts", "incident_id", "timestamp"),)
    id: Mapped[str] = _pk()
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # dedupe hash
    timestamp: Mapped[datetime] = mapped_column(index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[int] = mapped_column(Integer, default=1)  # normalized 1..4
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(400), default="")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    destination_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict)  # original payload, never altered
    meta: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow)

    incident: Mapped["Incident | None"] = relationship(back_populates="events")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value"),)
    id: Mapped[str] = _pk()
    type: Mapped[str] = mapped_column(String(16), index=True)  # ip | domain | url | hash | email
    value: Mapped[str] = mapped_column(String(1024), index=True)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    incidents: Mapped[list["Incident"]] = relationship(secondary=incident_iocs,
                                                       back_populates="iocs")
    intel: Mapped[list["ThreatIntel"]] = relationship(back_populates="ioc")


class ThreatIntel(Base):
    """Stored enrichment result for an IOC from one provider."""
    __tablename__ = "threat_intel"
    id: Mapped[str] = _pk()
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(16))  # malicious | suspicious | benign | unknown
    score: Mapped[float] = mapped_column(Float, default=0.0)  # 0..100
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0..1
    tags: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(default=utcnow)

    ioc: Mapped["IOC"] = relationship(back_populates="intel")


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"
    __table_args__ = (UniqueConstraint("incident_id", "technique_id", "source"),)
    id: Mapped[str] = _pk()
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    tactic: Mapped[str] = mapped_column(String(64))
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    technique_name: Mapped[str] = mapped_column(String(128))
    subtechnique: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(24))  # wazuh_rule | rule_engine | llm_inferred
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="mitre")


class ModelPrediction(Base):
    """Output of any analysis model: triage, anomaly, phishing, blast_radius, llm_commander."""
    __tablename__ = "model_predictions"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    model_name: Mapped[str] = mapped_column(String(64))
    model_version: Mapped[str] = mapped_column(String(64), default="")
    prediction: Mapped[str] = mapped_column(String(64), default="")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    incident: Mapped["Incident | None"] = relationship(back_populates="predictions")


class Playbook(Base):
    __tablename__ = "playbooks"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str] = mapped_column(Text, default="")
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    id: Mapped[str] = _pk()
    playbook_name: Mapped[str] = mapped_column(String(96), index=True)
    playbook_version: Mapped[int] = mapped_column(Integer, default=1)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(64), default="system")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)

    steps: Mapped[list["ExecutionStep"]] = relationship(
        back_populates="execution", order_by="ExecutionStep.idx", cascade="all, delete-orphan")


class ExecutionStep(Base):
    __tablename__ = "execution_steps"
    id: Mapped[str] = _pk()
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("playbook_executions.id", ondelete="CASCADE"), index=True)
    idx: Mapped[int] = mapped_column(Integer)
    step_key: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    approval_mode: Mapped[str] = mapped_column(String(16), default="policy")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verification: Mapped[dict] = mapped_column(JSON, default=dict)
    rollback: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)

    execution: Mapped["PlaybookExecution"] = relationship(back_populates="steps")


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("playbook_executions.id", ondelete="SET NULL"), nullable=True)
    step_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(8), default="high")
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(64), default="system")
    requested_at: Mapped[datetime] = mapped_column(default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AnalystAction(Base):
    """Manual analyst decision on an incident (also the label source for model feedback)."""
    __tablename__ = "analyst_actions"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TimelineEntry(Base):
    __tablename__ = "timeline_entries"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(default=utcnow)
    kind: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(64), default="system")
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    incident: Mapped["Incident"] = relationship(back_populates="timeline")


class BlocklistEntry(Base):
    """IP block state maintained by the `block_ip` action (exported at /api/blocklist)."""
    __tablename__ = "blocklist"
    id: Mapped[str] = _pk()
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    removed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    removed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    severity: Mapped[int] = mapped_column(Integer, default=1)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = _pk()
    timestamp: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(16), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
