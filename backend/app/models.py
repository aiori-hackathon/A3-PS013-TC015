from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def utcnow(): return datetime.now(timezone.utc).replace(tzinfo=None)

class Evidence(Base):
    __tablename__ = 'evidence'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    duplicate_of_id: Mapped[str | None] = mapped_column(ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True, index=True)
    mime_type: Mapped[str] = mapped_column(String(120), default='application/octet-stream')
    detected_format: Mapped[str] = mapped_column(String(40), default='unknown')
    source_timezone: Mapped[str] = mapped_column(String(80), default='UTC')
    clock_offset_minutes: Mapped[int] = mapped_column(Integer, default=0)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    scenario_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    processing_status: Mapped[str] = mapped_column(String(30), default='processing')
    integrity_status: Mapped[str] = mapped_column(String(20), default='not_checked')
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    records: Mapped[list['OriginalLogRecord']] = relationship(back_populates='evidence', cascade='all, delete-orphan')
    events: Mapped[list['NormalizedEvent']] = relationship(back_populates='evidence', cascade='all, delete-orphan')
    sources: Mapped[list['DataSource']] = relationship(back_populates='evidence', cascade='all, delete-orphan')

class OriginalLogRecord(Base):
    __tablename__ = 'original_log_records'
    __table_args__ = (Index('ix_original_evidence_line', 'evidence_id', 'line_number'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey('evidence.id', ondelete='CASCADE'), index=True)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    original_text: Mapped[str] = mapped_column(Text, nullable=False)
    parse_status: Mapped[str] = mapped_column(String(20), default='gap', index=True)
    parse_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    evidence: Mapped[Evidence] = relationship(back_populates='records')
    event: Mapped['NormalizedEvent | None'] = relationship(back_populates='original_record', uselist=False, cascade='all, delete-orphan')

class NormalizedEvent(Base):
    __tablename__ = 'normalized_events'
    __table_args__ = (Index('ix_event_time', 'timestamp_utc'), Index('ix_event_ip_user', 'source_ip', 'username'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey('evidence.id', ondelete='CASCADE'), index=True)
    original_record_id: Mapped[int] = mapped_column(ForeignKey('original_log_records.id', ondelete='CASCADE'), unique=True)
    timestamp_utc: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    original_timestamp: Mapped[str | None] = mapped_column(String(100))
    source_timezone: Mapped[str] = mapped_column(String(80), default='UTC')
    clock_offset_minutes: Mapped[int] = mapped_column(Integer, default=0)
    host: Mapped[str] = mapped_column(String(255), default='unknown')
    source_ip: Mapped[str | None] = mapped_column(String(80), index=True)
    username: Mapped[str | None] = mapped_column(String(160), index=True)
    event_type: Mapped[str] = mapped_column(String(120), default='event', index=True)
    severity: Mapped[str] = mapped_column(String(20), default='info', index=True)
    description: Mapped[str] = mapped_column(Text, default='')
    normalized_json: Mapped[str] = mapped_column(Text, default='{}')
    duplicate_record: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    evidence: Mapped[Evidence] = relationship(back_populates='events')
    original_record: Mapped[OriginalLogRecord] = relationship(back_populates='event')

class Investigation(Base):
    __tablename__ = 'investigations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(30), default='open', index=True)
    notes: Mapped[str] = mapped_column(Text, default='')
    triage_answers_json: Mapped[str] = mapped_column(Text, default='[]')
    manual_baseline_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    tool_assisted_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    evidence_links: Mapped[list['InvestigationEvidence']] = relationship(back_populates='investigation', cascade='all, delete-orphan')
    event_links: Mapped[list['InvestigationEvent']] = relationship(back_populates='investigation', cascade='all, delete-orphan')
    anomalies: Mapped[list['Anomaly']] = relationship(back_populates='investigation')

class InvestigationEvidence(Base):
    __tablename__ = 'investigation_evidence'
    __table_args__ = (UniqueConstraint('investigation_id', 'evidence_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey('investigations.id', ondelete='CASCADE'), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey('evidence.id', ondelete='CASCADE'), index=True)
    investigation: Mapped[Investigation] = relationship(back_populates='evidence_links')

class InvestigationEvent(Base):
    __tablename__ = 'investigation_events'
    __table_args__ = (UniqueConstraint('investigation_id', 'event_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey('investigations.id', ondelete='CASCADE'), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey('normalized_events.id', ondelete='CASCADE'), index=True)
    investigation: Mapped[Investigation] = relationship(back_populates='event_links')

class Anomaly(Base):
    __tablename__ = 'anomalies'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey('evidence.id', ondelete='SET NULL'), index=True)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey('investigations.id', ondelete='SET NULL'), index=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(30), default='heuristic')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    investigation: Mapped[Investigation | None] = relationship(back_populates='anomalies')

class DataSource(Base):
    __tablename__ = 'data_sources'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey('evidence.id', ondelete='CASCADE'), index=True)
    name: Mapped[str] = mapped_column(String(255))
    log_format: Mapped[str] = mapped_column(String(40))
    source_timezone: Mapped[str] = mapped_column(String(80), default='UTC')
    clock_offset_minutes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    evidence: Mapped[Evidence] = relationship(back_populates='sources')

class AuditRecord(Base):
    __tablename__ = 'audit_records'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(60), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(80), index=True)
    details_json: Mapped[str] = mapped_column(Text, default='{}')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

class SyntheticScenario(Base):
    __tablename__ = 'synthetic_scenarios'
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    seed: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[str] = mapped_column(Text, default='{}')
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
