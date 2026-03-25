"""
Database models for the nur server.

SQLAlchemy 2.0 async models for contributions, aggregated scores,
IOC hashes, and attack techniques.
"""
from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    String, Float, Integer, Boolean, DateTime, Text, ForeignKey, Index, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Contribution(Base):
    """A single anonymized contribution received by the server."""
    __tablename__ = "contributions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contrib_type: Mapped[str] = mapped_column(String(20), nullable=False)  # eval, attack_map, ioc_bundle
    received_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Context (bucketed, never raw)
    industry: Mapped[str | None] = mapped_column(String(50))
    org_size: Mapped[str | None] = mapped_column(String(20))
    role: Mapped[str | None] = mapped_column(String(30))

    # EvalRecord fields
    vendor: Mapped[str | None] = mapped_column(String(100))
    category: Mapped[str | None] = mapped_column(String(50))
    overall_score: Mapped[float | None] = mapped_column(Float)
    detection_rate: Mapped[float | None] = mapped_column(Float)
    fp_rate: Mapped[float | None] = mapped_column(Float)
    deploy_days: Mapped[int | None] = mapped_column(Integer)
    cpu_overhead: Mapped[float | None] = mapped_column(Float)
    ttfv_hours: Mapped[float | None] = mapped_column(Float)
    would_buy: Mapped[bool | None] = mapped_column(Boolean)
    eval_duration_days: Mapped[int | None] = mapped_column(Integer)
    top_strength: Mapped[str | None] = mapped_column(Text)
    top_friction: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)

    # Expanded eval fields
    annual_cost: Mapped[float | None] = mapped_column(Float)
    support_quality: Mapped[float | None] = mapped_column(Float)
    decision_factor: Mapped[str | None] = mapped_column(String(50))
    also_evaluated: Mapped[str | None] = mapped_column(Text)  # JSON array string
    replacing: Mapped[str | None] = mapped_column(String(100))

    # AttackMap fields (stored as JSON)
    threat_name: Mapped[str | None] = mapped_column(String(200))
    techniques_json: Mapped[str | None] = mapped_column(Text)  # JSON array
    tools_in_scope: Mapped[str | None] = mapped_column(Text)   # JSON array
    source: Mapped[str | None] = mapped_column(String(50))

    # IOCBundle — individual IOCs stored in ioc_hashes table
    ioc_count: Mapped[int | None] = mapped_column(Integer)

    # Incident response metadata
    remediation_json: Mapped[str | None] = mapped_column(Text)  # JSON array of RemediationAction
    time_to_detect: Mapped[str | None] = mapped_column(String(20))
    time_to_contain: Mapped[str | None] = mapped_column(String(20))
    time_to_recover: Mapped[str | None] = mapped_column(String(20))
    severity: Mapped[str | None] = mapped_column(String(20))
    data_exfiltrated: Mapped[bool | None] = mapped_column(Boolean)
    ransom_paid: Mapped[bool | None] = mapped_column(Boolean)

    __table_args__ = (
        Index("ix_contrib_vendor", "vendor"),
        Index("ix_contrib_category", "category"),
        Index("ix_contrib_type", "contrib_type"),
        Index("ix_contrib_received", "received_at"),
    )


class IOCHash(Base):
    """A single hashed IOC linked to a contribution."""
    __tablename__ = "ioc_hashes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contribution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("contributions.id"), nullable=False
    )
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hex
    detected_by: Mapped[str | None] = mapped_column(Text)   # JSON array
    missed_by: Mapped[str | None] = mapped_column(Text)     # JSON array
    threat_actor: Mapped[str | None] = mapped_column(String(200))
    campaign: Mapped[str | None] = mapped_column(String(200))

    __table_args__ = (
        Index("ix_ioc_hash", "value_hash"),
        Index("ix_ioc_type", "ioc_type"),
        Index("ix_ioc_contrib", "contribution_id"),
    )


class AttackTechnique(Base):
    """A single observed technique from an AttackMap contribution."""
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contribution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("contributions.id"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # T1566
    technique_name: Mapped[str | None] = mapped_column(String(200))
    tactic: Mapped[str | None] = mapped_column(String(50))
    observed: Mapped[bool] = mapped_column(Boolean, default=True)
    detected_by: Mapped[str | None] = mapped_column(Text)   # JSON array
    missed_by: Mapped[str | None] = mapped_column(Text)     # JSON array
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_tech_id", "technique_id"),
        Index("ix_tech_contrib", "contribution_id"),
    )


class APIKeyRecord(Base):
    """Registered API key — tracks who's using nur."""
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    api_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    org_name: Mapped[str | None] = mapped_column(String(200))
    public_key: Mapped[str | None] = mapped_column(String(64))
    tier: Mapped[str] = mapped_column(String(20), default="community")  # community, enterprise
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    request_count: Mapped[int] = mapped_column(Integer, default=0)

    # Invite system
    invite_codes: Mapped[str | None] = mapped_column(Text)  # JSON list of invite codes
    invited_by: Mapped[str | None] = mapped_column(String(100))  # invite code used to register
    invite_count: Mapped[int] = mapped_column(Integer, default=0)  # people this user invited

    __table_args__ = (
        Index("ix_apikey_email", "email"),
        Index("ix_apikey_key", "api_key"),
    )


class PendingVerification(Base):
    """Pending email verification — magic link flow."""
    __tablename__ = "pending_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(200), nullable=False)
    org_name: Mapped[str | None] = mapped_column(String(200))
    public_key: Mapped[str | None] = mapped_column(String(64))
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    invite_code: Mapped[str | None] = mapped_column(String(100))


class AggregatedScore(Base):
    """Pre-computed aggregate scores per vendor (materialized for fast reads)."""
    __tablename__ = "aggregated_scores"

    vendor: Mapped[str] = mapped_column(String(100), primary_key=True)
    category: Mapped[str | None] = mapped_column(String(50))
    avg_score: Mapped[float | None] = mapped_column(Float)
    avg_detection_rate: Mapped[float | None] = mapped_column(Float)
    avg_fp_rate: Mapped[float | None] = mapped_column(Float)
    avg_deploy_days: Mapped[float | None] = mapped_column(Float)
    contribution_count: Mapped[int] = mapped_column(Integer, default=0)
    would_buy_pct: Mapped[float | None] = mapped_column(Float)  # % who would buy
    last_updated: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class VendorProfile(Base):
    """Vendor profile — claimed by vendors, visible to practitioners."""
    __tablename__ = "vendor_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vendor_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    claimed_by_email: Mapped[str | None] = mapped_column(String(200))
    demo_url: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    logo_url: Mapped[str | None] = mapped_column(String(500))
    demo_request_url: Mapped[str | None] = mapped_column(String(500))
    claimed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScrapedItem(Base):
    """Tracks scraped items for dedup — prevents re-ingestion."""
    __tablename__ = "scraped_items"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 hash of content
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # sec-edgar, hhs, pacer, soc2, mitre
    source_id: Mapped[str | None] = mapped_column(String(500), nullable=True)  # accession number, case number, URL
    ingested_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON blob
