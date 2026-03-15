"""
Core data models for Bakeoff contributions.

Three types of contributions supported:
  - EvalRecord:   a practitioner's evaluation of a security tool
  - AttackMap:    an observed or simulated kill chain (MITRE ATT&CK aligned)
  - IOCBundle:    indicators of compromise linked to specific tools/vendors

All models are designed for anonymization — no PII fields, only buckets.
"""
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


# ── Shared enums ──────────────────────────────────────────────────────────────

class Industry(str, Enum):
    financial      = "financial"
    healthcare     = "healthcare"
    tech           = "tech"
    government     = "government"
    retail         = "retail"
    energy         = "energy"
    manufacturing  = "manufacturing"
    education      = "education"
    other          = "other"


class OrgSize(str, Enum):
    xs   = "1-100"
    s    = "100-500"
    m    = "500-1000"
    l    = "1000-5000"
    xl   = "5000-10000"
    xxl  = "10000+"


class Role(str, Enum):
    ciso              = "ciso"
    security_director = "security-director"
    security_engineer = "security-engineer"
    security_analyst  = "security-analyst"
    it_manager        = "it-manager"
    compliance        = "compliance"
    other             = "other"


class ContribType(str, Enum):
    eval       = "eval"
    attack_map = "attack_map"
    ioc_bundle = "ioc_bundle"


# ── Context (attached to every contribution) ──────────────────────────────────

class ContribContext(BaseModel):
    industry: Industry | None = None
    org_size: OrgSize | None  = None
    role: Role | None         = None


# ── EvalRecord ────────────────────────────────────────────────────────────────

class EvalRecord(BaseModel):
    """A practitioner's evaluation of a security tool."""
    type: ContribType = ContribType.eval
    context: ContribContext = Field(default_factory=ContribContext)

    # Required
    vendor: str                      # "CrowdStrike", "Splunk", etc.
    category: str                    # "edr", "siem", "cnapp", ...

    # Scored fields (all optional — contribute what you know)
    overall_score: float | None      = Field(None, ge=0, le=10)
    detection_rate: float | None     = Field(None, ge=0, le=100)
    fp_rate: float | None            = Field(None, ge=0, le=100)
    deploy_days: int | None          = None
    cpu_overhead: float | None       = Field(None, ge=0, le=100)
    ttfv_hours: float | None         = None
    would_buy: bool | None           = None
    eval_duration_days: int | None   = None

    # Free-text (will be anonymized before send)
    top_strength: str | None         = None
    top_friction: str | None         = None
    notes: str | None                = None


# ── AttackMap ─────────────────────────────────────────────────────────────────

class ObservedTechnique(BaseModel):
    """A single observed or simulated MITRE ATT&CK technique."""
    technique_id: str                # "T1566"
    technique_name: str | None       = None
    tactic: str | None               = None
    observed: bool                   = True   # True=seen in wild, False=simulated
    detected_by: list[str]           = Field(default_factory=list)   # vendor slugs
    missed_by: list[str]             = Field(default_factory=list)   # vendor slugs
    notes: str | None                = None   # will be anonymized


class AttackMap(BaseModel):
    """An observed or simulated kill chain, MITRE ATT&CK aligned."""
    type: ContribType = ContribType.attack_map
    context: ContribContext = Field(default_factory=ContribContext)

    threat_name: str | None          = None   # "APT28", "ransomware campaign", etc.
    techniques: list[ObservedTechnique] = Field(default_factory=list)
    tools_in_scope: list[str]        = Field(default_factory=list)   # vendor slugs
    source: str                      = "practitioner"   # "red-team", "incident", "simulation"
    notes: str | None                = None


# ── IOCBundle ─────────────────────────────────────────────────────────────────

class IOCEntry(BaseModel):
    """A single indicator of compromise."""
    ioc_type: str               # "domain", "ip", "hash-md5", "hash-sha256", "url", "email"
    # value is NEVER stored raw — it is hashed before leaving this machine
    value_hash: str | None = None     # SHA-256 of normalized value (set by anonymizer)
    value_raw: str | None  = None     # only exists locally, stripped before upload

    detected_by: list[str]     = Field(default_factory=list)  # vendor slugs
    missed_by: list[str]       = Field(default_factory=list)
    threat_actor: str | None   = None
    campaign: str | None       = None


class IOCBundle(BaseModel):
    """A set of IOCs linked to vendor detection outcomes."""
    type: ContribType = ContribType.ioc_bundle
    context: ContribContext = Field(default_factory=ContribContext)

    iocs: list[IOCEntry]             = Field(default_factory=list)
    tools_in_scope: list[str]        = Field(default_factory=list)
    source: str                      = "practitioner"   # "incident", "threat-hunt", "red-team"
    notes: str | None                = None


# ── Union type for the upload pipeline ───────────────────────────────────────

Contribution = EvalRecord | AttackMap | IOCBundle


def contribution_type(c: Contribution) -> str:
    return c.type.value
