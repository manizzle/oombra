"""
Attested Data Transformation Chain — core chain structure.

Modeled after DICE (Device Identifier Composition Engine):
each stage derives a Compound Device Identifier (CDI) from the
previous stage's CDI and the current stage's evidence.

    CDI_n = HMAC-SHA256(CDI_{n-1}, evidence_n)

The chain is unforgeable: producing CDI_n requires knowing CDI_{n-1},
which requires the org's root secret. Tampering with any stage
invalidates all subsequent CDIs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import datetime
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CDI:
    """
    Compound Device Identifier — a stage's cryptographic identity.

    Derived from: HMAC-SHA256(parent_cdi, stage_evidence)
    The root CDI₀ is derived from the org's HMAC key + file hash.
    """
    value: bytes
    stage: int

    @property
    def hex(self) -> str:
        return self.value.hex()

    @property
    def short(self) -> str:
        """First 16 chars for display."""
        return self.hex[:16]

    def derive(self, evidence: bytes, next_stage: int) -> CDI:
        """Derive the next CDI in the chain."""
        new_value = hmac.new(self.value, evidence, hashlib.sha256).digest()
        return CDI(value=new_value, stage=next_stage)


@dataclass
class StageAttestation:
    """
    A single stage's attestation in the chain.

    Contains:
      - stage_id: which transformation (extract, anonymize, dp, submit)
      - cdi: this stage's CDI
      - input_hash: SHA-256 of the input to this stage
      - output_hash: SHA-256 of the output from this stage
      - evidence: stage-specific proof data
      - timestamp: when this stage was executed
      - prev_cdi: the CDI of the previous stage (for verification)
    """
    stage_id: str
    stage_num: int
    cdi: str            # hex-encoded CDI
    input_hash: str     # SHA-256 of stage input
    output_hash: str    # SHA-256 of stage output
    evidence: dict[str, Any]
    timestamp: str
    prev_cdi: str       # hex-encoded previous CDI

    def to_dict(self) -> dict:
        return {
            "stage_id": self.stage_id,
            "stage_num": self.stage_num,
            "cdi": self.cdi,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "prev_cdi": self.prev_cdi,
        }

    @classmethod
    def from_dict(cls, d: dict) -> StageAttestation:
        return cls(**d)


@dataclass
class AttestationChain:
    """
    The full ADTC chain — a sequence of stage attestations
    linked by CDI derivation.
    """
    chain_id: str
    org_key_fingerprint: str  # SHA-256 of org key (never the key itself)
    root_cdi: str
    stages: list[StageAttestation] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    version: str = "adtc-v1"

    @property
    def final_cdi(self) -> str:
        if not self.stages:
            return self.root_cdi
        return self.stages[-1].cdi

    @property
    def final_output_hash(self) -> str | None:
        if not self.stages:
            return None
        return self.stages[-1].output_hash

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "version": self.version,
            "org_key_fingerprint": self.org_key_fingerprint,
            "root_cdi": self.root_cdi,
            "stages": [s.to_dict() for s in self.stages],
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> AttestationChain:
        return cls(
            chain_id=d["chain_id"],
            version=d.get("version", "adtc-v1"),
            org_key_fingerprint=d["org_key_fingerprint"],
            root_cdi=d["root_cdi"],
            stages=[StageAttestation.from_dict(s) for s in d.get("stages", [])],
            created_at=d.get("created_at", ""),
        )

    @classmethod
    def from_json(cls, text: str) -> AttestationChain:
        return cls.from_dict(json.loads(text))


def hash_content(content: Any) -> str:
    """Deterministic SHA-256 hash of any JSON-serializable content."""
    if isinstance(content, bytes):
        return hashlib.sha256(content).hexdigest()
    if isinstance(content, str):
        return hashlib.sha256(content.encode()).hexdigest()
    canonical = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def evidence_bytes(evidence: dict) -> bytes:
    """Serialize evidence dict to bytes for CDI derivation."""
    return json.dumps(evidence, sort_keys=True, default=str).encode()


class ChainBuilder:
    """
    Builds an attestation chain stage by stage.

    Usage:
        builder = ChainBuilder(org_secret=key, file_hash=h)
        builder.add_stage("extract", input_hash, output_hash, evidence)
        builder.add_stage("anonymize", input_hash, output_hash, evidence)
        chain = builder.build()
    """

    def __init__(self, org_secret: bytes, file_hash: str, chain_id: str | None = None):
        import uuid
        self._chain_id = chain_id or str(uuid.uuid4())
        self._org_fingerprint = hashlib.sha256(org_secret).hexdigest()

        # Root CDI = HMAC(org_secret, file_hash)
        root_value = hmac.new(org_secret, file_hash.encode(), hashlib.sha256).digest()
        self._root_cdi = CDI(value=root_value, stage=0)
        self._current_cdi = self._root_cdi
        self._stages: list[StageAttestation] = []
        self._stage_counter = 0

    def add_stage(
        self,
        stage_id: str,
        input_hash: str,
        output_hash: str,
        evidence: dict[str, Any],
    ) -> CDI:
        """
        Add a stage to the chain.

        Returns the new CDI for this stage.
        """
        self._stage_counter += 1
        prev_cdi = self._current_cdi

        # Evidence includes hashes for binding
        full_evidence = {
            "stage_id": stage_id,
            "input_hash": input_hash,
            "output_hash": output_hash,
            **evidence,
        }

        # Derive new CDI
        new_cdi = prev_cdi.derive(
            evidence_bytes(full_evidence),
            self._stage_counter,
        )
        self._current_cdi = new_cdi

        # Record attestation
        self._stages.append(StageAttestation(
            stage_id=stage_id,
            stage_num=self._stage_counter,
            cdi=new_cdi.hex,
            input_hash=input_hash,
            output_hash=output_hash,
            evidence=evidence,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            prev_cdi=prev_cdi.hex,
        ))

        return new_cdi

    def build(self) -> AttestationChain:
        """Build the final attestation chain."""
        return AttestationChain(
            chain_id=self._chain_id,
            org_key_fingerprint=self._org_fingerprint,
            root_cdi=self._root_cdi.hex,
            stages=list(self._stages),
        )
