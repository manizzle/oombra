"""
Chain verification — server-side and auditor-side.

Any party with the attestation chain + final payload can verify:
  1. CDI chain integrity (each CDI derives correctly from previous)
  2. Verifiable Absence Proof (re-run pattern scans)
  3. Payload hash matches chain's final output hash
  4. Stage evidence consistency

Verification does NOT require the org's secret key —
it only needs the chain and the payload.
"""
from __future__ import annotations

import hmac
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .chain import (
    AttestationChain,
    StageAttestation,
    hash_content,
    evidence_bytes,
)
from .stages import _scan_text_for_patterns


@dataclass
class VerificationResult:
    """Result of chain verification."""
    valid: bool
    chain_intact: bool = False
    vap_clean: bool = False
    payload_matches: bool = False
    org_key_present: bool = False
    stage_results: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        parts = [f"Chain: {status}"]
        if self.chain_intact:
            parts.append("CDI chain intact")
        if self.vap_clean:
            parts.append("VAP clean (no PII patterns)")
        if self.payload_matches:
            parts.append("Payload matches attestation")
        if self.errors:
            parts.append(f"Errors: {', '.join(self.errors)}")
        return " | ".join(parts)


def verify_chain(
    chain: AttestationChain,
    payload: dict | str | None = None,
) -> VerificationResult:
    """
    Verify an attestation chain.

    Args:
        chain: The attestation chain to verify.
        payload: The final payload (for hash and VAP verification).
                 If None, only CDI chain integrity is checked.

    Returns:
        VerificationResult with detailed findings.
    """
    result = VerificationResult(valid=False)
    result.org_key_present = bool(chain.org_key_fingerprint)

    # ── Step 1: Verify CDI chain integrity ────────────────────────────
    chain_ok = _verify_cdi_chain(chain, result)
    result.chain_intact = chain_ok

    # ── Step 2: Verify payload hash ───────────────────────────────────
    if payload is not None:
        payload_hash = hash_content(payload)
        if chain.final_output_hash:
            result.payload_matches = payload_hash == chain.final_output_hash
            if not result.payload_matches:
                result.errors.append(
                    f"Payload hash mismatch: expected {chain.final_output_hash[:16]}..., "
                    f"got {payload_hash[:16]}..."
                )
        else:
            result.warnings.append("Chain has no final output hash to verify against")
    else:
        result.warnings.append("No payload provided — skipping hash verification")

    # ── Step 3: Verify VAP (if payload has text) ──────────────────────
    if payload is not None:
        result.vap_clean = verify_vap(payload)
        if not result.vap_clean:
            result.errors.append("VAP failed: PII patterns detected in payload")

    # ── Step 4: Verify stage-specific evidence ────────────────────────
    for stage in chain.stages:
        stage_result = _verify_stage(stage)
        result.stage_results.append(stage_result)
        if not stage_result.get("valid", True):
            result.errors.append(f"Stage {stage.stage_id} verification failed")

    # ── Final verdict ─────────────────────────────────────────────────
    result.valid = (
        result.chain_intact
        and (result.payload_matches or payload is None)
        and result.vap_clean if payload is not None else result.chain_intact
    )

    return result


def _verify_cdi_chain(
    chain: AttestationChain,
    result: VerificationResult,
) -> bool:
    """
    Verify that each CDI correctly derives from the previous.

    We can't verify CDI₀ (requires org secret), but we CAN verify
    that each subsequent CDI was correctly derived from its predecessor.
    """
    if not chain.stages:
        result.warnings.append("Empty chain — nothing to verify")
        return True

    # Verify first stage links to root
    if chain.stages[0].prev_cdi != chain.root_cdi:
        result.errors.append("First stage's prev_cdi doesn't match root CDI")
        return False

    # Verify each subsequent stage links to previous
    for i in range(1, len(chain.stages)):
        prev_stage = chain.stages[i - 1]
        curr_stage = chain.stages[i]
        if curr_stage.prev_cdi != prev_stage.cdi:
            result.errors.append(
                f"Stage {curr_stage.stage_id} prev_cdi doesn't match "
                f"previous stage's CDI"
            )
            return False

    # Verify CDI derivation for each stage
    # We reconstruct each CDI from prev_cdi + evidence
    for stage in chain.stages:
        full_evidence = {
            "stage_id": stage.stage_id,
            "input_hash": stage.input_hash,
            "output_hash": stage.output_hash,
            **stage.evidence,
        }
        expected_cdi = hmac.new(
            bytes.fromhex(stage.prev_cdi),
            evidence_bytes(full_evidence),
            hashlib.sha256,
        ).hexdigest()

        if expected_cdi != stage.cdi:
            result.errors.append(
                f"Stage {stage.stage_id} CDI derivation mismatch: "
                f"expected {expected_cdi[:16]}..., got {stage.cdi[:16]}..."
            )
            return False

    return True


def verify_vap(payload: Any) -> bool:
    """
    Verifiable Absence Proof: verify that no PII patterns exist in payload.

    This is the bilateral verification step: the server independently
    runs the same regex patterns and confirms zero matches.
    """
    # Extract all text from the payload
    text = _extract_text_from_payload(payload)
    if not text:
        return True  # No text to scan

    scan = _scan_text_for_patterns(text)
    return all(count == 0 for count in scan.values())


# Fields that contain expected hashes/identifiers (not PII)
_SKIP_FIELDS = {
    "value_hash", "ioc_type", "type", "technique_id", "chain_id",
    "cdi", "prev_cdi", "root_cdi", "org_key_fingerprint",
    "input_hash", "output_hash", "receipt_hash", "payload_hash",
    "batch_hash", "commitment", "randomness",
}


def _extract_text_from_payload(payload: Any) -> str:
    """
    Extract text fields from a payload for VAP scanning.
    Skips fields that contain expected hashes/identifiers.
    """
    if isinstance(payload, str):
        return payload

    if isinstance(payload, dict):
        text_parts = []
        for key, value in payload.items():
            if key in _SKIP_FIELDS:
                continue
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, dict):
                text_parts.append(_extract_text_from_payload(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        text_parts.append(item)
                    elif isinstance(item, dict):
                        text_parts.append(_extract_text_from_payload(item))
        return " ".join(text_parts)

    return ""


def _verify_stage(stage: StageAttestation) -> dict:
    """Verify stage-specific evidence constraints."""
    result = {"stage_id": stage.stage_id, "valid": True, "checks": []}

    if stage.stage_id == "anonymize":
        # Check VAP claim in evidence
        vap = stage.evidence.get("vap", {})
        if vap.get("scan_clean") is not None:
            result["checks"].append({
                "check": "vap_claimed_clean",
                "value": vap["scan_clean"],
            })
        scrub_count = stage.evidence.get("total_items_scrubbed", 0)
        result["checks"].append({
            "check": "items_scrubbed",
            "value": scrub_count,
        })

    elif stage.stage_id == "dp":
        epsilon = stage.evidence.get("epsilon")
        if epsilon is not None:
            result["checks"].append({
                "check": "epsilon_declared",
                "value": epsilon,
            })
            if epsilon <= 0:
                result["valid"] = False
                result["checks"].append({
                    "check": "epsilon_positive",
                    "value": False,
                    "error": "Epsilon must be positive",
                })

    elif stage.stage_id == "submit":
        receipt = stage.evidence.get("receipt_hash")
        result["checks"].append({
            "check": "receipt_present",
            "value": receipt is not None,
        })

    return result


def verify_chain_json(chain_json: str, payload: dict | None = None) -> VerificationResult:
    """Convenience: verify from JSON string."""
    chain = AttestationChain.from_json(chain_json)
    return verify_chain(chain, payload)
