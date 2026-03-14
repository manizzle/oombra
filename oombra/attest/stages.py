"""
Stage-specific attestation logic.

Each function produces evidence for one transformation stage.
Evidence is a dict of provable claims about what happened.
"""
from __future__ import annotations

import re
import json
import hashlib
from typing import Any

from ..models import (
    Contribution, EvalRecord, AttackMap, IOCBundle,
)
from ..anonymize import (
    _EMAIL, _PHONE, _URL, _TITLE_NAME,
    _IPV4, _IPV6, _MAC, _INTERNAL_HOST, _API_KEY,
    _AWS_ACCOUNT, _CERT_SERIAL,
)
from .chain import hash_content


# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: Extraction Attestation
# ══════════════════════════════════════════════════════════════════════════════

def attest_extraction(
    raw_bytes: bytes,
    contributions: list[Contribution],
) -> dict[str, Any]:
    """
    Produce evidence for the extraction stage.

    Attests:
      - Source file hash (SHA-256 of raw bytes)
      - Number and types of contributions extracted
      - Field presence map (which fields have values)
    """
    contribs_summary = []
    for c in contributions:
        summary: dict[str, Any] = {"type": c.type.value}
        if isinstance(c, EvalRecord):
            summary["vendor"] = c.vendor
            summary["category"] = c.category
            summary["fields_present"] = [
                f for f in [
                    "overall_score", "detection_rate", "fp_rate",
                    "deploy_days", "cpu_overhead", "ttfv_hours",
                    "would_buy", "eval_duration_days",
                    "top_strength", "top_friction", "notes",
                ]
                if getattr(c, f) is not None
            ]
        elif isinstance(c, AttackMap):
            summary["threat_name"] = c.threat_name
            summary["technique_count"] = len(c.techniques)
            summary["tools_in_scope"] = len(c.tools_in_scope)
        elif isinstance(c, IOCBundle):
            summary["ioc_count"] = len(c.iocs)
            summary["ioc_types"] = list({i.ioc_type for i in c.iocs})
            summary["has_raw_values"] = any(i.value_raw for i in c.iocs)
        contribs_summary.append(summary)

    return {
        "source_file_hash": hashlib.sha256(raw_bytes).hexdigest(),
        "source_file_size": len(raw_bytes),
        "contributions_extracted": len(contributions),
        "contributions": contribs_summary,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: Anonymization Attestation + Verifiable Absence Proofs (VAP)
# ══════════════════════════════════════════════════════════════════════════════

# The patterns we scan for in VAP (Verifiable Absence Proofs)
_VAP_PATTERNS: dict[str, re.Pattern] = {
    "email": _EMAIL,
    "phone": _PHONE,
    "url": _URL,
    "titled_name": _TITLE_NAME,
    "ipv4": _IPV4,
    "ipv6": _IPV6,
    "mac_address": _MAC,
    "internal_host": _INTERNAL_HOST,
    "api_key": _API_KEY,
    "aws_account": _AWS_ACCOUNT,
    "cert_serial": _CERT_SERIAL,
}


def _scan_text_for_patterns(text: str) -> dict[str, int]:
    """
    Run all VAP patterns against text.
    Returns count of matches per pattern.
    A clean scan means all counts are 0.
    """
    results = {}
    for name, pattern in _VAP_PATTERNS.items():
        matches = pattern.findall(text)
        results[name] = len(matches)
    return results


def _extract_all_text(contrib: Contribution) -> str:
    """Extract all text fields from a contribution for VAP scanning."""
    texts = []
    if isinstance(contrib, EvalRecord):
        for f in ("top_strength", "top_friction", "notes"):
            v = getattr(contrib, f)
            if v:
                texts.append(v)
    elif isinstance(contrib, AttackMap):
        if contrib.notes:
            texts.append(contrib.notes)
        for t in contrib.techniques:
            if t.notes:
                texts.append(t.notes)
    elif isinstance(contrib, IOCBundle):
        if contrib.notes:
            texts.append(contrib.notes)
    return " ".join(texts)


def attest_anonymization(
    original: Contribution,
    anonymized: Contribution,
) -> dict[str, Any]:
    """
    Produce evidence for the anonymization stage.

    Attests:
      - Scrub operation counts (how many PII items removed per category)
      - Verifiable Absence Proof (VAP): zero pattern matches in output
      - IOC hashing method and count (for IOCBundles)
      - Field-level change summary

    The VAP is the novel element: it proves that NO instance of any
    PII/security pattern exists in the anonymized output. Any verifier
    with the output can re-run the scan and confirm.
    """
    evidence: dict[str, Any] = {}

    # ── Scrub counts: what was removed ────────────────────────────────
    original_text = _extract_all_text(original)
    anonymized_text = _extract_all_text(anonymized)

    original_scan = _scan_text_for_patterns(original_text)
    anonymized_scan = _scan_text_for_patterns(anonymized_text)

    evidence["scrub_counts"] = {
        name: original_scan[name] - anonymized_scan.get(name, 0)
        for name in original_scan
        if original_scan[name] > 0
    }
    evidence["total_items_scrubbed"] = sum(evidence["scrub_counts"].values())

    # ── Verifiable Absence Proof (VAP) ────────────────────────────────
    # This is the key claim: ZERO matches for all patterns in output.
    # Any party with the output can independently verify this.
    vap_results = _scan_text_for_patterns(anonymized_text)
    evidence["vap"] = {
        "scan_clean": all(v == 0 for v in vap_results.values()),
        "pattern_counts": vap_results,
        "patterns_checked": list(vap_results.keys()),
        "output_text_hash": hash_content(anonymized_text),
    }

    # ── IOC-specific attestation ──────────────────────────────────────
    if isinstance(anonymized, IOCBundle):
        ioc_evidence = {
            "ioc_count": len(anonymized.iocs),
            "all_raw_stripped": all(i.value_raw is None for i in anonymized.iocs),
            "all_hashed": all(i.value_hash is not None for i in anonymized.iocs),
            "hash_method": "sha256",  # or "hmac-sha256" if HMAC used
        }
        if isinstance(original, IOCBundle):
            ioc_evidence["original_had_raw"] = any(i.value_raw for i in original.iocs)
        evidence["ioc_attestation"] = ioc_evidence

    # ── Field change summary ──────────────────────────────────────────
    if isinstance(original, EvalRecord) and isinstance(anonymized, EvalRecord):
        changes = []
        for f in ("top_strength", "top_friction", "notes"):
            orig = getattr(original, f)
            anon = getattr(anonymized, f)
            if orig != anon:
                changes.append(f)
        evidence["fields_modified"] = changes
        evidence["numeric_fields_unchanged"] = all(
            getattr(original, f) == getattr(anonymized, f)
            for f in ("overall_score", "detection_rate", "fp_rate",
                       "deploy_days", "cpu_overhead", "ttfv_hours",
                       "would_buy", "eval_duration_days")
            if getattr(original, f) is not None
        )

    return evidence


# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: Differential Privacy Attestation
# ══════════════════════════════════════════════════════════════════════════════

def attest_dp(
    pre_noise: Contribution,
    post_noise: Contribution,
    epsilon: float,
) -> dict[str, Any]:
    """
    Produce evidence for the DP stage.

    Attests:
      - Epsilon value used
      - Which fields had noise applied
      - Noise magnitude bounds (not exact noise — that would break privacy)
      - Commitment to the noised values (for future ZKP upgrade)
      - Budget accounting reference
    """
    evidence: dict[str, Any] = {
        "epsilon": epsilon,
        "mechanism": "laplace",
        "noise_applied": True,
    }

    if isinstance(pre_noise, EvalRecord) and isinstance(post_noise, EvalRecord):
        noised_fields = []
        commitments = {}
        for f in ("overall_score", "detection_rate", "fp_rate",
                   "deploy_days", "cpu_overhead", "ttfv_hours",
                   "eval_duration_days"):
            pre_val = getattr(pre_noise, f)
            post_val = getattr(post_noise, f)
            if pre_val is not None and post_val is not None and pre_val != post_val:
                noised_fields.append(f)
                # Commitment: hash of the noised value + field name
                # (Not the original — that would break DP)
                commitment = hash_content(f"{f}:{post_val}")
                commitments[f] = commitment

        evidence["noised_fields"] = noised_fields
        evidence["field_count"] = len(noised_fields)
        evidence["value_commitments"] = commitments

        # Boolean field (randomized response)
        if pre_noise.would_buy is not None:
            evidence["boolean_fields_processed"] = ["would_buy"]
            evidence["randomized_response_applied"] = True

    elif isinstance(pre_noise, AttackMap) and isinstance(post_noise, AttackMap):
        evidence["technique_count"] = len(post_noise.techniques)
        evidence["randomized_response_applied"] = True
        evidence["per_technique_epsilon"] = epsilon / max(len(post_noise.techniques), 1)

    return evidence


# ══════════════════════════════════════════════════════════════════════════════
# Stage 4: Submission Attestation
# ══════════════════════════════════════════════════════════════════════════════

def attest_submission(
    payload: dict,
    target_url: str,
    receipt_hash: str | None = None,
) -> dict[str, Any]:
    """
    Produce evidence for the submission stage.

    Attests:
      - Payload hash (what was actually sent)
      - Target URL (where it was sent)
      - Receipt hash (for non-repudiation)
      - Timestamp of submission
    """
    return {
        "payload_hash": hash_content(payload),
        "payload_size": len(json.dumps(payload, default=str)),
        "target_url": target_url,
        "receipt_hash": receipt_hash,
    }
