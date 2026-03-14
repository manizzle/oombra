"""
File extraction — turn raw files into Contribution objects.

Supported formats:
  - .json          raw structured data or STIX 2.1 bundle
  - .csv           tabular eval data
  - .txt / .md     plain text (passed to LLM parser if key available)
  - .pdf           extracted text → field parsing
  - STIX 2.1       attack patterns, threat actors, indicators
  - MISP           event JSON export

All extraction is LOCAL. Nothing is sent anywhere here.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any

from .models import (
    AttackMap, ContribContext, EvalRecord, IOCBundle, IOCEntry,
    ObservedTechnique, Contribution,
)


# ── Public entry point ────────────────────────────────────────────────────────

def load_file(path: str | Path, context: ContribContext | None = None) -> list[Contribution]:
    """
    Load a file and return a list of Contribution objects.
    Detects format by extension and content sniffing.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    ctx = context or ContribContext()
    raw = p.read_bytes()
    suffix = p.suffix.lower()

    if suffix == ".json":
        return _load_json(raw, ctx)
    if suffix == ".csv":
        return _load_csv(raw, ctx)
    if suffix in (".txt", ".md"):
        return _load_text(raw.decode("utf-8", errors="replace"), ctx)
    if suffix == ".pdf":
        return _load_pdf(raw, ctx)

    # Try sniffing JSON anyway
    try:
        return _load_json(raw, ctx)
    except Exception:
        pass

    raise ValueError(f"Unsupported file format: {suffix}")


def load_dict(data: dict, context: ContribContext | None = None) -> list[Contribution]:
    """Load a Python dict directly (e.g. from an API response)."""
    ctx = context or ContribContext()
    return _parse_json_obj(data, ctx)


# ── JSON / STIX / MISP ────────────────────────────────────────────────────────

def _load_json(raw: bytes, ctx: ContribContext) -> list[Contribution]:
    data = json.loads(raw)
    return _parse_json_obj(data, ctx)


def _parse_json_obj(data: Any, ctx: ContribContext) -> list[Contribution]:
    # STIX 2.1 bundle
    if isinstance(data, dict) and data.get("type") == "bundle":
        return _parse_stix_bundle(data, ctx)

    # MISP event export
    if isinstance(data, dict) and "Event" in data:
        return _parse_misp_event(data["Event"], ctx)

    # Array of MISP events
    if isinstance(data, list) and data and isinstance(data[0], dict) and "Event" in data[0]:
        results = []
        for item in data:
            results.extend(_parse_misp_event(item["Event"], ctx))
        return results

    # Bakeoff eval format (dict with 'vendor' key)
    if isinstance(data, dict) and "vendor" in data:
        return [_parse_eval_dict(data, ctx)]

    # Array of eval dicts
    if isinstance(data, list) and data and isinstance(data[0], dict) and "vendor" in data[0]:
        return [_parse_eval_dict(item, ctx) for item in data]

    # AttackMap-like structure
    if isinstance(data, dict) and "techniques" in data:
        return [_parse_attack_map_dict(data, ctx)]

    # IOCBundle-like structure
    if isinstance(data, dict) and "iocs" in data:
        return [_parse_ioc_bundle_dict(data, ctx)]

    raise ValueError("Could not detect contribution type from JSON. Expected STIX bundle, MISP event, eval dict, attack map, or IOC bundle.")


def _parse_stix_bundle(bundle: dict, ctx: ContribContext) -> list[Contribution]:
    """Parse STIX 2.1 bundle into AttackMap + IOCBundle."""
    objects = bundle.get("objects", [])
    contributions: list[Contribution] = []

    techniques: list[ObservedTechnique] = []
    iocs: list[IOCEntry] = []
    threat_name: str | None = None

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "threat-actor":
            threat_name = obj.get("name")

        elif obj_type == "attack-pattern":
            # Map to MITRE technique
            ext_refs = obj.get("external_references", [])
            tech_id = next(
                (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None
            )
            techniques.append(ObservedTechnique(
                technique_id=tech_id or obj.get("id", "unknown"),
                technique_name=obj.get("name"),
                tactic=_stix_kill_chain_phase(obj),
                observed=True,
            ))

        elif obj_type == "indicator":
            pattern = obj.get("pattern", "")
            ioc_type, raw_val = _parse_stix_pattern(pattern)
            if raw_val:
                iocs.append(IOCEntry(
                    ioc_type=ioc_type,
                    value_hash=_hash_ioc(raw_val),
                    value_raw=raw_val,  # stripped by anonymizer before upload
                ))

    if techniques:
        contributions.append(AttackMap(
            context=ctx,
            threat_name=threat_name,
            techniques=techniques,
            source="stix",
        ))
    if iocs:
        contributions.append(IOCBundle(
            context=ctx,
            iocs=iocs,
            source="stix",
        ))

    return contributions


def _stix_kill_chain_phase(obj: dict) -> str | None:
    phases = obj.get("kill_chain_phases", [])
    for phase in phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name")
    return None


def _parse_stix_pattern(pattern: str) -> tuple[str, str | None]:
    """Extract type and value from a STIX pattern like [domain-name:value = 'evil.com']"""
    m = re.search(r"\[(\S+):value\s*=\s*'([^']+)'", pattern)
    if m:
        stix_type = m.group(1)
        value = m.group(2)
        type_map = {
            "domain-name": "domain",
            "ipv4-addr": "ip",
            "ipv6-addr": "ip",
            "url": "url",
            "email-addr": "email",
            "file:hashes.'MD5'": "hash-md5",
            "file:hashes.'SHA-256'": "hash-sha256",
        }
        return type_map.get(stix_type, stix_type), value
    return "unknown", None


def _parse_misp_event(event: dict, ctx: ContribContext) -> list[Contribution]:
    """Parse a MISP event JSON export."""
    iocs: list[IOCEntry] = []
    threat_name = event.get("info")

    for attr in event.get("Attribute", []):
        attr_type = attr.get("type", "")
        value = attr.get("value", "")

        ioc_type_map = {
            "domain": "domain", "domain|ip": "domain",
            "ip-dst": "ip", "ip-src": "ip",
            "url": "url",
            "email-src": "email", "email-dst": "email",
            "md5": "hash-md5",
            "sha256": "hash-sha256",
            "sha1": "hash-sha1",
            "filename|md5": "hash-md5",
            "filename|sha256": "hash-sha256",
        }

        if attr_type in ioc_type_map:
            iocs.append(IOCEntry(
                ioc_type=ioc_type_map[attr_type],
                value_hash=_hash_ioc(value),
                value_raw=value,
            ))

    contributions: list[Contribution] = []
    if iocs:
        contributions.append(IOCBundle(
            context=ctx,
            iocs=iocs,
            source="misp",
            notes=threat_name,
        ))
    return contributions


def _parse_eval_dict(d: dict, ctx: ContribContext) -> EvalRecord:
    return EvalRecord(
        context=ctx,
        vendor=d.get("vendor", d.get("tool", "")),
        category=d.get("category", d.get("type", "other")),
        overall_score=d.get("overall_score") or d.get("score"),
        detection_rate=d.get("detection_rate"),
        fp_rate=d.get("fp_rate") or d.get("false_positive_rate"),
        deploy_days=d.get("deploy_days") or d.get("deployment_days"),
        cpu_overhead=d.get("cpu_overhead"),
        ttfv_hours=d.get("ttfv_hours"),
        would_buy=d.get("would_buy"),
        top_strength=d.get("top_strength") or d.get("strength") or d.get("pros"),
        top_friction=d.get("top_friction") or d.get("friction") or d.get("cons"),
        notes=d.get("notes"),
    )


def _parse_attack_map_dict(d: dict, ctx: ContribContext) -> AttackMap:
    raw_techs = d.get("techniques", [])
    techniques = []
    for t in raw_techs:
        techniques.append(ObservedTechnique(
            technique_id=t.get("technique_id") or t.get("id", "unknown"),
            technique_name=t.get("name") or t.get("technique_name"),
            tactic=t.get("tactic"),
            observed=t.get("observed", True),
            detected_by=t.get("detected_by", []),
            missed_by=t.get("missed_by", []),
        ))
    return AttackMap(
        context=ctx,
        threat_name=d.get("threat_name") or d.get("threat"),
        techniques=techniques,
        tools_in_scope=d.get("tools_in_scope", []),
        source=d.get("source", "practitioner"),
        notes=d.get("notes"),
    )


def _parse_ioc_bundle_dict(d: dict, ctx: ContribContext) -> IOCBundle:
    raw_iocs = d.get("iocs", [])
    iocs = []
    for ioc in raw_iocs:
        iocs.append(IOCEntry(
            ioc_type=ioc.get("ioc_type", "unknown"),
            value_raw=ioc.get("value_raw"),
            value_hash=ioc.get("value_hash"),
            detected_by=ioc.get("detected_by", []),
            missed_by=ioc.get("missed_by", []),
            threat_actor=ioc.get("threat_actor"),
            campaign=ioc.get("campaign"),
        ))
    return IOCBundle(
        context=ctx,
        iocs=iocs,
        tools_in_scope=d.get("tools_in_scope", []),
        source=d.get("source", "practitioner"),
        notes=d.get("notes"),
    )


# ── CSV ───────────────────────────────────────────────────────────────────────

def _load_csv(raw: bytes, ctx: ContribContext) -> list[Contribution]:
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return []
    # Normalize headers
    results = []
    for row in rows:
        normalized = {k.lower().strip().replace(" ", "_"): v for k, v in row.items()}
        vendor = normalized.get("vendor") or normalized.get("tool") or normalized.get("product")
        if not vendor:
            continue
        results.append(_parse_eval_dict(normalized, ctx))
    return results


# ── PDF ───────────────────────────────────────────────────────────────────────

def _load_pdf(raw: bytes, ctx: ContribContext) -> list[Contribution]:
    try:
        import pypdf
    except ImportError:
        raise ImportError("Install pypdf for PDF support: pip install 'oombra[pdf]'")

    reader = pypdf.PdfReader(io.BytesIO(raw))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return _load_text(text, ctx)


# ── Plain text (regex field extraction) ──────────────────────────────────────

_SCORE_RE      = re.compile(r"(?:score|rating)[:\s]+([0-9.]+)", re.I)
_DETECTION_RE  = re.compile(r"detection[_\s]rate[:\s]+([0-9.]+)%?", re.I)
_VENDOR_RE     = re.compile(r"(?:vendor|tool|product)[:\s]+(\S+)", re.I)
_DEPLOY_RE     = re.compile(r"deploy(?:ment)?[_\s]days?[:\s]+(\d+)", re.I)


def _load_text(text: str, ctx: ContribContext) -> list[Contribution]:
    """Best-effort field extraction from unstructured text."""
    vendor_m    = _VENDOR_RE.search(text)
    score_m     = _SCORE_RE.search(text)
    detect_m    = _DETECTION_RE.search(text)
    deploy_m    = _DEPLOY_RE.search(text)

    if not vendor_m:
        raise ValueError("Could not extract vendor name from text. Use a structured format (JSON/CSV) for best results.")

    return [EvalRecord(
        context=ctx,
        vendor=vendor_m.group(1),
        category="other",
        overall_score=float(score_m.group(1)) if score_m else None,
        detection_rate=float(detect_m.group(1)) if detect_m else None,
        deploy_days=int(deploy_m.group(1)) if deploy_m else None,
        notes=text[:500],  # first 500 chars as notes; anonymizer will strip PII
    )]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_ioc(value: str) -> str:
    """SHA-256 of the normalized IOC value. Raw value never leaves machine."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()
