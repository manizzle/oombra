"""
Vendor registry and scoring engine.

In-memory vendor metadata loaded from JSON data files, plus weighted scoring
ported from bakeoff's scoring module.
"""
from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ── Module-level caches ──────────────────────────────────────────────
_capabilities_cache: dict | None = None
_integrations_cache: dict | None = None
_mitre_cache: dict | None = None

# ── Vendor Registry ──────────────────────────────────────────────────

VENDOR_REGISTRY: dict[str, dict] = {
    "crowdstrike": {
        "display_name": "CrowdStrike",
        "category": "edr",
        "price_range": "$25-60/endpoint/yr",
        "certifications": ["FedRAMP", "SOC2", "ISO27001"],
        "compliance_frameworks": ["NIST", "PCI-DSS", "HIPAA"],
        "known_issues": "Caused global IT outage in July 2024 via faulty channel file update",
        "insurance_carriers": ["Coalition", "At-Bay", "Corvus"],
    },
    "sentinelone": {
        "display_name": "SentinelOne",
        "category": "edr",
        "price_range": "$20-50/endpoint/yr",
        "certifications": ["SOC2", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST", "PCI-DSS"],
        "known_issues": "",
        "insurance_carriers": ["Coalition", "At-Bay"],
    },
    "ms-defender": {
        "display_name": "Microsoft Defender",
        "category": "edr",
        "price_range": "$5-12/user/mo (E5)",
        "certifications": ["FedRAMP-High", "SOC2", "ISO27001"],
        "compliance_frameworks": ["NIST", "PCI-DSS", "HIPAA", "FedRAMP"],
        "known_issues": "Complex licensing; requires E5 for full feature set",
        "insurance_carriers": ["Coalition", "At-Bay", "Corvus", "Resilience"],
    },
    "splunk": {
        "display_name": "Splunk",
        "category": "siem",
        "price_range": "$2-15K/day ingest",
        "certifications": ["SOC2", "FedRAMP-Moderate", "ISO27001"],
        "compliance_frameworks": ["NIST", "PCI-DSS", "HIPAA"],
        "known_issues": "High cost at scale; licensing complexity",
        "insurance_carriers": ["Coalition", "Corvus"],
    },
    "palo-alto": {
        "display_name": "Palo Alto Networks",
        "category": "ngfw",
        "price_range": "$20-80K/appliance",
        "certifications": ["FedRAMP", "SOC2", "CC-EAL4+"],
        "compliance_frameworks": ["NIST", "PCI-DSS"],
        "known_issues": "Critical PAN-OS vulnerabilities in 2024 (CVE-2024-0012, CVE-2024-9474)",
        "insurance_carriers": ["Coalition", "At-Bay"],
    },
    "okta": {
        "display_name": "Okta",
        "category": "iam",
        "price_range": "$6-15/user/mo",
        "certifications": ["SOC2", "FedRAMP-High", "ISO27001"],
        "compliance_frameworks": ["NIST", "PCI-DSS", "HIPAA"],
        "known_issues": "Customer support system breach Oct 2023; Lapsus$ breach 2022",
        "insurance_carriers": ["Coalition", "At-Bay", "Corvus"],
    },
    "wiz": {
        "display_name": "Wiz",
        "category": "cnapp",
        "price_range": "$30-60K/yr (cloud workloads)",
        "certifications": ["SOC2", "ISO27001"],
        "compliance_frameworks": ["NIST", "CIS"],
        "known_issues": "",
        "insurance_carriers": ["Coalition"],
    },
    "fortinet": {
        "display_name": "Fortinet",
        "category": "ngfw",
        "price_range": "$5-40K/appliance",
        "certifications": ["FedRAMP", "SOC2", "CC-NDPP"],
        "compliance_frameworks": ["NIST", "PCI-DSS"],
        "known_issues": "Multiple critical FortiOS CVEs exploited in the wild (2023-2024)",
        "insurance_carriers": ["Coalition"],
    },
    "proofpoint": {
        "display_name": "Proofpoint",
        "category": "email",
        "price_range": "$3-8/user/mo",
        "certifications": ["SOC2", "ISO27001"],
        "compliance_frameworks": ["NIST", "HIPAA"],
        "known_issues": "",
        "insurance_carriers": ["Coalition", "At-Bay"],
    },
    "zscaler": {
        "display_name": "Zscaler",
        "category": "ztna",
        "price_range": "$80-150/user/yr",
        "certifications": ["SOC2", "FedRAMP-High", "ISO27001"],
        "compliance_frameworks": ["NIST", "PCI-DSS"],
        "known_issues": "",
        "insurance_carriers": ["Coalition", "At-Bay"],
    },
}

# ── Source weights for scoring (ported from bakeoff) ─────────────────

SOURCE_WEIGHTS: dict[str, float] = {
    "mitre": 3.0,
    "mitre-attack-evals": 3.0,
    "av-test": 2.5,
    "selabs": 2.5,
    "cisa-kev": 2.0,
    "community": 1.5,
    "reddit": 1.0,
    "hackernews": 1.0,
    "g2": 0.8,
    "gartner": 0.8,
    "forrester": 0.8,
}
DEFAULT_WEIGHT = 1.0


# ── Vendor helpers ───────────────────────────────────────────────────

def get_vendor(vendor_id: str) -> dict | None:
    """Look up a vendor by slug. Returns dict with metadata or None."""
    return VENDOR_REGISTRY.get(vendor_id.lower())


def list_vendors(category: str | None = None) -> list[dict]:
    """List all vendors, optionally filtered by category."""
    out = []
    for vid, v in VENDOR_REGISTRY.items():
        if category and v["category"] != category.lower():
            continue
        out.append({"id": vid, **v})
    return out


# ── Data file loaders ────────────────────────────────────────────────

def load_capabilities() -> dict:
    global _capabilities_cache
    if _capabilities_cache is None:
        with open(DATA_DIR / "capabilities.json") as f:
            _capabilities_cache = json.load(f)
    return _capabilities_cache


def load_integrations() -> dict:
    global _integrations_cache
    if _integrations_cache is None:
        with open(DATA_DIR / "integrations.json") as f:
            _integrations_cache = json.load(f)
    return _integrations_cache


def load_mitre_map() -> dict:
    global _mitre_cache
    if _mitre_cache is None:
        with open(DATA_DIR / "mitre_map.json") as f:
            _mitre_cache = json.load(f)
    return _mitre_cache


# ── Scoring engine ───────────────────────────────────────────────────

def weighted_score(evals: list[dict]) -> float | None:
    """
    Compute weighted average score across evaluations.
    Each eval dict must have 'overall_score' and optionally 'source'.
    Returns None if no scoreable evaluations.
    """
    scoreable = [e for e in evals if e.get("overall_score") is not None]
    if not scoreable:
        return None

    numerator = 0.0
    denominator = 0.0
    for ev in scoreable:
        score = ev["overall_score"]
        source = ev.get("source", "community")
        weight = SOURCE_WEIGHTS.get(source, DEFAULT_WEIGHT)
        numerator += score * weight
        denominator += weight

    if denominator == 0:
        return None

    return round(numerator / denominator, 2)


def confidence_level(eval_count: int, source_count: int) -> str:
    """
    Return a confidence tier based on data coverage.
    """
    if eval_count >= 8 and source_count >= 5:
        return "high"
    if eval_count >= 4 and source_count >= 3:
        return "medium"
    if eval_count >= 3:
        return "low"
    return "insufficient"
