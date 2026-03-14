"""
Anonymization engine — the trust core of oombra.

Everything passes through here first. Four passes:

  1. PII          — emails, phones, URLs, titled names
  2. Security     — IPs, MACs, internal hostnames, API keys, cert serials,
                    private domains (but NOT public vendor domains)
  3. Bucketing    — org name → industry, headcount → size range,
                    job title → role tier, strips all org-identifying fields
  4. DP (opt)     — calibrated noise on numeric fields (epsilon parameter)

IOC values are HMAC-SHA256 hashed with org-local secret (never sent in plaintext).

Nothing leaves the machine until the user approves the result in review.py.
"""
from __future__ import annotations

import hashlib
import re

from .models import (
    AttackMap, EvalRecord, IOCBundle, IOCEntry, Contribution,
    Industry, OrgSize, Role,
)


# ══════════════════════════════════════════════════════════════════════════════
# Pass 1 — PII
# ══════════════════════════════════════════════════════════════════════════════

_EMAIL      = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE      = re.compile(
    r"(?:\+?1[-.\s]?)?"
    r"(?:\(?\d{3}\)?[-.\s]?)"
    r"\d{3}[-.\s]?\d{4}"
)
_URL        = re.compile(r"https?://[^\s<>\"]+")
_TITLE_NAME = re.compile(
    r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?"
)


def strip_pii(text: str) -> str:
    """Remove general PII from a string."""
    if not text:
        return text
    text = _EMAIL.sub("[EMAIL]", text)
    text = _PHONE.sub("[PHONE]", text)
    text = _URL.sub("[URL]", text)
    text = _TITLE_NAME.sub("[NAME]", text)
    return text


# ══════════════════════════════════════════════════════════════════════════════
# Pass 2 — Security-specific patterns
# ══════════════════════════════════════════════════════════════════════════════

_IPV4          = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6          = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_MAC           = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_INTERNAL_HOST = re.compile(
    r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:corp|internal|local|lan|intranet|private)\b",
    re.IGNORECASE,
)
_API_KEY       = re.compile(
    r"\b(?:sk_[a-zA-Z0-9_-]{20,}"
    r"|pk_[a-zA-Z0-9_-]{20,}"
    r"|ak_[a-zA-Z0-9_-]{20,}"
    r"|AKIA[A-Z0-9]{16}"
    r"|xox[bpsa]-[a-zA-Z0-9-]+"
    r"|ghp_[a-zA-Z0-9]{36}"          # GitHub PAT
    r"|glpat-[a-zA-Z0-9_-]{20,}"     # GitLab PAT
    r")\b"
)
_AWS_ACCOUNT   = re.compile(r"\b\d{12}\b")
_CERT_SERIAL   = re.compile(r"\b(?:serial[:\s]+)?[0-9A-Fa-f]{16,}\b", re.IGNORECASE)
_DOMAIN        = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")

# Domains we deliberately keep — vendor names, public references
_SAFE_DOMAINS: set[str] = {
    "github.com", "google.com", "microsoft.com", "amazon.com", "aws.com",
    "crowdstrike.com", "sentinelone.com", "paloaltonetworks.com",
    "cloudflare.com", "okta.com", "splunk.com", "wiz.io", "orca.security",
    "g2.com", "gartner.com", "forrester.com", "mitre.org", "cisa.gov",
    "intel.difalabs.com",
}

# TLD patterns we keep (likely vendor/public references, not internal infra)
_SAFE_TLDS = (".com", ".io", ".ai", ".co", ".org", ".gov", ".net")


def strip_security(text: str) -> str:
    """Remove security-sensitive infrastructure details from a string."""
    if not text:
        return text
    text = _MAC.sub("[MAC_ADDR]", text)   # before IP — MAC contains colon-separated hex
    text = _IPV4.sub("[IP_ADDR]", text)
    text = _IPV6.sub("[IP_ADDR]", text)
    text = _INTERNAL_HOST.sub("[INTERNAL_HOST]", text)
    text = _API_KEY.sub("[API_KEY]", text)
    text = _AWS_ACCOUNT.sub("[AWS_ACCOUNT]", text)
    text = _CERT_SERIAL.sub("[CERT_SERIAL]", text)

    def _replace_domain(m: re.Match) -> str:
        domain = m.group(0).lower()
        if domain in _SAFE_DOMAINS:
            return m.group(0)
        if any(domain.endswith(tld) for tld in _SAFE_TLDS):
            return m.group(0)
        return "[DOMAIN]"

    text = _DOMAIN.sub(_replace_domain, text)
    return text


def scrub(text: str) -> str:
    """Full text scrub: PII then security patterns."""
    return strip_security(strip_pii(text))


# ══════════════════════════════════════════════════════════════════════════════
# Pass 3 — Context bucketing
# ══════════════════════════════════════════════════════════════════════════════

_INDUSTRY_KEYWORDS: dict[str, list[str]] = {
    "financial":     ["bank", "financ", "invest", "insurance", "capital", "asset",
                      "fund", "credit", "trading", "fintech", "hedge"],
    "healthcare":    ["health", "hospital", "clinic", "medic", "pharma", "biotech",
                      "patient", "clinical", "ehr"],
    "tech":          ["tech", "software", "saas", "cloud", "startup", "platform",
                      "developer", "cyber", "digital", "ai", "data"],
    "government":    ["gov", "federal", "state", "municipal", "department of",
                      "dod", "dhs", "agency", "military", "defense", "intel"],
    "energy":        ["energy", "utility", "power", "oil", "gas", "electric",
                      "grid", "solar", "nuclear"],
    "retail":        ["retail", "e-commerce", "ecommerce", "store", "shop",
                      "consumer", "brand", "d2c"],
    "manufacturing": ["manufactur", "factory", "industrial", "supply chain",
                      "logistics", "production", "auto"],
    "education":     ["university", "college", "school", "educat", "academic",
                      "research", "campus"],
    "media":         ["media", "entertainment", "broadcast", "publish", "news",
                      "streaming"],
    "telecom":       ["telecom", "wireless", "mobile", "carrier", "isp", "telco"],
    "legal":         ["law", "legal", "attorney", "firm", "counsel"],
}

_ORG_SIZE_BREAKS = [
    (100,    "1-100"),
    (500,    "100-500"),
    (1_000,  "500-1000"),
    (5_000,  "1000-5000"),
    (10_000, "5000-10000"),
    (50_000, "10000-50000"),
]

_ROLE_KEYWORDS: dict[str, list[str]] = {
    "ciso":              ["ciso", "chief information security", "chief security", "cso"],
    "security-director": ["director", "head of security", "vp security", "vp of security"],
    "security-engineer": ["engineer", "architect", "sre", "devops", "developer"],
    "security-analyst":  ["analyst", "soc", "incident response", "threat hunter",
                          "threat intel"],
    "it-manager":        ["manager", "administrator", "admin", "it lead", "it ops"],
    "compliance":        ["compliance", "audit", "grc", "risk", "governance"],
}


def bucket_industry(raw: str) -> str:
    if not raw:
        return "other"
    low = raw.lower()
    for industry, keywords in _INDUSTRY_KEYWORDS.items():
        if any(kw in low for kw in keywords):
            return industry
    return "other"


def bucket_org_size(raw: str | int | None) -> str | None:
    if raw is None:
        return None
    # Already a valid bucket?
    valid = {b for _, b in _ORG_SIZE_BREAKS} | {"50000+"}
    if isinstance(raw, str) and raw in valid:
        return raw
    # Extract first number
    nums = re.findall(r"\d+", str(raw).replace(",", ""))
    if not nums:
        return None
    n = int(nums[0])
    for threshold, bucket in _ORG_SIZE_BREAKS:
        if n <= threshold:
            return bucket
    return "50000+"


def bucket_role(raw: str) -> str:
    if not raw:
        return "other"
    low = raw.lower()
    for role, keywords in _ROLE_KEYWORDS.items():
        if any(kw in low for kw in keywords):
            return role
    return "other"


def bucket_context_dict(fields: dict) -> dict:
    """
    Bucket org-identifying context fields in a plain dict.
    Strips: org_name, organization, company, company_name, org, employer.
    Replaces: industry (from org name), org_size (from headcount), role_tier (from title).
    Used by downstream consumers of oombra.
    """
    result = dict(fields)

    # Derive industry from org name if not already set
    for org_field in ("org_name", "organization", "company", "company_name", "org", "employer"):
        org = result.pop(org_field, None)
        if org and "industry" not in result:
            result["industry"] = bucket_industry(org)

    # Normalize size
    size = result.get("org_size") or result.pop("employees", None)
    if size:
        bucketed = bucket_org_size(size)
        if bucketed:
            result["org_size"] = bucketed

    # Normalize role
    role = result.get("role") or result.pop("job_title", None)
    if role:
        result["role_tier"] = bucket_role(role)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# IOC hashing
# ══════════════════════════════════════════════════════════════════════════════

def hash_ioc(value: str) -> str:
    """SHA-256 of the normalized IOC value. Raw value never leaves machine.
    NOTE: Prefer hmac_ioc() from keystore.py for rainbow-table resistance.
    """
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def hmac_hash_ioc(value: str, secret: bytes | None = None) -> str:
    """HMAC-SHA256 of IOC value with org-local secret. Rainbow-table resistant."""
    from .keystore import hmac_ioc
    return hmac_ioc(value, secret=secret)


def _hash_ioc_entries(
    bundle: IOCBundle,
    hmac_secret: bytes | None = None,
) -> IOCBundle:
    hashed = []
    for ioc in bundle.iocs:
        if ioc.value_raw and not ioc.value_hash:
            if hmac_secret is not None:
                h = hmac_hash_ioc(ioc.value_raw, secret=hmac_secret)
            else:
                h = hash_ioc(ioc.value_raw)
            ioc = ioc.model_copy(update={"value_hash": h})
        hashed.append(ioc.model_copy(update={"value_raw": None}))
    return bundle.model_copy(update={"iocs": hashed})


# ══════════════════════════════════════════════════════════════════════════════
# Main entrypoint — works on typed Contribution objects
# ══════════════════════════════════════════════════════════════════════════════

def anonymize(
    contrib: Contribution,
    epsilon: float | None = None,
    hmac_secret: bytes | None = None,
) -> Contribution:
    """
    Full anonymization pipeline on a Contribution.
    Returns new object — original untouched.

    Args:
        contrib: The contribution to anonymize.
        epsilon: If set, apply differential privacy noise (Phase 1).
        hmac_secret: If set, use HMAC for IOC hashing instead of bare SHA-256.
    """
    if isinstance(contrib, EvalRecord):
        result = contrib.model_copy(update={
            "top_strength": scrub(contrib.top_strength) if contrib.top_strength else None,
            "top_friction": scrub(contrib.top_friction) if contrib.top_friction else None,
            "notes":        scrub(contrib.notes)        if contrib.notes        else None,
        })
        if epsilon is not None:
            from .dp import dp_eval_record
            result = dp_eval_record(result, epsilon)
        return result

    if isinstance(contrib, AttackMap):
        clean_techs = [
            t.model_copy(update={"notes": scrub(t.notes) if t.notes else None})
            for t in contrib.techniques
        ]
        result = contrib.model_copy(update={
            "techniques": clean_techs,
            "notes": scrub(contrib.notes) if contrib.notes else None,
        })
        if epsilon is not None:
            from .dp import dp_attack_map
            result = dp_attack_map(result, epsilon)
        return result

    if isinstance(contrib, IOCBundle):
        b = _hash_ioc_entries(contrib, hmac_secret=hmac_secret)
        return b.model_copy(update={
            "notes": scrub(b.notes) if b.notes else None,
        })

    raise TypeError(f"Unknown contribution type: {type(contrib)}")
