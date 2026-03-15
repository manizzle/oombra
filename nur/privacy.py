"""
Privacy-utility configuration -- let deployers tune the tradeoff.

Higher privacy = more scrubbing = less utility.
Lower privacy  = less scrubbing = more utility (but more risk).

Levels:
  maximum:  All IOCs hashed, all text scrubbed, DP noise on everything, min-k=10
  standard: IOCs hashed, text scrubbed, DP optional, min-k=3 (default)
  research: IOCs hashed, text lightly scrubbed, no DP, min-k=2

Usage:
    from nur.privacy import get_privacy_level, apply_privacy_config
    config = get_privacy_level("standard")
    clean  = apply_privacy_config(contribution, level="standard")
"""
from __future__ import annotations

import copy
from typing import Any


PRIVACY_LEVELS: dict[str, dict[str, Any]] = {
    "maximum": {
        "ioc_hashing": True,
        "text_scrubbing": "aggressive",  # 4-pass + extra patterns
        "dp_noise": True,
        "dp_epsilon": 1.0,  # strong noise
        "min_k": 10,
        "session_key_derivation": True,
        "strip_timing": True,  # remove timestamps
        "strip_tools": False,  # keep tool names (needed for utility)
        "description": "Maximum privacy. Suitable for highly sensitive environments.",
    },
    "standard": {
        "ioc_hashing": True,
        "text_scrubbing": "standard",
        "dp_noise": False,
        "dp_epsilon": 5.0,
        "min_k": 3,
        "session_key_derivation": True,
        "strip_timing": False,
        "strip_tools": False,
        "description": "Balanced privacy and utility. Default for most deployments.",
    },
    "research": {
        "ioc_hashing": True,
        "text_scrubbing": "light",  # PII only, keep security context
        "dp_noise": False,
        "dp_epsilon": 10.0,
        "min_k": 2,
        "session_key_derivation": False,
        "strip_timing": False,
        "strip_tools": False,
        "description": "Research mode. More utility, less privacy. For trusted environments.",
    },
}


# Text fields to scrub in contributions
_TEXT_FIELDS = ("notes", "top_strength", "top_friction")

# Timing fields to strip in maximum mode
_TIMING_FIELDS = ("received_at", "created_at", "last_used", "timestamp")

# Numeric fields eligible for DP noise
_NUMERIC_FIELDS = (
    "overall_score", "detection_rate", "fp_rate", "deploy_days",
    "cpu_overhead", "ttfv_hours", "eval_duration_days",
)


def get_privacy_level(name: str = "standard") -> dict[str, Any]:
    """Get privacy configuration by level name.

    Args:
        name: One of 'maximum', 'standard', or 'research'.

    Returns:
        Dict with all privacy configuration keys.

    Raises:
        ValueError: If the level name is unknown.
    """
    if name not in PRIVACY_LEVELS:
        available = ", ".join(PRIVACY_LEVELS.keys())
        raise ValueError(f"Unknown privacy level: {name!r}. Available: {available}")
    return dict(PRIVACY_LEVELS[name])


def list_privacy_levels() -> list[dict[str, str]]:
    """List all available privacy levels with their descriptions.

    Returns:
        List of dicts with 'name' and 'description' keys.
    """
    return [
        {"name": name, "description": config["description"]}
        for name, config in PRIVACY_LEVELS.items()
    ]


def apply_privacy_config(
    contribution: dict[str, Any],
    level: str = "standard",
) -> dict[str, Any]:
    """Apply privacy configuration to a contribution before submission.

    This applies the configured scrubbing, hashing, and noise to the
    contribution dict. The original dict is not modified; a deep copy
    is returned.

    Args:
        contribution: Raw contribution dict (EvalRecord, AttackMap, or IOCBundle).
        level: Privacy level name ('maximum', 'standard', 'research').

    Returns:
        A new contribution dict with privacy transforms applied.
    """
    config = get_privacy_level(level)
    result = copy.deepcopy(contribution)

    # 1. IOC hashing
    if config["ioc_hashing"]:
        result = _apply_ioc_hashing(result)

    # 2. Text scrubbing
    scrub_mode = config["text_scrubbing"]
    result = _apply_text_scrubbing(result, scrub_mode)

    # 3. Strip timing
    if config["strip_timing"]:
        result = _strip_timing_fields(result)

    # 4. DP noise
    if config["dp_noise"]:
        epsilon = config["dp_epsilon"]
        result = _apply_dp_noise(result, epsilon)

    # 5. Annotate with privacy metadata
    result["_privacy_level"] = level
    result["_min_k"] = config["min_k"]

    return result


# -- Internal transforms -----------------------------------------------------


def _apply_ioc_hashing(contrib: dict) -> dict:
    """Hash any IOC values in the contribution."""
    try:
        from .anonymize import hash_ioc
    except ImportError:
        # Fallback: simple SHA-256
        import hashlib

        def hash_ioc(val: str) -> str:
            return hashlib.sha256(val.encode()).hexdigest()

    # Hash IOCs in ioc_bundle-style contributions
    iocs = contrib.get("iocs", [])
    for ioc in iocs:
        if "value" in ioc and "value_hash" not in ioc:
            ioc["value_hash"] = hash_ioc(ioc.pop("value"))
        elif "value" in ioc:
            ioc.pop("value", None)

    return contrib


def _apply_text_scrubbing(contrib: dict, mode: str) -> dict:
    """Scrub text fields based on the scrubbing mode."""
    try:
        from .anonymize import scrub, strip_pii, strip_security
    except ImportError:
        # Graceful fallback if anonymize is not available
        def scrub(text: str, **_kw: Any) -> str:
            return text

        def strip_pii(text: str) -> str:
            return text

        def strip_security(text: str) -> str:
            return text

    for field in _TEXT_FIELDS:
        # Check top-level and nested data
        for loc in (contrib, contrib.get("data", {})):
            val = loc.get(field)
            if not isinstance(val, str) or not val:
                continue

            if mode == "aggressive":
                # Full 4-pass: PII + security + extra
                cleaned = strip_pii(val)
                cleaned = strip_security(cleaned)
                cleaned = scrub(cleaned)
                loc[field] = cleaned
            elif mode == "standard":
                # Standard: PII + security
                cleaned = strip_pii(val)
                cleaned = strip_security(cleaned)
                loc[field] = cleaned
            elif mode == "light":
                # Light: PII only, keep security context
                loc[field] = strip_pii(val)

    return contrib


def _strip_timing_fields(contrib: dict) -> dict:
    """Remove timing fields for maximum privacy."""
    for field in _TIMING_FIELDS:
        contrib.pop(field, None)
        if "data" in contrib and isinstance(contrib["data"], dict):
            contrib["data"].pop(field, None)
        if "context" in contrib and isinstance(contrib["context"], dict):
            contrib["context"].pop(field, None)
    return contrib


def _apply_dp_noise(contrib: dict, epsilon: float) -> dict:
    """Apply differential privacy noise to numeric fields."""
    try:
        from .dp import dp_eval_record
    except ImportError:
        # DP module not available -- skip silently
        return contrib

    # Only apply to eval-type contributions with numeric data
    data = contrib.get("data", contrib)
    has_numeric = any(data.get(f) is not None for f in _NUMERIC_FIELDS)

    if not has_numeric:
        return contrib

    # Use the DP module for eval records
    try:
        contrib = dp_eval_record(contrib, epsilon=epsilon)
    except (TypeError, ValueError, KeyError):
        # If DP fails, continue without noise
        pass

    return contrib
