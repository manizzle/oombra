"""
Org-local key management for HMAC-based IOC hashing.

Stores a 256-bit secret at ~/.vigil/key — auto-generated on first use,
never transmitted. Each org's HMAC hashes are unique, defeating rainbow tables.
"""
from __future__ import annotations

import hmac
import hashlib
import secrets
from pathlib import Path

_VIGIL_DIR = Path.home() / ".vigil"
_KEY_PATH = _VIGIL_DIR / "key"
_BUDGET_PATH = _VIGIL_DIR / "budget.json"


def _ensure_dir() -> None:
    _VIGIL_DIR.mkdir(mode=0o700, exist_ok=True)


def get_or_create_key() -> bytes:
    """Return the org-local HMAC key, creating one if it doesn't exist."""
    _ensure_dir()
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = secrets.token_bytes(32)
    _KEY_PATH.write_bytes(key)
    _KEY_PATH.chmod(0o600)
    return key


def hmac_ioc(value: str, secret: bytes | None = None) -> str:
    """
    HMAC-SHA256 of the normalized IOC value using org-local secret.

    Unlike bare SHA-256, this prevents rainbow-table attacks on the
    small IOC space (known IPs, domains, hashes).
    """
    if secret is None:
        secret = get_or_create_key()
    normalized = value.strip().lower().encode()
    return hmac.new(secret, normalized, hashlib.sha256).hexdigest()


def load_budget() -> dict:
    """Load privacy budget state from ~/.vigil/budget.json."""
    import json
    if _BUDGET_PATH.exists():
        return json.loads(_BUDGET_PATH.read_text())
    return {"total_epsilon": 0.0, "sessions": []}


def save_budget(budget: dict) -> None:
    """Persist privacy budget state to ~/.vigil/budget.json."""
    import json
    _ensure_dir()
    _BUDGET_PATH.write_text(json.dumps(budget, indent=2))
