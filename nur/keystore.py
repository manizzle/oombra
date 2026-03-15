"""
Org-local key management for HMAC-based IOC hashing.

Stores a 256-bit secret at ~/.nur/key — auto-generated on first use,
never transmitted. Each org's HMAC hashes are unique, defeating rainbow tables.
"""
from __future__ import annotations

import hmac
import hashlib
import secrets
from pathlib import Path

_NUR_DIR = Path.home() / ".nur"
_KEY_PATH = _NUR_DIR / "key"
_BUDGET_PATH = _NUR_DIR / "budget.json"


def _ensure_dir() -> None:
    _NUR_DIR.mkdir(mode=0o700, exist_ok=True)


def get_or_create_key() -> bytes:
    """Return the org-local HMAC key, creating one if it doesn't exist."""
    _ensure_dir()
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = secrets.token_bytes(32)
    _KEY_PATH.write_bytes(key)
    _KEY_PATH.chmod(0o600)
    return key


def derive_session_key(base_key: bytes, session_id: str) -> bytes:
    """Derive a session-specific HMAC key to prevent cross-submission IOC correlation."""
    return hashlib.sha256(base_key + session_id.encode()).digest()


def hmac_ioc(value: str, secret: bytes | None = None, session_id: str | None = None) -> str:
    """
    HMAC-SHA256 of the normalized IOC value using org-local secret.

    Unlike bare SHA-256, this prevents rainbow-table attacks on the
    small IOC space (known IPs, domains, hashes).

    If *session_id* is provided, derives a session-specific key first so
    the same IOC hashes differently in each submission, preventing
    cross-submission correlation.
    """
    if secret is None:
        secret = get_or_create_key()
    if session_id is not None:
        secret = derive_session_key(secret, session_id)
    normalized = value.strip().lower().encode()
    return hmac.new(secret, normalized, hashlib.sha256).hexdigest()


def load_budget() -> dict:
    """Load privacy budget state from ~/.nur/budget.json."""
    import json
    if _BUDGET_PATH.exists():
        return json.loads(_BUDGET_PATH.read_text())
    return {"total_epsilon": 0.0, "sessions": []}


def save_budget(budget: dict) -> None:
    """Persist privacy budget state to ~/.nur/budget.json."""
    import json
    _ensure_dir()
    _BUDGET_PATH.write_text(json.dumps(budget, indent=2))
