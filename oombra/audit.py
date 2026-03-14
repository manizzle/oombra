"""
Append-only local audit log — proves to compliance exactly what left the machine.

Log lives at ~/.oombra/audit.log. Each entry records what was scrubbed,
what was sent, and when — timestamped and structured as JSON lines.
"""
from __future__ import annotations

import json
import datetime
from pathlib import Path
from typing import Any

from .models import Contribution, EvalRecord, AttackMap, IOCBundle

_OOMBRA_DIR = Path.home() / ".oombra"
_AUDIT_PATH = _OOMBRA_DIR / "audit.log"


def _ensure_dir() -> None:
    _OOMBRA_DIR.mkdir(mode=0o700, exist_ok=True)


def log_event(
    event_type: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Append a single audit event to the log."""
    _ensure_dir()
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event_type,
        **(details or {}),
    }
    with _AUDIT_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def log_scrub(contrib: Contribution, fields_scrubbed: list[str]) -> None:
    """Record that fields were scrubbed from a contribution."""
    log_event("scrub", {
        "contrib_type": contrib.type.value,
        "fields_scrubbed": fields_scrubbed,
    })


def log_submit(
    contrib: Contribution,
    target_url: str,
    success: bool,
    status_code: int,
) -> None:
    """Record that a contribution was submitted (or attempted)."""
    details: dict[str, Any] = {
        "contrib_type": contrib.type.value,
        "target_url": target_url,
        "success": success,
        "status_code": status_code,
    }
    if isinstance(contrib, EvalRecord):
        details["vendor"] = contrib.vendor
        details["category"] = contrib.category
    elif isinstance(contrib, AttackMap):
        details["threat_name"] = contrib.threat_name
        details["technique_count"] = len(contrib.techniques)
    elif isinstance(contrib, IOCBundle):
        details["ioc_count"] = len(contrib.iocs)
    log_event("submit", details)


def log_receipt(receipt_hash: str, receipt_path: str) -> None:
    """Record that a contribution receipt was generated."""
    log_event("receipt", {
        "receipt_hash": receipt_hash,
        "receipt_path": receipt_path,
    })


def read_log(last_n: int | None = None) -> list[dict]:
    """Read audit log entries. Returns most recent last_n if specified."""
    if not _AUDIT_PATH.exists():
        return []
    lines = _AUDIT_PATH.read_text().strip().split("\n")
    if not lines or lines == [""]:
        return []
    entries = [json.loads(line) for line in lines if line.strip()]
    if last_n is not None:
        entries = entries[-last_n:]
    return entries


def clear_log() -> None:
    """Clear the audit log (for testing only)."""
    if _AUDIT_PATH.exists():
        _AUDIT_PATH.unlink()
