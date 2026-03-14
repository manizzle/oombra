"""
HTTP client — sends anonymized contributions to any compatible endpoint.
Platform-agnostic: point api_url at whatever ingests the oombra wire format.

Includes contribution receipts (SHA-256 of anonymized payload) for
non-repudiation — prove you contributed without revealing content.
"""
from __future__ import annotations
import hashlib
import json
import os
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from .models import AttackMap, EvalRecord, IOCBundle, Contribution


_RECEIPTS_DIR = Path.home() / ".oombra" / "receipts"


@dataclass
class UploadResult:
    success: bool
    status_code: int
    response: dict = field(default_factory=dict)
    error: str | None = None
    receipt_hash: str | None = None


class Client:
    """
    HTTP client for submitting contributions.

    Usage:
        client = Client(api_url="https://intel.example.com", api_key="...")
        result = client.submit(contribution)
    """

    def __init__(self, api_url: str, api_key: str | None = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key or os.getenv("OOMBRA_API_KEY")

    def submit(self, contrib: Contribution) -> UploadResult:
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required: pip install httpx")

        payload = _serialize(contrib)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        url = f"{self.api_url}{_route_for(contrib)}"

        # Generate receipt before sending
        receipt_hash = _generate_receipt(payload)

        with httpx.Client(timeout=15) as http:
            resp = http.post(url, json=payload, headers=headers)

        success = resp.status_code == 200

        # Log to audit trail
        try:
            from .audit import log_submit, log_receipt
            log_submit(contrib, url, success, resp.status_code)
            if success:
                receipt_path = _store_receipt(receipt_hash, payload)
                log_receipt(receipt_hash, str(receipt_path))
        except Exception:
            pass  # Audit is best-effort

        if success:
            return UploadResult(
                success=True, status_code=200,
                response=resp.json(), receipt_hash=receipt_hash,
            )
        return UploadResult(
            success=False, status_code=resp.status_code,
            error=resp.text[:300], receipt_hash=receipt_hash,
        )

    def submit_secagg(
        self,
        contrib: Contribution,
        session_id: str,
        coordinator_url: str,
        n_parties: int = 3,
    ) -> UploadResult:
        """Submit via secure aggregation — splits values into shares."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required: pip install httpx")

        if not isinstance(contrib, EvalRecord):
            return UploadResult(
                success=False, status_code=0,
                error="Secure aggregation only supported for EvalRecord",
            )

        from .secagg import prepare_shares
        from .dp import _EVAL_SENSITIVITIES

        # Extract numeric values
        field_names = []
        values = []
        for f in _EVAL_SENSITIVITIES:
            val = getattr(contrib, f)
            if val is not None:
                field_names.append(f)
                values.append(float(val))

        if not values:
            return UploadResult(
                success=False, status_code=0,
                error="No numeric fields to aggregate",
            )

        # Split into shares
        share_vectors = prepare_shares(values, n_parties)

        # Enroll
        coord = coordinator_url.rstrip("/")
        with httpx.Client(timeout=15) as http:
            # Enroll
            resp = http.post(f"{coord}/secagg/enroll", json={
                "session_id": session_id,
                "party_id": f"party-{os.getpid()}",
                "n_parties": n_parties,
                "field_names": field_names,
            })
            if resp.status_code != 200:
                return UploadResult(success=False, status_code=resp.status_code, error=resp.text[:300])

            # Submit our aggregated share (sum of all our share vectors = our values)
            # In real protocol, each share_vector[i] goes to party_i
            # For MVP, we send our own summed shares to the coordinator
            our_shares = share_vectors[0]  # Our share for party 0
            resp = http.post(f"{coord}/secagg/submit-shares", json={
                "session_id": session_id,
                "party_id": f"party-{os.getpid()}",
                "shares": our_shares,
            })

        if resp.status_code == 200:
            return UploadResult(success=True, status_code=200, response=resp.json())
        return UploadResult(success=False, status_code=resp.status_code, error=resp.text[:300])

    def health(self) -> bool:
        try:
            import httpx
            resp = httpx.get(f"{self.api_url}/health", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


def _route_for(contrib: Contribution) -> str:
    if isinstance(contrib, EvalRecord):   return "/contribute/submit"
    if isinstance(contrib, AttackMap):    return "/contribute/attack-map"
    if isinstance(contrib, IOCBundle):    return "/contribute/ioc-bundle"
    raise TypeError(f"Unknown contribution type: {type(contrib)}")


def _serialize(contrib: Contribution) -> dict:
    if isinstance(contrib, EvalRecord):
        return {
            "context": {
                "industry": contrib.context.industry,
                "org_size": contrib.context.org_size,
                "role":     contrib.context.role,
            },
            "data": {
                "vendor":              contrib.vendor,
                "category":            contrib.category,
                "overall_score":       contrib.overall_score,
                "detection_rate":      contrib.detection_rate,
                "fp_rate":             contrib.fp_rate,
                "deploy_days":         contrib.deploy_days,
                "cpu_overhead":        contrib.cpu_overhead,
                "ttfv_hours":          contrib.ttfv_hours,
                "would_buy":           contrib.would_buy,
                "eval_duration_days":  contrib.eval_duration_days,
                "top_strength":        contrib.top_strength,
                "top_friction":        contrib.top_friction,
                "notes":               contrib.notes,
            },
        }
    return contrib.model_dump(mode="json")


def _generate_receipt(payload: dict) -> str:
    """SHA-256 hash of the serialized payload for non-repudiation."""
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _store_receipt(receipt_hash: str, payload: dict) -> Path:
    """Store receipt in ~/.oombra/receipts/"""
    _RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    receipt_file = _RECEIPTS_DIR / f"{ts}_{receipt_hash[:12]}.json"
    receipt_data = {
        "receipt_hash": receipt_hash,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "payload_summary": {
            "type": payload.get("type", payload.get("data", {}).get("vendor", "unknown")),
        },
    }
    receipt_file.write_text(json.dumps(receipt_data, indent=2))
    return receipt_file


def list_receipts() -> list[dict]:
    """List all stored receipts."""
    if not _RECEIPTS_DIR.exists():
        return []
    receipts = []
    for f in sorted(_RECEIPTS_DIR.glob("*.json")):
        try:
            receipts.append(json.loads(f.read_text()))
        except Exception:
            pass
    return receipts
