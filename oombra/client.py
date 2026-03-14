"""
HTTP client — sends anonymized contributions to any compatible endpoint.
Platform-agnostic: point api_url at whatever ingests the oombra wire format.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from .models import AttackMap, EvalRecord, IOCBundle, Contribution


@dataclass
class UploadResult:
    success: bool
    status_code: int
    response: dict = field(default_factory=dict)
    error: str | None = None


class Client:
    """
    Minimal HTTP client for submitting contributions.

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
        with httpx.Client(timeout=15) as http:
            resp = http.post(url, json=payload, headers=headers)

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
