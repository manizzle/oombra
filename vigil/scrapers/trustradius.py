"""
TrustRadius scraper — hardcoded public review scores.

TrustRadius focuses on verified reviews from authenticated business users.
We use publicly visible aggregate ratings (TrustRadius requires work email
for detailed access). Ratings are on a 10-point scale (native).

Source: https://www.trustradius.com/endpoint-detection-and-response-edr
Data: Public aggregate scores as of Q1 2026
"""
from __future__ import annotations


TRUSTRADIUS_REVIEWS = [
    {
        "vendor": "CrowdStrike Falcon",
        "vendor_id": "crowdstrike",
        "rating_10": 8.9,
        "review_count": 500,
    },
    {
        "vendor": "SentinelOne Singularity",
        "vendor_id": "sentinelone",
        "rating_10": 9.0,
        "review_count": 400,
    },
    {
        "vendor": "Microsoft Defender for Endpoint",
        "vendor_id": "ms-defender",
        "rating_10": 8.3,
        "review_count": 600,
    },
    {
        "vendor": "Palo Alto Cortex XDR",
        "vendor_id": "paloalto-cortex",
        "rating_10": 8.5,
        "review_count": 200,
    },
    {
        "vendor": "Trend Micro Vision One",
        "vendor_id": "trend-vision",
        "rating_10": 8.6,
        "review_count": 300,
    },
    {
        "vendor": "Carbon Black (VMware)",
        "vendor_id": "carbonblack",
        "rating_10": 7.9,
        "review_count": 250,
    },
    {
        "vendor": "Sophos Intercept X",
        "vendor_id": "sophos",
        "rating_10": 8.4,
        "review_count": 200,
    },
    {
        "vendor": "Cybereason",
        "vendor_id": "cybereason",
        "rating_10": 8.2,
        "review_count": 150,
    },
]


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return TrustRadius review scores as tool evaluation dicts."""
    evals: list[dict] = []
    for r in TRUSTRADIUS_REVIEWS:
        # TrustRadius uses a native 10-point scale — no conversion needed
        score_10 = r["rating_10"]

        evals.append({
            "vendor": r["vendor"],
            "vendor_id": r["vendor_id"],
            "category": "edr",
            "overall_score": score_10,
            "detection_rate": None,
            "fp_rate": None,
            "source": "trustradius",
            "source_url": "https://www.trustradius.com/endpoint-detection-and-response-edr",
            "notes": f"TrustRadius: {r['rating_10']}/10 ({r['review_count']}+ reviews)",
            "top_strength": None,
            "top_friction": None,
        })
    return evals
