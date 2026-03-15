"""
Capterra scraper — hardcoded public review scores.

Capterra is a Gartner-owned review platform focused on SMB/mid-market.
We use publicly visible aggregate ratings. Ratings are on a 5-point scale,
converted to 10-point for oombra consistency.

Source: https://www.capterra.com/endpoint-detection-and-response-software/
Data: Public aggregate scores as of Q1 2026
"""
from __future__ import annotations


CAPTERRA_REVIEWS = [
    {
        "vendor": "CrowdStrike Falcon",
        "vendor_id": "crowdstrike",
        "rating_5": 4.7,
        "review_count": 300,
    },
    {
        "vendor": "SentinelOne Singularity",
        "vendor_id": "sentinelone",
        "rating_5": 4.7,
        "review_count": 250,
    },
    {
        "vendor": "Microsoft Defender for Endpoint",
        "vendor_id": "ms-defender",
        "rating_5": 4.4,
        "review_count": 400,
    },
    {
        "vendor": "Malwarebytes Endpoint Protection",
        "vendor_id": "malwarebytes",
        "rating_5": 4.6,
        "review_count": 700,
    },
    {
        "vendor": "Sophos Intercept X",
        "vendor_id": "sophos",
        "rating_5": 4.5,
        "review_count": 350,
    },
    {
        "vendor": "Bitdefender GravityZone",
        "vendor_id": "bitdefender",
        "rating_5": 4.6,
        "review_count": 300,
    },
    {
        "vendor": "ESET Protect",
        "vendor_id": "eset",
        "rating_5": 4.6,
        "review_count": 400,
    },
    {
        "vendor": "Webroot Business Endpoint",
        "vendor_id": "webroot",
        "rating_5": 4.4,
        "review_count": 500,
    },
    {
        "vendor": "Kaspersky Endpoint Security",
        "vendor_id": "kaspersky",
        "rating_5": 4.5,
        "review_count": 350,
    },
    {
        "vendor": "Norton 360",
        "vendor_id": "norton",
        "rating_5": 4.5,
        "review_count": 600,
    },
]


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return Capterra review scores as tool evaluation dicts."""
    evals: list[dict] = []
    for r in CAPTERRA_REVIEWS:
        score_10 = round(r["rating_5"] * 2, 1)

        evals.append({
            "vendor": r["vendor"],
            "vendor_id": r["vendor_id"],
            "category": "edr",
            "overall_score": score_10,
            "detection_rate": None,
            "fp_rate": None,
            "source": "capterra",
            "source_url": "https://www.capterra.com/endpoint-detection-and-response-software/",
            "notes": f"Capterra: {r['rating_5']}/5 ({r['review_count']}+ reviews)",
            "top_strength": None,
            "top_friction": None,
        })
    return evals
