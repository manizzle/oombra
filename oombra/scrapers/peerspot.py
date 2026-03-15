"""
PeerSpot (formerly IT Central Station) scraper — hardcoded public review scores.

PeerSpot provides verified enterprise reviews. We use publicly visible
aggregate ratings. Ratings are on a 5-point scale, converted to 10-point.

Source: https://www.peerspot.com/categories/endpoint-detection-and-response-edr
Data: Public aggregate scores as of Q1 2026
"""
from __future__ import annotations


PEERSPOT_REVIEWS = [
    {
        "vendor": "CrowdStrike Falcon",
        "vendor_id": "crowdstrike",
        "rating_5": 4.6,
        "review_count": 400,
    },
    {
        "vendor": "SentinelOne Singularity",
        "vendor_id": "sentinelone",
        "rating_5": 4.7,
        "review_count": 350,
    },
    {
        "vendor": "Microsoft Defender for Endpoint",
        "vendor_id": "ms-defender",
        "rating_5": 4.3,
        "review_count": 500,
    },
    {
        "vendor": "Palo Alto Cortex XDR",
        "vendor_id": "paloalto-cortex",
        "rating_5": 4.4,
        "review_count": 250,
    },
    {
        "vendor": "Trend Micro Vision One",
        "vendor_id": "trend-vision",
        "rating_5": 4.5,
        "review_count": 300,
    },
    {
        "vendor": "Sophos Intercept X",
        "vendor_id": "sophos",
        "rating_5": 4.4,
        "review_count": 200,
    },
    {
        "vendor": "Carbon Black (VMware)",
        "vendor_id": "carbonblack",
        "rating_5": 4.2,
        "review_count": 250,
    },
    {
        "vendor": "Cybereason",
        "vendor_id": "cybereason",
        "rating_5": 4.3,
        "review_count": 150,
    },
    {
        "vendor": "Kaspersky Endpoint Security",
        "vendor_id": "kaspersky",
        "rating_5": 4.5,
        "review_count": 300,
    },
    {
        "vendor": "ESET Protect",
        "vendor_id": "eset",
        "rating_5": 4.5,
        "review_count": 200,
    },
]


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return PeerSpot review scores as tool evaluation dicts."""
    evals: list[dict] = []
    for r in PEERSPOT_REVIEWS:
        score_10 = round(r["rating_5"] * 2, 1)

        evals.append({
            "vendor": r["vendor"],
            "vendor_id": r["vendor_id"],
            "category": "edr",
            "overall_score": score_10,
            "detection_rate": None,
            "fp_rate": None,
            "source": "peerspot",
            "source_url": "https://www.peerspot.com/categories/endpoint-detection-and-response-edr",
            "notes": f"PeerSpot: {r['rating_5']}/5 ({r['review_count']}+ reviews)",
            "top_strength": None,
            "top_friction": None,
        })
    return evals
