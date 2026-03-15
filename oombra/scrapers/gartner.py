"""
Gartner Peer Insights scraper — hardcoded public review scores.

Gartner Peer Insights requires authentication for detailed data,
so we use publicly visible aggregate ratings from their category pages.
Ratings are on a 5-point scale, converted to 10-point for oombra.

Source: https://www.gartner.com/reviews/market/endpoint-detection-and-response
Data: Public aggregate scores as of Q1 2026
"""
from __future__ import annotations


GARTNER_REVIEWS = [
    {
        "vendor": "CrowdStrike Falcon",
        "vendor_id": "crowdstrike",
        "rating_5": 4.7,
        "review_count": 600,
    },
    {
        "vendor": "SentinelOne Singularity",
        "vendor_id": "sentinelone",
        "rating_5": 4.8,
        "review_count": 500,
    },
    {
        "vendor": "Microsoft Defender for Endpoint",
        "vendor_id": "ms-defender",
        "rating_5": 4.5,
        "review_count": 800,
    },
    {
        "vendor": "Palo Alto Cortex XDR",
        "vendor_id": "paloalto-cortex",
        "rating_5": 4.4,
        "review_count": 300,
    },
    {
        "vendor": "Trend Micro Vision One",
        "vendor_id": "trend-vision",
        "rating_5": 4.6,
        "review_count": 400,
    },
]


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return Gartner Peer Insights review scores as tool evaluation dicts."""
    evals: list[dict] = []
    for r in GARTNER_REVIEWS:
        score_10 = round(r["rating_5"] * 2, 1)

        evals.append({
            "vendor": r["vendor"],
            "vendor_id": r["vendor_id"],
            "category": "edr",
            "overall_score": score_10,
            "detection_rate": None,
            "fp_rate": None,
            "source": "gartner-peer-insights",
            "source_url": "https://www.gartner.com/reviews/market/endpoint-detection-and-response",
            "notes": f"Gartner Peer Insights: {r['rating_5']}/5 ({r['review_count']}+ reviews)",
            "top_strength": None,
            "top_friction": None,
        })
    return evals
