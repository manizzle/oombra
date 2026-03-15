"""
SE Labs Enterprise Endpoint Protection scraper.

SE Labs is an independent UK security testing lab. Results are public
and published quarterly. Rating scale: AAA (highest) to C.

Source: https://selabs.uk/reports/enterprise-endpoint-protection/
Data: Q3/Q4 2024 (hardcoded public results)
"""
from __future__ import annotations

SELABS_URL = "https://selabs.uk/reports/enterprise-endpoint-protection/"

# SE Labs Q3/Q4 2024 Enterprise Endpoint Protection results
# TAR = Total Accuracy Rating (0-100%)
# PAR = Protection Accuracy Rating (detection, 0-100%)
# LAR = Legitimate Accuracy Rating (false positives, 0-100%)
SELABS_2024 = [
    {
        "vendor":     "CrowdStrike Falcon",
        "vendor_id":  "crowdstrike",
        "rating":     "AAA",
        "tar":        99.1,
        "par":        100.0,
        "lar":        98.3,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. 100% protection, minimal false positives.",
    },
    {
        "vendor":     "SentinelOne Singularity",
        "vendor_id":  "sentinelone",
        "rating":     "AAA",
        "tar":        98.8,
        "par":        100.0,
        "lar":        97.7,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Perfect detection, very low FP rate.",
    },
    {
        "vendor":     "Microsoft Defender for Endpoint",
        "vendor_id":  "ms-defender",
        "rating":     "AAA",
        "tar":        98.2,
        "par":        99.1,
        "lar":        97.3,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Consistent improvement year-over-year.",
    },
    {
        "vendor":     "Bitdefender GravityZone",
        "vendor_id":  "bitdefender",
        "rating":     "AAA",
        "tar":        99.4,
        "par":        100.0,
        "lar":        98.8,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Highest TAR in Q4 2024 round.",
    },
    {
        "vendor":     "ESET Protect",
        "vendor_id":  "eset",
        "rating":     "AAA",
        "tar":        98.9,
        "par":        99.5,
        "lar":        98.4,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Low resource overhead, high accuracy.",
    },
    {
        "vendor":     "Kaspersky Endpoint Security",
        "vendor_id":  "kaspersky",
        "rating":     "AAA",
        "tar":        99.2,
        "par":        100.0,
        "lar":        98.5,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Consistently top performer in SE Labs rounds.",
    },
    {
        "vendor":     "Sophos Intercept X",
        "vendor_id":  "sophos",
        "rating":     "AAA",
        "tar":        98.5,
        "par":        99.8,
        "lar":        97.3,
        "period":     "Q4 2024",
        "notes":      "SE Labs AAA. Strong across all test categories.",
    },
    {
        "vendor":     "Trend Micro Vision One",
        "vendor_id":  "trend-apex",
        "rating":     "AA",
        "tar":        97.1,
        "par":        98.4,
        "lar":        95.9,
        "period":     "Q4 2024",
        "notes":      "SE Labs AA. Good detection, slightly higher FP rate.",
    },
    {
        "vendor":     "Malwarebytes for Teams",
        "vendor_id":  "malwarebytes",
        "rating":     "AA",
        "tar":        96.8,
        "par":        97.9,
        "lar":        95.8,
        "period":     "Q4 2024",
        "notes":      "SE Labs AA. Solid SMB option, ease of use strength.",
    },
    {
        "vendor":     "F-Secure Elements",
        "vendor_id":  "f-secure",
        "rating":     "AAA",
        "tar":        98.7,
        "par":        99.6,
        "lar":        97.9,
        "period":     "Q3 2024",
        "notes":      "SE Labs AAA. Consistent performer across all quarters.",
    },
]


def _tar_to_score(tar: float) -> float:
    """Map TAR percentage to 0-10 scale."""
    return round(tar / 10.0, 1)


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return SE Labs endpoint protection results as tool evaluation dicts."""
    evals: list[dict] = []
    for r in SELABS_2024:
        score = _tar_to_score(r["tar"])
        fp_approx = round((100.0 - r["lar"]) / 10.0, 1)

        evals.append({
            "vendor": r["vendor"],
            "vendor_id": r["vendor_id"],
            "category": "edr",
            "overall_score": score,
            "detection_rate": r["par"],
            "fp_rate": fp_approx,
            "source": "selabs",
            "source_url": SELABS_URL,
            "notes": (
                f"SE Labs {r['period']}. Rating: {r['rating']}. "
                f"TAR={r['tar']}% PAR={r['par']}% LAR={r['lar']}%. "
                f"{r['notes']}"
            ),
            "top_strength": None,
            "top_friction": None,
        })
    return evals
