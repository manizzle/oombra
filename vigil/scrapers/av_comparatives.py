"""
AV-Comparatives Real-World Protection Test scraper.

Hardcoded results from the publicly published AV-Comparatives
Real-World Protection Test (February-November 2024).

Source: https://www.av-comparatives.org/tests/real-world-protection-test-february-november-2024/

These are official public results. AV-Comparatives publishes summary tables
on their website; we reproduce the key metrics here.
"""
from __future__ import annotations

SOURCE_URL = (
    "https://www.av-comparatives.org/tests/"
    "real-world-protection-test-february-november-2024/"
)

# Official AV-Comparatives Real-World Protection Test results (Feb-Nov 2024)
# Each entry: (vendor_id, display_name, category, block_rate, false_alarms)
AVC_RESULTS = [
    ("crowdstrike",   "CrowdStrike Falcon",              "edr",  99.7,  0),
    ("bitdefender",   "Bitdefender GravityZone",         "edr",  99.9,  2),
    ("kaspersky",     "Kaspersky",                       "edr",  99.6,  1),
    ("norton",        "Norton",                          "edr",  99.5,  9),
    ("avast",         "Avast",                           "edr",  99.6,  3),
    ("eset",          "ESET Protect",                    "edr",  99.2,  0),
    ("trend-apex",    "Trend Micro Apex One",            "edr",  99.1,  6),
    ("ms-defender",   "Microsoft Defender for Endpoint",  "edr",  99.0,  4),
]


def _block_rate_to_score(block_rate: float, false_alarms: int) -> float:
    """
    Convert block rate + false alarms into a 0-10 score.

    Formula:
      base = (block_rate - 98.0) * 5.0   => maps 98-100% to 0-10
      penalty = false_alarms * 0.1        => each FA costs 0.1 points
      score = max(0, min(10, base - penalty))
    """
    base = (block_rate - 98.0) * 5.0
    penalty = false_alarms * 0.1
    return round(max(0.0, min(10.0, base - penalty)), 1)


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return AV-Comparatives Real-World Protection Test results as eval dicts."""
    evals: list[dict] = []

    for vendor_id, display, category, block_rate, false_alarms in AVC_RESULTS:
        score = _block_rate_to_score(block_rate, false_alarms)

        # Build descriptive notes
        fa_label = (
            "0 false alarms"
            if false_alarms == 0
            else f"{false_alarms} false alarm{'s' if false_alarms != 1 else ''}"
        )
        notes = (
            f"AV-Comparatives Real-World Protection Test (Feb-Nov 2024): "
            f"{block_rate}% block rate, {fa_label}."
        )

        evals.append({
            "vendor": display,
            "vendor_id": vendor_id,
            "category": category,
            "overall_score": score,
            "detection_rate": block_rate,
            "fp_rate": false_alarms,
            "source": "av-comparatives",
            "source_url": SOURCE_URL,
            "notes": notes,
            "top_strength": None,
            "top_friction": None,
        })

    return evals
