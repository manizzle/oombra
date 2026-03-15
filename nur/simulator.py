"""
Attack Chain Simulator -- simulate the most common attack chains against your stack.

Shows exactly where your defenses break. Uses real MITRE technique mappings
from mitre_map.json and vendor coverage data from the vendor registry.

Usage:
    from nur.simulator import simulate_attack
    result = simulate_attack(["crowdstrike", "splunk", "okta"], "healthcare", "ransomware")
    for step in result["chain"]:
        print(f"  {step['technique_id']} -> {step['result']}")
"""
from __future__ import annotations

from typing import Any

from .verticals import get_vertical
from .server.vendors import VENDOR_REGISTRY, load_mitre_map
from .intelligence import ATTACK_CHAINS, INDUSTRY_BASELINES


# -- Attack type aliases mapped to chain names per vertical ------------------

ATTACK_TYPE_MAP: dict[str, dict[str, str]] = {
    "healthcare": {
        "ransomware": "Classic Ransomware",
        "double-extortion": "Double Extortion",
    },
    "financial": {
        "apt": "APT Credential Harvest",
        "bec": "BEC Wire Fraud",
    },
    "energy": {
        "ics": "ICS/OT Pivot",
        "ransomware": "Ransomware (IT-side)",
    },
    "government": {
        "supply-chain": "Supply Chain Compromise",
        "apt": "Diplomatic Phishing",
    },
}

# Default attack type per vertical
DEFAULT_ATTACK_TYPE: dict[str, str] = {
    "healthcare": "ransomware",
    "financial": "apt",
    "energy": "ics",
    "government": "supply-chain",
}

# Technique-level detection probabilities by vendor category.
# These represent typical real-world detection rates (not lab benchmarks).
CATEGORY_DETECTION_RATES: dict[str, dict[str, float]] = {
    "initial-access": {
        "email": 0.85,
        "iam": 0.80,
        "ztna": 0.75,
        "waf": 0.70,
        "vm": 0.60,
        "edr": 0.40,
        "ndr": 0.30,
    },
    "execution": {
        "edr": 0.90,
        "siem": 0.50,
        "ndr": 0.30,
    },
    "lateral-movement": {
        "ndr": 0.80,
        "edr": 0.75,
        "pam": 0.70,
        "ztna": 0.65,
        "siem": 0.50,
    },
    "credential-access": {
        "edr": 0.85,
        "pam": 0.80,
        "iam": 0.60,
        "siem": 0.50,
    },
    "defense-evasion": {
        "edr": 0.70,
        "siem": 0.40,
        "ndr": 0.35,
    },
    "exfiltration": {
        "ndr": 0.75,
        "dlp": 0.70,
        "ztna": 0.60,
        "siem": 0.50,
        "edr": 0.40,
    },
    "impact": {
        "edr": 0.85,
        "siem": 0.60,
    },
    "persistence": {
        "edr": 0.80,
        "siem": 0.55,
        "iam": 0.50,
    },
    "privilege-escalation": {
        "edr": 0.80,
        "pam": 0.75,
        "siem": 0.45,
    },
    "discovery": {
        "edr": 0.65,
        "ndr": 0.60,
        "siem": 0.45,
    },
    "collection": {
        "edr": 0.60,
        "dlp": 0.70,
        "ndr": 0.50,
    },
    "command-and-control": {
        "ndr": 0.80,
        "ztna": 0.65,
        "edr": 0.50,
        "siem": 0.40,
    },
}


# -- Helpers -----------------------------------------------------------------


def _resolve_chain(
    vertical: str,
    attack_type: str,
) -> dict[str, Any] | None:
    """Find the attack chain definition for a vertical + attack type."""
    chains = ATTACK_CHAINS.get(vertical, [])
    type_map = ATTACK_TYPE_MAP.get(vertical, {})
    chain_name = type_map.get(attack_type)

    if chain_name:
        for chain in chains:
            if chain["name"] == chain_name:
                return chain

    # Fallback: first chain for the vertical
    if chains:
        return chains[0]
    # Ultimate fallback: healthcare ransomware
    return ATTACK_CHAINS["healthcare"][0]


def _detection_probability(
    tool_ids: list[str],
    technique_id: str,
    tactic: str,
    mitre_map: dict,
) -> tuple[str | None, float, str]:
    """Calculate detection probability for a technique given a stack.

    Returns (covering_tool, probability, detection_time).
    """
    mm = mitre_map.get(technique_id, mitre_map.get(technique_id.split(".")[0], {}))
    primary_vendors = mm.get("primary_vendors", [])
    categories = mm.get("categories", [])
    tactic_rates = CATEGORY_DETECTION_RATES.get(tactic, {})

    best_tool = None
    best_prob = 0.0
    best_time = "unknown"

    for tool_id in tool_ids:
        tool_lower = tool_id.lower()
        vendor_info = VENDOR_REGISTRY.get(tool_lower, {})
        tool_category = vendor_info.get("category", "unknown")

        # Direct coverage: tool is in primary_vendors for this technique
        if tool_lower in primary_vendors:
            base_rate = tactic_rates.get(tool_category, 0.60)
            # Bonus for being a primary vendor
            prob = min(base_rate + 0.15, 0.98)
        elif tool_category in categories:
            # Category match but not primary vendor
            prob = tactic_rates.get(tool_category, 0.40)
        else:
            continue

        # Estimate detection time by category
        if tool_category in ("email", "iam", "waf"):
            det_time = "immediate"
        elif tool_category in ("edr",):
            det_time = "minutes"
        elif tool_category in ("ndr", "ztna"):
            det_time = "minutes-hours"
        elif tool_category in ("siem",):
            det_time = "hours"
        else:
            det_time = "hours"

        if prob > best_prob:
            best_tool = tool_lower
            best_prob = prob
            best_time = det_time

    return best_tool, best_prob, best_time


def _generate_recommendations(
    chain_results: list[dict],
    vertical: str,
    mitre_map: dict,
) -> list[dict[str, str]]:
    """Generate prioritized recommendations from simulation gaps."""
    recs = []
    pass_throughs = [s for s in chain_results if s["result"] == "PASS_THROUGH"]
    detected_late = [s for s in chain_results if s.get("detection_time") in ("hours", "days")]

    for step in pass_throughs:
        tid = step["technique_id"]
        mm = mitre_map.get(tid, mitre_map.get(tid.split(".")[0], {}))
        categories = mm.get("categories", [])
        vendors = mm.get("primary_vendors", [])

        # Find cheapest option
        vendor_options = []
        for vid in vendors[:5]:
            vinfo = VENDOR_REGISTRY.get(vid, {})
            if vinfo:
                vendor_options.append(f"{vinfo.get('display_name', vid)} ({vinfo.get('price_range', '?')})")

        cat_str = "/".join(categories[:2]) if categories else "specialized"
        if vendor_options:
            detail = f"Add {cat_str} coverage. Options: {', '.join(vendor_options[:3])}"
        else:
            detail = f"Add {cat_str} coverage or deploy custom Sigma/YARA rules"

        # Check for free options
        has_free = False
        if tid in ("T1490",):
            detail = "Add Sigma rule for vssadmin shadow delete -- $0"
            has_free = True
        elif tid in ("T1059.001",):
            detail = "Enable PowerShell ScriptBlock logging + AMSI -- $0 (built-in)"
            has_free = True

        recs.append({
            "priority": "CRITICAL" if step["step"] <= 2 else "HIGH",
            "action": f"Deploy {step['technique_name']} detection ({tid})",
            "detail": detail,
            "cost": "$0" if has_free else VENDOR_REGISTRY.get(
                vendors[0] if vendors else "", {}
            ).get("price_range", "varies"),
        })

    for step in detected_late:
        recs.append({
            "priority": "MEDIUM",
            "action": f"Reduce detection time for {step['technique_id']}",
            "detail": (
                f"Current detection: {step.get('detection_time', '?')}. "
                f"Add real-time alerting or tune existing rules."
            ),
            "cost": "$0 (config changes)",
        })

    return recs


def _estimate_cost_to_close(
    recommendations: list[dict],
) -> str:
    """Estimate cost to close all gaps."""
    has_free = any("$0" in r.get("cost", "") for r in recommendations)
    has_paid = any("$0" not in r.get("cost", "") for r in recommendations)

    if not recommendations:
        return "$0 (no gaps found)"
    if has_free and not has_paid:
        return "$0 (config changes only)"
    if has_free and has_paid:
        return "$0 (config changes) to $15-30K/yr (additional tools)"
    return "$15-60K/yr (additional tools needed)"


# -- Main API ---------------------------------------------------------------


def simulate_attack(
    stack: list[str],
    vertical: str = "healthcare",
    attack_type: str | None = None,
) -> dict[str, Any]:
    """Simulate an attack chain against a given security stack.

    Args:
        stack: List of tool slugs (e.g., ["crowdstrike", "splunk", "okta"])
        vertical: Industry vertical (healthcare, financial, energy, government)
        attack_type: Attack type (ransomware, apt, ics, supply-chain, bec, double-extortion).
                     If None, uses the default for the vertical.

    Returns:
        Dict with chain steps, coverage analysis, and recommendations.
    """
    mitre_map = load_mitre_map()
    vertical_data = get_vertical(vertical)
    baselines = INDUSTRY_BASELINES.get(vertical, INDUSTRY_BASELINES["healthcare"])

    if attack_type is None:
        attack_type = DEFAULT_ATTACK_TYPE.get(vertical, "ransomware")

    chain_def = _resolve_chain(vertical, attack_type)
    if not chain_def:
        return {
            "error": f"No attack chain found for {vertical}/{attack_type}",
            "available_types": list(ATTACK_TYPE_MAP.get(vertical, {}).keys()),
        }

    stack_lower = [s.lower().strip() for s in stack]

    chain_results: list[dict] = []
    first_block: int | None = None
    first_detect: int | None = None
    total_detection_prob = 1.0
    pass_through_count = 0

    for i, tid in enumerate(chain_def["steps"], 1):
        mm = mitre_map.get(tid, mitre_map.get(tid.split(".")[0], {}))
        tech_name = mm.get("name", tid)
        tactic = mm.get("tactic", "unknown")

        # Check coverage
        covering_tool, prob, det_time = _detection_probability(
            stack_lower, tid, tactic, mitre_map,
        )

        if covering_tool:
            vendor_info = VENDOR_REGISTRY.get(covering_tool, {})
            display = vendor_info.get("display_name", covering_tool)

            if prob >= 0.70:
                result = "BLOCKED"
                if first_block is None:
                    first_block = i
            else:
                result = "DETECTED"
                if first_detect is None and first_block is None:
                    first_detect = i
        else:
            display = None
            prob = 0.0
            det_time = None
            result = "PASS_THROUGH"
            pass_through_count += 1

        # Track cumulative probability of attack getting through
        total_detection_prob *= (1.0 - prob)

        # Frequency context from baselines
        if tid.startswith("T1566"):
            freq_ctx = f"{baselines.get('spearphishing_pct', 80)}% of {vertical} attacks"
        elif tid == "T1190":
            freq_ctx = f"{baselines.get('vpn_exploit_pct', 20)}% of {vertical} attacks"
        else:
            freq_ctx = chain_def["frequency"]

        chain_results.append({
            "step": i,
            "technique_id": tid,
            "technique_name": tech_name,
            "tactic": tactic,
            "frequency": freq_ctx,
            "your_coverage": display,
            "result": result,
            "detection_probability": round(prob * 100),
            "detection_time": det_time,
        })

    # Determine where chain breaks
    breaks_at = first_block or first_detect
    break_prob = (
        chain_results[breaks_at - 1]["detection_probability"] if breaks_at else 0
    )

    # If bypassed analysis
    if breaks_at and breaks_at < len(chain_results):
        remaining = chain_results[breaks_at:]
        next_catch = next(
            (s for s in remaining if s["result"] in ("BLOCKED", "DETECTED")),
            None,
        )
        if next_catch:
            if_bypassed = (
                f"breaks at step {next_catch['step']} "
                f"({next_catch['detection_probability']}% chance)"
            )
        else:
            if_bypassed = "attack completes -- no further detection"
    elif not breaks_at:
        if_bypassed = "N/A -- attack is never detected"
    else:
        if_bypassed = "chain fully covered"

    # Find weakest links
    pass_throughs = [s for s in chain_results if s["result"] == "PASS_THROUGH"]
    weakest = " + ".join(s["technique_name"] for s in pass_throughs[:3]) if pass_throughs else "none"

    # Overall coverage
    total_steps = len(chain_results)
    covered_steps = sum(1 for s in chain_results if s["result"] != "PASS_THROUGH")
    coverage_pct = round(covered_steps / total_steps * 100) if total_steps else 0

    # Recommendations
    recommendations = _generate_recommendations(chain_results, vertical, mitre_map)
    cost_to_close = _estimate_cost_to_close(recommendations)

    # Calculate minimum improvement
    free_recs = [r for r in recommendations if "$0" in r.get("cost", "")]
    if free_recs:
        new_coverage = min(coverage_pct + len(free_recs) * 8, 100)
        min_improvement = (
            f"{len(free_recs)} free fixes ($0) -> coverage goes "
            f"from {coverage_pct}% to ~{new_coverage}%"
        )
    else:
        min_improvement = None

    return {
        "attack_type": attack_type,
        "attack_name": chain_def["name"],
        "vertical": vertical,
        "vertical_display": vertical_data.display_name,
        "stack": stack_lower,
        "chain": chain_results,
        "chain_breaks_at": breaks_at,
        "break_probability": break_prob,
        "if_bypassed": if_bypassed,
        "weakest_link": weakest,
        "coverage_pct": coverage_pct,
        "overall_pass_through_pct": round(total_detection_prob * 100),
        "recommendations": recommendations,
        "cost_to_close": cost_to_close,
        "minimum_improvement": min_improvement,
    }


def list_attack_types(vertical: str | None = None) -> dict[str, list[str]]:
    """List available attack types, optionally filtered by vertical.

    Returns dict mapping vertical -> list of attack type slugs.
    """
    if vertical:
        types = ATTACK_TYPE_MAP.get(vertical, {})
        return {vertical: list(types.keys())}
    return {v: list(types.keys()) for v, types in ATTACK_TYPE_MAP.items()}
