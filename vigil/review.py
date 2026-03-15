"""
Terminal review step — user sees exactly what will be sent before anything leaves.
Nothing is uploaded until approve() is called.
"""
from __future__ import annotations

from typing import Any
from .models import AttackMap, EvalRecord, IOCBundle, Contribution


def _fmt_val(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.1f}"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "—"
    return str(v)


def render(contrib: Contribution) -> str:
    """Return a plain-text summary of what will be sent."""
    lines = []

    if isinstance(contrib, EvalRecord):
        lines += [
            f"  Type       : Tool Evaluation",
            f"  Vendor     : {contrib.vendor}",
            f"  Category   : {contrib.category}",
            f"  Score      : {_fmt_val(contrib.overall_score)} / 10",
            f"  Detection  : {_fmt_val(contrib.detection_rate)}%",
            f"  FP Rate    : {_fmt_val(contrib.fp_rate)}%",
            f"  Deploy Days: {_fmt_val(contrib.deploy_days)}",
            f"  Would Buy  : {_fmt_val(contrib.would_buy)}",
            f"  Strength   : {_fmt_val(contrib.top_strength)}",
            f"  Friction   : {_fmt_val(contrib.top_friction)}",
            f"  Industry   : {_fmt_val(contrib.context.industry)}",
            f"  Org Size   : {_fmt_val(contrib.context.org_size)}",
            f"  Role       : {_fmt_val(contrib.context.role)}",
        ]

    elif isinstance(contrib, AttackMap):
        covered = sum(1 for t in contrib.techniques if t.detected_by)
        missed  = sum(1 for t in contrib.techniques if t.missed_by)
        lines += [
            f"  Type       : Attack Map",
            f"  Threat     : {_fmt_val(contrib.threat_name)}",
            f"  Techniques : {len(contrib.techniques)} total — {covered} detected, {missed} missed",
            f"  Tools      : {_fmt_val(contrib.tools_in_scope)}",
            f"  Source     : {contrib.source}",
        ]
        for t in contrib.techniques[:5]:
            status = "DETECTED" if t.detected_by else ("MISSED" if t.missed_by else "unknown")
            lines.append(f"    [{status:8s}] {t.technique_id}  {t.technique_name or ''}")
        if len(contrib.techniques) > 5:
            lines.append(f"    ... and {len(contrib.techniques) - 5} more")

    elif isinstance(contrib, IOCBundle):
        type_counts: dict[str, int] = {}
        for ioc in contrib.iocs:
            type_counts[ioc.ioc_type] = type_counts.get(ioc.ioc_type, 0) + 1
        lines += [
            f"  Type       : IOC Bundle",
            f"  IOC Count  : {len(contrib.iocs)} indicators",
            f"  IOC Types  : {', '.join(f'{v}x {k}' for k, v in sorted(type_counts.items()))}",
            f"  Tools      : {_fmt_val(contrib.tools_in_scope)}",
            f"  Source     : {contrib.source}",
            f"  NOTE       : Raw values hashed locally — only SHA-256 fingerprints sent",
        ]

    lines += [
        "",
        "  Raw values stripped. PII removed. Context bucketed.",
    ]
    return "\n".join(lines)


def prompt_approve(contrib: Contribution) -> bool:
    """Print summary and ask for terminal confirmation. Returns True if approved."""
    print()
    print("─" * 60)
    print("  REVIEW — this is what will be sent:")
    print("─" * 60)
    print(render(contrib))
    print("─" * 60)
    answer = input("  Send this contribution? [y/N] ").strip().lower()
    return answer in ("y", "yes")
