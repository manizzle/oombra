"""
Formal poisoning bound computation for VCI aggregation.

Given credibility weights and the maximum possible deviation,
computes the provable upper bound on a single poisoner's impact.

Bound formula:
  max_impact = w_j * max_deviation / sum(w_i for all i)

With asymmetric outlier suppression:
  effective_impact = w_j * exp(-deviation/MAD) * max_deviation / sum(w_i)
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class PoisoningBound:
    """Formal bound on a poisoner's maximum impact on the aggregate."""
    max_impact_pct: float           # Maximum impact as percentage of range
    effective_impact_pct: float     # Impact after asymmetric outlier suppression
    poisoner_weight: float          # The poisoner's credibility weight
    total_weight: float             # Sum of all weights
    n_contributors: int
    n_trusted: int
    max_deviation: float            # Maximum possible deviation from median
    bound_formula: str              # Human-readable formula

    def to_dict(self) -> dict:
        return {
            "max_impact_pct": round(self.max_impact_pct, 4),
            "effective_impact_pct": round(self.effective_impact_pct, 4),
            "poisoner_weight": round(self.poisoner_weight, 4),
            "total_weight": round(self.total_weight, 4),
            "n_contributors": self.n_contributors,
            "n_trusted": self.n_trusted,
            "max_deviation": self.max_deviation,
            "bound_formula": self.bound_formula,
        }


def compute_poisoning_bound(
    weights: list[float],
    poisoner_index: int,
    max_deviation: float,
    value_range: float = 10.0,
    median: float | None = None,
    mad: float | None = None,
) -> PoisoningBound:
    """
    Compute the formal bound on a single poisoner's maximum impact.

    Args:
        weights: credibility weights for all contributors
        poisoner_index: index of the suspected poisoner
        max_deviation: maximum possible deviation from true value
        value_range: full range of valid values (for percentage calculation)
        median: median of all values (for asymmetric outlier bound)
        mad: median absolute deviation (for asymmetric outlier bound)

    Returns:
        PoisoningBound with both raw and suppressed impact bounds
    """
    if not weights or poisoner_index >= len(weights):
        raise ValueError("Invalid weights or poisoner index")

    w_j = weights[poisoner_index]
    total_w = sum(weights)
    n_trusted = sum(1 for w in weights if w >= 0.4)

    # Raw bound: max_impact = w_j * max_deviation / total_weight
    raw_impact = (w_j * max_deviation / total_w) if total_w > 0 else 0
    raw_pct = (raw_impact / value_range * 100) if value_range > 0 else 0

    # Asymmetric outlier suppression bound
    if median is not None and mad is not None and mad > 0 and w_j < 0.4:
        deviation_ratio = max_deviation / mad
        suppressed_w = w_j * math.exp(-deviation_ratio / 2.0)
        effective_impact = (suppressed_w * max_deviation / total_w) if total_w > 0 else 0
    else:
        effective_impact = raw_impact

    effective_pct = (effective_impact / value_range * 100) if value_range > 0 else 0

    formula = (
        f"max_impact = w_j({w_j:.3f}) * max_dev({max_deviation:.1f}) "
        f"/ total_w({total_w:.3f}) = {raw_impact:.4f} "
        f"({raw_pct:.2f}% of range {value_range})"
    )

    return PoisoningBound(
        max_impact_pct=raw_pct,
        effective_impact_pct=effective_pct,
        poisoner_weight=w_j,
        total_weight=total_w,
        n_contributors=len(weights),
        n_trusted=n_trusted,
        max_deviation=max_deviation,
        bound_formula=formula,
    )


def compute_collective_bound(
    weights: list[float],
    poisoner_indices: list[int],
    max_deviation: float,
    value_range: float = 10.0,
) -> dict:
    """
    Compute the collective bound when multiple poisoners collude.

    Even with k colluding poisoners, the bound is:
      max_collective_impact = sum(w_j for j in poisoners) * max_deviation / total_weight
    """
    if not weights:
        return {"collective_impact_pct": 0, "n_poisoners": 0}

    total_w = sum(weights)
    poisoner_w = sum(weights[i] for i in poisoner_indices if i < len(weights))

    collective_impact = (poisoner_w * max_deviation / total_w) if total_w > 0 else 0
    collective_pct = (collective_impact / value_range * 100) if value_range > 0 else 0

    return {
        "collective_impact_pct": round(collective_pct, 4),
        "poisoner_total_weight": round(poisoner_w, 4),
        "honest_total_weight": round(total_w - poisoner_w, 4),
        "n_poisoners": len(poisoner_indices),
        "n_honest": len(weights) - len(poisoner_indices),
        "weight_ratio": round(poisoner_w / (total_w - poisoner_w), 4) if total_w > poisoner_w else float("inf"),
    }


__all__ = [
    "PoisoningBound",
    "compute_collective_bound",
    "compute_poisoning_bound",
]
