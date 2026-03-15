"""
Differential Privacy mechanisms for vigil.

Transforms "we promise we scrub" into "mathematically proven privacy."
Users can say "I shared at epsilon=1.0" and compliance knows exactly what that means.

All mechanisms are stdlib-only (~50 lines of math). No external dependencies.
"""
from __future__ import annotations

import json
import math
import random
import datetime
from dataclasses import dataclass, field

from .models import EvalRecord, AttackMap


# ══════════════════════════════════════════════════════════════════════════════
# Core mechanisms
# ══════════════════════════════════════════════════════════════════════════════

def add_laplace_noise(value: float, sensitivity: float, epsilon: float) -> float:
    """
    Laplace mechanism: adds Lap(sensitivity/epsilon) noise.
    Provides pure epsilon-differential privacy.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    scale = sensitivity / epsilon
    # Laplace(0, scale) = Exponential(1/scale) * random_sign
    u = random.random() - 0.5
    noise = -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
    return value + noise


def add_gaussian_noise(
    value: float,
    sensitivity: float,
    epsilon: float,
    delta: float = 1e-5,
) -> float:
    """
    Gaussian mechanism: adds N(0, sigma^2) noise.
    Provides (epsilon, delta)-differential privacy.
    """
    if epsilon <= 0 or delta <= 0:
        raise ValueError("epsilon and delta must be positive")
    sigma = sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / epsilon
    return value + random.gauss(0, sigma)


def randomized_response(value: bool, epsilon: float) -> bool:
    """
    Randomized response for boolean values.
    With probability p = e^epsilon / (1 + e^epsilon), report truth.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    p_truth = math.exp(epsilon) / (1 + math.exp(epsilon))
    if random.random() < p_truth:
        return value
    return not value


# ══════════════════════════════════════════════════════════════════════════════
# Pre-calibrated sensitivities per field
# ══════════════════════════════════════════════════════════════════════════════

# Field: (sensitivity, min_val, max_val)
_EVAL_SENSITIVITIES: dict[str, tuple[float, float, float]] = {
    "overall_score":     (10.0,   0.0,   10.0),    # 0-10 scale
    "detection_rate":    (100.0,  0.0,   100.0),   # 0-100%
    "fp_rate":           (100.0,  0.0,   100.0),   # 0-100%
    "deploy_days":       (365.0,  0.0,   365.0),   # 0-365 days
    "cpu_overhead":      (100.0,  0.0,   100.0),   # 0-100%
    "ttfv_hours":        (720.0,  0.0,   720.0),   # 0-720 hours (30 days)
    "eval_duration_days": (365.0, 0.0,   365.0),   # 0-365 days
}


def dp_eval_record(record: EvalRecord, epsilon: float) -> EvalRecord:
    """
    Apply calibrated Laplace noise to all numeric fields of an EvalRecord.
    Budget is split equally across present fields.
    """
    updates: dict = {}
    present_fields = [
        f for f in _EVAL_SENSITIVITIES
        if getattr(record, f) is not None
    ]
    if not present_fields:
        return record

    # Split budget equally across fields (composition theorem)
    per_field_epsilon = epsilon / len(present_fields)

    for field_name in present_fields:
        sensitivity, min_val, max_val = _EVAL_SENSITIVITIES[field_name]
        raw = getattr(record, field_name)
        noised = add_laplace_noise(float(raw), sensitivity, per_field_epsilon)
        # Clamp to valid range
        noised = max(min_val, min(max_val, noised))
        # Round to match field type
        if field_name in ("deploy_days", "eval_duration_days"):
            updates[field_name] = max(0, round(noised))
        else:
            updates[field_name] = round(noised, 1)

    # Randomized response for boolean
    if record.would_buy is not None:
        updates["would_buy"] = randomized_response(record.would_buy, epsilon)

    return record.model_copy(update=updates)


def dp_attack_map(attack_map: AttackMap, epsilon: float) -> AttackMap:
    """
    Apply randomized response to detected_by/missed_by lists in AttackMap.
    Each vendor in each list is independently flipped with DP guarantee.
    """
    per_tech_epsilon = epsilon / max(len(attack_map.techniques), 1)

    noised_techs = []
    for tech in attack_map.techniques:
        # For each vendor in detected_by, maybe flip to missed_by and vice versa
        all_vendors = set(tech.detected_by) | set(tech.missed_by)
        new_detected = []
        new_missed = []
        for v in all_vendors:
            was_detected = v in tech.detected_by
            if randomized_response(was_detected, per_tech_epsilon):
                new_detected.append(v)
            else:
                new_missed.append(v)
        noised_techs.append(tech.model_copy(update={
            "detected_by": new_detected,
            "missed_by": new_missed,
        }))

    return attack_map.model_copy(update={"techniques": noised_techs})


# ══════════════════════════════════════════════════════════════════════════════
# Privacy budget tracking
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PrivacyBudget:
    """
    Tracks cumulative epsilon spent across sessions.
    Warns when approaching threshold (default: 10.0).
    """
    total_epsilon: float = 0.0
    threshold: float = 10.0
    sessions: list[dict] = field(default_factory=list)

    def spend(self, epsilon: float, description: str = "") -> None:
        """Record epsilon spent."""
        self.total_epsilon += epsilon
        self.sessions.append({
            "epsilon": epsilon,
            "cumulative": self.total_epsilon,
            "description": description,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

    @property
    def remaining(self) -> float:
        return max(0.0, self.threshold - self.total_epsilon)

    @property
    def is_exhausted(self) -> bool:
        return self.total_epsilon >= self.threshold

    @property
    def warning(self) -> str | None:
        ratio = self.total_epsilon / self.threshold
        if ratio >= 1.0:
            return f"Privacy budget EXHAUSTED ({self.total_epsilon:.1f}/{self.threshold:.1f})"
        if ratio >= 0.8:
            return f"Privacy budget nearly exhausted ({self.total_epsilon:.1f}/{self.threshold:.1f})"
        if ratio >= 0.5:
            return f"Privacy budget half spent ({self.total_epsilon:.1f}/{self.threshold:.1f})"
        return None

    def to_dict(self) -> dict:
        return {
            "total_epsilon": self.total_epsilon,
            "threshold": self.threshold,
            "sessions": self.sessions,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PrivacyBudget:
        return cls(
            total_epsilon=data.get("total_epsilon", 0.0),
            threshold=data.get("threshold", 10.0),
            sessions=data.get("sessions", []),
        )

    def save(self) -> None:
        """Persist budget to ~/.vigil/budget.json."""
        from .keystore import save_budget
        save_budget(self.to_dict())

    @classmethod
    def load(cls) -> PrivacyBudget:
        """Load budget from ~/.vigil/budget.json."""
        from .keystore import load_budget
        return cls.from_dict(load_budget())
