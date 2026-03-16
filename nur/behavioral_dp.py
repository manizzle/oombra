"""
Behavioral Differential Privacy (BDP) — a novel algorithm for data poisoning defense.

═══════════════════════════════════════════════════════════════════════════════
PRIOR ART (what exists today):
═══════════════════════════════════════════════════════════════════════════════

1. ROBUST AGGREGATION (Federated Learning)
   - Krum: picks the contribution closest to the median of all contributions
   - Trimmed Mean: removes top/bottom k% before averaging
   - Geometric Median: finds the point minimizing sum of distances
   Problem: treats all contributors equally. A persistent poisoner with many
   contributions has as much weight as a real practitioner.

2. REPUTATION SYSTEMS (Wikipedia, StackOverflow)
   - Edit history, upvotes, revision tracking
   - Problem: gameable with sock puppets. Build reputation on easy edits,
   then make one poisonous edit.

3. GOLD STANDARD TESTING (Mechanical Turk, crowdsourcing)
   - Mix known-answer questions into the task
   - Problem: doesn't work for subjective data ("is CrowdStrike good?")
   and doesn't work when the "gold standard" IS the thing you're trying to
   discover (the whole point is to find things MITRE evals miss).

4. DIFFERENTIAL PRIVACY (traditional)
   - Adds noise to OUTPUT to protect contributor privacy
   - Problem: protects privacy but does NOT prevent poisoning. A fake
   contribution with DP noise is still a fake contribution.

5. STAKING/SLASHING (crypto)
   - Contributors put up collateral that's slashed if caught lying
   - Problem: excludes participants who can't afford the stake. A hospital
   IR team during an active incident doesn't have time for crypto.

═══════════════════════════════════════════════════════════════════════════════
NOVEL ALGORITHM: BEHAVIORAL DIFFERENTIAL PRIVACY (BDP)
═══════════════════════════════════════════════════════════════════════════════

Core insight: In a give-to-get system, contributors don't just submit data —
they also CONSUME intelligence. The pattern of what they REQUEST reveals
whether their contributions are genuine.

A poisoner submitting a fake CrowdStrike eval of 2/10 doesn't then run:
  - nur simulate --stack crowdstrike
  - nur threat-model --stack crowdstrike
  - nur report (with CrowdStrike IOCs)
Because they don't actually run CrowdStrike.

A real practitioner DOES all of those things. The behavioral signal —
the correlation between what you contribute and what you consume — is
nearly impossible to fake without actually being a real practitioner.

═══════════════════════════════════════════════════════════════════════════════
FORMAL CONSTRUCTION
═══════════════════════════════════════════════════════════════════════════════

Definitions:
  - C_i = contribution from participant i (e.g., a tool evaluation)
  - Q_i = set of queries/actions by participant i (reports, simulations, etc.)
  - B_i = behavioral feature vector for participant i
  - w_i = credibility weight for participant i (0.0 to 1.0)
  - ε = privacy parameter for behavioral feature noise

Step 1: BEHAVIORAL FEATURE EXTRACTION
  For each participant i, compute feature vector B_i:
    B_i = [
      f_1: query_diversity        — # unique query types used
      f_2: contribution_diversity  — # unique contribution types submitted
      f_3: temporal_spread        — time between first and last interaction
      f_4: qca_score             — Query-Contribution Alignment (see below)
      f_5: integration_signal    — boolean: data auto-submitted from integration
      f_6: cross_validation      — # of their IOCs that matched other orgs' campaigns
    ]

Step 2: QUERY-CONTRIBUTION ALIGNMENT (QCA) — the key innovation
  QCA measures the correlation between what a participant contributes
  and what they consume. Formally:

    Let T_c = set of tool/vendor IDs mentioned in contributions by i
    Let T_q = set of tool/vendor IDs mentioned in queries by i

    QCA_i = |T_c ∩ T_q| / |T_c ∪ T_q|    (Jaccard similarity)

  Example:
    - Real practitioner contributes CrowdStrike eval, queries CrowdStrike
      market position, simulates attacks against CrowdStrike stack
      → T_c = {crowdstrike}, T_q = {crowdstrike} → QCA = 1.0

    - Poisoner contributes fake CrowdStrike eval but queries about
      SentinelOne (their actual tool)
      → T_c = {crowdstrike}, T_q = {sentinelone} → QCA = 0.0

  QCA is hard to fake because:
    1. To fake it, you'd have to also run simulations/threat models for
       the tool you're poisoning — generating MORE real usage data
    2. The queries are logged server-side; the contributor can't control
       what the server records
    3. Faking query patterns requires sustained, consistent behavior
       over time — which is indistinguishable from being a real user

Step 3: DIFFERENTIAL PRIVACY ON BEHAVIORAL FEATURES
  To prevent the behavioral analysis from leaking information about
  individual contributors, apply Laplace noise to each feature:

    B̃_i[j] = B_i[j] + Lap(Δf_j / ε)

  Where:
    - Δf_j is the sensitivity of feature j (max change from one record)
    - ε is the privacy parameter (higher = less noise = more accuracy)
    - Lap(b) is a draw from the Laplace distribution with scale b

  This means:
    - The system knows "this contributor has HIGH QCA" but can't
      determine their exact query history
    - The contributor's query privacy is preserved
    - An adversary can't reverse-engineer the behavioral features
      to game specific metrics

Step 4: CREDIBILITY WEIGHT COMPUTATION
  The credibility weight is a function of the noised behavioral features:

    w_i = σ(α₁·B̃_i[1] + α₂·B̃_i[2] + ... + α₆·B̃_i[6] + β)

  Where σ is the sigmoid function and α, β are learned parameters.
  (In practice, we use a simpler weighted sum with hand-tuned coefficients.)

Step 5: ASYMMETRIC OUTLIER HANDLING — the second key innovation
  Traditional robust aggregation penalizes ALL outliers equally.
  BDP handles outliers ASYMMETRICALLY based on credibility:

    - Outlier from UNTRUSTED source (low w_i):
      → exponentially downweight: w'_i = w_i · exp(-|x_i - median| / MAD)

    - Outlier from TRUSTED source (high w_i):
      → PRESERVE the outlier. This is the "juicy dirt" — a trusted
        practitioner saying CrowdStrike misses T1490 is EXACTLY the
        kind of insight the system should amplify, not suppress.

  Formally:
    If |x_i - median(X)| > 2·MAD(X):  # x_i is an outlier
      if w_i < 0.3:  # untrusted
        w'_i = w_i · exp(-|x_i - median(X)| / MAD(X))
      else:  # trusted
        w'_i = w_i  # preserve the outlier — it's signal, not noise

Step 6: TEMPORAL DECAY WITH RENEWAL
  Credibility decays over time (half-life = 90 days):

    w_i(t) = w_i(t₀) · 2^(-(t - t₀) / 90)

  A poisoner who builds credibility, then goes silent and submits one
  fake eval months later, has decayed credibility. A real practitioner
  who continues using the platform naturally renews.

Step 7: WEIGHTED AGGREGATION
  Final aggregate for any metric M across all contributors:

    M̂ = Σ(w'_i · x_i) / Σ(w'_i)

  This is a credibility-weighted average where:
    - Poisoners with low QCA, no integration, no history → w' ≈ 0.01
    - Real practitioners with high QCA, integration, history → w' ≈ 0.85
    - Trusted outliers are preserved (the "dirty truth")
    - Untrusted outliers are suppressed (the "fake dirt")

═══════════════════════════════════════════════════════════════════════════════
WHAT MAKES THIS PATENTABLE (novel + non-obvious)
═══════════════════════════════════════════════════════════════════════════════

1. QUERY-CONTRIBUTION ALIGNMENT (QCA) as a trust signal
   No prior system uses the correlation between what a participant
   contributes and what they consume as a credibility metric.
   This is novel because give-to-get systems are new — traditional
   threat intel platforms don't have the consumption signal.

2. DP-NOISED BEHAVIORAL FEATURES for credibility
   Existing DP literature uses noise on OUTPUTS (to protect privacy).
   BDP uses noise on BEHAVIORAL FEATURES to compute CREDIBILITY
   while preserving the contributor's query privacy. This is a novel
   application of DP — using it for trust, not just privacy.

3. ASYMMETRIC OUTLIER HANDLING based on credibility
   All existing robust aggregation methods (Krum, trimmed mean,
   geometric median) treat outliers symmetrically — all are penalized.
   BDP treats outliers asymmetrically: trusted outliers are preserved,
   untrusted outliers are suppressed. This is critical for a system
   where the most valuable data IS the outlier (the tool that missed
   an attack that everyone thought was covered).

4. The COMBINATION of (1), (2), and (3) in a give-to-get system
   where the behavioral signal is an inherent property of the platform
   design, not an afterthought.
"""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# Implementation
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class BehavioralProfile:
    """Participant behavioral profile for BDP credibility computation."""
    participant_id: str  # hashed public key

    # Raw behavioral features (server-side only, never exposed)
    contribution_types: set[str] = field(default_factory=set)  # {"ioc_bundle", "attack_map", "eval"}
    query_types: set[str] = field(default_factory=set)  # {"report", "simulate", "market", "threat-model"}
    contributed_vendors: set[str] = field(default_factory=set)  # vendors mentioned in contributions
    queried_vendors: set[str] = field(default_factory=set)  # vendors mentioned in queries
    integration_sources: set[str] = field(default_factory=set)  # {"splunk", "crowdstrike", ...}
    iocs_matched: int = 0
    techniques_corroborated: int = 0
    total_contributions: int = 0
    total_queries: int = 0
    first_seen_ts: float = 0.0
    last_seen_ts: float = 0.0


def compute_qca(profile: BehavioralProfile) -> float:
    """Query-Contribution Alignment — Jaccard similarity between
    contributed vendors and queried vendors.

    QCA = |contributed ∩ queried| / |contributed ∪ queried|

    High QCA = real practitioner (contributes about and queries about same tools)
    Low QCA = potential poisoner (contributes about X but queries about Y)
    """
    c = profile.contributed_vendors
    q = profile.queried_vendors
    if not c and not q:
        return 0.0
    union = c | q
    if not union:
        return 0.0
    intersection = c & q
    return len(intersection) / len(union)


def compute_behavioral_features(profile: BehavioralProfile) -> list[float]:
    """Extract the 6 behavioral features from a participant profile."""
    import time

    # f1: query diversity (0-1, normalized by max possible query types)
    max_query_types = 8  # report, simulate, market, search, threat-model, patterns, threat-map, rfp
    f1 = min(1.0, len(profile.query_types) / max_query_types)

    # f2: contribution diversity (0-1, normalized by max contribution types)
    max_contrib_types = 3  # ioc_bundle, attack_map, eval
    f2 = min(1.0, len(profile.contribution_types) / max_contrib_types)

    # f3: temporal spread (0-1, normalized by 180 days)
    if profile.first_seen_ts and profile.last_seen_ts:
        days = (profile.last_seen_ts - profile.first_seen_ts) / 86400
        f3 = min(1.0, days / 180)
    else:
        f3 = 0.0

    # f4: QCA score (0-1)
    f4 = compute_qca(profile)

    # f5: integration signal (0 or 1)
    f5 = 1.0 if profile.integration_sources else 0.0

    # f6: cross-validation (0-1, normalized by 10 matches)
    f6 = min(1.0, (profile.iocs_matched + profile.techniques_corroborated) / 10)

    return [f1, f2, f3, f4, f5, f6]


def add_laplace_noise(features: list[float], epsilon: float = 2.0) -> list[float]:
    """Apply Laplace noise to behavioral features for privacy.

    Each feature has sensitivity 1.0 (normalized to [0,1]).
    Noise scale = sensitivity / epsilon = 1.0 / epsilon.

    Higher epsilon = less noise = more accurate credibility (less privacy).
    Lower epsilon = more noise = less accurate credibility (more privacy).
    """
    scale = 1.0 / epsilon
    noised = []
    for f in features:
        noise = random.expovariate(1.0 / scale) * random.choice([-1, 1])
        noised.append(max(0.0, min(1.0, f + noise)))
    return noised


# Feature weights (hand-tuned, could be learned)
FEATURE_WEIGHTS = [
    0.10,  # f1: query diversity
    0.10,  # f2: contribution diversity
    0.10,  # f3: temporal spread
    0.30,  # f4: QCA (highest weight — hardest to fake)
    0.25,  # f5: integration signal
    0.15,  # f6: cross-validation
]


def compute_credibility_weight(
    profile: BehavioralProfile,
    epsilon: float = 2.0,
) -> float:
    """Compute BDP credibility weight for a participant.

    Returns w ∈ [0.05, 0.95] — never fully zero (everyone gets a voice)
    and never fully one (nobody is unconditionally trusted).
    """
    features = compute_behavioral_features(profile)
    noised = add_laplace_noise(features, epsilon)

    # Weighted sum
    raw = sum(w * f for w, f in zip(FEATURE_WEIGHTS, noised))

    # Sigmoid squashing to [0.05, 0.95]
    # sigmoid(x) = 1 / (1 + exp(-k*(x - 0.5)))
    k = 8.0  # steepness
    sigmoid = 1.0 / (1.0 + math.exp(-k * (raw - 0.4)))

    # Clamp to [0.05, 0.95]
    return round(max(0.05, min(0.95, sigmoid)), 3)


def asymmetric_outlier_weight(
    value: float,
    median: float,
    mad: float,
    base_weight: float,
    trust_threshold: float = 0.4,
) -> float:
    """Asymmetric outlier handling.

    Trusted outliers (w >= threshold): PRESERVE — this is signal.
    Untrusted outliers (w < threshold): SUPPRESS — this is noise.

    Args:
        value: the data point
        median: median of all values for this metric
        mad: Median Absolute Deviation
        base_weight: the participant's BDP credibility weight
        trust_threshold: minimum weight to be considered "trusted"
    """
    if mad == 0:
        return base_weight

    deviation = abs(value - median) / mad

    if deviation <= 2.0:
        # Not an outlier — use base weight
        return base_weight

    if base_weight >= trust_threshold:
        # Trusted outlier — PRESERVE (this is the juicy dirt)
        return base_weight
    else:
        # Untrusted outlier — SUPPRESS exponentially
        return base_weight * math.exp(-deviation / 2.0)


def bdp_weighted_aggregate(
    values_and_profiles: list[tuple[float, BehavioralProfile]],
    epsilon: float = 2.0,
) -> dict:
    """Full BDP aggregation pipeline.

    Takes a list of (value, profile) pairs and returns a credibility-weighted
    aggregate that is resistant to data poisoning.

    Returns:
    {
        "aggregate": float,         # the BDP-weighted average
        "simple_average": float,    # for comparison
        "n_contributors": int,
        "n_trusted": int,          # contributors with w >= 0.4
        "n_untrusted": int,
        "poisoning_resistance": float,  # how much the aggregate differs from simple avg
    }
    """
    if not values_and_profiles:
        return {"aggregate": None, "simple_average": None, "n_contributors": 0}

    values = [v for v, _ in values_and_profiles]
    profiles = [p for _, p in values_and_profiles]

    # Compute credibility weights
    weights = [compute_credibility_weight(p, epsilon) for p in profiles]

    # Compute median and MAD for outlier detection
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2
    deviations = sorted([abs(v - median) for v in values])
    mad = deviations[len(deviations) // 2] if deviations else 0

    # Apply asymmetric outlier handling
    final_weights = [
        asymmetric_outlier_weight(v, median, mad, w)
        for v, w in zip(values, weights)
    ]

    # Weighted aggregate
    total_w = sum(final_weights)
    if total_w == 0:
        aggregate = sum(values) / len(values)
    else:
        aggregate = sum(v * w for v, w in zip(values, final_weights)) / total_w

    simple_avg = sum(values) / len(values)

    return {
        "aggregate": round(aggregate, 2),
        "simple_average": round(simple_avg, 2),
        "n_contributors": len(values),
        "n_trusted": sum(1 for w in weights if w >= 0.4),
        "n_untrusted": sum(1 for w in weights if w < 0.4),
        "poisoning_resistance": round(abs(aggregate - simple_avg), 2),
    }
