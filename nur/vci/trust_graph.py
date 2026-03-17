"""
PSI-Driven Trust Feedback — use PSI intersection results to
reinforce contributor credibility.

When two orgs run PSI and find matching IOCs:
- Both orgs' credibility increases proportionally to match count
- Weighted by IOC rarity (common IOCs from public feeds give less boost)
- Creates implicit trust graph: edges = corroborated data

A poisoner submitting fake IOCs gets no PSI matches -> credibility
stays low -> their contributions are downweighted in aggregation.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..behavioral_dp import BehavioralProfile


@dataclass
class TrustEdge:
    """An edge in the trust graph between two orgs."""
    org_a: str
    org_b: str
    match_count: int
    rarity_weight: float          # higher = rarer IOCs matched
    credibility_delta_a: float    # credibility boost for org A
    credibility_delta_b: float    # credibility boost for org B
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "org_a": self.org_a,
            "org_b": self.org_b,
            "match_count": self.match_count,
            "rarity_weight": round(self.rarity_weight, 4),
            "credibility_delta_a": round(self.credibility_delta_a, 4),
            "credibility_delta_b": round(self.credibility_delta_b, 4),
            "timestamp": self.timestamp,
        }


@dataclass
class TrustGraph:
    """Implicit trust graph built from PSI corroboration."""
    edges: list[TrustEdge] = field(default_factory=list)
    credibility_deltas: dict[str, float] = field(default_factory=dict)

    def add_edge(self, edge: TrustEdge) -> None:
        self.edges.append(edge)
        self.credibility_deltas[edge.org_a] = (
            self.credibility_deltas.get(edge.org_a, 0) + edge.credibility_delta_a
        )
        self.credibility_deltas[edge.org_b] = (
            self.credibility_deltas.get(edge.org_b, 0) + edge.credibility_delta_b
        )

    def get_credibility_boost(self, org_id: str) -> float:
        """Get the cumulative credibility boost for an org from PSI matches."""
        return self.credibility_deltas.get(org_id, 0.0)

    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict:
        return {
            "edges": [e.to_dict() for e in self.edges],
            "credibility_deltas": {
                k: round(v, 4) for k, v in self.credibility_deltas.items()
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# IOC rarity computation
# ══════════════════════════════════════════════════════════════════════════════

def compute_ioc_rarity(
    matched_iocs: list[str],
    public_feed_iocs: set[str] | None = None,
) -> float:
    """
    Compute rarity weight for matched IOCs.

    IOCs from public feeds (abuse.ch, AlienVault OTX, etc.) are common
    and give less credibility boost. Private/unique IOCs give more.

    Returns:
        Rarity weight in [0.1, 1.0]
    """
    if not matched_iocs:
        return 0.0

    if public_feed_iocs is None:
        public_feed_iocs = set()

    n_total = len(matched_iocs)
    n_public = sum(1 for ioc in matched_iocs if ioc in public_feed_iocs)
    n_private = n_total - n_public

    # Private IOCs are worth more
    # Rarity = (private_weight * n_private + public_weight * n_public) / n_total
    private_weight = 1.0
    public_weight = 0.2
    rarity = (private_weight * n_private + public_weight * n_public) / n_total

    return max(0.1, min(1.0, rarity))


# ══════════════════════════════════════════════════════════════════════════════
# PSI result processing
# ══════════════════════════════════════════════════════════════════════════════

def compute_credibility_delta(
    match_count: int,
    rarity_weight: float,
    max_boost: float = 0.15,
) -> float:
    """
    Compute credibility boost from PSI matches.

    Uses diminishing returns: log(1 + matches) * rarity
    Capped at max_boost to prevent gaming.

    Args:
        match_count: number of IOCs that matched
        rarity_weight: how rare the matched IOCs are (0-1)
        max_boost: maximum credibility increase per PSI session

    Returns:
        Credibility delta in [0, max_boost]
    """
    if match_count <= 0:
        return 0.0

    # Logarithmic scaling with diminishing returns
    raw_boost = math.log1p(match_count) * rarity_weight * 0.05
    return min(max_boost, raw_boost)


def process_psi_result(
    match_count: int,
    profile_a: BehavioralProfile,
    profile_b: BehavioralProfile,
    matched_iocs: list[str] | None = None,
    public_feed_iocs: set[str] | None = None,
    trust_graph: TrustGraph | None = None,
) -> TrustEdge:
    """
    Process a PSI result and update both participants' credibility.

    Args:
        match_count: number of IOC matches from PSI
        profile_a: first org's behavioral profile
        profile_b: second org's behavioral profile
        matched_iocs: the actual matched IOC values (for rarity computation)
        public_feed_iocs: set of known public-feed IOCs
        trust_graph: optional graph to add the edge to

    Returns:
        TrustEdge with credibility deltas for both orgs
    """
    import time

    # Compute IOC rarity
    if matched_iocs:
        rarity = compute_ioc_rarity(matched_iocs, public_feed_iocs)
    else:
        rarity = 0.5  # default when we don't know the actual IOCs

    # Compute credibility boosts
    delta_a = compute_credibility_delta(match_count, rarity)
    delta_b = compute_credibility_delta(match_count, rarity)

    # Update behavioral profiles
    profile_a.iocs_matched += match_count
    profile_b.iocs_matched += match_count

    edge = TrustEdge(
        org_a=profile_a.participant_id,
        org_b=profile_b.participant_id,
        match_count=match_count,
        rarity_weight=rarity,
        credibility_delta_a=delta_a,
        credibility_delta_b=delta_b,
        timestamp=time.time(),
    )

    if trust_graph is not None:
        trust_graph.add_edge(edge)

    return edge


def apply_trust_feedback(
    profile: BehavioralProfile,
    trust_graph: TrustGraph,
    base_weight: float,
) -> float:
    """
    Apply trust graph feedback to a contributor's weight.

    The PSI-derived credibility boost is additive to the BDP weight,
    capped at 0.95.
    """
    boost = trust_graph.get_credibility_boost(profile.participant_id)
    return min(0.95, base_weight + boost)


__all__ = [
    "TrustEdge",
    "TrustGraph",
    "apply_trust_feedback",
    "compute_credibility_delta",
    "compute_ioc_rarity",
    "process_psi_result",
]
