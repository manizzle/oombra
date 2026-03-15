"""
Build local threat graphs from vigil contributions.
All construction is LOCAL — no data leaves the machine.
"""
from __future__ import annotations

from ..models import AttackMap, IOCBundle, EvalRecord, Contribution
from .schema import ThreatGraph, GraphNode, GraphEdge, NodeType, EdgeType


def build_graph(contributions: list[Contribution]) -> ThreatGraph:
    """
    Build a local threat graph from contributions.

    - AttackMap  -> technique nodes + actor nodes + edges
    - IOCBundle  -> IOC nodes (hashed) + campaign edges + detection edges
    - EvalRecord -> tool nodes + category edges
    """
    subgraphs: list[ThreatGraph] = []
    for c in contributions:
        if isinstance(c, AttackMap):
            subgraphs.append(build_from_attack_map(c))
        elif isinstance(c, IOCBundle):
            subgraphs.append(build_from_ioc_bundle(c))
        elif isinstance(c, EvalRecord):
            subgraphs.append(_build_from_eval(c))
    return merge_graphs(subgraphs) if subgraphs else ThreatGraph()


# ── AttackMap ────────────────────────────────────────────────────────────────


def build_from_attack_map(am: AttackMap) -> ThreatGraph:
    """Build subgraph from a single AttackMap."""
    g = ThreatGraph()

    # Threat actor node
    actor_id: str | None = None
    if am.threat_name:
        actor_id = f"actor:{am.threat_name.lower().replace(' ', '_')}"
        g.add_node(GraphNode(
            node_id=actor_id,
            node_type=NodeType.THREAT_ACTOR,
            label=am.threat_name,
        ))

    for t in am.techniques:
        tech_id = f"technique:{t.technique_id}"
        g.add_node(GraphNode(
            node_id=tech_id,
            node_type=NodeType.TECHNIQUE,
            label=t.technique_name or t.technique_id,
            properties={"tactic": t.tactic} if t.tactic else {},
        ))

        # actor -> technique (USES)
        if actor_id:
            g.add_edge(GraphEdge(
                source_id=actor_id,
                target_id=tech_id,
                edge_type=EdgeType.USES,
            ))

        # technique -> tool (DETECTED_BY / MISSED_BY)
        for slug in t.detected_by:
            tool_id = f"tool:{slug}"
            g.add_node(GraphNode(node_id=tool_id, node_type=NodeType.TOOL, label=slug))
            g.add_edge(GraphEdge(
                source_id=tech_id,
                target_id=tool_id,
                edge_type=EdgeType.DETECTED_BY,
            ))

        for slug in t.missed_by:
            tool_id = f"tool:{slug}"
            g.add_node(GraphNode(node_id=tool_id, node_type=NodeType.TOOL, label=slug))
            g.add_edge(GraphEdge(
                source_id=tech_id,
                target_id=tool_id,
                edge_type=EdgeType.MISSED_BY,
            ))

    return g


# ── IOCBundle ────────────────────────────────────────────────────────────────


def build_from_ioc_bundle(bundle: IOCBundle) -> ThreatGraph:
    """Build subgraph from IOCBundle.  IOC values are NEVER stored raw."""
    g = ThreatGraph()

    for ioc in bundle.iocs:
        # CRITICAL: only use value_hash, never value_raw
        if not ioc.value_hash:
            continue

        ioc_id = f"ioc:{ioc.value_hash}"
        g.add_node(GraphNode(
            node_id=ioc_id,
            node_type=NodeType.IOC,
            label=ioc.ioc_type,  # type label only, NOT raw value
        ))

        # Campaign
        campaign_id: str | None = None
        if ioc.campaign:
            campaign_id = f"campaign:{ioc.campaign.lower().replace(' ', '_')}"
            g.add_node(GraphNode(
                node_id=campaign_id,
                node_type=NodeType.CAMPAIGN,
                label=ioc.campaign,
            ))
            g.add_edge(GraphEdge(
                source_id=ioc_id,
                target_id=campaign_id,
                edge_type=EdgeType.INDICATES,
            ))

        # Threat actor
        if ioc.threat_actor:
            actor_id = f"actor:{ioc.threat_actor.lower().replace(' ', '_')}"
            g.add_node(GraphNode(
                node_id=actor_id,
                node_type=NodeType.THREAT_ACTOR,
                label=ioc.threat_actor,
            ))
            if campaign_id:
                g.add_edge(GraphEdge(
                    source_id=campaign_id,
                    target_id=actor_id,
                    edge_type=EdgeType.ATTRIBUTED_TO,
                ))
            else:
                g.add_edge(GraphEdge(
                    source_id=ioc_id,
                    target_id=actor_id,
                    edge_type=EdgeType.RELATED_TO,
                ))

        # Detection edges
        for slug in ioc.detected_by:
            tool_id = f"tool:{slug}"
            g.add_node(GraphNode(node_id=tool_id, node_type=NodeType.TOOL, label=slug))
            g.add_edge(GraphEdge(
                source_id=ioc_id, target_id=tool_id, edge_type=EdgeType.DETECTED_BY,
            ))

        for slug in ioc.missed_by:
            tool_id = f"tool:{slug}"
            g.add_node(GraphNode(node_id=tool_id, node_type=NodeType.TOOL, label=slug))
            g.add_edge(GraphEdge(
                source_id=ioc_id, target_id=tool_id, edge_type=EdgeType.MISSED_BY,
            ))

    return g


# ── EvalRecord (lightweight) ────────────────────────────────────────────────


def _build_from_eval(ev: EvalRecord) -> ThreatGraph:
    """Build a minimal subgraph from an EvalRecord (tool + category)."""
    g = ThreatGraph()
    tool_id = f"tool:{ev.vendor.lower().replace(' ', '_')}"
    g.add_node(GraphNode(
        node_id=tool_id,
        node_type=NodeType.TOOL,
        label=ev.vendor,
        properties={"category": ev.category},
    ))
    return g


# ── Merge ────────────────────────────────────────────────────────────────────


def merge_graphs(graphs: list[ThreatGraph]) -> ThreatGraph:
    """Merge multiple subgraphs, deduplicating nodes by ID."""
    merged = ThreatGraph()
    for g in graphs:
        for node in g.nodes:
            merged.add_node(node)
        for edge in g.edges:
            merged.add_edge(edge)
    return merged
