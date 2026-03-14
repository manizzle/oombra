"""
Threat graph schema mapping to STIX 2.1 relationships.
Nodes are entities (IOCs, techniques, actors, tools).
Edges are relationships (uses, targets, indicates, attributed-to).
"""
from __future__ import annotations

from enum import Enum
from pydantic import BaseModel


class NodeType(str, Enum):
    IOC = "ioc"
    TECHNIQUE = "technique"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class EdgeType(str, Enum):
    USES = "uses"                      # actor -> technique
    TARGETS = "targets"                # campaign -> industry/org_type
    INDICATES = "indicates"            # IOC -> campaign
    ATTRIBUTED_TO = "attributed_to"    # campaign -> actor
    DETECTED_BY = "detected_by"        # IOC/technique -> tool
    MISSED_BY = "missed_by"            # IOC/technique -> tool
    RELATED_TO = "related_to"          # generic relationship
    EXPLOITS = "exploits"              # technique -> vulnerability


class GraphNode(BaseModel):
    node_id: str              # hash-based ID (no raw values)
    node_type: NodeType
    label: str | None = None  # safe label (technique name, not raw IOC)
    properties: dict = {}     # additional metadata


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    properties: dict = {}


class ThreatGraph(BaseModel):
    """Local threat graph built from contributions."""

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    metadata: dict = {}

    # ── Node / edge mutation ────────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> None:
        """Append node if no node with the same node_id already exists."""
        if not any(n.node_id == node.node_id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    # ── Lookups ─────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> GraphNode | None:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        return None

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        """Return all nodes connected to *node_id* by any edge."""
        neighbor_ids: set[str] = set()
        for e in self.edges:
            if e.source_id == node_id:
                neighbor_ids.add(e.target_id)
            elif e.target_id == node_id:
                neighbor_ids.add(e.source_id)
        return [n for n in self.nodes if n.node_id in neighbor_ids]

    def get_edges_for(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.source_id == node_id or e.target_id == node_id]

    # ── Metrics ─────────────────────────────────────────────────────────────

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)

    # ── Adjacency matrix ───────────────────────────────────────────────────

    def to_adjacency_matrix(self) -> tuple[list[list[float]], list[str]]:
        """
        Return (matrix, node_ids) where matrix[i][j] is the sum of edge
        weights from node_ids[i] to node_ids[j].
        """
        ids = [n.node_id for n in self.nodes]
        idx = {nid: i for i, nid in enumerate(ids)}
        n = len(ids)
        matrix = [[0.0] * n for _ in range(n)]
        for e in self.edges:
            si = idx.get(e.source_id)
            ti = idx.get(e.target_id)
            if si is not None and ti is not None:
                matrix[si][ti] += e.weight
        return matrix, ids

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict) -> ThreatGraph:
        return cls.model_validate(data)
