"""
oombra.graph — Federated graph intelligence for threat analysis.

Phase 5: Privacy-preserving cross-org attack chain reconstruction.
"""
from .schema import NodeType, EdgeType, GraphNode, GraphEdge, ThreatGraph
from .local import build_graph, build_from_attack_map, build_from_ioc_bundle, merge_graphs
from .embeddings import Node2VecLite, GraphAutoencoder
from .correlate import (
    cosine_similarity,
    find_similar_nodes,
    cluster_campaigns,
    campaign_summary,
    detect_shared_campaigns,
)
from .federated import FederatedGraphClient, federated_graph_round

__all__ = [
    # Schema
    "NodeType", "EdgeType", "GraphNode", "GraphEdge", "ThreatGraph",
    # Local graph building
    "build_graph", "build_from_attack_map", "build_from_ioc_bundle", "merge_graphs",
    # Embeddings
    "Node2VecLite", "GraphAutoencoder",
    # Correlation
    "cosine_similarity", "find_similar_nodes", "cluster_campaigns",
    "campaign_summary", "detect_shared_campaigns",
    # Federated
    "FederatedGraphClient", "federated_graph_round",
]
