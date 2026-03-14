"""
Cross-org campaign correlation using embedding similarity.
Uses only embeddings (not raw data) for privacy-preserving correlation.
"""
from __future__ import annotations

import numpy as np

from .schema import ThreatGraph, NodeType


# ── Similarity ──────────────────────────────────────────────────────────────


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two embedding vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def find_similar_nodes(
    our_embeddings: dict[str, np.ndarray],
    their_embeddings: dict[str, np.ndarray],
    threshold: float = 0.8,
) -> list[dict]:
    """
    Find similar nodes across two organizations' graphs.
    Only compares embeddings — never raw values.

    Returns list of:
        {"our_node": id, "their_node": id, "similarity": float}
    """
    results: list[dict] = []
    for our_id, our_vec in our_embeddings.items():
        for their_id, their_vec in their_embeddings.items():
            sim = cosine_similarity(our_vec, their_vec)
            if sim >= threshold:
                results.append({
                    "our_node": our_id,
                    "their_node": their_id,
                    "similarity": round(sim, 4),
                })
    # Sort by similarity descending
    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results


# ── Clustering ──────────────────────────────────────────────────────────────


def _kmeans(X: np.ndarray, k: int, max_iter: int = 100) -> tuple[np.ndarray, np.ndarray]:
    """Simple Lloyd's algorithm k-means with kmeans++ initialization."""
    n = X.shape[0]
    if n == 0 or k <= 0:
        return np.array([], dtype=int), np.empty((0, X.shape[1]))
    k = min(k, n)

    # kmeans++ initialization: pick centroids spread apart
    rng = np.random.default_rng()
    centroids = [X[rng.integers(n)]]
    for _ in range(1, k):
        dists = np.min([np.linalg.norm(X - c, axis=1) ** 2 for c in centroids], axis=0)
        probs = dists / dists.sum()
        centroids.append(X[rng.choice(n, p=probs)])
    centroids = np.array(centroids)

    labels = np.zeros(n, dtype=int)
    for _ in range(max_iter):
        # Assign
        distances = np.linalg.norm(X[:, None] - centroids[None], axis=2)
        labels = np.argmin(distances, axis=1)
        # Update
        new_centroids = np.array([
            X[labels == i].mean(axis=0) if np.any(labels == i) else centroids[i]
            for i in range(k)
        ])
        if np.allclose(centroids, new_centroids):
            break
        centroids = new_centroids

    return labels, centroids


def cluster_campaigns(
    embeddings: dict[str, np.ndarray],
    n_clusters: int = 5,
    method: str = "kmeans",
) -> dict[str, int]:
    """
    Cluster nodes into campaign groups based on embedding similarity.
    Uses simple k-means (numpy-only implementation).

    Returns: dict mapping node_id -> cluster_id
    """
    if not embeddings:
        return {}

    ids = list(embeddings.keys())
    X = np.array([embeddings[nid] for nid in ids])
    labels, _ = _kmeans(X, min(n_clusters, len(ids)))
    return {nid: int(labels[i]) for i, nid in enumerate(ids)}


# ── Campaign summaries ──────────────────────────────────────────────────────


def campaign_summary(
    graph: ThreatGraph,
    clusters: dict[str, int],
) -> list[dict]:
    """
    Generate human-readable campaign summaries from clusters.
    Returns list of campaign dicts with techniques, IOC types, tools involved.
    """
    # Group node_ids by cluster
    cluster_groups: dict[int, list[str]] = {}
    for nid, cid in clusters.items():
        cluster_groups.setdefault(cid, []).append(nid)

    summaries: list[dict] = []
    for cid, node_ids in sorted(cluster_groups.items()):
        techniques: list[str] = []
        ioc_types: set[str] = set()
        tools: set[str] = set()
        actors: set[str] = set()
        campaigns: set[str] = set()

        for nid in node_ids:
            node = graph.get_node(nid)
            if node is None:
                continue
            if node.node_type == NodeType.TECHNIQUE:
                techniques.append(node.label or nid)
            elif node.node_type == NodeType.IOC:
                ioc_types.add(node.label or "unknown")
            elif node.node_type == NodeType.TOOL:
                tools.add(node.label or nid)
            elif node.node_type == NodeType.THREAT_ACTOR:
                actors.add(node.label or nid)
            elif node.node_type == NodeType.CAMPAIGN:
                campaigns.add(node.label or nid)

        summaries.append({
            "cluster_id": cid,
            "node_count": len(node_ids),
            "techniques": techniques,
            "ioc_types": sorted(ioc_types),
            "tools": sorted(tools),
            "actors": sorted(actors),
            "campaigns": sorted(campaigns),
        })

    return summaries


# ── Cross-org campaign detection ────────────────────────────────────────────


def detect_shared_campaigns(
    our_graph: ThreatGraph,
    our_embeddings: dict[str, np.ndarray],
    their_embeddings: dict[str, np.ndarray],
    threshold: float = 0.75,
) -> list[dict]:
    """
    Detect campaigns that appear to be shared across orgs.
    "Your IOCs are part of a larger campaign seen by other orgs"
    — without revealing anyone's specific IOCs.
    """
    similar = find_similar_nodes(our_embeddings, their_embeddings, threshold=threshold)

    # Group matched nodes by type
    shared_techniques: list[dict] = []
    shared_iocs: int = 0
    shared_tools: list[str] = []

    for match in similar:
        our_node = our_graph.get_node(match["our_node"])
        if our_node is None:
            continue
        if our_node.node_type == NodeType.TECHNIQUE:
            shared_techniques.append({
                "technique": our_node.label or our_node.node_id,
                "similarity": match["similarity"],
            })
        elif our_node.node_type == NodeType.IOC:
            shared_iocs += 1
        elif our_node.node_type == NodeType.TOOL:
            shared_tools.append(our_node.label or our_node.node_id)

    campaigns: list[dict] = []
    if shared_techniques or shared_iocs > 0:
        campaigns.append({
            "description": "Shared attack patterns detected across organizations",
            "shared_technique_count": len(shared_techniques),
            "shared_ioc_count": shared_iocs,
            "shared_tools": list(set(shared_tools)),
            "techniques": shared_techniques[:10],  # top 10
            "confidence": round(
                np.mean([m["similarity"] for m in similar]) if similar else 0.0, 3
            ),
            "total_matches": len(similar),
        })

    return campaigns
