"""
Robust aggregation methods for federated learning.

Byzantine-tolerant aggregation ensures that a minority of poisoned
or malicious model updates cannot corrupt the global model.
"""
from __future__ import annotations

import numpy as np


# ══════════════════════════════════════════════════════════════════════════════
# Aggregation methods
# ══════════════════════════════════════════════════════════════════════════════

def fedavg(
    updates: list[dict[str, np.ndarray]],
    weights: list[float] | None = None,
) -> dict[str, np.ndarray]:
    """
    Federated Averaging — weighted mean of model updates.

    Args:
        updates: List of parameter dicts from each client.
        weights: Optional sample counts for weighted averaging.
                 If None, equal weight for all.
    """
    if not updates:
        raise ValueError("No updates to aggregate")

    keys = updates[0].keys()

    if weights is None:
        weights = [1.0] * len(updates)

    total_weight = sum(weights)
    result = {}
    for key in keys:
        weighted_sum = sum(w * u[key] for w, u in zip(weights, updates))
        result[key] = weighted_sum / total_weight

    return result


def trimmed_mean(
    updates: list[dict[str, np.ndarray]],
    trim_ratio: float = 0.1,
) -> dict[str, np.ndarray]:
    """
    Byzantine-tolerant: trim extreme values before averaging.

    For each parameter element, sort across clients, discard the
    top and bottom trim_ratio fraction, then average the rest.
    """
    if not updates:
        raise ValueError("No updates to aggregate")

    n = len(updates)
    trim_count = max(1, int(n * trim_ratio))
    if 2 * trim_count >= n:
        trim_count = max(0, (n - 1) // 2)

    keys = updates[0].keys()
    result = {}

    for key in keys:
        stacked = np.stack([u[key] for u in updates], axis=0)  # (n, *shape)
        flat_shape = (n, -1)
        flat = stacked.reshape(flat_shape)

        # Sort along client axis, trim, average
        sorted_vals = np.sort(flat, axis=0)
        if trim_count > 0:
            trimmed = sorted_vals[trim_count:-trim_count]
        else:
            trimmed = sorted_vals
        avg = np.mean(trimmed, axis=0)
        result[key] = avg.reshape(updates[0][key].shape)

    return result


def krum(
    updates: list[dict[str, np.ndarray]],
    n_byzantine: int = 1,
) -> dict[str, np.ndarray]:
    """
    Multi-Krum: select the update closest to the majority.

    For each update, compute sum of distances to closest (n - f - 2) neighbors.
    Select the update with the smallest score.
    """
    if not updates:
        raise ValueError("No updates to aggregate")

    n = len(updates)
    if n <= 2 * n_byzantine + 2:
        # Not enough clients for Krum, fall back to fedavg
        return fedavg(updates)

    # Flatten each update to a single vector
    vectors = []
    for u in updates:
        flat = np.concatenate([u[k].ravel() for k in sorted(u.keys())])
        vectors.append(flat)
    vectors = np.array(vectors)

    # Compute pairwise distances
    n_neighbors = n - n_byzantine - 2
    scores = np.zeros(n)
    for i in range(n):
        dists = np.array([np.sum((vectors[i] - vectors[j]) ** 2)
                          for j in range(n) if j != i])
        dists.sort()
        scores[i] = np.sum(dists[:n_neighbors])

    best_idx = int(np.argmin(scores))
    return {k: v.copy() for k, v in updates[best_idx].items()}


def geometric_median(
    updates: list[dict[str, np.ndarray]],
    max_iter: int = 100,
    tol: float = 1e-6,
) -> dict[str, np.ndarray]:
    """
    Weiszfeld algorithm for geometric median — robust to outliers.

    Iteratively reweights updates by inverse distance to current estimate.
    """
    if not updates:
        raise ValueError("No updates to aggregate")
    if len(updates) == 1:
        return {k: v.copy() for k, v in updates[0].items()}

    keys = sorted(updates[0].keys())

    # Flatten all updates
    flat_updates = []
    for u in updates:
        flat_updates.append(np.concatenate([u[k].ravel() for k in keys]))
    flat_updates = np.array(flat_updates)  # (n, D)

    # Initialize with mean
    estimate = np.mean(flat_updates, axis=0)

    for _ in range(max_iter):
        dists = np.linalg.norm(flat_updates - estimate, axis=1)  # (n,)
        dists = np.maximum(dists, 1e-10)  # avoid division by zero
        weights = 1.0 / dists
        new_estimate = np.average(flat_updates, axis=0, weights=weights)

        if np.linalg.norm(new_estimate - estimate) < tol:
            estimate = new_estimate
            break
        estimate = new_estimate

    # Unflatten back to dict
    result = {}
    offset = 0
    for k in keys:
        shape = updates[0][k].shape
        size = updates[0][k].size
        result[k] = estimate[offset:offset + size].reshape(shape)
        offset += size

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Poisoning detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_poisoning(
    updates: list[dict[str, np.ndarray]],
    method: str = "zscore",
    threshold: float = 3.0,
) -> list[dict]:
    """
    Score updates for potential poisoning.

    Returns list of dicts: [{"index": i, "score": float, "flagged": bool}, ...]
    """
    if not updates:
        return []

    keys = sorted(updates[0].keys())

    # Flatten
    vectors = []
    for u in updates:
        vectors.append(np.concatenate([u[k].ravel() for k in keys]))
    vectors = np.array(vectors)

    if method == "zscore":
        # Compute L2 norm of each update vector
        norms = np.linalg.norm(vectors, axis=1)
        mean_norm = np.mean(norms)
        std_norm = np.std(norms) + 1e-10
        z_scores = np.abs(norms - mean_norm) / std_norm

        return [
            {"index": i, "score": float(z_scores[i]), "flagged": bool(z_scores[i] > threshold)}
            for i in range(len(updates))
        ]

    elif method == "cosine":
        # Compare each update to the mean update
        mean_vec = np.mean(vectors, axis=0)
        mean_norm = np.linalg.norm(mean_vec) + 1e-10
        scores = []
        for i, v in enumerate(vectors):
            v_norm = np.linalg.norm(v) + 1e-10
            cosine_sim = np.dot(v, mean_vec) / (v_norm * mean_norm)
            # Distance = 1 - similarity; flag if too dissimilar
            dist = 1.0 - cosine_sim
            scores.append({
                "index": i,
                "score": float(dist),
                "flagged": bool(dist > threshold),
            })
        return scores

    else:
        raise ValueError(f"Unknown method: {method}")
