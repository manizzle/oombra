"""
Graph embedding algorithms for threat intelligence graphs.
Pure numpy — no torch-geometric dependency needed for core.
"""
from __future__ import annotations

import numpy as np

from .schema import ThreatGraph


class Node2VecLite:
    """
    Simplified Node2Vec using random walks + skip-gram.
    Pure numpy implementation for small-medium graphs.
    """

    def __init__(
        self,
        dimensions: int = 64,
        walk_length: int = 10,
        num_walks: int = 20,
        p: float = 1.0,
        q: float = 1.0,
        window: int = 3,
    ):
        self.dimensions = dimensions
        self.walk_length = walk_length
        self.num_walks = num_walks
        self.p = p
        self.q = q
        self.window = window
        self._embeddings: dict[str, np.ndarray] = {}

    # ── Public API ──────────────────────────────────────────────────────────

    def fit(
        self,
        graph: ThreatGraph,
        epochs: int = 5,
        lr: float = 0.025,
    ) -> dict[str, np.ndarray]:
        """Compute embeddings for all nodes via biased random walks + skip-gram."""
        node_ids = [n.node_id for n in graph.nodes]
        if not node_ids:
            return {}

        n = len(node_ids)
        idx = {nid: i for i, nid in enumerate(node_ids)}

        # Build adjacency list with weights
        adj: dict[int, list[tuple[int, float]]] = {i: [] for i in range(n)}
        for e in graph.edges:
            si, ti = idx.get(e.source_id), idx.get(e.target_id)
            if si is not None and ti is not None:
                adj[si].append((ti, e.weight))
                adj[ti].append((si, e.weight))  # treat as undirected

        # Initialize embedding matrix
        W = np.random.randn(n, self.dimensions).astype(np.float64) * 0.1

        # Generate walks and train
        for _epoch in range(epochs):
            for node_idx in range(n):
                for _ in range(self.num_walks):
                    walk = self._random_walk(adj, node_idx, self.walk_length, n)
                    # Skip-gram update for each (target, context) pair in the walk
                    for pos, target in enumerate(walk):
                        start = max(0, pos - self.window)
                        end = min(len(walk), pos + self.window + 1)
                        for ctx_pos in range(start, end):
                            if ctx_pos == pos:
                                continue
                            context = walk[ctx_pos]
                            self._skip_gram_update(W, target, context, lr)

        self._embeddings = {nid: W[i].copy() for nid, i in idx.items()}
        return self._embeddings

    # ── Internals ───────────────────────────────────────────────────────────

    def _random_walk(
        self,
        adj: dict[int, list[tuple[int, float]]],
        start: int,
        length: int,
        n: int,
    ) -> list[int]:
        """Biased random walk from *start* with return param p and in-out param q."""
        walk = [start]
        for _ in range(length - 1):
            cur = walk[-1]
            neighbors = adj.get(cur, [])
            if not neighbors:
                break

            if len(walk) == 1:
                # First step: weight by edge weight only
                weights = np.array([w for _, w in neighbors], dtype=np.float64)
            else:
                prev = walk[-2]
                weights = np.empty(len(neighbors), dtype=np.float64)
                for i, (nbr, w) in enumerate(neighbors):
                    if nbr == prev:
                        weights[i] = w / self.p  # return
                    elif any(nb == prev for nb, _ in adj.get(nbr, [])):
                        weights[i] = w  # BFS-like
                    else:
                        weights[i] = w / self.q  # DFS-like

            # Normalize to probabilities
            total = weights.sum()
            if total == 0:
                break
            probs = weights / total
            chosen_idx = np.random.choice(len(neighbors), p=probs)
            walk.append(neighbors[chosen_idx][0])

        return walk

    @staticmethod
    def _skip_gram_update(
        W: np.ndarray,
        target: int,
        context: int,
        lr: float,
    ) -> None:
        """Single SGD step: maximize dot(W[target], W[context])."""
        dot = np.dot(W[target], W[context])
        # Sigmoid
        sig = 1.0 / (1.0 + np.exp(-np.clip(dot, -10, 10)))
        grad = lr * (1.0 - sig)
        # Symmetric update
        W[target] += grad * W[context]
        W[context] += grad * W[target]


class GraphAutoencoder:
    """
    Simple graph autoencoder for learning node embeddings.
    Encodes adjacency structure into low-dimensional space.

    Architecture:
        Encoder: A -> sigmoid(A @ W1 + b1) -> sigmoid(H @ W2 + b2) = Z
        Decoder: Z @ Z.T  (inner product decoder)
        Loss: MSE between original adjacency and reconstructed adjacency
    """

    def __init__(self, input_dim: int, hidden_dim: int = 64, latent_dim: int = 32):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim

        # Encoder weights (Xavier init)
        self.W1 = np.random.randn(input_dim, hidden_dim) * np.sqrt(2.0 / (input_dim + hidden_dim))
        self.b1 = np.zeros(hidden_dim)
        self.W2 = np.random.randn(hidden_dim, latent_dim) * np.sqrt(2.0 / (hidden_dim + latent_dim))
        self.b2 = np.zeros(latent_dim)

        self._node_ids: list[str] = []
        self._Z: np.ndarray | None = None

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -10, 10)))

    def encode(self, adjacency: np.ndarray) -> np.ndarray:
        """Encode adjacency matrix to latent space."""
        H = self._sigmoid(adjacency @ self.W1 + self.b1)
        Z = self._sigmoid(H @ self.W2 + self.b2)
        return Z

    def decode(self, Z: np.ndarray) -> np.ndarray:
        """Decode latent representations via inner product."""
        return self._sigmoid(Z @ Z.T)

    def fit(self, graph: ThreatGraph, epochs: int = 100, lr: float = 0.01) -> None:
        """Train the autoencoder on a graph."""
        matrix, node_ids = graph.to_adjacency_matrix()
        A = np.array(matrix, dtype=np.float64)
        n = A.shape[0]
        if n == 0:
            return

        self._node_ids = node_ids

        # Re-init weights if input_dim doesn't match
        if self.input_dim != n:
            self.input_dim = n
            self.W1 = np.random.randn(n, self.hidden_dim) * np.sqrt(2.0 / (n + self.hidden_dim))
            self.b1 = np.zeros(self.hidden_dim)

        # Normalize adjacency (add self-loops, symmetric normalize)
        A_hat = A + np.eye(n)
        D_inv_sqrt = np.diag(1.0 / np.sqrt(np.maximum(A_hat.sum(axis=1), 1e-8)))
        A_norm = D_inv_sqrt @ A_hat @ D_inv_sqrt

        for _epoch in range(epochs):
            # Forward
            H = self._sigmoid(A_norm @ self.W1 + self.b1)
            Z = self._sigmoid(H @ self.W2 + self.b2)
            A_recon = self._sigmoid(Z @ Z.T)

            # Loss gradient (MSE)
            diff = A_recon - A_norm
            dA_recon = 2.0 * diff / n

            # Backprop through decoder
            dZ_decode = dA_recon * A_recon * (1 - A_recon)
            dZ = (dZ_decode + dZ_decode.T) @ Z

            # Backprop through encoder layer 2
            dZ_pre = dZ * Z * (1 - Z)
            dW2 = H.T @ dZ_pre
            db2 = dZ_pre.sum(axis=0)

            # Backprop through encoder layer 1
            dH = dZ_pre @ self.W2.T
            dH_pre = dH * H * (1 - H)
            dW1 = A_norm.T @ dH_pre
            db1 = dH_pre.sum(axis=0)

            # SGD update
            self.W1 -= lr * dW1
            self.b1 -= lr * db1
            self.W2 -= lr * dW2
            self.b2 -= lr * db2

        # Cache final embeddings
        H = self._sigmoid(A_norm @ self.W1 + self.b1)
        self._Z = self._sigmoid(H @ self.W2 + self.b2)

    def get_embeddings(self) -> dict[str, np.ndarray]:
        """Return learned node embeddings."""
        if self._Z is None:
            return {}
        return {nid: self._Z[i].copy() for i, nid in enumerate(self._node_ids)}
