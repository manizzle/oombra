"""
Federated graph learning — share model parameters, not graph structure.
Each org trains a local graph model, shares only the model update.
"""
from __future__ import annotations

import numpy as np

from .schema import ThreatGraph
from .embeddings import GraphAutoencoder
from .correlate import cluster_campaigns, campaign_summary


class FederatedGraphClient:
    """
    Federated learning client for graph models.
    Trains locally on org's threat graph, shares only model parameters.
    """

    def __init__(
        self,
        graph: ThreatGraph,
        embedding_dim: int = 64,
        latent_dim: int = 32,
        epsilon: float | None = None,
    ):
        """
        Args:
            graph: Local threat graph
            embedding_dim: Hidden dimension of autoencoder
            latent_dim: Latent (output) dimension of autoencoder
            epsilon: Optional DP noise budget. If set, Gaussian noise
                     scaled to sensitivity/epsilon is added to parameters.
        """
        self.graph = graph
        self.embedding_dim = embedding_dim
        self.latent_dim = latent_dim
        self.epsilon = epsilon

        n = graph.node_count()
        self.autoencoder = GraphAutoencoder(
            input_dim=n,
            hidden_dim=embedding_dim,
            latent_dim=latent_dim,
        )

    def train_round(
        self,
        global_params: dict | None = None,
        epochs: int = 5,
        lr: float = 0.01,
    ) -> dict:
        """
        Train graph autoencoder locally, return parameter update.
        If epsilon is set, add DP noise to the parameters before sharing.

        Returns: dict of model parameter arrays (W1, b1, W2, b2)
        """
        # Apply global parameters if provided
        if global_params is not None:
            if "W1" in global_params:
                self.autoencoder.W1 = np.array(global_params["W1"], dtype=np.float64)
            if "b1" in global_params:
                self.autoencoder.b1 = np.array(global_params["b1"], dtype=np.float64)
            if "W2" in global_params:
                self.autoencoder.W2 = np.array(global_params["W2"], dtype=np.float64)
            if "b2" in global_params:
                self.autoencoder.b2 = np.array(global_params["b2"], dtype=np.float64)

        # Train locally
        self.autoencoder.fit(self.graph, epochs=epochs, lr=lr)

        # Collect parameters
        params = {
            "W1": self.autoencoder.W1.copy(),
            "b1": self.autoencoder.b1.copy(),
            "W2": self.autoencoder.W2.copy(),
            "b2": self.autoencoder.b2.copy(),
        }

        # Apply differential privacy noise
        if self.epsilon is not None and self.epsilon > 0:
            sensitivity = 1.0  # L2 sensitivity estimate
            sigma = sensitivity / self.epsilon
            for key in params:
                noise = np.random.normal(0, sigma, size=params[key].shape)
                params[key] = params[key] + noise

        return params

    def get_embeddings(self) -> dict[str, np.ndarray]:
        """Get current node embeddings."""
        return self.autoencoder.get_embeddings()

    def detect_campaigns(self, n_clusters: int = 5) -> list[dict]:
        """Run campaign detection on local graph."""
        embeddings = self.get_embeddings()
        if not embeddings:
            return []
        clusters = cluster_campaigns(embeddings, n_clusters=n_clusters)
        return campaign_summary(self.graph, clusters)


def federated_graph_round(
    client_updates: list[dict],
    aggregation: str = "fedavg",
) -> dict:
    """
    Aggregate graph model updates from multiple clients.

    Supports:
        - "fedavg": Federated Averaging (weighted mean of parameters)

    Returns: global model parameters dict with keys W1, b1, W2, b2.
    """
    if not client_updates:
        return {}

    if aggregation == "fedavg":
        return _fedavg(client_updates)
    else:
        raise ValueError(f"Unknown aggregation method: {aggregation}")


def _fedavg(updates: list[dict]) -> dict:
    """Federated Averaging: simple mean of all client parameters."""
    keys = [k for k in updates[0] if isinstance(updates[0][k], np.ndarray)]
    result: dict = {}

    for key in keys:
        arrays = []
        for u in updates:
            if key in u and isinstance(u[key], np.ndarray):
                arrays.append(u[key])
        if arrays:
            # Pad/truncate to common shape (handle varying graph sizes for W1)
            # W1 varies per client (input_dim = node_count), so skip if shapes differ
            shapes = {a.shape for a in arrays}
            if len(shapes) == 1:
                result[key] = np.mean(arrays, axis=0)
            else:
                # For parameters with different shapes (W1 due to different graph sizes),
                # use the first client's shape and average only matching-shape updates
                target_shape = arrays[0].shape
                matching = [a for a in arrays if a.shape == target_shape]
                result[key] = np.mean(matching, axis=0) if matching else arrays[0]

    return result
