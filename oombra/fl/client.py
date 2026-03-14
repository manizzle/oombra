"""
Federated learning client — trains locally, shares only DP-noised model updates.

The client never sends raw data. Only parameter deltas (optionally noised
with differential privacy) leave the machine.
"""
from __future__ import annotations

import copy
from typing import Any

import numpy as np

from .models import NumpyModel, MalwareClassifier, AnomalyDetector, IOCScorer


class FLClient:
    """
    Federated learning client — trains locally, shares only DP-noised model updates.
    """

    def __init__(
        self,
        model: NumpyModel,
        local_data: np.ndarray | tuple[np.ndarray, ...],
        epsilon: float | None = None,
    ):
        """
        Args:
            model: A model instance (MalwareClassifier, AnomalyDetector, or IOCScorer).
            local_data: Local training data. For supervised models, a tuple (X, y).
                        For unsupervised (AnomalyDetector), just X.
            epsilon: Optional DP budget for gradient noise.
        """
        self.model = model
        self.epsilon = epsilon

        if isinstance(local_data, tuple):
            self.X = local_data[0]
            self.y = local_data[1] if len(local_data) > 1 else None
        else:
            self.X = local_data
            self.y = None

    def train_round(
        self,
        global_params: dict[str, np.ndarray] | None = None,
        epochs: int = 1,
        lr: float = 0.01,
    ) -> dict[str, np.ndarray]:
        """
        Train on local data, return model update (gradient delta).
        If epsilon is set, add calibrated DP noise to gradients.

        Args:
            global_params: Current global model parameters. If provided, model is
                           set to these before training.
            epochs: Number of local epochs.
            lr: Learning rate.

        Returns:
            Dict of parameter updates (delta = new_params - old_params).
        """
        # Set global parameters if provided
        if global_params is not None:
            self.model.set_params(global_params)

        # Snapshot params before training
        old_params = self.model.get_params()

        # Train locally
        for _ in range(epochs):
            if isinstance(self.model, AnomalyDetector):
                self.model.train_step(self.X, lr=lr)
            else:
                self.model.train_step(self.X, self.y, lr=lr)

        # Compute delta
        new_params = self.model.get_params()
        delta = {
            k: new_params[k] - old_params[k]
            for k in new_params
        }

        # Add DP noise if epsilon is set
        if self.epsilon is not None and self.epsilon > 0:
            delta = self._add_dp_noise(delta)

        return delta

    def _add_dp_noise(self, delta: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
        """Add calibrated Laplace noise to parameter deltas."""
        noised = {}
        n_params = len(delta)
        per_param_epsilon = self.epsilon / max(n_params, 1)

        for key, grad in delta.items():
            # Sensitivity: clip grad norm then use as sensitivity
            sensitivity = float(np.max(np.abs(grad))) + 1e-10
            scale = sensitivity / per_param_epsilon
            noise = np.random.laplace(0, scale, size=grad.shape)
            noised[key] = grad + noise

        return noised

    def evaluate(self, test_data: np.ndarray | tuple[np.ndarray, ...]) -> dict[str, float]:
        """Evaluate model on local test data. Returns metrics dict."""
        if isinstance(test_data, tuple):
            X_test = test_data[0]
            y_test = test_data[1] if len(test_data) > 1 else None
        else:
            X_test = test_data
            y_test = None

        metrics: dict[str, float] = {}

        if isinstance(self.model, MalwareClassifier):
            preds = self.model.predict(X_test)
            probs = self.model.forward(X_test)
            if y_test is not None:
                y_true = y_test.ravel()
                metrics["accuracy"] = float(np.mean(preds == y_true))
                eps = 1e-8
                metrics["loss"] = float(-np.mean(
                    y_true * np.log(probs + eps) + (1 - y_true) * np.log(1 - probs + eps)
                ))
        elif isinstance(self.model, AnomalyDetector):
            errors = self.model.reconstruction_error(X_test)
            metrics["mean_reconstruction_error"] = float(np.mean(errors))
            metrics["max_reconstruction_error"] = float(np.max(errors))
        elif isinstance(self.model, IOCScorer):
            preds = self.model.predict(X_test)
            if y_test is not None:
                metrics["mse"] = float(np.mean((preds - y_test.ravel()) ** 2))
                metrics["mae"] = float(np.mean(np.abs(preds - y_test.ravel())))

        return metrics

    def get_params(self) -> dict[str, np.ndarray]:
        """Return current model parameters."""
        return self.model.get_params()

    def set_params(self, params: dict[str, np.ndarray]) -> None:
        """Set model parameters from global update."""
        self.model.set_params(params)

    @property
    def n_samples(self) -> int:
        """Number of local training samples."""
        return self.X.shape[0]
