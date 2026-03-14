"""
Numpy-only neural network models for federated threat intelligence.

No torch/sklearn required — just numpy math. Each model supports
get_params/set_params for federated parameter exchange.
"""
from __future__ import annotations

import numpy as np


# ══════════════════════════════════════════════════════════════════════════════
# Activation helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sigmoid(x: np.ndarray) -> np.ndarray:
    x = np.clip(x, -500, 500)
    return 1.0 / (1.0 + np.exp(-x))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0, x)


def _relu_grad(x: np.ndarray) -> np.ndarray:
    return (x > 0).astype(x.dtype)


def _he_init(fan_in: int, fan_out: int) -> np.ndarray:
    """He initialization — good for ReLU layers."""
    return np.random.randn(fan_in, fan_out) * np.sqrt(2.0 / fan_in)


def _clip_gradients(grads: dict[str, np.ndarray], max_norm: float = 1.0) -> dict[str, np.ndarray]:
    """Clip gradient dict by global norm."""
    total_norm = np.sqrt(sum(np.sum(g ** 2) for g in grads.values()))
    if total_norm > max_norm:
        scale = max_norm / (total_norm + 1e-8)
        return {k: v * scale for k, v in grads.items()}
    return grads


# ══════════════════════════════════════════════════════════════════════════════
# Base class
# ══════════════════════════════════════════════════════════════════════════════

class NumpyModel:
    """Base class for numpy-based models (no torch needed)."""

    def get_params(self) -> dict[str, np.ndarray]:
        raise NotImplementedError

    def set_params(self, params: dict[str, np.ndarray]) -> None:
        raise NotImplementedError

    def predict(self, X: np.ndarray) -> np.ndarray:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# MalwareClassifier — binary classifier
# ══════════════════════════════════════════════════════════════════════════════

class MalwareClassifier(NumpyModel):
    """
    Binary classifier for malware detection on feature vectors.
    Simple 2-layer neural network with sigmoid output.

    Architecture: input -> ReLU hidden -> sigmoid output
    Loss: binary cross-entropy
    """

    def __init__(self, input_dim: int = 256, hidden_dim: int = 64):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.W1 = _he_init(input_dim, hidden_dim)
        self.b1 = np.zeros(hidden_dim)
        self.W2 = _he_init(hidden_dim, 1)
        self.b2 = np.zeros(1)

    def forward(self, X: np.ndarray) -> np.ndarray:
        """Forward pass. Returns probabilities (N,)."""
        self._z1 = X @ self.W1 + self.b1
        self._a1 = _relu(self._z1)
        self._z2 = self._a1 @ self.W2 + self.b2
        return _sigmoid(self._z2).ravel()

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.forward(X) > 0.5).astype(int)

    def train_step(self, X: np.ndarray, y: np.ndarray, lr: float = 0.01) -> float:
        """One gradient step. Returns binary cross-entropy loss."""
        N = X.shape[0]
        eps = 1e-8
        y = y.ravel()

        # Forward
        probs = self.forward(X)  # (N,)

        # Loss
        loss = -np.mean(y * np.log(probs + eps) + (1 - y) * np.log(1 - probs + eps))

        # Backward
        dz2 = (probs - y).reshape(-1, 1) / N  # (N, 1)
        dW2 = self._a1.T @ dz2
        db2 = np.sum(dz2, axis=0)

        da1 = dz2 @ self.W2.T  # (N, hidden)
        dz1 = da1 * _relu_grad(self._z1)
        dW1 = X.T @ dz1
        db1 = np.sum(dz1, axis=0)

        grads = _clip_gradients({"W1": dW1, "b1": db1, "W2": dW2, "b2": db2})

        self.W1 -= lr * grads["W1"]
        self.b1 -= lr * grads["b1"]
        self.W2 -= lr * grads["W2"]
        self.b2 -= lr * grads["b2"]

        return float(loss)

    def get_params(self) -> dict[str, np.ndarray]:
        return {"W1": self.W1.copy(), "b1": self.b1.copy(),
                "W2": self.W2.copy(), "b2": self.b2.copy()}

    def set_params(self, params: dict[str, np.ndarray]) -> None:
        self.W1 = params["W1"].copy()
        self.b1 = params["b1"].copy()
        self.W2 = params["W2"].copy()
        self.b2 = params["b2"].copy()


# ══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector — autoencoder
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector(NumpyModel):
    """
    Autoencoder-based anomaly detector.
    Learns normal patterns, flags high-reconstruction-error inputs.

    Architecture: input -> ReLU latent -> sigmoid reconstruction
    Loss: MSE reconstruction error
    """

    def __init__(self, input_dim: int = 128, latent_dim: int = 32):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.W_enc = _he_init(input_dim, latent_dim)
        self.b_enc = np.zeros(latent_dim)
        self.W_dec = _he_init(latent_dim, input_dim)
        self.b_dec = np.zeros(input_dim)

    def encode(self, X: np.ndarray) -> np.ndarray:
        self._z_enc = X @ self.W_enc + self.b_enc
        return _relu(self._z_enc)

    def decode(self, Z: np.ndarray) -> np.ndarray:
        return _sigmoid(Z @ self.W_dec + self.b_dec)

    def forward(self, X: np.ndarray) -> np.ndarray:
        return self.decode(self.encode(X))

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Per-sample MSE reconstruction error."""
        recon = self.forward(X)
        return np.mean((X - recon) ** 2, axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Higher values = more anomalous."""
        return self.reconstruction_error(X)

    def train_step(self, X: np.ndarray, lr: float = 0.01) -> float:
        """One gradient step on reconstruction MSE. Returns loss."""
        N = X.shape[0]

        # Forward
        z_enc = X @ self.W_enc + self.b_enc
        a_enc = _relu(z_enc)
        z_dec = a_enc @ self.W_dec + self.b_dec
        recon = _sigmoid(z_dec)

        # Loss
        diff = recon - X  # (N, input_dim)
        loss = float(np.mean(diff ** 2))

        # Backward through decoder
        # d_loss/d_recon = 2 * diff / (N * input_dim)
        d_recon = 2.0 * diff / (N * self.input_dim)
        # sigmoid gradient: recon * (1 - recon)
        d_z_dec = d_recon * recon * (1 - recon)  # (N, input_dim)
        dW_dec = a_enc.T @ d_z_dec
        db_dec = np.sum(d_z_dec, axis=0)

        # Backward through encoder
        d_a_enc = d_z_dec @ self.W_dec.T  # (N, latent_dim)
        d_z_enc = d_a_enc * _relu_grad(z_enc)
        dW_enc = X.T @ d_z_enc
        db_enc = np.sum(d_z_enc, axis=0)

        grads = _clip_gradients({
            "W_enc": dW_enc, "b_enc": db_enc,
            "W_dec": dW_dec, "b_dec": db_dec,
        })

        self.W_enc -= lr * grads["W_enc"]
        self.b_enc -= lr * grads["b_enc"]
        self.W_dec -= lr * grads["W_dec"]
        self.b_dec -= lr * grads["b_dec"]

        return loss

    def get_params(self) -> dict[str, np.ndarray]:
        return {"W_enc": self.W_enc.copy(), "b_enc": self.b_enc.copy(),
                "W_dec": self.W_dec.copy(), "b_dec": self.b_dec.copy()}

    def set_params(self, params: dict[str, np.ndarray]) -> None:
        self.W_enc = params["W_enc"].copy()
        self.b_enc = params["b_enc"].copy()
        self.W_dec = params["W_dec"].copy()
        self.b_dec = params["b_dec"].copy()


# ══════════════════════════════════════════════════════════════════════════════
# IOCScorer — regression
# ══════════════════════════════════════════════════════════════════════════════

class IOCScorer(NumpyModel):
    """
    Predict IOC severity from contextual features.
    Regression model: features -> severity score (0-10).

    Architecture: input -> ReLU hidden -> linear output (clamped to 0-10)
    Loss: MSE
    """

    def __init__(self, input_dim: int = 64, hidden_dim: int = 32):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.W1 = _he_init(input_dim, hidden_dim)
        self.b1 = np.zeros(hidden_dim)
        self.W2 = _he_init(hidden_dim, 1)
        self.b2 = np.zeros(1)

    def forward(self, X: np.ndarray) -> np.ndarray:
        """Returns severity scores (N,) clamped to [0, 10]."""
        self._z1 = X @ self.W1 + self.b1
        self._a1 = _relu(self._z1)
        out = (self._a1 @ self.W2 + self.b2).ravel()
        return np.clip(out, 0.0, 10.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.forward(X)

    def train_step(self, X: np.ndarray, y: np.ndarray, lr: float = 0.01) -> float:
        """One gradient step on MSE. Returns loss."""
        N = X.shape[0]
        y = y.ravel()

        # Forward (unclamped for gradient flow)
        z1 = X @ self.W1 + self.b1
        a1 = _relu(z1)
        out = (a1 @ self.W2 + self.b2).ravel()

        # Loss (MSE)
        diff = out - y
        loss = float(np.mean(diff ** 2))

        # Backward
        d_out = (2.0 * diff / N).reshape(-1, 1)  # (N, 1)
        dW2 = a1.T @ d_out
        db2 = np.sum(d_out, axis=0)

        da1 = d_out @ self.W2.T
        dz1 = da1 * _relu_grad(z1)
        dW1 = X.T @ dz1
        db1 = np.sum(dz1, axis=0)

        grads = _clip_gradients({"W1": dW1, "b1": db1, "W2": dW2, "b2": db2})

        self.W1 -= lr * grads["W1"]
        self.b1 -= lr * grads["b1"]
        self.W2 -= lr * grads["W2"]
        self.b2 -= lr * grads["b2"]

        return loss

    def get_params(self) -> dict[str, np.ndarray]:
        return {"W1": self.W1.copy(), "b1": self.b1.copy(),
                "W2": self.W2.copy(), "b2": self.b2.copy()}

    def set_params(self, params: dict[str, np.ndarray]) -> None:
        self.W1 = params["W1"].copy()
        self.b1 = params["b1"].copy()
        self.W2 = params["W2"].copy()
        self.b2 = params["b2"].copy()
