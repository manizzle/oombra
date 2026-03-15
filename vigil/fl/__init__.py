"""
Federated Learning for vigil — train models collaboratively without sharing raw data.

Each participant trains locally and shares only DP-noised model updates.
The coordinator aggregates updates using Byzantine-tolerant methods.

Quick start:
    from vigil.fl import FLClient, MalwareClassifier, fedavg

    model = MalwareClassifier(input_dim=256)
    client = FLClient(model, local_data, epsilon=1.0)
    update = client.train_round(global_params)
"""
from .models import NumpyModel, MalwareClassifier, AnomalyDetector, IOCScorer
from .client import FLClient
from .aggregator import fedavg, trimmed_mean, krum, geometric_median, detect_poisoning
from .protocol import FLSession, FLUpdate, FLRoundResult, FLRoundState

__all__ = [
    "NumpyModel", "MalwareClassifier", "AnomalyDetector", "IOCScorer",
    "FLClient",
    "fedavg", "trimmed_mean", "krum", "geometric_median", "detect_poisoning",
    "FLSession", "FLUpdate", "FLRoundResult", "FLRoundState",
]
