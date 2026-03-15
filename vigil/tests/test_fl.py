"""Tests for federated learning: models, aggregation, client, protocol."""
from __future__ import annotations

import numpy as np
import pytest

from vigil.fl.models import MalwareClassifier, AnomalyDetector, IOCScorer
from vigil.fl.aggregator import fedavg, trimmed_mean, krum, geometric_median, detect_poisoning
from vigil.fl.client import FLClient
from vigil.fl.protocol import (
    FLSession, FLUpdate, FLRoundResult, FLRoundState,
    serialize_params, deserialize_params, ndarray_to_b64, b64_to_ndarray,
)


# ══════════════════════════════════════════════════════════════════════════════
# Model tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMalwareClassifier:
    def test_forward_shape(self):
        model = MalwareClassifier(input_dim=16, hidden_dim=8)
        X = np.random.randn(10, 16)
        out = model.forward(X)
        assert out.shape == (10,)
        assert np.all((out >= 0) & (out <= 1))

    def test_predict_binary(self):
        model = MalwareClassifier(input_dim=16, hidden_dim=8)
        X = np.random.randn(10, 16)
        preds = model.predict(X)
        assert set(np.unique(preds)).issubset({0, 1})

    def test_training_loss_decreases(self):
        np.random.seed(42)
        model = MalwareClassifier(input_dim=8, hidden_dim=4)
        X = np.random.randn(100, 8)
        y = (X[:, 0] > 0).astype(float)

        losses = []
        for _ in range(50):
            loss = model.train_step(X, y, lr=0.05)
            losses.append(loss)

        # Loss should decrease overall
        assert losses[-1] < losses[0], f"Loss did not decrease: {losses[0]:.4f} -> {losses[-1]:.4f}"

    def test_get_set_params(self):
        model = MalwareClassifier(input_dim=8, hidden_dim=4)
        params = model.get_params()
        assert "W1" in params and "W2" in params
        assert "b1" in params and "b2" in params

        # Modify and restore
        model2 = MalwareClassifier(input_dim=8, hidden_dim=4)
        model2.set_params(params)
        for k in params:
            np.testing.assert_array_equal(model2.get_params()[k], params[k])


class TestAnomalyDetector:
    def test_encode_decode_shape(self):
        model = AnomalyDetector(input_dim=16, latent_dim=4)
        X = np.random.rand(10, 16)  # Use [0,1] for sigmoid output
        encoded = model.encode(X)
        assert encoded.shape == (10, 4)
        decoded = model.decode(encoded)
        assert decoded.shape == (10, 16)

    def test_reconstruction_error(self):
        model = AnomalyDetector(input_dim=16, latent_dim=4)
        X = np.random.rand(10, 16)
        errors = model.reconstruction_error(X)
        assert errors.shape == (10,)
        assert np.all(errors >= 0)

    def test_training_loss_decreases(self):
        np.random.seed(42)
        model = AnomalyDetector(input_dim=8, latent_dim=4)
        # Normal data: values around 0.5
        X = np.random.rand(100, 8) * 0.5 + 0.25

        losses = []
        for _ in range(100):
            loss = model.train_step(X, lr=0.05)
            losses.append(loss)

        assert losses[-1] < losses[0], f"Loss did not decrease: {losses[0]:.4f} -> {losses[-1]:.4f}"

    def test_get_set_params(self):
        model = AnomalyDetector(input_dim=8, latent_dim=4)
        params = model.get_params()
        assert "W_enc" in params and "W_dec" in params


class TestIOCScorer:
    def test_predict_range(self):
        model = IOCScorer(input_dim=8)
        X = np.random.randn(10, 8)
        preds = model.predict(X)
        assert preds.shape == (10,)
        assert np.all((preds >= 0) & (preds <= 10))

    def test_training_converges(self):
        np.random.seed(42)
        model = IOCScorer(input_dim=8, hidden_dim=16)
        X = np.random.randn(200, 8)
        y = 5.0 + 2.0 * X[:, 0]  # Linear relationship
        y = np.clip(y, 0, 10)

        losses = []
        for _ in range(100):
            loss = model.train_step(X, y, lr=0.001)
            losses.append(loss)

        assert losses[-1] < losses[0], f"Loss did not decrease: {losses[0]:.4f} -> {losses[-1]:.4f}"


# ══════════════════════════════════════════════════════════════════════════════
# Aggregation tests
# ══════════════════════════════════════════════════════════════════════════════

def _make_updates(n=3, dim=4):
    """Create n random parameter updates for testing."""
    return [
        {"W": np.random.randn(dim, dim), "b": np.random.randn(dim)}
        for _ in range(n)
    ]


class TestFedAvg:
    def test_equal_weights(self):
        updates = _make_updates(3, 4)
        result = fedavg(updates)
        expected_W = np.mean([u["W"] for u in updates], axis=0)
        np.testing.assert_allclose(result["W"], expected_W)

    def test_weighted(self):
        updates = _make_updates(2, 2)
        result = fedavg(updates, weights=[3.0, 1.0])
        expected_W = (3.0 * updates[0]["W"] + 1.0 * updates[1]["W"]) / 4.0
        np.testing.assert_allclose(result["W"], expected_W)

    def test_single_update(self):
        updates = _make_updates(1, 2)
        result = fedavg(updates)
        np.testing.assert_array_equal(result["W"], updates[0]["W"])


class TestTrimmedMean:
    def test_handles_outlier(self):
        np.random.seed(42)
        # 5 normal updates + 1 extreme outlier
        updates = [{"W": np.ones((2, 2)) * i} for i in range(5)]
        updates.append({"W": np.ones((2, 2)) * 1000})  # outlier

        result = trimmed_mean(updates, trim_ratio=0.2)
        # After trimming top and bottom 20% (1 each from 6), avg of middle 4
        # Middle values: 1, 2, 3, 4 -> mean = 2.5
        assert result["W"][0, 0] < 100, "Outlier should be trimmed"


class TestKrum:
    def test_selects_non_byzantine(self):
        np.random.seed(42)
        # 4 honest updates near each other, 1 Byzantine far away
        honest = [{"W": np.ones(4) * 1.0 + np.random.randn(4) * 0.01} for _ in range(4)]
        byzantine = [{"W": np.ones(4) * 1000.0}]
        updates = honest + byzantine

        result = krum(updates, n_byzantine=1)
        # Result should be close to 1.0, not 1000.0
        assert np.mean(result["W"]) < 10.0


class TestGeometricMedian:
    def test_converges(self):
        np.random.seed(42)
        updates = [{"W": np.ones(4) * i} for i in [1.0, 2.0, 3.0, 100.0]]
        result = geometric_median(updates)
        # Should be closer to the cluster (1,2,3) than the outlier (100)
        assert np.mean(result["W"]) < 50.0

    def test_single_update(self):
        updates = [{"W": np.array([1.0, 2.0])}]
        result = geometric_median(updates)
        np.testing.assert_array_equal(result["W"], updates[0]["W"])


class TestPoisoningDetection:
    def test_flags_extreme_outlier(self):
        np.random.seed(42)
        updates = [{"W": np.ones(4) * 1.0} for _ in range(5)]
        updates.append({"W": np.ones(4) * 1000.0})  # outlier

        flags = detect_poisoning(updates, method="zscore", threshold=2.0)
        assert len(flags) == 6
        # The outlier (index 5) should be flagged
        assert flags[5]["flagged"] is True
        # At least some non-outliers should NOT be flagged
        assert not all(f["flagged"] for f in flags[:5])

    def test_no_false_positives_on_uniform(self):
        updates = [{"W": np.ones(4) * 1.0} for _ in range(5)]
        flags = detect_poisoning(updates, threshold=3.0)
        assert all(not f["flagged"] for f in flags)


# ══════════════════════════════════════════════════════════════════════════════
# Client tests
# ══════════════════════════════════════════════════════════════════════════════

class TestFLClient:
    def test_train_round_returns_valid_updates(self):
        np.random.seed(42)
        model = MalwareClassifier(input_dim=8, hidden_dim=4)
        X = np.random.randn(50, 8)
        y = (X[:, 0] > 0).astype(float)

        client = FLClient(model, (X, y))
        global_params = model.get_params()
        delta = client.train_round(global_params, epochs=1, lr=0.01)

        assert set(delta.keys()) == {"W1", "b1", "W2", "b2"}
        # Deltas should not all be zero
        assert any(np.any(v != 0) for v in delta.values())

    def test_dp_noise_changes_params(self):
        np.random.seed(42)
        model = MalwareClassifier(input_dim=8, hidden_dim=4)
        X = np.random.randn(50, 8)
        y = (X[:, 0] > 0).astype(float)

        # Train without DP
        client_no_dp = FLClient(MalwareClassifier(input_dim=8, hidden_dim=4), (X, y))
        params = model.get_params()
        delta_no_dp = client_no_dp.train_round(params.copy(), epochs=1)

        # Train with DP
        client_dp = FLClient(MalwareClassifier(input_dim=8, hidden_dim=4), (X, y), epsilon=0.1)
        delta_dp = client_dp.train_round(params.copy(), epochs=1)

        # With small epsilon (lots of noise), deltas should differ
        differs = any(
            not np.allclose(delta_no_dp[k], delta_dp[k], atol=1e-6)
            for k in delta_no_dp
        )
        assert differs, "DP noise should change the parameter deltas"

    def test_evaluate_malware(self):
        np.random.seed(42)
        model = MalwareClassifier(input_dim=8, hidden_dim=4)
        X = np.random.randn(20, 8)
        y = (X[:, 0] > 0).astype(float)

        client = FLClient(model, (X, y))
        metrics = client.evaluate((X, y))
        assert "accuracy" in metrics
        assert "loss" in metrics
        assert 0.0 <= metrics["accuracy"] <= 1.0

    def test_anomaly_detector_client(self):
        np.random.seed(42)
        model = AnomalyDetector(input_dim=8, latent_dim=4)
        X = np.random.rand(50, 8)

        client = FLClient(model, X)
        delta = client.train_round(model.get_params(), epochs=5, lr=0.01)
        assert set(delta.keys()) == {"W_enc", "b_enc", "W_dec", "b_dec"}


# ══════════════════════════════════════════════════════════════════════════════
# Full FL round test
# ══════════════════════════════════════════════════════════════════════════════

class TestFullFLRound:
    def test_three_clients_improve(self):
        """3 clients train locally, aggregate with fedavg, verify improvement."""
        np.random.seed(42)
        input_dim, hidden_dim = 8, 4

        # Generate shared test data
        X_test = np.random.randn(100, input_dim)
        y_test = (X_test[:, 0] + X_test[:, 1] > 0).astype(float)

        # Create initial model
        global_model = MalwareClassifier(input_dim=input_dim, hidden_dim=hidden_dim)
        global_params = global_model.get_params()

        # Evaluate before training
        initial_preds = global_model.predict(X_test)
        initial_acc = np.mean(initial_preds == y_test)

        # Create 3 clients with different local data
        clients = []
        for i in range(3):
            X_local = np.random.randn(100, input_dim)
            y_local = (X_local[:, 0] + X_local[:, 1] > 0).astype(float)
            model = MalwareClassifier(input_dim=input_dim, hidden_dim=hidden_dim)
            clients.append(FLClient(model, (X_local, y_local)))

        # Run 5 FL rounds
        for round_num in range(5):
            deltas = []
            weights = []
            for client in clients:
                delta = client.train_round(global_params, epochs=3, lr=0.05)
                deltas.append(delta)
                weights.append(client.n_samples)

            # Aggregate
            avg_delta = fedavg(deltas, weights=weights)

            # Apply to global model
            global_params = {
                k: global_params[k] + avg_delta[k]
                for k in global_params
            }

        # Evaluate after training
        global_model.set_params(global_params)
        final_preds = global_model.predict(X_test)
        final_acc = np.mean(final_preds == y_test)

        assert final_acc > initial_acc, (
            f"FL training should improve accuracy: {initial_acc:.2f} -> {final_acc:.2f}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Protocol serialization tests
# ══════════════════════════════════════════════════════════════════════════════

class TestProtocol:
    def test_ndarray_roundtrip(self):
        arr = np.random.randn(3, 4).astype(np.float64)
        encoded = ndarray_to_b64(arr)
        decoded = b64_to_ndarray(encoded)
        np.testing.assert_array_equal(arr, decoded)

    def test_params_roundtrip(self):
        params = {"W": np.random.randn(4, 4), "b": np.random.randn(4)}
        serialized = serialize_params(params)
        restored = deserialize_params(serialized)
        for k in params:
            np.testing.assert_array_equal(params[k], restored[k])

    def test_fl_session_model(self):
        session = FLSession(
            session_id="test-123",
            model_type="malware",
            round_num=0,
            max_rounds=10,
            min_clients=2,
            aggregation="fedavg",
        )
        assert session.state == FLRoundState.WAITING_FOR_CLIENTS
        data = session.model_dump()
        restored = FLSession(**data)
        assert restored.session_id == "test-123"

    def test_fl_update_model(self):
        params = serialize_params({"W": np.ones((2, 2))})
        update = FLUpdate(
            session_id="s1",
            client_id="c1",
            round_num=0,
            params=params,
            metrics={"loss": 0.5},
            n_samples=100,
        )
        data = update.model_dump()
        restored = FLUpdate(**data)
        assert restored.n_samples == 100

    def test_fl_round_result_model(self):
        result = FLRoundResult(
            session_id="s1",
            round_num=0,
            global_params={},
            aggregation_method="fedavg",
            n_contributors=3,
            aggregate_metrics={"loss": 0.3},
        )
        assert result.poisoning_flags == []
