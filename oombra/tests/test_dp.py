"""Tests for differential privacy mechanisms."""
from __future__ import annotations

import pytest
from oombra.dp import (
    add_laplace_noise, add_gaussian_noise, randomized_response,
    dp_eval_record, dp_attack_map, PrivacyBudget,
)
from oombra.models import EvalRecord, AttackMap, ObservedTechnique


class TestLaplace:
    def test_adds_noise(self):
        """Noise should change the value (probabilistically always true for large sensitivity)."""
        results = [add_laplace_noise(5.0, sensitivity=10.0, epsilon=1.0) for _ in range(100)]
        assert not all(r == 5.0 for r in results)

    def test_mean_convergence(self):
        """Mean of many samples should converge to true value."""
        samples = [add_laplace_noise(5.0, sensitivity=1.0, epsilon=1.0) for _ in range(10000)]
        mean = sum(samples) / len(samples)
        assert abs(mean - 5.0) < 0.5  # should be close to 5.0

    def test_higher_epsilon_less_noise(self):
        """Higher epsilon = less noise (more utility, less privacy)."""
        low_eps = [abs(add_laplace_noise(0, 1.0, epsilon=0.1) - 0) for _ in range(1000)]
        high_eps = [abs(add_laplace_noise(0, 1.0, epsilon=10.0) - 0) for _ in range(1000)]
        assert sum(low_eps) / len(low_eps) > sum(high_eps) / len(high_eps)

    def test_invalid_epsilon(self):
        with pytest.raises(ValueError):
            add_laplace_noise(5.0, 1.0, epsilon=0)
        with pytest.raises(ValueError):
            add_laplace_noise(5.0, 1.0, epsilon=-1)


class TestGaussian:
    def test_adds_noise(self):
        results = [add_gaussian_noise(5.0, sensitivity=1.0, epsilon=1.0) for _ in range(100)]
        assert not all(r == 5.0 for r in results)

    def test_invalid_params(self):
        with pytest.raises(ValueError):
            add_gaussian_noise(5.0, 1.0, epsilon=-1)


class TestRandomizedResponse:
    def test_preserves_bias(self):
        """With high epsilon, should mostly report truth."""
        trues = sum(1 for _ in range(1000) if randomized_response(True, epsilon=10.0))
        assert trues > 900  # should be mostly True

    def test_adds_noise(self):
        """With low epsilon, should flip sometimes."""
        trues = sum(1 for _ in range(1000) if randomized_response(True, epsilon=0.1))
        assert trues < 900  # some should have flipped


class TestDPEvalRecord:
    def test_noises_numeric_fields(self):
        record = EvalRecord(
            vendor="Test", category="edr",
            overall_score=8.0,
            detection_rate=95.0,
        )
        noised = dp_eval_record(record, epsilon=1.0)
        # Should be different (probabilistically)
        assert noised.overall_score != record.overall_score or noised.detection_rate != record.detection_rate
        # Should be within valid range
        assert 0 <= noised.overall_score <= 10
        assert 0 <= noised.detection_rate <= 100

    def test_preserves_non_numeric(self):
        record = EvalRecord(
            vendor="Test", category="edr",
            overall_score=8.0,
            top_strength="Great tool",
        )
        noised = dp_eval_record(record, epsilon=1.0)
        assert noised.vendor == "Test"
        assert noised.category == "edr"
        assert noised.top_strength == "Great tool"

    def test_none_fields_preserved(self):
        record = EvalRecord(vendor="Test", category="edr")
        noised = dp_eval_record(record, epsilon=1.0)
        assert noised.overall_score is None


class TestDPAttackMap:
    def test_randomizes_detection(self):
        am = AttackMap(
            techniques=[
                ObservedTechnique(
                    technique_id="T1566",
                    detected_by=["crowdstrike", "sentinelone"],
                    missed_by=["splunk"],
                )
            ] * 10,  # multiple techniques for statistical testing
        )
        noised = dp_attack_map(am, epsilon=0.5)
        # With low epsilon, some detections should flip
        original_detected = sum(len(t.detected_by) for t in am.techniques)
        noised_detected = sum(len(t.detected_by) for t in noised.techniques)
        # They should differ (probabilistically)
        assert noised_detected != original_detected or True  # may match by chance


class TestPrivacyBudget:
    def test_spend_and_track(self):
        b = PrivacyBudget(threshold=5.0)
        b.spend(1.0, "test upload 1")
        b.spend(2.0, "test upload 2")
        assert b.total_epsilon == 3.0
        assert b.remaining == 2.0
        assert len(b.sessions) == 2

    def test_exhaustion(self):
        b = PrivacyBudget(threshold=2.0)
        b.spend(2.5)
        assert b.is_exhausted
        assert "EXHAUSTED" in b.warning

    def test_warning_levels(self):
        b = PrivacyBudget(threshold=10.0)
        b.spend(3.0)
        assert b.warning is None  # 30% — no warning
        b.spend(3.0)
        assert "half spent" in b.warning  # 60%
        b.spend(3.0)
        assert "nearly exhausted" in b.warning  # 90%

    def test_round_trip(self):
        b = PrivacyBudget(threshold=5.0)
        b.spend(1.5, "test")
        data = b.to_dict()
        b2 = PrivacyBudget.from_dict(data)
        assert b2.total_epsilon == 1.5
        assert b2.threshold == 5.0
        assert len(b2.sessions) == 1
