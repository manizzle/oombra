"""Tests for secure aggregation."""
from __future__ import annotations

import pytest
from nur.secagg import (
    split, aggregate, prepare_shares,
    shamir_split, shamir_reconstruct,
    SecAggSession,
)


class TestAdditiveSplitting:
    def test_shares_sum_to_value(self):
        for val in [0.0, 1.0, -5.5, 100.0, 0.001]:
            shares = split(val, 3)
            assert len(shares) == 3
            assert abs(sum(shares) - val) < 1e-9

    def test_individual_shares_reveal_nothing(self):
        """Each share should be random, not close to the original value."""
        shares = split(5.0, 3)
        # At least one share should be far from 5.0
        assert any(abs(s - 5.0) > 0.1 for s in shares)

    def test_minimum_parties(self):
        with pytest.raises(ValueError):
            split(5.0, 1)


class TestAggregate:
    def test_three_parties(self):
        """Three parties with values 10, 20, 30 should aggregate to 60."""
        values = [10.0, 20.0, 30.0]
        n_parties = 3

        # Each party splits their value
        party_shares = [split(v, n_parties) for v in values]

        # Transpose: each party collects their column
        received = [[party_shares[p][i] for p in range(n_parties)] for i in range(n_parties)]

        # Each party sums their received shares
        party_sums = [[sum(received[i])] for i in range(n_parties)]

        # Coordinator aggregates
        result = aggregate(party_sums)
        assert abs(result[0] - 60.0) < 1e-6

    def test_multi_field(self):
        """Multiple fields aggregated simultaneously."""
        # Party 0: [10, 20], Party 1: [30, 40]
        all_shares = [[10.0, 20.0], [30.0, 40.0]]
        result = aggregate(all_shares)
        assert abs(result[0] - 40.0) < 1e-10
        assert abs(result[1] - 60.0) < 1e-10


class TestPrepareShares:
    def test_share_vectors(self):
        values = [10.0, 20.0, 30.0]
        vectors = prepare_shares(values, n_parties=3)
        assert len(vectors) == 3
        # Each vector has 3 fields
        for v in vectors:
            assert len(v) == 3
        # Sum across parties for each field should equal original
        for f in range(3):
            total = sum(vectors[p][f] for p in range(3))
            assert abs(total - values[f]) < 1e-9


class TestShamir:
    def test_basic_split_reconstruct(self):
        secret = 42
        shares = shamir_split(secret, n_parties=5, threshold=3)
        assert len(shares) == 5
        # Any 3 shares should reconstruct
        recovered = shamir_reconstruct(shares[:3])
        assert recovered == secret

    def test_different_share_subsets(self):
        secret = 12345
        shares = shamir_split(secret, n_parties=5, threshold=3)
        # Different subsets of 3 all work
        assert shamir_reconstruct(shares[:3]) == secret
        assert shamir_reconstruct(shares[1:4]) == secret
        assert shamir_reconstruct(shares[2:5]) == secret

    def test_threshold_validation(self):
        with pytest.raises(ValueError):
            shamir_split(42, n_parties=3, threshold=4)
        with pytest.raises(ValueError):
            shamir_split(42, n_parties=3, threshold=1)


class TestSecAggSession:
    def test_full_flow(self):
        session = SecAggSession(
            session_id="test-1",
            n_parties=3,
            field_names=["score", "detection_rate"],
        )

        # Enroll 3 parties
        assert not session.enroll("alice")
        assert not session.enroll("bob")
        assert session.enroll("charlie")

        # Each party submits shares (in real protocol, these are split)
        # For testing, we simulate: values are [8.0, 95.0], [7.5, 90.0], [9.0, 98.0]
        # Each party sends their share of the aggregate
        session.submit_shares("alice", [8.0, 95.0])
        session.submit_shares("bob", [7.5, 90.0])
        assert session.submit_shares("charlie", [9.0, 98.0])

        # Compute result
        result = session.compute_result()
        assert abs(result[0] - 24.5) < 1e-10  # sum of scores
        assert abs(result[1] - 283.0) < 1e-10  # sum of detection rates

    def test_unenrolled_party_rejected(self):
        session = SecAggSession(session_id="test-2", n_parties=2)
        with pytest.raises(ValueError):
            session.submit_shares("unknown", [1.0])
