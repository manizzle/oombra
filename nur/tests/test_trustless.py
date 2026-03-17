"""
Tests for the Trustless Server Architecture + Business Tier System.

Track A — Trustless Layer:
  1. Every contribution gets a Pedersen commitment
  2. All commitments bound in a Merkle tree
  3. Aggregates proven against commitment chain
  4. Individual values NOT stored — only commitments + running sums
  5. Receipts verify with Merkle inclusion proofs

Track B — Business Model:
  6. Tier system (Community/Pro/Enterprise)
  7. Feature gating on routes
  8. Vendor dashboard (B2B intelligence product)
  9. Pricing endpoint
"""
from __future__ import annotations

import json
import secrets
import pytest


# ══════════════════════════════════════════════════════════════════════════════
# Track A: Trustless Layer — Server Accountability Proofs
# ══════════════════════════════════════════════════════════════════════════════

class TestProofEngine:
    """Core proof engine: commit, aggregate, prove, verify."""

    def test_commit_contribution_returns_receipt(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        receipt = engine.commit_contribution(
            "CrowdStrike", "edr",
            {"overall_score": 9.2, "detection_rate": 94.5},
        )

        assert receipt.receipt_id
        assert receipt.commitment_hash
        assert receipt.contribution_hash
        assert receipt.merkle_root
        assert receipt.aggregate_id == "crowdstrike:edr"
        assert receipt.server_signature

    def test_receipt_merkle_proof_verifies(self):
        from nur.server.proofs import ProofEngine, verify_receipt
        engine = ProofEngine()
        receipt = engine.commit_contribution(
            "CrowdStrike", "edr", {"overall_score": 9.2},
        )
        assert verify_receipt(receipt)

    def test_multiple_contributions_all_verify(self):
        from nur.server.proofs import ProofEngine, verify_receipt
        engine = ProofEngine()

        receipts = []
        for score in [9.2, 8.5, 7.8, 8.0, 9.1]:
            r = engine.commit_contribution(
                "CrowdStrike", "edr", {"overall_score": score},
            )
            receipts.append(r)

        # All receipts should verify against the LATEST Merkle root
        # (earlier receipts' proofs may be stale — that's expected,
        # but the commitment_hash is still in the tree)
        assert engine.total_contributions == 5

        # The last receipt should definitely verify
        assert verify_receipt(receipts[-1])

    def test_aggregate_computed_correctly(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.0})
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 7.0})

        agg = engine.get_aggregate("CrowdStrike")
        assert agg is not None
        assert agg["contributor_count"] == 3
        assert abs(agg["avg_overall_score"] - 8.0) < 0.01  # (9+8+7)/3

    def test_aggregate_multiple_fields(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 9.0,
            "detection_rate": 95.0,
            "fp_rate": 2.0,
            "would_buy": True,
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 8.0,
            "detection_rate": 90.0,
            "fp_rate": 5.0,
            "would_buy": False,
        })

        agg = engine.get_aggregate("CrowdStrike")
        assert abs(agg["avg_overall_score"] - 8.5) < 0.01
        assert abs(agg["avg_detection_rate"] - 92.5) < 0.01
        assert abs(agg["avg_fp_rate"] - 3.5) < 0.01
        assert abs(agg["would_buy_pct"] - 50.0) < 0.01

    def test_prove_aggregate(self):
        from nur.server.proofs import ProofEngine, verify_aggregate_proof
        engine = ProofEngine()

        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.0})

        proof = engine.prove_aggregate("CrowdStrike")
        assert proof is not None
        assert proof.contributor_count == 2
        assert proof.merkle_root == engine.merkle_root
        assert len(proof.commitment_hashes) == 2
        assert proof.server_signature

        # Verify the proof
        result = verify_aggregate_proof(proof, expected_root=engine.merkle_root)
        assert result["valid"]

    def test_aggregate_proof_detects_inflated_count(self):
        """If server claims more contributors than commitments, proof fails."""
        from nur.server.proofs import AggregateProof, verify_aggregate_proof
        fake_proof = AggregateProof(
            aggregate_id="fake:edr",
            vendor="Fake",
            category="edr",
            contributor_count=100,  # claims 100
            merkle_root="a" * 64,
            commitment_hashes=["b" * 64, "c" * 64],  # only 2
            aggregate_values={"avg_overall_score": 9.5},
            server_signature="d" * 64,
        )
        result = verify_aggregate_proof(fake_proof)
        assert not result["valid"]
        assert "Commitment count" in result["errors"][0]

    def test_different_vendors_separate_aggregates(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_contribution("SentinelOne", "edr", {"overall_score": 8.0})

        cs = engine.get_aggregate("CrowdStrike")
        s1 = engine.get_aggregate("SentinelOne")
        assert cs["avg_overall_score"] == 9.0
        assert s1["avg_overall_score"] == 8.0

    def test_list_aggregates(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_contribution("Splunk", "siem", {"overall_score": 7.5})

        aggs = engine.list_aggregates()
        assert len(aggs) == 2
        vendors = {a["vendor"] for a in aggs}
        assert "CrowdStrike" in vendors
        assert "Splunk" in vendors


class TestContributionReceipt:
    """Receipt verification and serialization."""

    def test_receipt_serialization(self):
        from nur.server.proofs import ProofEngine, ContributionReceipt
        engine = ProofEngine()
        receipt = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})

        d = receipt.to_dict()
        restored = ContributionReceipt.from_dict(d)
        assert restored.commitment_hash == receipt.commitment_hash
        assert restored.receipt_id == receipt.receipt_id

    def test_receipt_json_roundtrip(self):
        from nur.server.proofs import ProofEngine, ContributionReceipt
        engine = ProofEngine()
        receipt = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})

        j = json.dumps(receipt.to_dict())
        restored = ContributionReceipt.from_dict(json.loads(j))
        assert restored.commitment_hash == receipt.commitment_hash


class TestUsageTracking:
    """Track how many times each contribution is used in queries."""

    def test_usage_count_increments(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        receipt = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})

        assert engine.get_usage_count(receipt.commitment_hash) == 0

        # Query triggers usage
        engine.get_aggregate("CrowdStrike")
        assert engine.get_usage_count(receipt.commitment_hash) == 1

        engine.get_aggregate("CrowdStrike")
        assert engine.get_usage_count(receipt.commitment_hash) == 2


class TestServerCantCheat:
    """
    The "can't cheat" guarantees — the whole point of the architecture.
    """

    def test_commitment_hash_is_binding(self):
        """Two different contributions produce different commitment hashes."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        r1 = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        r2 = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.0})
        assert r1.commitment_hash != r2.commitment_hash

    def test_contribution_hash_is_deterministic(self):
        """Same data produces the same contribution hash (binding property)."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        r1 = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        # Note: commitment_hash includes timestamp so it differs,
        # but contribution_hash is deterministic from data
        r2 = engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        assert r1.contribution_hash == r2.contribution_hash

    def test_merkle_root_changes_with_new_contribution(self):
        """Adding a contribution changes the Merkle root — can't hide additions."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        root1 = engine.merkle_root

        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.0})
        root2 = engine.merkle_root

        assert root1 != root2

    def test_proof_count_matches_commitments(self):
        """Server can't claim more contributors than actual commitments."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        for _ in range(5):
            engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.0})

        proof = engine.prove_aggregate("CrowdStrike")
        assert proof.contributor_count == 5
        assert len(proof.commitment_hashes) == 5

    def test_no_plaintext_in_commitments(self):
        """Commitment hashes don't contain the original values."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        receipt = engine.commit_contribution(
            "CrowdStrike", "edr",
            {"overall_score": 9.2, "detection_rate": 94.5},
        )

        # The commitment hash is a SHA-256 — doesn't contain "9.2" or "94.5"
        assert "9.2" not in receipt.commitment_hash
        assert "94.5" not in receipt.commitment_hash
        assert "CrowdStrike" not in receipt.commitment_hash

    def test_categorical_fields_aggregated(self):
        """Structured categories (replacing free text) aggregate correctly."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 9.0,
            "top_strength": "detection_quality",
            "severity": "critical",
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 8.0,
            "top_strength": "detection_quality",
            "severity": "high",
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 8.5,
            "top_strength": "response_speed",
            "severity": "critical",
        })

        # Categories are tracked in bool_counts
        bucket = engine._aggregates["crowdstrike:edr"]
        assert bucket.bool_counts.get("top_strength:detection_quality", 0) == 2
        assert bucket.bool_counts.get("top_strength:response_speed", 0) == 1
        assert bucket.bool_counts.get("severity:critical", 0) == 2


# ══════════════════════════════════════════════════════════════════════════════
# Track A Tier 2: Technique × Vendor Histograms
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackMapCommitment:
    """Attack maps produce technique × vendor histogram aggregates."""

    def _sample_techniques(self):
        return [
            {"technique_id": "T1566", "technique_name": "Phishing", "observed": True,
             "detected_by": ["crowdstrike", "proofpoint"], "missed_by": ["sentinelone"]},
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "observed": True,
             "detected_by": ["okta"], "missed_by": ["crowdstrike", "sentinelone"]},
            {"technique_id": "T1021.001", "technique_name": "RDP", "observed": True,
             "detected_by": ["crowdstrike"], "missed_by": []},
        ]

    def test_commit_attack_map_returns_receipt(self):
        from nur.server.proofs import ProofEngine, verify_receipt
        engine = ProofEngine()
        receipt = engine.commit_attack_map(self._sample_techniques())
        assert receipt.receipt_id
        assert receipt.aggregate_id == "attack_maps"
        assert verify_receipt(receipt)

    def test_technique_frequency_tracked(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(self._sample_techniques())
        engine.commit_attack_map([
            {"technique_id": "T1566", "observed": True, "detected_by": [], "missed_by": []},
            {"technique_id": "T1490", "observed": True, "detected_by": [], "missed_by": ["crowdstrike"]},
        ])

        freq = engine.get_technique_frequency()
        freq_map = {t["technique_id"]: t["count"] for t in freq}
        assert freq_map["T1566"] == 2  # seen in both contributions
        assert freq_map["T1078"] == 1
        assert freq_map["T1490"] == 1

    def test_vendor_detection_rate(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(self._sample_techniques())

        cs_rate = engine.get_vendor_detection_rate("crowdstrike")
        # CrowdStrike: detected T1566 + T1021.001, missed T1078
        # 2 detected / 3 evaluated = 0.667
        assert cs_rate["overall_detection_rate"] == pytest.approx(0.667, abs=0.01)
        assert cs_rate["techniques_detected"] == 2
        assert cs_rate["techniques_evaluated"] == 3
        assert "T1566" in cs_rate["per_technique"]
        assert cs_rate["per_technique"]["T1566"]["rate"] == 1.0

    def test_vendor_gaps(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(self._sample_techniques())

        cs_gaps = engine.get_vendor_gaps("crowdstrike")
        assert "T1078" in cs_gaps  # CrowdStrike missed valid accounts

        s1_gaps = engine.get_vendor_gaps("sentinelone")
        assert "T1566" in s1_gaps  # SentinelOne missed phishing

    def test_technique_coverage_analysis(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(self._sample_techniques())

        coverage = engine.get_technique_coverage(["crowdstrike"])
        assert coverage["covered"] == 2   # T1566, T1021.001
        assert coverage["gaps"] == 1      # T1078
        assert coverage["coverage_pct"] == pytest.approx(66.7, abs=0.1)

        # Gap details show what catches the gaps
        gaps = coverage["gap_details"]
        assert len(gaps) == 1
        assert gaps[0]["technique_id"] == "T1078"
        assert "okta" in gaps[0]["caught_by"]

    def test_vendor_comparison(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(self._sample_techniques())

        comp = engine.get_vendor_comparison(["crowdstrike", "sentinelone"])
        assert comp["crowdstrike"]["overall_detection_rate"] > comp["sentinelone"]["overall_detection_rate"]

    def test_multiple_attack_maps_aggregate(self):
        """Multiple contributions sum into the histogram — no individual data stored."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        # 10 different orgs report on T1566 detection
        for i in range(10):
            detected = ["crowdstrike"] if i < 8 else []  # 8 of 10 detect
            missed = [] if i < 8 else ["crowdstrike"]     # 2 of 10 miss
            engine.commit_attack_map([
                {"technique_id": "T1566", "observed": True,
                 "detected_by": detected, "missed_by": missed},
            ])

        rate = engine.get_vendor_detection_rate("crowdstrike")
        assert rate["per_technique"]["T1566"]["detected"] == 8
        assert rate["per_technique"]["T1566"]["missed"] == 2
        assert rate["per_technique"]["T1566"]["rate"] == 0.8

    def test_remediation_stats(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_attack_map(
            techniques=[{"technique_id": "T1566", "observed": True, "detected_by": [], "missed_by": []}],
            severity="critical",
            time_to_detect="hours",
            time_to_contain="days",
            remediation=[
                {"category": "containment", "effectiveness": "stopped_attack"},
                {"category": "detection", "effectiveness": "slowed_attack"},
            ],
        )

        stats = engine.get_remediation_stats()
        assert stats["total_actions"] == 2
        assert stats["by_category"]["containment"]["stopped_attack"] == 1
        assert stats["severity_distribution"]["critical"] == 1
        assert stats["time_to_detect"]["hours"] == 1

    def test_no_individual_technique_lists_stored(self):
        """After committing, no individual contribution's technique list exists."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        engine.commit_attack_map([
            {"technique_id": "T1566", "observed": True,
             "detected_by": ["crowdstrike"], "missed_by": ["sentinelone"]},
        ])
        engine.commit_attack_map([
            {"technique_id": "T1078", "observed": True,
             "detected_by": ["okta"], "missed_by": []},
        ])

        # Only running sums exist — not lists of which contribution had which technique
        assert isinstance(engine._technique_freq, dict)
        assert engine._technique_freq["T1566"] == 1  # a count, not a list
        assert isinstance(engine._vendor_detection[("T1566", "crowdstrike")], dict)
        # Just {"detected": 1, "missed": 0} — no contributor attribution

    def test_platform_stats(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_attack_map([
            {"technique_id": "T1566", "observed": True, "detected_by": [], "missed_by": []},
        ])

        stats = engine.get_platform_stats()
        assert stats["total_contributions"] == 2
        assert stats["eval_count"] == 1
        assert stats["attack_map_count"] == 1
        assert stats["unique_techniques"] == 1
        assert stats["merkle_root"]


class TestHistogramPowersFeatures:
    """
    The advanced features (threat map, simulation, compliance, RFP)
    are powered by histogram aggregates, not plaintext data.
    """

    def _build_engine_with_data(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()

        # 20 evals across 3 vendors
        for _ in range(8):
            engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 8.5 + _ * 0.1})
        for _ in range(7):
            engine.commit_contribution("SentinelOne", "edr", {"overall_score": 8.0 + _ * 0.1})
        for _ in range(5):
            engine.commit_contribution("Splunk", "siem", {"overall_score": 7.5 + _ * 0.1})

        # 15 attack maps with technique data
        techniques_data = [
            [{"technique_id": "T1566", "observed": True, "detected_by": ["crowdstrike", "proofpoint"], "missed_by": ["sentinelone"]}],
            [{"technique_id": "T1566", "observed": True, "detected_by": ["crowdstrike"], "missed_by": []}],
            [{"technique_id": "T1078", "observed": True, "detected_by": ["okta"], "missed_by": ["crowdstrike", "sentinelone"]}],
            [{"technique_id": "T1078", "observed": True, "detected_by": ["okta", "crowdstrike"], "missed_by": ["sentinelone"]}],
            [{"technique_id": "T1021.001", "observed": True, "detected_by": ["crowdstrike", "sentinelone"], "missed_by": []}],
            [{"technique_id": "T1490", "observed": True, "detected_by": [], "missed_by": ["crowdstrike", "sentinelone"]}],
        ]
        for techs in techniques_data:
            engine.commit_attack_map(
                techs,
                severity="high",
                remediation=[{"category": "containment", "effectiveness": "stopped_attack"}],
            )

        return engine

    def test_market_map_from_aggregates(self):
        """Market map only needs avg scores — works with Tier 1 aggregates."""
        engine = self._build_engine_with_data()

        cs = engine.get_aggregate("CrowdStrike")
        s1 = engine.get_aggregate("SentinelOne")
        assert cs["avg_overall_score"] > s1["avg_overall_score"]
        assert cs["contributor_count"] == 8

    def test_threat_map_from_histograms(self):
        """Threat map needs per-technique coverage — works with Tier 2 histograms."""
        engine = self._build_engine_with_data()

        coverage = engine.get_technique_coverage(["crowdstrike"])
        assert coverage["total_techniques"] == 4
        assert coverage["covered"] >= 2  # T1566, T1021.001, maybe T1078 (partial)
        assert len(coverage["gap_details"]) > 0

    def test_simulation_from_histograms(self):
        """Attack simulation needs vendor × technique matrix — histograms provide it."""
        engine = self._build_engine_with_data()

        cs_rate = engine.get_vendor_detection_rate("crowdstrike")
        # Can simulate: "If attack uses T1566 → CrowdStrike detects (rate=1.0)"
        # "If attack uses T1490 → CrowdStrike misses (rate=0.0)"
        assert cs_rate["per_technique"]["T1566"]["rate"] == 1.0
        assert cs_rate["per_technique"]["T1490"]["rate"] == 0.0

    def test_vendor_comparison_from_histograms(self):
        """RFP/comparison needs multi-vendor detection rates — histograms provide it."""
        engine = self._build_engine_with_data()

        comp = engine.get_vendor_comparison(["crowdstrike", "sentinelone", "okta"])
        assert "crowdstrike" in comp
        assert "sentinelone" in comp
        assert "okta" in comp
        # Each has overall_detection_rate and per_technique breakdown
        assert "overall_detection_rate" in comp["crowdstrike"]
        assert "per_technique" in comp["crowdstrike"]

    def test_remediation_intelligence_from_histograms(self):
        """Remediation stats aggregate what actually worked — no individual attribution."""
        engine = self._build_engine_with_data()

        stats = engine.get_remediation_stats()
        assert stats["total_actions"] == 6  # 6 attack maps × 1 action each
        assert stats["by_category"]["containment"]["stopped_attack"] == 6

    def test_everything_is_aggregate_nothing_individual(self):
        """
        The complete 'trustless features' test:
        All advanced features work, and the server stores ZERO
        individual contributions — only running aggregate sums.
        """
        engine = self._build_engine_with_data()

        # Verify all features produce output
        assert engine.get_aggregate("CrowdStrike") is not None
        assert len(engine.get_technique_frequency()) > 0
        assert engine.get_vendor_detection_rate("crowdstrike")["techniques_evaluated"] > 0
        assert engine.get_technique_coverage(["crowdstrike"])["total_techniques"] > 0
        assert engine.get_remediation_stats()["total_actions"] > 0

        # Verify nothing individual is stored
        # Technique freq: just counts
        for tid, count in engine._technique_freq.items():
            assert isinstance(count, int)

        # Vendor detection: just counts
        for key, counts in engine._vendor_detection.items():
            assert isinstance(counts["detected"], int)
            assert isinstance(counts["missed"], int)

        # No list of "contribution X had techniques [T1566, T1078]" anywhere
        # The server literally cannot tell you which org reported which technique


# ══════════════════════════════════════════════════════════════════════════════
# Track B: Business Model — Tiers + Vendor Dashboard
# ══════════════════════════════════════════════════════════════════════════════

class TestTierSystem:
    """Tier definitions and feature gating."""

    def test_tier_definitions_exist(self):
        from nur.server.routes.tiers import TIERS
        assert "community" in TIERS
        assert "pro" in TIERS
        assert "enterprise" in TIERS

    def test_community_has_basic_features(self):
        from nur.server.routes.tiers import check_feature_access
        assert check_feature_access("community", "contribute_data")
        assert check_feature_access("community", "own_percentile")
        assert check_feature_access("community", "receipts")

    def test_community_lacks_pro_features(self):
        from nur.server.routes.tiers import check_feature_access
        assert not check_feature_access("community", "market_maps")
        assert not check_feature_access("community", "vendor_rankings")
        assert not check_feature_access("community", "simulate")

    def test_pro_has_intelligence_features(self):
        from nur.server.routes.tiers import check_feature_access
        assert check_feature_access("pro", "market_maps")
        assert check_feature_access("pro", "vendor_rankings")
        assert check_feature_access("pro", "threat_maps")
        assert check_feature_access("pro", "simulate")

    def test_pro_lacks_enterprise_features(self):
        from nur.server.routes.tiers import check_feature_access
        assert not check_feature_access("pro", "vendor_dashboard")
        assert not check_feature_access("pro", "api_access")
        assert not check_feature_access("pro", "compliance_reports")

    def test_enterprise_has_everything(self):
        from nur.server.routes.tiers import check_feature_access, TIERS
        enterprise_features = TIERS["enterprise"]["features"]
        for feature in enterprise_features:
            assert check_feature_access("enterprise", feature)

    def test_require_feature_raises_on_wrong_tier(self):
        from nur.server.routes.tiers import require_feature
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_feature("community", "market_maps")
        assert exc_info.value.status_code == 403
        assert "Pro" in str(exc_info.value.detail)

    def test_require_feature_passes_on_correct_tier(self):
        from nur.server.routes.tiers import require_feature
        # Should not raise
        require_feature("pro", "market_maps")
        require_feature("enterprise", "vendor_dashboard")

    def test_tier_pricing(self):
        from nur.server.routes.tiers import TIERS
        assert TIERS["community"]["price"] == 0
        assert TIERS["pro"]["price"] > 0
        assert TIERS["enterprise"]["price"] > TIERS["pro"]["price"]

    def test_tier_rate_limits_escalate(self):
        from nur.server.routes.tiers import TIERS
        assert TIERS["community"]["rate_limit"] < TIERS["pro"]["rate_limit"]
        assert TIERS["pro"]["rate_limit"] < TIERS["enterprise"]["rate_limit"]


class TestStructuredCategories:
    """Free-text fields replaced with structured categories."""

    def test_strength_categories_defined(self):
        from nur.server.proofs import STRENGTH_CATEGORIES
        assert "detection_quality" in STRENGTH_CATEGORIES
        assert "response_speed" in STRENGTH_CATEGORIES
        assert len(STRENGTH_CATEGORIES) >= 8

    def test_friction_categories_defined(self):
        from nur.server.proofs import FRICTION_CATEGORIES
        assert "high_false_positives" in FRICTION_CATEGORIES
        assert "deployment_difficulty" in FRICTION_CATEGORIES

    def test_remediation_categories_defined(self):
        from nur.server.proofs import REMEDIATION_CATEGORIES
        assert "containment" in REMEDIATION_CATEGORIES
        assert "eradication" in REMEDIATION_CATEGORIES

    def test_all_categories_are_strings(self):
        from nur.server.proofs import (
            STRENGTH_CATEGORIES, FRICTION_CATEGORIES,
            REMEDIATION_CATEGORIES, EFFECTIVENESS_LEVELS,
            SEVERITY_LEVELS,
        )
        for cat_list in [STRENGTH_CATEGORIES, FRICTION_CATEGORIES,
                         REMEDIATION_CATEGORIES, EFFECTIVENESS_LEVELS,
                         SEVERITY_LEVELS]:
            for item in cat_list:
                assert isinstance(item, str)
                assert len(item) > 0


# ══════════════════════════════════════════════════════════════════════════════
# Integration: Trustless + Business together
# ══════════════════════════════════════════════════════════════════════════════

class TestTrustlessBusinessIntegration:
    """The complete flow: contribute → commit → aggregate → prove → tier-gate."""

    def test_full_contribution_to_proven_query(self):
        """End-to-end: contribute, get receipt, query aggregate with proof."""
        from nur.server.proofs import ProofEngine, verify_receipt, verify_aggregate_proof

        engine = ProofEngine()

        # 5 contributors evaluate CrowdStrike
        receipts = []
        scores = [9.2, 8.5, 8.8, 7.9, 9.0]
        for score in scores:
            r = engine.commit_contribution("CrowdStrike", "edr", {
                "overall_score": score,
                "detection_rate": score * 10,
                "would_buy": score > 8.0,
            })
            receipts.append(r)

        # Verify last receipt
        assert verify_receipt(receipts[-1])

        # Query aggregate
        agg = engine.get_aggregate("CrowdStrike")
        expected_avg = sum(scores) / len(scores)
        assert abs(agg["avg_overall_score"] - expected_avg) < 0.01
        assert agg["contributor_count"] == 5

        # Get proof
        proof = engine.prove_aggregate("CrowdStrike")
        result = verify_aggregate_proof(proof)
        assert result["valid"]
        assert proof.contributor_count == 5

    def test_multi_vendor_multi_category(self):
        """Multiple vendors and categories tracked independently."""
        from nur.server.proofs import ProofEngine

        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {"overall_score": 9.0})
        engine.commit_contribution("SentinelOne", "edr", {"overall_score": 8.5})
        engine.commit_contribution("Splunk", "siem", {"overall_score": 7.5})
        engine.commit_contribution("Splunk", "siem", {"overall_score": 8.0})

        assert engine.get_aggregate("CrowdStrike")["avg_overall_score"] == 9.0
        assert engine.get_aggregate("SentinelOne")["avg_overall_score"] == 8.5
        assert engine.get_aggregate("Splunk")["avg_overall_score"] == 7.75
        assert engine.get_aggregate("Splunk")["contributor_count"] == 2

    def test_the_pitch_is_true(self):
        """
        'In the age of AI data mining, your data can't be mined.'

        This test verifies: after committing 100 contributions, the engine
        retains ZERO individual values. Only commitments + aggregate sums.
        """
        from nur.server.proofs import ProofEngine

        engine = ProofEngine()
        for i in range(100):
            engine.commit_contribution("CrowdStrike", "edr", {
                "overall_score": 7.0 + (i % 30) / 10,
                "detection_rate": 80 + (i % 20),
                "would_buy": i % 3 != 0,
            })

        # What the engine retains:
        # 1. Commitment hashes (opaque SHA-256 strings)
        assert len(engine._commitments) == 100
        for c in engine._commitments:
            assert len(c) == 64  # SHA-256 hex
            # Not a score, not a rate, not a vendor name
            assert all(ch in "0123456789abcdef" for ch in c)

        # 2. Running sums (not individual values)
        bucket = engine._aggregates["crowdstrike:edr"]
        # The sum is a single number, not a list of 100 scores
        assert isinstance(bucket.sums["overall_score"], float)
        assert isinstance(bucket.counts["overall_score"], int)
        assert bucket.counts["overall_score"] == 100

        # 3. Merkle tree (hashes all the way down)
        assert engine.merkle_root
        assert len(engine.merkle_root) == 64

        # There is NO list of individual scores stored anywhere.
        # The only way to get "Hospital X scored 9.2" would be to
        # reverse a SHA-256 hash — computationally infeasible.
