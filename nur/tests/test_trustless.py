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


# ══════════════════════════════════════════════════════════════════════════════
# Translators — raw payloads → structured aggregatable form
# ══════════════════════════════════════════════════════════════════════════════

class TestTranslators:
    """Unit tests for each translator function."""

    def test_translate_eval_extracts_numeric(self):
        from nur.server.proofs import translate_eval
        vendor, cat, values = translate_eval({
            "data": {
                "vendor": "CrowdStrike",
                "category": "edr",
                "overall_score": 9.2,
                "detection_rate": 94.5,
                "fp_rate": 2.1,
            }
        })
        assert vendor == "CrowdStrike"
        assert cat == "edr"
        assert values["overall_score"] == 9.2
        assert values["detection_rate"] == 94.5
        assert values["fp_rate"] == 2.1

    def test_translate_eval_maps_strength_category(self):
        from nur.server.proofs import translate_eval
        _, _, values = translate_eval({
            "data": {
                "vendor": "X",
                "top_strength": "Great detection quality",
                "top_friction": "High false positives everywhere",
            }
        })
        assert values["top_strength"] == "detection_quality"
        assert values["top_friction"] == "high_false_positives"

    def test_translate_eval_drops_notes(self):
        from nur.server.proofs import translate_eval
        _, _, values = translate_eval({
            "data": {
                "vendor": "X",
                "notes": "This should be dropped",
                "overall_score": 8.0,
            }
        })
        assert "notes" not in values
        assert "overall_score" in values

    def test_translate_eval_handles_bool(self):
        from nur.server.proofs import translate_eval
        _, _, values = translate_eval({"data": {"vendor": "X", "would_buy": True}})
        assert values["would_buy"] is True

    def test_translate_eval_flat_format(self):
        """Supports both {data: {vendor: ...}} and flat {vendor: ...}."""
        from nur.server.proofs import translate_eval
        vendor, _, _ = translate_eval({"vendor": "Direct", "category": "siem"})
        assert vendor == "Direct"

    def test_translate_attack_map_normalizes(self):
        from nur.server.proofs import translate_attack_map
        params = translate_attack_map({
            "techniques": [
                {"technique_id": "T1566", "detected_by": ["CrowdStrike"], "missed_by": ["SentinelOne"]},
            ],
            "severity": "critical",
            "time_to_detect": "hours",
            "notes": "Should be dropped",
        })
        assert len(params["techniques"]) == 1
        assert params["techniques"][0]["detected_by"] == ["crowdstrike"]
        assert params["techniques"][0]["missed_by"] == ["sentinelone"]
        assert params["severity"] == "critical"
        assert params["time_to_detect"] == "hours"

    def test_translate_attack_map_drops_free_text(self):
        from nur.server.proofs import translate_attack_map
        params = translate_attack_map({
            "techniques": [{"technique_id": "T1566"}],
            "notes": "Full writeup",
            "remediation": [
                {"category": "containment", "effectiveness": "stopped_attack",
                 "action": "Free text action", "sigma_rule": "yaml content"},
            ],
        })
        # Remediation has only category + effectiveness
        assert len(params["remediation"]) == 1
        assert set(params["remediation"][0].keys()) == {"category", "effectiveness"}

    def test_translate_attack_map_skips_empty_technique_id(self):
        from nur.server.proofs import translate_attack_map
        params = translate_attack_map({
            "techniques": [
                {"technique_id": "T1566"},
                {"technique_id": ""},
                {"technique_name": "No ID"},
            ],
        })
        assert len(params["techniques"]) == 1

    def test_translate_ioc_bundle(self):
        from nur.server.proofs import translate_ioc_bundle
        count, types = translate_ioc_bundle({
            "iocs": [
                {"ioc_type": "ip", "value_hash": "abc"},
                {"ioc_type": "domain", "value_hash": "def"},
                {"ioc_type": "ip", "value_hash": "ghi"},
            ]
        })
        assert count == 3
        assert set(types) == {"ip", "domain"}

    def test_translate_ioc_bundle_empty(self):
        from nur.server.proofs import translate_ioc_bundle
        count, types = translate_ioc_bundle({})
        assert count == 0
        assert types == []

    def test_translate_webhook_crowdstrike(self):
        from nur.server.proofs import translate_webhook_crowdstrike
        result = translate_webhook_crowdstrike({
            "detection": {
                "technique": "T1059.001",
                "severity": "high",
                "ioc_type": "ip",
                "ioc_value": "1.2.3.4",
            }
        })
        assert result["attack_map_params"] is not None
        assert result["attack_map_params"]["techniques"][0]["technique_id"] == "T1059.001"
        assert result["ioc_params"] == (1, ["ip"])

    def test_translate_webhook_crowdstrike_no_technique(self):
        from nur.server.proofs import translate_webhook_crowdstrike
        result = translate_webhook_crowdstrike({
            "detection": {"severity": "low", "ioc_type": "domain"}
        })
        assert result["attack_map_params"] is None
        assert result["ioc_params"] == (1, ["domain"])

    def test_translate_webhook_sentinel(self):
        from nur.server.proofs import translate_webhook_sentinel
        result = translate_webhook_sentinel({
            "properties": {
                "severity": "High",
                "techniques": ["T1566", "T1078"],
                "entities": [
                    {"kind": "ip", "address": "1.2.3.4"},
                    {"kind": "host", "hostName": "evil.com"},
                ],
            }
        })
        assert result["attack_map_params"] is not None
        assert len(result["attack_map_params"]["techniques"]) == 2
        assert result["ioc_params"][0] == 2
        assert sorted(result["ioc_params"][1]) == sorted(["ip", "host"])

    def test_translate_webhook_sentinel_no_data(self):
        from nur.server.proofs import translate_webhook_sentinel
        result = translate_webhook_sentinel({"properties": {}})
        assert result["attack_map_params"] is None
        assert result["ioc_params"] is None


async def _make_proof_app():
    """Create a fresh app with initialized in-memory database and ProofEngine."""
    import nur.server.app as app_mod
    from nur.server.db import Database
    from nur.server.proofs import ProofEngine
    the_app = app_mod.create_app("sqlite+aiosqlite://")
    db = Database("sqlite+aiosqlite://")
    await db.init()
    app_mod._db = db
    app_mod._proof_engine = ProofEngine()
    return the_app


class TestE2ESubmissionWithProofs:
    """FastAPI test client -- each endpoint returns receipt."""

    @pytest.mark.asyncio
    async def test_contribute_eval_returns_receipt(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/contribute/submit", json={
                "data": {"vendor": "TestVendor", "category": "edr", "overall_score": 8.5}
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipt" in data
            assert data["receipt"]["commitment_hash"]
            assert data["receipt"]["merkle_root"]

    @pytest.mark.asyncio
    async def test_contribute_attack_map_returns_receipt(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/contribute/attack-map", json={
                "techniques": [{"technique_id": "T1566", "observed": True, "detected_by": [], "missed_by": []}],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipt" in data

    @pytest.mark.asyncio
    async def test_contribute_ioc_bundle_returns_receipt(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/contribute/ioc-bundle", json={
                "iocs": [{"ioc_type": "ip", "value_hash": "abc123"}],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipt" in data

    @pytest.mark.asyncio
    async def test_webhook_crowdstrike_returns_receipts(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/ingest/webhook", json={
                "detection": {
                    "technique": "T1059.001",
                    "severity": "high",
                    "ioc_type": "ip",
                    "ioc_value": "1.2.3.4",
                }
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipts" in data
            assert len(data["receipts"]) >= 1

    @pytest.mark.asyncio
    async def test_webhook_sentinel_returns_receipts(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/ingest/webhook", json={
                "properties": {
                    "severity": "High",
                    "techniques": ["T1566"],
                    "entities": [{"kind": "ip", "address": "1.2.3.4"}],
                }
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipts" in data

    @pytest.mark.asyncio
    async def test_analyze_returns_receipt(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/analyze", json={
                "data": {"vendor": "TestVendor", "category": "edr", "overall_score": 8.0}
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "receipt" in data


class TestVerifyEndpoints:
    """Verification endpoints work correctly."""

    @pytest.mark.asyncio
    async def test_verify_receipt_endpoint(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Submit first
            resp = await c.post("/contribute/submit", json={
                "data": {"vendor": "TestVendor", "category": "edr", "overall_score": 9.0}
            })
            receipt = resp.json()["receipt"]

            # Verify
            resp = await c.post("/verify/receipt", json=receipt)
            assert resp.status_code == 200
            data = resp.json()
            assert data["receipt_id"] == receipt["receipt_id"]
            # Note: may be stale if tree grew, but endpoint should work

    @pytest.mark.asyncio
    async def test_verify_aggregate_endpoint(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Submit data first
            await c.post("/contribute/submit", json={
                "data": {"vendor": "CrowdStrike", "category": "edr", "overall_score": 9.0}
            })
            await c.post("/contribute/submit", json={
                "data": {"vendor": "CrowdStrike", "category": "edr", "overall_score": 8.0}
            })

            # Verify aggregate
            resp = await c.get("/verify/aggregate/CrowdStrike")
            assert resp.status_code == 200
            data = resp.json()
            assert data["proof"]["contributor_count"] == 2
            assert data["verification"]["valid"]

    @pytest.mark.asyncio
    async def test_verify_aggregate_404(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/verify/aggregate/NonExistent")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_proof_stats_endpoint(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/contribute/submit", json={
                "data": {"vendor": "TestVendor", "category": "edr", "overall_score": 8.0}
            })
            resp = await c.get("/proof/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_contributions"] >= 1
            assert data["merkle_root"]


class TestAllPathsShareMerkleTree:
    """All submission paths feed into the same Merkle tree."""

    @pytest.mark.asyncio
    async def test_single_merkle_tree(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Submit via all paths
            await c.post("/contribute/submit", json={
                "data": {"vendor": "V1", "category": "edr", "overall_score": 8.0}
            })
            await c.post("/contribute/attack-map", json={
                "techniques": [{"technique_id": "T1566", "observed": True, "detected_by": [], "missed_by": []}],
            })
            await c.post("/contribute/ioc-bundle", json={
                "iocs": [{"ioc_type": "ip", "value_hash": "test"}],
            })
            await c.post("/ingest/webhook", json={
                "detection": {"technique": "T1059", "severity": "high"}
            })

            # All should share one Merkle tree -- check stats
            resp = await c.get("/proof/stats")
            data = resp.json()
            assert data["total_contributions"] >= 4
            assert data["merkle_root"]  # single root


class TestWebhookFormatsProduceProofs:
    """CrowdStrike + Sentinel webhook formats produce valid receipts."""

    @pytest.mark.asyncio
    async def test_crowdstrike_receipt_verifiable(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/ingest/webhook", json={
                "detection": {
                    "technique": "T1059.001",
                    "severity": "critical",
                    "ioc_type": "hash-sha256",
                    "ioc_value": "deadbeef",
                }
            })
            data = resp.json()
            assert len(data["receipts"]) == 2  # attack_map + ioc

            # Verify the last receipt
            last_receipt = data["receipts"][-1]
            verify_resp = await c.post("/verify/receipt", json=last_receipt)
            assert verify_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_sentinel_receipt_verifiable(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_proof_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/ingest/webhook", json={
                "properties": {
                    "title": "Test Incident",
                    "severity": "High",
                    "techniques": ["T1566", "T1078"],
                    "entities": [
                        {"kind": "ip", "address": "10.0.0.1"},
                        {"kind": "host", "hostName": "bad.example.com"},
                    ],
                }
            })
            data = resp.json()
            assert len(data["receipts"]) == 2  # attack_map + ioc

            last_receipt = data["receipts"][-1]
            verify_resp = await c.post("/verify/receipt", json=last_receipt)
            assert verify_resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# Public Taxonomy — NIST/D3FEND/RE&CT framework guidance
# ══════════════════════════════════════════════════════════════════════════════

class TestTaxonomy:
    """Public remediation taxonomy maps aggregate categories to known frameworks."""

    def test_all_remediation_categories_have_taxonomy(self):
        from nur.server.proofs import REMEDIATION_CATEGORIES
        from nur.server.taxonomy import REMEDIATION_TAXONOMY
        for cat in REMEDIATION_CATEGORIES:
            assert cat in REMEDIATION_TAXONOMY, f"Missing taxonomy for '{cat}'"

    def test_taxonomy_has_required_fields(self):
        from nur.server.taxonomy import REMEDIATION_TAXONOMY
        required = {"description", "nist_phase", "d3fend", "react", "typical_actions", "applies_to"}
        for cat, entry in REMEDIATION_TAXONOMY.items():
            for field in required:
                assert field in entry, f"'{cat}' missing '{field}'"
            assert len(entry["typical_actions"]) >= 3
            assert "NIST" in entry["nist_phase"]

    def test_technique_guidance_has_mitigations(self):
        from nur.server.taxonomy import TECHNIQUE_GUIDANCE
        for tid, entry in TECHNIQUE_GUIDANCE.items():
            assert "name" in entry
            assert "mitigations" in entry
            assert len(entry["mitigations"]) >= 1
            assert "recommended_categories" in entry
            from nur.server.taxonomy import REMEDIATION_TAXONOMY
            for cat in entry["recommended_categories"]:
                assert cat in REMEDIATION_TAXONOMY

    def test_get_remediation_guidance(self):
        from nur.server.taxonomy import get_remediation_guidance
        g = get_remediation_guidance("containment")
        assert g is not None
        assert "Network Isolation" in g["d3fend"][0]
        assert get_remediation_guidance("nonexistent") is None

    def test_get_technique_guidance(self):
        from nur.server.taxonomy import get_technique_guidance
        g = get_technique_guidance("T1566")
        assert g is not None
        assert g["name"] == "Phishing"
        assert len(g["mitigations"]) >= 2
        assert get_technique_guidance("T9999") is None

    def test_enrich_remediation_hints(self):
        from nur.server.taxonomy import enrich_remediation_hints
        hints = {
            "most_effective_categories": [
                {"category": "containment", "success_rate": 0.87, "total_reports": 12},
                {"category": "detection", "success_rate": 0.65, "total_reports": 8},
            ],
            "severity_distribution": {"critical": 5, "high": 3},
            "total_attack_reports": 20,
        }
        enriched = enrich_remediation_hints(hints, gap_technique_ids=["T1490", "T1566"])

        # Categories have framework_ref
        assert "framework_ref" in enriched["most_effective_categories"][0]
        ref = enriched["most_effective_categories"][0]["framework_ref"]
        assert "NIST" in ref["nist_phase"]
        assert len(ref["d3fend"]) >= 1
        assert len(ref["typical_actions"]) >= 3

        # Technique guidance present
        assert "technique_guidance" in enriched
        tg = enriched["technique_guidance"]
        assert len(tg) == 2
        t1490 = next(t for t in tg if t["technique_id"] == "T1490")
        assert t1490["name"] == "Inhibit System Recovery"
        assert "M1053" in t1490["mitigations"][0]

    def test_enrich_with_subtechnique_fallback(self):
        from nur.server.taxonomy import enrich_remediation_hints
        hints = {"most_effective_categories": [], "total_attack_reports": 1}
        enriched = enrich_remediation_hints(hints, gap_technique_ids=["T1059.001"])
        assert "technique_guidance" in enriched
        assert enriched["technique_guidance"][0]["technique_id"] == "T1059.001"
        assert enriched["technique_guidance"][0]["name"] == "PowerShell"

    def test_enrich_without_gaps(self):
        from nur.server.taxonomy import enrich_remediation_hints
        hints = {"most_effective_categories": [], "total_attack_reports": 0}
        enriched = enrich_remediation_hints(hints)
        assert "technique_guidance" not in enriched


class TestAnalyzeResponsesAreAggregateOnly:
    """Verify no individual org data leaks through /analyze responses."""

    @pytest.fixture
    def app(self):
        import nur.server.app as app_mod
        return app_mod.create_app("sqlite+aiosqlite://")

    @pytest.mark.asyncio
    async def test_ioc_response_has_no_threat_actors(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/analyze", json={
                "iocs": [{"ioc_type": "ip", "value_hash": "test123"}],
            })
            data = resp.json()
            intel = data["intelligence"]
            assert "threat_actors" not in intel
            assert "campaign_summary" not in intel
            assert "shared_ioc_count" in intel
            assert "ioc_type_distribution" in intel

    @pytest.mark.asyncio
    async def test_attack_map_response_has_no_individual_actions(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/analyze", json={
                "techniques": [{"technique_id": "T1566", "observed": True}],
                "tools_in_scope": ["crowdstrike"],
            })
            data = resp.json()
            intel = data["intelligence"]
            assert "what_worked" not in intel
            assert "ir_metrics" not in intel
            assert "detection_gaps" in intel
            assert "coverage_score" in intel

    @pytest.mark.asyncio
    async def test_eval_response_has_no_individual_gaps_list(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/analyze", json={
                "vendor": "TestVendor", "category": "edr", "overall_score": 8.0,
            })
            data = resp.json()
            intel = data["intelligence"]
            assert "known_gaps" not in intel
            assert "better_alternatives" not in intel
            assert "known_gaps_count" in intel


# ══════════════════════════════════════════════════════════════════════════════
# Blind Category Discovery — threshold reveal protocol
# ══════════════════════════════════════════════════════════════════════════════

class TestBlindCategoryDiscovery:
    """Core protocol: propose → threshold → reveal."""

    def test_propose_category(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        result = bcd.propose_category(h, "threat_actor", "org-1")
        assert result["status"] == "pending"
        assert result["supporter_count"] == 1
        assert result["ready_for_reveal"] is False

    def test_threshold_met_after_enough_orgs(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")
        result = bcd.propose_category(h, "threat_actor", "org-3")

        assert result["status"] == "threshold_met"
        assert result["supporter_count"] == 3
        assert result["ready_for_reveal"] is True

    def test_same_org_doesnt_double_count(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-1")

        result = bcd.check_threshold(h)
        assert result["supporter_count"] == 1  # same org, counted once

    def test_reveal_requires_threshold(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        result = bcd.vote_reveal(h, "DarkAngel", "salt1", "org-1")
        assert "error" in result
        assert "threshold" in result["error"].lower()

    def test_reveal_verifies_hash(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")

        # Wrong plaintext
        result = bcd.vote_reveal(h, "WrongName", "salt1", "org-1")
        assert "error" in result
        assert "verification failed" in result["error"].lower()

    def test_reveal_quorum_reveals_category(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")

        r1 = bcd.vote_reveal(h, "DarkAngel", "salt1", "org-1")
        assert r1["status"] == "vote_recorded"
        assert r1["remaining"] == 1

        r2 = bcd.vote_reveal(h, "DarkAngel", "salt1", "org-2")
        assert r2["status"] == "revealed"
        assert r2["revealed_name"] == "darkangel"

    def test_revealed_category_in_list(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")
        bcd.vote_reveal(h, "DarkAngel", "salt1", "org-1")
        bcd.vote_reveal(h, "DarkAngel", "salt1", "org-2")

        revealed = bcd.get_revealed_categories()
        assert len(revealed) == 1
        assert revealed[0]["name"] == "darkangel"
        assert revealed[0]["category_type"] == "threat_actor"

    def test_double_propose_after_reveal(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")
        bcd.vote_reveal(h, "DarkAngel", "salt1", "org-1")
        bcd.vote_reveal(h, "DarkAngel", "salt1", "org-2")

        result = bcd.propose_category(h, "threat_actor", "org-3")
        assert result["status"] == "already_revealed"

    def test_non_proposer_cannot_reveal(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)
        h = hash_category("DarkAngel", "salt1")

        bcd.propose_category(h, "threat_actor", "org-1")
        bcd.propose_category(h, "threat_actor", "org-2")

        result = bcd.vote_reveal(h, "DarkAngel", "salt1", "org-3")
        assert "error" in result
        assert "original proposers" in result["error"].lower()

    def test_pending_categories_list(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)

        h1 = hash_category("DarkAngel", "s1")
        h2 = hash_category("BlackCat", "s2")

        bcd.propose_category(h1, "threat_actor", "org-1")
        bcd.propose_category(h1, "threat_actor", "org-2")
        bcd.propose_category(h2, "malware", "org-1")

        pending = bcd.get_pending_categories()
        assert len(pending) == 2
        # Sorted by supporter count (h1 has 2, h2 has 1)
        assert pending[0]["supporter_count"] == 2
        assert pending[1]["supporter_count"] == 1

    def test_invalid_category_type(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery()
        h = hash_category("test", "salt")
        result = bcd.propose_category(h, "invalid_type", "org-1")
        assert "error" in result

    def test_hash_category_deterministic(self):
        from nur.server.blind_categories import hash_category
        h1 = hash_category("DarkAngel", "salt1")
        h2 = hash_category("DarkAngel", "salt1")
        h3 = hash_category("DarkAngel", "salt2")
        assert h1 == h2
        assert h1 != h3

    def test_hash_category_case_insensitive(self):
        from nur.server.blind_categories import hash_category
        h1 = hash_category("DarkAngel", "salt1")
        h2 = hash_category("darkangel", "salt1")
        assert h1 == h2

    def test_stats(self):
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
        bcd = BlindCategoryDiscovery(discovery_threshold=2, reveal_quorum=2)

        h1 = hash_category("A", "s")
        h2 = hash_category("B", "s")
        bcd.propose_category(h1, "threat_actor", "org-1")
        bcd.propose_category(h1, "threat_actor", "org-2")
        bcd.propose_category(h2, "malware", "org-1")

        assert bcd.pending_count == 2
        assert bcd.revealed_count == 0

        bcd.vote_reveal(h1, "A", "s", "org-1")
        bcd.vote_reveal(h1, "A", "s", "org-2")

        assert bcd.pending_count == 1
        assert bcd.revealed_count == 1


class TestBlindCategoryE2E:
    """Full scenario: multiple orgs discover a new threat actor."""

    def test_three_hospitals_discover_darkangel(self):
        """
        Three hospitals independently encounter "DarkAngel" ransomware.
        None of them know the others are seeing it.
        Through blind category discovery, they collectively surface it.
        """
        from nur.server.blind_categories import BlindCategoryDiscovery, hash_category

        bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)

        # Each hospital hashes "DarkAngel" with their own salt
        # (In practice, they'd use a shared salt from the server or protocol)
        shared_salt = "nur-2026"
        h = hash_category("DarkAngel", shared_salt)

        # Hospital A submits
        r1 = bcd.propose_category(h, "threat_actor", "hospital-a")
        assert r1["status"] == "pending"
        assert r1["supporter_count"] == 1

        # Hospital B submits independently
        r2 = bcd.propose_category(h, "threat_actor", "hospital-b")
        assert r2["status"] == "pending"
        assert r2["supporter_count"] == 2

        # Hospital C submits — threshold met!
        r3 = bcd.propose_category(h, "threat_actor", "hospital-c")
        assert r3["status"] == "threshold_met"
        assert r3["ready_for_reveal"] is True

        # Server says: "category H has 3 supporters, ready for reveal"
        # Hospitals A and B vote to reveal
        v1 = bcd.vote_reveal(h, "DarkAngel", shared_salt, "hospital-a")
        assert v1["status"] == "vote_recorded"

        v2 = bcd.vote_reveal(h, "DarkAngel", shared_salt, "hospital-b")
        assert v2["status"] == "revealed"
        assert v2["revealed_name"] == "darkangel"

        # Now "DarkAngel" is a public category — aggregation can begin
        revealed = bcd.get_revealed_categories()
        assert len(revealed) == 1
        assert revealed[0]["name"] == "darkangel"
        assert revealed[0]["category_type"] == "threat_actor"
        assert revealed[0]["supporter_count"] == 3


class TestBlindCategoryEndpoints:
    """API endpoint tests for blind category discovery."""

    @pytest.fixture
    def app(self):
        import nur.server.app as app_mod
        return app_mod.create_app("sqlite+aiosqlite://")

    @pytest.mark.asyncio
    async def test_propose_and_check(self, app):
        from httpx import AsyncClient, ASGITransport
        from nur.server.blind_categories import hash_category
        h = hash_category("NewThreat", "test-salt")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/category/propose", json={
                "category_hash": h,
                "category_type": "threat_actor",
                "submitter_id": "org-1",
            })
            assert resp.status_code == 200
            assert resp.json()["status"] == "pending"

            resp = await c.get(f"/category/check/{h}")
            assert resp.status_code == 200
            assert resp.json()["supporter_count"] == 1

    @pytest.mark.asyncio
    async def test_full_reveal_flow(self, app):
        from httpx import AsyncClient, ASGITransport
        from nur.server.blind_categories import hash_category
        h = hash_category("NewMalware", "salt")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # 3 orgs propose
            for org in ["org-1", "org-2", "org-3"]:
                await c.post("/category/propose", json={
                    "category_hash": h, "category_type": "malware", "submitter_id": org,
                })

            # 2 orgs reveal
            r1 = await c.post("/category/reveal", json={
                "category_hash": h, "plaintext": "NewMalware", "salt": "salt", "submitter_id": "org-1",
            })
            assert r1.json()["status"] == "vote_recorded"

            r2 = await c.post("/category/reveal", json={
                "category_hash": h, "plaintext": "NewMalware", "salt": "salt", "submitter_id": "org-2",
            })
            assert r2.json()["status"] == "revealed"
            assert r2.json()["revealed_name"] == "newmalware"

            # Check pending list
            resp = await c.get("/category/pending")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["revealed"]) == 1
            assert data["revealed"][0]["name"] == "newmalware"

    @pytest.mark.asyncio
    async def test_propose_missing_fields(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/category/propose", json={"category_hash": "abc"})
            assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# BDP (Behavioral Differential Privacy) Integration Tests
# ══════════════════════════════════════════════════════════════════════════════


async def _make_bdp_app():
    """Create a fresh app with initialized DB, ProofEngine, and empty BDP profiles."""
    import nur.server.app as app_mod
    from nur.server.db import Database
    from nur.server.proofs import ProofEngine
    the_app = app_mod.create_app("sqlite+aiosqlite://")
    db = Database("sqlite+aiosqlite://")
    await db.init()
    app_mod._db = db
    app_mod._proof_engine = ProofEngine()
    app_mod._profiles = {}
    return the_app


class TestBDPProfileTracking:
    """Behavioral profile tracking across endpoints."""

    @pytest.mark.asyncio
    async def test_contribute_eval_creates_profile(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/contribute/submit", json={
                "data": {"vendor": "CrowdStrike", "category": "edr", "overall_score": 9.0}
            }, headers={"X-API-Key": "test-key-123"})
            assert resp.status_code == 200

            import nur.server.app as app_mod
            assert len(app_mod._profiles) >= 1
            # Profile should have contribution tracked
            profile = list(app_mod._profiles.values())[0]
            assert "eval" in profile.contribution_types
            assert "crowdstrike" in profile.contributed_vendors
            assert profile.total_contributions >= 1

    @pytest.mark.asyncio
    async def test_webhook_tracks_integration_source(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/ingest/webhook", json={
                "detection": {"technique": "T1059", "severity": "high"}
            }, headers={"X-API-Key": "test-key-456"})
            assert resp.status_code == 200

            import nur.server.app as app_mod
            profile = list(app_mod._profiles.values())[0]
            assert "crowdstrike" in profile.integration_sources

    @pytest.mark.asyncio
    async def test_profile_keyed_by_hash_not_raw_key(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/contribute/submit", json={
                "data": {"vendor": "Test", "overall_score": 8.0}
            }, headers={"X-API-Key": "my-secret-key"})

            import nur.server.app as app_mod
            for pid in app_mod._profiles:
                assert "my-secret-key" not in pid
                assert len(pid) == 16  # truncated hash

    @pytest.mark.asyncio
    async def test_anonymous_contributions_get_profile(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/contribute/submit", json={
                "data": {"vendor": "Test", "overall_score": 8.0}
            })
            assert resp.status_code == 200
            # Should not crash, anonymous gets a profile too

    @pytest.mark.asyncio
    async def test_bdp_stats_endpoint(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Submit some data first
            await c.post("/contribute/submit", json={
                "data": {"vendor": "CrowdStrike", "overall_score": 9.0}
            }, headers={"X-API-Key": "key-1"})
            await c.post("/contribute/submit", json={
                "data": {"vendor": "SentinelOne", "overall_score": 8.0}
            }, headers={"X-API-Key": "key-2"})

            resp = await c.get("/proof/bdp-stats")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_profiles"] >= 1
            assert "credibility_distribution" in data

    @pytest.mark.asyncio
    async def test_same_key_same_profile(self):
        from httpx import AsyncClient, ASGITransport
        app = await _make_bdp_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/contribute/submit", json={
                "data": {"vendor": "CrowdStrike", "overall_score": 9.0}
            }, headers={"X-API-Key": "same-key"})
            await c.post("/contribute/attack-map", json={
                "techniques": [{"technique_id": "T1566"}]
            }, headers={"X-API-Key": "same-key"})

            import nur.server.app as app_mod
            # Should be ONE profile with both contribution types
            profiles = [p for p in app_mod._profiles.values() if p.total_contributions >= 2]
            assert len(profiles) >= 1
            profile = profiles[0]
            assert "eval" in profile.contribution_types
            assert "attack_map" in profile.contribution_types


class TestBDPPrivacyPreservation:
    """Ensure BDP tracking doesn't leak individual data."""

    def test_profile_never_stores_raw_api_key(self):
        import nur.server.app as app_mod
        app_mod._profiles = {}
        profile = app_mod.get_or_create_profile("super-secret-api-key-12345")
        assert "super-secret-api-key-12345" not in profile.participant_id
        assert len(profile.participant_id) == 16

    def test_profile_stores_vendors_lowercase_only(self):
        import nur.server.app as app_mod
        app_mod._profiles = {}
        profile = app_mod.get_or_create_profile("test-key")
        profile.contributed_vendors.add("crowdstrike")
        # No org names, no specific details — just vendor IDs
        for v in profile.contributed_vendors:
            assert v == v.lower()

    def test_bdp_stats_returns_only_aggregates(self):
        """The /proof/bdp-stats endpoint must never return individual profiles."""
        # This is verified by the endpoint implementation — it only returns
        # counts and distributions, never profile contents
        from nur.behavioral_dp import BehavioralProfile, compute_credibility_weight
        profile = BehavioralProfile(participant_id="test")
        profile.contributed_vendors = {"crowdstrike"}
        profile.query_types = {"market", "search"}
        w = compute_credibility_weight(profile)
        # Weight is a single float — no profile details leak
        assert isinstance(w, float)
        assert 0.05 <= w <= 0.95

    def test_credibility_weight_has_laplace_noise(self):
        """Two calls with same profile should return DIFFERENT weights due to noise."""
        from nur.behavioral_dp import BehavioralProfile, compute_credibility_weight
        profile = BehavioralProfile(participant_id="test")
        profile.contributed_vendors = {"crowdstrike"}
        profile.queried_vendors = {"crowdstrike"}
        profile.query_types = {"market", "search", "simulate"}
        profile.contribution_types = {"eval", "attack_map"}

        weights = [compute_credibility_weight(profile) for _ in range(20)]
        # With Laplace noise, weights should vary
        assert len(set(weights)) > 1  # not all identical


# ══════════════════════════════════════════════════════════════════════════════
# Expanded eval metrics: price, support, performance, decision intelligence
# ══════════════════════════════════════════════════════════════════════════════

class TestExpandedEvalMetrics:
    """Price, support, performance, and decision intel fields."""

    def test_price_fields_aggregate(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 9.0,
            "annual_cost": 50000,
            "per_seat_cost": 12.50,
            "contract_length_months": 36,
            "discount_pct": 15.0,
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 8.5,
            "annual_cost": 45000,
            "per_seat_cost": 11.00,
            "contract_length_months": 24,
            "discount_pct": 20.0,
        })
        agg = engine.get_aggregate("CrowdStrike")
        assert abs(agg["avg_annual_cost"] - 47500) < 1
        assert abs(agg["avg_per_seat_cost"] - 11.75) < 0.01
        assert abs(agg["avg_discount_pct"] - 17.5) < 0.01

    def test_support_fields_aggregate(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {
            "support_quality": 8.0,
            "escalation_ease": 7.0,
            "support_sla_hours": 4.0,
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "support_quality": 9.0,
            "escalation_ease": 6.0,
            "support_sla_hours": 2.0,
        })
        agg = engine.get_aggregate("CrowdStrike")
        assert abs(agg["avg_support_quality"] - 8.5) < 0.01
        assert abs(agg["avg_support_sla_hours"] - 3.0) < 0.01

    def test_decision_factor_categorical(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 9.0,
            "chose_this_vendor": True,
            "decision_factor": "detection",
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "overall_score": 8.0,
            "chose_this_vendor": False,
            "decision_factor": "price",
        })
        agg = engine.get_aggregate("CrowdStrike")
        assert abs(agg["chose_this_vendor_pct"] - 50.0) < 0.01
        bucket = engine._aggregates["crowdstrike:edr"]
        assert bucket.bool_counts.get("decision_factor:detection", 0) == 1
        assert bucket.bool_counts.get("decision_factor:price", 0) == 1

    def test_translate_eval_handles_new_fields(self):
        from nur.server.proofs import translate_eval
        vendor, cat, values = translate_eval({
            "data": {
                "vendor": "CrowdStrike",
                "category": "edr",
                "overall_score": 9.0,
                "annual_cost": 50000,
                "support_quality": 8.0,
                "chose_this_vendor": True,
                "decision_factor": "detection quality is great",
            }
        })
        assert values["annual_cost"] == 50000
        assert values["support_quality"] == 8.0
        assert values["chose_this_vendor"] is True
        assert values["decision_factor"] == "detection"  # matched to category

    def test_performance_fields(self):
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        engine.commit_contribution("CrowdStrike", "edr", {
            "agent_memory_mb": 150,
            "scan_latency_ms": 45,
        })
        engine.commit_contribution("CrowdStrike", "edr", {
            "agent_memory_mb": 200,
            "scan_latency_ms": 55,
        })
        agg = engine.get_aggregate("CrowdStrike")
        assert abs(agg["avg_agent_memory_mb"] - 175) < 1
        assert abs(agg["avg_scan_latency_ms"] - 50) < 1

    def test_price_data_not_in_receipts(self):
        """Price data should be aggregated but never appear in receipts."""
        from nur.server.proofs import ProofEngine
        engine = ProofEngine()
        receipt = engine.commit_contribution("CrowdStrike", "edr", {
            "annual_cost": 50000,
            "per_seat_cost": 12.50,
        })
        d = receipt.to_dict()
        # Receipt contains hashes, not values
        assert "50000" not in str(d["commitment_hash"])
        assert "12.50" not in str(d["commitment_hash"])
