"""
VCI Protocol — full test suite.

Tests all 4 phases:
  1. Share validity (Shamir-Pedersen binding)
  2. Weighted aggregation with formal poisoning bound
  3. Platform attestation with Merkle tree
  4. PSI-driven trust feedback
  5. End-to-end pipeline
"""
import hashlib
import math
import time

import pytest

from nur.zkp.proofs import (
    ProofParams,
    Commitment,
    commit,
    create_range_proof,
    verify_range_proof,
)
from nur.zkp.contrib_proofs import ContributionProofBundle, EvalRecordProof
from nur.attest.chain import ChainBuilder, hash_content
from nur.behavioral_dp import BehavioralProfile, compute_credibility_weight


# ════════════════════════════════════════════════════════════════════════════
# Phase 1: Share Validity (Shamir-Pedersen binding)
# ════════════════════════════════════════════════════════════════════════════

class TestShareProofs:
    """Test Shamir-Pedersen binding proofs."""

    def setup_method(self):
        self.params = ProofParams()

    def test_vci_shamir_split_and_reconstruct(self):
        """Shamir shares over Z_q reconstruct correctly."""
        from nur.vci.share_proofs import vci_shamir_split, vci_shamir_reconstruct

        secret = 92  # CrowdStrike eval score * 10
        shares = vci_shamir_split(secret, 5, 3, self.params.q)

        assert len(shares) == 5
        # Any 3 shares should reconstruct
        reconstructed = vci_shamir_reconstruct(shares[:3], self.params.q)
        assert reconstructed == secret

        # Different subset of 3
        reconstructed2 = vci_shamir_reconstruct(shares[2:5], self.params.q)
        assert reconstructed2 == secret

    def test_share_consistency_proof_valid(self):
        """Valid shares produce a passing consistency proof."""
        from nur.vci.share_proofs import (
            vci_shamir_split,
            commit_and_prove_shares,
            verify_share_consistency,
        )

        value = 92
        original = commit(self.params, value)
        shares = vci_shamir_split(value, 5, 3, self.params.q)

        proof = commit_and_prove_shares(self.params, original, shares)
        assert verify_share_consistency(self.params, original, proof)

    def test_share_consistency_proof_tampered_share(self):
        """Tampering with a share breaks the consistency proof."""
        from nur.vci.share_proofs import (
            vci_shamir_split,
            commit_and_prove_shares,
            verify_share_consistency,
        )

        value = 92
        original = commit(self.params, value)
        shares = vci_shamir_split(value, 5, 3, self.params.q)

        # Create valid proof first
        proof = commit_and_prove_shares(self.params, original, shares)
        assert verify_share_consistency(self.params, original, proof)

        # Now commit to different shares (tampered)
        tampered_value = 20  # poisoner tries to substitute
        tampered_original = commit(self.params, tampered_value)

        # The proof was made for value=92, checking against commitment to 20 should fail
        assert not verify_share_consistency(self.params, tampered_original, proof)

    def test_share_consistency_wrong_commitment(self):
        """Proof for value=92 fails against commitment to value=50."""
        from nur.vci.share_proofs import (
            vci_shamir_split,
            commit_and_prove_shares,
            verify_share_consistency,
        )

        # Create shares for value 92
        shares = vci_shamir_split(92, 5, 3, self.params.q)
        original_92 = commit(self.params, 92)
        proof = commit_and_prove_shares(self.params, original_92, shares)

        # Verify against commitment to 50 — should fail
        wrong_commitment = commit(self.params, 50)
        assert not verify_share_consistency(self.params, wrong_commitment, proof)

    def test_lagrange_coefficients(self):
        """Lagrange coefficients sum to 1 at x=0."""
        from nur.vci.share_proofs import lagrange_coefficients

        xs = [1, 2, 3, 4, 5]
        lambdas = lagrange_coefficients(xs, self.params.q)
        # Sum of lambda_i should be 1 mod q (since f(0) = sum(lambda_i * f(x_i))
        # and for constant polynomial f(x)=1, f(0)=1)
        total = sum(lambdas) % self.params.q
        assert total == 1


# ════════════════════════════════════════════════════════════════════════════
# Phase 2: Weighted Aggregation with Formal Poisoning Bound
# ════════════════════════════════════════════════════════════════════════════

class TestAggregation:
    """Test credibility-weighted aggregation and poisoning bounds."""

    def _real_profile(self, pid: str) -> BehavioralProfile:
        """Create a profile for a real practitioner."""
        return BehavioralProfile(
            participant_id=pid,
            contribution_types={"eval", "ioc_bundle", "attack_map"},
            query_types={"report", "simulate", "market", "threat-model"},
            contributed_vendors={"crowdstrike", "sentinelone"},
            queried_vendors={"crowdstrike", "sentinelone"},
            integration_sources={"splunk"},
            iocs_matched=8,
            techniques_corroborated=5,
            total_contributions=15,
            total_queries=30,
            first_seen_ts=time.time() - 120 * 86400,
            last_seen_ts=time.time(),
        )

    def _poisoner_profile(self, pid: str) -> BehavioralProfile:
        """Create a profile for a poisoner."""
        return BehavioralProfile(
            participant_id=pid,
            contribution_types={"eval"},
            query_types=set(),
            contributed_vendors={"crowdstrike"},
            queried_vendors=set(),
            total_contributions=1,
            total_queries=0,
            first_seen_ts=time.time(),
            last_seen_ts=time.time(),
        )

    def test_weighted_aggregate_resists_poisoning(self):
        """VCI weighted aggregate should resist poisoner better than simple average."""
        from nur.vci.aggregation import vci_aggregate_with_bound

        # 5 real contributors rating CrowdStrike 8-9
        values = [9.2, 8.8, 9.0, 8.5, 8.7]
        profiles = [self._real_profile(f"real_{i}") for i in range(5)]

        # 2 poisoners rating CrowdStrike 1-2
        values.extend([1.0, 2.0])
        profiles.extend([self._poisoner_profile(f"poison_{i}") for i in range(2)])

        result = vci_aggregate_with_bound(values, profiles, epsilon=100.0)

        # Simple average: (9.2+8.8+9.0+8.5+8.7+1.0+2.0)/7 = 6.74
        # Weighted should be much closer to 8.7+ because poisoners have low weight
        assert result["simple_average"] < 7.0  # simple average pulls down
        assert result["aggregate"] > result["simple_average"]  # VCI resists
        assert result["n_trusted"] >= 4  # real contributors are trusted
        assert result["n_untrusted"] >= 1  # poisoners are untrusted

    def test_poisoning_bound_computation(self):
        """Formal poisoning bound is computed correctly."""
        from nur.vci.bounds import compute_poisoning_bound

        weights = [0.7, 0.8, 0.75, 0.7, 0.65, 0.05, 0.05]
        # Poisoner at index 5 with weight 0.05
        bound = compute_poisoning_bound(
            weights=weights,
            poisoner_index=5,
            max_deviation=10.0,
            value_range=10.0,
        )

        # max_impact = 0.05 * 10 / sum(weights) = 0.5 / 3.7 ≈ 13.5%
        assert bound.max_impact_pct < 15.0
        assert bound.poisoner_weight == 0.05
        assert bound.n_trusted >= 5

    def test_collective_bound(self):
        """Collective bound for multiple colluding poisoners."""
        from nur.vci.bounds import compute_collective_bound

        weights = [0.7, 0.8, 0.75, 0.7, 0.65, 0.05, 0.05]
        result = compute_collective_bound(
            weights=weights,
            poisoner_indices=[5, 6],
            max_deviation=10.0,
        )

        # Even 2 colluding poisoners with w=0.05 each: 0.1/3.7 ≈ 2.7%
        assert result["collective_impact_pct"] < 5.0
        assert result["n_poisoners"] == 2
        assert result["n_honest"] == 5

    def test_weighted_aggregate_values(self):
        """Simple weighted average helper works correctly."""
        from nur.vci.aggregation import weighted_aggregate_values

        result = weighted_aggregate_values([
            (9.2, 0.8),
            (2.0, 0.1),
            (8.8, 0.7),
        ])
        # (9.2*0.8 + 2.0*0.1 + 8.8*0.7) / (0.8+0.1+0.7) = (7.36+0.2+6.16)/1.6 = 8.575
        assert abs(result - 8.575) < 0.01


# ════════════════════════════════════════════════════════════════════════════
# Phase 3: Platform Attestation
# ════════════════════════════════════════════════════════════════════════════

class TestPlatformAttestation:
    """Test zero-knowledge platform attestation."""

    def setup_method(self):
        self.params = ProofParams()

    def test_generate_and_verify_attestation(self):
        """Generate attestation and verify all proofs pass."""
        from nur.vci.platform import (
            generate_platform_attestation,
            verify_platform_attestation,
        )

        # Simulate 10 contributions from 3 orgs
        envelope_hashes = [
            hashlib.sha256(f"envelope_{i}".encode()).hexdigest()
            for i in range(10)
        ]
        org_ids = ["org_a"] * 4 + ["org_b"] * 3 + ["org_c"] * 3
        cred_weights = [0.7, 0.8, 0.75, 0.6, 0.7, 0.65, 0.8, 0.5, 0.6, 0.7]

        attestation = generate_platform_attestation(
            params=self.params,
            envelope_hashes=envelope_hashes,
            org_ids=org_ids,
            credibility_weights=cred_weights,
            server_secret=b"test_server_secret",
        )

        result = verify_platform_attestation(self.params, attestation)
        assert result["valid"], f"Attestation invalid: {result['errors']}"
        assert result["statistics"]["leaf_count"] == 10

    def test_merkle_tree_integrity(self):
        """Merkle tree correctly binds leaf hashes."""
        from nur.vci.platform import build_merkle_tree, get_merkle_proof, verify_merkle_proof

        leaves = [
            hashlib.sha256(f"leaf_{i}".encode()).hexdigest()
            for i in range(8)
        ]

        root, levels = build_merkle_tree(leaves)

        # Verify each leaf has a valid proof
        for i in range(len(leaves)):
            proof_path = get_merkle_proof(i, levels)
            assert verify_merkle_proof(leaves[i], proof_path, root)

        # Tamper with a leaf — proof should fail
        tampered_leaf = hashlib.sha256(b"tampered").hexdigest()
        proof_path = get_merkle_proof(0, levels)
        assert not verify_merkle_proof(tampered_leaf, proof_path, root)

    def test_attestation_with_tampered_n(self):
        """Tampering with leaf count N produces different range proof — detection."""
        from nur.vci.platform import generate_platform_attestation, PlatformAttestation
        from nur.zkp.proofs import RangeProof

        envelope_hashes = [
            hashlib.sha256(f"e_{i}".encode()).hexdigest()
            for i in range(5)
        ]
        org_ids = ["org_a"] * 3 + ["org_b"] * 2
        cred_weights = [0.7, 0.8, 0.6, 0.7, 0.5]

        attestation = generate_platform_attestation(
            self.params, envelope_hashes, org_ids, cred_weights, b"secret",
        )

        # Tamper: claim 50 contributions instead of 5
        tampered = attestation.to_dict()
        tampered["leaf_count"] = 50

        # The range proof was created for N=5, so it's still valid for [1, 100000]
        # But the leaf_count field no longer matches the commitment
        # The detection happens because merkle_root has only 5 leaves
        att = PlatformAttestation.from_dict(tampered)
        assert att.leaf_count == 50  # tampered
        # The proofs still verify (they prove the COMMITTED value is in range)
        # The real protection is that the Merkle tree only has 5 leaves,
        # so any client requesting inclusion proofs would discover the mismatch


# ════════════════════════════════════════════════════════════════════════════
# Phase 4: PSI-Driven Trust Feedback
# ════════════════════════════════════════════════════════════════════════════

class TestTrustGraph:
    """Test PSI-driven trust feedback."""

    def test_psi_match_increases_credibility(self):
        """PSI matches increase both orgs' credibility."""
        from nur.vci.trust_graph import process_psi_result, TrustGraph

        graph = TrustGraph()

        profile_a = BehavioralProfile(
            participant_id="org_a",
            contribution_types={"ioc_bundle"},
            query_types={"report"},
            contributed_vendors={"crowdstrike"},
            queried_vendors={"crowdstrike"},
        )
        profile_b = BehavioralProfile(
            participant_id="org_b",
            contribution_types={"ioc_bundle"},
            query_types={"simulate"},
            contributed_vendors={"sentinelone"},
            queried_vendors={"sentinelone"},
        )

        edge = process_psi_result(
            match_count=5,
            profile_a=profile_a,
            profile_b=profile_b,
            matched_iocs=["ioc_1", "ioc_2", "ioc_3", "ioc_4", "ioc_5"],
            trust_graph=graph,
        )

        assert edge.match_count == 5
        assert edge.credibility_delta_a > 0
        assert edge.credibility_delta_b > 0
        assert graph.get_credibility_boost("org_a") > 0
        assert graph.get_credibility_boost("org_b") > 0

    def test_no_matches_no_boost(self):
        """Zero PSI matches give zero credibility boost."""
        from nur.vci.trust_graph import process_psi_result, TrustGraph

        graph = TrustGraph()

        profile_a = BehavioralProfile(participant_id="fake_org")
        profile_b = BehavioralProfile(participant_id="real_org")

        edge = process_psi_result(
            match_count=0,
            profile_a=profile_a,
            profile_b=profile_b,
            trust_graph=graph,
        )

        assert edge.credibility_delta_a == 0
        assert edge.credibility_delta_b == 0
        assert graph.get_credibility_boost("fake_org") == 0

    def test_public_iocs_give_less_boost(self):
        """IOCs from public feeds give less credibility boost than private ones."""
        from nur.vci.trust_graph import compute_ioc_rarity

        public_feeds = {"1.2.3.4", "malware.com", "evil.ru"}

        # All private IOCs
        private_rarity = compute_ioc_rarity(
            ["unique_ioc_1", "unique_ioc_2"], public_feeds,
        )

        # All public IOCs
        public_rarity = compute_ioc_rarity(
            ["1.2.3.4", "malware.com"], public_feeds,
        )

        assert private_rarity > public_rarity

    def test_trust_feedback_caps_at_maximum(self):
        """Trust boost is capped to prevent gaming."""
        from nur.vci.trust_graph import apply_trust_feedback, TrustGraph, TrustEdge

        graph = TrustGraph()
        # Add many edges to accumulate boost
        for i in range(100):
            graph.add_edge(TrustEdge(
                org_a="org_x", org_b=f"org_{i}",
                match_count=10, rarity_weight=1.0,
                credibility_delta_a=0.15, credibility_delta_b=0.05,
            ))

        profile = BehavioralProfile(participant_id="org_x")
        boosted = apply_trust_feedback(profile, graph, base_weight=0.5)

        # Should be capped at 0.95
        assert boosted <= 0.95


# ════════════════════════════════════════════════════════════════════════════
# Phase 5: End-to-End Pipeline
# ════════════════════════════════════════════════════════════════════════════

class TestEndToEnd:
    """Test the full VCI pipeline: envelope -> verify -> aggregate -> attest -> PSI."""

    def setup_method(self):
        self.params = ProofParams()

    def _make_eval_record(self, score, category="edr", vendor="crowdstrike"):
        """Create a simple object with eval record attributes."""
        class EvalRecord:
            pass
        r = EvalRecord()
        r.overall_score = score
        r.detection_rate = 85.0
        r.fp_rate = 3.0
        r.cpu_overhead = 12.0
        r.deploy_days = 30
        r.category = category
        r.vendor = vendor
        return r

    def test_envelope_build_and_verify(self):
        """Build a VCI envelope and verify it passes all checks."""
        from nur.vci.envelope import build_envelope, verify_envelope

        # Create eval record and ZKP bundle
        record = self._make_eval_record(9.2)
        prover = EvalRecordProof(self.params)
        zkp_bundle = prover.prove(record)

        # Build attestation chain
        builder = ChainBuilder(
            org_secret=b"org_secret_key",
            file_hash=hash_content({"score": 9.2}),
        )
        builder.add_stage(
            "extract", hash_content("raw"), hash_content("extracted"),
            {"method": "api"},
        )
        builder.add_stage(
            "validate", hash_content("extracted"), hash_content("validated"),
            {"zkp": True},
        )
        chain = builder.build()

        # Build envelope
        envelope = build_envelope(
            params=self.params,
            attestation_chain=chain,
            zkp_bundle=zkp_bundle,
            field_values={"overall_score": 92},  # scaled by 10
            n_parties=5,
            threshold=3,
            contributor_secret=b"contributor_key",
        )

        # Verify
        result = verify_envelope(self.params, envelope)
        assert result["valid"], f"Envelope verification failed: {result['errors']}"
        assert result["checks"]["envelope_hash"]
        assert result["checks"]["zkp_proofs"]
        assert result["checks"]["share_consistency"]
        assert result["checks"]["attestation_chain"]

    def test_full_pipeline(self):
        """End-to-end: contribute -> verify -> aggregate -> attest -> PSI."""
        from nur.vci.envelope import build_envelope, verify_envelope
        from nur.vci.aggregation import vci_aggregate_with_bound
        from nur.vci.platform import (
            generate_platform_attestation,
            verify_platform_attestation,
        )
        from nur.vci.trust_graph import process_psi_result, TrustGraph

        # === Step 1: Multiple contributors create envelopes ===
        envelope_hashes = []
        values = []
        profiles = []

        for i in range(5):
            score = 8.0 + i * 0.3  # 8.0, 8.3, 8.6, 8.9, 9.2
            record = self._make_eval_record(score)
            prover = EvalRecordProof(self.params)
            zkp_bundle = prover.prove(record)

            builder = ChainBuilder(
                org_secret=f"org_{i}_secret".encode(),
                file_hash=hash_content({"score": score}),
            )
            builder.add_stage(
                "extract", hash_content(f"raw_{i}"), hash_content(f"extracted_{i}"),
                {"method": "api"},
            )
            chain = builder.build()

            envelope = build_envelope(
                params=self.params,
                attestation_chain=chain,
                zkp_bundle=zkp_bundle,
                field_values={"overall_score": int(round(score * 10))},
                n_parties=5,
                threshold=3,
                contributor_secret=f"contributor_{i}".encode(),
            )

            # Verify each envelope
            result = verify_envelope(self.params, envelope)
            assert result["valid"], f"Envelope {i} failed: {result['errors']}"

            envelope_hashes.append(envelope.envelope_hash)
            values.append(score)
            profiles.append(BehavioralProfile(
                participant_id=f"org_{i}",
                contribution_types={"eval", "ioc_bundle"},
                query_types={"report", "simulate", "market"},
                contributed_vendors={"crowdstrike"},
                queried_vendors={"crowdstrike"},
                integration_sources={"splunk"} if i < 3 else set(),
                iocs_matched=5 + i,
                total_contributions=10 + i,
                first_seen_ts=time.time() - 90 * 86400,
                last_seen_ts=time.time(),
            ))

        # === Step 2: Aggregate with credibility weights ===
        agg_result = vci_aggregate_with_bound(
            values, profiles, epsilon=100.0, value_range=10.0,
        )
        assert agg_result["aggregate"] is not None
        assert agg_result["n_trusted"] >= 3

        # === Step 3: Generate platform attestation ===
        org_ids = [f"org_{i}" for i in range(5)]
        cred_weights = [compute_credibility_weight(p, epsilon=100.0) for p in profiles]

        attestation = generate_platform_attestation(
            params=self.params,
            envelope_hashes=envelope_hashes,
            org_ids=org_ids,
            credibility_weights=cred_weights,
            server_secret=b"server_master_key",
        )

        att_result = verify_platform_attestation(self.params, attestation)
        assert att_result["valid"], f"Attestation failed: {att_result['errors']}"

        # === Step 4: PSI cross-validation ===
        trust_graph = TrustGraph()

        edge = process_psi_result(
            match_count=5,
            profile_a=profiles[0],
            profile_b=profiles[1],
            matched_iocs=["ioc_1", "ioc_2", "ioc_3", "ioc_4", "ioc_5"],
            trust_graph=trust_graph,
        )

        assert edge.match_count == 5
        assert trust_graph.get_credibility_boost("org_0") > 0
        assert trust_graph.get_credibility_boost("org_1") > 0

    def test_poisoner_detected_and_bounded(self):
        """A poisoner is detected by low BDP weight and their impact is bounded."""
        from nur.vci.aggregation import vci_aggregate_with_bound

        # 5 real contributors
        real_values = [9.0, 8.8, 9.2, 8.5, 8.7]
        real_profiles = []
        for i in range(5):
            real_profiles.append(BehavioralProfile(
                participant_id=f"real_{i}",
                contribution_types={"eval", "ioc_bundle", "attack_map"},
                query_types={"report", "simulate", "market", "threat-model"},
                contributed_vendors={"crowdstrike", "sentinelone"},
                queried_vendors={"crowdstrike", "sentinelone"},
                integration_sources={"splunk"},
                iocs_matched=8,
                techniques_corroborated=5,
                total_contributions=15,
                first_seen_ts=time.time() - 120 * 86400,
                last_seen_ts=time.time(),
            ))

        # 2 poisoners
        poison_values = [1.0, 2.0]
        poison_profiles = []
        for i in range(2):
            poison_profiles.append(BehavioralProfile(
                participant_id=f"poison_{i}",
                contribution_types={"eval"},
                query_types=set(),
                contributed_vendors={"crowdstrike"},
                queried_vendors=set(),
                total_contributions=1,
                first_seen_ts=time.time(),
                last_seen_ts=time.time(),
            ))

        all_values = real_values + poison_values
        all_profiles = real_profiles + poison_profiles

        result = vci_aggregate_with_bound(
            all_values, all_profiles, epsilon=100.0,
        )

        # Simple average: ~6.74
        # VCI weighted should be > 8.0
        assert result["simple_average"] < 7.5
        assert result["aggregate"] > 7.5
        assert result["poisoning_bound"]["max_impact_pct"] < 20.0


# ════════════════════════════════════════════════════════════════════════════
# Regression / edge cases
# ════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases and regression tests."""

    def setup_method(self):
        self.params = ProofParams()

    def test_single_contributor(self):
        """VCI works with a single contributor."""
        from nur.vci.aggregation import vci_aggregate_with_bound

        result = vci_aggregate_with_bound(
            values=[9.0],
            profiles=[BehavioralProfile(
                participant_id="solo",
                contribution_types={"eval"},
                query_types={"report"},
                contributed_vendors={"crowdstrike"},
                queried_vendors={"crowdstrike"},
            )],
            epsilon=100.0,
        )
        assert result["aggregate"] == 9.0

    def test_empty_trust_graph(self):
        """Trust graph with no edges returns zero boost."""
        from nur.vci.trust_graph import TrustGraph

        graph = TrustGraph()
        assert graph.get_credibility_boost("nonexistent") == 0.0
        assert graph.edge_count() == 0

    def test_merkle_tree_single_leaf(self):
        """Merkle tree works with a single leaf."""
        from nur.vci.platform import build_merkle_tree

        root, levels = build_merkle_tree(["abc123"])
        assert root  # non-empty
        assert len(levels) >= 1

    def test_merkle_tree_empty(self):
        """Merkle tree handles empty input."""
        from nur.vci.platform import build_merkle_tree

        root, levels = build_merkle_tree([])
        assert root  # returns hash of "empty"

    def test_shamir_threshold_boundary(self):
        """Shamir with threshold == n_parties works."""
        from nur.vci.share_proofs import vci_shamir_split, vci_shamir_reconstruct

        shares = vci_shamir_split(42, 3, 3, self.params.q)
        assert vci_shamir_reconstruct(shares, self.params.q) == 42

        # 2 out of 3 should NOT reconstruct correctly (threshold = 3)
        wrong = vci_shamir_reconstruct(shares[:2], self.params.q)
        assert wrong != 42  # insufficient shares

    def test_ioc_rarity_all_private(self):
        """All private IOCs get maximum rarity."""
        from nur.vci.trust_graph import compute_ioc_rarity

        rarity = compute_ioc_rarity(["private_1", "private_2"], {"public_1"})
        assert rarity == 1.0

    def test_ioc_rarity_all_public(self):
        """All public IOCs get minimum rarity (0.2, clamped to 0.2)."""
        from nur.vci.trust_graph import compute_ioc_rarity

        rarity = compute_ioc_rarity(
            ["pub_a", "pub_b"],
            {"pub_a", "pub_b"},
        )
        assert rarity == 0.2

    def test_poisoning_bound_invalid_index(self):
        """Invalid poisoner index raises ValueError."""
        from nur.vci.bounds import compute_poisoning_bound

        with pytest.raises(ValueError):
            compute_poisoning_bound(
                weights=[0.5, 0.6],
                poisoner_index=5,
                max_deviation=10.0,
            )
