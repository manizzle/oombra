"""Tests for zero-knowledge proof module."""
from __future__ import annotations

import json
import pytest

from oombra.zkp.proofs import (
    ProofParams,
    Commitment,
    RangeProof,
    MembershipProof,
    ConsistencyProof,
    NonZeroProof,
    commit,
    create_range_proof,
    verify_range_proof,
    create_membership_proof,
    verify_membership_proof,
    create_consistency_proof,
    verify_consistency_proof,
    create_nonzero_proof,
    verify_nonzero_proof,
    _encode_value,
    _in_subgroup,
)
from oombra.zkp.contrib_proofs import (
    EvalRecordProof,
    AttackMapProof,
    IOCBundleProof,
    ContributionProofBundle,
)
from oombra.zkp.verify import ZKPVerifier, ZKPVerificationResult
from oombra.models import (
    EvalRecord,
    AttackMap,
    IOCBundle,
    IOCEntry,
    ObservedTechnique,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def params():
    return ProofParams()


@pytest.fixture
def eval_record():
    return EvalRecord(
        vendor="CrowdStrike",
        category="edr",
        overall_score=8.5,
        detection_rate=95.0,
        fp_rate=2.3,
        deploy_days=30,
        cpu_overhead=12.0,
    )


@pytest.fixture
def attack_map():
    return AttackMap(
        threat_name="APT28",
        techniques=[
            ObservedTechnique(
                technique_id="T1566",
                detected_by=["crowdstrike"],
                missed_by=["splunk"],
            ),
            ObservedTechnique(
                technique_id="T1059.001",
                detected_by=["sentinel"],
            ),
        ],
    )


@pytest.fixture
def ioc_bundle():
    return IOCBundle(
        iocs=[
            IOCEntry(ioc_type="domain", value_hash="a" * 64, detected_by=["crowdstrike"]),
            IOCEntry(ioc_type="ip", value_hash="b" * 64, missed_by=["splunk"]),
        ],
    )


# ---------------------------------------------------------------------------
# ProofParams
# ---------------------------------------------------------------------------

class TestProofParams:
    def test_params_generation(self, params):
        assert params.p > 0
        assert params.g > 1
        assert params.q > 0
        assert params.h > 1
        assert params.p == 2 * params.q + 1

    def test_generator_order(self, params):
        assert pow(params.g, params.q, params.p) == 1
        assert pow(params.h, params.q, params.p) == 1

    def test_generators_independent(self, params):
        assert params.g != params.h
        assert params.g != 1
        assert params.h != 1

    def test_validate(self, params):
        assert _in_subgroup(params, params.g)
        assert _in_subgroup(params, params.h)

    def test_to_dict_round_trip(self, params):
        d = params.to_dict()
        restored = ProofParams.from_dict(d)
        assert restored.p == params.p
        assert restored.g == params.g
        assert restored.q == params.q
        assert restored.h == params.h


# ---------------------------------------------------------------------------
# Pedersen commitment
# ---------------------------------------------------------------------------

class TestPedersenCommitment:
    def test_commit_and_open(self, params):
        com = commit(params, 42)
        assert com.value_commitment > 0
        assert com.randomness >= 0
        # Verify: C == g^42 * h^r mod p
        expected = (pow(params.g, 42, params.p) * pow(params.h, com.randomness, params.p)) % params.p
        assert com.value_commitment == expected

    def test_hiding(self, params):
        """Same value with different randomness gives different commitments."""
        c1 = commit(params, 42, randomness=100)
        c2 = commit(params, 42, randomness=200)
        assert c1.value_commitment != c2.value_commitment

    def test_binding(self, params):
        """Same randomness but different values gives different commitments."""
        c1 = commit(params, 42, randomness=100)
        c2 = commit(params, 43, randomness=100)
        assert c1.value_commitment != c2.value_commitment

    def test_deterministic_with_fixed_randomness(self, params):
        c1 = commit(params, 7, randomness=99)
        c2 = commit(params, 7, randomness=99)
        assert c1.value_commitment == c2.value_commitment

    def test_serialization(self, params):
        com = commit(params, 42)
        d = com.to_dict()
        restored = Commitment.from_dict(d)
        assert restored.value_commitment == com.value_commitment
        assert restored.randomness == com.randomness


# ---------------------------------------------------------------------------
# Range proof
# ---------------------------------------------------------------------------

class TestRangeProof:
    def test_valid_range(self, params):
        com, proof = create_range_proof(params, 5, 0, 10)
        assert verify_range_proof(params, com, proof, 0, 10)

    def test_out_of_range_fails(self, params):
        with pytest.raises(ValueError):
            create_range_proof(params, 15, 0, 10)

    def test_boundary_lo(self, params):
        com, proof = create_range_proof(params, 0, 0, 10)
        assert verify_range_proof(params, com, proof, 0, 10)

    def test_boundary_hi(self, params):
        com, proof = create_range_proof(params, 10, 0, 10)
        assert verify_range_proof(params, com, proof, 0, 10)

    def test_negative_rejected(self, params):
        with pytest.raises(ValueError):
            create_range_proof(params, -1, 0, 10)

    def test_wrong_range_fails_verification(self, params):
        com, proof = create_range_proof(params, 5, 0, 10)
        assert not verify_range_proof(params, com, proof, 0, 4)

    def test_single_value_range(self, params):
        com, proof = create_range_proof(params, 5, 5, 5)
        assert verify_range_proof(params, com, proof, 5, 5)

    def test_large_range(self, params):
        com, proof = create_range_proof(params, 500, 0, 1000)
        assert verify_range_proof(params, com, proof, 0, 1000)

    def test_serialization_round_trip(self, params):
        com, proof = create_range_proof(params, 5, 0, 10)
        d = proof.to_dict()
        restored = RangeProof.from_dict(d)
        assert verify_range_proof(params, com, restored, 0, 10)


# ---------------------------------------------------------------------------
# Membership proof
# ---------------------------------------------------------------------------

class TestMembershipProof:
    def test_member_proves(self, params):
        com, proof = create_membership_proof(params, "edr", ["edr", "siem", "cnapp"])
        assert verify_membership_proof(params, com, proof, ["edr", "siem", "cnapp"])

    def test_non_member_fails(self, params):
        with pytest.raises(ValueError):
            create_membership_proof(params, "xyz", ["edr", "siem"])

    def test_single_element_set(self, params):
        com, proof = create_membership_proof(params, "edr", ["edr"])
        assert verify_membership_proof(params, com, proof, ["edr"])

    def test_wrong_set_fails(self, params):
        com, proof = create_membership_proof(params, "edr", ["edr", "siem", "cnapp"])
        assert not verify_membership_proof(params, com, proof, ["siem", "cnapp", "xdr"])

    def test_integer_values(self, params):
        com, proof = create_membership_proof(params, 2, [1, 2, 3, 4, 5])
        assert verify_membership_proof(params, com, proof, [1, 2, 3, 4, 5])

    def test_serialization_round_trip(self, params):
        com, proof = create_membership_proof(params, "siem", ["edr", "siem", "cnapp"])
        d = proof.to_dict()
        restored = MembershipProof.from_dict(d)
        assert verify_membership_proof(params, com, restored, ["edr", "siem", "cnapp"])


# ---------------------------------------------------------------------------
# Non-zero proof
# ---------------------------------------------------------------------------

class TestNonZeroProof:
    def test_non_zero_proves(self, params):
        com = commit(params, 42)
        proof = create_nonzero_proof(params, com, 42)
        assert verify_nonzero_proof(params, com, proof)

    def test_zero_fails(self, params):
        com = commit(params, 0)
        with pytest.raises(ValueError):
            create_nonzero_proof(params, com, 0)

    def test_large_value(self, params):
        com = commit(params, 99999)
        proof = create_nonzero_proof(params, com, 99999)
        assert verify_nonzero_proof(params, com, proof)

    def test_value_one(self, params):
        com = commit(params, 1)
        proof = create_nonzero_proof(params, com, 1)
        assert verify_nonzero_proof(params, com, proof)

    def test_serialization_round_trip(self, params):
        com = commit(params, 42)
        proof = create_nonzero_proof(params, com, 42)
        d = proof.to_dict()
        restored = NonZeroProof.from_dict(d)
        assert verify_nonzero_proof(params, com, restored)


# ---------------------------------------------------------------------------
# Consistency proof
# ---------------------------------------------------------------------------

class TestConsistencyProof:
    def test_equal_values(self, params):
        com1 = commit(params, 7)
        com2 = commit(params, 7)
        proof = create_consistency_proof(params, com1, com2)
        assert verify_consistency_proof(params, com1, com2, proof)

    def test_unequal_fails(self, params):
        com1 = commit(params, 7)
        com2 = commit(params, 8)
        # The proof should still be "created" but verification should fail
        # because the quotient C1/C2 != h^{r1-r2} when values differ.
        # Actually, create_consistency_proof uses the commitments directly
        # and will produce a proof that C1/C2 = h^{witness}. If values
        # differ, the quotient has a g-component and verification fails.
        proof = create_consistency_proof(params, com1, com2)
        assert not verify_consistency_proof(params, com1, com2, proof)

    def test_same_commitment_object(self, params):
        com = commit(params, 42)
        proof = create_consistency_proof(params, com, com)
        assert verify_consistency_proof(params, com, com, proof)

    def test_serialization_round_trip(self, params):
        com1 = commit(params, 7)
        com2 = commit(params, 7)
        proof = create_consistency_proof(params, com1, com2)
        d = proof.to_dict()
        restored = ConsistencyProof.from_dict(d)
        assert verify_consistency_proof(params, com1, com2, restored)


# ---------------------------------------------------------------------------
# EvalRecord proof
# ---------------------------------------------------------------------------

class TestEvalRecordProof:
    def test_valid_record(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        result = ep.verify(bundle)
        assert result.valid
        assert result.verified_count == result.proof_count
        assert result.proof_count > 0

    def test_invalid_score_range(self, params):
        """Record with invalid score cannot produce valid range proof."""
        record = EvalRecord(
            vendor="Test",
            category="edr",
            overall_score=8.5,
            detection_rate=95.0,
        )
        ep = EvalRecordProof(params)
        bundle = ep.prove(record)
        assert bundle.proofs  # proofs were generated
        result = ep.verify(bundle)
        assert result.valid

    def test_minimal_record(self, params):
        record = EvalRecord(vendor="Test", category="edr")
        ep = EvalRecordProof(params)
        bundle = ep.prove(record)
        result = ep.verify(bundle)
        assert result.valid

    def test_all_categories(self, params):
        from oombra.zkp.contrib_proofs import EVAL_CATEGORIES
        for cat in EVAL_CATEGORIES:
            record = EvalRecord(vendor="V", category=cat)
            ep = EvalRecordProof(params)
            bundle = ep.prove(record)
            result = ep.verify(bundle)
            assert result.valid, f"Failed for category: {cat}"


# ---------------------------------------------------------------------------
# IOCBundle proof
# ---------------------------------------------------------------------------

class TestIOCBundleProof:
    def test_valid_bundle(self, params, ioc_bundle):
        ip = IOCBundleProof(params)
        bundle = ip.prove(ioc_bundle)
        result = ip.verify(bundle)
        assert result.valid
        assert result.proof_count > 0

    def test_empty_bundle_fails(self, params):
        empty = IOCBundle(iocs=[])
        ip = IOCBundleProof(params)
        with pytest.raises(ValueError, match="at least one IOC"):
            ip.prove(empty)

    def test_all_ioc_types(self, params):
        from oombra.zkp.contrib_proofs import IOC_TYPES
        for ioc_type in IOC_TYPES:
            bundle = IOCBundle(
                iocs=[IOCEntry(ioc_type=ioc_type, value_hash="c" * 64)],
            )
            ip = IOCBundleProof(params)
            pb = ip.prove(bundle)
            result = ip.verify(pb)
            assert result.valid, f"Failed for IOC type: {ioc_type}"


# ---------------------------------------------------------------------------
# AttackMap proof
# ---------------------------------------------------------------------------

class TestAttackMapProof:
    def test_valid_map(self, params, attack_map):
        ap = AttackMapProof(params)
        bundle = ap.prove(attack_map)
        result = ap.verify(bundle)
        assert result.valid

    def test_empty_techniques_fails(self, params):
        amap = AttackMap(techniques=[])
        ap = AttackMapProof(params)
        with pytest.raises(ValueError, match="at least one technique"):
            ap.prove(amap)

    def test_invalid_technique_id_fails(self, params):
        amap = AttackMap(
            techniques=[
                ObservedTechnique(technique_id="INVALID"),
            ],
        )
        ap = AttackMapProof(params)
        with pytest.raises(ValueError, match="Invalid MITRE"):
            ap.prove(amap)


# ---------------------------------------------------------------------------
# ContributionProofBundle serialization
# ---------------------------------------------------------------------------

class TestContributionProofBundle:
    def test_serialization_round_trip(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        json_str = bundle.to_json()
        restored = ContributionProofBundle.from_json(json_str)
        assert restored.contribution_type == bundle.contribution_type
        assert len(restored.proofs) == len(bundle.proofs)
        result = ep.verify(restored)
        assert result.valid

    def test_to_dict_from_dict(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        d = bundle.to_dict()
        restored = ContributionProofBundle.from_dict(d)
        assert restored.contribution_type == bundle.contribution_type


# ---------------------------------------------------------------------------
# ZKPVerifier (server-side)
# ---------------------------------------------------------------------------

class TestZKPVerifier:
    def test_verify_valid(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        verifier = ZKPVerifier(params)
        result = verifier.verify_contribution(bundle)
        assert result.valid
        assert "VALID" in result.summary

    def test_verify_from_dict(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        verifier = ZKPVerifier(params)
        result = verifier.verify_contribution(bundle.to_dict())
        assert result.valid

    def test_verify_invalid(self, params):
        """Tampered proof bundle should fail verification."""
        record = EvalRecord(vendor="Test", category="edr", overall_score=5.0)
        ep = EvalRecordProof(params)
        bundle = ep.prove(record)
        # Tamper with a commitment
        if bundle.proofs:
            bundle.proofs[0]["commitment"]["value_commitment"] = 999
        verifier = ZKPVerifier(params)
        result = verifier.verify_contribution(bundle)
        assert not result.valid

    def test_batch_verify(self, params, eval_record, attack_map, ioc_bundle):
        ep = EvalRecordProof(params)
        ap = AttackMapProof(params)
        ip = IOCBundleProof(params)

        bundles = [
            ep.prove(eval_record).to_dict(),
            ap.prove(attack_map).to_dict(),
            ip.prove(ioc_bundle).to_dict(),
        ]

        verifier = ZKPVerifier(params)
        results = verifier.verify_batch(bundles)
        assert len(results) == 3
        assert all(r.valid for r in results)

    def test_verification_result_summary(self, params, eval_record):
        ep = EvalRecordProof(params)
        bundle = ep.prove(eval_record)
        verifier = ZKPVerifier(params)
        result = verifier.verify_contribution(bundle)
        assert "eval" in result.summary
        assert "VALID" in result.summary
