"""
Tests for the vigil Attested Data Transformation Chain (ADTC).

Verifies:
  - CDI chain derivation and integrity
  - Verifiable Absence Proofs (VAP)
  - Stage attestation evidence
  - Commitment scheme correctness
  - Full pipeline attestation
  - Chain verification (valid and tampered cases)
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

from vigil.attest.chain import (
    CDI, ChainBuilder, AttestationChain, hash_content, evidence_bytes,
)
from vigil.attest.stages import (
    attest_extraction, attest_anonymization, attest_dp, attest_submission,
    _scan_text_for_patterns,
)
from vigil.attest.verify import (
    verify_chain, verify_vap, VerificationResult,
)
from vigil.attest.commitments import (
    commit, verify_commitment,
    commit_field, verify_field_commitment,
    commit_batch, verify_batch,
)
from vigil.attest.pipeline import attest_pipeline, AttestedContribution
from vigil.models import (
    EvalRecord, AttackMap, IOCBundle, IOCEntry, ObservedTechnique,
    ContribContext,
)
from vigil.anonymize import anonymize


# ══════════════════════════════════════════════════════════════════════════════
# CDI and Chain tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCDI:
    def test_derivation_deterministic(self):
        cdi = CDI(value=b"\x00" * 32, stage=0)
        cdi1 = cdi.derive(b"evidence_1", 1)
        cdi2 = cdi.derive(b"evidence_1", 1)
        assert cdi1.value == cdi2.value

    def test_derivation_different_evidence(self):
        cdi = CDI(value=b"\x00" * 32, stage=0)
        cdi1 = cdi.derive(b"evidence_1", 1)
        cdi2 = cdi.derive(b"evidence_2", 1)
        assert cdi1.value != cdi2.value

    def test_hex_and_short(self):
        cdi = CDI(value=b"\xab" * 32, stage=0)
        assert len(cdi.hex) == 64
        assert len(cdi.short) == 16
        assert cdi.hex.startswith(cdi.short)


class TestChainBuilder:
    def test_build_empty_chain(self):
        builder = ChainBuilder(org_secret=b"test_key", file_hash="abc123")
        chain = builder.build()
        assert chain.stage_count == 0
        assert chain.root_cdi is not None
        assert chain.org_key_fingerprint is not None

    def test_build_multi_stage(self):
        builder = ChainBuilder(org_secret=b"test_key", file_hash="abc123")
        builder.add_stage("extract", "in1", "out1", {"fields": 5})
        builder.add_stage("anonymize", "out1", "out2", {"scrubbed": 3})
        chain = builder.build()
        assert chain.stage_count == 2
        assert chain.stages[0].stage_id == "extract"
        assert chain.stages[1].stage_id == "anonymize"

    def test_cdi_chain_links(self):
        builder = ChainBuilder(org_secret=b"test_key", file_hash="abc123")
        builder.add_stage("s1", "a", "b", {})
        builder.add_stage("s2", "b", "c", {})
        chain = builder.build()
        # Stage 1's prev_cdi should be root
        assert chain.stages[0].prev_cdi == chain.root_cdi
        # Stage 2's prev_cdi should be stage 1's cdi
        assert chain.stages[1].prev_cdi == chain.stages[0].cdi

    def test_different_keys_different_chains(self):
        b1 = ChainBuilder(org_secret=b"key_a", file_hash="same")
        b2 = ChainBuilder(org_secret=b"key_b", file_hash="same")
        b1.add_stage("s", "a", "b", {})
        b2.add_stage("s", "a", "b", {})
        c1 = b1.build()
        c2 = b2.build()
        # Different org keys = different root CDIs and different chains
        assert c1.root_cdi != c2.root_cdi
        assert c1.stages[0].cdi != c2.stages[0].cdi


class TestChainSerialization:
    def test_round_trip(self):
        builder = ChainBuilder(org_secret=b"test", file_hash="h")
        builder.add_stage("extract", "a", "b", {"count": 1})
        builder.add_stage("anon", "b", "c", {"scrubbed": 2})
        chain = builder.build()

        j = chain.to_json()
        restored = AttestationChain.from_json(j)

        assert restored.chain_id == chain.chain_id
        assert restored.root_cdi == chain.root_cdi
        assert restored.stage_count == 2
        assert restored.stages[0].evidence["count"] == 1
        assert restored.stages[1].evidence["scrubbed"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# Verifiable Absence Proofs (VAP)
# ══════════════════════════════════════════════════════════════════════════════

class TestVAP:
    def test_clean_text(self):
        """Clean text should pass VAP."""
        assert verify_vap("This is safe text with no PII") is True

    def test_email_detected(self):
        """Text with email should fail VAP."""
        assert verify_vap("Contact john@example.com") is False

    def test_ip_detected(self):
        """Text with IP should fail VAP."""
        assert verify_vap("Server at 192.168.1.1") is False

    def test_clean_payload_dict(self):
        """Dict payload with clean text should pass."""
        payload = {
            "data": {"vendor": "CrowdStrike", "notes": "Great detection"},
            "context": {"industry": "tech"},
        }
        assert verify_vap(payload) is True

    def test_dirty_payload_dict(self):
        """Dict payload with PII should fail."""
        payload = {
            "data": {"notes": "Contact admin@corp.com for access"},
        }
        assert verify_vap(payload) is False

    def test_scan_patterns(self):
        """Pattern scan should detect known patterns."""
        text = "Email john@test.com, IP 10.0.0.1, call 555-123-4567"
        scan = _scan_text_for_patterns(text)
        assert scan["email"] >= 1
        assert scan["ipv4"] >= 1
        assert scan["phone"] >= 1

    def test_anonymized_text_clean(self):
        """After anonymization, text should pass VAP."""
        record = EvalRecord(
            vendor="CrowdStrike", category="edr",
            top_strength="Great for 192.168.1.1 monitoring at john@corp.com",
            notes="Contact Dr. Smith via admin@internal.corp",
        )
        clean = anonymize(record)
        text = " ".join(filter(None, [clean.top_strength, clean.notes]))
        scan = _scan_text_for_patterns(text)
        # Email and IP should be scrubbed
        assert scan["email"] == 0
        assert scan["ipv4"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# Stage attestation tests
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractionAttestation:
    def test_eval_record(self):
        record = EvalRecord(
            vendor="CrowdStrike", category="edr",
            overall_score=9.0, detection_rate=98.0,
        )
        evidence = attest_extraction(b"raw file content", [record])
        assert evidence["contributions_extracted"] == 1
        assert evidence["source_file_hash"] is not None
        assert evidence["contributions"][0]["type"] == "eval"
        assert "overall_score" in evidence["contributions"][0]["fields_present"]

    def test_ioc_bundle(self):
        bundle = IOCBundle(
            iocs=[
                IOCEntry(ioc_type="ip", value_raw="10.0.0.1"),
                IOCEntry(ioc_type="domain", value_raw="evil.com"),
            ]
        )
        evidence = attest_extraction(b"raw", [bundle])
        assert evidence["contributions"][0]["ioc_count"] == 2
        assert evidence["contributions"][0]["has_raw_values"] is True


class TestAnonymizationAttestation:
    def test_scrub_counts(self):
        original = EvalRecord(
            vendor="Test", category="edr",
            top_strength="Contact john@corp.com at 192.168.1.1",
        )
        clean = anonymize(original)
        evidence = attest_anonymization(original, clean)
        assert evidence["total_items_scrubbed"] > 0
        assert evidence["vap"]["scan_clean"] is True

    def test_vap_in_evidence(self):
        original = EvalRecord(
            vendor="Test", category="edr",
            top_strength="Clean text no PII",
        )
        clean = anonymize(original)
        evidence = attest_anonymization(original, clean)
        assert evidence["vap"]["scan_clean"] is True
        assert all(v == 0 for v in evidence["vap"]["pattern_counts"].values())

    def test_ioc_attestation(self):
        original = IOCBundle(
            iocs=[IOCEntry(ioc_type="ip", value_raw="10.0.0.1")]
        )
        clean = anonymize(original)
        evidence = attest_anonymization(original, clean)
        assert evidence["ioc_attestation"]["all_raw_stripped"] is True
        assert evidence["ioc_attestation"]["all_hashed"] is True

    def test_numeric_fields_unchanged(self):
        """Without DP, numeric fields should not change."""
        original = EvalRecord(
            vendor="Test", category="edr",
            overall_score=8.5, detection_rate=95.0,
        )
        clean = anonymize(original)
        evidence = attest_anonymization(original, clean)
        assert evidence["numeric_fields_unchanged"] is True


class TestDPAttestation:
    def test_dp_evidence(self):
        record = EvalRecord(
            vendor="Test", category="edr",
            overall_score=8.0, detection_rate=95.0,
        )
        noised = anonymize(record, epsilon=1.0)
        evidence = attest_dp(record, noised, epsilon=1.0)
        assert evidence["epsilon"] == 1.0
        assert evidence["mechanism"] == "laplace"
        assert len(evidence["noised_fields"]) > 0
        assert len(evidence["value_commitments"]) > 0


class TestSubmissionAttestation:
    def test_basic(self):
        payload = {"vendor": "Test", "score": 8.0}
        evidence = attest_submission(payload, "https://api.example.com", "abc123")
        assert evidence["payload_hash"] is not None
        assert evidence["target_url"] == "https://api.example.com"
        assert evidence["receipt_hash"] == "abc123"


# ══════════════════════════════════════════════════════════════════════════════
# Commitment tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCommitments:
    def test_commit_and_verify(self):
        c = commit("secret_value")
        assert verify_commitment(c.commitment, "secret_value", c.randomness)
        assert not verify_commitment(c.commitment, "wrong_value", c.randomness)

    def test_hiding(self):
        """Same value should produce different commitments (randomized)."""
        c1 = commit("same")
        c2 = commit("same")
        assert c1.commitment != c2.commitment

    def test_field_commitment(self):
        c = commit_field("overall_score", 8.5)
        assert verify_field_commitment(c.commitment, "overall_score", 8.5, c.randomness)
        assert not verify_field_commitment(c.commitment, "overall_score", 9.0, c.randomness)
        assert not verify_field_commitment(c.commitment, "detection_rate", 8.5, c.randomness)

    def test_batch(self):
        fields = {"score": 8.5, "detection": 95.0, "fp_rate": 1.2}
        batch = commit_batch(fields)
        assert verify_batch(batch, fields)

    def test_batch_tampered(self):
        fields = {"score": 8.5, "detection": 95.0}
        batch = commit_batch(fields)
        tampered = {"score": 9.0, "detection": 95.0}
        assert not verify_batch(batch, tampered)

    def test_serialization(self):
        c = commit("value")
        d = c.to_dict()
        assert "commitment" in d
        assert "randomness" not in d  # Hidden by default


# ══════════════════════════════════════════════════════════════════════════════
# Chain verification tests
# ══════════════════════════════════════════════════════════════════════════════

class TestVerification:
    def _build_valid_chain(self) -> tuple[AttestationChain, dict]:
        """Helper: build a valid chain with clean payload."""
        builder = ChainBuilder(org_secret=b"test_key", file_hash="filehash")

        payload = {"vendor": "CrowdStrike", "score": 9.0, "notes": "Great tool"}
        payload_hash = hash_content(payload)

        builder.add_stage("extract", "filehash", "extracted_hash", {"count": 1})
        builder.add_stage("anonymize", "extracted_hash", payload_hash, {
            "vap": {"scan_clean": True},
            "total_items_scrubbed": 0,
        })

        chain = builder.build()
        return chain, payload

    def test_valid_chain(self):
        chain, payload = self._build_valid_chain()
        result = verify_chain(chain, payload)
        assert result.chain_intact is True
        assert result.payload_matches is True
        assert result.vap_clean is True
        assert result.valid is True

    def test_tampered_payload(self):
        chain, _ = self._build_valid_chain()
        tampered = {"vendor": "FakeVendor", "score": 10.0}
        result = verify_chain(chain, tampered)
        assert result.payload_matches is False

    def test_chain_without_payload(self):
        chain, _ = self._build_valid_chain()
        result = verify_chain(chain)
        assert result.chain_intact is True
        assert result.valid is True

    def test_dirty_payload_fails_vap(self):
        """Payload with PII should fail VAP even if chain is intact."""
        builder = ChainBuilder(org_secret=b"key", file_hash="h")
        dirty = {"notes": "Contact admin@corp.com for access"}
        builder.add_stage("extract", "h", hash_content(dirty), {})
        chain = builder.build()
        result = verify_chain(chain, dirty)
        assert result.vap_clean is False

    def test_serialized_chain_verification(self):
        """Verify a chain after JSON serialization round-trip."""
        chain, payload = self._build_valid_chain()
        j = chain.to_json()
        restored = AttestationChain.from_json(j)
        result = verify_chain(restored, payload)
        assert result.chain_intact is True
        assert result.valid is True


# ══════════════════════════════════════════════════════════════════════════════
# Full pipeline attestation tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAttestedPipeline:
    def _make_test_file(self, data: dict) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_eval_pipeline(self):
        path = self._make_test_file({
            "vendor": "CrowdStrike",
            "category": "edr",
            "overall_score": 9.0,
            "top_strength": "Great detection at admin@corp.com",
        })
        try:
            results = attest_pipeline(path)
            assert len(results) == 1
            ac = results[0]
            assert isinstance(ac, AttestedContribution)
            assert ac.attestation.stage_count >= 2  # extract + anonymize
            assert ac.payload is not None

            # Verify the chain
            vr = verify_chain(ac.attestation, ac.payload)
            assert vr.chain_intact is True
            assert vr.vap_clean is True
        finally:
            os.unlink(path)

    def test_eval_with_dp(self):
        path = self._make_test_file({
            "vendor": "Splunk",
            "category": "siem",
            "overall_score": 7.5,
            "detection_rate": 85.0,
        })
        try:
            results = attest_pipeline(path, epsilon=1.0)
            assert len(results) == 1
            ac = results[0]
            assert ac.attestation.stage_count >= 3  # extract + anonymize + dp

            # Check DP stage exists
            dp_stages = [s for s in ac.attestation.stages if s.stage_id == "dp"]
            assert len(dp_stages) == 1
            assert dp_stages[0].evidence["epsilon"] == 1.0
        finally:
            os.unlink(path)

    def test_ioc_bundle_pipeline(self):
        path = self._make_test_file({
            "iocs": [
                {"ioc_type": "ip", "value_raw": "192.168.1.100"},
                {"ioc_type": "domain", "value_raw": "evil.com"},
            ],
            "source": "incident",
        })
        try:
            results = attest_pipeline(path)
            assert len(results) == 1
            ac = results[0]

            # Check IOC attestation in anonymization stage
            anon_stage = [s for s in ac.attestation.stages if s.stage_id == "anonymize"][0]
            assert anon_stage.evidence["ioc_attestation"]["all_raw_stripped"] is True
            assert anon_stage.evidence["ioc_attestation"]["all_hashed"] is True
        finally:
            os.unlink(path)

    def test_json_round_trip(self):
        """AttestedContribution should survive JSON serialization."""
        path = self._make_test_file({
            "vendor": "Test", "category": "edr", "overall_score": 8.0,
        })
        try:
            results = attest_pipeline(path)
            ac = results[0]
            j = ac.to_json()
            restored = json.loads(j)
            assert "attestation" in restored
            assert "payload" in restored
            assert restored["attestation"]["version"] == "adtc-v1"
        finally:
            os.unlink(path)
