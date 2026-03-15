"""
Server-side ZKP verification.

The server can verify proofs without learning the underlying values.
This module provides a high-level verifier that accepts proof bundles
and returns structured verification results.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .proofs import ProofParams
from .contrib_proofs import (
    ContributionProofBundle,
    VerificationResult,
    EvalRecordProof,
    AttackMapProof,
    IOCBundleProof,
    _verify_bundle,
)


@dataclass
class ZKPVerificationResult:
    """Structured result from server-side ZKP verification."""

    valid: bool = False
    proof_count: int = 0
    verified_count: int = 0
    failed_proofs: list[dict] = field(default_factory=list)
    contribution_type: str = ""

    @property
    def summary(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return (
            f"ZKP Verification [{self.contribution_type}]: {status} "
            f"({self.verified_count}/{self.proof_count} proofs passed)"
        )

    @classmethod
    def from_verification_result(
        cls, vr: VerificationResult, contribution_type: str = "",
    ) -> ZKPVerificationResult:
        return cls(
            valid=vr.valid,
            proof_count=vr.proof_count,
            verified_count=vr.verified_count,
            failed_proofs=vr.failed_proofs,
            contribution_type=contribution_type,
        )


class ZKPVerifier:
    """Server-side verifier for contribution proof bundles.

    The verifier holds the public proof parameters and can verify
    any contribution proof bundle without access to the original data.
    """

    def __init__(self, params: ProofParams | None = None):
        self.params = params or ProofParams()

    def verify_contribution(
        self, proof_bundle: ContributionProofBundle | dict,
    ) -> ZKPVerificationResult:
        """Verify a single contribution proof bundle.

        Accepts either a ContributionProofBundle or a dict (from JSON).
        """
        if isinstance(proof_bundle, dict):
            proof_bundle = ContributionProofBundle.from_dict(proof_bundle)

        vr = _verify_bundle(self.params, proof_bundle)
        return ZKPVerificationResult.from_verification_result(
            vr, proof_bundle.contribution_type,
        )

    def verify_batch(
        self, proof_bundles: list[ContributionProofBundle | dict],
    ) -> list[ZKPVerificationResult]:
        """Verify multiple proof bundles. Returns list of results."""
        return [self.verify_contribution(pb) for pb in proof_bundles]
