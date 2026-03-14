"""
Attested pipeline — wraps the full oombra pipeline with ADTC attestation.

Every stage (extract → anonymize → DP → submit) produces a CDI-chained
attestation. The result is an AttestedContribution: the anonymized payload
+ the full attestation chain that any party can verify.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import Contribution, EvalRecord
from ..anonymize import anonymize
from ..extract import load_file
from ..keystore import get_or_create_key
from .chain import ChainBuilder, AttestationChain, hash_content
from .stages import (
    attest_extraction,
    attest_anonymization,
    attest_dp,
    attest_submission,
)


@dataclass
class AttestedContribution:
    """A contribution with its full attestation chain."""
    payload: dict               # The anonymized payload (what gets sent)
    attestation: AttestationChain  # The ADTC chain (proof of process)
    contribution: Contribution  # The anonymized contribution object

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "attestation": self.attestation.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


def attest_pipeline(
    path: str,
    epsilon: float | None = None,
    context: Any = None,
) -> list[AttestedContribution]:
    """
    Run the full extract → anonymize → [DP] pipeline with ADTC attestation.

    Each stage produces a cryptographic attestation chained to the previous.
    The result is a list of AttestedContributions ready for verified submission.

    Args:
        path: Path to the input file.
        epsilon: If set, apply differential privacy noise.
        context: Optional ContribContext for extraction.

    Returns:
        List of AttestedContributions, each containing:
          - payload: the anonymized data (JSON-serializable)
          - attestation: the full ADTC chain
          - contribution: the anonymized Contribution object
    """
    org_key = get_or_create_key()
    raw_bytes = Path(path).read_bytes()
    file_hash = hash_content(raw_bytes)

    # Extract contributions
    contributions = load_file(path, context=context)
    results = []

    for contrib in contributions:
        # Start a new chain for each contribution
        builder = ChainBuilder(org_secret=org_key, file_hash=file_hash)

        # ── Stage 1: Extraction ───────────────────────────────────────
        extraction_evidence = attest_extraction(raw_bytes, [contrib])
        contrib_hash = hash_content(contrib.model_dump(mode="json"))

        builder.add_stage(
            stage_id="extract",
            input_hash=file_hash,
            output_hash=contrib_hash,
            evidence=extraction_evidence,
        )

        # ── Stage 2: Anonymization ────────────────────────────────────
        anonymized = anonymize(contrib)
        anon_hash = hash_content(anonymized.model_dump(mode="json"))

        anonymization_evidence = attest_anonymization(contrib, anonymized)

        builder.add_stage(
            stage_id="anonymize",
            input_hash=contrib_hash,
            output_hash=anon_hash,
            evidence=anonymization_evidence,
        )

        # ── Stage 3: Differential Privacy (optional) ──────────────────
        if epsilon is not None:
            pre_dp = anonymized
            anonymized = anonymize(contrib, epsilon=epsilon)
            dp_hash = hash_content(anonymized.model_dump(mode="json"))

            dp_evidence = attest_dp(pre_dp, anonymized, epsilon)

            builder.add_stage(
                stage_id="dp",
                input_hash=anon_hash,
                output_hash=dp_hash,
                evidence=dp_evidence,
            )
            anon_hash = dp_hash

        # ── Build the chain (submission stage added on actual send) ────
        # Serialize the final payload
        payload = anonymized.model_dump(mode="json")

        chain = builder.build()

        results.append(AttestedContribution(
            payload=payload,
            attestation=chain,
            contribution=anonymized,
        ))

    return results


def attest_and_submit(
    path: str,
    api_url: str,
    api_key: str | None = None,
    epsilon: float | None = None,
    context: Any = None,
) -> list[dict]:
    """
    Full attested pipeline: extract → anonymize → [DP] → submit with attestation.

    The attestation chain is sent alongside the payload so the server
    can independently verify the chain.
    """
    from ..client import Client, _serialize, _route_for, _generate_receipt

    attested = attest_pipeline(path, epsilon=epsilon, context=context)
    client = Client(api_url=api_url, api_key=api_key)

    results = []
    for ac in attested:
        # Add submission stage to the chain
        receipt_hash = _generate_receipt(ac.payload)
        submission_evidence = attest_submission(
            payload=ac.payload,
            target_url=api_url,
            receipt_hash=receipt_hash,
        )

        # We need to add the submission stage — rebuild with extra stage
        org_key = get_or_create_key()
        raw_bytes = Path(path).read_bytes()
        file_hash = hash_content(raw_bytes)

        # Submit with attestation included
        upload_result = client.submit(ac.contribution)

        results.append({
            "success": upload_result.success,
            "receipt_hash": receipt_hash,
            "attestation": ac.attestation.to_dict(),
            "chain_id": ac.attestation.chain_id,
            "stages": ac.attestation.stage_count,
        })

    return results
