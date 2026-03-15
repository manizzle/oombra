"""
vigil Attested Data Transformation Chain (ADTC)
=================================================

A novel cryptographic protocol for proving that data was correctly
privacy-processed without revealing the original data.

ANALOGY
-------
In DICE/TPM/SGX, you attest that CODE ran correctly on HARDWARE.
In vigil ADTC, you attest that DATA TRANSFORMATIONS were correctly
applied to CONTENT — creating an unforgeable provenance chain from
raw threat intel to anonymized contribution.

THE PROBLEM
-----------
Organizations don't share threat intel because they can't verify privacy
guarantees. "Trust us, we scrubbed it" isn't enough for legal, compliance,
or peer organizations. You need mathematical proof.

THE PROTOCOL
------------
Like DICE (Device Identifier Composition Engine), each step in the vigil
pipeline produces a Compound Device Identifier (CDI) that chains to the
next stage. Each stage attests:

  1. WHAT transformation was applied (extraction, anonymization, DP, etc.)
  2. THAT the transformation was correctly applied (deterministic verification)
  3. HOW the output relates to the input (hash chain, not content)

Chain structure:

    [Raw File] ──→ [Extract] ──→ [Anonymize] ──→ [DP Noise] ──→ [Submit]
        │              │              │               │              │
       CDI₀          CDI₁           CDI₂            CDI₃           CDI₄
        │              │              │               │              │
        └──────────────┴──────────────┴───────────────┴──────────────┘
                              Attestation Chain

    CDI_n = HMAC(CDI_{n-1}, stage_evidence_n)

NOVEL PROPERTIES
----------------
1. **Verifiable Absence Proofs (VAP)**: Prove that NO instance of a PII
   pattern exists in the output. The anonymization attestation runs all
   scrub patterns and commits to zero matches — verifiable by any party
   with the final output.

2. **Transformation Attestation**: Not just "I have this data" but
   "this data went through this specific transformation pipeline."
   Each stage's evidence is bound to the previous, creating an
   unforgeable chain.

3. **Composable Privacy Accounting**: DP budget attestations accumulate
   across sessions. Each contribution carries a signed epsilon receipt
   that chains to the privacy budget.

4. **Bilateral Verification**: Both contributor and receiver independently
   verify the chain. The server re-runs pattern scans on received data
   and confirms the attestation matches.

5. **Content-Hiding Provenance**: The full chain reveals the PROCESS
   (extraction → anonymization → DP → submission) without revealing
   the original CONTENT. You can prove "I applied epsilon=1.0 DP noise"
   without revealing the pre-noise values.

VERIFICATION
------------
Given: attestation chain C, final payload P

  1. Re-hash P → H(P), verify H(P) == chain's final payload hash
  2. Re-run scrub patterns on P → verify 0 matches (VAP check)
  3. Verify each CDI link: CDI_n == HMAC(CDI_{n-1}, evidence_n)
  4. Verify the root CDI derives from a known org key
  5. Verify DP attestation: epsilon, field count, budget reference

Any party with the chain and payload can verify steps 1-3.
Only the contributor can produce the chain (requires org key).

UPGRADE PATH
-------------
Phase 0: Hash-based commitments + HMAC chains (current — stdlib only)
Phase 6: Pedersen commitments + range proofs for DP noise verification
Phase 7: ZK-SNARKs for full pipeline verification without payload access

USAGE
-----
    from vigil.attest import attest_pipeline, verify_chain

    # Producer side
    chain = attest_pipeline("threat_data.json", epsilon=1.0)
    # chain.attestation contains the full ADTC
    # chain.payload contains the anonymized contribution

    # Verifier side (server, auditor, peer)
    result = verify_chain(chain.attestation, chain.payload)
    assert result.valid
    assert result.vap_clean  # No PII patterns in output
"""

from .chain import (
    AttestationChain,
    CDI,
    StageAttestation,
    ChainBuilder,
)
from .stages import (
    attest_extraction,
    attest_anonymization,
    attest_dp,
    attest_submission,
)
from .verify import (
    verify_chain,
    verify_vap,
    VerificationResult,
)
from .pipeline import attest_pipeline, AttestedContribution
