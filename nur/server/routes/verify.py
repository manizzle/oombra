"""Verification endpoints — anyone can verify proofs."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(tags=["verify"])


def _get_engine():
    from ..app import get_proof_engine
    return get_proof_engine()


@router.post("/verify/receipt")
async def verify_receipt_endpoint(body: dict):
    """Verify a contribution receipt's Merkle inclusion proof."""
    from ..proofs import ContributionReceipt, verify_receipt
    try:
        receipt = ContributionReceipt.from_dict(body)
    except (TypeError, KeyError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid receipt: {e}")

    valid = verify_receipt(receipt)
    return {
        "valid": valid,
        "receipt_id": receipt.receipt_id,
        "commitment_hash": receipt.commitment_hash,
        "merkle_root": receipt.merkle_root,
    }


@router.get("/verify/aggregate/{vendor}")
async def verify_aggregate(vendor: str, request: Request, category: str | None = None):
    """Generate and verify an aggregate proof for a vendor."""
    from ..app import track_query
    track_query(request, "verify", [vendor])
    from ..proofs import verify_aggregate_proof
    engine = _get_engine()
    proof = engine.prove_aggregate(vendor, category)
    if not proof:
        raise HTTPException(status_code=404, detail=f"No aggregate found for vendor '{vendor}'")

    verification = verify_aggregate_proof(proof, expected_root=engine.merkle_root)
    return {
        "proof": proof.to_dict(),
        "verification": verification,
    }


@router.get("/proof/stats")
async def proof_stats():
    """Platform-wide proof statistics."""
    engine = _get_engine()
    return engine.get_platform_stats()


@router.post("/category/propose")
async def propose_category(body: dict):
    """Propose a new category by submitting its hash (blind)."""
    engine = _get_engine()
    category_hash = body.get("category_hash", "")
    category_type = body.get("category_type", "")
    submitter_id = body.get("submitter_id", "")
    if not category_hash or not category_type or not submitter_id:
        raise HTTPException(status_code=400, detail="Required: category_hash, category_type, submitter_id")
    result = engine.blind_categories.propose_category(category_hash, category_type, submitter_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/category/check/{category_hash}")
async def check_category(category_hash: str):
    """Check if a proposed category has reached the discovery threshold."""
    engine = _get_engine()
    return engine.blind_categories.check_threshold(category_hash)


@router.post("/category/reveal")
async def reveal_category(body: dict):
    """Vote to reveal a category's plaintext name."""
    engine = _get_engine()
    category_hash = body.get("category_hash", "")
    plaintext = body.get("plaintext", "")
    salt = body.get("salt", "")
    submitter_id = body.get("submitter_id", "")
    if not all([category_hash, plaintext, salt, submitter_id]):
        raise HTTPException(status_code=400, detail="Required: category_hash, plaintext, salt, submitter_id")
    result = engine.blind_categories.vote_reveal(category_hash, plaintext, salt, submitter_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/category/pending")
async def list_pending_categories():
    """List pending categories awaiting reveal."""
    engine = _get_engine()
    return {
        "pending": engine.blind_categories.get_pending_categories(),
        "revealed": engine.blind_categories.get_revealed_categories(),
    }


@router.get("/proof/bdp-stats")
async def bdp_stats():
    """BDP behavioral profile statistics (aggregate only, no individual profiles)."""
    from ..app import _profiles
    from ...behavioral_dp import compute_credibility_weight

    if not _profiles:
        return {
            "total_profiles": 0,
            "avg_credibility": None,
            "trusted_count": 0,
            "untrusted_count": 0,
            "credibility_distribution": {
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }

    weights = []
    for profile in _profiles.values():
        w = compute_credibility_weight(profile)
        weights.append(w)

    trusted = sum(1 for w in weights if w >= 0.4)

    return {
        "total_profiles": len(_profiles),
        "avg_credibility": round(sum(weights) / len(weights), 3) if weights else None,
        "trusted_count": trusted,
        "untrusted_count": len(weights) - trusted,
        "credibility_distribution": {
            "high": sum(1 for w in weights if w >= 0.7),
            "medium": sum(1 for w in weights if 0.4 <= w < 0.7),
            "low": sum(1 for w in weights if w < 0.4),
        },
    }
