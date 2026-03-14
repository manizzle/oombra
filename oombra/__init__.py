"""
oombra — privacy-preserving federated threat intelligence sharing.

Anonymize locally. Share selectively. Contribute to the collective.

Quick start:
    from oombra import load_file, anonymize, submit

    contribs = load_file("mitre_eval.json")
    clean    = [anonymize(c) for c in contribs]
    results  = [submit(c, api_url="https://your-platform.example.com") for c in clean]

Or the full pipeline with terminal review:
    from oombra import pipeline
    pipeline("apt28_campaign.stix.json", api_url="https://your-platform.example.com")
"""
from .models import (
    EvalRecord, AttackMap, IOCBundle, ObservedTechnique, IOCEntry,
    ContribContext, Industry, OrgSize, Role, Contribution,
)
from .extract import load_file, load_dict
from .anonymize import (
    anonymize, scrub, strip_pii, strip_security,
    bucket_industry, bucket_org_size, bucket_role, bucket_context_dict,
    hash_ioc,
)
from .review import render, prompt_approve
from .client import Client, UploadResult


def submit(
    contrib: "Contribution",
    api_url: str,
    api_key: str | None = None,
) -> "UploadResult":
    """Submit a single already-anonymized contribution to any compatible endpoint."""
    return Client(api_url=api_url, api_key=api_key).submit(contrib)


def pipeline(
    path: str,
    api_url: str,
    context: "ContribContext | None" = None,
    api_key: str | None = None,
    auto_approve: bool = False,
) -> "list[UploadResult]":
    """
    Full extract -> anonymize -> review -> submit pipeline for a file.
    Nothing leaves the machine until the user approves at the review step.
    """
    contribs = load_file(path, context=context)
    clean    = [anonymize(c) for c in contribs]
    results  = []
    for c in clean:
        if auto_approve or prompt_approve(c):
            results.append(submit(c, api_url=api_url, api_key=api_key))
        else:
            print("  Skipped.")
            results.append(UploadResult(success=False, status_code=0, error="user skipped"))
    return results
