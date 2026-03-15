"""
GitHub open-source security tool scraper.

Searches the GitHub API for security-related repositories matching vendor names.
Extracts stars, forks, open issues, and last update as popularity/activity signals.
No authentication required (60 req/hour for unauthenticated, 5000 with token).

Source: https://api.github.com/search/repositories
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

# Vendors -- same list as reddit.py (vendor_id, display_name, category)
VENDORS = [
    # EDR
    ("crowdstrike",   "CrowdStrike Falcon",              "edr"),
    ("sentinelone",   "SentinelOne",                     "edr"),
    ("ms-defender",   "Microsoft Defender for Endpoint",  "edr"),
    ("cortex-xdr",    "Palo Alto Cortex XDR",            "edr"),
    ("sophos",        "Sophos Intercept X",              "edr"),
    ("bitdefender",   "Bitdefender GravityZone",         "edr"),
    ("carbon-black",  "VMware Carbon Black",             "edr"),
    ("cybereason",    "Cybereason",                      "edr"),
    ("eset",          "ESET Protect",                    "edr"),
    ("trend-apex",    "Trend Micro Apex One",            "edr"),
    # SIEM
    ("splunk",        "Splunk Enterprise Security",      "siem"),
    ("ms-sentinel",   "Microsoft Sentinel",              "siem"),
    ("qradar",        "IBM QRadar",                      "siem"),
    ("elastic-siem",  "Elastic SIEM",                    "siem"),
    # CNAPP
    ("wiz",           "Wiz",                             "cnapp"),
    ("prisma-cloud",  "Palo Alto Prisma Cloud",          "cnapp"),
    ("snyk",          "Snyk",                            "cnapp"),
    # IAM
    ("okta",          "Okta",                            "iam"),
    ("entra-id",      "Microsoft Entra ID",              "iam"),
    # PAM
    ("cyberark-pam",  "CyberArk",                       "pam"),
    ("beyondtrust",   "BeyondTrust",                     "pam"),
    # Email
    ("proofpoint",    "Proofpoint",                      "email"),
    ("mimecast",      "Mimecast",                        "email"),
    # ZTNA
    ("zscaler",       "Zscaler",                         "ztna"),
    ("cloudflare-zt", "Cloudflare Zero Trust",           "ztna"),
    # VM
    ("qualys",        "Qualys",                          "vm"),
    ("tenable",       "Tenable Nessus",                  "vm"),
    # NDR
    ("darktrace",     "Darktrace",                       "ndr"),
    ("vectra",        "Vectra AI",                       "ndr"),
]

GH_API = "https://api.github.com/search/repositories"


def _search_github(vendor: str) -> list[dict]:
    """Search GitHub for security-related repos matching a vendor name."""
    encoded = urllib.request.quote(f"{vendor} security")
    url = f"{GH_API}?q={encoded}&sort=stars&per_page=5"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "oombra-scraper/1.0")
    req.add_header("Accept", "application/vnd.github+json")

    # Use token if available (raises rate limit from 10 to 30 req/min)
    gh_token = os.getenv("GITHUB_TOKEN")
    if gh_token:
        req.add_header("Authorization", f"Bearer {gh_token}")

    time.sleep(3.0)  # stay under unauthenticated rate limit (10 req/min)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data.get("items", [])
    except Exception:
        return []


def _score_from_stars(stars: int) -> float:
    """Compute a 0-10 popularity score from star count. Rough heuristic."""
    return round(min(10.0, stars / 1000.0), 1)


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Scrape GitHub for open-source security tool signals."""
    evals: list[dict] = []

    for vendor_id, display, category in VENDORS:
        # Use the first word of the display name for a focused search
        search_term = display.split()[0]
        repos = _search_github(search_term)

        if not repos:
            continue

        # Aggregate stats across top repos
        total_stars = 0
        total_forks = 0
        total_issues = 0
        latest_update = ""
        repo_summaries: list[str] = []

        for repo in repos[:5]:
            stars = repo.get("stargazers_count", 0)
            forks = repo.get("forks_count", 0)
            issues = repo.get("open_issues_count", 0)
            updated = repo.get("updated_at", "")
            name = repo.get("full_name", "")
            desc = (repo.get("description") or "")[:120]

            total_stars += stars
            total_forks += forks
            total_issues += issues
            if updated > latest_update:
                latest_update = updated

            repo_summaries.append(
                f"{name} ({stars} stars, {forks} forks): {desc}"
            )

        score = _score_from_stars(total_stars)
        notes_parts = [
            f"GitHub OSS signal: {total_stars} total stars, "
            f"{total_forks} forks, {total_issues} open issues across "
            f"{len(repos)} repos.",
        ]
        if latest_update:
            notes_parts.append(f"Last updated: {latest_update[:10]}.")
        if repo_summaries:
            notes_parts.append(f"Top: {repo_summaries[0]}")

        notes = " ".join(notes_parts)[:300]

        evals.append({
            "vendor": display,
            "vendor_id": vendor_id,
            "category": category,
            "overall_score": score,
            "detection_rate": None,
            "fp_rate": None,
            "source": "github-oss",
            "source_url": f"https://github.com/search?q={search_term}+security&type=repositories",
            "notes": notes,
            "top_strength": None,
            "top_friction": None,
            "github_stars": total_stars,
            "github_forks": total_forks,
            "github_open_issues": total_issues,
            "github_last_updated": latest_update[:10] if latest_update else None,
        })

    return evals
