"""
Security Stack Exchange community intelligence scraper.

Searches Security Stack Exchange via the public API for Q&A discussions
about security tools. No authentication required (throttled at 300 req/day).
LLM extraction is optional.

Source: https://api.stackexchange.com/2.3
"""
from __future__ import annotations

import html as html_mod
import json
import os
import re
import time
import urllib.request

from .llm import llm_extract

SE_API = "https://api.stackexchange.com/2.3/search"

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


def _strip_html(text: str) -> str:
    """Remove HTML tags from SE body text."""
    text = html_mod.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _search_se(vendor: str) -> list[dict]:
    """Search Security Stack Exchange for questions mentioning a vendor."""
    encoded = urllib.request.quote(vendor)
    url = (
        f"{SE_API}?order=desc&sort=votes"
        f"&intitle={encoded}"
        f"&site=security&filter=withbody&pagesize=5"
    )
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "vigil-scraper/1.0")

    time.sleep(1.0)  # stay well under 300 req/day limit
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data.get("items", [])
    except Exception:
        return []


def _build_corpus(questions: list[dict]) -> str:
    """Extract readable text from SE question dicts."""
    parts: list[str] = []
    for q in questions[:5]:
        title = html_mod.unescape(q.get("title", ""))
        body = _strip_html(q.get("body", ""))
        score = q.get("score", 0)
        answers = q.get("answer_count", 0)
        if not title:
            continue
        parts.append(
            f"Title: {title}\n"
            f"Votes: {score}  Answers: {answers}\n"
            f"{body[:800]}"
        )
    return "\n\n---\n".join(parts)


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Scrape Security Stack Exchange for vendor evaluations. LLM extraction is optional."""
    use_llm = bool(
        os.getenv("AZURE_OPENAI_KEY") or os.getenv("AZURE_API_KEY")
        or os.getenv("AWS_DEFAULT_REGION")
        or os.getenv("ANTHROPIC_API_KEY")
    )

    evals: list[dict] = []

    for vendor_id, display, category in VENDORS:
        # Use a shorter search term for better API results
        search_term = display.split()[0]  # e.g. "CrowdStrike" from "CrowdStrike Falcon"
        questions = _search_se(search_term)

        corpus = _build_corpus(questions)
        if not corpus:
            continue

        if use_llm:
            data = llm_extract(corpus, f"""
These are Security Stack Exchange questions discussing {display}.

Extract a structured evaluation insight. Return a JSON object:
{{
  "overall_score": <float 0-10, based on expressed sentiment and expertise, null if insufficient data>,
  "top_strength":  "<main positive aspect mentioned, max 100 chars, null if none>",
  "top_friction":  "<main complaint or difficulty, max 100 chars, null if none>",
  "notes":         "<1-2 sentence summary of SE community view, max 200 chars>"
}}

Rules:
- Return null for overall_score if fewer than 2 questions discuss this vendor substantively
- Do not invent data -- only extract what's actually expressed in the questions
- Focus on technical practitioner perspective
- Return the raw JSON object only, no markdown
""")
            if not data or not isinstance(data, dict):
                continue
        else:
            # No LLM -- return raw corpus summary
            snippet = corpus[:400].replace("\n", " ").strip()
            data = {"notes": f"Security SE discussion: {snippet}"}

        evals.append({
            "vendor": display,
            "vendor_id": vendor_id,
            "category": category,
            "overall_score": data.get("overall_score"),
            "detection_rate": None,
            "fp_rate": None,
            "source": "stackexchange-community",
            "source_url": f"https://security.stackexchange.com/search?q={search_term}",
            "notes": data.get("notes", ""),
            "top_strength": data.get("top_strength"),
            "top_friction": data.get("top_friction"),
        })

    return evals
