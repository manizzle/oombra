"""
Reddit community intelligence scraper.

Searches security subreddits for practitioner discussions about security tools.
Uses Reddit's public JSON API (no auth required).
LLM extraction is optional -- works without it, returning raw corpus summaries.

Sources: r/netsec, r/cybersecurity, r/sysadmin, r/networking
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from .llm import llm_extract

SUBREDDITS = ["netsec", "cybersecurity", "sysadmin", "networking"]

# Vendors to search -- (vendor_id, display_name, category)
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

_USER_AGENT = os.getenv("REDDIT_USER_AGENT", "vigil-scraper/1.0")


def _search_subreddit(query: str, subreddit: str) -> list[dict]:
    """Search a subreddit using the public JSON API. Returns post dicts."""
    url = (
        f"https://www.reddit.com/r/{subreddit}/search.json"
        f"?q={urllib.request.quote(query)}"
        f"&sort=relevance&t=year&limit=8&restrict_sr=1"
    )
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _USER_AGENT)

    time.sleep(2.0)  # polite rate limit for public API
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            children = data.get("data", {}).get("children", [])
            return [p["data"] for p in children if p.get("data")]
    except Exception:
        return []


def _build_corpus(posts: list[dict]) -> str:
    """Extract readable text from Reddit post dicts."""
    parts: list[str] = []
    for p in posts[:6]:
        title = p.get("title", "")
        body = p.get("selftext", "")
        if not body or body in ("[deleted]", "[removed]"):
            body = ""
        score = p.get("score", 0)
        comments = p.get("num_comments", 0)
        if not title:
            continue
        parts.append(
            f"Title: {title}\n"
            f"Upvotes: {score}  Comments: {comments}\n"
            f"{body[:800]}"
        )
    return "\n\n---\n".join(parts)


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Scrape Reddit for vendor evaluations. LLM extraction is optional."""
    use_llm = bool(
        os.getenv("AZURE_OPENAI_KEY") or os.getenv("AZURE_API_KEY")
        or os.getenv("AWS_DEFAULT_REGION")
        or os.getenv("ANTHROPIC_API_KEY")
    )

    evals: list[dict] = []

    for vendor_id, display, category in VENDORS:
        query = f"{display} evaluation OR review OR experience"
        posts: list[dict] = []

        for sub in SUBREDDITS[:2]:  # limit to 2 subs to stay under rate limits
            results = _search_subreddit(query, sub)
            posts.extend(results[:3])

        corpus = _build_corpus(posts)
        if not corpus:
            continue

        if use_llm:
            data = llm_extract(corpus, f"""
These are Reddit posts from security practitioners discussing {display}.

Extract a structured evaluation insight. Return a JSON object:
{{
  "overall_score": <float 0-10, based on expressed sentiment and satisfaction, null if insufficient data>,
  "top_strength":  "<main positive aspect mentioned, max 100 chars, null if none>",
  "top_friction":  "<main complaint or pain point, max 100 chars, null if none>",
  "notes":         "<1-2 sentence summary of community consensus, max 200 chars>"
}}

Rules:
- Return null for overall_score if fewer than 2 posts discuss this vendor substantively
- Do not invent data -- only extract what's actually expressed in the posts
- Focus on practitioner experience, not marketing claims
- Return the raw JSON object only, no markdown
""")
            if not data or not isinstance(data, dict):
                continue
        else:
            # No LLM -- return raw corpus summary
            snippet = corpus[:400].replace("\n", " ").strip()
            data = {"notes": f"Reddit community discussion: {snippet}"}

        evals.append({
            "vendor": display,
            "vendor_id": vendor_id,
            "category": category,
            "overall_score": data.get("overall_score"),
            "detection_rate": None,
            "fp_rate": None,
            "source": "reddit-community",
            "source_url": f"https://www.reddit.com/search?q={display.replace(' ', '+')}+evaluation",
            "notes": data.get("notes", ""),
            "top_strength": data.get("top_strength"),
            "top_friction": data.get("top_friction"),
        })

    return evals
