"""
Hacker News community intelligence scraper.

Searches HN comments via the Algolia API for practitioner discussion
of security tools. Completely free, no authentication required.
LLM extraction is optional.

Source: https://hn.algolia.com/api
"""
from __future__ import annotations

import html as html_mod
import json
import os
import re
import time
import urllib.request

from .llm import llm_extract

HN_SEARCH = "https://hn.algolia.com/api/v1/search"

# Vendors -- (vendor_id, display_name, category, search_terms)
VENDORS = [
    # EDR
    ("crowdstrike",  "CrowdStrike",        "edr",   ["CrowdStrike Falcon", "crowdstrike EDR"]),
    ("sentinelone",  "SentinelOne",        "edr",   ["SentinelOne", "S1 EDR"]),
    ("ms-defender",  "Microsoft Defender", "edr",   ["Microsoft Defender", "Defender for Endpoint"]),
    ("cortex-xdr",   "Palo Alto Cortex",   "edr",   ["Cortex XDR", "Palo Alto XDR"]),
    ("sophos",       "Sophos",             "edr",   ["Sophos Intercept X"]),
    ("carbon-black", "Carbon Black",       "edr",   ["Carbon Black EDR", "VMware Carbon Black"]),
    ("bitdefender",  "Bitdefender",        "edr",   ["Bitdefender GravityZone"]),
    # SIEM
    ("splunk",       "Splunk",             "siem",  ["Splunk SIEM", "Splunk Enterprise"]),
    ("ms-sentinel",  "Microsoft Sentinel", "siem",  ["Microsoft Sentinel", "Azure Sentinel"]),
    ("elastic-siem", "Elastic SIEM",       "siem",  ["Elastic SIEM", "Elastic Security"]),
    # CNAPP
    ("wiz",          "Wiz",                "cnapp", ["Wiz cloud security", "wiz.io"]),
    ("snyk",         "Snyk",               "cnapp", ["Snyk security"]),
    # GRC
    ("vanta",        "Vanta",              "grc",   ["Vanta compliance", "Vanta SOC2"]),
    ("drata",        "Drata",              "grc",   ["Drata compliance"]),
    # IAM
    ("okta",         "Okta",               "iam",   ["Okta identity", "Okta SSO"]),
    ("entra-id",     "Microsoft Entra",    "iam",   ["Azure AD", "Entra ID"]),
    # PAM
    ("cyberark-pam", "CyberArk",          "pam",   ["CyberArk PAM"]),
    ("hashicorp-vault","HashiCorp Vault",  "pam",   ["HashiCorp Vault", "vault secrets"]),
    # ZTNA
    ("zscaler",      "Zscaler",            "ztna",  ["Zscaler ZPA", "Zscaler Private"]),
    ("cloudflare-zt","Cloudflare Access",  "ztna",  ["Cloudflare Zero Trust", "Cloudflare Access"]),
    # VM
    ("qualys",       "Qualys",             "vm",    ["Qualys VMDR"]),
    ("tenable",      "Tenable",            "vm",    ["Tenable Nessus"]),
    # NDR
    ("darktrace",    "Darktrace",          "ndr",   ["Darktrace NDR"]),
    ("vectra",       "Vectra AI",          "ndr",   ["Vectra AI NDR"]),
]


def _strip_html(text: str) -> str:
    """Remove HTML tags from HN comment text."""
    text = html_mod.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _search_hn(query: str, tags: str = "comment") -> list[str]:
    """Search HN via Algolia. Returns list of clean comment texts."""
    params = urllib.request.quote(query)
    url = f"{HN_SEARCH}?query={params}&tags={tags}&hitsPerPage=15"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "vigil-scraper/1.0")

    time.sleep(0.8)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            hits = data.get("hits", [])
            texts: list[str] = []
            for h in hits:
                raw = h.get("comment_text") or h.get("story_text") or ""
                if raw:
                    texts.append(_strip_html(raw))
            return [t for t in texts if len(t) > 50]
    except Exception:
        return []


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Scrape Hacker News for vendor evaluations. LLM extraction is optional."""
    use_llm = bool(
        os.getenv("AZURE_OPENAI_KEY") or os.getenv("AZURE_API_KEY")
        or os.getenv("AWS_DEFAULT_REGION")
        or os.getenv("ANTHROPIC_API_KEY")
    )

    evals: list[dict] = []

    for vendor_id, display, category, terms in VENDORS:
        all_comments: list[str] = []

        for term in terms[:2]:
            comments = _search_hn(f"{term} security")
            all_comments.extend(comments[:8])

        # Also search for stories (Ask HN, etc.)
        ask_hits = _search_hn(f"{display} evaluation OR review", tags="story")
        all_comments.extend(ask_hits[:4])

        # Deduplicate
        seen: set[str] = set()
        unique: list[str] = []
        for c in all_comments:
            key = c[:80]
            if key not in seen:
                seen.add(key)
                unique.append(c)

        if not unique:
            continue

        corpus = "\n\n---\n".join(c[:600] for c in unique[:12])

        if use_llm:
            data = llm_extract(corpus, f"""
These are Hacker News comments discussing {display} (a security product/tool).

Extract a structured evaluation insight. Return a JSON object:
{{
  "overall_score": <float 0-10 based on practitioner sentiment, null if unclear>,
  "top_strength":  "<main positive aspect mentioned, max 100 chars, null if none>",
  "top_friction":  "<main complaint or concern, max 100 chars, null if none>",
  "notes":         "<1-2 sentence summary of HN community view, max 200 chars>"
}}

Rules:
- Only assess if comments substantively discuss using/evaluating this tool
- Return null for overall_score if comments are not product reviews
- Do not invent data -- only extract what practitioners actually say
- Return the raw JSON object only, no markdown
""")
            if not data or not isinstance(data, dict):
                continue
        else:
            snippet = corpus[:400].replace("\n", " ").strip()
            data = {"notes": f"HN community discussion: {snippet}"}

        evals.append({
            "vendor": display,
            "vendor_id": vendor_id,
            "category": category,
            "overall_score": data.get("overall_score"),
            "detection_rate": None,
            "fp_rate": None,
            "source": "hackernews-community",
            "source_url": f"https://hn.algolia.com/?query={display.replace(' ', '+')}",
            "notes": data.get("notes", ""),
            "top_strength": data.get("top_strength"),
            "top_friction": data.get("top_friction"),
        })

    return evals
