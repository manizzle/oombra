"""
CISA Known Exploited Vulnerabilities (KEV) — vendor cross-reference scraper.

Fetches the CISA KEV catalog and cross-references against security vendor
keywords to find which tools have had actively exploited vulnerabilities.

This is richer than vigil's base CISA KEV feed (which only returns CVE IOCs).
This scraper returns per-vendor risk scores based on KEV exposure.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import json
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Map vendor product keywords -> (vendor_id, display_name, category)
VENDOR_KEYWORDS = {
    "crowdstrike":        ("crowdstrike",      "CrowdStrike Falcon",                "edr"),
    "sentinelone":        ("sentinelone",      "SentinelOne Singularity",           "edr"),
    "microsoft defender": ("ms-defender",      "Microsoft Defender",                "edr"),
    "cortex xsoar":       ("cortex-xdr",       "Palo Alto Cortex XDR",             "edr"),
    "cortex xdr":         ("cortex-xdr",       "Palo Alto Cortex XDR",             "edr"),
    "carbon black":       ("carbon-black",     "VMware Carbon Black",              "edr"),
    "trend micro":        ("trend-apex",       "Trend Micro Apex One",             "edr"),
    "sophos":             ("sophos",           "Sophos Intercept X",               "edr"),
    "eset":               ("eset",             "ESET Protect",                     "edr"),
    "bitdefender":        ("bitdefender",      "Bitdefender GravityZone",          "edr"),
    "malwarebytes":       ("malwarebytes",     "Malwarebytes for Teams",           "edr"),
    "kaspersky":          ("kaspersky",        "Kaspersky Endpoint Security",      "edr"),
    "splunk":             ("splunk",           "Splunk Enterprise",                "siem"),
    "qradar":             ("qradar",           "IBM QRadar",                       "siem"),
    "elastic":            ("elastic-siem",     "Elastic Security (SIEM)",          "siem"),
    "okta":               ("okta",             "Okta Workforce Identity",          "iam"),
    "azure ad":           ("entra-id",         "Microsoft Entra ID",              "iam"),
    "entra":              ("entra-id",         "Microsoft Entra ID",              "iam"),
    "sailpoint":          ("sailpoint",        "SailPoint IdentityNow",           "iam"),
    "cyberark":           ("cyberark-pam",     "CyberArk Privileged Access Manager", "pam"),
    "beyondtrust":        ("beyondtrust",      "BeyondTrust Password Safe",       "pam"),
    "hashicorp vault":    ("hashicorp-vault",  "HashiCorp Vault",                 "pam"),
    "proofpoint":         ("proofpoint",       "Proofpoint Email Protection",     "email"),
    "mimecast":           ("mimecast",         "Mimecast",                        "email"),
    "barracuda":          ("barracuda",        "Barracuda Email Gateway",         "email"),
    "cloudflare":         ("cloudflare-waf",   "Cloudflare WAF",                  "waf"),
    "f5 big-ip":          ("f5-waf",           "F5 Advanced WAF",                "waf"),
    "f5 networks":        ("f5-waf",           "F5 Advanced WAF",                "waf"),
    "imperva":            ("imperva",          "Imperva WAF",                     "waf"),
    "fortinet":           ("fortinet-fortiweb","Fortinet FortiWeb",               "waf"),
    "fortigate":          ("fortinet-fortiweb","Fortinet FortiWeb",               "waf"),
    "fortios":            ("fortinet-fortiweb","Fortinet FortiWeb",               "waf"),
    "zscaler":            ("zscaler",          "Zscaler Private Access",          "ztna"),
    "ivanti":             ("ivanti-connect",   "Ivanti Connect Secure",           "ztna"),
    "cisco duo":          ("cisco-duo",        "Cisco Duo",                       "ztna"),
    "pulse secure":       ("ivanti-connect",   "Ivanti Connect Secure",           "ztna"),
    "qualys":             ("qualys",           "Qualys VMDR",                     "vm"),
    "tenable":            ("tenable",          "Tenable.io",                      "vm"),
    "rapid7":             ("rapid7",           "Rapid7 InsightVM",                "vm"),
    "darktrace":          ("darktrace",        "Darktrace",                       "ndr"),
    "extrahop":           ("extrahop",         "ExtraHop Reveal(x)",              "ndr"),
}

# Generic vendor names that match too broadly
EXCLUDE_VENDORS = {"microsoft", "cisco", "apple", "google", "adobe", "oracle"}


def _fetch_kev() -> dict:
    """Fetch the CISA KEV JSON catalog."""
    req = urllib.request.Request(KEV_URL)
    req.add_header("User-Agent", "vigil-scraper/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Fetch CISA KEV and return per-vendor risk evaluation dicts."""
    catalog = _fetch_kev()
    vulns = catalog.get("vulnerabilities", [])
    if not vulns:
        return []

    # Cross-reference: vendor_id -> list of CVE dicts
    matches: dict[str, list[dict]] = {}
    for v in vulns:
        vendor_raw = (v.get("vendorProject", "") or "").lower()
        product_raw = (v.get("product", "") or "").lower()
        combined = f"{vendor_raw} {product_raw}"

        for keyword, (vid, display, cat) in VENDOR_KEYWORDS.items():
            if keyword in combined:
                if keyword in EXCLUDE_VENDORS:
                    continue
                if vid not in matches:
                    matches[vid] = []
                matches[vid].append({
                    "cve_id": v.get("cveID", ""),
                    "display_name": display,
                    "category": cat,
                    "severity": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "date_added": v.get("dateAdded", ""),
                    "short_desc": v.get("shortDescription", "")[:200],
                })
                break

    evals: list[dict] = []
    for vid, cves in matches.items():
        display = cves[0]["display_name"]
        cat = cves[0]["category"]
        cve_ids = [c["cve_id"] for c in cves]
        ransomware_used = sum(1 for c in cves if c["severity"] == "Known")
        latest = max((c["date_added"] for c in cves), default="")

        notes = f"{len(cves)} CVEs in CISA KEV catalog. "
        if ransomware_used:
            notes += f"{ransomware_used} used in ransomware campaigns. "
        notes += f"Latest added: {latest}. "
        notes += "CVEs: " + ", ".join(cve_ids[:10])
        if len(cve_ids) > 10:
            notes += f" (+{len(cve_ids) - 10} more)"

        # Score: inverse -- more KEVs = worse. Max penalty at 10+ CVEs.
        kev_count = len(cves)
        risk_score = max(0, 10 - kev_count * 1.5)
        risk_score = round(max(0, min(10, risk_score)), 1)

        evals.append({
            "vendor": display,
            "vendor_id": vid,
            "category": cat,
            "overall_score": risk_score,
            "detection_rate": None,
            "fp_rate": None,
            "source": "cisa-kev-vendors",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "notes": notes,
            "top_strength": "product under active CISA monitoring" if kev_count <= 2 else None,
            "top_friction": f"{kev_count} actively exploited CVEs in CISA KEV" if kev_count >= 3 else None,
        })

    return evals
