"""
Feed scraper module — ingest real IOCs from public threat intelligence feeds.

Supported feeds:
  - ThreatFox (abuse.ch)    — domains, IPs, hashes with malware family tags
  - Feodo Tracker (abuse.ch) — C2 server IPs
  - MalwareBazaar (abuse.ch) — malware SHA-256 hashes
  - CISA KEV                 — exploited vulnerabilities (ransomware-tagged)
  - URLhaus (abuse.ch)       — malicious URLs and domains
  - SSL Blacklist (abuse.ch) — malicious SSL certificate SHA1 fingerprints
  - FireHOL Level 1          — aggregated malicious IPs from 30+ feeds
  - IPsum                    — IPs scored by multi-blacklist overlap
  - OpenPhish                — phishing URLs
  - Emerging Threats         — compromised IPs
  - Dataplane SSH            — SSH brute force attacker IPs
  - Spamhaus DROP            — hijacked IP ranges
  - DigitalSide              — malware-related IPs from OSINT analysis
  - CINS Score               — poorly-rated suspicious IPs
  - BruteForceBlocker        — SSH brute force attacker IPs
  - NVD                      — recent CVEs with CVSS scores
  - AbuseIPDB               — reported malicious IPs (API key required)
  - OTX AlienVault          — community threat pulses (API key required)
  - Pulsedive               — community threat intel (API key required)
  - GreyNoise               — internet scanner classification (API key required)
  - Hybrid Analysis         — daily malware samples with verdicts (API key required)
  - JPCERT                  — Japanese CERT security advisories (RSS feed)
"""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 30) -> str:
    """Fetch URL content. Returns empty string on failure."""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _fetch_with_headers(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> str:
    """Fetch URL with custom headers. Returns empty string on failure."""
    req = urllib.request.Request(url)
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


# ── Individual scrapers ──────────────────────────────────────────────────────

def scrape_threatfox(url: str) -> list[dict]:
    """ThreatFox — real IOCs with malware family tags. Capped at 500."""
    raw = _fetch(url)
    if not raw:
        return []

    type_map = {
        "domain": "domain",
        "ip:port": "ip",
        "url": "url",
        "md5_hash": "hash-md5",
        "sha256_hash": "hash-sha256",
        "sha1_hash": "hash-sha1",
    }

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        if line.startswith("#") or line.startswith('"#'):
            continue
        parts = line.strip().strip('"').split('", "')
        if len(parts) < 8:
            continue
        try:
            ioc_value = parts[2].strip('"')
            ioc_type_raw = parts[3].strip('"')
            malware = parts[5].strip('"')
            threat_actor = parts[7].strip('"') if len(parts) > 7 else None

            vigil_type = type_map.get(ioc_type_raw, ioc_type_raw)

            # Clean up IP:port
            if vigil_type == "ip" and ":" in ioc_value:
                ioc_value = ioc_value.split(":")[0]

            iocs.append({
                "ioc_type": vigil_type,
                "value_raw": ioc_value,
                "threat_actor": threat_actor if threat_actor and threat_actor != "None" else malware,
                "campaign": malware,
                "detected_by": [],
                "missed_by": [],
            })
        except (IndexError, ValueError):
            continue

    return iocs[:500]


def scrape_feodo(url: str) -> list[dict]:
    """Feodo Tracker — C2 server IPs (Emotet, QakBot, etc.)."""
    raw = _fetch(url)
    if not raw:
        return []

    entries = json.loads(raw)
    iocs: list[dict] = []
    for e in entries:
        iocs.append({
            "ioc_type": "ip",
            "value_raw": e["ip_address"],
            "threat_actor": e.get("malware", "unknown"),
            "campaign": f"{e.get('malware', 'unknown')}-c2",
            "detected_by": [],
            "missed_by": [],
        })
    return iocs


def scrape_bazaar(url: str) -> list[dict]:
    """MalwareBazaar — malware SHA-256 hashes. Capped at 200."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if line.startswith("#") or not line or len(line) != 64:
            continue
        iocs.append({
            "ioc_type": "hash-sha256",
            "value_raw": line,
            "threat_actor": "malware",
            "campaign": "recent-malware",
            "detected_by": [],
            "missed_by": [],
        })
    return iocs[:200]


def scrape_cisa_kev(url: str) -> list[dict]:
    """CISA KEV — ransomware-related CVEs. Last 50."""
    raw = _fetch(url)
    if not raw:
        return []

    data = json.loads(raw)
    vulns = data.get("vulnerabilities", [])
    ransomware = [v for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"]

    iocs: list[dict] = []
    for v in ransomware[-50:]:
        iocs.append({
            "ioc_type": "cve",
            "value_raw": v["cveID"],
            "threat_actor": v.get("vendorProject", "unknown"),
            "campaign": "ransomware-kev",
            "detected_by": [],
            "missed_by": [],
        })
    return iocs


def scrape_urlhaus(url: str) -> list[dict]:
    """URLhaus — malicious URLs and domains. Capped at 300."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        if line.startswith("#") or line.startswith('"#'):
            continue
        parts = line.strip().strip('"').split('","')
        if len(parts) < 7:
            continue
        try:
            mal_url = parts[2].strip('"')
            threat = parts[5].strip('"') if len(parts) > 5 else "malware"
            tags = parts[6].strip('"') if len(parts) > 6 else "unknown"

            iocs.append({
                "ioc_type": "url",
                "value_raw": mal_url,
                "threat_actor": tags if tags else "unknown",
                "campaign": threat if threat else "malware-distribution",
                "detected_by": [],
                "missed_by": [],
            })

            # Also extract domain
            try:
                domain = urlparse(mal_url).hostname
                if domain:
                    iocs.append({
                        "ioc_type": "domain",
                        "value_raw": domain,
                        "threat_actor": tags if tags else "unknown",
                        "campaign": threat if threat else "malware-distribution",
                        "detected_by": [],
                        "missed_by": [],
                    })
            except Exception:
                pass
        except (IndexError, ValueError):
            continue

    return iocs[:300]


def scrape_ssl_blacklist(url: str) -> list[dict]:
    """SSL Blacklist — malicious SSL certificate SHA1 fingerprints. Capped at 200."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        if line.startswith("#"):
            continue
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue
        try:
            sha1 = parts[1].strip()
            reason = parts[2].strip()
            if not sha1 or len(sha1) != 40:
                continue
            iocs.append({
                "ioc_type": "hash-sha1",
                "value_raw": sha1,
                "threat_actor": reason if reason else "unknown",
                "campaign": "ssl-blacklist",
                "detected_by": [],
                "missed_by": [],
            })
        except (IndexError, ValueError):
            continue

    return iocs[:200]


def scrape_firehol(url: str) -> list[dict]:
    """FireHOL Level 1 — high-confidence malicious IPs. Capped at 500."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if line.startswith("#") or not line or "/" in line:
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": line,
            "threat_actor": "firehol-level1",
            "campaign": "blocklist-aggregated",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:500]


def scrape_ipsum(url: str) -> list[dict]:
    """IPsum — IPs scored by multi-blacklist overlap (count >= 3). Capped at 300."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        try:
            ip = parts[0].strip()
            count = int(parts[1].strip())
            if count < 3:
                continue
            iocs.append({
                "ioc_type": "ip",
                "value_raw": ip,
                "threat_actor": "multi-blacklist",
                "campaign": f"ipsum-score-{count}",
                "detected_by": [],
                "missed_by": [],
            })
        except (IndexError, ValueError):
            continue

    return iocs[:300]


def scrape_openphish(url: str) -> list[dict]:
    """OpenPhish — phishing URLs. Capped at 200."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        iocs.append({
            "ioc_type": "url",
            "value_raw": line,
            "threat_actor": "phishing",
            "campaign": "openphish-live",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:200]


def scrape_emergingthreats(url: str) -> list[dict]:
    """Emerging Threats — compromised IPs. Capped at 300."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": line,
            "threat_actor": "compromised",
            "campaign": "emergingthreats-compromised",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:300]


def scrape_dataplane_ssh(url: str) -> list[dict]:
    """Dataplane SSH — SSH brute force attacker IPs. Capped at 200."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        try:
            ip = parts[2]
            if not ip:
                continue
            iocs.append({
                "ioc_type": "ip",
                "value_raw": ip,
                "threat_actor": "ssh-bruteforce",
                "campaign": "dataplane-sshpwauth",
                "detected_by": [],
                "missed_by": [],
            })
        except (IndexError, ValueError):
            continue

    return iocs[:200]


def scrape_spamhaus_drop(url: str) -> list[dict]:
    """Spamhaus DROP — hijacked IP ranges (network part only). Capped at 100."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        try:
            cidr_part = line.split(";")[0].strip()
            ip = cidr_part.split("/")[0].strip()
            if not ip:
                continue
            iocs.append({
                "ioc_type": "ip",
                "value_raw": ip,
                "threat_actor": "spamhaus",
                "campaign": "drop-hijacked",
                "detected_by": [],
                "missed_by": [],
            })
        except (IndexError, ValueError):
            continue

    return iocs[:100]


def scrape_digitalside(url: str) -> list[dict]:
    """DigitalSide — malware-related IPs from OSINT analysis. Capped at 300."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": line,
            "threat_actor": "malware",
            "campaign": "digitalside-feed",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:300]


def scrape_cinsscore(url: str) -> list[dict]:
    """CINS Score — poorly-rated suspicious IPs. Capped at 300."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": line,
            "threat_actor": "suspicious",
            "campaign": "cinsscore-feed",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:300]


def scrape_bruteforceblocker(url: str) -> list[dict]:
    """BruteForceBlocker — SSH brute force attacker IPs. Capped at 200."""
    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": line,
            "threat_actor": "brute-force",
            "campaign": "ssh-brute-force",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:200]


def scrape_nvd(url: str) -> list[dict]:
    """NVD — recent CVEs with CVSS scores. Capped at 50."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    full_url = (
        f"{url}?resultsPerPage=50"
        f"&pubStartDate={today}T00:00:00.000"
        f"&pubEndDate={today}T23:59:59.999"
    )
    raw = _fetch(full_url, timeout=45)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    iocs: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        source = cve.get("sourceIdentifier", "unknown")
        if not cve_id:
            continue

        # Extract CVSS score from metrics (try v31 first, then v30, then v2)
        cvss_score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                if cvss_score is not None:
                    break

        entry: dict = {
            "ioc_type": "cve",
            "value_raw": cve_id,
            "threat_actor": source,
            "campaign": "nvd-recent",
            "detected_by": [],
            "missed_by": [],
        }
        if cvss_score is not None:
            entry["cvss_score"] = cvss_score

        iocs.append(entry)

    return iocs[:50]


# ── API-key-dependent scrapers ──────────────────────────────────────────────

def scrape_abuseipdb(url: str) -> list[dict]:
    """AbuseIPDB — reported malicious IPs with confidence scores. Capped at 200.

    Requires ABUSEIPDB_API_KEY environment variable.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        print("[nur] ABUSEIPDB_API_KEY not set — skipping abuseipdb feed")
        return []

    full_url = f"{url}?confidenceMinimum=90&limit=200"
    headers = {"Key": api_key, "Accept": "application/json"}
    raw = _fetch_with_headers(full_url, headers)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    iocs: list[dict] = []
    for entry in data.get("data", []):
        ip = entry.get("ipAddress", "")
        confidence = entry.get("abuseConfidenceScore", 0)
        if not ip:
            continue
        iocs.append({
            "ioc_type": "ip",
            "value_raw": ip,
            "threat_actor": "abuse-reported",
            "campaign": f"abuseipdb-{confidence}",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:200]


def scrape_otx_alienvault(url: str) -> list[dict]:
    """OTX AlienVault — community threat pulses with IOCs. Capped at 300.

    Requires OTX_API_KEY environment variable.
    """
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key:
        print("[nur] OTX_API_KEY not set — skipping OTX AlienVault feed")
        return []

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    full_url = f"{url}?limit=10&modified_since={today}"
    headers = {"X-OTX-API-KEY": api_key}
    raw = _fetch_with_headers(full_url, headers)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    type_map = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-SHA256": "hash-sha256",
        "FileHash-SHA1": "hash-sha1",
        "FileHash-MD5": "hash-md5",
        "email": "email",
    }

    iocs: list[dict] = []
    for pulse in data.get("results", []):
        pulse_name = pulse.get("name", "unknown-pulse")
        for indicator in pulse.get("indicators", []):
            ioc_type_raw = indicator.get("type", "")
            vigil_type = type_map.get(ioc_type_raw)
            if not vigil_type:
                continue
            value = indicator.get("indicator", "")
            if not value:
                continue
            iocs.append({
                "ioc_type": vigil_type,
                "value_raw": value,
                "threat_actor": pulse_name,
                "campaign": pulse_name,
                "detected_by": [],
                "missed_by": [],
            })

    return iocs[:300]


def scrape_pulsedive(url: str) -> list[dict]:
    """Pulsedive — community threat intelligence with risk scoring. Capped at 200.

    Requires PULSEDIVE_API_KEY environment variable.
    """
    api_key = os.environ.get("PULSEDIVE_API_KEY", "")
    if not api_key:
        print("[nur] PULSEDIVE_API_KEY not set — skipping Pulsedive feed")
        return []

    full_url = f"{url}?q=type%3Dip+risk%3Dcritical&limit=100&key={api_key}"
    raw = _fetch(full_url)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    type_map = {"ip": "ip", "domain": "domain", "url": "url"}

    iocs: list[dict] = []
    results = data if isinstance(data, list) else data.get("results", [])
    for entry in results:
        raw_type = str(entry.get("type", "")).lower()
        vigil_type = type_map.get(raw_type)
        if not vigil_type:
            continue
        value = entry.get("indicator", "")
        if not value:
            continue
        risk = entry.get("risk", "unknown")
        iocs.append({
            "ioc_type": vigil_type,
            "value_raw": value,
            "threat_actor": str(risk),
            "campaign": "pulsedive-feed",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:200]


def scrape_greynoise(url: str) -> list[dict]:
    """GreyNoise — internet scanner classification. Capped at 100.

    Requires GREYNOISE_API_KEY environment variable.
    Note: GreyNoise bulk feed requires a paid API plan.
    """
    api_key = os.environ.get("GREYNOISE_API_KEY", "")
    if not api_key:
        print("[nur] GREYNOISE_API_KEY not set — skipping GreyNoise feed")
        return []

    # GreyNoise bulk noise context endpoint requires paid API
    print("[nur] GreyNoise bulk feed requires paid API — returning empty")
    return []  # Cap at 100 (when implemented)


def scrape_hybrid_analysis(url: str) -> list[dict]:
    """Hybrid Analysis — malware sample feed with verdicts. Requires HYBRID_ANALYSIS_API_KEY."""
    api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
    if not api_key:
        print("[nur] HYBRID_ANALYSIS_API_KEY not set — skipping Hybrid Analysis")
        return []

    req = urllib.request.Request(url, headers={
        "api-key": api_key,
        "user-agent": "Falcon Sandbox",
        "accept": "application/json",
    })
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    iocs: list[dict] = []
    for entry in data.get("data", []):
        # API uses threat_level_human for classification (verdict field is often "none")
        threat_level = entry.get("threat_level_human", "")
        if threat_level != "malicious":
            continue
        sha256 = entry.get("sha256", "")
        if not sha256:
            continue
        iocs.append({
            "ioc_type": "hash-sha256",
            "value_raw": sha256,
            "threat_actor": threat_level,
            "campaign": "hybrid-analysis-daily",
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:200]


def scrape_jpcert(url: str) -> list[dict]:
    """JPCERT — Japanese CERT advisories via RSS/RDF feed."""
    import re

    raw = _fetch(url)
    if not raw:
        return []

    iocs: list[dict] = []
    # Parse items from RSS/RDF — extract <item>...</item> blocks
    items = re.findall(r"<item[^>]*>(.*?)</item>", raw, re.DOTALL)
    for item in items:
        title_m = re.search(r"<title>(.*?)</title>", item, re.DOTALL)
        link_m = re.search(r"<link>(.*?)</link>", item, re.DOTALL)
        desc_m = re.search(r"<description>(.*?)</description>", item, re.DOTALL)

        title = title_m.group(1).strip() if title_m else ""
        link = link_m.group(1).strip() if link_m else ""
        desc = desc_m.group(1).strip() if desc_m else ""

        if not link:
            continue

        # Try to extract CVE IDs from title or description
        cves = re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {desc}")
        campaign = ", ".join(cves) if cves else "jpcert-advisory"

        iocs.append({
            "ioc_type": "advisory",
            "value_raw": link,
            "threat_actor": "JPCERT",
            "campaign": campaign,
            "detected_by": [],
            "missed_by": [],
        })

    return iocs[:50]


# ── Feed registry ────────────────────────────────────────────────────────────

FEEDS: dict[str, dict[str, Any]] = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "scraper": scrape_threatfox,
        "description": "ThreatFox IOCs — domains, IPs, hashes with malware tags",
    },
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "scraper": scrape_feodo,
        "description": "Feodo Tracker — C2 server IPs (Emotet, QakBot, etc.)",
    },
    "bazaar": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "scraper": scrape_bazaar,
        "description": "MalwareBazaar — recent malware SHA-256 hashes",
    },
    "cisa-kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "scraper": scrape_cisa_kev,
        "description": "CISA KEV — known exploited vulnerabilities (ransomware)",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "scraper": scrape_urlhaus,
        "description": "URLhaus — malicious URLs and domains (malware distribution)",
    },
    "ssl-blacklist": {
        "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "scraper": scrape_ssl_blacklist,
        "description": "SSL Blacklist — malicious SSL certificate SHA1 fingerprints",
    },
    "firehol": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "scraper": scrape_firehol,
        "description": "FireHOL Level 1 — high-confidence malicious IPs (30+ feeds)",
    },
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "scraper": scrape_ipsum,
        "description": "IPsum — IPs scored by multi-blacklist overlap (count >= 3)",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "scraper": scrape_openphish,
        "description": "OpenPhish — phishing URLs",
    },
    "emergingthreats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "scraper": scrape_emergingthreats,
        "description": "Emerging Threats — compromised IPs",
    },
    "dataplane-ssh": {
        "url": "https://dataplane.org/sshpwauth.txt",
        "scraper": scrape_dataplane_ssh,
        "description": "Dataplane SSH — SSH brute force attacker IPs",
    },
    "spamhaus-drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "scraper": scrape_spamhaus_drop,
        "description": "Spamhaus DROP — hijacked IP ranges",
    },
    "digitalside": {
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
        "scraper": scrape_digitalside,
        "description": "DigitalSide — malware-related IPs from OSINT analysis",
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "scraper": scrape_cinsscore,
        "description": "CINS Score — poorly-rated suspicious IPs",
    },
    "bruteforceblocker": {
        "url": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "scraper": scrape_bruteforceblocker,
        "description": "BruteForceBlocker — SSH brute force attacker IPs",
    },
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "scraper": scrape_nvd,
        "description": "NVD — recent CVEs with CVSS scores",
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "scraper": scrape_abuseipdb,
        "description": "AbuseIPDB — reported malicious IPs with confidence scores (requires API key)",
    },
    "otx-alienvault": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "scraper": scrape_otx_alienvault,
        "description": "OTX AlienVault — community threat pulses with IOCs (requires API key)",
    },
    "pulsedive": {
        "url": "https://pulsedive.com/api/explore.php",
        "scraper": scrape_pulsedive,
        "description": "Pulsedive — community threat intelligence with risk scoring (requires API key)",
    },
    "greynoise": {
        "url": "https://api.greynoise.io/v2/noise/context",
        "scraper": scrape_greynoise,
        "description": "GreyNoise — internet scanner classification (requires API key)",
    },
    "hybrid-analysis": {
        "url": "https://www.hybrid-analysis.com/api/v2/feed/latest",
        "scraper": scrape_hybrid_analysis,
        "description": "Hybrid Analysis — daily malware samples with verdicts (requires API key)",
    },
    "jpcert": {
        "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        "scraper": scrape_jpcert,
        "description": "JPCERT — Japanese CERT security advisories (RSS feed)",
    },
}


# ── Public API ───────────────────────────────────────────────────────────────

def scrape_feed(name: str) -> list[dict]:
    """Scrape a single feed by name. Returns list of IOC dicts."""
    if name not in FEEDS:
        raise ValueError(f"Unknown feed: {name!r}. Available: {', '.join(FEEDS)}")
    feed = FEEDS[name]
    return feed["scraper"](feed["url"])


def scrape_all() -> dict[str, list[dict]]:
    """Scrape all feeds. Returns {feed_name: [ioc_dicts]}."""
    results: dict[str, list[dict]] = {}
    for name in FEEDS:
        try:
            results[name] = scrape_feed(name)
        except Exception:
            results[name] = []
    return results


def bundle_iocs(iocs: list[dict], feed_name: str, chunk_size: int = 50) -> list[dict]:
    """Split IOC dicts into nur-format bundle dicts."""
    bundles: list[dict] = []
    for i in range(0, len(iocs), chunk_size):
        chunk = iocs[i : i + chunk_size]
        bundles.append({
            "iocs": chunk,
            "tools_in_scope": [],
            "source": "threat-feed",
            "notes": f"Auto-ingested from {feed_name} public feed ({len(chunk)} IOCs)",
        })
    return bundles


def ingest_to_server(
    api_url: str,
    bundles: list[dict],
    api_key: str | None = None,
) -> int:
    """Upload IOC bundles to an nur server. Returns count of successful uploads."""
    url = f"{api_url.rstrip('/')}/contribute/ioc-bundle"
    ok = 0
    for bundle in bundles:
        payload = json.dumps(bundle).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        if api_key:
            req.add_header("X-API-Key", api_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status < 300:
                    ok += 1
        except Exception:
            continue
    return ok
