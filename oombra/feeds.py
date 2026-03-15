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
"""
from __future__ import annotations

import json
import urllib.request
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

            oombra_type = type_map.get(ioc_type_raw, ioc_type_raw)

            # Clean up IP:port
            if oombra_type == "ip" and ":" in ioc_value:
                ioc_value = ioc_value.split(":")[0]

            iocs.append({
                "ioc_type": oombra_type,
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
    """Split IOC dicts into oombra-format bundle dicts."""
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
    """Upload IOC bundles to an oombra server. Returns count of successful uploads."""
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
