"""
Master registry of ALL known public threat intelligence and security data sources.

This is the map of everything nur can ingest. Sources are categorized by:
  - Type: ioc_feed, vendor_eval, vulnerability, community, lab_test, compliance
  - Access: free, freemium, api_key_required, commercial
  - Method: json_api, csv_download, html_scrape, llm_extract, hardcoded

To add a new source: add it here, then implement the scraper in the appropriate module.
"""
from __future__ import annotations


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1: Direct feeds — structured data, no auth, high reliability
# These are the backbone. Always available. Always fresh.
# ══════════════════════════════════════════════════════════════════════════════

TIER_1_FEEDS = {
    # ── abuse.ch ecosystem (CC0 license, best free feeds in existence) ─────
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "type": "ioc_feed",
        "data": "domains, IPs, hashes with malware family tags",
        "format": "csv",
        "license": "CC0 1.0",
        "refresh": "real-time",
        "status": "implemented",
    },
    "feodo-tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "ioc_feed",
        "data": "C2 server IPs (Emotet, QakBot, BumbleBee, Pikabot)",
        "format": "json",
        "license": "CC0 1.0",
        "refresh": "real-time",
        "status": "implemented",
    },
    "malware-bazaar": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "type": "ioc_feed",
        "data": "malware SHA-256 hashes",
        "format": "text",
        "license": "CC0 1.0",
        "refresh": "real-time",
        "status": "implemented",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "ioc_feed",
        "data": "malicious URLs (malware distribution, phishing)",
        "format": "csv",
        "license": "CC0 1.0",
        "refresh": "real-time",
        "status": "implemented",
    },
    "ssl-blacklist": {
        "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "type": "ioc_feed",
        "data": "malicious SSL certificate fingerprints",
        "format": "csv",
        "license": "CC0 1.0",
        "refresh": "real-time",
        "status": "implemented",
    },

    # ── US Government (public domain) ──────────────────────────────────────
    "cisa-kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "vulnerability",
        "data": "known exploited vulnerabilities with ransomware tags",
        "format": "json",
        "license": "Public Domain (US Gov)",
        "refresh": "daily",
        "status": "implemented",
    },
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "type": "vulnerability",
        "data": "CVE database with CVSS scores",
        "format": "json_api",
        "license": "Public Domain (US Gov)",
        "refresh": "real-time",
        "status": "implemented",
    },

    # ── Open-source IP/domain blocklists ───────────────────────────────────
    "firehol-level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "type": "ioc_feed",
        "data": "high-confidence malicious IPs (aggregated from 30+ feeds)",
        "format": "text",
        "license": "Open Source",
        "refresh": "hourly",
        "status": "implemented",
    },
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "type": "ioc_feed",
        "data": "daily threat intel from 30+ blacklists (scored by overlap)",
        "format": "text",
        "license": "Open Source",
        "refresh": "daily",
        "status": "implemented",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "ioc_feed",
        "data": "phishing URLs",
        "format": "text",
        "license": "Free (non-commercial)",
        "refresh": "hourly",
        "status": "implemented",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.json",
        "type": "ioc_feed",
        "data": "verified phishing URLs with target brands",
        "format": "json",
        "license": "Free (API key required)",
        "refresh": "hourly",
        "status": "planned",
    },
    "certstream": {
        "url": "wss://certstream.calidog.io",
        "type": "ioc_feed",
        "data": "real-time SSL certificate transparency logs (domain discovery)",
        "format": "websocket",
        "license": "Free",
        "refresh": "real-time",
        "status": "planned",
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "type": "ioc_feed",
        "data": "reported malicious IPs with confidence scores",
        "format": "json_api",
        "license": "Free (API key required)",
        "refresh": "real-time",
        "status": "implemented",
    },
    "spamhaus-drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "ioc_feed",
        "data": "IP ranges hijacked for spam/malware (Don't Route Or Peer)",
        "format": "text",
        "license": "Free (non-commercial)",
        "refresh": "daily",
        "status": "implemented",
    },
    "emergingthreats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ioc_feed",
        "data": "compromised IPs (Snort/Suricata compatible)",
        "format": "text",
        "license": "Free",
        "refresh": "daily",
        "status": "implemented",
    },
    "dataplane-sshpwauth": {
        "url": "https://dataplane.org/sshpwauth.txt",
        "type": "ioc_feed",
        "data": "SSH brute force attacker IPs",
        "format": "text",
        "license": "Free",
        "refresh": "daily",
        "status": "implemented",
    },
    "digitalside": {
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
        "type": "ioc_feed",
        "data": "IOCs from malware analysis (also available as STIX/MISP)",
        "format": "text",
        "license": "MIT",
        "refresh": "daily",
        "status": "implemented",
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ioc_feed",
        "data": "poorly-rated IPs not on other lists",
        "format": "text",
        "license": "Free",
        "refresh": "daily",
        "status": "implemented",
    },
    "bruteforceblocker": {
        "url": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "type": "ioc_feed",
        "data": "SSH brute force attacker IPs",
        "format": "text",
        "license": "Free",
        "refresh": "daily",
        "status": "implemented",
    },
    "hybrid-analysis": {
        "url": "https://www.hybrid-analysis.com/api/v2/feed/latest",
        "type": "ioc_feed",
        "data": "daily malware samples with verdicts (SHA-256 hashes)",
        "format": "json_api",
        "license": "Free (API key required)",
        "refresh": "daily",
        "status": "implemented",
    },
    "jpcert": {
        "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        "type": "ioc_feed",
        "data": "Japanese CERT security advisories",
        "format": "rss",
        "license": "Free",
        "refresh": "daily",
        "status": "implemented",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2: Independent labs & authoritative evaluations
# These are the most trusted vendor evaluation sources.
# ══════════════════════════════════════════════════════════════════════════════

TIER_2_LABS = {
    "mitre-attack-evals": {
        "url": "https://attackevals.mitre-engenuity.org",
        "type": "vendor_eval",
        "data": "EDR detection rates against real APT scenarios (8+ vendors)",
        "weight": 3.0,
        "license": "Apache 2.0",
        "status": "implemented",
    },
    "av-test": {
        "url": "https://www.av-test.org/en/antivirus/business-windows-client/",
        "type": "vendor_eval",
        "data": "independent lab scores: protection, performance, usability",
        "weight": 2.5,
        "license": "Public (scrape)",
        "status": "implemented",
    },
    "se-labs": {
        "url": "https://selabs.uk/reports/",
        "type": "vendor_eval",
        "data": "UK lab endpoint protection accuracy ratings",
        "weight": 2.5,
        "license": "Public (scrape)",
        "status": "implemented",
    },
    "av-comparatives": {
        "url": "https://www.av-comparatives.org/tests/real-world-protection-test/",
        "type": "vendor_eval",
        "data": "real-world protection test results (20+ vendors)",
        "weight": 2.5,
        "license": "Public (scrape)",
        "status": "implemented",
    },
    "cisa-kev-vendors": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "vendor_eval",
        "data": "which security tools have actively exploited CVEs (risk signal)",
        "weight": 2.0,
        "license": "Public Domain",
        "status": "implemented",
    },
    "fedramp-marketplace": {
        "url": "https://marketplace.fedramp.gov/products",
        "type": "compliance",
        "data": "FedRAMP authorized security products (government trust signal)",
        "weight": 2.0,
        "license": "Public Domain",
        "status": "planned",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3: Community & practitioner sources
# Real opinions from real practitioners. Higher volume, noisier signal.
# ══════════════════════════════════════════════════════════════════════════════

TIER_3_COMMUNITY = {
    "reddit": {
        "url": "https://www.reddit.com/r/netsec/search.json",
        "type": "community",
        "data": "practitioner discussions from r/netsec, r/cybersecurity, r/sysadmin",
        "weight": 1.0,
        "method": "public JSON API + optional LLM extraction",
        "status": "implemented",
    },
    "hackernews": {
        "url": "https://hn.algolia.com/api/v1/search",
        "type": "community",
        "data": "HN security tool discussions",
        "weight": 1.0,
        "method": "Algolia API + optional LLM extraction",
        "status": "implemented",
    },
    "stackexchange": {
        "url": "https://api.stackexchange.com/2.3/search",
        "type": "community",
        "data": "Security Stack Exchange Q&A about tools",
        "weight": 1.0,
        "method": "SE API + LLM extraction",
        "status": "implemented",
    },
    "g2-reviews": {
        "url": "https://www.g2.com/categories/endpoint-detection-and-response",
        "type": "vendor_eval",
        "data": "G2 peer review scores and sentiment",
        "weight": 0.8,
        "method": "hardcoded (public aggregate data)",
        "status": "implemented",
    },
    "gartner-peer-insights": {
        "url": "https://www.gartner.com/reviews/market/endpoint-detection-and-response",
        "type": "vendor_eval",
        "data": "Gartner Peer Insights practitioner reviews",
        "weight": 0.8,
        "method": "hardcoded (public aggregate data)",
        "status": "implemented",
    },
    "peerspot": {
        "url": "https://www.peerspot.com/categories/endpoint-detection-and-response-edr",
        "type": "vendor_eval",
        "data": "PeerSpot (formerly IT Central Station) reviews",
        "weight": 0.8,
        "method": "hardcoded (public aggregate data)",
        "status": "implemented",
    },
    "capterra": {
        "url": "https://www.capterra.com/endpoint-detection-and-response-software/",
        "type": "vendor_eval",
        "data": "Capterra ratings and reviews",
        "weight": 0.8,
        "method": "hardcoded (public aggregate data)",
        "status": "implemented",
    },
    "trustradius": {
        "url": "https://www.trustradius.com/endpoint-detection-and-response-edr",
        "type": "vendor_eval",
        "data": "TrustRadius verified reviews (requires work email)",
        "weight": 0.8,
        "method": "hardcoded (public aggregate data)",
        "status": "implemented",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 4: Market intelligence & metadata
# Pricing, adoption, job demand — signals about vendor health.
# ══════════════════════════════════════════════════════════════════════════════

TIER_4_MARKET = {
    "vendor-meta": {
        "type": "vendor_meta",
        "data": "pricing, certifications, insurance carriers, deploy time (36 vendors)",
        "weight": 0.3,
        "method": "curated",
        "status": "implemented",
    },
    "github-oss": {
        "url": "https://api.github.com/search/repositories",
        "type": "market",
        "data": "open-source security tool stars, activity, community size",
        "weight": 0.5,
        "method": "GitHub API",
        "status": "implemented",
    },
    "indeed-jobs": {
        "url": "https://www.indeed.com/jobs",
        "type": "market",
        "data": "job postings requiring specific security tools (adoption signal)",
        "weight": 0.3,
        "method": "HTML scrape",
        "status": "planned",
    },
    "greynoise": {
        "url": "https://api.greynoise.io/v3/community/",
        "type": "ioc_feed",
        "data": "internet scanner classification (benign vs malicious)",
        "weight": 1.5,
        "license": "Free (community API)",
        "status": "implemented",
    },
    "shodan": {
        "url": "https://api.shodan.io",
        "type": "ioc_feed",
        "data": "internet-exposed device and service discovery",
        "weight": 1.5,
        "license": "Free (API key, limited)",
        "status": "planned",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 5: Threat intelligence platforms (require API keys / partnerships)
# ══════════════════════════════════════════════════════════════════════════════

TIER_5_PLATFORMS = {
    "otx-alienvault": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "type": "ioc_feed",
        "data": "community threat pulses with IOCs, tags, references",
        "license": "Free (API key required)",
        "status": "implemented",
    },
    "misp-feeds": {
        "url": "https://www.misp-project.org/feeds/",
        "type": "ioc_feed",
        "data": "MISP community feeds (STIX/JSON format)",
        "license": "Various (mostly open)",
        "status": "planned",
    },
    "opencti": {
        "url": "https://www.opencti.io",
        "type": "platform",
        "data": "open cyber threat intelligence platform (STIX 2.1)",
        "license": "Apache 2.0",
        "status": "planned",
    },
    "facebook-threatexchange": {
        "url": "https://developers.facebook.com/docs/threat-exchange/",
        "type": "ioc_feed",
        "data": "privacy-controlled threat data sharing API",
        "license": "Free (requires approval)",
        "status": "planned",
    },
    "ibm-xforce": {
        "url": "https://exchange.xforce.ibmcloud.com/api/",
        "type": "ioc_feed",
        "data": "IP/URL/malware threat intelligence",
        "license": "Free (API key required)",
        "status": "planned",
    },
    "pulsedive": {
        "url": "https://pulsedive.com/api/",
        "type": "ioc_feed",
        "data": "community threat intelligence with risk scoring",
        "license": "Free (API key required)",
        "status": "implemented",
    },
    "crowdsec": {
        "url": "https://app.crowdsec.net/hub/collections",
        "type": "ioc_feed",
        "data": "crowd-sourced attack signals (near real-time)",
        "license": "Free (community)",
        "status": "planned",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

ALL_SOURCES = {}
ALL_SOURCES.update(TIER_1_FEEDS)
ALL_SOURCES.update(TIER_2_LABS)
ALL_SOURCES.update(TIER_3_COMMUNITY)
ALL_SOURCES.update(TIER_4_MARKET)
ALL_SOURCES.update(TIER_5_PLATFORMS)


def get_source_stats() -> dict:
    """Summary statistics for all known sources."""
    implemented = sum(1 for s in ALL_SOURCES.values() if s.get("status") == "implemented")
    planned = sum(1 for s in ALL_SOURCES.values() if s.get("status") == "planned")
    return {
        "total_sources": len(ALL_SOURCES),
        "implemented": implemented,
        "planned": planned,
        "by_tier": {
            "tier_1_feeds": len(TIER_1_FEEDS),
            "tier_2_labs": len(TIER_2_LABS),
            "tier_3_community": len(TIER_3_COMMUNITY),
            "tier_4_market": len(TIER_4_MARKET),
            "tier_5_platforms": len(TIER_5_PLATFORMS),
        },
    }
"""
To see what's available:
    from nur.scrapers.sources import ALL_SOURCES, get_source_stats
    print(get_source_stats())
    # {'total_sources': 45, 'implemented': 11, 'planned': 34}
"""
