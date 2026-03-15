# oombra 🔒

Threat intelligence platform that gives you back more than you give. Share your anonymized incident data — get campaign matches, detection gaps, vendor benchmarks, and prioritized actions from every other contributor. Deploy it for any industry. Build a company on it.

<p align="center">
  <img src="demo/oombra-demo.gif" alt="oombra demo" width="700" />
</p>

## Table of Contents

- [👋 Overview](#-overview)
- [💻 How to Install](#-how-to-install)
- [🚀 How to Run](#-how-to-run)
- [⚔️ War Mode — Incident Response](#️-war-mode--incident-response)
- [🛡️ Peace Mode — Strengthen Defenses](#️-peace-mode--strengthen-defenses)
- [🏥 The Hospital Scenario](#-the-hospital-scenario)
- [🔌 How to Integrate](#-how-to-integrate)
- [🏗️ How to Deploy](#️-how-to-deploy)
- [🔐 How Privacy Works](#-how-privacy-works)
- [📡 Live Threat Feeds](#-live-threat-feeds)
- [🧪 How to Test](#-how-to-test)
- [📄 License](#-license)

## 👋 Overview

Two modes. One platform.

```
  PEACE MODE                         WAR MODE
  "Strengthen my system"             "I'm getting hacked"

  oombra market edr                  oombra report iocs.json
  oombra search vendor crowdstrike   oombra report attack_map.json
  oombra search compare X Y          oombra report eval.json
  oombra threat-map "ransomware"

  You give: tool evaluations         You give: incident data
  You get:  market intel, stack      You get:  campaign matches,
    gaps, vendor risk signals          detection gaps, actions
```

Your peacetime tool eval helps someone in wartime. Their wartime IOCs help your peacetime planning. Same database. Same give-to-get.

**Key Capabilities:**
- **Campaign Correlation**: Upload IOCs, discover you're part of a campaign hitting 4 other orgs
- **Detection Gap Analysis**: Find MITRE techniques your tools miss that others catch
- **Market Maps**: Leaders, contenders, emerging vendors — weighted by source authority
- **Vendor Search**: Real practitioner scores, side-by-side comparisons, danger signals
- **Threat Mapping**: Map any threat description to MITRE techniques, find coverage gaps
- **Live Feed Ingestion**: Auto-scrapes ThreatFox, Feodo Tracker, MalwareBazaar, CISA KEV
- **Industry Verticals**: Healthcare, financial, energy, government — deploy for any sector
- **Mathematical Privacy**: HMAC-hashed IOCs, differential privacy, k-anonymity, attestation chains
- **AI-Native**: JSON output on every command, Python SDK, zero-config after setup

[![Tests](https://img.shields.io/badge/tests-281%20passing-brightgreen)](#-how-to-test)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Code](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Data](https://img.shields.io/badge/data-LGPL--3.0-orange)](DATA_LICENSE.md)

## 💻 How to Install

Don't want to read? Got it:

```bash
git clone https://github.com/manizzle/oombra.git
cd oombra
pip install -e ".[all,dev]"
```

> ✅ Everything is anonymized on your machine. Nothing leaves without your approval.

## 🚀 How to Run

Two commands. That's the full loop.

```bash
# Terminal 1 — start the platform (server + live feeds + data)
oombra up

# Or with an industry vertical
oombra up --vertical healthcare

# Terminal 2 — use it
oombra report incident_iocs.json        # war mode: give data, get intel
oombra market edr                        # peace mode: market map
oombra search vendor crowdstrike         # peace mode: vendor lookup
```

`oombra up` starts the server, scrapes 750+ real IOCs from public feeds, seeds the database, and saves your config. No `--api-url`. No flags. No config files.

## ⚔️ War Mode — Incident Response

You're getting hacked. You have IOCs, attack observations, and you need answers NOW.

```bash
# "Am I alone?" — give IOCs, get campaign correlation
oombra report incident_iocs.json

# "What am I missing?" — give attack map, get detection gaps
oombra report attack_map.json

# "What tools work?" — give eval, get real benchmarks
oombra report our_crowdstrike_eval.json
```

**What you get back:**
```
  Campaign Match: Yes — 4 other healthcare orgs
  Shared IOCs: 12
  Threat Actor: LockBit

  Actions:
    [CRITICAL] Block C2 domains at firewall
    [CRITICAL] Deploy T1490 detection — your tools miss it
    [HIGH]     Hunt for RDP lateral movement (T1021)
```

**No contribution = no report. That's the deal.**

## 🛡️ Peace Mode — Strengthen Defenses

No incident. You're planning, building your stack, finding gaps before attackers do.

```bash
# Market map — who leads in EDR?
oombra market edr

# Vendor deep dive — weighted scores from multiple sources
oombra search vendor crowdstrike

# Side-by-side — objective comparison
oombra search compare crowdstrike sentinelone

# Threat coverage — map a threat to MITRE, find gaps
oombra threat-map "ransomware lateral movement" --tools crowdstrike,splunk

# Danger radar — vendors with hidden risks
curl http://localhost:8000/intelligence/danger-radar | python3 -m json.tool
```

**What you get back:**
```
  Market Map: edr
  ══════════════════════════════════════════════════

  LEADERS (2):
    CrowdStrike Falcon          score=9.2  confidence=high
    SentinelOne Singularity     score=8.8  confidence=high

  CONTENDERS (1):
    Microsoft Defender           score=7.5  confidence=medium
```

## 🏥 The Hospital Scenario

It's 2AM. Ohio Children's Hospital gets hit with LockBit. EHR encrypted. NICU monitors offline.

**War mode — the IR team acts:**
```bash
oombra report lockbit_iocs.json       # Campaign Match: Yes. 12 shared IOCs.
oombra report lockbit_attack_map.json # 7 detection gaps. T1490 critical.
oombra report our_crowdstrike.json    # 9.2 avg. 5 known gaps. Supplement.
```

At 4:30 AM, West Virginia gets the same ransom note. Their report is **better** — because Ohio contributed. Every hospital that shares makes the next one safer.

**Peace mode — the CISO plans (next week):**
```bash
oombra market edr                      # who leads in EDR?
oombra search compare crowdstrike sentinelone  # objective data
oombra threat-map "ransomware" --tools crowdstrike  # where are our gaps?
```

Real data for the board. Not vendor marketing.

## 🔌 How to Integrate

**Python SDK (3 lines):**
```python
from oombra import load_file, anonymize, submit

data  = load_file("incident_iocs.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="http://oombra:8000") for c in clean]
```

**CLI with JSON output (for AI agents / SOAR):**
```bash
oombra report incident.json --json | jq '.intelligence.actions'
oombra market edr --json | jq '.tiers.leaders'
oombra search vendor crowdstrike --json | jq '.weighted_score'
```

**Server API:**

| Method | Endpoint | Mode | What it does |
|--------|----------|------|-------------|
| `POST` | `/analyze` | War | Give data, get intelligence report |
| `POST` | `/contribute/ioc-bundle` | War | Submit IOCs |
| `POST` | `/contribute/attack-map` | War | Submit attack map |
| `POST` | `/contribute/submit` | War | Submit tool evaluation |
| `GET` | `/intelligence/market/{cat}` | Peace | Market map (leaders/contenders) |
| `POST` | `/intelligence/threat-map` | Peace | MITRE coverage gap analysis |
| `GET` | `/intelligence/danger-radar` | Peace | Hidden vendor risk signals |
| `GET` | `/search/vendor/{name}` | Peace | Weighted vendor scores |
| `GET` | `/search/category/{name}` | Peace | Category ranking |
| `GET` | `/search/compare?a=X&b=Y` | Peace | Side-by-side comparison |
| `GET` | `/query/techniques` | Both | Top MITRE techniques |
| `GET` | `/stats` | Both | Contribution counts |
| `GET` | `/docs` | Both | OpenAPI documentation |

## 🏗️ How to Deploy

oombra is a stack anyone can deploy. Start a threat intel sharing platform for hospitals, banks, energy companies. Your users contribute anonymized data, you run the server, everyone gets intelligence.

```bash
git clone https://github.com/manizzle/oombra.git
cd oombra
cp .env.example .env        # edit with your settings
docker compose up            # SQLite, zero config
```

**Production (PostgreSQL + auto-ingest):**
```bash
docker compose --profile production up -d
```

**With a vertical:**
```bash
oombra up --vertical healthcare    # hospitals
oombra up --vertical financial     # banks, fintech
oombra up --vertical energy        # power grids, ICS/OT
oombra up --vertical government    # federal, state, local
```

Each vertical comes with relevant threat actors, priority MITRE techniques, compliance frameworks, and action templates.

**Configuration (`.env`):**

| Variable | Default | What it does |
|----------|---------|-------------|
| `OOMBRA_API_KEY` | *(none)* | API key for write endpoints |
| `OOMBRA_MIN_K` | `3` | Min contributors before showing aggregates |
| `OOMBRA_AUTO_INGEST` | `0` | Set `1` for hourly threat feed scraping |
| `OOMBRA_PORT` | `8000` | Port to expose |
| `POSTGRES_PASSWORD` | `oombra` | PostgreSQL password (production) |

**Your users just need:**
```bash
pip install oombra
oombra init                          # point to your server
oombra report their_incident.json    # contribute + get intelligence
```

## 🔐 How Privacy Works

Everything is anonymized **on your machine** before anything touches the network.

| What you share | What happens | What leaves |
|---------------|-------------|------------|
| Raw IOCs | HMAC-SHA256 with your org's secret key | Keyed fingerprints only |
| Attack notes | 4-pass PII/security regex scrubbing | `[IP_ADDR]`, `[EMAIL]`, etc. |
| Org context | k-anonymity bucketing | `healthcare`, `1000-5000` |
| Tool scores | Calibrated Laplace noise (optional) | DP-noised values |
| Everything | ADTC attestation chain | Cryptographic proof |

| Attack | Defense |
|--------|---------|
| IOC rainbow tables | HMAC-SHA256 per-org secret key |
| IOC list exposure | ECDH Private Set Intersection |
| PII in data | 4-pass scrubbing + Verifiable Absence Proof |
| Score inference | Differential privacy (Laplace noise) |
| Skipped anonymization | ADTC attestation chain |
| Data poisoning | Byzantine aggregation + ZKP range proofs |

Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

## 📡 Live Threat Feeds

oombra auto-ingests real IOCs from public feeds so reports match against the entire threat landscape.

```bash
oombra scrape --list          # show available feeds
oombra scrape                 # scrape all, upload to server
oombra scrape --dry-run       # scrape without uploading
```

| Feed | Source | License | What it provides |
|------|--------|---------|-----------------|
| ThreatFox | abuse.ch | CC0 1.0 | Domains, IPs, hashes with malware tags |
| Feodo Tracker | abuse.ch | CC0 1.0 | C2 server IPs (Emotet, QakBot) |
| MalwareBazaar | abuse.ch | CC0 1.0 | Recent malware SHA-256 hashes |
| CISA KEV | cisa.gov | Public domain | Ransomware-related exploited CVEs |

`oombra up` scrapes all feeds automatically on startup.

## 🧪 How to Test

```bash
pytest           # 281 tests across 12 files
pytest -v        # verbose
pytest -x        # stop on first failure
```

Includes property-based tests via [Hypothesis](https://hypothesis.readthedocs.io/) — "no generated email/IP survives scrub()."

## 🤝 How to Contribute

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

- **Code**: [Apache 2.0](LICENSE)
- **Data** (threat intel, capabilities, MITRE mappings): [LGPL 3.0](DATA_LICENSE.md) — open data, free to use
- **Third-party feeds**: CC0 1.0 (abuse.ch), Public Domain (CISA), Apache 2.0 (MITRE ATT&CK)
