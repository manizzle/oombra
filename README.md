# oombra 🔒

An AI-native threat intelligence sharing tool that gives you back more than you give. Share your anonymized incident data — get campaign matches, detection gaps, and prioritized actions from every other contributor. Think VirusTotal, but for cross-org incident correlation with mathematical privacy guarantees.

<p align="center">
  <img src="demo/oombra-demo.gif" alt="oombra demo" width="700" />
</p>

## Table of Contents

- [👋 Overview](#-overview)
- [💻 How to Install](#-how-to-install)
- [🚀 How to Run](#-how-to-run)
- [🏥 The Hospital Scenario](#-the-hospital-scenario)
- [🔌 How to Integrate](#-how-to-integrate)
- [🛡️ How Privacy Works](#️-how-privacy-works)
- [📡 Live Threat Feeds](#-live-threat-feeds)
- [🧪 How to Test](#-how-to-test)
- [🤝 How to Contribute](#-how-to-contribute)
- [📄 License](#-license)

## 👋 Overview

oombra takes your raw incident data — IOCs, MITRE ATT&CK observations, tool evaluations — anonymizes it locally on your machine, and uploads it to a shared platform. In return, you get an intelligence report: which campaigns match your IOCs, which MITRE techniques your tools miss that others catch, and what to do about it.

**No contribution = no report. That's the deal.**

**Key Capabilities:**
- **Campaign Correlation**: Upload IOCs, discover you're part of a campaign hitting 4 other orgs
- **Detection Gap Analysis**: Find which MITRE techniques your tools miss that others catch
- **Tool Benchmarking**: Real practitioner scores from real incidents — not Gartner
- **Live Feed Ingestion**: Auto-scrapes ThreatFox, Feodo Tracker, MalwareBazaar, CISA KEV
- **Mathematical Privacy**: HMAC-hashed IOCs, differential privacy, k-anonymity, attestation chains
- **AI-Native**: JSON output on every command, Python SDK, zero-config after setup

[![Tests](https://img.shields.io/badge/tests-270%20passing-brightgreen)](#-how-to-test)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

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
# Terminal 1 — start the platform
oombra up

# Terminal 2 — give data, get intelligence
oombra report your_incident_iocs.json
```

`oombra up` starts the server, scrapes 750+ real IOCs from public threat feeds, seeds the database, and saves your config. No `--api-url`. No flags. No config files.

**What you get back:**
```
  Analysis Report
  ══════════════════════════════════════════════════
  Campaign Match: Yes
  Summary: Your IOCs match 12 indicators seen by other organizations.
  Threat Actors: LockBit
  Shared IOCs: 12

  Actions (3):
    [CRITICAL] Block C2 domains/IPs at firewall and DNS
    [HIGH]     Hunt for related activity — cross-reference 12 matched IOCs
    [MEDIUM]   Share findings with your sector ISAC
```

## 🏥 The Hospital Scenario

It's 2AM. A children's hospital in Ohio gets hit with LockBit. EHR encrypted. NICU monitors offline. The IR team pulls IOCs — C2 domains, payload hashes, attacker IPs.

They can't share the raw data (HIPAA, internal network details). But they need to know if anyone else is being hit.

```bash
oombra report lockbit_iocs.json
```

**Campaign Match: Yes.** 12 shared IOCs. 3 other hospitals saw the same LockBit C2 domain. The platform told them in seconds what would take days through an ISAC.

```bash
oombra report lockbit_attack_map.json
```

**7 detection gaps.** CrowdStrike misses T1490 (VSS deletion). SentinelOne catches it. Ohio's IR team now knows exactly what detection rule to deploy.

```bash
oombra report our_crowdstrike_eval.json
```

**CrowdStrike scores 9.2** — above average. But 5 known technique gaps from cross-org data. Don't switch vendors. Supplement with Sigma rules.

At 4:30 AM, a rural hospital in West Virginia gets the same ransom note. They run `oombra report`. Their report is **better** than Ohio's — because Ohio contributed. Every hospital that shares makes the next one safer.

## 🔌 How to Integrate

**Python SDK (3 lines):**
```python
from oombra import load_file, anonymize, submit

data  = load_file("incident_iocs.json")            # JSON, STIX, MISP, CSV, PDF
clean = [anonymize(d) for d in data]                # anonymize locally
[submit(c, api_url="http://oombra:8000") for c in clean]
```

**CLI with JSON output (for AI agents):**
```bash
oombra report incident.json --json | jq '.intelligence.actions'
oombra preview incident.json --json | jq '.iocs | length'
```

**Full pipeline:**
```python
from oombra import pipeline

results = pipeline("data.json", api_url="http://oombra:8000", epsilon=5.0, auto_approve=True)
```

**Server API:**

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/analyze` | Give data, get intelligence report |
| `POST` | `/contribute/ioc-bundle` | Submit IOCs |
| `POST` | `/contribute/attack-map` | Submit attack map |
| `POST` | `/contribute/submit` | Submit tool evaluation |
| `GET` | `/query/techniques` | Top MITRE techniques |
| `GET` | `/query/category/{name}` | Tool scores in category |
| `GET` | `/stats` | Contribution counts |

API key auth: set `OOMBRA_API_KEY` env var. Min-k privacy: aggregates require 3+ contributors.

## 🛡️ How Privacy Works

Everything is anonymized **on your machine** before anything touches the network.

| What you share | What happens | What leaves your machine |
|---------------|-------------|------------------------|
| Raw IOCs | HMAC-SHA256 with your org's secret key | Keyed fingerprints only |
| Attack notes | 4-pass PII/security regex scrubbing | `[IP_ADDR]`, `[EMAIL]`, etc. |
| Org context | k-anonymity bucketing | `healthcare`, `1000-5000` |
| Tool scores | Calibrated Laplace noise (optional) | DP-noised values |
| Everything | ADTC attestation chain | Cryptographic proof |

**Attack → Defense mapping:**

| Attack | Defense |
|--------|---------|
| IOC rainbow tables | HMAC-SHA256 per-org secret key |
| IOC list exposure | ECDH Private Set Intersection |
| PII in submitted data | 4-pass scrubbing + Verifiable Absence Proof |
| Score inference | Differential privacy (Laplace noise) |
| Skipped anonymization | ADTC attestation chain |
| Data poisoning | Byzantine aggregation + ZKP range proofs |

Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

## 📡 Live Threat Feeds

oombra auto-ingests real IOCs from public feeds so your reports match against the entire threat landscape — not just other users' contributions.

```bash
oombra scrape --list          # show available feeds
oombra scrape                 # scrape all, upload to server
oombra scrape --dry-run       # scrape without uploading
```

| Feed | Source | What it provides |
|------|--------|-----------------|
| ThreatFox | abuse.ch | Domains, IPs, hashes with malware tags |
| Feodo Tracker | abuse.ch | C2 server IPs (Emotet, QakBot) |
| MalwareBazaar | abuse.ch | Recent malware SHA-256 hashes |
| CISA KEV | cisa.gov | Ransomware-related exploited CVEs |

`oombra up` scrapes all feeds automatically on startup.

## 🧪 How to Test

```bash
pytest           # 270 tests across 12 files
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

Apache 2.0
