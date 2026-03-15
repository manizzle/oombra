<h1 align="center">oombra</h1>

<p align="center"><strong>Collective security intelligence for industries. Give data, get smarter.</strong></p>

<p align="center">Your industry should be smarter together than any single company is alone.</p>

<p align="center">
  <img src="demo/oombra-demo.gif" alt="oombra demo" width="750" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/sources-19_live_feeds-ff6b6b" />
  <img src="https://img.shields.io/badge/sources-45_catalogued-ffa502" />
  <img src="https://img.shields.io/badge/tests-281_passing-2ed573" />
  <img src="https://img.shields.io/badge/python-3.11%2B-1e90ff" />
  <img src="https://img.shields.io/badge/code-Apache_2.0-1e90ff" />
  <img src="https://img.shields.io/badge/data-LGPL_3.0-f9ca24" />
</p>

---

Every hospital buys security tools based on vendor marketing. Every bank figures out their detection gaps by getting hacked. Every energy company fights the same APT without knowing three other utilities already beat it.

oombra fixes this. Two questions, one platform:

- **What's compromising us?** — IOCs, attack patterns, campaigns hitting your sector
- **What actually works?** — which tools catch what, real practitioner scores from real incidents

> ✅ Everything is anonymized on your machine. Nothing leaves without your approval. Math, not promises.

---

## 💡 Why this exists

Three assumptions the security industry is built on — and why they're wrong:

| Assumption | Reality |
|-----------|---------|
| "Sharing is altruistic" | Nobody shares out of goodness. oombra makes it selfish: **no contribution = no report**. Give to get. |
| "Threat intel = IOCs" | IOCs are one piece. Practitioners need: what tools catch this? What scores are others giving their EDR? What techniques are being missed sector-wide? |
| "You need a dashboard" | You need a CLI that works in SOAR pipelines, that AI agents can call, that scripts automate. `oombra report` — one command, JSON output, done. |

---

## 🚀 Get started

```bash
git clone https://github.com/manizzle/oombra.git
cd oombra
pip install -e ".[all,dev]"
oombra up --vertical healthcare
```

That starts the platform, scrapes **19 real data sources**, and you're ready.

```bash
oombra report your_incident_data.json
```

Two commands. Full loop. No config files.

---

## ⚔️ When you're under attack

```bash
oombra report incident_iocs.json
```

```
  Campaign Match: Yes — 4 other healthcare orgs
  Shared IOCs: 12
  Threat Actor: LockBit

  Actions:
    [CRITICAL] Block C2 domains at firewall
    [CRITICAL] Deploy T1490 detection — your tools miss it
    [HIGH]     Hunt for RDP lateral movement
```

You gave IOCs. You got campaign correlation, detection gaps, and a prioritized to-do list.

---

## 🛡️ When you're building defenses

```bash
oombra market edr                                    # who leads?
oombra search vendor crowdstrike                     # real scores
oombra search compare crowdstrike sentinelone        # side-by-side
oombra threat-map "ransomware" --tools crowdstrike   # coverage gaps
```

```
  Market Map: edr
  ══════════════════════════════════════════

  LEADERS:
    CrowdStrike Falcon          score=9.2  confidence=high
    SentinelOne Singularity     score=8.8  confidence=high

  CONTENDERS:
    Microsoft Defender          score=7.5  confidence=medium
```

Real data from 19 sources. Not vendor marketing. Not analyst reports funded by vendors.

---

## 🏥 The hospital scenario

**2:17 AM** — Ohio Children's Hospital. LockBit. EHR encrypted. NICU monitors offline.

```bash
oombra report lockbit_iocs.json         # Campaign Match: Yes. 12 shared IOCs.
oombra report lockbit_attack_map.json   # 7 detection gaps. T1490 critical.
oombra report our_crowdstrike.json      # 9.2 avg. 5 known gaps. Supplement.
```

**4:30 AM** — West Virginia gets the same ransom note. Their report is *better* — because Ohio contributed.

**Next week** — Ohio's CISO needs data for the board:

```bash
oombra market edr
oombra search compare crowdstrike sentinelone
oombra threat-map "ransomware" --tools crowdstrike
```

Real data. Not vendor slides.

---

## 📡 19 live data sources (45 catalogued)

oombra isn't an empty platform waiting for users. It scrapes real intelligence from public feeds and independent labs. **Day one, you have data.**

```bash
oombra scrape --list           # see all sources
oombra admin sources           # see all 45 with status
```

### IOC Feeds — *what's compromising us*

| Source | Data | License |
|--------|------|---------|
| [ThreatFox](https://threatfox.abuse.ch) | Domains, IPs, hashes with malware tags | CC0 |
| [Feodo Tracker](https://feodotracker.abuse.ch) | C2 server IPs (Emotet, QakBot, Pikabot) | CC0 |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware SHA-256 hashes | CC0 |
| [URLhaus](https://urlhaus.abuse.ch) | Malicious URLs (malware distribution) | CC0 |
| [SSL Blacklist](https://sslbl.abuse.ch) | Malicious SSL certificate fingerprints | CC0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited CVEs (ransomware-tagged) | Public Domain |
| [FireHOL](https://iplists.firehol.org) | High-confidence malicious IPs (30+ feeds aggregated) | Open Source |
| [IPsum](https://github.com/stamparm/ipsum) | Multi-blacklist scored IPs | Open Source |
| [OpenPhish](https://openphish.com) | Phishing URLs | Free |
| [Emerging Threats](https://rules.emergingthreats.net) | Compromised IPs (Snort/Suricata) | Free |
| [Dataplane](https://dataplane.org) | SSH brute force attacker IPs | Free |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked IP ranges | Free |

### Vendor Intelligence — *what actually works*

| Source | Data | Method |
|--------|------|--------|
| [MITRE ATT&CK Evals](https://attackevals.mitre-engenuity.org) | EDR detection rates (8 vendors) | Public results (weight: 3.0) |
| CISA KEV × Vendors | Security tools with exploited CVEs (risk signal) | Cross-reference 40+ keywords |
| [Reddit](https://reddit.com/r/netsec) | Practitioner discussions (30 vendors) | Public API + optional LLM |
| [Hacker News](https://news.ycombinator.com) | Security tool discussions (27 vendors) | Algolia API + optional LLM |
| [AV-TEST](https://www.av-test.org) | Independent lab scores (8 vendors) | Public results (weight: 2.5) |
| [SE Labs](https://selabs.uk) | UK lab endpoint protection (10 vendors) | Public results (weight: 2.5) |
| Vendor Metadata | Pricing, certs, insurance, deploy time (36 vendors) | Curated |

**26 more sources planned** — NVD, AV-Comparatives, FedRAMP, PhishTank, CertStream, AbuseIPDB, G2, Gartner, PeerSpot, StackExchange, GitHub, GreyNoise, Shodan, AlienVault OTX, MISP feeds, OpenCTI, IBM X-Force, Pulsedive, CrowdSec, and more.

---

## 🏗️ Deploy for your industry

oombra is a stack. Deploy it for hospitals. Deploy it for banks. **Build a company on it.**

```bash
oombra up --vertical healthcare     # LockBit, HIPAA, hospital playbooks
oombra up --vertical financial      # APT28/Lazarus, PCI DSS, SWIFT isolation
oombra up --vertical energy         # Sandworm, NERC CIP, ICS/OT focus
oombra up --vertical government     # APT29, FISMA, supply chain
```

**Docker (production):**
```bash
cp .env.example .env
docker compose --profile production up -d
```

| Variable | Default | What it does |
|----------|---------|-------------|
| `OOMBRA_API_KEY` | — | API key for write endpoints |
| `OOMBRA_MIN_K` | `3` | Min contributors before showing aggregates |
| `OOMBRA_AUTO_INGEST` | `0` | `1` = hourly feed scraping |
| `OOMBRA_PORT` | `8000` | Port to expose |

**Your users:**
```bash
pip install oombra && oombra init && oombra report incident.json
```

---

## 🔌 Integrate anywhere

**Python:**
```python
from oombra import load_file, anonymize, submit

data  = load_file("incident.json")          # JSON, STIX, MISP, CSV, PDF
clean = [anonymize(d) for d in data]         # anonymize locally
[submit(c, api_url="http://oombra:8000") for c in clean]
```

**CLI + JSON (AI agents, SOAR, scripts):**
```bash
oombra report incident.json --json | jq '.intelligence.actions'
oombra market edr --json | jq '.tiers.leaders'
oombra search vendor crowdstrike --json
```

**API:**

| Endpoint | Mode | What it does |
|----------|------|-------------|
| `POST /analyze` | ⚔️ | Give data, get intelligence report |
| `POST /contribute/*` | ⚔️ | Submit IOCs, attack maps, evals |
| `GET /intelligence/market/{cat}` | 🛡️ | Market map (leaders/contenders) |
| `POST /intelligence/threat-map` | 🛡️ | MITRE coverage gap analysis |
| `GET /intelligence/danger-radar` | 🛡️ | Hidden vendor risk signals |
| `GET /search/vendor/{name}` | 🛡️ | Weighted vendor scores |
| `GET /search/category/{name}` | 🛡️ | Category ranking |
| `GET /search/compare?a=X&b=Y` | 🛡️ | Side-by-side comparison |
| `GET /query/techniques` | Both | Top MITRE techniques |
| `GET /docs` | Both | OpenAPI documentation |

---

## 🔐 How privacy works

Everything anonymized **on your machine** before anything touches the network.

| What you share | What leaves | How |
|---------------|------------|-----|
| Raw IOCs | Keyed fingerprints | HMAC-SHA256 with org secret — can't be reversed |
| Attack notes | Scrubbed text | 4-pass regex — no IPs, names, hostnames |
| Org context | Bucketed | `healthcare`, `1000-5000` — never your name |
| Tool scores | Noised values | Differential privacy (Laplace) |
| All of the above | Attested | ADTC cryptographic proof chain |

Server returns aggregates only. Never individual contributions. Min-k enforcement (3+ contributors). Full analysis → [THREAT_MODEL.md](THREAT_MODEL.md)

---

## 🔧 Admin

```bash
oombra admin status         # server health + feed freshness
oombra admin sources        # all 45 data sources by tier
oombra admin db-stats       # detailed database breakdown
oombra admin export         # dump all aggregated data as JSON
oombra admin rotate-key     # generate new API key
```

---

## 🧪 Tests

```bash
pytest           # 281 tests across 12 files
pytest -v        # verbose
```

---

## 📄 License

| Component | License |
|-----------|---------|
| Code | [Apache 2.0](LICENSE) |
| Threat intel data | [LGPL 3.0](DATA_LICENSE.md) — open data |
| abuse.ch feeds | CC0 1.0 (public domain) |
| CISA KEV | US Government public domain |
| MITRE ATT&CK | Apache 2.0 |
