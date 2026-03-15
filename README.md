<h1 align="center">vigil</h1>

<p align="center"><strong>Collective security intelligence for industries. Give data, get smarter.</strong></p>

<p align="center">Your industry should be smarter together than any single company is alone.</p>

<p align="center">
  <img src="demo/vigil-demo.gif" alt="vigil demo" width="750" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/sources-35_live-ff6b6b" />
  <img src="https://img.shields.io/badge/sources-45_catalogued-ffa502" />
  <img src="https://img.shields.io/badge/tests-281_passing-2ed573" />
  <img src="https://img.shields.io/badge/python-3.11%2B-1e90ff" />
  <img src="https://img.shields.io/badge/code-Apache_2.0-1e90ff" />
  <img src="https://img.shields.io/badge/data-LGPL_3.0-f9ca24" />
</p>

---

Every hospital buys security tools based on vendor marketing. Every bank figures out their detection gaps by getting hacked. Every energy company fights the same APT without knowing three other utilities already beat it.

vigil fixes this. Two questions, one platform:

- **What's compromising us?** — IOCs, attack patterns, campaigns hitting your sector
- **What actually works?** — which tools catch what, real practitioner scores from real incidents

> ✅ Everything is anonymized on your machine. Nothing leaves without your approval. Math, not promises.

---

## 💡 Why this exists

Three assumptions the security industry is built on — and why they're wrong:

| Assumption | Reality |
|-----------|---------|
| "Sharing is altruistic" | Nobody shares out of goodness. vigil makes it selfish: **no contribution = no report**. Give to get. |
| "Threat intel = IOCs" | IOCs are one piece. Practitioners need: what tools catch this? What scores are others giving their EDR? What techniques are being missed sector-wide? |
| "You need a dashboard" | You need a CLI that works in SOAR pipelines, that AI agents can call, that scripts automate. `vigil report` — one command, JSON output, done. |

---

## 🚀 Get started

```bash
git clone https://github.com/manizzle/oombra.git
cd vigil
pip install -e ".[all,dev]"
vigil up --vertical healthcare
```

That starts the platform, scrapes **19 real data sources**, and you're ready.

```bash
vigil report your_incident_data.json
```

Two commands. Full loop. No config files.

---

## ⚔️ When you're under attack

```bash
vigil report incident_iocs.json
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
vigil market edr                                    # who leads?
vigil search vendor crowdstrike                     # real scores
vigil search compare crowdstrike sentinelone        # side-by-side
vigil threat-map "ransomware" --tools crowdstrike   # coverage gaps
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
vigil report lockbit_iocs.json         # Campaign Match: Yes. 12 shared IOCs.
vigil report lockbit_attack_map.json   # 7 detection gaps. T1490 critical.
vigil report our_crowdstrike.json      # 9.2 avg. 5 known gaps. Supplement.
```

**4:30 AM** — West Virginia gets the same ransom note. Their report is *better* — because Ohio contributed.

**Next week** — Ohio's CISO needs data for the board:

```bash
vigil market edr
vigil search compare crowdstrike sentinelone
vigil threat-map "ransomware" --tools crowdstrike
```

Real data. Not vendor slides.

---

## 📡 35 live data sources (45 catalogued)

vigil isn't an empty platform waiting for users. It scrapes real intelligence from public feeds, independent labs, review platforms, and community discussions. **Day one, you have 658,000+ data points.**

```bash
vigil scrape --list           # see all sources
vigil admin sources           # see all 45 with tier/status
```

### IOC Feeds (20) — *what's compromising us*

| Source | Data | License |
|--------|------|---------|
| [ThreatFox](https://threatfox.abuse.ch) | Domains, IPs, hashes with malware tags | CC0 |
| [Feodo Tracker](https://feodotracker.abuse.ch) | C2 server IPs (Emotet, QakBot, Pikabot) | CC0 |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware SHA-256 hashes | CC0 |
| [URLhaus](https://urlhaus.abuse.ch) | Malicious URLs (malware distribution) | CC0 |
| [SSL Blacklist](https://sslbl.abuse.ch) | Malicious SSL certificate fingerprints | CC0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited CVEs (ransomware-tagged) | Public Domain |
| [NVD](https://nvd.nist.gov) | CVE database with CVSS scores | Public Domain |
| [FireHOL](https://iplists.firehol.org) | High-confidence malicious IPs (30+ feeds aggregated) | Open Source |
| [IPsum](https://github.com/stamparm/ipsum) | Multi-blacklist scored IPs | Open Source |
| [OpenPhish](https://openphish.com) | Phishing URLs | Free |
| [Emerging Threats](https://rules.emergingthreats.net) | Compromised IPs | Free |
| [Dataplane](https://dataplane.org) | SSH brute force attacker IPs | Free |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked IP ranges | Free |
| [DigitalSide](https://osint.digitalside.it) | Malware-related IPs (STIX/MISP) | MIT |
| [CINS Score](https://cinsscore.com) | Poorly-rated suspicious IPs | Free |
| [BruteForceBlocker](https://danger.rulez.sk) | SSH brute force IPs | Free |
| [AbuseIPDB](https://abuseipdb.com) | Reported malicious IPs *(API key)* | Free |
| [AlienVault OTX](https://otx.alienvault.com) | Community threat pulses *(API key)* | Free |
| [Pulsedive](https://pulsedive.com) | Community threat intel *(API key)* | Free |
| [GreyNoise](https://greynoise.io) | Internet scanner classification *(API key)* | Free |

### Vendor Intelligence (15) — *what actually works*

| Source | Data | Weight |
|--------|------|--------|
| [MITRE ATT&CK Evals](https://attackevals.mitre-engenuity.org) | EDR detection rates (8 vendors) | 3.0 |
| [AV-TEST](https://www.av-test.org) | Independent lab scores (8 vendors) | 2.5 |
| [SE Labs](https://selabs.uk) | UK lab endpoint protection (10 vendors) | 2.5 |
| [AV-Comparatives](https://av-comparatives.org) | Real-world protection test (8 vendors) | 2.5 |
| CISA KEV × Vendors | Security tools with exploited CVEs | 2.0 |
| [Reddit](https://reddit.com/r/netsec) | Practitioner discussions (30 vendors) | 1.0 |
| [Hacker News](https://news.ycombinator.com) | Security tool discussions (27 vendors) | 1.0 |
| [Stack Exchange](https://security.stackexchange.com) | Security Q&A (30 vendors) | 1.0 |
| [G2](https://g2.com) | Peer review scores (10 vendors) | 0.8 |
| [Gartner Peer Insights](https://gartner.com/reviews) | Enterprise practitioner reviews | 0.8 |
| [PeerSpot](https://peerspot.com) | Verified enterprise reviews | 0.8 |
| [Capterra](https://capterra.com) | SMB/mid-market ratings | 0.8 |
| [TrustRadius](https://trustradius.com) | Verified business reviews | 0.8 |
| [GitHub](https://github.com) | Open-source tool popularity signals | 0.5 |
| Vendor Metadata | Pricing, certs, insurance (36 vendors) | 0.3 |

Raw data snapshots available in `data/feeds/` (658,000+ records, CDLA-Permissive-2.0).

> 🔑 **Want to help?** 4 feeds just need free API keys — [grab one and help us](https://github.com/manizzle/oombra/issues/1). Run a threat intel feed? [Get listed on this page](https://github.com/manizzle/oombra/issues/2).

---

## 🏗️ Deploy for your industry

vigil is a stack. Deploy it for hospitals. Deploy it for banks. **Build a company on it.**

```bash
vigil up --vertical healthcare     # LockBit, HIPAA, hospital playbooks
vigil up --vertical financial      # APT28/Lazarus, PCI DSS, SWIFT isolation
vigil up --vertical energy         # Sandworm, NERC CIP, ICS/OT focus
vigil up --vertical government     # APT29, FISMA, supply chain
```

**Docker (production):**
```bash
cp .env.example .env
docker compose --profile production up -d
```

| Variable | Default | What it does |
|----------|---------|-------------|
| `VIGIL_API_KEY` | — | API key for write endpoints |
| `VIGIL_MIN_K` | `3` | Min contributors before showing aggregates |
| `VIGIL_AUTO_INGEST` | `0` | `1` = hourly feed scraping |
| `VIGIL_PORT` | `8000` | Port to expose |

**Your users:**
```bash
pip install vigil && vigil init && vigil report incident.json
```

---

## 🔌 Integrate anywhere

**Python:**
```python
from vigil import load_file, anonymize, submit

data  = load_file("incident.json")          # JSON, STIX, MISP, CSV, PDF
clean = [anonymize(d) for d in data]         # anonymize locally
[submit(c, api_url="http://vigil:8000") for c in clean]
```

**CLI + JSON (AI agents, SOAR, scripts):**
```bash
vigil report incident.json --json | jq '.intelligence.actions'
vigil market edr --json | jq '.tiers.leaders'
vigil search vendor crowdstrike --json
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
vigil admin status         # server health + feed freshness
vigil admin sources        # all 45 data sources by tier
vigil admin db-stats       # detailed database breakdown
vigil admin export         # dump all aggregated data as JSON
vigil admin rotate-key     # generate new API key
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
