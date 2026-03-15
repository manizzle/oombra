# oombra

**Your industry should be smarter together than any single company is alone.**

Right now, every hospital buys security tools based on vendor marketing. Every bank figures out their detection gaps by getting hacked. Every energy company fights the same APT without knowing three other utilities already beat it.

oombra is collective intelligence for industries. Two questions, one platform:

1. **What's compromising us?** — IOCs, attack patterns, campaigns hitting your sector
2. **What actually works?** — which tools catch what, real scores from real incidents

The privacy layer is what makes people actually willing to participate. Everything is anonymized on your machine before it leaves. Math, not promises.

<p align="center">
  <img src="demo/oombra-demo.gif" alt="oombra demo" width="700" />
</p>

[![Tests](https://img.shields.io/badge/tests-281%20passing-brightgreen)](#tests)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Code](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE)
[![Data](https://img.shields.io/badge/data-LGPL--3.0-orange)](DATA_LICENSE.md)

---

## Why this exists

Three assumptions the security industry is built on — and why they're wrong:

**1. "Sharing threat intel is altruistic."** Wrong. Nobody shares out of goodness. oombra makes sharing selfish: you can't get a report without contributing. Your data makes the next person's report better. Their data made yours possible. Give to get.

**2. "Threat intel = IOCs."** Wrong. IOCs are one piece. What practitioners actually need is: what tools catch this attack? What are other orgs in my industry scoring their EDR? What MITRE techniques are being missed across the sector? It's collective intelligence about tools AND compromise, not just indicator feeds.

**3. "You need a dashboard."** Wrong. You need a CLI that works in SOAR pipelines, that AI agents can call, that scripts can automate. The interface is `oombra report incident.json` — one command, structured JSON output, done.

---

## Get started

```bash
git clone https://github.com/manizzle/oombra.git
cd oombra
pip install -e ".[all,dev]"
oombra up --vertical healthcare
```

That starts the platform, scrapes 11 real data sources, and you're ready. In another terminal:

```bash
oombra report your_incident_data.json
```

> ✅ Everything is anonymized on your machine. Nothing leaves without your approval.

---

## What you get

### When you're under attack

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

You gave IOCs. You got campaign correlation, detection gaps, and a to-do list. Seconds, not days.

### When you're building defenses

```bash
oombra market edr                                    # who leads in EDR?
oombra search vendor crowdstrike                     # real scores, not Gartner
oombra search compare crowdstrike sentinelone        # objective side-by-side
oombra threat-map "ransomware" --tools crowdstrike   # where are your gaps?
```

Real data from 11 sources. Not vendor marketing. Not analyst reports funded by vendors. Collective intelligence from practitioners, independent labs, and public threat feeds.

---

## The hospital scenario

It's 2AM. Ohio Children's Hospital gets hit with LockBit. EHR encrypted. NICU monitors offline.

```bash
oombra report lockbit_iocs.json         # Campaign Match: Yes. 12 shared IOCs.
oombra report lockbit_attack_map.json   # 7 detection gaps. T1490 critical.
oombra report our_crowdstrike.json      # 9.2 avg. 5 known gaps. Supplement.
```

At 4:30 AM, West Virginia gets the same ransom note. Their report is better — because Ohio contributed. Every hospital that shares makes the next one safer.

Next week, Ohio's CISO needs data for the board:

```bash
oombra market edr
oombra search compare crowdstrike sentinelone
oombra threat-map "ransomware" --tools crowdstrike
```

Real data. Not vendor slides. The board sees objective scores from across the industry.

---

## 11 data sources

oombra isn't an empty platform waiting for users. It scrapes real intelligence from public feeds and independent labs. Day one, you have data.

```bash
oombra scrape --list
```

**IOC Feeds** (what's compromising us):

| Source | Data | License |
|--------|------|---------|
| [ThreatFox](https://threatfox.abuse.ch) | Domains, IPs, hashes with malware tags | CC0 |
| [Feodo Tracker](https://feodotracker.abuse.ch) | C2 server IPs (Emotet, QakBot) | CC0 |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware SHA-256 hashes | CC0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited CVEs | Public Domain |

**Vendor Intelligence** (what actually works):

| Source | Data | Method |
|--------|------|--------|
| [MITRE ATT&CK Evals](https://attackevals.mitre-engenuity.org) | EDR detection rates (8 vendors) | Hardcoded public results |
| CISA KEV × Vendors | Which security tools have exploited CVEs | Cross-reference 40+ vendor keywords |
| [Reddit](https://reddit.com/r/netsec) | Practitioner discussions (30 vendors) | Public JSON API + optional LLM |
| [Hacker News](https://news.ycombinator.com) | Security tool discussions (27 vendors) | Algolia API + optional LLM |
| [AV-TEST](https://www.av-test.org) | Independent lab scores (8 vendors) | Hardcoded public results |
| [SE Labs](https://selabs.uk) | UK lab endpoint protection (10 vendors) | Hardcoded public results |
| Vendor Metadata | Pricing, certs, insurance, deploy time (36 vendors) | Curated |

```bash
oombra scrape                    # scrape all 11 sources
oombra scrape --feed mitre       # just MITRE evals
oombra scrape --dry-run          # preview without uploading
```

`oombra up` scrapes everything automatically on startup.

---

## Deploy for your industry

oombra is a stack. Deploy it for hospitals. Deploy it for banks. Build a company on it.

```bash
oombra up --vertical healthcare     # LockBit, HIPAA, hospital action templates
oombra up --vertical financial      # APT28/Lazarus, PCI DSS, SWIFT isolation
oombra up --vertical energy         # Sandworm, NERC CIP, ICS/OT isolation
oombra up --vertical government     # APT29, FISMA, supply chain focus
```

Or Docker for production:

```bash
cp .env.example .env
docker compose --profile production up -d
```

| Variable | Default | What it does |
|----------|---------|-------------|
| `OOMBRA_API_KEY` | *(none)* | API key for write endpoints |
| `OOMBRA_MIN_K` | `3` | Min contributors before showing aggregates |
| `OOMBRA_AUTO_INGEST` | `0` | Set `1` for hourly feed scraping |
| `OOMBRA_PORT` | `8000` | Port to expose |

Your users just need:
```bash
pip install oombra
oombra init
oombra report their_incident.json
```

---

## Integrate anywhere

**Python:**
```python
from oombra import load_file, anonymize, submit

data  = load_file("incident_iocs.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="http://oombra:8000") for c in clean]
```

**CLI + JSON (for AI agents, SOAR, scripts):**
```bash
oombra report incident.json --json | jq '.intelligence.actions'
oombra market edr --json | jq '.tiers.leaders'
oombra search vendor crowdstrike --json
```

**API:**

| Endpoint | What it does |
|----------|-------------|
| `POST /analyze` | Give data, get intelligence report |
| `GET /intelligence/market/{cat}` | Market map |
| `POST /intelligence/threat-map` | MITRE coverage gaps |
| `GET /intelligence/danger-radar` | Hidden vendor risks |
| `GET /search/vendor/{name}` | Vendor scores |
| `GET /search/category/{name}` | Category ranking |
| `POST /contribute/*` | Submit IOCs, attack maps, evals |
| `GET /query/techniques` | Top MITRE techniques |

---

## How privacy works

Everything is anonymized **on your machine** before anything touches the network.

| What you share | What leaves your machine |
|---------------|------------------------|
| Raw IOCs | HMAC-SHA256 fingerprints — can't be reversed |
| Attack notes | Scrubbed text — no org details |
| Org context | Bucketed: `healthcare`, `1000-5000` |
| Tool scores | DP-noised values |

Server returns aggregates only. Never individual contributions. Min-k enforcement. Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Tests

```bash
pytest    # 281 tests
```

---

## License

- **Code**: [Apache 2.0](LICENSE)
- **Data**: [LGPL 3.0](DATA_LICENSE.md) — open data
- **Feeds**: CC0 (abuse.ch), Public Domain (CISA), Apache 2.0 (MITRE ATT&CK)
