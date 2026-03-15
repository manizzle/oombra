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

[![Tests](https://img.shields.io/badge/tests-281%20passing-brightgreen)](#-tests)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Code](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE)
[![Data](https://img.shields.io/badge/data-LGPL--3.0-orange)](DATA_LICENSE.md)

---

## Get started

```bash
git clone https://github.com/manizzle/oombra.git
cd oombra
pip install -e ".[all,dev]"
oombra up --vertical healthcare
```

That starts the platform, scrapes live threat feeds, and you're ready. In another terminal:

```bash
oombra report your_incident_data.json
```

You give your data. You get back what everyone else knows. No contribution, no report.

---

## What you get

### When you're under attack

You got breached. You have IOCs and MITRE observations. You need answers now.

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

You contributed your IOCs. In return, you learned it's a campaign, what you're missing, and what to do. Seconds, not days.

### When you're building defenses

No incident. You're planning, budgeting, justifying purchases to the board.

```bash
oombra market edr                                    # who leads in EDR?
oombra search vendor crowdstrike                     # real scores, not Gartner
oombra search compare crowdstrike sentinelone        # objective side-by-side
oombra threat-map "ransomware" --tools crowdstrike   # where are your gaps?
```

Real practitioner data from real incidents across your industry. Not vendor marketing. Not analyst reports funded by vendors. Actual collective intelligence from people doing the same job as you.

---

## Why people contribute

Because they're selfish. You can't get a report without contributing. Your data makes the next person's report better. Their data made yours possible.

A hospital in Ohio contributes their LockBit IOCs at 2AM. At 4:30AM, a hospital in West Virginia gets the same ransom note. Their report is *better* — because Ohio shared. Ohio's CISO gets real tool benchmarks for the board next week — because West Virginia shared their CrowdStrike eval last month.

Everyone gets back more than they give. That's the loop.

---

## Deploy it for your industry

oombra is a stack anyone can deploy. Run it for hospitals. Run it for banks. Run it for energy companies. Your users contribute anonymized data, you run the platform, everyone gets smarter.

```bash
# Pick your vertical
oombra up --vertical healthcare     # hospitals, clinics, pharma
oombra up --vertical financial      # banks, insurance, fintech
oombra up --vertical energy         # power grids, oil & gas, ICS/OT
oombra up --vertical government     # federal, state, local

# Or Docker for production
cp .env.example .env
docker compose --profile production up -d
```

Each vertical comes pre-loaded with relevant threat actors, MITRE techniques, compliance frameworks, and action templates. Healthcare gets LockBit + HIPAA. Financial gets APT28 + PCI DSS. Energy gets Sandworm + NERC CIP.

Your users just need:
```bash
pip install oombra
oombra init
oombra report their_incident.json
```

---

## How privacy works

Everything is anonymized **on your machine** before anything touches the network. You review what leaves. You approve what's sent.

| What you share | What leaves your machine |
|---------------|------------------------|
| Raw IOCs (IPs, domains, hashes) | HMAC-SHA256 fingerprints — can't be reversed |
| Attack observations with notes | Technique IDs + scrubbed text — no org details |
| Org context (name, size, industry) | Bucketed: `healthcare`, `1000-5000` — never your name |
| Tool scores | DP-noised values — can't pinpoint your exact score |

The server only sees anonymized data. Queries return aggregates — never individual contributions. Min-k enforcement means no data is returned with fewer than 3 contributors. Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Integrate anywhere

**Python (3 lines):**
```python
from oombra import load_file, anonymize, submit

data  = load_file("incident_iocs.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="http://oombra:8000") for c in clean]
```

**CLI with JSON (for AI agents / SOAR / automation):**
```bash
oombra report incident.json --json | jq '.intelligence.actions'
oombra market edr --json | jq '.tiers.leaders'
```

**API endpoints:**

| Endpoint | What it does |
|----------|-------------|
| `POST /analyze` | Give data, get intelligence report |
| `GET /intelligence/market/{category}` | Market map — leaders, contenders, emerging |
| `POST /intelligence/threat-map` | Map a threat to MITRE, find coverage gaps |
| `GET /intelligence/danger-radar` | Vendors with hidden risks |
| `GET /search/vendor/{name}` | Vendor lookup with weighted scores |
| `GET /search/category/{name}` | Category ranking |
| `GET /search/compare?a=X&b=Y` | Side-by-side comparison |
| `POST /contribute/*` | Submit IOCs, attack maps, tool evals |
| `GET /query/techniques` | Top MITRE techniques across contributors |

---

## Live threat feeds

The platform auto-ingests real IOCs from public feeds so your reports match against the full threat landscape — not just other users' contributions.

| Feed | Source | What it provides |
|------|--------|-----------------|
| ThreatFox | abuse.ch (CC0) | Domains, IPs, hashes with malware family tags |
| Feodo Tracker | abuse.ch (CC0) | C2 server IPs — Emotet, QakBot |
| MalwareBazaar | abuse.ch (CC0) | Malware SHA-256 hashes |
| CISA KEV | cisa.gov (public domain) | Ransomware-exploited CVEs |

`oombra up` scrapes all feeds on startup. `oombra scrape` to refresh manually.

---

## Tests

```bash
pytest    # 281 tests
```

---

## License

- **Code**: [Apache 2.0](LICENSE)
- **Data**: [LGPL 3.0](DATA_LICENSE.md) — open data, free to use
- **Feeds**: CC0 (abuse.ch), Public Domain (CISA), Apache 2.0 (MITRE ATT&CK)
