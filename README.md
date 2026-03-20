<h1 align="center">nur</h1>

<p align="center"><strong>Collective security intelligence for industries. Give data, get smarter.</strong></p>

<p align="center">Your industry should be smarter together than any single company is alone.</p>

<p align="center">
  <img src="demo/nur-demo.gif?v=3" alt="nur demo — trustless pipeline" width="750" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/sources-37_live-ff6b6b" />
  <img src="https://img.shields.io/badge/vendors-36_tracked-ffa502" />
  <img src="https://img.shields.io/badge/tests-575_passing-2ed573" />
  <img src="https://img.shields.io/badge/python-3.11%2B-1e90ff" />
  <img src="https://img.shields.io/badge/code-Apache_2.0-1e90ff" />
  <img src="https://img.shields.io/badge/data-CDLA_Permissive_2.0-f9ca24" />
</p>

---

Every hospital buys security tools based on vendor marketing. Every bank figures out their detection gaps by getting hacked. Every energy company fights the same APT without knowing three other utilities already beat it.

nur fixes this. Two modes, one platform:

- **Wartime** — you're under attack. Upload IOCs, get campaign matches, remediation actions, detection gaps.
- **Peacetime** — build defenses. Market maps, vendor comparisons, threat modeling, stack coverage analysis.

> **Try it live:** [nur.saramena.us](https://nur.saramena.us) — [dashboard](https://nur.saramena.us/dashboard) · [docs](https://nur.saramena.us/guide) · [register](https://nur.saramena.us/register)

---

## Architecture

The server is an **accountable compute node** — it commits to every value, proves every aggregate, and discards individual data. Not blind, but on a cryptographic leash.

<p align="center">
  <img src="demo/architecture.png?v=4" alt="nur trustless architecture — contributor, server, consumer flow with blind category discovery" width="750" />
</p>

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed three-party flow diagram.

**Every response comes from aggregates only:**

| Source | Examples | Can identify an org? |
|--------|---------|---------------------|
| **ProofEngine histograms** | "containment stops attacks 87% of the time" | No — running sums |
| **ProofEngine coverage** | "T1490 observed 47x, 5 tools detect it" | No — aggregate counts |
| **Template logic** | "Block network IOCs at firewall" | No — generated from patterns |
| **Public taxonomy** | "NIST: containment → Network Isolation (D3-NI)" | No — public knowledge |
| ~~Individual contributions~~ | ~~"Org X used this sigma rule"~~ | ~~Yes~~ — **removed** |

---

## Get started

```bash
pip install nur
nur init
nur register you@yourorg.com     # work email required, keypair generated
nur report incident.json          # give data, get intelligence
```

Or self-host:
```bash
git clone https://github.com/manizzle/nur.git && cd nur
nur up --vertical healthcare
```

---

## Wartime — incident response

```bash
nur report incident_iocs.json
```
```
  Campaign Match: Yes
  Shared IOCs: 32
  IOC Types: domain=12, ip=15, hash-sha256=5

  Actions:
    [CRITICAL] Block matching network indicators at firewall and DNS
    [HIGH]     Hunt for matching file hashes in your environment
    [HIGH]     Hunt for related activity (cross-reference 32 matched IOCs)
```

```bash
nur report attack_map.json
```
```
  Coverage Score: 71%
  Detection Gaps: 3
    - T1490: 47x observed, 5 tools detect it
    - T1078: 23x observed, 3 tools detect it
    - T1021.001: 12x observed, 4 tools detect it
  Best Remediation: containment (87% success rate)

  Actions:
    [CRITICAL] Prioritize containment — 87% success rate across the collective
    [CRITICAL] Deploy T1490 detection
    [HIGH]     Deploy T1078 detection
```

> All intelligence comes from aggregate histograms. The remediation hints tell you *what category* of response works and at what success rate, not what any specific org did.

---

## Peacetime — build defenses

```bash
nur eval                                             # interactive walkthrough
nur market edr                                       # vendor rankings
nur search compare crowdstrike sentinelone           # side-by-side
nur threat-map "ransomware" --tools crowdstrike      # coverage gaps
nur threat-model --stack crowdstrike,splunk,okta --vertical healthcare
nur simulate --stack crowdstrike,splunk,okta --vertical healthcare
```

**Threat modeling** — generate MITRE-mapped threat models, compatible with [threatcl](https://github.com/threatcl/threatcl):

```
  Coverage: 75% (6/8 priority techniques)
  Gaps: T1566 Spearphishing → add email security
        T1048 Exfiltration → add NDR or DLP
  Compliance: HIPAA ✓ · NIST CSF ✓ · HITECH ✗
```

---

## The hospital scenario

**2:17 AM** — Ohio Children's Hospital. LockBit. EHR encrypted. NICU monitors offline.

```bash
nur report lockbit_iocs.json              # 32 shared IOCs. LockBit confirmed.
nur report lockbit_attack_map.json        # 7 detection gaps. T1490 critical.
nur threat-model --stack crowdstrike,splunk --vertical healthcare  # 75% coverage, 2 gaps
```

**4:30 AM** — West Virginia gets the same ransom note. Their report is *better* — because Ohio contributed.

---

## Trustless Architecture — deep dive

In the age of AI data mining, your data **cannot be mined, sold, or misused** — not because we promise, but because the math makes it impossible.

**Proof verification chain:**

```
Submit ──▶ Translate ──▶ Commit ──▶ Merkle ──▶ Receipt
               │             │          │          │
          drop text     running sum   proof    signature
               │             │          │
          category       aggregate     │
               │             │         │
               └── DISCARD ──┘         │
                                       ▼
                        /verify/receipt ──▶ consumer verifies
                        /verify/aggregate ──▶ proof + checks
                        /proof/stats ──▶ platform totals
```

**Verify anything:**

```bash
# Every submission returns a receipt
curl -X POST /contribute/submit -d '{"data": {"vendor": "CrowdStrike", ...}}'
# → {"status": "accepted", "receipt": {"commitment_hash": "a3c7...", "merkle_proof": [...], ...}}

# Verify any receipt
curl -X POST /verify/receipt -d '{"commitment_hash": "a3c7...", ...}'
# → {"valid": true}

# Verify any aggregate
curl /verify/aggregate/CrowdStrike
# → {"proof": {...}, "verification": {"valid": true, "checks": {...}}}

# Platform proof stats
curl /proof/stats
# → {"total_contributions": 547, "merkle_root": "38978f...", "unique_vendors": 12, ...}
```

**Blind category discovery:**

```
Org-A: H("DarkAngel":salt) ──┐
Org-B: H("DarkAngel":salt) ──┼──▶ Server: count(H) >= 3? ──▶ REVEAL VOTE
Org-C: H("DarkAngel":salt) ──┘         │                         │
                                   threshold met            quorum met?
                                        │                         │
                                server sees:                      ▼
                                hash ONLY                  PUBLIC TAXONOMY
                                                           aggregation begins
```

```bash
# Contributor hashes category locally (server never sees plaintext)
curl -X POST /category/propose -d '{"category_hash": "H", "category_type": "threat_actor", ...}'
# → {"status": "pending", "supporter_count": 1, "threshold": 3}

# When 3+ orgs submit the same hash → threshold met → vote to reveal
curl -X POST /category/reveal -d '{"category_hash": "H", "plaintext": "DarkAngel", "salt": "...", ...}'
# → {"status": "revealed", "revealed_name": "darkangel"}
```

<details>
<summary>Crypto primitives (click to expand)</summary>

| Primitive | What it does | What breaks without it |
|-----------|-------------|----------------------|
| **Pedersen Commitments** | Seals each value — server can't change it after receipt | Server could alter scores to favor vendors |
| **Merkle Tree** | Binds all commitments — server can't add/remove contributions | Server could inflate N or exclude low scores |
| **ZKP Range Proofs** | Proves score is in [0, 10] without revealing it | Poisoner submits score=99999, corrupts aggregate |
| **Contribution Receipts** | Proves your data was included correctly | Server could silently drop your contribution |
| **Aggregate Proofs** | Proves computation is correct against commitment chain | Server could fabricate rankings |
| **Secure Histograms** | Technique frequency from binary vector sums | Server would need plaintext technique lists |
| **BDP Credibility** | Behavior-based lie detection for data poisoning | Competitor creates 100 fake accounts, rates rivals 0/10 |
| **Blind Category Discovery** | Threshold reveal — server can't learn category names until quorum | Server could see what threats orgs are investigating |

</details>

<details>
<summary>Security hardening (click to expand)</summary>

- **Work email required** — gmail/yahoo/disposable blocked
- **Keypair auth** — private key never leaves your machine
- **Signed requests** — replay prevention (5-min window)
- **Rate limiting** — 60 req/min (community), 600 (pro), 6000 (enterprise)
- **Min-k enforcement** — no aggregates with < 3 contributors
- **Payload limits** — 10K IOCs, 500 techniques max
- **AWS Secrets Manager** — zero secrets in code

</details>

Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## 37 data sources · 36 vendors · 658,000+ IOCs

**IOC Feeds (20):** ThreatFox, Feodo, MalwareBazaar, URLhaus, SSL Blacklist, CISA KEV, NVD, FireHOL, IPsum, OpenPhish, Emerging Threats, Dataplane, Spamhaus DROP, DigitalSide, CINS, BruteForceBlocker, AbuseIPDB, OTX, Pulsedive, GreyNoise

**Vendor Intelligence (15):** MITRE ATT&CK Evals, AV-TEST, SE Labs, AV-Comparatives, CISA KEV vendors, Reddit, Hacker News, Stack Exchange, G2, Gartner, PeerSpot, Capterra, TrustRadius, GitHub, Vendor Metadata

**Vendors (36):** CrowdStrike, SentinelOne, Microsoft Defender, Cortex XDR, Carbon Black, Sophos, Bitdefender, ESET, Trend Micro, Kaspersky, Splunk, Sentinel, QRadar, Elastic, Wiz, Prisma Cloud, Snyk, Okta, Entra ID, CyberArk, BeyondTrust, Vault, Proofpoint, Mimecast, Zscaler, Cloudflare, Cisco Duo, Tenable, Qualys, Rapid7, Cloudflare WAF, F5, Imperva, Darktrace, Vectra, Recorded Future

> **Run a threat intel feed?** [Get listed](https://github.com/manizzle/nur/issues/4). Premium feed access? [What we need](https://github.com/manizzle/nur/issues/5).

---

## Pricing

| | Community | Pro | Enterprise |
|---|---|---|---|
| **Price** | Free | $99/mo | $499/mo |
| Contribute data | ✓ | ✓ | ✓ |
| Your percentile position | ✓ | ✓ | ✓ |
| Cryptographic receipts | ✓ | ✓ | ✓ |
| Market maps + vendor rankings | | ✓ | ✓ |
| Threat maps + coverage analysis | | ✓ | ✓ |
| Attack simulation | | ✓ | ✓ |
| Vendor side-by-side comparison | | ✓ | ✓ |
| API access | | | ✓ |
| Vendor intelligence dashboard | | | ✓ |
| Compliance reports | | | ✓ |
| RFP generation | | | ✓ |
| Priority support | | | ✓ |

> **For vendors:** Enterprise tier includes the Vendor Intelligence Dashboard — see how practitioners rate your product, technique-level detection gaps, and category ranking with cryptographic proof of methodology.

---

## API

Full API reference: [nur.saramena.us/guide](https://nur.saramena.us/guide)

---

## Integrate anywhere

```bash
# SIEM / EDR
nur integrate splunk                   # forward alerts from Splunk
nur integrate sentinel                 # forward incidents from Microsoft Sentinel
nur integrate crowdstrike              # forward detections from CrowdStrike

# Syslog / Webhook
nur integrate syslog --port 1514       # listen for CEF/syslog events
# POST to /ingest/webhook              # universal webhook endpoint
```

**Python:**
```python
from nur import load_file, anonymize, submit
data  = load_file("incident.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="https://nur.saramena.us") for c in clean]
```

---

## Deploy

```bash
nur up --vertical healthcare     # LockBit, HIPAA
nur up --vertical financial      # APT28, PCI DSS
nur up --vertical energy         # Sandworm, NERC CIP
nur up --vertical government     # APT29, FISMA
```

---

## Tests

```bash
pytest                                    # 575 tests (89 trustless + 486 core)
python demo/trustless_demo.py             # full E2E trustless pipeline demo
```

**Trustless demo** shows all 11 steps: eval → attack map → IOC bundle → CrowdStrike webhook → Sentinel webhook → aggregate query → receipt verification → aggregate proof → trust summary → zero-individual-values proof → blind category discovery.

---

## License

| Component | License |
|-----------|---------|
| Code | [Apache 2.0](LICENSE) |
| Data | [CDLA-Permissive-2.0](DATA_LICENSE.md) |
| Feeds | CC0 (abuse.ch) · Public Domain (CISA) · Apache 2.0 (MITRE) |
