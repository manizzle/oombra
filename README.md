<p align="center">
  <h1 align="center">oombra</h1>
  <p align="center">
    <strong>Privacy-preserving federated threat intelligence sharing</strong>
  </p>
  <p align="center">
    Anonymize locally. Share selectively. Contribute to the collective.
  </p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> &bull;
    <a href="#how-it-works">How It Works</a> &bull;
    <a href="#demo">Demo</a> &bull;
    <a href="#cli-reference">CLI Reference</a> &bull;
    <a href="#server">Server</a> &bull;
    <a href="#api">Python API</a> &bull;
    <a href="#architecture">Architecture</a>
  </p>
</p>

---

Threat actors collaborate better than defenders. **oombra** fixes that by making sharing mathematically safe.

Organizations don't share threat intel because they're afraid of leaking sensitive data. oombra provides **cryptographic guarantees** — not promises — that nothing identifying ever leaves your machine.

```
[Your Data] → Extract → Anonymize → DP Noise → Review → Attest → Submit
               local      local       local     local    local    you decide
```

**Nothing is sent until you explicitly approve it.**

[![Tests](https://img.shields.io/badge/tests-126%20passing-brightgreen)](#tests)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

---

## What oombra Does

| Layer | What | How |
|-------|------|-----|
| **PII Stripping** | Emails, phones, URLs, names | Regex replacement → `[EMAIL]`, `[PHONE]`, etc. |
| **Security Scrubbing** | IPs, MACs, hostnames, API keys | Pattern matching → `[IP_ADDR]`, `[INTERNAL_HOST]`, etc. |
| **Context Bucketing** | Org name, size, role | "JP Morgan" → `financial`, "5000 employees" → `1000-5000` |
| **IOC Hashing** | Raw indicators | HMAC-SHA256 with org-local secret (rainbow-table resistant) |
| **Differential Privacy** | Numeric scores | Calibrated Laplace noise with privacy budget tracking |
| **Attestation (ADTC)** | Transformation proof | HMAC-linked chain proving each step was applied correctly |
| **PSI** | IOC comparison | "Do we see the same threats?" without revealing your list |
| **Secure Aggregation** | Score benchmarking | Multiple orgs compute averages without revealing individual scores |

---

## Quickstart

### Install

```bash
pip install -e "."

# With server support
pip install -e ".[server]"

# With everything
pip install -e ".[all,dev]"
```

### Generate demo data

```bash
python oombra/tests/demo_data.py demo/
```

This creates 13 files in `demo/` — vendor evaluations, attack maps, IOC bundles, STIX 2.1 bundles, CSV, and plain text.

### Preview what would be sent

```bash
oombra preview demo/eval_crowdstrike.json
```

```
  Type       : Tool Evaluation
  Vendor     : CrowdStrike
  Category   : edr
  Score      : 9.2 / 10
  Detection  : 98.5%
  FP Rate    : 0.8%
  Deploy Days: 3
  Would Buy  : yes
  Strength   : Exceptional real-time detection with minimal endpoint impact
  Friction   : Pricing can be prohibitive for smaller orgs

  Raw values stripped. PII removed. Context bucketed.
```

### Preview with differential privacy noise

```bash
oombra preview demo/eval_crowdstrike.json --epsilon 1.0
```

Scores get Laplace noise added. Higher epsilon = less noise = less privacy. Lower epsilon = more noise = more privacy.

---

## How It Works

### Three contribution types

**EvalRecord** — Practitioner tool evaluations
```json
{
  "vendor": "CrowdStrike",
  "category": "edr",
  "overall_score": 9.2,
  "detection_rate": 98.5,
  "top_strength": "Exceptional real-time detection"
}
```

**AttackMap** — MITRE ATT&CK kill chain observations
```json
{
  "threat_name": "APT28 - Credential Harvesting",
  "techniques": [
    {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",
     "detected_by": ["crowdstrike"], "missed_by": ["splunk"]}
  ]
}
```

**IOCBundle** — Indicators of compromise (hashed before sending)
```json
{
  "iocs": [
    {"ioc_type": "domain", "value_raw": "evil-c2.com",
     "detected_by": ["crowdstrike"], "threat_actor": "APT28"}
  ]
}
```

### Supported input formats

| Format | Extension | What it handles |
|--------|-----------|-----------------|
| JSON | `.json` | Eval records, attack maps, IOC bundles |
| STIX 2.1 | `.json` | Threat actors, attack patterns, indicators |
| MISP | `.json` | Event exports with attributes |
| CSV | `.csv` | Tabular vendor evaluations |
| Plain text | `.txt`, `.md` | Regex field extraction |
| PDF | `.pdf` | Text extraction (requires `pip install oombra[pdf]`) |

### Anonymization pipeline (4 passes)

```
Pass 1: PII         "Contact john@corp.com"    → "Contact [EMAIL]"
Pass 2: Security     "Server 192.168.1.1"      → "Server [IP_ADDR]"
Pass 3: Bucketing    "JP Morgan, 5000 people"   → industry=financial, org_size=1000-5000
Pass 4: IOC Hashing  "evil.com" (raw)           → "a3f2..." (HMAC-SHA256)
```

---

## Demo

### Step 1: Generate demo data

```bash
python oombra/tests/demo_data.py demo/
```

### Step 2: Preview different contribution types

```bash
# Vendor evaluation
oombra preview demo/eval_crowdstrike.json

# Attack map (MITRE ATT&CK)
oombra preview demo/attack_map_apt28.json

# IOC bundle
oombra preview demo/ioc_bundle_1.json

# STIX 2.1 bundle
oombra preview demo/apt28_campaign.stix.json

# CSV bulk import
oombra preview demo/evaluations.csv

# Plain text report
oombra preview demo/eval_report.txt
```

### Step 3: Preview with differential privacy

```bash
# epsilon=1.0 (moderate privacy)
oombra preview demo/eval_crowdstrike.json --epsilon 1.0

# epsilon=10.0 (less noise, less privacy)
oombra preview demo/eval_crowdstrike.json --epsilon 10.0
```

### Step 4: Generate attestation chain

```bash
# Basic attestation (extract + anonymize stages)
oombra attest demo/eval_crowdstrike.json

# With DP stage (extract + anonymize + dp stages)
oombra attest demo/eval_crowdstrike.json --epsilon 1.0

# Full JSON output (machine-readable)
oombra attest demo/eval_crowdstrike.json --json-out
```

Output:
```
  ADTC Attestation Chain
  ==================================================
  Chain ID:  17003b87-691c-42...
  Org Key:   bf4abc3ce37ccb0e...
  Root CDI:  1fedef437d901fc6...
  Stages:    2
  Version:   adtc-v1

  Stage 1: extract
    CDI:     86fed0f2f91707ae...
    Input:   d015e99e17cc07ea...
    Output:  1ba049c1dd12399f...
    Extracted: 1 contributions

  Stage 2: anonymize
    CDI:     95c149e3aa83e9ca...
    Input:   1ba049c1dd12399f...
    Output:  1ba049c1dd12399f...
    VAP:     CLEAN
    Scrubbed: 0 items

  Self-verification: VALID
  VAP: No PII patterns detected in output
```

### Step 5: Start the server and upload

**Terminal 1 — Start the server:**

```bash
oombra serve --port 8000
```

**Terminal 2 — Upload data:**

```bash
# Upload with interactive review
oombra upload demo/eval_crowdstrike.json --api-url http://localhost:8000

# Upload without review (non-interactive)
oombra upload demo/eval_crowdstrike.json --api-url http://localhost:8000 --yes

# Upload all evaluations
oombra upload demo/all_evaluations.json --api-url http://localhost:8000 --yes

# Upload attack map
oombra upload demo/attack_map_apt28.json --api-url http://localhost:8000 --yes

# Upload IOC bundle
oombra upload demo/ioc_bundle_1.json --api-url http://localhost:8000 --yes

# Upload with DP noise
oombra upload demo/eval_crowdstrike.json --api-url http://localhost:8000 --yes --epsilon 5.0
```

### Step 6: Query aggregated data

```bash
# Server stats
curl http://localhost:8000/stats

# Vendor aggregate (average scores across all anonymous contributors)
curl http://localhost:8000/query/vendor/CrowdStrike

# Category comparison
curl http://localhost:8000/query/category/edr

# Top MITRE ATT&CK techniques across all contributions
curl http://localhost:8000/query/techniques

# IOC type distribution (no raw values — ever)
curl http://localhost:8000/query/ioc-stats

# Health check
curl http://localhost:8000/health

# OpenAPI docs
open http://localhost:8000/docs
```

Example response — `/query/category/edr`:
```json
{
  "category": "edr",
  "vendors": [
    {
      "vendor": "CrowdStrike",
      "avg_score": 9.2,
      "avg_detection_rate": 98.5,
      "contribution_count": 1,
      "would_buy_pct": 100.0
    },
    {
      "vendor": "SentinelOne",
      "avg_score": 8.8,
      "avg_detection_rate": 97.2,
      "contribution_count": 1,
      "would_buy_pct": 100.0
    }
  ]
}
```

### Step 7: Check audit trail

```bash
# What was scrubbed and sent
oombra audit

# Contribution receipts (non-repudiation)
oombra receipts

# Privacy budget (if you used --epsilon)
oombra budget
```

---

## CLI Reference

```
oombra preview <file> [--epsilon FLOAT]
    Preview what would be sent (nothing leaves your machine)

oombra upload <file> --api-url URL [--api-key KEY] [--epsilon FLOAT] [--yes]
    [--industry INDUSTRY] [--org-size SIZE] [--role ROLE]
    Extract, anonymize, review, and submit

oombra attest <file> [--epsilon FLOAT] [--json-out] [--verify-only]
    Generate or verify ADTC attestation chain

oombra serve [--port 8000] [--host 0.0.0.0] [--db URL]
    Start the oombra server

oombra audit [--last N]
    View local audit log

oombra receipts
    List contribution receipts

oombra budget
    Show differential privacy budget status

oombra psi query --peer URL <file>
    Run Private Set Intersection against a peer

oombra aggregate <file> --session ID --coordinator URL [--n-parties N]
    Submit via secure aggregation
```

---

## Server

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/contribute/submit` | Submit EvalRecord |
| `POST` | `/contribute/attack-map` | Submit AttackMap |
| `POST` | `/contribute/ioc-bundle` | Submit IOCBundle |
| `GET` | `/query/vendor/{name}` | Aggregated vendor scores |
| `GET` | `/query/category/{name}` | All vendors in category |
| `GET` | `/query/techniques` | Top MITRE techniques |
| `GET` | `/query/ioc-stats` | IOC type distribution |
| `GET` | `/stats` | Contribution counts |
| `GET` | `/health` | Liveness check |
| `POST` | `/secagg/enroll` | Enroll in secure aggregation session |
| `POST` | `/secagg/submit-shares` | Submit secret shares |
| `GET` | `/secagg/result/{id}` | Get aggregated result |
| `GET` | `/docs` | OpenAPI documentation |

The query API returns **aggregates only**. No individual contribution is ever returned.

### Docker

```bash
# Development (SQLite)
docker compose up

# Production (PostgreSQL)
docker compose --profile production up
```

### Database

SQLite by default (zero-config). PostgreSQL for production:

```bash
oombra serve --db postgresql+asyncpg://user:pass@host:5432/oombra
```

---

## Python API

```python
from oombra import load_file, anonymize, submit

# Load any supported format
contribs = load_file("vendor_eval.json")

# Anonymize (PII strip + security scrub + bucketing + IOC hashing)
clean = [anonymize(c) for c in contribs]

# With differential privacy
clean = [anonymize(c, epsilon=1.0) for c in contribs]

# Submit
results = [submit(c, api_url="http://localhost:8000") for c in clean]
```

### Full pipeline (extract → anonymize → review → submit)

```python
from oombra import pipeline

results = pipeline(
    "apt28_campaign.stix.json",
    api_url="http://localhost:8000",
    epsilon=5.0,         # optional DP noise
    auto_approve=True,   # skip terminal review
)
```

### Attestation

```python
from oombra.attest import attest_pipeline, verify_chain

# Generate attestation chain
results = attest_pipeline("data.json", epsilon=1.0)
for ac in results:
    chain = ac.attestation
    print(f"Chain ID: {chain.chain_id}")
    print(f"Stages: {chain.stage_count}")
    print(f"VAP clean: {verify_chain(chain, ac.payload).vap_clean}")
```

### HMAC IOC hashing

```python
from oombra import hmac_ioc

# Same IOC, same org key → same hash
h1 = hmac_ioc("evil.com")
h2 = hmac_ioc("evil.com")
assert h1 == h2

# Different org key → different hash (rainbow-table resistant)
h3 = hmac_ioc("evil.com", secret=b"different_org_key_here!!!!!!!!!")
assert h1 != h3
```

### Private Set Intersection

```python
from oombra.psi import psi_cardinality

# How many IOCs do we share? (neither side reveals their list)
shared = psi_cardinality(
    our_values=["evil.com", "bad.net", "malware.org"],
    their_values=["evil.com", "other.com", "malware.org"],
)
print(f"Shared IOCs: {shared}")  # → 2
```

### Secure Aggregation

```python
from oombra.secagg import split, aggregate

# Split a score into 3 shares (no single share reveals the value)
shares = split(9.2, n_parties=3)
# shares might be: [3.1, -5.7, 11.8] — random, sum to 9.2

# Multiple parties contribute, coordinator aggregates
all_shares = [
    split(9.2, 3),  # Org A's CrowdStrike score
    split(8.5, 3),  # Org B's CrowdStrike score
    split(9.0, 3),  # Org C's CrowdStrike score
]
result = aggregate(all_shares)
# result[0] ≈ 26.7 (sum), divide by 3 → avg = 8.9
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    YOUR MACHINE (local)                   │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  [Raw File] ──→ [Extract] ──→ [Anonymize] ──→ [DP]      │
│   JSON/CSV/      format        4-pass:       optional    │
│   STIX/MISP      detect        PII/Sec/      Laplace    │
│                                Bucket/Hash    noise      │
│                                    │                      │
│                              [Terminal Review]            │
│                              user sees exactly            │
│                              what will be sent            │
│                                    │                      │
│                              [Attestation Chain]          │
│                              ADTC proof of                │
│                              correct processing           │
│                                    │                      │
│                         ┌──── Approve? ────┐             │
│                         │                  │              │
│                       [Yes]              [No]             │
│                         │                  │              │
│                     [Submit]          [Audit log]         │
│                     + receipt          (skip logged)      │
│                                                           │
├──────────────────────────────────────────────────────────┤
│                    SERVER (remote)                        │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  [Receive] ──→ [Store] ──→ [Aggregate] ──→ [Query API]  │
│  anonymized     SQLite/     avg scores,    /query/*      │
│  data only      Postgres    technique      aggregates    │
│                             counts         only          │
│                                                           │
│  [SecAgg Coordinator]                                    │
│  receives shares only — never sees individual values     │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### Local files

| Path | Purpose |
|------|---------|
| `~/.oombra/key` | Org-local HMAC secret (auto-generated, 256-bit) |
| `~/.oombra/audit.log` | Append-only audit trail |
| `~/.oombra/budget.json` | Differential privacy budget tracker |
| `~/.oombra/receipts/` | Non-repudiation contribution receipts |

### ADTC: Attested Data Transformation Chain

A novel cryptographic protocol inspired by [DICE (Device Identifier Composition Engine)](https://trustedcomputinggroup.org/work-groups/dice-architectures/) — but for **data transformations** instead of hardware boot chains.

Each processing stage generates a **Compound Device Identifier (CDI)**:

```
CDI₀ = HMAC(org_secret, "oombra-adtc-v1")           ← root
CDI₁ = HMAC(CDI₀, evidence_of_extraction)            ← extract stage
CDI₂ = HMAC(CDI₁, evidence_of_anonymization + VAP)   ← anonymize stage
CDI₃ = HMAC(CDI₂, evidence_of_dp_noise)              ← DP stage (optional)
```

**Verifiable Absence Proofs (VAP)**: The anonymization stage runs deterministic regex scans and proves zero PII patterns exist in the output. Both contributor and server can independently verify this.

**Properties**:
- Break any stage → chain verification fails
- Skip a stage → CDI derivation breaks
- Tamper with output → hash mismatch detected
- Both sides verify independently (bilateral verification)

---

## Privacy Layers

| Layer | Mechanism | What it proves |
|-------|-----------|----------------|
| **Anonymization** | Regex PII/security stripping | No emails, IPs, hostnames, API keys in output |
| **Bucketing** | k-anonymity generalization | Org identity hidden in bucket (e.g., "financial", "1000-5000") |
| **HMAC Hashing** | Keyed hash with org secret | IOCs can't be rainbow-tabled; different orgs → different hashes |
| **Differential Privacy** | Laplace/Gaussian noise | Mathematical bound on information leakage (epsilon-DP) |
| **Attestation (ADTC)** | HMAC-linked CDI chain | Cryptographic proof that all privacy steps were applied |
| **VAP** | Deterministic absence proof | Proof that NO PII pattern exists in final output |
| **PSI** | ECDH 2-round protocol | Compare IOC lists without revealing contents |
| **Secure Aggregation** | Additive/Shamir secret sharing | Compute averages without anyone seeing individual values |

---

## Tests

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all 126 tests
pytest

# Verbose output
pytest -v

# Specific test file
pytest oombra/tests/test_anonymize.py -v
```

Test coverage:

| File | Tests | What's tested |
|------|-------|---------------|
| `test_anonymize.py` | 38 | PII stripping, security scrubbing, HMAC, bucketing, full pipeline, hypothesis property tests |
| `test_attest.py` | 38 | CDI chains, attestation stages, VAP, commitments, verification, pipeline |
| `test_dp.py` | 14 | Laplace, Gaussian, randomized response, sensitivity calibration, budget |
| `test_extract.py` | 7 | JSON, CSV, STIX 2.1, text extraction |
| `test_models.py` | 15 | Pydantic validation, round-trips, bounds |
| `test_secagg.py` | 10 | Additive splitting, Shamir's scheme, multi-party aggregation |
| `test_fl.py` | 29 | ML models, aggregators, FL client, full FL round, protocol serialization |
| `test_graph.py` | 25 | Graph construction, embeddings, correlation, clustering, federated graph |
| `test_zkp.py` | ~20 | Pedersen commitments, range/membership/non-zero proofs, contribution proofs |

Property-based tests (via [Hypothesis](https://hypothesis.readthedocs.io/)):
- "No generated email survives `scrub()`"
- "No generated IPv4 survives `scrub()`"

---

## Project Structure

```
oombra/
├── __init__.py              # Public API
├── anonymize.py             # 4-pass anonymization engine
├── audit.py                 # Append-only audit log
├── cli.py                   # Click CLI
├── client.py                # HTTP client + receipts
├── dp.py                    # Differential privacy mechanisms
├── extract.py               # Format detection + parsing
├── keystore.py              # Org-local HMAC key management
├── models.py                # Pydantic data models
├── protocol.py              # PSI/SecAgg wire protocol
├── psi.py                   # Private Set Intersection (ECDH)
├── review.py                # Terminal review UI
├── secagg.py                # Secure aggregation (Shamir + additive)
├── attest/
│   ├── __init__.py          # ADTC protocol docs
│   ├── chain.py             # CDI + attestation chain
│   ├── commitments.py       # Hash-based commitments
│   ├── pipeline.py          # Attested pipeline orchestration
│   ├── stages.py            # Per-stage attestation + VAP
│   └── verify.py            # Chain verification
├── fl/
│   ├── __init__.py          # Federated learning package
│   ├── models.py            # Numpy-only ML models (MalwareClassifier, AnomalyDetector, IOCScorer)
│   ├── aggregator.py        # FedAvg, trimmed mean, Krum, geometric median, poisoning detection
│   ├── client.py            # FL client (local training + DP-noised updates)
│   ├── protocol.py          # FL session/update/result protocol models
│   └── server.py            # FL coordinator FastAPI routes
├── graph/
│   ├── __init__.py          # Graph intelligence package
│   ├── schema.py            # Threat graph schema (nodes, edges, types)
│   ├── local.py             # Build graphs from contributions (AttackMap, IOCBundle)
│   ├── embeddings.py        # Node2Vec + graph autoencoder (numpy-only)
│   ├── correlate.py         # Campaign correlation, clustering, shared campaign detection
│   └── federated.py         # Federated graph learning client
├── zkp/
│   ├── __init__.py          # Zero-knowledge proof package
│   ├── proofs.py            # Core ZKP (Schnorr, range, membership, consistency, non-zero)
│   ├── contrib_proofs.py    # Contribution-specific proof bundles
│   └── verify.py            # Server-side ZKP verification
├── server/
│   ├── app.py               # FastAPI application
│   ├── db.py                # Async SQLAlchemy (SQLite/PostgreSQL)
│   ├── models.py            # Database models
│   └── routes/
│       ├── query.py         # Aggregated query API
│       └── secagg.py        # Secure aggregation coordinator
└── tests/
    ├── demo_data.py         # Demo data generator
    ├── test_anonymize.py    # Anonymization tests
    ├── test_attest.py       # Attestation tests
    ├── test_dp.py           # Differential privacy tests
    ├── test_extract.py      # Extraction tests
    ├── test_models.py       # Model tests
    └── test_secagg.py       # Secure aggregation tests
```

---

## Optional Dependencies

```bash
pip install oombra[server]      # FastAPI server (SQLite)
pip install oombra[server-pg]   # PostgreSQL support
pip install oombra[crypto]      # PSI (ECDH elliptic curve)
pip install oombra[pdf]         # PDF extraction
pip install oombra[dev]         # pytest + hypothesis + ruff
pip install oombra[all]         # Everything
```

Core oombra (anonymization, DP, attestation, secure aggregation) requires **zero crypto dependencies** — it's all stdlib (`hmac`, `hashlib`, `secrets`, `random`).

---

## Roadmap

- [x] **Phase 0** — Hardening: HMAC hashing, audit log, receipts, tests
- [x] **Phase 0.5** — Server: FastAPI, SQLite/PostgreSQL, query API, Docker
- [x] **Phase 1** — Differential Privacy: Laplace/Gaussian mechanisms, budget tracking
- [x] **Phase 2** — Private Set Intersection: ECDH-based IOC comparison
- [x] **Phase 3** — Secure Aggregation: Additive + Shamir secret sharing
- [x] **ADTC** — Attested Data Transformation Chain (novel protocol)
- [x] **Phase 4** — Federated Learning: Collaborative model training (numpy-only models, robust aggregation, poisoning detection)
- [x] **Phase 5** — Federated Graph Intelligence: Cross-org attack chain reconstruction (Node2Vec, graph autoencoder, campaign clustering)
- [x] **Phase 6** — Zero-Knowledge Proofs: Prove contributions are valid without revealing content (Schnorr proofs, range/membership/consistency proofs)

---

## License

Apache 2.0
