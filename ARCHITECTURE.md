# Architecture — Detailed Three-Party Flow

What each side does, step by step:

```
CLIENT (your machine)                 SERVER (accountable compute)          CONSUMER (querier)
═════════════════════                 ════════════════════════════          ══════════════════

 ┌─ COLLECT ──────────┐
 │ Load incident.json  │
 └────────┬───────────┘
          ▼
 ┌─ SCRUB ────────────┐
 │ Remove PII locally  │
 │ Hash IOC values     │
 │ (HMAC-SHA256)       │
 └────────┬───────────┘
          ▼
 ┌─ TRANSLATE ────────┐
 │ translate_eval()    │
 │ translate_attack_   │
 │   map()             │
 │                     │
 │ DROPPED:            │
 │  notes, sigma_rule, │
 │  action strings     │
 │                     │
 │ KEPT:               │
 │  overall_score: 9.2 │
 │  top_strength:      │
 │   "detection_quality"│
 │  would_buy: true    │
 └────────┬───────────┘
          ▼
 ┌─ SUBMIT ───────────┐         ┌─ VALIDATE ──────────┐
 │ POST /contribute/   │────────▶│ Check API key        │
 │   submit            │         │ Check rate limit     │
 │ POST /contribute/   │         │ Check payload limits │
 │   attack-map        │         └────────┬────────────┘
 │ POST /contribute/   │                  ▼
 │   ioc-bundle        │         ┌─ COMMIT ────────────┐
 │ POST /ingest/       │         │ SHA-256(data + ts)   │
 │   webhook           │         │ → commitment_hash    │
 │ POST /analyze       │         └────────┬────────────┘
 └─────────────────────┘                  ▼
                                 ┌─ AGGREGATE ─────────┐
                                 │ running_sum += value │
                                 │ count += 1           │
                                 │ tech_freq[T1566] += 1│
                                 └────────┬────────────┘
                                          ▼
                                 ┌─ MERKLE TREE ───────┐
                                 │ commitment → leaf    │
                                 │ rebuild tree → root  │
                                 └────────┬────────────┘
                                          ▼
                                 ┌─ DISCARD ───────────┐
                                 │ individual values    │
                                 │ = GONE               │
                                 │ only commitment hash │
                                 │ retained             │
                                 └────────┬────────────┘
                                          ▼
 ┌─ RECEIPT ──────────┐◀─────── ┌─ RETURN RECEIPT ─────┐
 │ commitment_hash     │         │ commitment + proof    │
 │ merkle_proof        │         │ + server signature    │
 │ server_signature    │         └──────────────────────┘
 │ aggregate_id        │
 │                     │
 │ Store locally —     │
 │ proves you          │
 │ contributed         │                                  ┌─ QUERY ────────────┐
 └─────────────────────┘                                  │ GET /verify/       │
                                                          │   aggregate/CS     │
                                                          └────────┬──────────┘
                                                                   ▼
                                 ┌─ PROVE AGGREGATE ───┐  ┌─ RECEIVE ─────────┐
                                 │ Merkle root          │──▶│ proof.count       │
                                 │ commitment_hashes[]  │  │ proof.merkle_root │
                                 │ aggregate_values     │  │ proof.values      │
                                 │ server_signature     │  └────────┬──────────┘
                                 └─────────────────────┘           ▼
                                                          ┌─ VERIFY LOCALLY ──┐
                                                          │ commitments==count?│
                                                          │ Merkle root valid? │
                                                          │ signature present? │
                                                          └────────┬──────────┘
                                                                   ▼
                                                            TRUST: aggregate
                                                            is real. Math,
                                                            not promises.
```
