# Architecture — Detailed Three-Party Flow

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (your machine)
    participant S as Server (accountable compute)
    participant Q as Consumer (querier)

    rect rgb(235, 245, 235)
    Note over C,Q: CONTRIBUTION PHASE
    Note over C: 1. COLLECT — Load incident.json
    Note over C: 2. SCRUB — Remove PII, hash IOCs
    Note over C: 3. TRANSLATE — Drop free text, keep scores
    C->>S: POST /contribute/submit
    S->>S: 4. VALIDATE
    S->>S: 5. COMMIT (Pedersen hash)
    S->>S: 6. AGGREGATE (running sums)
    S->>S: 7. MERKLE TREE
    S->>S: 8. DISCARD individual values
    S-->>C: RECEIPT (commitment + proof + signature)
    Note over C: Store receipt — proves you contributed
    end

    rect rgb(235, 235, 245)
    Note over C,Q: QUERY + VERIFICATION PHASE
    Q->>S: GET /verify/aggregate/CrowdStrike
    S->>S: 9. PROVE (Merkle root + commitments)
    S-->>Q: Proof response
    Q->>Q: 10. VERIFY locally
    Note over Q: TRUST — aggregate is real
    end

    rect rgb(245, 240, 230)
    Note over C,Q: BLIND CATEGORY DISCOVERY
    C->>S: propose(H) — H = SHA-256(name:salt)
    Note over S: Server sees ONLY the hash
    S->>S: count(H) >= 3 orgs?
    S-->>C: Threshold met
    C->>S: reveal(H, plaintext, salt)
    S->>S: Verify → PUBLIC TAXONOMY
    end
```


## What Gets Stored vs Discarded

| Stored (server retains) | Discarded (gone after commit) |
|------------------------|------------------------------|
| Commitment hashes (SHA-256) | Individual scores |
| Running sums per vendor | Per-org attribution |
| Technique frequency counters | Free-text notes |
| Merkle tree of all commitments | Sigma rules, action strings |
| Blind category hashes (opaque) | Raw IOC values |
| Revealed category names | Who proposed what (until reveal) |
| Eval dimension aggregates (price, support, detection) | Raw dollar amounts, individual SLA times |

## Regulatory Compliance

See [COMPLIANCE.md](COMPLIANCE.md) for the full legal analysis covering CIRCIA, NERC CIP, SEC 8-K, state breach laws, and CISA 2015 safe harbor protections.
