# nur Threat Model

## What We're Protecting

An organization contributes threat intelligence (vendor evaluations, attack maps, IOC lists) to a shared platform. The privacy goal: **learn collective insights without exposing any single organization's data**.

Sensitive data at risk:
- **Network topology** — internal IPs, hostnames, MAC addresses
- **Identity** — analyst names, emails, org name
- **Security posture** — which tools they use, what they miss, detection gaps
- **Operational details** — when incidents happened, how long response took
- **Raw IOCs** — specific indicators from their environment

---

## Threat Actors

| Actor | Goal | Capability |
|-------|------|-----------|
| **Curious Server** | Learn individual org's data from submissions | Sees all anonymized data, can correlate |
| **External Attacker** | Breach server, steal contribution database | Full DB access after compromise |
| **Malicious Contributor** | Poison aggregates with fake data | Submits crafted contributions |
| **Network Observer** | Intercept data in transit | Passive eavesdropping, traffic analysis |
| **Insider at Org** | Prove what another org contributed | Access to platform + some org knowledge |
| **Colluding Parties** | Combine knowledge to de-anonymize | Multiple orgs share what they know |

---

## Attack → Defense Mapping

### Attack 1: Raw PII in submitted data
**Threat**: Server sees "Contact john.doe@hospital.com about the 192.168.1.1 incident on server db01.corp.internal"

**Defense**: `anonymize.py` — 4-pass regex scrubbing
- Pass 1: emails → `[EMAIL]`, phones → `[PHONE]`, URLs → `[URL]`, names → `[NAME]`
- Pass 2: IPs → `[IP_ADDR]`, MACs → `[MAC_ADDR]`, hostnames → `[INTERNAL_HOST]`, API keys → `[API_KEY]`

**Residual risk**: Novel PII patterns not covered by regex. Custom identifiers (employee IDs, ticket numbers) may slip through.

**Mitigation**: ADTC VAP (Verifiable Absence Proof) runs the same patterns server-side. Both sides confirm zero matches. But this only catches *known* patterns.

---

### Attack 2: Organization identification from context
**Threat**: "A 5000-person financial company using CrowdStrike EDR with a CISO submitting" narrows to ~50 orgs.

**Defense**: `anonymize.py` — k-anonymity bucketing
- "JP Morgan" → `financial` (industry bucket)
- "5247 employees" → `1000-5000` (size bucket)
- "Chief Information Security Officer" → `ciso` (role bucket)
- Org name stripped entirely

**Residual risk**: Combination of industry + size + role + specific vendor scores could still fingerprint an org. If only one `financial` org with `5000-10000` employees evaluates `Wiz`, that's unique.

**Mitigation needed**: Require minimum k contributors per bucket before releasing aggregates. The server query API returns aggregates, but doesn't enforce minimum counts yet.

---

### Attack 3: IOC rainbow tables
**Threat**: SHA-256("evil.com") is deterministic. An attacker pre-computes hashes for all known domains/IPs and matches against submitted IOC hashes.

**Defense**: `keystore.py` — HMAC-SHA256 with org-local secret
- Each org has a unique 256-bit key at `~/.nur/key`
- `HMAC(org_key, "evil.com")` differs between orgs
- Attacker needs the org's key to build a rainbow table

**Residual risk**: If org key is compromised, all their IOC hashes are reversible. Also, IOC hashes from the same org are still correlatable (same key).

**Mitigation**: Key rotation, key derivation per-session, or PSI for IOC comparison instead of hash submission.

---

### Attack 4: Score inference from aggregates
**Threat**: If only 2 orgs contribute CrowdStrike scores, and one knows their own score (9.0), they can compute the other's score from the average.

**Defense**: `dp.py` — Differential Privacy (Laplace mechanism)
- `noised_score = real_score + Laplace(sensitivity/epsilon)`
- Mathematically bounds information leakage
- Privacy budget tracking prevents over-querying

**Residual risk**: Low epsilon = more noise = less utility. High epsilon = less noise = more leakage. The privacy-utility tradeoff is inherent. Also, DP noise on small contributor counts is extreme.

**What epsilon means**:
- epsilon=1.0: Strong privacy, significant noise (scores shift by ±10 points)
- epsilon=5.0: Moderate privacy, noticeable noise (scores shift by ±2 points)
- epsilon=10.0: Weak privacy, minimal noise (scores shift by ±1 point)

---

### Attack 5: IOC list exposure during comparison
**Threat**: Two orgs want to know if they share IOCs, but don't want to reveal their full lists.

**Defense**: `psi.py` — Private Set Intersection (ECDH 2-round protocol)
- Neither party reveals their IOC list
- They learn ONLY the count (or intersection) of shared IOCs
- Based on ECDH commutativity: `H(x)^(a*b) == H(x)^(b*a)`

**Residual risk**: The cardinality itself leaks information (knowing you share 50 out of 100 IOCs tells you something). Malicious party could submit a targeted set to test specific IOCs.

**Mitigation**: Cardinality-only mode (don't reveal which IOCs match). Rate limiting on PSI queries.

---

### Attack 6: Individual scores visible to coordinator
**Threat**: Aggregation coordinator sees each org's raw scores.

**Defense**: `secagg.py` — Additive secret sharing + Shamir's threshold
- Score split into n random shares summing to original
- Each share goes to a different party
- Coordinator only sees random-looking numbers
- Threshold scheme (k-of-n) handles party dropout

**Residual risk**: If coordinator colludes with n-1 parties, they can reconstruct the remaining party's value. Also, with only 2 parties, each learns the other's value from the aggregate.

**Mitigation**: Minimum 3 parties required. Compose with DP: add noise BEFORE splitting into shares.

---

### Attack 7: Skipped anonymization / tampered data
**Threat**: Contributor claims data was anonymized but actually sent raw PII. Or: contributor tampered with the output after anonymization.

**Defense**: `attest/` — ADTC (Attested Data Transformation Chain)
- HMAC-linked CDI chain: `CDI_n = HMAC(CDI_{n-1}, stage_evidence)`
- Break any step → chain verification fails
- Skip a step → CDI derivation breaks
- **VAP**: Deterministic regex scan proves zero PII patterns in output

**Residual risk**: The attestation proves the *process* ran, but can't prove the *input* was real data (could be fabricated). Also, a malicious client could modify the attestation code itself.

**Mitigation**: ZKP (Phase 6) proves data validity. Code signing / reproducible builds for client integrity.

---

### Attack 8: Data poisoning / fake contributions
**Threat**: Attacker submits fake evaluations to skew aggregates (e.g., giving a competitor a score of 0).

**Defense (partial)**:
- `fl/aggregator.py` — Poisoning detection (z-score, cosine anomaly)
- `fl/aggregator.py` — Byzantine-tolerant aggregation (Krum, trimmed mean, geometric median)
- `zkp/` — Zero-knowledge proofs that scores are in valid ranges

**Residual risk**: ZKP proves scores are *in range* (0-10) but can't prove they're *honest*. A malicious contributor can submit 1.0 for a tool they never tested — that's a valid range but dishonest data.

**Mitigation needed**: Reputation systems, stake/deposit mechanisms, or cross-validation against known benchmarks.

---

### Attack 9: Traffic analysis
**Threat**: Network observer sees timing, size, and frequency of submissions to infer what happened (e.g., burst of IOC submissions = active incident).

**Defense**: HTTPS (transport layer). No nur-specific defense currently.

**Mitigation needed**: Padding, batching, or scheduled submissions to mask traffic patterns.

---

### Attack 10: Model parameter leakage in FL
**Threat**: Federated learning model updates can leak training data through gradient inversion attacks.

**Defense**: `fl/client.py` — DP-noised gradient updates
- Add calibrated noise to model parameters before sharing
- Composable with per-round privacy budget

**Residual risk**: Deep model gradients are harder to protect than simple aggregates. Gradient inversion attacks are an active research area.

---

## Which Algorithm Solves Which Problem

| Privacy Problem | Algorithm | File | What it guarantees |
|----------------|-----------|------|-------------------|
| PII in free text | Regex scrubbing | `anonymize.py` | Known patterns removed |
| Org identification | k-anonymity bucketing | `anonymize.py` | Identity hidden in bucket |
| IOC rainbow tables | HMAC-SHA256 keyed hash | `keystore.py` | Per-org unique hashes |
| Score inference | Differential Privacy (Laplace) | `dp.py` | Bounded info leakage (epsilon) |
| IOC list exposure | ECDH Private Set Intersection | `psi.py` | Learn only intersection, not sets |
| Coordinator sees values | Additive/Shamir secret sharing | `secagg.py` | Coordinator sees only random shares |
| Skipped anonymization | ADTC attestation chain | `attest/` | Cryptographic proof of process |
| PII in output | Verifiable Absence Proof | `attest/verify.py` | Zero PII patterns in final output |
| Data poisoning | Byzantine aggregation + ZKP | `fl/aggregator.py`, `zkp/` | Outlier detection, valid-range proofs |
| Model gradient leakage | DP-noised gradients | `fl/client.py` | Bounded leakage per FL round |
| Campaign correlation | Graph embeddings only | `graph/` | Share model params, not graph structure |

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              TRUSTED (your machine)             │
│                                                  │
│  Raw data → Extract → Anonymize → DP → Attest  │
│  Key storage, audit log, receipts, review       │
│                                                  │
│  NOTHING leaves without explicit approval        │
├─────────────────────────────────────────────────┤
│           UNTRUSTED (network + server)           │
│                                                  │
│  Transport (HTTPS assumed)                       │
│  Server receives anonymized data only            │
│  SecAgg coordinator sees random shares only      │
│  PSI peer sees blinded points only               │
│  FL coordinator sees noised gradients only       │
│                                                  │
│  Server stores aggregates, never returns         │
│  individual contributions via query API          │
└─────────────────────────────────────────────────┘
```

---

## Known Gaps (ordered by severity)

### Resolved ✅
1. ~~No minimum-k enforcement on aggregates~~ — **Fixed.** `NUR_MIN_K=3` enforced on all query endpoints. No vendor data returned with fewer than 3 contributors.
2. ~~No transport layer enforcement~~ — **Fixed.** Production deployment uses Caddy with auto-HTTPS (Let's Encrypt). Live instance at nur.saramena.us is HTTPS-only.
3. ~~No API key enforcement~~ — **Fixed.** Registration requires work email (free/disposable domains blocked). API key required for all write endpoints.

### Medium Priority
4. **Client integrity verification** — A modified client could skip anonymization and forge attestation. Mitigated by ADTC chain verification on server side.
5. **Bucketing quasi-identifiers** — Industry + size + role combinations may be unique enough to fingerprint. Mitigated by min-k enforcement.
6. **IOC hash correlation within same org** — Same HMAC key means same IOC always hashes the same within that org's contributions.
7. **No rate limiting on PSI queries** — Attacker could probe specific IOCs by submitting targeted sets.
8. **Data poisoning via fake contributions** — Malicious actor could submit fraudulent evaluations. Mitigated by work email requirement and ZKP range proofs.

### Low Priority (theoretical)
9. **Gradient inversion on FL** — Active research area, DP noise is the standard defense.
10. **ZKP proves range, not honesty** — Can prove score ∈ [0,10] but not that it's truthful.
11. **Traffic analysis** — Submission patterns could reveal incident timing.

---

## Anti-Spam Measures

| Measure | Status |
|---------|--------|
| Work email required for API keys | ✅ Implemented — gmail, yahoo, hotmail, etc. blocked |
| API key required for write endpoints | ✅ Implemented |
| Min-k enforcement on aggregates | ✅ Implemented (default k=3) |
| HTTPS enforcement (production) | ✅ Implemented via Caddy |
| Rate limiting per API key | Planned |
| Submission batching (traffic analysis defense) | Planned |
| Per-session IOC key derivation | Planned |
| Reproducible client builds | Planned |
