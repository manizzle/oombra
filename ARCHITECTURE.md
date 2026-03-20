# Architecture — Detailed Three-Party Flow

## Swimlane Diagram

**[View interactive diagram on swimlanes.io](https://swimlanes.io##dGl0bGU6IG51ciDigJQgVHJ1c3RsZXNzIFBpcGVsaW5lIEFyY2hpdGVjdHVyZQoKb3JkZXI6IENsaWVudCwgU2VydmVyLCBDb25zdW1lcgoKYXV0b251bWJlcgoKPTogKipDT05UUklCVVRJT04gUEhBU0UqKgoKbm90ZSBDbGllbnQ6CioqMS4gQ09MTEVDVCoqCkxvYWQgaW5jaWRlbnQuanNvbgoKbm90ZSBDbGllbnQ6CioqMi4gU0NSVUIqKgpSZW1vdmUgUElJIGxvY2FsbHkKSGFzaCBJT0MgdmFsdWVzIChITUFDLVNIQTI1NikKCm5vdGUgQ2xpZW50OgoqKjMuIFRSQU5TTEFURSoqCnRyYW5zbGF0ZV9ldmFsKCkgLyB0cmFuc2xhdGVfYXR0YWNrX21hcCgpCioqRFJPUFBFRDoqKiBub3Rlcywgc2lnbWEgcnVsZXMsIGFjdGlvbiB0ZXh0CioqS0VQVDoqKiBvdmVyYWxsX3Njb3JlOiA5LjIsIGNhdGVnb3J5OiBkZXRlY3Rpb25fcXVhbGl0eQoKQ2xpZW50IC0-IFNlcnZlcjogUE9TVCAvY29udHJpYnV0ZS9zdWJtaXQKClNlcnZlciAtPiBTZXJ2ZXI6ICoqNC4gVkFMSURBVEUqKgoKU2VydmVyIC0-IFNlcnZlcjogKio1LiBDT01NSVQqKiBTSEEtMjU2KGRhdGEgKyB0aW1lc3RhbXApCgpTZXJ2ZXIgLT4gU2VydmVyOiAqKjYuIEFHR1JFR0FURSoqIHJ1bm5pbmdfc3VtICs9IHZhbHVlCgpTZXJ2ZXIgLT4gU2VydmVyOiAqKjcuIE1FUktMRSBUUkVFKiogY29tbWl0bWVudCAtPiBsZWFmIC0-IHJvb3QKClNlcnZlciAtPiBTZXJ2ZXI6ICoqOC4gRElTQ0FSRCoqIGluZGl2aWR1YWwgdmFsdWVzIEdPTkUKClNlcnZlciAtLT4gQ2xpZW50OiBSRUNFSVBUIChjb21taXRtZW50X2hhc2ggKyBtZXJrbGVfcHJvb2YgKyBzaWduYXR1cmUpCgo9OiAqKlFVRVJZICsgVkVSSUZJQ0FUSU9OIFBIQVNFKioKCkNvbnN1bWVyIC0-IFNlcnZlcjogR0VUIC92ZXJpZnkvYWdncmVnYXRlL0Nyb3dkU3RyaWtlCgpTZXJ2ZXIgLT4gU2VydmVyOiAqKjkuIFBST1ZFKiogTWVya2xlIHJvb3QgKyBjb21taXRtZW50cyArIHNpZ25hdHVyZQoKU2VydmVyIC0tPiBDb25zdW1lcjogUHJvb2YgcmVzcG9uc2UKCkNvbnN1bWVyIC0-IENvbnN1bWVyOiAqKjEwLiBWRVJJRlkqKiBjb21taXRtZW50cz09Y291bnQ_IHJvb3QgdmFsaWQ_IHNpZ25hdHVyZT8KCj06ICoqQkxJTkQgQ0FURUdPUlkgRElTQ09WRVJZKioKCkNsaWVudCAtPiBTZXJ2ZXI6IHByb3Bvc2UoSCkgd2hlcmUgSCA9IFNIQS0yNTYobmFtZTpzYWx0KQoKU2VydmVyIC0-IFNlcnZlcjogY291bnQoSCkgPj0gMz8KClNlcnZlciAtLT4gQ2xpZW50OiB0aHJlc2hvbGQgbWV0CgpDbGllbnQgLT4gU2VydmVyOiByZXZlYWwoSCwgcGxhaW50ZXh0LCBzYWx0KQoKU2VydmVyIC0-IFNlcnZlcjogVmVyaWZ5IGhhc2ggLT4gUFVCTElDIFRBWE9OT01ZCg)** — click to view and edit interactively

To edit or regenerate, paste this markup into [swimlanes.io](https://swimlanes.io):

```
title: nur — Trustless Pipeline Architecture

order: Client, Server, Consumer

autonumber

=: **CONTRIBUTION PHASE**

note Client:
**1. COLLECT**
Load `incident.json`

note Client:
**2. SCRUB**
Remove PII locally
Hash IOC values (HMAC-SHA256)

note Client:
**3. TRANSLATE**
`translate_eval()` / `translate_attack_map()`
**DROPPED:** notes, sigma rules, action text
**KEPT:** `overall_score: 9.2`, `category: detection_quality`

Client -> Server: POST /contribute/submit
note: Structured data only — no free text, no PII

Server -> Server: **4. VALIDATE**
note Server: Check API key, rate limit, payload limits

Server -> Server: **5. COMMIT**
note Server:
`SHA-256(data + timestamp)` → `commitment_hash`
Individual value sealed — can't be changed

Server -> Server: **6. AGGREGATE**
note Server:
`running_sum += value`
`count += 1`
`technique_freq[T1566] += 1`

Server -> Server: **7. MERKLE TREE**
note Server:
`commitment` → leaf node
Rebuild tree → new root

Server -> Server: **8. DISCARD**
note Server:
Individual values = **GONE**
Only `commitment_hash` retained

Server --> Client: **RECEIPT**
note Client:
`commitment_hash` (proves data sealed)
`merkle_proof` (proves inclusion)
`server_signature` (server can't deny)
Store locally — proves you contributed

=: **QUERY + VERIFICATION PHASE**

Consumer -> Server: GET /verify/aggregate/CrowdStrike

Server -> Server: **9. PROVE AGGREGATE**
note Server:
Merkle root + commitment_hashes[]
aggregate_values (from running sums)
server_signature

Server --> Consumer: Proof response

note Consumer:
**10. VERIFY LOCALLY**
`len(commitments) == count`?
Merkle root valid?
Signature present?
→ **TRUST: aggregate is real**

=: **BLIND CATEGORY DISCOVERY**

Client -> Server: `propose(H)` — H = SHA-256("DarkAngel":salt)
note: Server sees ONLY the hash, never the name

Server -> Server: `count(H) >= 3`?
note Server: 3 independent orgs submitted same hash

Server --> Client: "threshold met — ready for reveal"

Client -> Server: `reveal(H, "DarkAngel", salt)`
note: Quorum of original proposers vote to reveal

Server -> Server: Verify SHA-256("DarkAngel":salt) == H
note Server: Category enters **PUBLIC TAXONOMY**
Aggregation begins on "DarkAngel"
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

## Response Sources — Everything is Aggregate

| Source | Examples | Can identify an org? |
|--------|---------|---------------------|
| **ProofEngine histograms** | "containment stops attacks 87% of the time" | No — running sums |
| **ProofEngine coverage** | "T1490 observed 47x, 5 tools detect it" | No — aggregate counts |
| **Template logic** | "Block network IOCs at firewall" | No — generated from patterns |
| **Public taxonomy** | "NIST: containment → Network Isolation (D3-NI)" | No — public knowledge |
| ~~Individual contributions~~ | ~~"Org X used this sigma rule"~~ | ~~Yes~~ — **removed** |

## Regulatory Compliance

See [COMPLIANCE.md](COMPLIANCE.md) for the full legal analysis covering CIRCIA, NERC CIP, SEC 8-K, state breach laws, and CISA 2015 safe harbor protections.
