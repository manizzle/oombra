# nur — Compliance & Legal Analysis

**For: General Counsel, CISO, Compliance Officers**
**Purpose: Demonstrate that using nur does not create regulatory reporting obligations or liability exposure**

---

## Executive Summary

nur is a privacy-preserving threat intelligence aggregation platform. Organizations contribute security data (tool evaluations, attack technique observations, IOC hashes) and receive back aggregate intelligence from the collective.

**The key legal fact:** What leaves your organization when you use nur is *not* an incident report, *not* a breach notification, and *not* a material cybersecurity disclosure. It is structured threat intelligence — numeric scores, categorical labels, and cryptographic hashes — which is explicitly protected under federal information sharing safe harbor laws.

---

## What Data Leaves Your Organization

nur's client-side translators run **on your machine** and convert raw security data into structured, aggregatable form before anything is transmitted. Here is exactly what crosses your network boundary:

| Data sent to nur | Example | Is this PII? | Is this an incident report? |
|-----------------|---------|-------------|---------------------------|
| Numeric scores | `overall_score: 9.2` | No | No |
| Detection rates | `detection_rate: 94.5` | No | No |
| Boolean flags | `would_buy: true` | No | No |
| Categorical labels | `top_strength: "detection_quality"` | No | No |
| MITRE technique IDs | `T1566, T1490` | No | No |
| Hashed IOC values | `SHA-256(ip_address)` | No — irreversible hash | No |
| Remediation categories | `containment: stopped_attack` | No | No |

### What is explicitly stripped before transmission

| Data type | Example | Removed by |
|-----------|---------|-----------|
| Free-text notes | "We found malware on server DC-PROD-03" | `translate_eval()` |
| IP addresses | `10.0.5.42` | Hashed to SHA-256 |
| Hostnames | `dc-prod-03.acme.internal` | Not transmitted |
| Employee names | "John Smith, SOC Analyst" | Not transmitted |
| Sigma rules | YAML detection rule content | `translate_attack_map()` |
| Remediation action text | "Isolated hosts in VLAN 42" | `translate_attack_map()` |
| Organization identity | "Acme Energy Corp" | Pseudonymized |
| Network topology | Subnet layouts, firewall rules | Not transmitted |

### Server-side guarantees

The nur server operates as an "accountable compute node" with the following cryptographic properties:

1. **Individual values are discarded** — only commitment hashes and running aggregate sums are retained
2. **No per-organization attribution** — the server cannot determine which organization contributed which data point
3. **Merkle tree binding** — every contribution is cryptographically committed; the server cannot alter, add, or remove contributions
4. **Aggregate-only responses** — all query responses come from histogram aggregates and template logic, never individual contributions
5. **Dice chain verification** — the client independently hashes the translated payload before submission; the server's receipt contains its own hash of what it received. If they match, the entire transformation chain is verified end-to-end. No data was altered in transit.
6. **BDP anti-poisoning defense** — Behavioral Differential Privacy uses credibility scoring (consistency, variance, timing) to weight contributions. Poisoned data from malicious contributors is automatically down-weighted without revealing individual scores.

---

## Federal Regulatory Framework Analysis

### 1. CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act)

**Requirement:** Report "covered cyber incidents" to CISA within 72 hours. Report ransomware payments within 24 hours. Final rule expected May 2026.

**Analysis:** CIRCIA requires reporting of *cyber incidents* — events that actually or potentially jeopardize information systems or the information they process. What nur receives (numeric scores, categorical labels, hashed IOCs) does not constitute a "covered cyber incident" under CIRCIA's proposed definition. Contributing to nur is threat intelligence sharing, not incident reporting.

**Conclusion:** Using nur does **not** satisfy, replace, or conflict with CIRCIA reporting obligations. Your CIRCIA reporting requirements to CISA remain unchanged.

### 2. NERC CIP-008-6 (Electricity Sector)

**Requirement:** Report Cyber Security Incidents to E-ISAC and ICS-CERT, including functional impact, attack vector, and level of intrusion. Penalties up to $1.29M per violation per day.

**Analysis:** NERC CIP-008-6 requires reporting of incidents that "compromise or attempt to compromise" an Electronic Security Perimeter (ESP) or associated Electronic Access Control and Monitoring Systems (EACMS). The data nur receives does not include: functional impact on BES reliability, specific attack vectors against named systems, or intrusion levels achieved against identified infrastructure.

**Timing consideration:** If your organization is experiencing an active incident, your NERC CIP-008 reporting timeline to E-ISAC takes priority. Contributing aggregate data to nur during an active incident does not fulfill or delay your E-ISAC obligation — they are separate activities.

**Conclusion:** Using nur does **not** satisfy, replace, or conflict with NERC CIP-008-6 obligations.

### 3. SEC Cybersecurity Disclosure (Form 8-K Item 1.05)

**Requirement:** Public companies must disclose material cybersecurity incidents within 4 business days of determining materiality.

**Analysis:** SEC disclosure requires assessment of material impact on the registrant's financial condition and operations. The structured data nur receives (vendor evaluation scores, technique observation frequencies, hashed IOC values) does not constitute disclosure of a material cybersecurity incident. The data is anonymized, aggregated, and contains no information about specific impact to any registrant's business operations.

**Conclusion:** Contributing to nur does **not** constitute an SEC cybersecurity disclosure and does **not** trigger Form 8-K filing requirements.

### 4. State Breach Notification Laws

**Analysis:** State breach notification laws (all 50 states) require notification when personally identifiable information (PII) is compromised. nur does not receive, store, or process PII. Hashed IOC values are irreversible one-way hashes. No individual's personal information is involved at any point in the nur data flow.

**Conclusion:** nur has **no intersection** with state breach notification requirements.

---

## Federal Safe Harbor: CISA 2015

The **Cybersecurity Information Sharing Act of 2015** (extended through September 2026) provides explicit liability protection for organizations that share cyber threat indicators and defensive measures with third parties.

### Protections that apply to nur usage:

| Protection | How it applies to nur |
|-----------|----------------------|
| **No civil liability** for sharing cyber threat indicators | Sharing hashed IOCs, technique observations, and detection scores with nur is protected |
| **No antitrust liability** | Multiple organizations contributing evaluations of the same vendor is not collusion |
| **FOIA exemption** | Data shared through nur is exempt from Freedom of Information Act requests |
| **Regulatory enforcement shield** | Shared data cannot be used as the sole basis for regulatory action against the sharing entity |
| **Evidentiary and discovery bar** | Reports submitted under CISA 2015 protections face limitations on use in civil litigation |

### Requirements for safe harbor applicability:

1. **Personally identifiable information must be removed** before sharing — nur's client-side translators enforce this technically (PII is never transmitted)
2. **Sharing must be for a "cybersecurity purpose"** — nur's purpose (collective threat intelligence, vendor evaluation aggregation, detection gap analysis) qualifies
3. **Reasonable measures to scrub PII** — nur's HMAC-SHA256 hashing, field stripping, and structured-only translation are technically verifiable reasonable measures

---

## Data Flow Certification

The following diagram shows exactly what crosses organizational boundaries:

```
YOUR ORGANIZATION                    nur SERVER
────────────────                     ──────────

Raw incident data
├─ IP addresses        ──STRIPPED──  Never received
├─ hostnames           ──STRIPPED──  Never received
├─ employee names      ──STRIPPED──  Never received
├─ free-text notes     ──STRIPPED──  Never received
├─ sigma rules         ──STRIPPED──  Never received
├─ remediation text    ──STRIPPED──  Never received
│
├─ IOC values          ──HASHED───▶ SHA-256 hash only (irreversible)
├─ vendor scores       ──────────▶  Numeric value (e.g., 9.2)
├─ detection rates     ──────────▶  Numeric value (e.g., 94.5%)
├─ boolean flags       ──────────▶  true/false
├─ technique IDs       ──────────▶  MITRE ATT&CK ID (e.g., T1566)
└─ categories          ──────────▶  Predefined label (e.g., "containment")

                                    Server processes:
                                    ├─ Commits (Pedersen hash)
                                    ├─ Adds to Merkle tree
                                    ├─ Updates running sums
                                    ├─ DISCARDS individual values
                                    └─ Returns cryptographic receipt

RECEIPT returned:
├─ Commitment hash (SHA-256)        Proves your data was included
├─ Merkle inclusion proof           Proves it's in the tree
└─ Server signature                 Server can't deny receiving it
```

---

## Billing & Identity Separation

nur architecturally separates billing from data contribution:

- **Billing system** knows: organization email, payment method, tier
- **nur server** knows: pseudonymous org ID, contribution data, tier access level
- **No join path** exists between billing identity and contribution data in code or database
- A legal request to nur's data systems produces: commitment hashes, aggregate sums, and Merkle trees — none of which are linked to billing identity

---

## Frequently Asked Questions

**Q: Does contributing to nur delay or replace our mandatory incident reporting?**
A: No. nur is threat intelligence sharing, not incident reporting. Your obligations to CISA (CIRCIA), E-ISAC (NERC CIP), SEC (Form 8-K), and state regulators are completely separate and unaffected by nur usage.

**Q: Could nur be subpoenaed for our data?**
A: nur can be subpoenaed, but what the server holds is: commitment hashes (opaque SHA-256 strings), running aggregate sums, and a Merkle tree. There are no individual contribution records, no organization identifiers, and no raw security data. The trustless architecture means there is nothing to produce that identifies any specific organization's contribution.

**Q: Does sharing detection scores with nur violate our NDA with our security vendor?**
A: This depends on your specific vendor agreement. However, sharing an aggregate numeric score (e.g., "9.2 out of 10") and a categorical evaluation (e.g., "detection_quality") is typically not covered by vendor NDAs, which usually restrict sharing of specific technical findings, test methodologies, or product internals. Consult your vendor agreement for specifics.

**Q: What if we're in the middle of an active incident?**
A: Focus on incident response and mandatory reporting first. nur is designed for after-action contribution and peacetime evaluation sharing. There is no time sensitivity requirement — contribute when you're ready.

**Q: Is nur a "security vendor" that requires procurement review?**
A: nur receives only anonymized, structured data — no access to your systems, no credentials, no network access, no agents installed. The community tier is free and requires no procurement. Pro/Enterprise tiers involve a standard SaaS subscription.

**Q: What happens if CISA 2015 safe harbor expires (September 2026)?**
A: Even without CISA 2015 protections, nur's architecture means what you share is technically not "your data" in any identifiable sense — it's anonymized aggregate contributions. However, we actively monitor reauthorization and will notify users of any changes to the legal landscape.

---

## Regulatory Contact Points

For your mandatory reporting obligations (unrelated to nur):

| Framework | Report to | Timeline |
|-----------|----------|----------|
| CIRCIA | CISA (cisa.gov/report) | 72 hours (incidents), 24 hours (ransomware payments) |
| NERC CIP-008-6 | E-ISAC + ICS-CERT | Per your entity's incident response plan |
| SEC Form 8-K | SEC EDGAR | 4 business days after materiality determination |
| State breach notification | State AG office | Varies by state (typically 30-60 days) |

---

*This document is provided for informational purposes and does not constitute legal advice. Organizations should consult their own legal counsel regarding their specific regulatory obligations. Last updated: March 2026.*
