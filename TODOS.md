# TODOS

## P1 — Launch Blockers

### Legal: CISA 2015 Opinion Letter
**What:** Find a cyber law attorney and get a formal legal opinion letter confirming nur's data qualifies as "cyber threat indicators" under CISA 2015.
**Why:** Every enterprise customer conversation ends with "run this by legal." Without the opinion letter, their lawyer does the analysis from scratch and defaults to "no." With it, their lawyer calls your lawyer and gets a 2-page "this is fine."
**Budget:** ~$2-5K one-time
**Action items:**
- [ ] Contact 2-3 cyber law firms (Venable, Morrison Foerster, Cadwalader, or solo cyber law practitioner)
- [ ] Send them COMPLIANCE.md + translate_eval/translate_attack_map code showing what's stripped
- [ ] Get opinion letter covering: CISA 2015 applicability, CIRCIA non-triggering, NERC CIP non-triggering, SEC 8-K non-triggering
- [ ] Get Terms of Service + Privacy Policy drafted (~$1-2K additional)
- [ ] CISA 2015 expires September 2026 — monitor reauthorization
**Depends on:** Nothing — can start today
**Priority:** P1 — blocks enterprise conversations

### Legal: Terms of Service + Privacy Policy
**What:** ToS + Privacy Policy pages for nur.saramena.us
**Why:** No enterprise will use a platform without these. Also needed for GDPR if EU users contribute.
**Budget:** ~$1-2K (lawyer review of template)
**Action items:**
- [ ] Draft ToS covering AGPL licensing, data contribution terms, acceptable use
- [ ] Draft Privacy Policy covering what data is collected (hashed API keys, aggregate behavioral profiles), retention, GDPR
- [ ] Draft DPA template for Enterprise customers
- [ ] Add /terms and /privacy pages to the site
**Depends on:** Lawyer engagement from above
**Priority:** P1

---

## P1 — Product: First Customer

### Direct Outreach to Contact
**What:** Reach out to specific critical infrastructure contact with a 15-minute demo offer.
**Why:** One real conversation > 100 LinkedIn posts. The product is ready. The bottleneck is the founder, not the code.
**Action items:**
- [ ] Message: "I built something that lets security teams share vendor evaluations and attack data without revealing who they are — math, not promises. I'd love 15 minutes to show you."
- [ ] Have the 5-minute CLI demo ready (demo/demo.sh)
- [ ] Have COMPLIANCE.md ready for their legal team
**Depends on:** Nothing — can do today
**Priority:** P1

---

## P1 — Product: Messaging & PMF

### Sharpen the IOC→Remediation Pitch
**What:** The IOC upload isn't about "sharing IOCs" (altruism). It's about getting remediation intelligence back (self-interest). Every piece of marketing, demo, and README needs to lead with what you GET, not what you GIVE.
**The pitch:** "Upload your IOCs → instantly learn: is this a known campaign? What category of remediation works (containment 87% success)? How fast are peers detecting this? You get intelligence that takes weeks through your ISAC — in seconds."
**Action items:**
- [ ] Update demo/demo.sh narration to emphasize remediation output, not IOC upload
- [ ] Update landing page hero text
- [ ] Update YC application "what does your company do" to lead with remediation value
- [ ] Prepare the "Blind/Bloomberg Terminal for security" one-liner for all contexts
**Priority:** P1 — this IS the PMF message

### YC Application
**What:** Complete and submit YC application
**Status:** Draft at docs/yc-application.md
**Action items:**
- [ ] Record 1-minute video demo (required by YC)
- [ ] Refine answers based on design partner conversation feedback
- [ ] Submit application
**Depends on:** First customer conversation (strengthens the application enormously)
**Priority:** P1

---

## P2 — Product Features

### Invite-Only / Referral System
**What:** Add invite codes so existing users can invite peers. Limits spam, builds community organically.
**Why:** Solves two problems: (1) anti-spam without heavy auth friction, (2) builds community through trust chains — security people trust referrals from peers.
**How it works:**
- Each registered user gets 3-5 invite codes
- New users need an invite code OR a work email to register
- Invite chains are tracked (who invited whom) for community growth metrics
- Invited users inherit a small credibility boost in BDP (their inviter vouched for them)
**Effort:** M (human: ~1 week / CC: ~30 min)
**Depends on:** Nothing
**Priority:** P2

### Web-Based Eval Form
**What:** A /contribute page on the website where non-security people can submit vendor evals without installing the CLI.
**Why:** Yushea has interested people who aren't going to install a CLI. Procurement teams, IT managers, MSP operators know pricing and support quality but won't use terminal tools.
**How it works:**
- User enters work email → magic link → logged in with API key in cookie
- Fill out eval form (vendor, scores, pricing, support, decision)
- Submit → hits POST /contribute/submit with API key
- Get receipt back
**Effort:** M (human: ~1 week / CC: ~30 min)
**Depends on:** Nothing — existing email verification flow supports this
**Priority:** P2

### Vendor Demo Marketplace
**What:** Vendor profile pages at /vendor/{name} showing practitioner aggregate scores + vendor-submitted demo videos.
**Why:** Creates a complete evaluation experience — truth layer (anonymous scores) + marketing layer (vendor demos). Revenue model: vendors pay for featured listings, lead gen metrics.
**Tiers:**
- Free listing: name + category + practitioner scores (already exists in aggregates)
- Demo listing: upload demo video/link + product description ($0 — want adoption)
- Featured: pinned in category, highlighted in comparisons ($2-5K/mo)
- Lead gen: anonymized interest metrics ("47 orgs watched your demo") (enterprise pricing)
**Effort:** L (human: ~2 weeks / CC: ~2 hours)
**Depends on:** Some eval data in the system first
**Priority:** P2

### PIR (Private Information Retrieval) for Queries
**What:** Allow users to query aggregates without the server knowing what they queried.
**Why:** Nate Lawson suggested this. Strengthens privacy story. Currently BDP tracks queries (conflicts with PIR).
**Sweet spot:** Use PIR for sensitive queries (which vendor you're evaluating) and BDP for general behavioral patterns (contribution types, integration sources). Poisoner detection still works because it's based on contribution behavior, not query behavior.
**Effort:** XL (human: ~2 months / CC: ~2 weeks) — real cryptographic PIR is complex
**Depends on:** Research into practical PIR implementations (SealPIR, SimplePIR)
**Priority:** P3 — nice to have, not launch blocking

### ADTC → ProofEngine Dice Chain Link
**What:** Wire the client-side ADTC (Attested Data Transformation Chain) to the server-side ProofEngine so there's an end-to-end cryptographic chain from raw data to final aggregate.
**Why:** Travis's "data dice chains" concept. Proves every transformation step was honest.
**How:** Client's last ADTC hash must match the server's contribution_hash in the receipt. If they match, the chain is verified end-to-end.
**Effort:** S (human: ~2 days / CC: ~30 min) — most of the code exists
**Depends on:** Nothing
**Priority:** P2

### Blind Token Payment System
**What:** Privacy Pass-style blind tokens for anonymous payment. Payment proxy issues tokens, nur server redeems without knowing who bought them.
**Why:** Strengthens trustless promise — even billing doesn't reveal identity.
**Effort:** L (human: ~3 weeks / CC: ~6 hours)
**Depends on:** Having paying customers first (premature until then)
**Priority:** P3

### Server-Side Build Attestation
**What:** Reproducible Docker builds or TEE (Nitro Enclaves) so anyone can verify the server code matches the source.
**Why:** Travis's concern: "so you know I haven't backdoored the server."
**Effort:** M for reproducible builds, XL for TEE
**Depends on:** Nothing for reproducible builds
**Priority:** P2

### IOC Hashing Weakness (HMAC Salt Rotation)
**What:** Current IOC hashing uses HMAC-SHA256 with an org-local salt. IPv4 addresses have only 2^32 possible values — a motivated attacker could rainbow-table them. Short-term: rotate salts periodically. Long-term: ECDH PSI (see P3).
**Why:** Nate Lawson and Travis both flagged this. If someone gets the HMAC key, they can reverse all IP IOCs.
**Mitigation (now):** Document that IOC hash matching is "good enough for campaign correlation" not "cryptographically unbreakable." For IP addresses specifically, consider bucketing into /24 subnets before hashing (reduces precision but increases security).
**Effort:** S (documentation + salt rotation: CC ~15 min). M (subnet bucketing: CC ~30 min).
**Priority:** P2

### BDP→ProofEngine Full Integration
**What:** Currently BDP computes credibility weights but ProofEngine uses simple averages. Wire BDP weights into the actual aggregation so poisoned contributions are downweighted in real-time.
**Why:** Right now BDP tracks behavior and /proof/bdp-stats shows credibility distribution, but the aggregate scores at /verify/aggregate still use unweighted averages. The defense exists but isn't applied.
**How:** Store contributor profile ID with each commitment in the aggregate bucket. When computing averages, use bdp_weighted_aggregate() instead of sum/count.
**Effort:** M (human: ~1 week / CC: ~30 min)
**Depends on:** Nothing
**Priority:** P2

### Hybrid BDP+PIR Query Privacy
**What:** Use PIR for sensitive queries (which vendor you're evaluating) and BDP for contribution behavior tracking. Sweet spot between privacy and anti-poisoning.
**Why:** Nate suggested PIR. Current BDP tracks ALL queries including sensitive ones (reveals procurement intent). Hybrid approach: PIR hides WHAT you query, BDP tracks HOW you contribute.
**Effort:** L (human: ~3 weeks / CC: ~4 hours)
**Depends on:** PIR research (SealPIR, SimplePIR)
**Priority:** P2 — differentiator for enterprise customers who care about query privacy

---

## P3 — Future

### ECDH PSI for Secure Threat Matching
**What:** Replace SHA-256 IOC hashing with Elliptic-Curve Diffie-Hellman Private Set Intersection.
**Why:** SHA-256 of IPv4 addresses is rainbow-table-attackable (only 2^32 possible IPs). ECDH PSI is mathematically secure.
**Effort:** XL
**Priority:** P3

### Shamir's Secret Sharing for Aggregation
**What:** Shred data into fragments so no single server holds raw information.
**Why:** Part of the full cryptographic pipeline (ZKP + SSS + Pedersen).
**Effort:** XL
**Priority:** P3

---

## Completed

- [x] Trustless pipeline integration (575→595 tests)
- [x] Blind category discovery
- [x] Public taxonomy (NIST/D3FEND/RE&CT)
- [x] BDP behavioral profile tracking (all endpoints)
- [x] Expanded eval schema (price, support, performance, decision)
- [x] COMPLIANCE.md — legal-ready regulatory analysis
- [x] AGPL-3.0 + CLA dual licensing (in first commit)
- [x] Site redesign (modern dark theme, Inter font)
- [x] Server stability (health checks, watchdog, memory limits, log rotation)
- [x] Streamlined README (131 lines)
- [x] Mermaid architecture diagram in ARCHITECTURE.md
- [x] Narrated demo (demo/demo.sh) — block display, real server
- [x] Vendor profile pages (/vendor/{id} + claim flow)
- [x] YC application draft (docs/yc-application.md)
- [x] CI lint fixes (ruff.toml + 129 auto-fixes)
