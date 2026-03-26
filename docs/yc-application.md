# YC Application — nur

## Company name
nur

## One-liner
The Blind for security — practitioners share tool evaluations, attack data, and pricing anonymously through a trustless protocol.

## What does your company do?
nur is a social network for security intelligence. Product = protocol + users. Organizations contribute vendor evaluations (pricing, detection rates, support quality), attack technique observations, and IOC data through a trustless aggregation protocol. In return, they get aggregate intelligence from the collective — what tools actually work, what they cost, and what peers did when they got hit by the same threat actor.

The data model: query data (threat models, IOCs, stacks) flows in. Response data (tool intel, remediation, pricing) flows back. The protocol IS the product — it commits to every value using Pedersen hashes, binds them in a Merkle tree, aggregates running sums, and discards individual data. Every query comes with a cryptographic proof. Contributors get receipts. Consumers verify proofs. Nobody has to trust anyone — math, not promises.

The integration shares. The human gets remediation back. Connect your CrowdStrike/Splunk/Sentinel via webhook. When a detection fires, nur automatically ingests it, matches against the collective, and pushes remediation intelligence back to your Slack channel. The human does nothing.

## Why did you pick this idea to work on?
I've lived this problem on both sides. During incident response, I couldn't get peer intelligence — no scalable way to know if other orgs were seeing the same campaign or which tools caught it. During vendor evaluations, the only "data" was Gartner (pay-to-play) and vendor marketing (biased). Internal bakeoffs take months and reflect one org's experience.

The security industry has a fundamental information asymmetry: attackers share everything (tools, techniques, infrastructure), defenders share nothing. Not because they don't want to — because they can't. Sharing incident data risks mandatory reporting violations. Sharing eval data risks vendor NDAs. Sharing pricing data reveals procurement strategy.

nur solves this with math: the server literally cannot see individual contributions. What leaves your machine is numeric scores and categorical labels — not an incident report, not PII, not raw IOCs. Federal law (CISA 2015) explicitly protects this kind of sharing with liability safe harbor.

## How far along are you?
Live at nur.saramena.us. 616 tests. 37 live threat feeds scraping 658,000+ IOCs. 3,000+ vendors in the evaluation taxonomy. Full CLI (pip install nur). Trustless architecture fully wired — every submission returns a cryptographic receipt. Behavioral Differential Privacy (BDP) engine detects data poisoning through Query-Contribution Alignment. Blind category discovery lets orgs surface new threat actors without revealing who was attacked. Expanded eval schema covers price, support, detection, performance, and decision intel. Invite-only referral system with invite codes. Slack remediation notifications (auto-alert when webhooks fire with campaign matches and remediation steps). End-to-end dice chain verification (client hash matches server commitment). Vendor demo marketplace with profile pages.

Pre-revenue, pre-customers. Ready for first customer conversations.

## How long have each of the founders been working on this?
Solo founder, 2 weeks of building. The entire platform — server, CLI, trustless layer, 37 feed scrapers, 616 tests — was built with AI-assisted coding (Claude Code). This compression is the thesis: one person with AI can build what used to take a team of 20.

## How will you get users?
Three channels:

1. **Direct outreach** to security directors at critical infrastructure orgs (energy, water, transportation). They're the most targeted (nation-state actors), most underserved (small teams, no budget for expensive ISACs), and most motivated by compliance pressure (NERC CIP mandates information sharing). I have a specific contact to start with.

2. **Vendor demo marketplace** — vendors claim their profile (free), add their demo video, and get leads from practitioners evaluating their product. Vendors drive traffic because their demo sits next to real practitioner scores. If CrowdStrike's demo is on nur and SentinelOne's isn't, SentinelOne is invisible.

3. **Invite-only community** — each registered user gets invite codes for peers. Security people trust peer referrals. This builds a trust network organically and limits spam. The invite system is already built and live — this is the primary growth channel from day one.

## What's your revenue model?
Three tiers:

- **Community** (free): Contribute data, get intelligence reports, cryptographic receipts. This is the data acquisition engine.
- **Pro** ($99/mo): Market maps, vendor rankings, threat coverage analysis, attack simulation. This is the intelligence product.
- **Enterprise** ($499/mo): API access, vendor intelligence dashboard, compliance reports, RFP generation, priority support.

Additionally, vendors pay for featured listings, verified badges, and lead generation metrics on their profile pages ($2-5K/mo). This is the G2/TrustRadius model but with cryptographically verified practitioner data instead of hand-curated reviews.

## Who are your competitors?
- **Gartner/Forrester** ($50-100K/yr): Lagging, pay-to-play, vendor-biased. Not practitioner truth.
- **G2/TrustRadius/PeerSpot**: Reviews but no privacy, no aggregation, no cryptographic verification. Gameable.
- **ISACs** (FS-ISAC, H-ISAC): Slow, PDF-based, sector-specific. The intel is stale by the time it arrives.
- **Vendr/Tropic**: Have pricing data but from vendor negotiations, not practitioner experience. Don't cover detection/support.
- **Informal Slack/Signal groups**: Work but don't scale. No privacy guarantees. Depends on who you know.

nur is the only platform that combines (1) real practitioner data, (2) cryptographic privacy guarantees, and (3) multi-dimensional intelligence (price + support + detection + decision) in one place.

## What do you understand that others don't?
Every company is an algorithm — 20+ decision points, all algorithmic. Every handoff between them is a data contract. Today most of those contracts are empty: the "Select Vendor" diamond has no real practitioner data, the "Accept/Mitigate/Transfer" diamond has no peer remediation intel. nur fills data contracts. Product = protocol + users. The protocol enables trust. The users create value. At 1,000 users, switching cost is infinite — you'd lose the collective intelligence of every security team in your vertical. 10 users = interesting. 100 = useful. 1,000 = indispensable.

The security intelligence problem isn't a technology problem — it's a trust problem. ISACs tried to solve sharing with legal agreements. Threat intel platforms tried with anonymization. Both failed because defenders won't share if they can't verify the platform is honest.

The insight: in a give-to-get system, the behavioral pattern of how people use the platform IS the trust signal. A real CrowdStrike practitioner contributes evals AND queries about CrowdStrike's market position AND simulates attacks against their stack. A poisoner just submits fake data. The correlation between what you give and what you consume (Query-Contribution Alignment) is nearly impossible to fake without actually being a real practitioner.

This means you can build a platform that is simultaneously blind to individual data AND resistant to data poisoning — which everyone said was impossible.

The data model makes this concrete: query data (threat models, IOCs, stacks) flows in. Response data (tool intel, remediation, pricing) flows back. The protocol IS the product — it's what makes give-to-get trustless.

## How do you know people need what you're making?
I've been on both sides of this problem. During incident response, I scrambled to find out if peers were seeing the same attack — nobody shares. During vendor evaluations, I spent months on bakeoffs that reflected only our experience. When I asked security peers how they evaluated tools, every single one said some variant of: "We did a bakeoff, but we have no idea if our results are typical."

The current workarounds are broken: informal peer networks (don't scale), Gartner (biased), internal bakeoffs (one org's view, months of effort). Every CISO I've talked to agrees the problem exists. The question was always trust — "I'd share if I knew my data was safe." That's what the cryptography solves.

## Anything else we should know?
The entire platform was built in 2 weeks by a solo founder with AI-assisted coding. 616 tests. 37 live feeds scraping 658K+ IOCs. Trustless cryptography (Pedersen commitments, Merkle trees, aggregate-only responses). Behavioral anti-poisoning (BDP with Query-Contribution Alignment). Blind category discovery (threshold reveal protocol for new threat actors). End-to-end dice chain verification (client hash matches server commitment). Expanded vendor evaluation (price, support, detection, performance, decision intel). Vendor demo marketplace (vendors claim profiles, add demos, get leads). Invite-only referral system. Slack remediation notifications (auto-alert when webhooks fire with campaign matches and remediation steps). Legal compliance documentation (CIRCIA, NERC CIP, SEC 8-K, CISA 2015 safe harbor). AGPL + CLA dual licensing.

The key integration insight: nobody manually shares IOC data. You connect your CrowdStrike/Splunk/Sentinel via webhook. When a detection fires, nur automatically ingests it, matches against the collective, and pushes remediation intelligence back to your Slack channel. The human does nothing — the integration shares, the human gets remediation back. Connect your SIEM, webhook fires, nur matches, Slack notification with remediation steps. The auto-remediation loop runs 24/7.

What I need from YC: the network to find my first 10 design partners in critical infrastructure, and the batch pressure to stop building and start selling.
