<h1 align="center">nur</h1>

<p align="center"><strong>Collective security intelligence for industries.</strong></p>

<p align="center">
  <img src="demo/nur-demo.gif?v=5" alt="nur demo" width="750" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-591_passing-2ed573" />
  <img src="https://img.shields.io/badge/sources-37_live-ff6b6b" />
  <img src="https://img.shields.io/badge/vendors-36_tracked-ffa502" />
  <img src="https://img.shields.io/badge/license-AGPL--3.0-1e90ff" />
</p>

---

Attackers share everything. Defenders share nothing. nur fixes that.

- **Wartime** — under attack? Upload IOCs, get campaign matches and detection gaps.
- **Peacetime** — evaluating tools? Get real practitioner benchmarks: price, support, detection, decision intel.

The server commits to every value, proves every aggregate, and discards individual data. Cryptographic receipts, Merkle proofs, and aggregate-only responses. Your data can't be mined — math, not promises.

> [nur.saramena.us](https://nur.saramena.us) — [dashboard](https://nur.saramena.us/dashboard) · [docs](https://nur.saramena.us/guide) · [register](https://nur.saramena.us/register)

---

## Get started

```bash
pip install nur
nur init
nur register you@yourorg.com
nur report incident.json
```

---

## Architecture

<p align="center">
  <img src="demo/architecture.png?v=5" alt="nur trustless architecture" width="700" />
</p>

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed sequence diagram.

---

## What you can evaluate

```
Detection:    overall score, detection rate, false positives
Price:        annual cost, per-seat cost, contract length, discount
Support:      quality, escalation ease, SLA response time
Performance:  CPU overhead, memory, scan latency, deploy time
Decision:     chose this vendor?, main decision factor
```

All fields committed, aggregated, individual values discarded. Competitive with Vendr/Tropic on pricing data — crowdsourced from practitioners, not vendor negotiations.

---

## Example: wartime

```bash
$ nur report lockbit_iocs.json
  Campaign Match: Yes
  Shared IOCs: 32
  [CRITICAL] Block matching network indicators at firewall and DNS

$ nur report lockbit_attack_map.json
  Coverage Score: 71%
  Detection Gaps: 3
  Best Remediation: containment (87% success rate)
```

## Example: peacetime

```bash
$ nur eval --vendor crowdstrike       # price, support, detection, decision intel
$ nur market edr                      # vendor rankings from real practitioners
$ nur search compare crowdstrike sentinelone
$ nur threat-model --stack crowdstrike,splunk,okta --vertical healthcare
```

---

## Trustless deep dive

<details>
<summary>Proof verification chain</summary>

```
Submit ──▶ Translate ──▶ Commit ──▶ Merkle ──▶ Receipt
               │             │          │          │
          drop text     running sum   proof    signature
               │             │          │
               └── DISCARD ──┘         ▼
                              /verify/receipt
                              /verify/aggregate/{vendor}
                              /proof/stats
```

</details>

<details>
<summary>Blind category discovery</summary>

New threat actors not in any database? Three orgs hash the same name independently → threshold met → vote to reveal → enters public taxonomy for aggregation. Server never sees the name until quorum agrees.

</details>

<details>
<summary>Crypto primitives</summary>

| Primitive | Purpose |
|-----------|---------|
| Pedersen Commitments | Server can't alter values after receipt |
| Merkle Tree | Server can't add/remove contributions undetected |
| ZKP Range Proofs | Proves scores valid without revealing them |
| BDP Credibility | Behavior-based poisoning defense (QCA) |
| Blind Category Discovery | Server can't learn category names until quorum |

</details>

<details>
<summary>Security hardening</summary>

Work email required · keypair auth · signed requests · rate limiting · min-k enforcement · payload limits · AWS Secrets Manager

</details>

Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md) · [COMPLIANCE.md](COMPLIANCE.md)

---

## Pricing

| | Community | Pro | Enterprise |
|---|---|---|---|
| **Price** | Free | $99/mo | $499/mo |
| Contribute + receipts | ✓ | ✓ | ✓ |
| Market maps + rankings | | ✓ | ✓ |
| Threat maps + simulation | | ✓ | ✓ |
| API + dashboard + RFP | | | ✓ |

---

## License

[AGPL-3.0](LICENSE) — free for open source. Commercial use requires a [separate license](mailto:murtaza@saramena.us). See [CLA.md](CLA.md).

Data: [CDLA-Permissive-2.0](DATA_LICENSE.md)
