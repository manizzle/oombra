# Data License

## vigil Curated Data

The curated threat intelligence data in `vigil/data/` (capabilities, integrations, MITRE mappings, vendor metadata) is licensed under the **Community Data License Agreement – Permissive, Version 2.0 (CDLA-Permissive-2.0)**.

Full text: https://cdla.dev/permissive-2-0/

This means:
- You can **use** this data for any purpose (commercial or non-commercial)
- You can **modify, combine, and redistribute** this data
- You must **include the license notice** when redistributing
- No copyleft / share-alike requirement — use it however you want

The CDLA-Permissive-2.0 is maintained by the Linux Foundation and is specifically designed for data sharing. It's the Apache 2.0 equivalent for data.

## Scraped Feed Data (`data/feeds/`)

The `data/feeds/` directory contains snapshots from public threat intelligence feeds. Each feed has its own license:

| Feed | License | Attribution |
|------|---------|------------|
| ThreatFox | CC0 1.0 (public domain) | abuse.ch |
| Feodo Tracker | CC0 1.0 | abuse.ch |
| MalwareBazaar | CC0 1.0 | abuse.ch |
| URLhaus | CC0 1.0 | abuse.ch |
| SSL Blacklist | CC0 1.0 | abuse.ch |
| CISA KEV | Public Domain (US Government) | CISA |
| FireHOL | Open Source | FireHOL project |
| IPsum | Open Source | stamparm |
| Emerging Threats | Free | Proofpoint |
| Spamhaus DROP | Free (non-commercial) | Spamhaus Project |
| MITRE ATT&CK | Apache 2.0 | MITRE Corporation |
| NVD | Public Domain (US Government) | NIST |

## User-Contributed Data

Data contributed by users through `vigil report` or `vigil upload`:
- **Anonymized locally** before submission
- **Owned by the contributor** — vigil does not claim ownership
- **Licensed for aggregation** — by contributing, you grant vigil the right to include your anonymized data in aggregate reports
- **Never returned individually** — only aggregates via query endpoints

## Open Data Principles

vigil follows the [Open Data Charter](https://opendatacharter.net/):

1. **Open by default** — all aggregated intelligence available to contributors
2. **Timely and comprehensive** — 19+ live feeds, hourly refresh
3. **Accessible and usable** — JSON API, CLI `--json`, Python SDK
4. **Comparable and interoperable** — MITRE ATT&CK aligned, STIX 2.1 compatible
5. **For improved governance** — collective defense is a public good
6. **For inclusive development** — open source, deployable by anyone
