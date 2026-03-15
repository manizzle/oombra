# Data License

## Threat Intelligence Data

The threat intelligence data in `oombra/data/` (capabilities, integrations, MITRE mappings, vendor metadata) is licensed under the **GNU Lesser General Public License v3.0 (LGPL-3.0)**.

This means:
- You can **use** this data in any project (commercial or open-source)
- You can **modify** this data
- If you **distribute modified versions** of the data files themselves, you must share your modifications under the same LGPL-3.0 license
- Using oombra (which loads this data) does **not** require your application to be open-source

## Third-Party Data Sources

oombra ingests data from public threat intelligence feeds. These sources have their own terms:

| Source | License/Terms | URL |
|--------|--------------|-----|
| ThreatFox (abuse.ch) | CC0 1.0 | https://threatfox.abuse.ch/faq/#tos |
| Feodo Tracker (abuse.ch) | CC0 1.0 | https://feodotracker.abuse.ch/ |
| MalwareBazaar (abuse.ch) | CC0 1.0 | https://bazaar.abuse.ch/about/ |
| URLhaus (abuse.ch) | CC0 1.0 | https://urlhaus.abuse.ch/api/ |
| CISA KEV | Public domain (US Gov) | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| MITRE ATT&CK | Apache 2.0 | https://attack.mitre.org/resources/terms-of-use/ |

All scraped data is used in compliance with the respective terms of service.

## User-Contributed Data

Data contributed by users through `oombra report` or `oombra upload` is:
- **Anonymized locally** before submission (HMAC-hashed IOCs, scrubbed PII, bucketed context)
- **Owned by the contributor** — oombra does not claim ownership
- **Licensed for aggregation** — by contributing, you grant oombra the right to include your anonymized data in aggregate statistics and intelligence reports
- **Never returned individually** — only aggregates are exposed via query/intelligence endpoints

## Open Data Principles

oombra follows the [Open Data Charter](https://opendatacharter.net/) principles:
1. **Open by default** — aggregated threat intelligence is available to all contributors
2. **Timely and comprehensive** — live feed ingestion keeps data current
3. **Accessible and usable** — JSON API, CLI with `--json`, Python SDK
4. **Comparable and interoperable** — MITRE ATT&CK aligned, STIX 2.1 compatible
5. **For improved governance and citizen engagement** — collective defense is a public good
6. **For inclusive development and innovation** — open source, deployable by anyone
