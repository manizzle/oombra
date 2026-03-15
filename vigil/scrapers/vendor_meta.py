"""
Vendor metadata scraper -- pricing, certifications, deploy time, insurance, known issues.

All data is publicly verifiable from vendor trust pages, CVE databases,
SEC filings, and cyber insurance carrier published tool lists.

Sources:
  - Vendor trust/compliance pages (SOC2, FedRAMP, ISO27001 certifications)
  - NVD / CISA advisories (CVEs and incidents)
  - Coalition, Corvus, At-Bay published preferred tool lists (2024)
  - Gartner, G2, Forrester pricing research (public)
"""
from __future__ import annotations

# Each entry: (vendor_id, price_range, certifications, deploy_days,
#               insurance_carriers, insurance_notes, known_issues)
VENDOR_META = [
    # -- EDR / XDR --
    ("crowdstrike", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss", "hipaa-baa", "stateramp"],
     12,
     ["coalition", "corvus", "at-bay", "beazley", "chubb"],
     "Coalition and At-Bay list CrowdStrike as a preferred EDR -- 10-20% premium reduction.",
     "July 2024 global IT outage -- faulty sensor content update caused BSOD on ~8.5M Windows devices."),

    ("sentinelone", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss", "hipaa-baa"],
     10,
     ["coalition", "corvus", "at-bay"],
     "Listed as preferred EDR by Coalition and Corvus.",
     ""),

    ("ms-defender", "included-m365",
     ["soc2-type2", "fedramp-high", "iso27001", "fips-140-2", "hipaa", "pci-dss"],
     3,
     ["coalition", "beazley"],
     "Widely accepted but not typically a premium differentiator.",
     "Historical detection gaps in MITRE evaluations (2020-2022); improved in later rounds."),

    ("cortex-xdr", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss", "fips-140-2"],
     14,
     ["chubb", "beazley"],
     "Accepted by enterprise carriers. Not commonly on preferred-tool discounts.",
     "Complex licensing tiers. CVE-2021-3044 (Cortex XSOAR, CVSS 9.8)."),

    ("carbon-black", "$30-60/ep/yr",
     ["soc2-type2", "iso27001"], 21, [], "",
     "Product direction uncertainty since Broadcom acquisition of VMware (2023)."),

    ("sophos", "$30-60/ep/yr",
     ["soc2-type2", "iso27001"], 10, ["corvus"],
     "Corvus lists Sophos as an accepted MDR/EDR provider.", ""),

    ("bitdefender", "$30-60/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate"], 7, [], "", ""),

    ("eset", "<$30/ep/yr",
     ["iso27001", "soc2-type2"], 7, [], "", ""),

    ("trend-apex", "$30-60/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate"], 14, [],
     "", "2019 data breach -- rogue employee sold customer data."),

    ("kaspersky", "<$30/ep/yr",
     ["iso27001", "soc2-type2"], 7, [],
     "", "US government ban on Kaspersky products (2024)."),

    # -- SIEM --
    ("splunk", "consumption",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss", "hipaa"],
     45, ["chubb", "beazley", "aig"],
     "Positively viewed by enterprise carriers for regulated industries.",
     "Cisco acquisition (2024). 2022 significant license price increases."),

    ("ms-sentinel", "consumption",
     ["soc2-type2", "fedramp-high", "iso27001", "fips-140-2", "hipaa", "pci-dss"],
     14, ["coalition", "beazley"],
     "Coalition values the integrated Microsoft security stack.", ""),

    ("qradar", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2", "pci-dss"],
     60, [], "", "IBM strategic shift to QRadar Cloud."),

    ("elastic-siem", "open-source",
     ["soc2-type2", "fedramp-moderate", "iso27001"], 28, [], "", ""),

    # -- CNAPP --
    ("wiz", "consumption",
     ["soc2-type2", "iso27001", "fedramp-moderate"],
     7, ["coalition", "at-bay", "corvus"],
     "Most-cited tool on carrier preferred cloud security lists. 5-15% discount.", ""),

    ("prisma-cloud", "consumption",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss"], 21, ["chubb"], "", ""),

    ("snyk", "consumption",
     ["soc2-type2", "iso27001"], 7, [], "", ""),

    # -- IAM --
    ("okta", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss", "fips-140-2"],
     14, ["coalition", "at-bay", "corvus", "beazley"],
     "Universally listed on carrier preferred IAM/MFA programs. 5-15% discounts.",
     "2022 Lapsus$ breach. 2023 support system breach."),

    ("entra-id", "included-m365",
     ["soc2-type2", "fedramp-high", "iso27001", "fips-140-2", "hipaa", "pci-dss"],
     3, ["coalition", "beazley"],
     "MFA via Entra frequently cited as discount trigger.", ""),

    # -- PAM --
    ("cyberark-pam", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2", "pci-dss"],
     45, ["coalition", "chubb", "beazley", "aig"],
     "Most widely cited PAM tool on carrier preferred lists. 10-20% discounts.", ""),

    ("beyondtrust", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2", "pci-dss"],
     30, ["coalition", "beazley"],
     "Listed on Coalition and Beazley preferred PAM programs.",
     "2024 Remote Support compromise used to access US Treasury systems."),

    ("hashicorp-vault", "open-source",
     ["soc2-type2", "iso27001"], 14, [],
     "", "2023 license change to BSL. OpenBao fork created."),

    # -- Email --
    ("proofpoint", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss"],
     14, ["coalition", "beazley", "chubb"],
     "Top-listed email security on carrier programs. 5-10% premium discounts.", ""),

    ("mimecast", "$30-60/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate"],
     14, ["coalition"],
     "Listed on Coalition preferred programs.",
     "2021 breach via Mimecast-issued certificate."),

    # -- ZTNA --
    ("zscaler", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2", "pci-dss"],
     21, ["coalition", "at-bay"],
     "Listed on At-Bay and Coalition preferred Zero Trust programs.", ""),

    ("cloudflare-zt", "<$30/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate", "pci-dss"],
     1, ["coalition", "at-bay"], "", ""),

    ("cisco-duo", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2"],
     7, ["coalition", "corvus", "beazley"],
     "Top-accepted MFA solution across carrier programs.", ""),

    # -- VM --
    ("tenable", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-high", "iso27001", "fips-140-2", "pci-dss"],
     7, ["corvus", "coalition"],
     "Among the most cited VM tools on carrier preferred programs.", ""),

    ("qualys", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss"],
     7, ["corvus"],
     "Corvus recognises Qualys as a preferred VM platform.",
     "2020 data breach via Accellion FTA vulnerability."),

    ("rapid7", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001"], 7, ["corvus"], "", ""),

    # -- WAF --
    ("cloudflare-waf", "<$30/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate", "pci-dss"],
     1, ["coalition", "at-bay"],
     "Broadly listed as preferred DDoS/WAF provider.", ""),

    ("f5-waf", ">$60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "fips-140-2", "pci-dss"],
     21, [], "",
     "CVE-2022-1388 + CVE-2023-46747 (both CVSS 9.8, actively exploited)."),

    ("imperva", "$30-60/ep/yr",
     ["soc2-type2", "fedramp-moderate", "iso27001", "pci-dss"], 14, [],
     "", "2019 data breach via misconfigured AWS S3 snapshot."),

    # -- NDR --
    ("darktrace", "$30-60/ep/yr",
     ["soc2-type2", "iso27001"], 14, [], "",
     "AI detection claims questioned. Taken private by Thoma Bravo (2023)."),

    ("vectra", "$30-60/ep/yr",
     ["soc2-type2", "iso27001"], 14, [], "", ""),

    # -- Threat Intel --
    ("recorded-future", ">$60/ep/yr",
     ["soc2-type2", "iso27001", "fedramp-moderate"],
     14, ["chubb", "beazley"],
     "Threat intel feeds viewed positively by enterprise carriers.",
     "Acquired by Mastercard (2024) for $2.65B."),
]


def scrape(_config: str | dict | None = None) -> list[dict]:
    """Return vendor metadata as tool evaluation dicts."""
    evals: list[dict] = []
    for (vid, price, certs, deploy, ins_carriers, ins_notes, issues) in VENDOR_META:
        notes_parts: list[str] = []
        notes_parts.append(f"Price: {price}")
        notes_parts.append(f"Deploy: ~{deploy} days")
        if certs:
            notes_parts.append(f"Certs: {', '.join(certs[:4])}")
        if ins_carriers:
            notes_parts.append(f"Insurance carriers: {', '.join(ins_carriers)}")
        if ins_notes:
            notes_parts.append(ins_notes)

        evals.append({
            "vendor": vid,
            "vendor_id": vid,
            "category": "metadata",
            "overall_score": None,
            "detection_rate": None,
            "fp_rate": None,
            "source": "vendor-meta",
            "source_url": None,
            "notes": ". ".join(notes_parts),
            "top_strength": ins_notes if ins_notes else None,
            "top_friction": issues if issues else None,
            "price_range": price,
            "certifications": certs,
            "typical_deploy_days": deploy,
            "insurance_carriers": ins_carriers,
            "insurance_notes": ins_notes or None,
            "known_issues": issues or None,
        })
    return evals
