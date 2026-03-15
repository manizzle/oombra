"""
Demo data generator for vigil — realistic threat intel for demos and testing.

Sources modeled after real public feeds:
  - CISA Known Exploited Vulnerabilities (KEV)
  - MITRE ATT&CK techniques
  - AlienVault OTX pulse IOCs
  - Abuse.ch URLhaus / ThreatFox
  - Common vendor evaluation patterns

Usage:
    python -m vigil.tests.demo_data --output demo/
    # Generates JSON files ready for `vigil upload` or `vigil preview`
"""
from __future__ import annotations

import json
import os
import random
from pathlib import Path

# ── Realistic vendor evaluations ─────────────────────────────────────────────

EVAL_RECORDS = [
    {
        "vendor": "CrowdStrike",
        "category": "edr",
        "overall_score": 9.2,
        "detection_rate": 98.5,
        "fp_rate": 0.8,
        "deploy_days": 3,
        "cpu_overhead": 2.1,
        "ttfv_hours": 4.0,
        "would_buy": True,
        "top_strength": "Exceptional real-time detection with minimal endpoint impact",
        "top_friction": "Pricing can be prohibitive for smaller orgs",
        "notes": "Evaluated across 500 endpoints in our manufacturing environment. "
                 "Caught 3 zero-days that other tools missed during our 90-day eval.",
        "context": {"industry": "manufacturing", "org_size": "1000-5000", "role": "ciso"},
    },
    {
        "vendor": "SentinelOne",
        "category": "edr",
        "overall_score": 8.8,
        "detection_rate": 97.2,
        "fp_rate": 1.5,
        "deploy_days": 2,
        "cpu_overhead": 1.8,
        "would_buy": True,
        "top_strength": "Autonomous response and rollback capabilities are game-changing",
        "top_friction": "Console can be overwhelming for junior analysts",
        "context": {"industry": "financial", "org_size": "5000-10000", "role": "security-director"},
    },
    {
        "vendor": "Splunk",
        "category": "siem",
        "overall_score": 7.5,
        "detection_rate": 85.0,
        "fp_rate": 5.2,
        "deploy_days": 30,
        "would_buy": True,
        "top_strength": "Unmatched search and correlation capabilities across log sources",
        "top_friction": "License costs scale painfully with data volume",
        "notes": "Running Splunk Cloud with 2TB/day ingest. Detection rules need constant tuning.",
        "context": {"industry": "tech", "org_size": "500-1000", "role": "security-engineer"},
    },
    {
        "vendor": "Wiz",
        "category": "cnapp",
        "overall_score": 9.0,
        "detection_rate": 94.0,
        "fp_rate": 3.0,
        "deploy_days": 1,
        "would_buy": True,
        "top_strength": "Agentless scanning found critical misconfigs in first hour",
        "top_friction": "Runtime protection still maturing compared to established players",
        "context": {"industry": "tech", "org_size": "100-500", "role": "security-engineer"},
    },
    {
        "vendor": "Palo Alto Prisma Cloud",
        "category": "cnapp",
        "overall_score": 7.8,
        "detection_rate": 89.0,
        "fp_rate": 4.5,
        "deploy_days": 14,
        "would_buy": False,
        "top_strength": "Comprehensive coverage across cloud, containers, and code",
        "top_friction": "Too many modules to manage, UI feels fragmented across acquisitions",
        "context": {"industry": "financial", "org_size": "10000+", "role": "security-director"},
    },
]

# ── MITRE ATT&CK attack maps ────────────────────────────────────────────────

ATTACK_MAPS = [
    {
        "threat_name": "APT28 (Fancy Bear) - Credential Harvesting Campaign",
        "techniques": [
            {
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "tactic": "initial-access",
                "observed": True,
                "detected_by": ["crowdstrike", "proofpoint"],
                "missed_by": ["splunk"],
                "notes": "Weaponized Word doc with macro targeting HR department",
            },
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "execution",
                "observed": True,
                "detected_by": ["crowdstrike", "sentinelone"],
                "missed_by": [],
            },
            {
                "technique_id": "T1003.001",
                "technique_name": "LSASS Memory",
                "tactic": "credential-access",
                "observed": True,
                "detected_by": ["crowdstrike"],
                "missed_by": ["sentinelone"],
                "notes": "Modified Mimikatz variant evaded signature-based detection",
            },
            {
                "technique_id": "T1021.001",
                "technique_name": "Remote Desktop Protocol",
                "tactic": "lateral-movement",
                "observed": True,
                "detected_by": [],
                "missed_by": ["crowdstrike", "sentinelone"],
                "notes": "Used stolen creds for RDP — looked like legit admin activity",
            },
            {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration",
                "observed": True,
                "detected_by": ["palo-alto-firewall"],
                "missed_by": ["crowdstrike"],
            },
        ],
        "tools_in_scope": ["crowdstrike", "sentinelone", "splunk", "proofpoint", "palo-alto-firewall"],
        "source": "incident",
        "notes": "Real incident response from Q4 2025. Attacker dwelled for 11 days before detection.",
        "context": {"industry": "government", "org_size": "5000-10000", "role": "security-analyst"},
    },
    {
        "threat_name": "LockBit 3.0 Ransomware Simulation",
        "techniques": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "initial-access",
                "observed": False,
                "detected_by": ["palo-alto-firewall"],
                "missed_by": [],
            },
            {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "impact",
                "observed": False,
                "detected_by": ["crowdstrike", "sentinelone"],
                "missed_by": [],
            },
            {
                "technique_id": "T1490",
                "technique_name": "Inhibit System Recovery",
                "tactic": "impact",
                "observed": False,
                "detected_by": ["sentinelone"],
                "missed_by": ["crowdstrike"],
                "notes": "VSS deletion caught by behavioral analysis only",
            },
        ],
        "tools_in_scope": ["crowdstrike", "sentinelone", "palo-alto-firewall"],
        "source": "simulation",
        "context": {"industry": "healthcare", "org_size": "1000-5000", "role": "security-engineer"},
    },
]

# ── IOC bundles (modeled after real public feeds) ────────────────────────────

IOC_BUNDLES = [
    {
        "iocs": [
            # Based on common Cobalt Strike C2 indicators
            {"ioc_type": "domain", "value_raw": "update-service-cdn.com",
             "detected_by": ["crowdstrike"], "missed_by": ["sentinelone"],
             "threat_actor": "APT28", "campaign": "Q4-2025-credential-harvest"},
            {"ioc_type": "domain", "value_raw": "secure-login-verify.net",
             "detected_by": ["crowdstrike", "palo-alto"], "missed_by": [],
             "threat_actor": "APT28", "campaign": "Q4-2025-credential-harvest"},
            {"ioc_type": "ip", "value_raw": "185.220.101.42",
             "detected_by": ["palo-alto"], "missed_by": ["crowdstrike"],
             "threat_actor": "APT28"},
            {"ioc_type": "ip", "value_raw": "91.234.56.78",
             "detected_by": [], "missed_by": ["crowdstrike", "sentinelone"],
             "threat_actor": "APT28"},
            {"ioc_type": "hash-sha256",
             "value_raw": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "detected_by": ["crowdstrike", "sentinelone"],
             "threat_actor": "APT28"},
            {"ioc_type": "url", "value_raw": "https://update-service-cdn.com/payload/stage2.exe",
             "detected_by": ["proofpoint"], "missed_by": [],
             "campaign": "Q4-2025-credential-harvest"},
        ],
        "tools_in_scope": ["crowdstrike", "sentinelone", "palo-alto", "proofpoint"],
        "source": "incident",
        "notes": "IOCs extracted from APT28 incident. C2 infrastructure used Cobalt Strike.",
        "context": {"industry": "government", "org_size": "5000-10000"},
    },
    {
        "iocs": [
            # Based on common ransomware IOCs from ThreatFox/URLhaus
            {"ioc_type": "domain", "value_raw": "lockbit-decryptor.onion.ws",
             "detected_by": ["palo-alto"], "threat_actor": "LockBit"},
            {"ioc_type": "hash-sha256",
             "value_raw": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
             "detected_by": ["crowdstrike", "sentinelone"],
             "threat_actor": "LockBit", "campaign": "lockbit-3.0-healthcare"},
            {"ioc_type": "ip", "value_raw": "45.33.32.156",
             "detected_by": ["palo-alto"], "missed_by": [],
             "threat_actor": "LockBit"},
            {"ioc_type": "email", "value_raw": "lockbit-support@protonmail.com",
             "detected_by": [], "missed_by": [],
             "threat_actor": "LockBit"},
        ],
        "tools_in_scope": ["crowdstrike", "sentinelone", "palo-alto"],
        "source": "threat-hunt",
        "notes": "IOCs from proactive threat hunt based on LockBit 3.0 TTPs.",
        "context": {"industry": "healthcare", "org_size": "1000-5000"},
    },
]

# ── STIX 2.1 bundle (realistic format) ──────────────────────────────────────

STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--vigil-demo-001",
    "objects": [
        {
            "type": "threat-actor",
            "id": "threat-actor--apt28",
            "name": "APT28",
            "description": "Russian state-sponsored threat group",
            "threat_actor_types": ["nation-state"],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1566-001",
            "name": "Spearphishing Attachment",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059-001",
            "name": "PowerShell",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        },
        {
            "type": "indicator",
            "id": "indicator--malicious-domain-1",
            "name": "APT28 C2 Domain",
            "pattern": "[domain-name:value = 'update-service-cdn.com']",
            "pattern_type": "stix",
            "valid_from": "2025-10-01T00:00:00Z",
        },
        {
            "type": "indicator",
            "id": "indicator--malicious-ip-1",
            "name": "APT28 C2 IP",
            "pattern": "[ipv4-addr:value = '185.220.101.42']",
            "pattern_type": "stix",
            "valid_from": "2025-10-01T00:00:00Z",
        },
    ],
}


def generate_demo_files(output_dir: str = "demo") -> list[str]:
    """Generate demo data files for testing and demos."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = []

    # Vendor evaluations
    for i, ev in enumerate(EVAL_RECORDS):
        path = out / f"eval_{ev['vendor'].lower().replace(' ', '_')}.json"
        path.write_text(json.dumps(ev, indent=2))
        files.append(str(path))

    # All evaluations as array
    path = out / "all_evaluations.json"
    path.write_text(json.dumps(EVAL_RECORDS, indent=2))
    files.append(str(path))

    # Attack maps
    for i, am in enumerate(ATTACK_MAPS):
        slug = am["threat_name"].split(" ")[0].lower()
        path = out / f"attack_map_{slug}.json"
        path.write_text(json.dumps(am, indent=2))
        files.append(str(path))

    # IOC bundles
    for i, bundle in enumerate(IOC_BUNDLES):
        path = out / f"ioc_bundle_{i+1}.json"
        path.write_text(json.dumps(bundle, indent=2))
        files.append(str(path))

    # STIX bundle
    path = out / "apt28_campaign.stix.json"
    path.write_text(json.dumps(STIX_BUNDLE, indent=2))
    files.append(str(path))

    # CSV evaluation data
    csv_lines = ["vendor,category,overall_score,detection_rate,fp_rate,deploy_days,would_buy"]
    for ev in EVAL_RECORDS:
        csv_lines.append(
            f"{ev['vendor']},{ev['category']},{ev['overall_score']},"
            f"{ev.get('detection_rate', '')},{ev.get('fp_rate', '')},"
            f"{ev.get('deploy_days', '')},{ev.get('would_buy', '')}"
        )
    path = out / "evaluations.csv"
    path.write_text("\n".join(csv_lines))
    files.append(str(path))

    # Text evaluation (plain text format)
    text = """
Security Tool Evaluation Report - Q1 2026

Vendor: CrowdStrike
Category: EDR
Score: 9.2
Detection Rate: 98.5%
Deploy Days: 3

Tested across 500 endpoints in manufacturing environment.
Exceptional real-time detection with minimal performance impact.
Caught 3 zero-days during 90-day evaluation period.
Pricing prohibitive for organizations under 1000 employees.
"""
    path = out / "eval_report.txt"
    path.write_text(text)
    files.append(str(path))

    return files


if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "demo"
    files = generate_demo_files(output)
    print(f"Generated {len(files)} demo files in {output}/:")
    for f in files:
        print(f"  {f}")
