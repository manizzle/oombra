"""
Industry vertical configurations.

Each vertical defines:
  - Relevant threat actors and campaigns
  - Priority MITRE ATT&CK techniques
  - Industry-specific action templates
  - Feed priorities

Usage:
    from vigil.verticals import get_vertical, VERTICALS
    v = get_vertical("healthcare")
    v.threat_actors   # ["LockBit", "BlackCat", "Clop", ...]
    v.priority_techniques  # ["T1486", "T1490", ...]
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vertical:
    name: str
    display_name: str
    description: str
    threat_actors: list[str]
    campaigns: list[str]
    priority_techniques: list[dict]  # [{id, name, why}]
    compliance: list[str]  # regulatory frameworks
    action_templates: list[dict]  # industry-specific recommended actions
    feed_priority: list[str]  # which feeds matter most


VERTICALS: dict[str, Vertical] = {
    "healthcare": Vertical(
        name="healthcare",
        display_name="Healthcare & Life Sciences",
        description="Hospitals, clinics, pharma, medical devices, EHR systems",
        threat_actors=[
            "LockBit", "BlackCat/ALPHV", "Clop", "Royal", "Hive",
            "Rhysida", "Black Basta", "Vice Society",
        ],
        campaigns=[
            "lockbit-3.0-healthcare", "blackcat-healthcare-2024",
            "clop-moveit-healthcare", "rhysida-hospital-campaign",
        ],
        priority_techniques=[
            {"id": "T1486", "name": "Data Encrypted for Impact",
             "why": "Ransomware encrypting EHR/PACS systems — direct patient safety risk"},
            {"id": "T1490", "name": "Inhibit System Recovery",
             "why": "VSS deletion prevents rollback — extends downtime for critical care systems"},
            {"id": "T1566.001", "name": "Spearphishing Attachment",
             "why": "Primary initial access vector for healthcare ransomware campaigns"},
            {"id": "T1021.001", "name": "Remote Desktop Protocol",
             "why": "Lateral movement across hospital networks — often flat networks"},
            {"id": "T1059.001", "name": "PowerShell",
             "why": "Execution of ransomware payloads and reconnaissance scripts"},
            {"id": "T1070.001", "name": "Clear Windows Event Logs",
             "why": "Anti-forensics — delays incident response during critical care disruption"},
            {"id": "T1562.001", "name": "Disable or Modify Tools",
             "why": "EDR/AV tampering before encryption — common in healthcare ransomware"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
             "why": "PHI exfiltration for double extortion — HIPAA breach notification trigger"},
        ],
        compliance=["HIPAA", "HITECH", "FDA 21 CFR Part 11", "NIST CSF"],
        action_templates=[
            {"priority": "critical", "action": "Isolate affected EHR/PACS segments",
             "detail": "Prevent lateral movement to clinical systems. Prioritize NICU, OR, and ED network segments."},
            {"priority": "critical", "action": "Activate downtime procedures",
             "detail": "Switch to paper-based workflows for medication administration and patient tracking."},
            {"priority": "high", "action": "Notify HHS within 72 hours if PHI is involved",
             "detail": "HIPAA Breach Notification Rule requires reporting to HHS for breaches affecting 500+ individuals."},
            {"priority": "high", "action": "Preserve forensic evidence for law enforcement",
             "detail": "FBI and CISA have active healthcare ransomware task forces. Contact IC3.gov."},
        ],
        feed_priority=["threatfox", "feodo", "cisa-kev", "bazaar"],
    ),

    "financial": Vertical(
        name="financial",
        display_name="Financial Services & Banking",
        description="Banks, insurance, fintech, trading, payment processors",
        threat_actors=[
            "APT28/Fancy Bear", "APT38/Lazarus", "FIN7", "FIN11",
            "Carbanak", "Cobalt Group", "TA505", "Evil Corp",
        ],
        campaigns=[
            "apt28-credential-harvest", "lazarus-swift-banking",
            "fin7-pos-campaign", "ta505-clop-extortion",
        ],
        priority_techniques=[
            {"id": "T1566.001", "name": "Spearphishing Attachment",
             "why": "Primary vector for BEC and credential harvesting targeting financial staff"},
            {"id": "T1003.001", "name": "LSASS Memory",
             "why": "Credential dumping for lateral movement to trading/SWIFT systems"},
            {"id": "T1055", "name": "Process Injection",
             "why": "Used by banking trojans to hook browser processes for credential theft"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
             "why": "Data exfiltration of PII/financial records for fraud or extortion"},
            {"id": "T1059.001", "name": "PowerShell",
             "why": "Fileless malware execution — evades endpoint controls common in financial environments"},
            {"id": "T1021.001", "name": "Remote Desktop Protocol",
             "why": "Lateral movement to high-value targets (SWIFT terminals, treasury systems)"},
            {"id": "T1486", "name": "Data Encrypted for Impact",
             "why": "Ransomware targeting financial operations — immediate revenue impact"},
            {"id": "T1053.005", "name": "Scheduled Task",
             "why": "Persistence mechanism for long-term access to trading infrastructure"},
        ],
        compliance=["PCI DSS", "SOX", "GLBA", "FFIEC", "DORA", "NIST CSF"],
        action_templates=[
            {"priority": "critical", "action": "Isolate SWIFT/payment processing systems",
             "detail": "Prevent unauthorized transactions. Coordinate with correspondent banks."},
            {"priority": "critical", "action": "Freeze suspicious accounts and transactions",
             "detail": "Work with fraud team to identify and reverse unauthorized transfers."},
            {"priority": "high", "action": "File SAR with FinCEN within 30 days",
             "detail": "Suspicious Activity Report required for cyber incidents involving financial transactions."},
            {"priority": "high", "action": "Notify regulators (OCC/FDIC/state) per GLBA",
             "detail": "Financial institutions must notify primary federal regulator within 36 hours of a cyber incident."},
        ],
        feed_priority=["threatfox", "feodo", "bazaar", "cisa-kev"],
    ),

    "energy": Vertical(
        name="energy",
        display_name="Energy & Utilities (ICS/OT)",
        description="Power grids, oil & gas, water treatment, nuclear, renewables",
        threat_actors=[
            "Sandworm", "Volt Typhoon", "XENOTIME", "KAMACITE",
            "ELECTRUM", "Dragonfly/Energetic Bear", "Triton/TRISIS",
        ],
        campaigns=[
            "sandworm-ukraine-grid", "volt-typhoon-critical-infrastructure",
            "xenotime-safety-systems", "dragonfly-energy-sector",
        ],
        priority_techniques=[
            {"id": "T0855", "name": "Unauthorized Command Message (ICS)",
             "why": "Direct manipulation of industrial control systems — safety risk"},
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "why": "Internet-exposed HMI/SCADA interfaces are primary entry points"},
            {"id": "T1059.001", "name": "PowerShell",
             "why": "Used in IT/OT pivot — attackers move from corporate to control networks"},
            {"id": "T1021.001", "name": "Remote Desktop Protocol",
             "why": "RDP to engineering workstations that bridge IT and OT networks"},
            {"id": "T1486", "name": "Data Encrypted for Impact",
             "why": "Ransomware hitting operational technology — pipeline shutdowns, grid disruption"},
            {"id": "T1562.001", "name": "Disable or Modify Tools",
             "why": "Disabling safety instrumented systems (SIS) — physical danger"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
             "why": "Exfiltration of grid topology, SCADA configs, or operational data"},
            {"id": "T1070.001", "name": "Clear Windows Event Logs",
             "why": "Anti-forensics on engineering workstations — delays ICS incident response"},
        ],
        compliance=["NERC CIP", "TSA Security Directives", "IEC 62443", "NIST SP 800-82"],
        action_templates=[
            {"priority": "critical", "action": "Isolate IT/OT boundary immediately",
             "detail": "Sever connections between corporate network and control systems. Use out-of-band communication."},
            {"priority": "critical", "action": "Verify safety instrumented systems (SIS) integrity",
             "detail": "TRITON/TRISIS targeted SIS directly. Confirm safety controllers are in known-good state."},
            {"priority": "high", "action": "Report to CISA ICS-CERT within 24 hours",
             "detail": "Critical infrastructure incidents require reporting per TSA Security Directives."},
            {"priority": "high", "action": "Activate manual override for critical processes",
             "detail": "Switch to manual control for generation, transmission, or distribution systems."},
        ],
        feed_priority=["cisa-kev", "threatfox", "feodo", "bazaar"],
    ),

    "government": Vertical(
        name="government",
        display_name="Government & Defense",
        description="Federal, state, local government, military, intelligence",
        threat_actors=[
            "APT28/Fancy Bear", "APT29/Cozy Bear", "APT41",
            "Volt Typhoon", "Sandworm", "Kimsuky", "Charming Kitten",
        ],
        campaigns=[
            "solarwinds-supply-chain", "volt-typhoon-lotl",
            "apt29-diplomatic-phishing", "apt41-supply-chain",
        ],
        priority_techniques=[
            {"id": "T1195.002", "name": "Supply Chain Compromise: Software Supply Chain",
             "why": "SolarWinds-style attacks targeting government software vendors"},
            {"id": "T1566.001", "name": "Spearphishing Attachment",
             "why": "Targeted phishing of government officials and contractors"},
            {"id": "T1003.001", "name": "LSASS Memory",
             "why": "Credential harvesting for persistent access to classified networks"},
            {"id": "T1059.001", "name": "PowerShell",
             "why": "Living-off-the-land techniques to evade government endpoint detection"},
            {"id": "T1021.001", "name": "Remote Desktop Protocol",
             "why": "Lateral movement across government agency networks"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
             "why": "Exfiltration of classified or sensitive government data"},
            {"id": "T1055", "name": "Process Injection",
             "why": "Evasion of government-mandated endpoint security (EDR/HBSS)"},
            {"id": "T1070.001", "name": "Clear Windows Event Logs",
             "why": "Anti-forensics — delays detection in already-compromised networks"},
        ],
        compliance=["FedRAMP", "FISMA", "NIST 800-53", "CMMC", "CISA BOD"],
        action_templates=[
            {"priority": "critical", "action": "Notify CISA and agency SOC immediately",
             "detail": "Federal agencies must report incidents to CISA within 72 hours per FISMA."},
            {"priority": "critical", "action": "Isolate affected systems and preserve evidence",
             "detail": "Chain of custody for potential law enforcement or counterintelligence investigation."},
            {"priority": "high", "action": "Check for supply chain compromise indicators",
             "detail": "Review software update mechanisms, third-party integrations, and vendor access."},
            {"priority": "high", "action": "Activate COOP/continuity plans if operational impact",
             "detail": "Continuity of Operations Plan activation for mission-critical system disruption."},
        ],
        feed_priority=["cisa-kev", "threatfox", "feodo", "bazaar"],
    ),
}


def get_vertical(name: str) -> Vertical:
    """Get a vertical config by name. Raises ValueError if unknown."""
    if name not in VERTICALS:
        available = ", ".join(VERTICALS.keys())
        raise ValueError(f"Unknown vertical: {name!r}. Available: {available}")
    return VERTICALS[name]


def list_verticals() -> list[dict]:
    """List all available verticals."""
    return [
        {"name": v.name, "display_name": v.display_name, "description": v.description}
        for v in VERTICALS.values()
    ]
