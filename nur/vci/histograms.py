"""
Secure Histograms — technique frequency and vendor detection rates via SecAgg.

Every contributor has a local copy of the MITRE technique table (~200 techniques
for MVP). To contribute "my CrowdStrike detected T1566":

1. Create a binary vector: [0, 0, ..., 1, ..., 0] where position for T1566 = 1
2. Split each position into SecAgg shares
3. Server sums all position vectors across contributors
4. Result: [count_T1001, count_T1002, ..., count_T1566=47, ...]

Server sees random shares per position. After summing: technique frequency histogram.

For vendor-specific detection rates:
The vector encodes (technique, vendor, detected?) triples.
With 200 techniques x 36 vendors x 2 states = 14,400 positions.
Still just addition. Performance: sub-second for 100 contributors.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..secagg import split, aggregate


# ══════════════════════════════════════════════════════════════════════════════
# Public lookup tables — these are PUBLIC data, no crypto needed.
# The crypto protects the MAPPING: which org saw which technique detected
# by which vendor. The names themselves are public knowledge.
# ══════════════════════════════════════════════════════════════════════════════

TECHNIQUE_TABLE: list[str] = [
    # Initial Access
    "T1189", "T1190", "T1133", "T1200", "T1566", "T1566.001", "T1566.002",
    "T1566.003", "T1078", "T1195", "T1195.001", "T1195.002",
    # Execution
    "T1059", "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007",
    "T1203", "T1047", "T1053", "T1053.005", "T1204", "T1204.001", "T1204.002",
    "T1569", "T1569.002",
    # Persistence
    "T1547", "T1547.001", "T1136", "T1136.001", "T1543", "T1543.003",
    "T1546", "T1546.001", "T1546.003", "T1546.015", "T1053.005",
    "T1505", "T1505.003", "T1078.001", "T1078.003",
    # Privilege Escalation
    "T1548", "T1548.002", "T1134", "T1134.001", "T1068", "T1055",
    "T1055.001", "T1055.012", "T1574", "T1574.001", "T1574.002",
    # Defense Evasion
    "T1140", "T1070", "T1070.001", "T1070.004", "T1036", "T1036.005",
    "T1027", "T1027.002", "T1218", "T1218.011", "T1562", "T1562.001",
    "T1112", "T1497", "T1497.001", "T1620",
    # Credential Access
    "T1110", "T1110.001", "T1110.003", "T1003", "T1003.001", "T1003.006",
    "T1555", "T1555.003", "T1056", "T1056.001", "T1557", "T1558",
    "T1558.003", "T1552", "T1552.001",
    # Discovery
    "T1087", "T1087.002", "T1482", "T1083", "T1135", "T1046", "T1057",
    "T1018", "T1518", "T1082", "T1016", "T1049", "T1033", "T1007",
    # Lateral Movement
    "T1021", "T1021.001", "T1021.002", "T1021.003", "T1021.004",
    "T1021.006", "T1091", "T1570", "T1563",
    # Collection
    "T1560", "T1560.001", "T1005", "T1039", "T1025", "T1074",
    "T1074.001", "T1113", "T1115", "T1119",
    # Command and Control
    "T1071", "T1071.001", "T1071.004", "T1132", "T1573", "T1573.001",
    "T1573.002", "T1008", "T1105", "T1095", "T1572", "T1090",
    "T1090.002", "T1219", "T1102",
    # Exfiltration
    "T1041", "T1048", "T1048.003", "T1567", "T1567.002", "T1029", "T1030",
    # Impact
    "T1485", "T1486", "T1490", "T1489", "T1498", "T1496", "T1565",
    "T1565.001", "T1529",
]

VENDOR_TABLE: list[str] = [
    "crowdstrike", "sentinelone", "microsoft-defender", "palo-alto",
    "trellix", "cybereason", "vmware-cb", "sophos", "trend-micro",
    "elastic", "splunk", "qradar", "sentinel", "chronicle",
    "sumo-logic", "datadog", "wiz", "orca", "lacework", "prisma-cloud",
    "snyk", "aqua", "zscaler", "netskope", "cloudflare", "fortinet",
    "checkpoint", "cisco", "okta", "ping-identity", "cyberark",
    "sailpoint", "proofpoint", "mimecast", "abnormal", "darktrace",
]


# ══════════════════════════════════════════════════════════════════════════════
# Histogram encoding / decoding
# ══════════════════════════════════════════════════════════════════════════════

class HistogramEncoder:
    """Encode/decode contribution data as position vectors for SecAgg."""

    def __init__(
        self,
        technique_table: list[str] | None = None,
        vendor_table: list[str] | None = None,
    ):
        self.techniques = technique_table or TECHNIQUE_TABLE
        self.vendors = vendor_table or VENDOR_TABLE
        self._tech_idx = {t: i for i, t in enumerate(self.techniques)}
        self._vendor_idx = {v: i for i, v in enumerate(self.vendors)}

    @property
    def technique_vector_size(self) -> int:
        return len(self.techniques)

    @property
    def vendor_detection_vector_size(self) -> int:
        return len(self.techniques) * len(self.vendors) * 2

    def technique_index(self, technique_id: str) -> int | None:
        """Get the position of a technique in the table."""
        return self._tech_idx.get(technique_id)

    def vendor_index(self, vendor_slug: str) -> int | None:
        """Get the position of a vendor in the table."""
        return self._vendor_idx.get(vendor_slug.lower())

    def encode_technique_vector(self, detected_techniques: list[str]) -> list[int]:
        """
        Create a binary vector with 1 at each detected technique position.
        Length = len(technique_table).
        """
        vec = [0] * len(self.techniques)
        for tid in detected_techniques:
            idx = self.technique_index(tid)
            if idx is not None:
                vec[idx] = 1
        return vec

    def encode_vendor_detection_vector(
        self, detections: list[tuple[str, str, bool]]
    ) -> list[int]:
        """
        Encode (technique_id, vendor_slug, detected_bool) triples into a flat vector.

        Position = tech_idx * len(vendors) * 2 + vendor_idx * 2 + (1 if detected else 0)
        """
        n_vendors = len(self.vendors)
        vec = [0] * self.vendor_detection_vector_size
        for tech_id, vendor, detected in detections:
            t_idx = self.technique_index(tech_id)
            v_idx = self.vendor_index(vendor)
            if t_idx is None or v_idx is None:
                continue
            pos = t_idx * n_vendors * 2 + v_idx * 2 + (1 if detected else 0)
            vec[pos] = 1
        return vec

    def decode_technique_histogram(
        self, summed_vector: list[float]
    ) -> dict[str, int]:
        """Map summed position vector back to {technique_id: count}."""
        result = {}
        for i, count in enumerate(summed_vector):
            if i < len(self.techniques) and count > 0.5:  # threshold for floating-point
                result[self.techniques[i]] = int(round(count))
        return result

    def decode_vendor_detection_histogram(
        self, summed_vector: list[float]
    ) -> dict[str, dict[str, dict[str, int]]]:
        """
        Map summed vendor detection vector to:
        {technique_id: {vendor: {"detected": count, "missed": count}}}
        """
        n_vendors = len(self.vendors)
        result: dict[str, dict[str, dict[str, int]]] = {}

        for t_idx, tech_id in enumerate(self.techniques):
            for v_idx, vendor in enumerate(self.vendors):
                detected_pos = t_idx * n_vendors * 2 + v_idx * 2 + 1
                missed_pos = t_idx * n_vendors * 2 + v_idx * 2
                d_count = int(round(summed_vector[detected_pos])) if detected_pos < len(summed_vector) else 0
                m_count = int(round(summed_vector[missed_pos])) if missed_pos < len(summed_vector) else 0

                if d_count > 0 or m_count > 0:
                    if tech_id not in result:
                        result[tech_id] = {}
                    result[tech_id][vendor] = {
                        "detected": d_count,
                        "missed": m_count,
                    }
        return result


# ══════════════════════════════════════════════════════════════════════════════
# Secure histogram session
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecureHistogramSession:
    """
    Secure histogram aggregation session.

    Each contributor encodes their data as a position vector, splits it
    into SecAgg shares, and submits. The server sums shares to produce
    the histogram — without seeing any individual contributor's vector.
    """
    session_id: str
    n_parties: int
    histogram_type: str = "technique"  # "technique" or "vendor_detection"
    encoder: HistogramEncoder = field(default_factory=HistogramEncoder)
    enrolled: list[str] = field(default_factory=list)
    shares_received: dict[str, list[float]] = field(default_factory=dict)
    _result: dict | None = field(default=None, repr=False)

    @property
    def vector_size(self) -> int:
        if self.histogram_type == "vendor_detection":
            return self.encoder.vendor_detection_vector_size
        return self.encoder.technique_vector_size

    def submit_vector(
        self, party_id: str, vector: list[int]
    ) -> list[list[float]]:
        """
        Split a binary vector into SecAgg shares.
        Returns share vectors (one per party) to be distributed.
        """
        if party_id not in self.enrolled:
            self.enrolled.append(party_id)

        # Split each position into additive shares
        n = self.n_parties
        share_vectors: list[list[float]] = [[] for _ in range(n)]

        for val in vector:
            shares = split(float(val), n)
            for p_idx, s in enumerate(shares):
                share_vectors[p_idx].append(s)

        return share_vectors

    def submit_shares(self, party_id: str, shares: list[float]) -> bool:
        """Submit aggregated shares from a party. Returns True when all received."""
        self.shares_received[party_id] = shares
        return len(self.shares_received) >= self.n_parties

    def compute_result(self) -> dict:
        """Sum all shares and decode the histogram."""
        if len(self.shares_received) < self.n_parties:
            raise ValueError(
                f"Need {self.n_parties} submissions, have {len(self.shares_received)}"
            )
        all_shares = list(self.shares_received.values())
        summed = aggregate(all_shares)

        if self.histogram_type == "vendor_detection":
            self._result = self.encoder.decode_vendor_detection_histogram(summed)
        else:
            self._result = self.encoder.decode_technique_histogram(summed)
        return self._result

    @property
    def result(self) -> dict | None:
        return self._result

    @property
    def is_ready(self) -> bool:
        return len(self.shares_received) >= self.n_parties


# ══════════════════════════════════════════════════════════════════════════════
# Convenience helpers
# ══════════════════════════════════════════════════════════════════════════════

def build_technique_vector(
    techniques: list,
    encoder: HistogramEncoder | None = None,
) -> list[int]:
    """
    Build a technique frequency vector from ObservedTechnique model objects.

    Each technique that was observed (observed=True) gets a 1 in its position.
    """
    enc = encoder or HistogramEncoder()
    tech_ids = []
    for t in techniques:
        tid = t.technique_id if hasattr(t, "technique_id") else t.get("technique_id", "")
        observed = t.observed if hasattr(t, "observed") else t.get("observed", True)
        if tid and observed:
            tech_ids.append(tid)
    return enc.encode_technique_vector(tech_ids)


def build_vendor_detection_vector(
    techniques: list,
    encoder: HistogramEncoder | None = None,
) -> list[int]:
    """
    Build a vendor detection vector from ObservedTechnique model objects.

    Encodes (technique, vendor, detected?) triples for all detected_by/missed_by entries.
    """
    enc = encoder or HistogramEncoder()
    detections = []
    for t in techniques:
        tid = t.technique_id if hasattr(t, "technique_id") else t.get("technique_id", "")
        if not tid:
            continue
        detected_by = t.detected_by if hasattr(t, "detected_by") else t.get("detected_by", [])
        missed_by = t.missed_by if hasattr(t, "missed_by") else t.get("missed_by", [])
        for vendor in detected_by:
            detections.append((tid, vendor.lower().replace(" ", "-"), True))
        for vendor in missed_by:
            detections.append((tid, vendor.lower().replace(" ", "-"), False))
    return enc.encode_vendor_detection_vector(detections)


def compute_detection_rate(
    histogram: dict[str, dict[str, dict[str, int]]],
    vendor: str,
) -> float:
    """Compute overall detection rate for a vendor from a vendor detection histogram."""
    vendor_lower = vendor.lower().replace(" ", "-")
    total_detected = 0
    total_evaluated = 0
    for tech_id, vendors in histogram.items():
        vdata = vendors.get(vendor_lower, {})
        d = vdata.get("detected", 0)
        m = vdata.get("missed", 0)
        if d + m > 0:
            total_detected += d
            total_evaluated += d + m
    if total_evaluated == 0:
        return 0.0
    return total_detected / total_evaluated


__all__ = [
    "TECHNIQUE_TABLE",
    "VENDOR_TABLE",
    "HistogramEncoder",
    "SecureHistogramSession",
    "build_technique_vector",
    "build_vendor_detection_vector",
    "compute_detection_rate",
]
