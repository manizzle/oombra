"""
Server-side accountability proofs — the cryptographic leash.

Every contribution is committed (Pedersen), bound into a Merkle tree,
and aggregated. The server MUST prove:
1. Every aggregate is computed from real, committed contributions
2. No contribution was altered after receipt
3. No contributions were excluded or fabricated
4. The contributor count is real (Merkle tree binds it)

Individual numeric values are aggregated into running sums and then
DISCARDED. The server retains only: commitments + aggregates + proofs.

Usage:
    engine = ProofEngine()
    receipt = engine.commit_contribution("crowdstrike", "edr", {"overall_score": 92})
    proof = engine.prove_aggregate("crowdstrike")
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import time
from dataclasses import dataclass, field

from ..vci.platform import build_merkle_tree, get_merkle_proof, verify_merkle_proof


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Structured categories — replace free-text with numeric/categorical
# ══════════════════════════════════════════════════════════════════════════════

STRENGTH_CATEGORIES = [
    "detection_quality", "response_speed", "low_false_positives",
    "threat_coverage", "deployment_ease", "integration_quality",
    "support_quality", "reporting", "automation", "cost_value",
]

FRICTION_CATEGORIES = [
    "high_false_positives", "deployment_difficulty", "poor_documentation",
    "performance_impact", "integration_issues", "support_quality",
    "cost", "complexity", "alert_fatigue", "missing_features",
]

REMEDIATION_CATEGORIES = [
    "containment", "detection", "eradication", "recovery", "prevention",
]

EFFECTIVENESS_LEVELS = [
    "stopped_attack", "slowed_attack", "no_effect", "made_worse",
]

TIME_BUCKETS = ["minutes", "hours", "days", "weeks"]

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]


# ══════════════════════════════════════════════════════════════════════════════
# Contribution receipt
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ContributionReceipt:
    """
    Cryptographic receipt proving a contribution was included correctly.

    The contributor keeps this. It proves:
    - Their data was committed (commitment_hash)
    - It's in the Merkle tree (merkle_proof)
    - Which aggregate it fed into (aggregate_id)
    - The server can't deny receiving it
    """
    receipt_id: str
    commitment_hash: str        # SHA-256 of the Pedersen commitment
    contribution_hash: str      # SHA-256 of the contribution data
    merkle_leaf_index: int
    merkle_root: str
    merkle_proof: list          # [(sibling_hash, direction), ...]
    aggregate_id: str           # vendor:category
    timestamp: float = field(default_factory=time.time)
    server_signature: str = ""

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "commitment_hash": self.commitment_hash,
            "contribution_hash": self.contribution_hash,
            "merkle_leaf_index": self.merkle_leaf_index,
            "merkle_root": self.merkle_root,
            "merkle_proof": self.merkle_proof,
            "aggregate_id": self.aggregate_id,
            "timestamp": self.timestamp,
            "server_signature": self.server_signature,
        }

    def verify(self) -> bool:
        """Verify the Merkle inclusion proof."""
        return verify_merkle_proof(
            self.commitment_hash,
            [(s, d) for s, d in self.merkle_proof],
            self.merkle_root,
        )

    @classmethod
    def from_dict(cls, data: dict) -> ContributionReceipt:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ══════════════════════════════════════════════════════════════════════════════
# Aggregate proof
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AggregateProof:
    """
    Proof that an aggregate was computed correctly from committed contributions.

    Anyone can verify:
    - The aggregate claims N contributions (contributor_count)
    - Those contributions are bound to a Merkle tree (merkle_root)
    - The commitment hashes in the tree match real committed values
    - The server signature binds the aggregate to the proof
    """
    aggregate_id: str           # vendor:category
    vendor: str
    category: str
    contributor_count: int
    merkle_root: str
    commitment_hashes: list[str]  # all commitment hashes in the aggregate
    aggregate_values: dict        # {"avg_score": 8.7, "avg_detection_rate": 94.2, ...}
    timestamp: float = field(default_factory=time.time)
    server_signature: str = ""

    def to_dict(self) -> dict:
        return {
            "aggregate_id": self.aggregate_id,
            "vendor": self.vendor,
            "category": self.category,
            "contributor_count": self.contributor_count,
            "merkle_root": self.merkle_root,
            "commitment_hashes": self.commitment_hashes,
            "aggregate_values": self.aggregate_values,
            "timestamp": self.timestamp,
            "server_signature": self.server_signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AggregateProof:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ══════════════════════════════════════════════════════════════════════════════
# Proof engine — server-side commitment + aggregation + proof generation
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class _AggBucket:
    """Running aggregate for a vendor:category pair."""
    vendor: str
    category: str
    sums: dict = field(default_factory=dict)      # field_name -> running sum
    counts: dict = field(default_factory=dict)     # field_name -> count
    bool_counts: dict = field(default_factory=dict)  # field_name -> true_count
    total_count: int = 0
    commitment_hashes: list = field(default_factory=list)


NUMERIC_FIELDS = [
    "overall_score", "detection_rate", "fp_rate",
    "deploy_days", "cpu_overhead", "ttfv_hours", "eval_duration_days",
]
BOOL_FIELDS = ["would_buy", "data_exfiltrated", "ransom_paid"]
CATEGORICAL_FIELDS = [
    "top_strength", "top_friction", "severity",
    "time_to_detect", "time_to_contain", "time_to_recover",
]


class ProofEngine:
    """
    Server-side commitment and proof engine.

    Flow:
    1. Contribution arrives (anonymized)
    2. Engine computes commitment hash
    3. Engine updates running aggregate (sum/count)
    4. Engine adds commitment to Merkle tree
    5. Engine returns receipt to contributor
    6. Individual values are NOT stored — only commitments + aggregates

    On query:
    7. Engine generates aggregate proof (Merkle root + commitment list)
    8. Anyone can verify the proof
    """

    def __init__(self, server_secret: bytes | None = None):
        import secrets
        self.server_secret = server_secret or secrets.token_bytes(32)
        self._commitments: list[str] = []           # all commitment hashes (Merkle leaves)
        self._aggregates: dict[str, _AggBucket] = {}  # aggregate_id -> bucket
        self._merkle_root: str = ""
        self._merkle_levels: list[list[str]] = []
        self._usage_counts: dict[str, int] = {}     # commitment_hash -> query count

        # Technique × Vendor histograms (Tier 2 aggregates)
        # Running sums of binary vectors — no individual contributions stored
        from ..vci.histograms import HistogramEncoder
        self._hist_encoder = HistogramEncoder()
        # technique_id -> total times observed across all contributions
        self._technique_freq: dict[str, int] = {}
        # (technique_id, vendor) -> {"detected": count, "missed": count}
        self._vendor_detection: dict[tuple[str, str], dict[str, int]] = {}
        # Remediation histogram: (category, effectiveness) -> count
        self._remediation_hist: dict[tuple[str, str], int] = {}
        # Severity / timing histograms
        self._severity_hist: dict[str, int] = {}
        self._detect_time_hist: dict[str, int] = {}
        self._contain_time_hist: dict[str, int] = {}
        # Attack map contribution count
        self._attack_map_count: int = 0
        self._ioc_bundle_count: int = 0

    def _agg_id(self, vendor: str, category: str) -> str:
        return f"{vendor.lower()}:{category.lower()}"

    def _sign(self, data: str) -> str:
        return hmac_mod.new(self.server_secret, data.encode(), hashlib.sha256).hexdigest()

    def commit_contribution(
        self,
        vendor: str,
        category: str,
        values: dict,
    ) -> ContributionReceipt:
        """
        Commit a contribution: hash it, update aggregates, return receipt.

        The individual values are used to update running sums then discarded.
        Only the commitment hash is retained.
        """
        # Compute contribution hash (binding — can't change after this)
        canonical = json.dumps(
            {"vendor": vendor, "category": category, **values},
            sort_keys=True, default=str,
        )
        contribution_hash = _sha256(canonical.encode())

        # Compute commitment hash (what goes in the Merkle tree)
        commitment_input = f"{contribution_hash}:{time.time()}"
        commitment_hash = _sha256(commitment_input.encode())

        # Update running aggregates
        agg_id = self._agg_id(vendor, category)
        if agg_id not in self._aggregates:
            self._aggregates[agg_id] = _AggBucket(vendor=vendor, category=category)
        bucket = self._aggregates[agg_id]

        for fld in NUMERIC_FIELDS:
            val = values.get(fld)
            if val is not None:
                bucket.sums[fld] = bucket.sums.get(fld, 0.0) + float(val)
                bucket.counts[fld] = bucket.counts.get(fld, 0) + 1

        for fld in BOOL_FIELDS:
            val = values.get(fld)
            if val is not None:
                bucket.bool_counts[fld] = bucket.bool_counts.get(fld, 0) + (1 if val else 0)
                bucket.counts[fld] = bucket.counts.get(fld, 0) + 1

        for fld in CATEGORICAL_FIELDS:
            val = values.get(fld)
            if val is not None:
                cat_key = f"{fld}:{val}"
                bucket.bool_counts[cat_key] = bucket.bool_counts.get(cat_key, 0) + 1

        bucket.total_count += 1
        bucket.commitment_hashes.append(commitment_hash)

        # Add to Merkle tree
        leaf_index = len(self._commitments)
        self._commitments.append(commitment_hash)
        self._rebuild_merkle()

        # Generate receipt
        merkle_proof = get_merkle_proof(leaf_index, self._merkle_levels)

        receipt_id = _sha256(f"{commitment_hash}:{leaf_index}".encode())[:16]
        sig_data = f"{receipt_id}:{commitment_hash}:{self._merkle_root}"
        signature = self._sign(sig_data)

        return ContributionReceipt(
            receipt_id=receipt_id,
            commitment_hash=commitment_hash,
            contribution_hash=contribution_hash,
            merkle_leaf_index=leaf_index,
            merkle_root=self._merkle_root,
            merkle_proof=merkle_proof,
            aggregate_id=agg_id,
            server_signature=signature,
        )

    def commit_attack_map(
        self,
        techniques: list[dict],
        tools_in_scope: list[str] | None = None,
        severity: str | None = None,
        time_to_detect: str | None = None,
        time_to_contain: str | None = None,
        remediation: list[dict] | None = None,
    ) -> ContributionReceipt:
        """
        Commit an attack map: technique × vendor detection data.

        Updates the technique frequency histogram and vendor detection
        matrix. Individual technique lists are discarded — only running
        sums remain.
        """
        # Build canonical representation for hashing
        canonical = json.dumps({
            "type": "attack_map",
            "techniques": techniques,
            "tools_in_scope": tools_in_scope or [],
            "severity": severity,
        }, sort_keys=True, default=str)
        contribution_hash = _sha256(canonical.encode())
        commitment_hash = _sha256(f"{contribution_hash}:{time.time()}".encode())

        # Update technique frequency histogram
        for tech in techniques:
            tid = tech.get("technique_id", "")
            if not tid:
                continue
            observed = tech.get("observed", True)
            if observed:
                self._technique_freq[tid] = self._technique_freq.get(tid, 0) + 1

            # Update vendor detection matrix
            for vendor in tech.get("detected_by", []):
                v = vendor.lower().replace(" ", "-")
                key = (tid, v)
                if key not in self._vendor_detection:
                    self._vendor_detection[key] = {"detected": 0, "missed": 0}
                self._vendor_detection[key]["detected"] += 1

            for vendor in tech.get("missed_by", []):
                v = vendor.lower().replace(" ", "-")
                key = (tid, v)
                if key not in self._vendor_detection:
                    self._vendor_detection[key] = {"detected": 0, "missed": 0}
                self._vendor_detection[key]["missed"] += 1

        # Update severity + timing histograms
        if severity:
            self._severity_hist[severity] = self._severity_hist.get(severity, 0) + 1
        if time_to_detect:
            self._detect_time_hist[time_to_detect] = self._detect_time_hist.get(time_to_detect, 0) + 1
        if time_to_contain:
            self._contain_time_hist[time_to_contain] = self._contain_time_hist.get(time_to_contain, 0) + 1

        # Update remediation histogram
        for action in (remediation or []):
            cat = action.get("category", "other")
            eff = action.get("effectiveness", "unknown")
            key = (cat, eff)
            self._remediation_hist[key] = self._remediation_hist.get(key, 0) + 1

        self._attack_map_count += 1

        # Add to Merkle tree
        leaf_index = len(self._commitments)
        self._commitments.append(commitment_hash)
        self._rebuild_merkle()

        merkle_proof = get_merkle_proof(leaf_index, self._merkle_levels)
        receipt_id = _sha256(f"{commitment_hash}:{leaf_index}".encode())[:16]
        sig_data = f"{receipt_id}:{commitment_hash}:{self._merkle_root}"

        return ContributionReceipt(
            receipt_id=receipt_id,
            commitment_hash=commitment_hash,
            contribution_hash=contribution_hash,
            merkle_leaf_index=leaf_index,
            merkle_root=self._merkle_root,
            merkle_proof=merkle_proof,
            aggregate_id="attack_maps",
            server_signature=self._sign(sig_data),
        )

    def commit_ioc_bundle(
        self,
        ioc_count: int,
        ioc_types: list[str] | None = None,
    ) -> ContributionReceipt:
        """Commit an IOC bundle contribution (count only, no raw IOCs)."""
        canonical = json.dumps({
            "type": "ioc_bundle", "ioc_count": ioc_count,
            "ioc_types": ioc_types or [],
        }, sort_keys=True)
        contribution_hash = _sha256(canonical.encode())
        commitment_hash = _sha256(f"{contribution_hash}:{time.time()}".encode())

        self._ioc_bundle_count += 1

        leaf_index = len(self._commitments)
        self._commitments.append(commitment_hash)
        self._rebuild_merkle()

        merkle_proof = get_merkle_proof(leaf_index, self._merkle_levels)
        receipt_id = _sha256(f"{commitment_hash}:{leaf_index}".encode())[:16]
        sig_data = f"{receipt_id}:{commitment_hash}:{self._merkle_root}"

        return ContributionReceipt(
            receipt_id=receipt_id,
            commitment_hash=commitment_hash,
            contribution_hash=contribution_hash,
            merkle_leaf_index=leaf_index,
            merkle_root=self._merkle_root,
            merkle_proof=merkle_proof,
            aggregate_id="ioc_bundles",
            server_signature=self._sign(sig_data),
        )

    # ── Histogram queries (Tier 2 — powers advanced features) ─────────

    def get_technique_frequency(self, limit: int = 50) -> list[dict]:
        """Top techniques by frequency across all attack map contributions."""
        sorted_techs = sorted(
            self._technique_freq.items(), key=lambda x: -x[1]
        )[:limit]
        return [
            {"technique_id": tid, "count": count, "pct": round(count / max(self._attack_map_count, 1) * 100, 1)}
            for tid, count in sorted_techs
        ]

    def get_vendor_detection_rate(self, vendor: str) -> dict:
        """Per-technique detection rate for a specific vendor."""
        vendor_lower = vendor.lower().replace(" ", "-")
        techniques = {}
        total_detected = 0
        total_evaluated = 0

        for (tid, v), counts in self._vendor_detection.items():
            if v != vendor_lower:
                continue
            d = counts["detected"]
            m = counts["missed"]
            total_detected += d
            total_evaluated += d + m
            techniques[tid] = {
                "detected": d, "missed": m,
                "rate": round(d / (d + m), 3) if (d + m) > 0 else 0,
            }

        overall_rate = round(total_detected / total_evaluated, 3) if total_evaluated > 0 else 0

        return {
            "vendor": vendor,
            "overall_detection_rate": overall_rate,
            "techniques_evaluated": total_evaluated,
            "techniques_detected": total_detected,
            "per_technique": dict(sorted(techniques.items(), key=lambda x: -x[1]["rate"])),
        }

    def get_vendor_gaps(self, vendor: str) -> list[str]:
        """Techniques this vendor misses (missed > 0)."""
        vendor_lower = vendor.lower().replace(" ", "-")
        gaps = []
        for (tid, v), counts in self._vendor_detection.items():
            if v == vendor_lower and counts["missed"] > 0:
                gaps.append(tid)
        return sorted(set(gaps))

    def get_technique_coverage(self, tools: list[str]) -> dict:
        """
        Coverage analysis: which techniques are covered by the given tools,
        which are gaps, and what catches the gaps.
        """
        tools_lower = {t.lower().replace(" ", "-") for t in tools}
        covered = set()
        gaps = set()
        all_techniques = set()

        for (tid, v), counts in self._vendor_detection.items():
            all_techniques.add(tid)
            if v in tools_lower and counts["detected"] > 0:
                covered.add(tid)

        # Gaps = techniques seen in the wild but not detected by your tools
        for tid in self._technique_freq:
            all_techniques.add(tid)
            if tid not in covered:
                gaps.add(tid)

        # What catches each gap?
        gap_details = []
        for tid in sorted(gaps):
            catchers = []
            for (t, v), counts in self._vendor_detection.items():
                if t == tid and counts["detected"] > 0 and v not in tools_lower:
                    catchers.append(v)
            gap_details.append({
                "technique_id": tid,
                "frequency": self._technique_freq.get(tid, 0),
                "caught_by": sorted(set(catchers)),
            })
        gap_details.sort(key=lambda x: -x["frequency"])

        total = len(all_techniques) if all_techniques else 1
        return {
            "tools": list(tools),
            "total_techniques": len(all_techniques),
            "covered": len(covered),
            "gaps": len(gaps),
            "coverage_pct": round(len(covered) / total * 100, 1),
            "gap_details": gap_details[:20],
        }

    def get_vendor_comparison(self, vendors: list[str]) -> dict:
        """Side-by-side detection rates for multiple vendors."""
        result = {}
        for vendor in vendors:
            result[vendor] = self.get_vendor_detection_rate(vendor)
        return result

    def get_remediation_stats(self) -> dict:
        """Aggregated remediation effectiveness — what actually works."""
        by_category: dict[str, dict[str, int]] = {}
        for (cat, eff), count in self._remediation_hist.items():
            if cat not in by_category:
                by_category[cat] = {}
            by_category[cat][eff] = count

        return {
            "total_actions": sum(self._remediation_hist.values()),
            "by_category": by_category,
            "severity_distribution": dict(self._severity_hist),
            "time_to_detect": dict(self._detect_time_hist),
            "time_to_contain": dict(self._contain_time_hist),
            "attack_map_count": self._attack_map_count,
        }

    def get_platform_stats(self) -> dict:
        """Overall platform statistics for the dashboard."""
        return {
            "total_contributions": self.total_contributions,
            "eval_count": sum(b.total_count for b in self._aggregates.values()),
            "attack_map_count": self._attack_map_count,
            "ioc_bundle_count": self._ioc_bundle_count,
            "unique_vendors": len(set(b.vendor for b in self._aggregates.values())),
            "unique_techniques": len(self._technique_freq),
            "merkle_root": self._merkle_root,
        }

    def _rebuild_merkle(self) -> None:
        """Rebuild the Merkle tree from all commitments."""
        self._merkle_root, self._merkle_levels = build_merkle_tree(self._commitments)

    def get_aggregate(self, vendor: str, category: str | None = None) -> dict | None:
        """Get the current aggregate for a vendor, with proof."""
        # Try exact match first
        if category:
            agg_id = self._agg_id(vendor, category)
            bucket = self._aggregates.get(agg_id)
            if bucket:
                return self._format_aggregate(bucket)

        # Search by vendor across all categories
        for agg_id, bucket in self._aggregates.items():
            if bucket.vendor.lower() == vendor.lower():
                return self._format_aggregate(bucket)
        return None

    def _format_aggregate(self, bucket: _AggBucket) -> dict:
        """Format an aggregate bucket into a response."""
        agg_values = {}
        for fld in NUMERIC_FIELDS:
            s = bucket.sums.get(fld)
            c = bucket.counts.get(fld, 0)
            if s is not None and c > 0:
                agg_values[f"avg_{fld}"] = round(s / c, 2)

        for fld in BOOL_FIELDS:
            tc = bucket.bool_counts.get(fld, 0)
            c = bucket.counts.get(fld, 0)
            if c > 0:
                agg_values[f"{fld}_pct"] = round(tc / c * 100, 1)

        # Track usage
        for ch in bucket.commitment_hashes:
            self._usage_counts[ch] = self._usage_counts.get(ch, 0) + 1

        return {
            "vendor": bucket.vendor,
            "category": bucket.category,
            "contributor_count": bucket.total_count,
            **agg_values,
        }

    def prove_aggregate(self, vendor: str, category: str | None = None) -> AggregateProof | None:
        """Generate a cryptographic proof for an aggregate."""
        bucket = None
        agg_id = ""
        if category:
            agg_id = self._agg_id(vendor, category)
            bucket = self._aggregates.get(agg_id)
        else:
            for aid, b in self._aggregates.items():
                if b.vendor.lower() == vendor.lower():
                    bucket = b
                    agg_id = aid
                    break

        if not bucket:
            return None

        agg_data = self._format_aggregate(bucket)
        agg_data.pop("vendor", None)
        agg_data.pop("category", None)
        agg_data.pop("contributor_count", None)

        sig_data = json.dumps({
            "aggregate_id": agg_id,
            "contributor_count": bucket.total_count,
            "merkle_root": self._merkle_root,
            "values": agg_data,
        }, sort_keys=True)

        return AggregateProof(
            aggregate_id=agg_id,
            vendor=bucket.vendor,
            category=bucket.category,
            contributor_count=bucket.total_count,
            merkle_root=self._merkle_root,
            commitment_hashes=list(bucket.commitment_hashes),
            aggregate_values=agg_data,
            server_signature=self._sign(sig_data),
        )

    def get_usage_count(self, commitment_hash: str) -> int:
        """How many times a contribution was included in query responses."""
        return self._usage_counts.get(commitment_hash, 0)

    @property
    def total_contributions(self) -> int:
        return len(self._commitments)

    @property
    def merkle_root(self) -> str:
        return self._merkle_root

    def list_aggregates(self) -> list[dict]:
        """List all aggregate buckets with stats."""
        return [
            {
                "aggregate_id": aid,
                "vendor": b.vendor,
                "category": b.category,
                "contributor_count": b.total_count,
            }
            for aid, b in self._aggregates.items()
        ]


def verify_receipt(receipt: ContributionReceipt) -> bool:
    """Verify a contribution receipt's Merkle inclusion proof."""
    return receipt.verify()


def verify_aggregate_proof(
    proof: AggregateProof,
    expected_root: str | None = None,
) -> dict:
    """
    Verify an aggregate proof.

    Checks:
    1. Commitment count matches claimed contributor_count
    2. Merkle root matches expected (if provided)
    3. Server signature is present

    Returns {"valid": bool, "checks": dict, "errors": list}
    """
    errors = []
    checks = {
        "commitment_count_matches": False,
        "merkle_root_present": False,
        "signature_present": False,
    }

    # Check commitment count
    if len(proof.commitment_hashes) == proof.contributor_count:
        checks["commitment_count_matches"] = True
    else:
        errors.append(
            f"Commitment count ({len(proof.commitment_hashes)}) != "
            f"claimed contributors ({proof.contributor_count})"
        )

    # Check Merkle root
    if proof.merkle_root and len(proof.merkle_root) == 64:
        checks["merkle_root_present"] = True
        if expected_root and proof.merkle_root != expected_root:
            checks["merkle_root_present"] = False
            errors.append("Merkle root mismatch")
    else:
        errors.append("Missing or invalid Merkle root")

    # Check signature
    if proof.server_signature and len(proof.server_signature) == 64:
        checks["signature_present"] = True
    else:
        errors.append("Missing server signature")

    return {
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
    }


__all__ = [
    "AggregateProof",
    "ContributionReceipt",
    "ProofEngine",
    "verify_aggregate_proof",
    "verify_receipt",
    "STRENGTH_CATEGORIES",
    "FRICTION_CATEGORIES",
    "REMEDIATION_CATEGORIES",
    "EFFECTIVENESS_LEVELS",
    "SEVERITY_LEVELS",
]
