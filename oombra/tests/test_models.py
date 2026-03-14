"""
Tests for oombra data models — round-trip serialization, validation, edge cases.
"""
from __future__ import annotations

import json
import pytest

from oombra.models import (
    EvalRecord, AttackMap, IOCBundle, IOCEntry, ObservedTechnique,
    ContribContext, Industry, OrgSize, Role, ContribType,
    contribution_type,
)


class TestEvalRecord:
    def test_minimal(self):
        r = EvalRecord(vendor="CrowdStrike", category="edr")
        assert r.vendor == "CrowdStrike"
        assert r.type == ContribType.eval
        assert r.overall_score is None

    def test_full(self):
        r = EvalRecord(
            vendor="Splunk",
            category="siem",
            overall_score=7.5,
            detection_rate=92.3,
            fp_rate=1.2,
            deploy_days=14,
            would_buy=True,
            context=ContribContext(
                industry=Industry.tech,
                org_size=OrgSize.l,
                role=Role.ciso,
            ),
        )
        assert r.overall_score == 7.5
        assert r.context.industry == Industry.tech

    def test_score_bounds(self):
        with pytest.raises(Exception):
            EvalRecord(vendor="X", category="edr", overall_score=11.0)
        with pytest.raises(Exception):
            EvalRecord(vendor="X", category="edr", overall_score=-1.0)

    def test_detection_rate_bounds(self):
        with pytest.raises(Exception):
            EvalRecord(vendor="X", category="edr", detection_rate=101.0)

    def test_round_trip(self):
        r = EvalRecord(
            vendor="Wiz", category="cnapp", overall_score=9.0,
            top_strength="Cloud native", notes="Great tool",
        )
        data = r.model_dump(mode="json")
        r2 = EvalRecord.model_validate(data)
        assert r2.vendor == r.vendor
        assert r2.overall_score == r.overall_score
        assert r2.top_strength == r.top_strength


class TestAttackMap:
    def test_minimal(self):
        am = AttackMap()
        assert am.type == ContribType.attack_map
        assert am.techniques == []

    def test_with_techniques(self):
        am = AttackMap(
            threat_name="APT28",
            techniques=[
                ObservedTechnique(
                    technique_id="T1566",
                    technique_name="Phishing",
                    tactic="initial-access",
                    detected_by=["crowdstrike"],
                    missed_by=["splunk"],
                ),
                ObservedTechnique(
                    technique_id="T1059",
                    technique_name="Command and Scripting",
                    observed=False,
                ),
            ],
            tools_in_scope=["crowdstrike", "splunk"],
        )
        assert len(am.techniques) == 2
        assert am.techniques[0].detected_by == ["crowdstrike"]

    def test_round_trip(self):
        am = AttackMap(
            threat_name="Ransomware",
            techniques=[
                ObservedTechnique(technique_id="T1486", technique_name="Data Encrypted"),
            ],
        )
        data = am.model_dump(mode="json")
        am2 = AttackMap.model_validate(data)
        assert am2.threat_name == "Ransomware"
        assert len(am2.techniques) == 1


class TestIOCBundle:
    def test_minimal(self):
        b = IOCBundle()
        assert b.type == ContribType.ioc_bundle
        assert b.iocs == []

    def test_with_iocs(self):
        b = IOCBundle(
            iocs=[
                IOCEntry(ioc_type="domain", value_raw="evil.com"),
                IOCEntry(ioc_type="ip", value_raw="10.0.0.1"),
                IOCEntry(
                    ioc_type="hash-sha256",
                    value_hash="a" * 64,
                    detected_by=["crowdstrike"],
                ),
            ],
        )
        assert len(b.iocs) == 3
        assert b.iocs[0].ioc_type == "domain"

    def test_round_trip(self):
        b = IOCBundle(
            iocs=[IOCEntry(ioc_type="url", value_hash="abc123" * 10 + "abcd")],
            tools_in_scope=["sentinelone"],
            source="incident",
        )
        data = b.model_dump(mode="json")
        b2 = IOCBundle.model_validate(data)
        assert b2.source == "incident"
        assert len(b2.iocs) == 1


class TestContribContext:
    def test_empty(self):
        ctx = ContribContext()
        assert ctx.industry is None

    def test_full(self):
        ctx = ContribContext(
            industry=Industry.financial,
            org_size=OrgSize.xl,
            role=Role.security_analyst,
        )
        assert ctx.industry.value == "financial"
        assert ctx.org_size.value == "5000-10000"


class TestContributionType:
    def test_eval(self):
        r = EvalRecord(vendor="X", category="edr")
        assert contribution_type(r) == "eval"

    def test_attack_map(self):
        am = AttackMap()
        assert contribution_type(am) == "attack_map"

    def test_ioc_bundle(self):
        b = IOCBundle()
        assert contribution_type(b) == "ioc_bundle"
