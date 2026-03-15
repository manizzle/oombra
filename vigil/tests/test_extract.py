"""
Tests for vigil extraction pipeline — round-trip tests for every format.
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

from vigil.extract import load_file, load_dict
from vigil.models import EvalRecord, AttackMap, IOCBundle


class TestLoadDict:
    def test_eval_dict(self):
        data = {
            "vendor": "CrowdStrike",
            "category": "edr",
            "overall_score": 8.5,
            "detection_rate": 95.0,
        }
        results = load_dict(data)
        assert len(results) >= 1
        assert isinstance(results[0], EvalRecord)
        assert results[0].vendor == "CrowdStrike"

    def test_attack_map_dict(self):
        data = {
            "threat_name": "APT28",
            "techniques": [
                {
                    "technique_id": "T1566",
                    "technique_name": "Phishing",
                    "detected_by": ["crowdstrike"],
                }
            ],
        }
        results = load_dict(data)
        assert len(results) >= 1
        assert isinstance(results[0], AttackMap)


class TestLoadJSON:
    def test_eval_json(self):
        data = {
            "vendor": "Splunk",
            "category": "siem",
            "overall_score": 7.0,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            f.flush()
            results = load_file(f.name)
        os.unlink(f.name)
        assert len(results) >= 1
        assert isinstance(results[0], EvalRecord)

    def test_json_array(self):
        data = [
            {"vendor": "Splunk", "category": "siem", "overall_score": 7.0},
            {"vendor": "CrowdStrike", "category": "edr", "overall_score": 9.0},
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            f.flush()
            results = load_file(f.name)
        os.unlink(f.name)
        assert len(results) == 2

    def test_stix_bundle(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Phishing",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1566"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ],
                },
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(bundle, f)
            f.flush()
            results = load_file(f.name)
        os.unlink(f.name)
        assert any(isinstance(r, AttackMap) for r in results)


class TestLoadCSV:
    def test_eval_csv(self):
        csv_content = "vendor,category,overall_score,detection_rate\nCrowdStrike,edr,9.0,98.5\nSplunk,siem,7.5,85.0\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(csv_content)
            f.flush()
            results = load_file(f.name)
        os.unlink(f.name)
        assert len(results) == 2
        assert all(isinstance(r, EvalRecord) for r in results)
        assert results[0].vendor == "CrowdStrike"


class TestLoadText:
    def test_text_extraction(self):
        text = """
        Vendor: CrowdStrike
        Score: 8.5
        Detection Rate: 95%
        Deploy Days: 7
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write(text)
            f.flush()
            results = load_file(f.name)
        os.unlink(f.name)
        assert len(results) >= 1
        assert isinstance(results[0], EvalRecord)
        assert results[0].vendor == "CrowdStrike"
