"""Tests for MITRE ATT&CK Evaluations + AV-TEST lab data module."""
from __future__ import annotations


class TestMITREEvals:
    def test_mitre_to_payload(self):
        from nur.feeds.mitre_evals import MITRE_EVAL_RESULTS, mitre_eval_to_nur_payload

        payload = mitre_eval_to_nur_payload(MITRE_EVAL_RESULTS[0])
        assert payload["data"]["vendor"] == "CrowdStrike"
        assert 1 <= payload["data"]["overall_score"] <= 10
        assert payload["data"]["detection_rate"] > 0

    def test_avtest_to_payload(self):
        from nur.feeds.mitre_evals import AV_TEST_RESULTS, avtest_to_nur_payload

        payload = avtest_to_nur_payload(AV_TEST_RESULTS[0])
        assert 1 <= payload["data"]["overall_score"] <= 10

    def test_all_results_have_required_fields(self):
        from nur.feeds.mitre_evals import AV_TEST_RESULTS, MITRE_EVAL_RESULTS

        for r in MITRE_EVAL_RESULTS:
            assert "vendor" in r
            assert "overall_detection_rate" in r
        for r in AV_TEST_RESULTS:
            assert "vendor" in r
            assert "total" in r
