"""Unit tests for hardcoded scraper modules — no network calls needed."""
from __future__ import annotations

import pytest


# ── Shared helpers ────────────────────────────────────────────────────

EXPECTED_KEYS = {"vendor", "category", "overall_score", "source"}


def _assert_eval_list(evals: list[dict], min_count: int = 1, required_keys=EXPECTED_KEYS):
    """Assert evals is a non-empty list of dicts with expected keys."""
    assert isinstance(evals, list)
    assert len(evals) >= min_count, f"expected >= {min_count} results, got {len(evals)}"
    for ev in evals:
        assert isinstance(ev, dict)
        for key in required_keys:
            assert key in ev, f"Missing key {key!r} in eval: {ev}"


# ── MITRE ─────────────────────────────────────────────────────────────


class TestMitreScraper:
    def test_returns_8_results(self):
        from nur.scrapers.mitre import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=8)

    def test_results_have_expected_fields(self):
        from nur.scrapers.mitre import scrape
        evals = scrape()
        for ev in evals:
            assert ev["source"] == "mitre-attack-evals"
            assert "vendor_id" in ev
            assert "detection_rate" in ev
            assert isinstance(ev["overall_score"], (int, float))
            assert 0 <= ev["overall_score"] <= 10

    def test_handles_none_config(self):
        from nur.scrapers.mitre import scrape
        result = scrape(None)
        assert isinstance(result, list)


# ── AV-TEST ───────────────────────────────────────────────────────────


class TestAvtestScraper:
    def test_returns_results(self):
        from nur.scrapers.avtest import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=1)

    def test_results_have_detection_rate(self):
        from nur.scrapers.avtest import scrape
        evals = scrape()
        for ev in evals:
            assert "detection_rate" in ev
            assert ev["source"] == "av-test"

    def test_scores_in_valid_range(self):
        from nur.scrapers.avtest import scrape
        for ev in scrape():
            assert 0 <= ev["overall_score"] <= 10


# ── SE Labs ───────────────────────────────────────────────────────────


class TestSelabsScraper:
    def test_returns_results(self):
        from nur.scrapers.selabs import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=1)

    def test_results_have_correct_source(self):
        from nur.scrapers.selabs import scrape
        for ev in scrape():
            assert ev["source"] == "selabs"

    def test_scores_in_valid_range(self):
        from nur.scrapers.selabs import scrape
        for ev in scrape():
            assert 0 <= ev["overall_score"] <= 10


# ── AV-Comparatives ──────────────────────────────────────────────────


class TestAvComparativesScraper:
    def test_returns_results(self):
        from nur.scrapers.av_comparatives import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=1)

    def test_results_have_correct_source(self):
        from nur.scrapers.av_comparatives import scrape
        for ev in scrape():
            assert ev["source"] == "av-comparatives"

    def test_scores_in_valid_range(self):
        from nur.scrapers.av_comparatives import scrape
        for ev in scrape():
            assert 0 <= ev["overall_score"] <= 10


# ── Vendor Meta ───────────────────────────────────────────────────────


class TestVendorMetaScraper:
    def test_returns_36_vendors(self):
        from nur.scrapers.vendor_meta import scrape
        evals = scrape()
        assert isinstance(evals, list)
        assert len(evals) == 36

    def test_results_have_metadata_category(self):
        from nur.scrapers.vendor_meta import scrape
        for ev in scrape():
            assert ev["category"] == "metadata"
            assert ev["source"] == "vendor-meta"

    def test_results_have_extra_fields(self):
        from nur.scrapers.vendor_meta import scrape
        for ev in scrape():
            assert "price_range" in ev
            assert "certifications" in ev
            assert "typical_deploy_days" in ev
            assert isinstance(ev["certifications"], list)


# ── G2 ────────────────────────────────────────────────────────────────


class TestG2Scraper:
    def test_returns_results(self):
        from nur.scrapers.g2 import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=1)

    def test_results_have_g2_source(self):
        from nur.scrapers.g2 import scrape
        for ev in scrape():
            assert ev["source"] == "g2"

    def test_scores_in_valid_range(self):
        from nur.scrapers.g2 import scrape
        for ev in scrape():
            assert 0 <= ev["overall_score"] <= 10


# ── Gartner ───────────────────────────────────────────────────────────


class TestGartnerScraper:
    def test_returns_results(self):
        from nur.scrapers.gartner import scrape
        evals = scrape()
        _assert_eval_list(evals, min_count=1)

    def test_results_have_gartner_source(self):
        from nur.scrapers.gartner import scrape
        for ev in scrape():
            assert ev["source"] == "gartner-peer-insights"

    def test_scores_in_valid_range(self):
        from nur.scrapers.gartner import scrape
        for ev in scrape():
            assert 0 <= ev["overall_score"] <= 10


# ── Empty / edge-case handling ────────────────────────────────────────


class TestScrapersHandleEmptyInput:
    """All scrapers accept an optional config arg and handle it gracefully."""

    @pytest.mark.parametrize("module_path", [
        "nur.scrapers.mitre",
        "nur.scrapers.avtest",
        "nur.scrapers.selabs",
        "nur.scrapers.av_comparatives",
        "nur.scrapers.vendor_meta",
        "nur.scrapers.g2",
        "nur.scrapers.gartner",
    ])
    def test_scrape_with_none_config(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        result = mod.scrape(None)
        assert isinstance(result, list)

    @pytest.mark.parametrize("module_path", [
        "nur.scrapers.mitre",
        "nur.scrapers.avtest",
        "nur.scrapers.selabs",
        "nur.scrapers.av_comparatives",
        "nur.scrapers.vendor_meta",
        "nur.scrapers.g2",
        "nur.scrapers.gartner",
    ])
    def test_scrape_with_empty_dict_config(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        result = mod.scrape({})
        assert isinstance(result, list)
