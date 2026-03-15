"""Tests for nur.server.vendors — vendor registry, scoring engine, data loaders."""
from __future__ import annotations

import pytest

from nur.server.vendors import (
    VENDOR_REGISTRY,
    SOURCE_WEIGHTS,
    confidence_level,
    get_vendor,
    list_vendors,
    load_capabilities,
    load_integrations,
    load_mitre_map,
    weighted_score,
)


# ── VENDOR_REGISTRY ───────────────────────────────────────────────────


class TestVendorRegistry:
    def test_is_non_empty_dict(self):
        assert isinstance(VENDOR_REGISTRY, dict)
        assert len(VENDOR_REGISTRY) > 0

    def test_each_vendor_has_required_fields(self):
        required = {"display_name", "category"}
        for vid, vendor in VENDOR_REGISTRY.items():
            for field in required:
                assert field in vendor, f"Vendor {vid!r} missing field {field!r}"
            assert isinstance(vendor["display_name"], str)
            assert isinstance(vendor["category"], str)

    def test_get_vendor_returns_dict(self):
        v = get_vendor("crowdstrike")
        assert v is not None
        assert v["display_name"] == "CrowdStrike"

    def test_get_vendor_case_insensitive(self):
        assert get_vendor("CrowdStrike") is not None
        assert get_vendor("CROWDSTRIKE") is not None

    def test_get_vendor_unknown_returns_none(self):
        assert get_vendor("nonexistent-vendor") is None

    def test_list_vendors_returns_all(self):
        vendors = list_vendors()
        assert len(vendors) == len(VENDOR_REGISTRY)
        for v in vendors:
            assert "id" in v
            assert "display_name" in v

    def test_list_vendors_filter_by_category(self):
        edr_vendors = list_vendors(category="edr")
        assert len(edr_vendors) > 0
        assert all(v["category"] == "edr" for v in edr_vendors)


# ── SOURCE_WEIGHTS ────────────────────────────────────────────────────


class TestSourceWeights:
    def test_has_expected_sources(self):
        expected = ["mitre", "av-test", "reddit", "g2", "gartner", "selabs"]
        for src in expected:
            assert src in SOURCE_WEIGHTS, f"Missing source weight for {src!r}"

    def test_weights_are_positive_floats(self):
        for src, w in SOURCE_WEIGHTS.items():
            assert isinstance(w, (int, float))
            assert w > 0, f"Weight for {src!r} should be positive"


# ── weighted_score ────────────────────────────────────────────────────


class TestWeightedScore:
    def test_returns_float_for_valid_evals(self):
        evals = [
            {"overall_score": 8.0, "source": "mitre"},
            {"overall_score": 7.5, "source": "av-test"},
        ]
        result = weighted_score(evals)
        assert isinstance(result, float)
        assert 0 <= result <= 10

    def test_returns_none_for_empty_list(self):
        assert weighted_score([]) is None

    def test_returns_none_for_evals_without_scores(self):
        evals = [{"overall_score": None, "source": "mitre"}]
        assert weighted_score(evals) is None

    def test_single_eval(self):
        evals = [{"overall_score": 9.0, "source": "mitre"}]
        result = weighted_score(evals)
        assert result == 9.0

    def test_respects_source_weights(self):
        # mitre has weight 3.0, reddit has weight 1.0
        evals = [
            {"overall_score": 10.0, "source": "mitre"},
            {"overall_score": 0.0, "source": "reddit"},
        ]
        result = weighted_score(evals)
        # (10*3 + 0*1) / (3+1) = 7.5
        assert result == 7.5

    def test_uses_default_weight_for_unknown_source(self):
        evals = [{"overall_score": 6.0, "source": "unknown-source"}]
        result = weighted_score(evals)
        assert result == 6.0


# ── confidence_level ──────────────────────────────────────────────────


class TestConfidenceLevel:
    def test_high(self):
        assert confidence_level(eval_count=10, source_count=6) == "high"
        assert confidence_level(eval_count=8, source_count=5) == "high"

    def test_medium(self):
        assert confidence_level(eval_count=5, source_count=3) == "medium"
        assert confidence_level(eval_count=4, source_count=3) == "medium"

    def test_low(self):
        assert confidence_level(eval_count=3, source_count=2) == "low"
        assert confidence_level(eval_count=3, source_count=1) == "low"

    def test_insufficient(self):
        assert confidence_level(eval_count=2, source_count=1) == "insufficient"
        assert confidence_level(eval_count=0, source_count=0) == "insufficient"


# ── Data file loaders ─────────────────────────────────────────────────


class TestDataLoaders:
    def test_load_capabilities(self):
        data = load_capabilities()
        assert isinstance(data, (dict, list))

    def test_load_integrations(self):
        data = load_integrations()
        assert isinstance(data, (dict, list))

    def test_load_mitre_map(self):
        data = load_mitre_map()
        assert isinstance(data, (dict, list))
