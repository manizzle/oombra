"""Tests for nur.verticals — industry vertical configurations."""
from __future__ import annotations

import pytest

from nur.verticals import VERTICALS, Vertical, get_vertical, list_verticals


# ── get_vertical ──────────────────────────────────────────────────────


class TestGetVertical:
    def test_healthcare_returns_vertical_with_correct_fields(self):
        v = get_vertical("healthcare")
        assert isinstance(v, Vertical)
        assert v.name == "healthcare"
        assert v.display_name == "Healthcare & Life Sciences"
        assert len(v.threat_actors) > 0
        assert len(v.priority_techniques) > 0
        assert "HIPAA" in v.compliance

    def test_financial_returns_different_threat_actors(self):
        hc = get_vertical("healthcare")
        fin = get_vertical("financial")
        assert hc.threat_actors != fin.threat_actors

    def test_financial_has_expected_compliance(self):
        fin = get_vertical("financial")
        assert "PCI DSS" in fin.compliance or "SOX" in fin.compliance

    def test_unknown_vertical_raises_valueerror(self):
        with pytest.raises(ValueError, match="Unknown vertical"):
            get_vertical("unknown")

    def test_energy_vertical_exists(self):
        v = get_vertical("energy")
        assert v.name == "energy"

    def test_government_vertical_exists(self):
        v = get_vertical("government")
        assert v.name == "government"


# ── list_verticals ────────────────────────────────────────────────────


class TestListVerticals:
    def test_returns_list_of_dicts(self):
        result = list_verticals()
        assert isinstance(result, list)
        assert len(result) == len(VERTICALS)
        for item in result:
            assert isinstance(item, dict)

    def test_each_item_has_required_keys(self):
        for item in list_verticals():
            assert "name" in item
            assert "display_name" in item
            assert "description" in item


# ── Vertical data integrity ──────────────────────────────────────────


class TestVerticalDataIntegrity:
    @pytest.mark.parametrize("name", list(VERTICALS.keys()))
    def test_has_non_empty_threat_actors(self, name):
        v = VERTICALS[name]
        assert len(v.threat_actors) > 0, f"{name} has empty threat_actors"

    @pytest.mark.parametrize("name", list(VERTICALS.keys()))
    def test_has_non_empty_priority_techniques(self, name):
        v = VERTICALS[name]
        assert len(v.priority_techniques) > 0, f"{name} has empty priority_techniques"

    @pytest.mark.parametrize("name", list(VERTICALS.keys()))
    def test_has_non_empty_compliance(self, name):
        v = VERTICALS[name]
        assert len(v.compliance) > 0, f"{name} has empty compliance"

    @pytest.mark.parametrize("name", list(VERTICALS.keys()))
    def test_priority_techniques_have_required_fields(self, name):
        v = VERTICALS[name]
        for tech in v.priority_techniques:
            assert "id" in tech, f"{name}: technique missing 'id'"
            assert "name" in tech, f"{name}: technique missing 'name'"
            assert "why" in tech, f"{name}: technique missing 'why'"
            assert tech["id"], f"{name}: technique 'id' is empty"
            assert tech["name"], f"{name}: technique 'name' is empty"
            assert tech["why"], f"{name}: technique 'why' is empty"
