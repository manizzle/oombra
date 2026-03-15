"""
Tests for CLI --json flag on preview and upload commands.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from click.testing import CliRunner

from vigil.cli import main


@pytest.fixture
def eval_file():
    """Create a temporary eval JSON file for testing."""
    data = {
        "vendor": "TestVendor",
        "category": "edr",
        "overall_score": 8.5,
        "detection_rate": 95.0,
        "fp_rate": 1.2,
        "deploy_days": 5,
        "would_buy": True,
        "top_strength": "Fast deployment",
        "top_friction": "Complex UI",
        "notes": "Good product overall.",
        "context": {"industry": "technology", "org_size": "1000-5000", "role": "engineer"},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        yield f.name
    os.unlink(f.name)


class TestPreviewJson:
    def test_preview_json_valid(self, eval_file):
        """preview --json should output valid JSON."""
        runner = CliRunner()
        result = runner.invoke(main, ["preview", eval_file, "--json"])
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_preview_json_has_expected_fields(self, eval_file):
        """JSON output should contain vendor, category, etc."""
        runner = CliRunner()
        result = runner.invoke(main, ["preview", eval_file, "--json"])
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        parsed = json.loads(result.output)
        assert "vendor" in parsed
        assert "category" in parsed

    def test_preview_without_json_is_not_json(self, eval_file):
        """preview without --json should output human-readable text, not JSON."""
        runner = CliRunner()
        result = runner.invoke(main, ["preview", eval_file])
        assert result.exit_code == 0
        # Should not be valid JSON (human-readable format)
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.output)
