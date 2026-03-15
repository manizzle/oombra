"""Tests for vigil.feeds — threat intelligence feed scraping."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from vigil.feeds import (
    FEEDS,
    scrape_threatfox,
    scrape_feodo,
    scrape_bazaar,
    scrape_cisa_kev,
    scrape_feed,
    scrape_all,
    bundle_iocs,
    ingest_to_server,
)


FIXTURES = Path(__file__).parent / "fixtures"


# ── Scraper unit tests (using fixture files) ─────────────────────────────────

class TestScrapeThreatfox:
    def test_parses_csv(self):
        raw = (FIXTURES / "threatfox_sample.csv").read_text()
        iocs = scrape_threatfox.__wrapped__(raw) if hasattr(scrape_threatfox, "__wrapped__") else _parse_with_fixture(scrape_threatfox, raw)
        assert len(iocs) == 4

    def test_parses_domain(self):
        raw = (FIXTURES / "threatfox_sample.csv").read_text()
        iocs = _parse_with_fixture(scrape_threatfox, raw)
        domain_iocs = [i for i in iocs if i["ioc_type"] == "domain"]
        assert len(domain_iocs) >= 1
        assert domain_iocs[0]["value_raw"] == "evil-domain.com"
        assert domain_iocs[0]["threat_actor"] == "TA542"

    def test_strips_port_from_ip(self):
        raw = (FIXTURES / "threatfox_sample.csv").read_text()
        iocs = _parse_with_fixture(scrape_threatfox, raw)
        ip_iocs = [i for i in iocs if i["ioc_type"] == "ip"]
        assert len(ip_iocs) >= 1
        assert ":" not in ip_iocs[0]["value_raw"]
        assert ip_iocs[0]["value_raw"] == "192.168.1.100"

    def test_maps_hash_type(self):
        raw = (FIXTURES / "threatfox_sample.csv").read_text()
        iocs = _parse_with_fixture(scrape_threatfox, raw)
        hash_iocs = [i for i in iocs if i["ioc_type"] == "hash-sha256"]
        assert len(hash_iocs) >= 1

    def test_has_required_fields(self):
        raw = (FIXTURES / "threatfox_sample.csv").read_text()
        iocs = _parse_with_fixture(scrape_threatfox, raw)
        for ioc in iocs:
            assert "ioc_type" in ioc
            assert "value_raw" in ioc
            assert "threat_actor" in ioc
            assert "campaign" in ioc
            assert "detected_by" in ioc
            assert "missed_by" in ioc
            assert isinstance(ioc["detected_by"], list)
            assert isinstance(ioc["missed_by"], list)


class TestScrapeFeodo:
    def test_parses_json(self):
        raw = (FIXTURES / "feodo_sample.json").read_text()
        iocs = _parse_with_fixture(scrape_feodo, raw)
        assert len(iocs) == 3

    def test_extracts_ip(self):
        raw = (FIXTURES / "feodo_sample.json").read_text()
        iocs = _parse_with_fixture(scrape_feodo, raw)
        assert iocs[0]["ioc_type"] == "ip"
        assert iocs[0]["value_raw"] == "1.2.3.4"
        assert iocs[0]["threat_actor"] == "Emotet"
        assert iocs[0]["campaign"] == "Emotet-c2"


class TestScrapeBazaar:
    def test_parses_hashes(self):
        raw = (FIXTURES / "bazaar_sample.txt").read_text()
        iocs = _parse_with_fixture(scrape_bazaar, raw)
        # Should get 3 valid 64-char hashes (comments, short lines, and 68-char line skipped)
        assert len(iocs) == 3

    def test_skips_comments_and_short(self):
        raw = (FIXTURES / "bazaar_sample.txt").read_text()
        iocs = _parse_with_fixture(scrape_bazaar, raw)
        values = [i["value_raw"] for i in iocs]
        assert "short" not in values
        assert all(len(v) == 64 for v in values)

    def test_ioc_type(self):
        raw = (FIXTURES / "bazaar_sample.txt").read_text()
        iocs = _parse_with_fixture(scrape_bazaar, raw)
        assert all(i["ioc_type"] == "hash-sha256" for i in iocs)


class TestScrapeCisaKev:
    def test_filters_ransomware(self):
        raw = (FIXTURES / "cisa_kev_sample.json").read_text()
        iocs = _parse_with_fixture(scrape_cisa_kev, raw)
        # Only 2 have knownRansomwareCampaignUse == "Known"
        assert len(iocs) == 2

    def test_extracts_cve(self):
        raw = (FIXTURES / "cisa_kev_sample.json").read_text()
        iocs = _parse_with_fixture(scrape_cisa_kev, raw)
        assert iocs[0]["ioc_type"] == "cve"
        assert iocs[0]["value_raw"] == "CVE-2024-0001"
        assert iocs[0]["threat_actor"] == "Microsoft"
        assert iocs[0]["campaign"] == "ransomware-kev"


# ── Public API tests ─────────────────────────────────────────────────────────

class TestScrapeAll:
    @patch("vigil.feeds._fetch")
    def test_returns_dict_of_lists(self, mock_fetch):
        mock_fetch.return_value = "[]"
        results = scrape_all()
        assert isinstance(results, dict)
        assert set(results.keys()) == set(FEEDS.keys())

    def test_unknown_feed_raises(self):
        with pytest.raises(ValueError, match="Unknown feed"):
            scrape_feed("nonexistent")


class TestBundleIocs:
    def test_chunks_correctly(self):
        iocs = [{"ioc_type": "ip", "value_raw": f"1.1.1.{i}",
                 "threat_actor": "test", "campaign": "test",
                 "detected_by": [], "missed_by": []} for i in range(120)]
        bundles = bundle_iocs(iocs, "test-feed", chunk_size=50)
        assert len(bundles) == 3
        assert len(bundles[0]["iocs"]) == 50
        assert len(bundles[1]["iocs"]) == 50
        assert len(bundles[2]["iocs"]) == 20

    def test_bundle_format(self):
        iocs = [{"ioc_type": "ip", "value_raw": "1.2.3.4",
                 "threat_actor": "t", "campaign": "c",
                 "detected_by": [], "missed_by": []}]
        bundles = bundle_iocs(iocs, "feodo")
        assert len(bundles) == 1
        b = bundles[0]
        assert b["source"] == "threat-feed"
        assert b["tools_in_scope"] == []
        assert "feodo" in b["notes"]

    def test_empty_input(self):
        bundles = bundle_iocs([], "empty")
        assert bundles == []


class TestIngestToServer:
    @patch("vigil.feeds.urllib.request.urlopen")
    def test_posts_bundles(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        bundles = [{"iocs": [], "source": "test"}]
        count = ingest_to_server("http://localhost:8000", bundles)
        assert count == 1
        mock_urlopen.assert_called_once()

    @patch("vigil.feeds.urllib.request.urlopen")
    def test_sets_api_key_header(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        bundles = [{"iocs": [], "source": "test"}]
        ingest_to_server("http://localhost:8000", bundles, api_key="secret123")

        # Check the Request object passed to urlopen
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_header("X-api-key") == "secret123"

    @patch("vigil.feeds.urllib.request.urlopen")
    def test_handles_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("connection refused")
        bundles = [{"iocs": [], "source": "test"}]
        count = ingest_to_server("http://localhost:8000", bundles)
        assert count == 0


# ── CLI tests ────────────────────────────────────────────────────────────────

class TestScrapeCLI:
    def test_list_shows_feeds(self):
        from vigil.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["scrape", "--list"])
        assert result.exit_code == 0
        for name in FEEDS:
            assert name in result.output

    @patch("vigil.feeds._fetch")
    def test_dry_run_no_upload(self, mock_fetch):
        mock_fetch.return_value = (FIXTURES / "feodo_sample.json").read_text()
        from vigil.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["scrape", "--feed", "feodo", "--dry-run"])
        assert result.exit_code == 0
        assert "dry-run" in result.output
        assert "3 IOCs" in result.output


# ── Helper ───────────────────────────────────────────────────────────────────

def _parse_with_fixture(scraper_fn, raw_data: str) -> list[dict]:
    """Call a scraper function with fixture data by mocking _fetch."""
    with patch("vigil.feeds._fetch", return_value=raw_data):
        # Get the URL from FEEDS registry
        for feed_info in FEEDS.values():
            if feed_info["scraper"] is scraper_fn:
                return scraper_fn(feed_info["url"])
        # Fallback: call with dummy URL
        return scraper_fn("http://test.local/fixture")
