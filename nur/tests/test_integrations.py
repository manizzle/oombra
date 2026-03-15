"""
Tests for wartime integrations — webhook endpoint and integration modules.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _make_app():
    """Create a fresh app with initialized database."""
    import nur.server.app as app_mod
    from nur.server.app import create_app
    from nur.server.db import Database

    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.init()
    app_mod._db = db
    return app


# ── Webhook: generic/Splunk format ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_generic_iocs():
    """POST generic IOC list to /ingest/webhook should store and return 'generic'."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "iocs": [
                {"ioc_type": "ip", "value_raw": "192.168.1.100"},
                {"ioc_type": "domain", "value_raw": "evil.example.com"},
            ],
            "source": "splunk",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["format_detected"] == "generic"
        assert data["items_stored"] == 1  # one ioc_bundle


@pytest.mark.asyncio
async def test_webhook_generic_prehashed():
    """IOCs with value_hash should be stored directly."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        h = hashlib.sha256(b"test-ioc").hexdigest()
        resp = await client.post("/ingest/webhook", json={
            "iocs": [{"ioc_type": "ip", "value_hash": h}],
            "source": "test",
        })
        assert resp.status_code == 200
        assert resp.json()["items_stored"] == 1


# ── Webhook: CrowdStrike format ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_crowdstrike_detection():
    """CrowdStrike detection format should store attack_map + ioc_bundle."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "detection": {
                "technique": "T1486",
                "tactic": "Impact",
                "ioc_type": "ip",
                "ioc_value": "10.0.0.99",
                "severity": "critical",
                "scenario": "Ransomware",
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "crowdstrike"
        assert data["items_stored"] == 2  # attack_map + ioc_bundle


@pytest.mark.asyncio
async def test_webhook_crowdstrike_technique_only():
    """CrowdStrike detection without IOC should store only attack_map."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "detection": {
                "technique": "T1059",
                "tactic": "Execution",
                "severity": "medium",
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "crowdstrike"
        assert data["items_stored"] == 1  # attack_map only


# ── Webhook: Sentinel format ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_sentinel_incident():
    """Sentinel incident format should store attack_map + ioc_bundle."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "properties": {
                "severity": "High",
                "title": "Phishing Campaign",
                "tactics": ["InitialAccess"],
                "techniques": ["T1566", "T1059"],
                "entities": [
                    {"kind": "ip", "address": "10.0.0.50"},
                    {"kind": "host", "hostName": "malware.example.com"},
                ],
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "sentinel"
        assert data["items_stored"] == 2  # attack_map + ioc_bundle


@pytest.mark.asyncio
async def test_webhook_sentinel_no_entities():
    """Sentinel incident without entities should store only attack_map."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "properties": {
                "severity": "Medium",
                "tactics": ["LateralMovement"],
                "techniques": ["T1021"],
                "entities": [],
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "sentinel"
        assert data["items_stored"] == 1  # attack_map only


# ── Webhook: CEF format ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_cef_format():
    """CEF syslog format should parse and store ioc_bundle."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "cef": "CEF:0|SecurityVendor|Firewall|1.0|100|Blocked Connection|7|src=192.168.1.1 dst=10.0.0.1 dhost=evil.example.com",
            "source_ip": "192.168.1.1",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "cef"
        assert data["items_stored"] == 1


@pytest.mark.asyncio
async def test_webhook_cef_invalid():
    """Invalid CEF string should return 0 items stored."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "cef": "not a valid CEF message",
            "source_ip": "1.2.3.4",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "cef"
        assert data["items_stored"] == 0


# ── Webhook: indicators format ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_indicators_format():
    """Generic indicators list should hash values and store."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "indicators": [
                {"type": "ip", "value": "172.16.0.99"},
                {"type": "domain", "value": "phishing.example.com"},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["format_detected"] == "indicators"
        assert data["items_stored"] == 1


# ── Webhook: auth enforcement ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_requires_auth():
    """Webhook should require API key when NUR_API_KEY is set."""
    os.environ["NUR_API_KEY"] = "test-secret-key"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Without key
            resp = await client.post("/ingest/webhook", json={
                "iocs": [{"ioc_type": "ip", "value_raw": "1.2.3.4"}],
            })
            assert resp.status_code == 401

            # With correct key
            resp = await client.post(
                "/ingest/webhook",
                json={"iocs": [{"ioc_type": "ip", "value_raw": "1.2.3.4"}]},
                headers={"X-API-Key": "test-secret-key"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "accepted"
    finally:
        del os.environ["NUR_API_KEY"]


# ── Webhook: unrecognized format ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_unrecognized_format():
    """Unrecognized format should return 400."""
    os.environ.pop("NUR_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/ingest/webhook", json={
            "random_field": "some data",
        })
        assert resp.status_code == 400


# ── Integration modules: Splunk ──────────────────────────────────────────────


def test_splunk_app_generation():
    """generate_splunk_app should return all required files."""
    from nur.integrations.splunk import generate_splunk_app

    files = generate_splunk_app("https://nur.example.com", "nur_test_key")

    assert "default/app.conf" in files
    assert "default/savedsearches.conf" in files
    assert "default/alert_actions.conf" in files
    assert "bin/nur_alert.py" in files
    assert "README.md" in files

    # Check API URL and key are embedded
    assert "nur.example.com" in files["bin/nur_alert.py"]
    assert "nur_test_key" in files["bin/nur_alert.py"]


def test_splunk_alert_script_has_ioc_extraction():
    """Alert script should have IOC field extraction logic."""
    from nur.integrations.splunk import generate_splunk_app

    files = generate_splunk_app("http://localhost:8000", "key123")
    script = files["bin/nur_alert.py"]

    assert "src_ip" in script
    assert "dest_ip" in script
    assert "file_hash" in script
    assert "/ingest/webhook" in script


# ── Integration modules: Sentinel ────────────────────────────────────────────


def test_sentinel_playbook_generation():
    """generate_sentinel_playbook should return valid ARM template JSON."""
    from nur.integrations.sentinel import generate_sentinel_playbook

    arm_json = generate_sentinel_playbook("https://nur.example.com", "nur_test_key")
    template = json.loads(arm_json)

    assert "$schema" in template
    assert "resources" in template
    assert "parameters" in template
    assert "NurApiUrl" in template["parameters"]
    assert "NurApiKey" in template["parameters"]

    # Check that the Logic App resource exists
    resource_types = [r["type"] for r in template["resources"]]
    assert "Microsoft.Logic/workflows" in resource_types


def test_sentinel_playbook_has_webhook_action():
    """ARM template should include HTTP POST action to nur webhook."""
    from nur.integrations.sentinel import generate_sentinel_playbook

    arm_json = generate_sentinel_playbook("https://nur.example.com", "key")
    assert "/ingest/webhook" in arm_json
    assert "X-API-Key" in arm_json


# ── Integration modules: CrowdStrike ────────────────────────────────────────


def test_crowdstrike_extract_detection_data():
    """_extract_detection_data should extract technique and IOC info."""
    from nur.integrations.crowdstrike import _extract_detection_data

    detection = {
        "detection_id": "ldt:abc123",
        "max_severity_displayname": "Critical",
        "behaviors": [{
            "technique_id": "T1486",
            "tactic": "Impact",
            "sha256": "abc123def456789",
            "description": "Ransomware detected",
            "scenario": "ransomware",
            "timestamp": "2026-01-01T00:00:00Z",
        }],
        "device": {
            "external_ip": "10.0.0.1",
        },
    }

    result = _extract_detection_data(detection)
    assert result is not None
    assert result["detection"]["technique"] == "T1486"
    assert result["detection"]["tactic"] == "Impact"
    assert result["detection"]["severity"] == "critical"
    # SHA256 takes priority over IP for ioc_type
    assert result["detection"]["ioc_type"] == "hash-sha256"
    assert result["detection"]["ioc_value"] == "abc123def456789"


def test_crowdstrike_extract_no_behaviors():
    """Detection without behaviors should return None."""
    from nur.integrations.crowdstrike import _extract_detection_data

    result = _extract_detection_data({"behaviors": []})
    assert result is None


def test_crowdstrike_extract_ip_only():
    """Detection with only external IP (no hash) should use IP."""
    from nur.integrations.crowdstrike import _extract_detection_data

    result = _extract_detection_data({
        "max_severity_displayname": "Medium",
        "behaviors": [{
            "technique_id": "T1059",
            "tactic": "Execution",
        }],
        "device": {"external_ip": "10.0.0.5"},
    })
    assert result is not None
    assert result["detection"]["ioc_type"] == "ip"
    assert result["detection"]["ioc_value"] == "10.0.0.5"


# ── Integration modules: Syslog/CEF ─────────────────────────────────────────


def test_cef_parse_valid():
    """parse_cef should correctly parse a standard CEF message."""
    from nur.integrations.syslog_listener import parse_cef

    msg = "CEF:0|SecurityVendor|Firewall|1.0|100|Blocked|7|src=192.168.1.1 dst=10.0.0.1 dhost=evil.com"
    parsed = parse_cef(msg)

    assert parsed is not None
    assert parsed["version"] == "0"
    assert parsed["vendor"] == "SecurityVendor"
    assert parsed["product"] == "Firewall"
    assert parsed["severity"] == "7"
    assert parsed["extensions"]["src"] == "192.168.1.1"
    assert parsed["extensions"]["dst"] == "10.0.0.1"
    assert parsed["extensions"]["dhost"] == "evil.com"


def test_cef_parse_with_syslog_header():
    """parse_cef should handle syslog header prefix."""
    from nur.integrations.syslog_listener import parse_cef

    msg = "<134>Jan  1 00:00:00 host CEF:0|Vendor|Product|1.0|1|Event|3|src=1.2.3.4"
    parsed = parse_cef(msg)

    assert parsed is not None
    assert parsed["vendor"] == "Vendor"
    assert parsed["extensions"]["src"] == "1.2.3.4"


def test_cef_parse_invalid():
    """parse_cef should return None for non-CEF messages."""
    from nur.integrations.syslog_listener import parse_cef

    assert parse_cef("not a cef message") is None
    assert parse_cef("") is None
    assert parse_cef("syslog: some event happened") is None


def test_cef_extract_iocs():
    """extract_iocs_from_cef should extract IP, domain, and hash IOCs."""
    from nur.integrations.syslog_listener import parse_cef, extract_iocs_from_cef

    msg = "CEF:0|V|P|1|1|E|5|src=10.0.0.1 dst=10.0.0.2 dhost=malware.com fileHash=abc123"
    parsed = parse_cef(msg)
    iocs = extract_iocs_from_cef(parsed)

    ioc_types = {i["ioc_type"] for i in iocs}
    assert "ip" in ioc_types
    assert "domain" in ioc_types
    assert "hash-sha256" in ioc_types
    assert len(iocs) == 4  # src, dst, dhost, fileHash

    # All should have value_hash
    for ioc in iocs:
        assert "value_hash" in ioc
        assert len(ioc["value_hash"]) == 64  # SHA-256 hex


def test_cef_extract_skips_empty():
    """extract_iocs_from_cef should skip empty/null extension values."""
    from nur.integrations.syslog_listener import parse_cef, extract_iocs_from_cef

    msg = "CEF:0|V|P|1|1|E|5|src=10.0.0.1 dst=- dhost=N/A"
    parsed = parse_cef(msg)
    iocs = extract_iocs_from_cef(parsed)

    assert len(iocs) == 1  # Only src
    assert iocs[0]["ioc_type"] == "ip"


def test_syslog_listener_init():
    """SyslogListener should initialize with correct defaults."""
    from nur.integrations.syslog_listener import SyslogListener

    listener = SyslogListener(port=9514, api_url="http://test:8000", api_key="k")
    assert listener.port == 9514
    assert listener.api_url == "http://test:8000"
    assert listener.api_key == "k"
    assert listener.stats["total_received"] == 0
    assert listener.stats["total_submitted"] == 0
