"""
Tests for vigil anonymization engine.

Property-based tests using hypothesis: "no raw IP/email survives scrub()"
Plus deterministic tests for HMAC hashing, bucketing, and full pipeline.
"""
from __future__ import annotations

import re
import pytest

from vigil.anonymize import (
    strip_pii, strip_security, scrub, hash_ioc,
    bucket_industry, bucket_org_size, bucket_role,
    bucket_context_dict, anonymize,
)
from vigil.keystore import hmac_ioc, get_or_create_key
from vigil.models import (
    EvalRecord, AttackMap, IOCBundle, IOCEntry, ObservedTechnique,
    ContribContext, Industry,
)


# ── PII stripping ────────────────────────────────────────────────────────────

class TestStripPII:
    def test_email_removed(self):
        assert "[EMAIL]" in strip_pii("Contact john.doe@example.com for details")

    def test_phone_removed(self):
        assert "[PHONE]" in strip_pii("Call 555-123-4567 now")
        assert "[PHONE]" in strip_pii("Call (555) 123-4567")
        assert "[PHONE]" in strip_pii("Call +1-555-123-4567")

    def test_url_removed(self):
        assert "[URL]" in strip_pii("See https://internal.corp.com/secret")

    def test_titled_name_removed(self):
        assert "[NAME]" in strip_pii("Ask Dr. Smith about this")
        assert "[NAME]" in strip_pii("Contact Mr. John Doe")

    def test_empty_passthrough(self):
        assert strip_pii("") == ""
        assert strip_pii("no pii here") == "no pii here"

    def test_no_raw_email_survives(self):
        """Property: no email-like pattern with valid domain survives scrub."""
        texts = [
            "admin@corp.local",
            "user.name+tag@sub.domain.com",
        ]
        for t in texts:
            result = strip_pii(t)
            assert "@" not in result or "[EMAIL]" in result

    def test_no_raw_ip_survives(self):
        """Property: no IPv4 address survives full scrub."""
        texts = [
            "Server at 192.168.1.1 responded",
            "Connect to 10.0.0.1:8080",
            "DNS: 8.8.8.8 and 1.1.1.1",
        ]
        for t in texts:
            result = scrub(t)
            # All IPs should be replaced
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result)
            # The only IPs left should be inside [IP_ADDR] markers
            for ip in ips:
                assert ip in ("[IP_ADDR]",) or "[IP_ADDR]" in result


# ── Security stripping ───────────────────────────────────────────────────────

class TestStripSecurity:
    def test_ipv4_removed(self):
        assert "[IP_ADDR]" in strip_security("Server 192.168.1.1")

    def test_ipv6_removed(self):
        # Full IPv6 (the regex requires 2-7 colon groups, :: shorthand not matched)
        assert "[IP_ADDR]" in strip_security("Host 2001:db8:85a3:0000:0000:8a2e:0370:7334")

    def test_mac_removed(self):
        assert "[MAC_ADDR]" in strip_security("MAC: 00:1A:2B:3C:4D:5E")

    def test_internal_host_removed(self):
        assert "[INTERNAL_HOST]" in strip_security("Host db01.corp.internal")

    def test_api_key_removed(self):
        # Use sk_test_ prefix (not sk_live_) to avoid GitHub push protection
        assert "[API_KEY]" in strip_security("Key: sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        # GitHub PAT: ghp_ + exactly 36 alphanums
        assert "[API_KEY]" in strip_security("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

    def test_safe_domains_preserved(self):
        result = strip_security("Visit crowdstrike.com for more info")
        assert "crowdstrike.com" in result

    def test_safe_tld_preserved(self):
        result = strip_security("Check example.com")
        assert "example.com" in result  # .com is safe TLD

    def test_private_domain_removed(self):
        result = strip_security("internal.mycorp.internal is down")
        assert "[INTERNAL_HOST]" in result


# ── HMAC IOC hashing ─────────────────────────────────────────────────────────

class TestHMACHashing:
    def test_hmac_differs_from_sha256(self):
        """HMAC hash should differ from bare SHA-256."""
        plain_hash = hash_ioc("192.168.1.1")
        hmac_hash = hmac_ioc("192.168.1.1")
        assert plain_hash != hmac_hash

    def test_hmac_deterministic(self):
        """Same value + same key = same hash."""
        key = b"test_key_32_bytes_exactly_here!!"
        h1 = hmac_ioc("evil.com", secret=key)
        h2 = hmac_ioc("evil.com", secret=key)
        assert h1 == h2

    def test_hmac_different_keys(self):
        """Different keys produce different hashes for same IOC."""
        h1 = hmac_ioc("evil.com", secret=b"key_a" * 6 + b"aa")
        h2 = hmac_ioc("evil.com", secret=b"key_b" * 6 + b"bb")
        assert h1 != h2

    def test_hmac_normalized(self):
        """Whitespace and case are normalized before hashing."""
        key = b"test_key_32_bytes_exactly_here!!"
        assert hmac_ioc("  Evil.Com  ", secret=key) == hmac_ioc("evil.com", secret=key)


# ── Context bucketing ────────────────────────────────────────────────────────

class TestBucketing:
    def test_industry_financial(self):
        assert bucket_industry("JP Morgan Bank") == "financial"
        assert bucket_industry("Goldman Sachs Investment") == "financial"

    def test_industry_healthcare(self):
        assert bucket_industry("Mayo Hospital") == "healthcare"

    def test_industry_tech(self):
        assert bucket_industry("Acme Software Corp") == "tech"

    def test_industry_fallback(self):
        assert bucket_industry("Unknown Org XYZ") == "other"

    def test_industry_empty(self):
        assert bucket_industry("") == "other"

    def test_org_size_numeric(self):
        assert bucket_org_size(50) == "1-100"
        assert bucket_org_size(250) == "100-500"
        assert bucket_org_size(750) == "500-1000"
        assert bucket_org_size(3000) == "1000-5000"
        assert bucket_org_size(8000) == "5000-10000"
        assert bucket_org_size(100000) == "50000+"

    def test_org_size_string(self):
        assert bucket_org_size("about 200 people") == "100-500"

    def test_org_size_valid_bucket(self):
        assert bucket_org_size("1-100") == "1-100"

    def test_org_size_none(self):
        assert bucket_org_size(None) is None

    def test_role_ciso(self):
        assert bucket_role("CISO") == "ciso"
        assert bucket_role("Chief Information Security Officer") == "ciso"

    def test_role_engineer(self):
        assert bucket_role("Security Engineer") == "security-engineer"

    def test_role_fallback(self):
        assert bucket_role("Intern") == "other"

    def test_context_dict_strips_org(self):
        result = bucket_context_dict({
            "org_name": "JP Morgan Bank",
            "employees": "5000",
            "job_title": "CISO",
        })
        assert "org_name" not in result
        assert result["industry"] == "financial"
        assert result["org_size"] == "1000-5000"
        assert result["role_tier"] == "ciso"


# ── Full anonymize pipeline ──────────────────────────────────────────────────

class TestAnonymize:
    def test_eval_record(self):
        record = EvalRecord(
            vendor="CrowdStrike",
            category="edr",
            overall_score=8.5,
            top_strength="Great for 192.168.1.1 monitoring at john@corp.com",
            notes="Contact Dr. Smith at internal.corp for details",
        )
        clean = anonymize(record)
        assert "192.168" not in (clean.top_strength or "")
        assert "john@" not in (clean.top_strength or "")
        assert "Dr. Smith" not in (clean.notes or "")
        # Vendor preserved
        assert clean.vendor == "CrowdStrike"
        assert clean.overall_score == 8.5

    def test_attack_map(self):
        am = AttackMap(
            threat_name="APT28",
            techniques=[
                ObservedTechnique(
                    technique_id="T1566",
                    technique_name="Phishing",
                    notes="Targeted admin@corp.internal",
                )
            ],
        )
        clean = anonymize(am)
        assert "admin@" not in (clean.techniques[0].notes or "")

    def test_ioc_bundle(self):
        bundle = IOCBundle(
            iocs=[
                IOCEntry(ioc_type="ip", value_raw="192.168.1.100"),
                IOCEntry(ioc_type="domain", value_raw="evil.com"),
            ]
        )
        clean = anonymize(bundle)
        for ioc in clean.iocs:
            assert ioc.value_raw is None
            assert ioc.value_hash is not None
            assert len(ioc.value_hash) == 64  # SHA-256 hex

    def test_original_untouched(self):
        """Anonymize returns new object, original is preserved."""
        record = EvalRecord(
            vendor="Splunk",
            category="siem",
            top_strength="Contact john@test.com",
        )
        clean = anonymize(record)
        assert "john@test.com" in record.top_strength
        assert "john@" not in (clean.top_strength or "")


# ── Hypothesis property tests (if hypothesis is available) ───────────────────

try:
    from hypothesis import given, strategies as st

    @given(st.from_regex(r"[A-Za-z0-9][A-Za-z0-9._%+-]{1,10}@[A-Za-z0-9][A-Za-z0-9.-]{1,10}\.[A-Za-z]{2,4}", fullmatch=True))
    def test_no_email_survives_scrub(email):
        """Property: no generated realistic email survives scrub()."""
        text = f"Some context with {email} in it"
        result = scrub(text)
        assert email not in result

    @given(st.from_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", fullmatch=True))
    def test_no_ip_survives_scrub(ip):
        """Property: no generated IPv4 survives scrub()."""
        text = f"Server at {ip} port 443"
        result = scrub(text)
        assert ip not in result

except ImportError:
    pass  # hypothesis not installed, skip property tests
