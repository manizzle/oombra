"""Tests for PACER court records scraper."""
from nur.feeds.pacer import case_to_nur_payload, generate_totp


class TestPACERScraper:
    def test_case_to_payload(self):
        case = {
            "case_number": "1:24-cv-01234",
            "case_title": "Smith v. Corp",
            "court": "NYSD",
            "filing_date": "2024-06-15",
        }
        payload = case_to_nur_payload(case)
        assert payload["source"] == "pacer-court-records"
        assert len(payload["techniques"]) >= 1
        assert payload["severity"] == "high"

    def test_totp_generation(self):
        # Test with a known secret
        secret = b"12345678901234567890"
        token = generate_totp(secret)
        assert len(token) == 6
        assert token.isdigit()

    def test_totp_deterministic_within_period(self):
        secret = b"testsecret12345"
        t1 = generate_totp(secret)
        t2 = generate_totp(secret)
        assert t1 == t2  # same 30-second window
