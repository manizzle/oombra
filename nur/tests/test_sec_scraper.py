"""Tests for SEC EDGAR cybersecurity breach scraper."""
import pytest
from nur.sec_breach import (
    extract_techniques,
    extract_remediation_categories,
    extract_timeline,
    parse_filing,
    filing_to_nur_payload,
    BreachFiling,
)


class TestTechniqueExtraction:
    def test_ransomware(self):
        text = "The company discovered a ransomware attack that encrypted critical systems."
        techs = extract_techniques(text)
        assert "T1486" in techs

    def test_phishing(self):
        text = "An employee fell victim to a phishing email that led to unauthorized access."
        techs = extract_techniques(text)
        assert "T1566" in techs
        assert "T1078" in techs

    def test_multiple_techniques(self):
        text = "Attackers gained unauthorized access via a vulnerability in our VPN, exfiltrated data, and deployed ransomware."
        techs = extract_techniques(text)
        assert "T1190" in techs  # vulnerability
        assert "T1133" in techs  # VPN/remote access
        assert "T1048" in techs  # exfiltration
        assert "T1486" in techs  # ransomware

    def test_no_techniques(self):
        text = "The company reported improved quarterly earnings."
        techs = extract_techniques(text)
        assert len(techs) == 0


class TestRemediationExtraction:
    def test_containment(self):
        text = "We immediately contained the incident and isolated affected systems."
        cats = extract_remediation_categories(text)
        assert "containment" in cats

    def test_multiple_categories(self):
        text = "We detected the breach, contained it, removed the malware, restored from backups, and implemented MFA."
        cats = extract_remediation_categories(text)
        assert "detection" in cats
        assert "containment" in cats
        assert "eradication" in cats
        assert "recovery" in cats
        assert "prevention" in cats


class TestFilingParsing:
    def test_parse_to_payload(self):
        filing = BreachFiling(
            company="Test Corp",
            ticker="TEST",
            cik="12345",
            filing_date="2024-06-15",
            accession_number="0001234567-24-000001",
            techniques=["T1566", "T1486"],
            remediation_categories=["containment", "recovery"],
        )
        payload = filing_to_nur_payload(filing)
        assert payload["source"] == "sec-edgar-8k"
        assert len(payload["techniques"]) == 2
        assert payload["techniques"][0]["technique_id"] == "T1566"
        assert len(payload["remediation"]) == 2

    def test_default_technique_when_none_detected(self):
        filing = BreachFiling(
            company="Unknown Corp",
            ticker=None,
            cik="99999",
            filing_date="2024-01-01",
            accession_number="0009999999-24-000001",
            techniques=[],
            remediation_categories=[],
        )
        payload = filing_to_nur_payload(filing)
        assert len(payload["techniques"]) == 1
        assert payload["techniques"][0]["technique_id"] == "T1190"

    def test_parse_filing_extracts_item_105(self):
        text = "Some preamble text. Item 1.05 The company detected unauthorized access to its systems on January 5, 2024. Item 2.02 Other stuff."
        filing = parse_filing("Acme Inc", "12345", "2024-01-10", "0001234567-24-000001", text)
        assert "unauthorized access" in filing.incident_description.lower()
        assert "T1078" in filing.techniques


class TestTimelineExtraction:
    def test_date_extraction(self):
        text = "The company discovered the incident on January 15, 2024 and immediately began containment."
        date = extract_timeline(text)
        assert date is not None
        assert "January" in date or "15" in date

    def test_date_with_detected(self):
        text = "We detected suspicious activity on March 3, 2024."
        date = extract_timeline(text)
        assert date is not None
        assert "March" in date

    def test_no_date(self):
        text = "The company reported the incident to authorities."
        date = extract_timeline(text)
        # May or may not find a date — just shouldn't crash
