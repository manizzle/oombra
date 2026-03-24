"""
SEC EDGAR cybersecurity breach scraper.

Scrapes Form 8-K Item 1.05 filings for cybersecurity incident disclosures.
Extracts: company name, filing date, incident description, remediation steps,
MITRE techniques (if identifiable), timeline.

All data is public — SEC filings are public records.

EDGAR API: https://efts.sec.gov/LATEST/search-index?q=%22item+1.05%22&dateRange=custom&startdt=2024-01-01&enddt=2026-12-31&forms=8-K
Full-text search: https://efts.sec.gov/LATEST/search-index?q=%22cybersecurity+incident%22+%228-K%22
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BreachFiling:
    """A parsed SEC 8-K cybersecurity incident filing."""

    company: str
    ticker: str | None
    cik: str
    filing_date: str
    accession_number: str

    # Extracted from filing text
    incident_description: str = ""
    incident_date: str | None = None
    systems_affected: list[str] = field(default_factory=list)
    data_types_affected: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    third_parties_involved: list[str] = field(default_factory=list)  # forensics firms, law firms
    estimated_impact: str | None = None

    # Mapped to nur categories
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs if identifiable
    severity: str = "high"  # material by definition (that's why they filed)
    remediation_categories: list[str] = field(default_factory=list)  # containment, detection, etc.


# Keywords for extracting MITRE techniques from filing text
TECHNIQUE_KEYWORDS: dict[str, str] = {
    "phishing": "T1566",
    "spear phishing": "T1566.001",
    "ransomware": "T1486",
    "encrypted": "T1486",
    "data exfiltration": "T1048",
    "exfiltrated": "T1048",
    "unauthorized access": "T1078",
    "credential": "T1078",
    "remote access": "T1133",
    "vpn": "T1133",
    "lateral movement": "T1021",
    "rdp": "T1021.001",
    "malware": "T1059",
    "command and control": "T1071",
    "c2": "T1071",
    "supply chain": "T1195",
    "third-party": "T1195",
    "social engineering": "T1566",
    "brute force": "T1110",
    "vulnerability": "T1190",
    "exploit": "T1190",
    "zero-day": "T1190",
    "privilege escalation": "T1068",
    "data destruction": "T1485",
    "denial of service": "T1498",
    "ddos": "T1498",
}

REMEDIATION_KEYWORDS: dict[str, list[str]] = {
    "containment": ["contained", "isolated", "quarantined", "shut down", "disabled", "blocked"],
    "detection": ["detected", "discovered", "identified", "monitoring", "alert"],
    "eradication": ["removed", "eradicated", "eliminated", "cleaned", "patched", "remediated"],
    "recovery": ["restored", "recovered", "rebuilt", "backup", "resumed operations"],
    "prevention": ["implemented", "enhanced", "strengthened", "deployed", "upgraded", "mfa", "multi-factor"],
}


async def search_edgar_filings(
    start_date: str = "2024-01-01",
    end_date: str = "2026-12-31",
    max_results: int = 100,
) -> list[dict]:
    """Search SEC EDGAR for 8-K cybersecurity incident filings."""
    import httpx

    url = "https://efts.sec.gov/LATEST/search-index"
    params = {
        "q": '"item 1.05" OR "cybersecurity incident"',
        "forms": "8-K",
        "dateRange": "custom",
        "startdt": start_date,
        "enddt": end_date,
    }
    headers = {
        "User-Agent": "nur-research contact@saramena.us",
        "Accept": "application/json",
    }

    filings: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                for hit in hits[:max_results]:
                    source = hit.get("_source", {})
                    filings.append({
                        "company": source.get("display_names", ["Unknown"])[0] if source.get("display_names") else "Unknown",
                        "cik": source.get("entity_id", ""),
                        "filing_date": source.get("file_date", ""),
                        "accession_number": source.get("file_num", ""),
                        "form_type": source.get("form_type", ""),
                    })
    except Exception as e:
        print(f"EDGAR search error: {e}")

    return filings


async def fetch_filing_text(cik: str, accession_number: str) -> str:
    """Fetch the full text of an 8-K filing from EDGAR."""
    import httpx

    # Clean accession number for URL
    acc_clean = accession_number.replace("-", "")
    url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc_clean}/{accession_number}.txt"
    headers = {"User-Agent": "nur-research contact@saramena.us"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.text
    except Exception:
        pass
    return ""


def extract_techniques(text: str) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from filing text."""
    text_lower = text.lower()
    found: set[str] = set()
    for keyword, technique_id in TECHNIQUE_KEYWORDS.items():
        if keyword in text_lower:
            found.add(technique_id)
    return sorted(found)


def extract_remediation_categories(text: str) -> list[str]:
    """Extract remediation categories from filing text."""
    text_lower = text.lower()
    found: set[str] = set()
    for category, keywords in REMEDIATION_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                found.add(category)
                break
    return sorted(found)


def extract_timeline(text: str) -> str | None:
    """Try to extract incident date from filing text."""
    # Look for common date patterns near incident keywords
    patterns = [
        r"(?:discovered|detected|identified|occurred|began)\s+(?:[\w\s]{0,30}?)(?:on\s+)?(\w+\s+\d{1,2},?\s+\d{4})",
        r"(?:on|around|approximately)\s+(\w+\s+\d{1,2},?\s+\d{4})\s*,?\s*(?:the company|we|the registrant)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def parse_filing(
    company: str,
    cik: str,
    filing_date: str,
    accession_number: str,
    text: str,
) -> BreachFiling:
    """Parse a filing into a structured BreachFiling."""
    # Extract a summary (first 1000 chars of the Item 1.05 section)
    item_match = re.search(
        r"item\s+1\.05(.*?)(?:item\s+\d|signature|$)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    description = ""
    if item_match:
        raw = item_match.group(1).strip()
        # Clean HTML tags
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = re.sub(r"\s+", " ", raw).strip()
        description = raw[:1000]

    return BreachFiling(
        company=company,
        ticker=None,
        cik=cik,
        filing_date=filing_date,
        accession_number=accession_number,
        incident_description=description,
        incident_date=extract_timeline(text),
        techniques=extract_techniques(text),
        remediation_categories=extract_remediation_categories(text),
        severity="high",
    )


def filing_to_nur_payload(filing: BreachFiling) -> dict:
    """Convert a BreachFiling into a nur attack_map contribution payload."""
    techniques = []
    for tid in filing.techniques:
        techniques.append({
            "technique_id": tid,
            "observed": True,
            "detected_by": [],
            "missed_by": [],
        })

    remediation = []
    for cat in filing.remediation_categories:
        remediation.append({
            "category": cat,
            "effectiveness": "stopped_attack",  # they're still here to file, so it eventually worked
        })

    return {
        "techniques": techniques if techniques else [{"technique_id": "T1190", "observed": True, "detected_by": [], "missed_by": []}],
        "severity": filing.severity,
        "source": "sec-edgar-8k",
        "remediation": remediation,
    }


async def scrape_and_ingest(
    api_url: str,
    api_key: str | None = None,
    max_filings: int = 50,
) -> dict:
    """Scrape SEC EDGAR and ingest filings into nur."""
    import httpx

    print("Searching SEC EDGAR for cybersecurity 8-K filings...")
    filings_meta = await search_edgar_filings(max_results=max_filings)
    print(f"Found {len(filings_meta)} filings")

    results: dict[str, Any] = {"total": len(filings_meta), "ingested": 0, "errors": 0, "filings": []}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    for meta in filings_meta:
        try:
            # Rate limit — SEC asks for max 10 req/sec
            time.sleep(0.2)

            text = await fetch_filing_text(meta["cik"], meta.get("accession_number", ""))
            if not text:
                results["errors"] += 1
                continue

            filing = parse_filing(
                company=meta["company"],
                cik=meta["cik"],
                filing_date=meta["filing_date"],
                accession_number=meta.get("accession_number", ""),
                text=text,
            )

            payload = filing_to_nur_payload(filing)

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{api_url.rstrip('/')}/contribute/attack-map",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    results["ingested"] += 1
                    results["filings"].append({
                        "company": filing.company,
                        "date": filing.filing_date,
                        "techniques": filing.techniques,
                        "remediation": filing.remediation_categories,
                    })
                else:
                    results["errors"] += 1
        except Exception as e:
            print(f"Error processing {meta.get('company', '?')}: {e}")
            results["errors"] += 1

    return results
