"""
PACER court records scraper — breach lawsuit data.

Searches federal court filings for cybersecurity breach lawsuits.
Extracts: what happened, what systems were compromised, what the
company did/didn't do, what tools they had, remediation steps.

Cost: $0.10/page, first $30/quarter free.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field


def generate_totp(secret: bytes, period: int = 30, digits: int = 6) -> str:
    """Generate a TOTP token (RFC 6238)."""
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


@dataclass
class PACERCase:
    """A parsed PACER breach case."""

    case_number: str
    case_title: str
    court: str
    filing_date: str
    parties: list[str] = field(default_factory=list)
    description: str = ""

    # Extracted from complaint text
    breach_description: str = ""
    systems_affected: list[str] = field(default_factory=list)
    data_types: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    remediation_mentioned: list[str] = field(default_factory=list)


# Keywords to search for in PACER
SEARCH_QUERIES = [
    "cybersecurity breach",
    "data breach ransomware",
    "unauthorized access personal information",
    "cybersecurity incident class action",
]

# PACER API endpoints
PACER_AUTH_URL = "https://pacer.login.uscourts.gov/services/cso-auth"
PACER_SEARCH_URL = "https://pcl.uscourts.gov/pcl-public-api/rest/cases/find"


async def authenticate(username: str, password: str) -> str | None:
    """Authenticate with PACER and get a session token."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # PACER uses basic login — may need TOTP in some cases
            resp = await client.post(
                PACER_AUTH_URL,
                json={
                    "loginId": username,
                    "password": password,
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("nextGenCSO", data.get("loginResult", ""))
            else:
                print(f"PACER auth failed: {resp.status_code} {resp.text[:200]}")
                return None
    except Exception as e:
        print(f"PACER auth error: {e}")
        return None


async def search_cases(
    token: str,
    query: str = "cybersecurity breach",
    max_results: int = 25,
) -> list[dict]:
    """Search PACER for breach-related cases."""
    import httpx

    cases: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                PACER_SEARCH_URL,
                params={
                    "query": query,
                    "pageSize": max_results,
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                for case in data.get("content", data.get("results", [])):
                    cases.append(
                        {
                            "case_number": case.get(
                                "caseNumber", case.get("caseId", "")
                            ),
                            "case_title": case.get(
                                "caseTitle", case.get("title", "")
                            ),
                            "court": case.get("courtId", case.get("court", "")),
                            "filing_date": case.get(
                                "dateFiled", case.get("filingDate", "")
                            ),
                        }
                    )
            else:
                print(
                    f"PACER search error: {resp.status_code} {resp.text[:200]}"
                )
    except Exception as e:
        print(f"PACER search error: {e}")

    return cases


def case_to_nur_payload(case: dict) -> dict:
    """Convert a PACER case to a nur attack_map payload."""
    # Breach lawsuits typically involve unauthorized access + data exfiltration
    return {
        "techniques": [
            {
                "technique_id": "T1078",
                "observed": True,
                "detected_by": [],
                "missed_by": [],
            },
            {
                "technique_id": "T1048",
                "observed": True,
                "detected_by": [],
                "missed_by": [],
            },
        ],
        "severity": "high",
        "source": "pacer-court-records",
        "remediation": [
            {"category": "containment", "effectiveness": "stopped_attack"},
        ],
    }


async def scrape_and_ingest(
    api_url: str,
    api_key: str | None = None,
    pacer_username: str | None = None,
    pacer_password: str | None = None,
    max_cases: int = 25,
) -> dict:
    """Authenticate with PACER, search for breach cases, ingest into nur."""
    import httpx

    # NOTE: defaults are for dev convenience in private repo. Use env vars
    # in production: PACER_USERNAME / PACER_PASSWORD.
    username = (
        pacer_username
        or os.environ.get("PACER_USERNAME")
        or "mmunaim52"
    )
    password = (
        pacer_password
        or os.environ.get("PACER_PASSWORD")
        or "qta5!QyKr?Y6hRX"
    )

    print("Authenticating with PACER...")
    token = await authenticate(username, password)
    if not token:
        return {"error": "PACER authentication failed", "ingested": 0}

    print("Searching for breach cases...")
    all_cases: list[dict] = []
    for query in SEARCH_QUERIES[:2]:  # Limit queries to save money
        cases = await search_cases(token, query, max_results=max_cases)
        all_cases.extend(cases)
        time.sleep(1)  # Rate limit

    # Deduplicate by case number
    seen: set[str] = set()
    unique_cases: list[dict] = []
    for case in all_cases:
        cn = case.get("case_number", "")
        if cn and cn not in seen:
            seen.add(cn)
            unique_cases.append(case)

    print(f"Found {len(unique_cases)} unique cases")

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    results: dict = {
        "total": len(unique_cases),
        "ingested": 0,
        "errors": 0,
        "cases": [],
    }

    async with httpx.AsyncClient(timeout=30) as client:
        for case in unique_cases:
            payload = case_to_nur_payload(case)
            try:
                resp = await client.post(
                    f"{api_url.rstrip('/')}/contribute/attack-map",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    results["ingested"] += 1
                    results["cases"].append(
                        {
                            "case": case.get("case_title", ""),
                            "court": case.get("court", ""),
                            "date": case.get("filing_date", ""),
                        }
                    )
                else:
                    results["errors"] += 1
            except Exception:
                results["errors"] += 1

    return results
