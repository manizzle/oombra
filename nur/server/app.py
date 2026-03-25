"""
FastAPI application — the nur server.

Endpoints:
  POST /contribute/submit       — receive EvalRecord
  POST /contribute/attack-map   — receive AttackMap
  POST /contribute/ioc-bundle   — receive IOCBundle
  POST /analyze                 — contribute AND get actionable intelligence
  GET  /health                  — liveness check
  GET  /stats                   — contribution counts (anonymized)
  GET  /query/*                 — aggregated read-side queries
  POST /secagg/*                — secure aggregation coordinator
  GET  /intelligence/*          — market maps, threat mapping, danger radar
  GET  /search/*                — enhanced vendor/category search, comparisons
"""
from __future__ import annotations

# Load secrets from AWS Secrets Manager before anything else reads env vars
from ..secrets import load_secrets
load_secrets()

import asyncio
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import json
import secrets as _secrets_mod

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .db import Database
from .proofs import ProofEngine
from .routes.query import router as query_router
from .routes.secagg import router as secagg_router
from .routes.intelligence import router as intel_router
from .routes.search import router as search_router
from .routes.tiers import router as tiers_router
from ..vendors import VENDORS


# ── App setup ────────────────────────────────────────────────────────────────

_db: Database | None = None


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


_proof_engine: ProofEngine | None = None

import hashlib as _hashlib_mod

from ..behavioral_dp import BehavioralProfile

_profiles: dict[str, BehavioralProfile] = {}


def get_or_create_profile(api_key: str | None, invited: bool = False) -> BehavioralProfile:
    """Get or create a behavioral profile for a participant.

    Key is SHA-256 of the API key — server never stores raw keys in profiles.
    Invited users get a small BDP credibility boost (techniques_corroborated=1).
    """
    if not api_key:
        return BehavioralProfile(participant_id="anonymous")
    pid = _hashlib_mod.sha256(api_key.encode()).hexdigest()[:16]
    if pid not in _profiles:
        _profiles[pid] = BehavioralProfile(
            participant_id=pid,
            first_seen_ts=time.time(),
            techniques_corroborated=1 if invited else 0,
        )
    _profiles[pid].last_seen_ts = time.time()
    return _profiles[pid]


def track_query(request: Request, query_type: str, vendors: list[str] | None = None):
    """Track a query for BDP behavioral profiling."""
    api_key = request.headers.get("X-API-Key")
    profile = get_or_create_profile(api_key)
    profile.query_types.add(query_type)
    if vendors:
        for v in vendors:
            profile.queried_vendors.add(v.lower())
    profile.total_queries += 1


def get_proof_engine() -> ProofEngine:
    global _proof_engine
    if _proof_engine is None:
        _proof_engine = ProofEngine()
    return _proof_engine


async def _feed_ingest_loop(app: FastAPI):
    """Background task: scrape public feeds every hour (if NUR_AUTO_INGEST=1)."""
    port = getattr(app.state, "port", 8000)
    while True:
        try:
            from ..feeds import scrape_all, bundle_iocs, ingest_to_server

            results = scrape_all()
            total = 0
            for feed_name, iocs in results.items():
                if not iocs:
                    continue
                bundles = bundle_iocs(iocs, feed_name)
                count = ingest_to_server(f"http://127.0.0.1:{port}", bundles)
                total += count
            if total > 0:
                print(f"  [feed-ingest] Ingested {total} bundles from public feeds")
        except Exception as e:
            print(f"  [feed-ingest] Error: {e}")
        await asyncio.sleep(3600)  # every hour


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db, _proof_engine, _profiles
    db_url = app.state.db_url if hasattr(app.state, "db_url") else "sqlite+aiosqlite:///nur.db"
    _db = Database(db_url)
    await _db.init()
    _proof_engine = ProofEngine()
    _profiles = {}

    # Start auto-ingest background task if enabled
    ingest_task = None
    if os.environ.get("NUR_AUTO_INGEST") == "1":
        ingest_task = asyncio.create_task(_feed_ingest_loop(app))
        print("  [feed-ingest] Auto-ingest enabled (every 60 min)")

    yield

    if ingest_task is not None:
        ingest_task.cancel()
        try:
            await ingest_task
        except asyncio.CancelledError:
            pass

    _profiles = {}
    _proof_engine = None
    await _db.close()
    _db = None


def create_app(db_url: str = "sqlite+aiosqlite:///nur.db") -> FastAPI:
    app = FastAPI(
        title="nur",
        description="Privacy-preserving federated threat intelligence server",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,       # disable Swagger UI
        redoc_url=None,      # disable ReDoc
    )
    app.state.db_url = db_url

    # ── API key + signature auth middleware ──────────────────────────────
    master_key = os.environ.get("NUR_API_KEY")

    @app.middleware("http")
    async def api_key_auth(request: Request, call_next):
        write_paths = (
                request.url.path.startswith("/contribute/")
                or request.url.path.startswith("/ingest/")
                or request.url.path == "/analyze"
            )
        if master_key and write_paths and request.method == "POST":
            provided = request.headers.get("X-API-Key")
            if not provided:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )
            # Accept master key OR any registered user key
            if not _secrets_mod.compare_digest(provided, master_key):
                from sqlalchemy import select
                from .models import APIKeyRecord
                try:
                    db = get_db()
                    async with db.session() as s:
                        result = await s.execute(
                            select(APIKeyRecord).where(APIKeyRecord.api_key == provided)
                        )
                        record = result.scalar_one_or_none()
                    if not record:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid or missing API key"},
                        )
                except Exception:
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Invalid or missing API key"},
                    )

            # Signature timestamp validation (replay prevention)
            sig_header = request.headers.get("X-Signature")
            if sig_header:
                try:
                    parts = sig_header.split(".", 1)
                    if len(parts) == 2:
                        ts = int(parts[0])
                        if abs(int(time.time()) - ts) > 300:
                            return JSONResponse(
                                status_code=401,
                                content={"error": "Signature expired (>5 min)"},
                            )
                except (ValueError, TypeError):
                    pass  # Don't fail the request on malformed signatures

        return await call_next(request)

    # ── Rate limiting middleware ──────────────────────────────────────────
    _rate_limits: dict[str, list[float]] = defaultdict(list)
    _COMMUNITY_LIMIT = 60   # requests per window
    _ENTERPRISE_LIMIT = 600  # future: per-key tier lookup
    _WINDOW = 60  # seconds

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if request.method == "POST":
            key = request.headers.get("X-API-Key", request.client.host if request.client else "unknown")
            now = time.time()
            # Prune timestamps outside the current window
            _rate_limits[key] = [t for t in _rate_limits[key] if now - t < _WINDOW]
            if len(_rate_limits[key]) >= _COMMUNITY_LIMIT:
                retry_after = int(_WINDOW - (now - _rate_limits[key][0])) + 1
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded", "retry_after": retry_after},
                )
            _rate_limits[key].append(now)
        return await call_next(request)

    app.include_router(query_router)
    app.include_router(secagg_router)
    app.include_router(intel_router)
    app.include_router(search_router)
    app.include_router(tiers_router)

    from .routes.verify import router as verify_router
    app.include_router(verify_router)

    from .routes.vendors import router as vendors_router
    app.include_router(vendors_router)

    # Conditionally include FL router
    try:
        from ..fl.server import router as fl_router
        app.include_router(fl_router)
    except ImportError:
        pass  # FL module not available (missing numpy)

    # ── Root ──────────────────────────────────────────────────────────

    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse)
    async def root():
        db = get_db()
        stats = await db.get_stats()
        total = stats.get("total_contributions", 0)
        vendors = stats.get("unique_vendors", 0)
        by_type = stats.get("by_type", {})
        iocs = by_type.get("ioc_bundle", 0)
        attacks = by_type.get("attack_map", 0)
        evals = by_type.get("eval", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-YLL9Y97GG0"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag('js',new Date());gtag('config','G-YLL9Y97GG0');</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: dark; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background:
      radial-gradient(circle at top, rgba(34, 197, 94, 0.12), transparent 32%),
      #0a0a0f;
    color: #e4e4e7;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
  }}
  a {{
    color: inherit;
    text-decoration: none;
  }}
  .page {{
    width: min(1100px, calc(100% - 48px));
    margin: 0 auto;
  }}
  .hero {{
    padding: 112px 0 88px;
    border-bottom: 1px solid #1e1e2e;
  }}
  .hero-grid {{
    display: grid;
    gap: 32px;
    align-items: end;
  }}
  h1 {{
    font-size: clamp(5.2rem, 15vw, 7rem);
    line-height: 0.95;
    color: #fafafa;
    letter-spacing: 0.3em;
    text-transform: lowercase;
    margin-left: 0.3em;
  }}
  .hero-subtitle {{
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #22c55e;
    margin-top: 20px;
  }}
  .hero-copy {{
    max-width: 680px;
    margin-top: 24px;
    font-size: 1.2rem;
    line-height: 1.7;
    color: #a1a1aa;
  }}
  .cta-row {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-top: 36px;
  }}
  .btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-width: 172px;
    padding: 16px 22px;
    border-radius: 999px;
    border: 1px solid #1e1e2e;
    font-size: 0.96rem;
    font-weight: 700;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease, color 0.2s ease;
  }}
  .btn:hover {{
    transform: translateY(-1px);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  .btn-primary {{
    background: #22c55e;
    border-color: #22c55e;
    color: #0a0a0f;
  }}
  .btn-secondary {{
    background: transparent;
    color: #fafafa;
  }}
  .btn-secondary:hover {{
    border-color: rgba(34, 197, 94, 0.5);
    color: #22c55e;
  }}
  .stats {{
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
    margin-top: 56px;
  }}
  .stat {{
    flex: 1 1 220px;
    min-width: 0;
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 18px;
    padding: 26px 24px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .stat:hover {{
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.4);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  .stat-num {{
    display: block;
    font-size: clamp(2.2rem, 5vw, 3rem);
    font-weight: 800;
    color: #fafafa;
    margin-bottom: 8px;
  }}
  .stat-label {{
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: #a1a1aa;
  }}
  .hero-meta {{
    margin-top: 24px;
    font-size: 0.95rem;
    line-height: 1.8;
    color: #a1a1aa;
  }}
  .section {{
    padding: 88px 0;
  }}
  .section-heading {{
    max-width: 720px;
    margin-bottom: 28px;
  }}
  .section-label {{
    display: inline-block;
    margin-bottom: 14px;
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #22c55e;
  }}
  .section-heading h2 {{
    font-size: clamp(2rem, 4vw, 3rem);
    color: #fafafa;
    margin-bottom: 14px;
  }}
  .section-heading p {{
    color: #a1a1aa;
    line-height: 1.8;
  }}
  .card-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 24px;
  }}
  .card {{
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 12px;
    padding: 32px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .card:hover {{
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.4);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  .card h3 {{
    color: #fafafa;
    font-size: 1.25rem;
    margin-bottom: 14px;
  }}
  .card p {{
    color: #a1a1aa;
    line-height: 1.8;
  }}
  .code-card {{
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 20px;
    padding: 32px;
    transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
  }}
  .code-card:hover {{
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.4);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  pre {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
    font-size: 0.98rem;
    line-height: 2;
    color: #e4e4e7;
    white-space: pre-wrap;
  }}
  .footer {{
    padding: 40px 0 56px;
    border-top: 1px solid #1e1e2e;
  }}
  .footer-links {{
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
  }}
  .footer-links a {{
    color: #a1a1aa;
    border-bottom: 1px solid transparent;
    padding-bottom: 2px;
    transition: color 0.2s ease, border-color 0.2s ease;
  }}
  .footer-links a:hover {{
    color: #22c55e;
    border-color: rgba(34, 197, 94, 0.4);
  }}
  .license {{
    margin-top: 18px;
    color: #a1a1aa;
    line-height: 1.8;
  }}
  .license a {{
    color: #fafafa;
  }}
  @media (max-width: 900px) {{
    .card-grid {{
      grid-template-columns: 1fr;
    }}
  }}
  @media (max-width: 640px) {{
    .page {{
      width: min(1100px, calc(100% - 32px));
    }}
    .hero {{
      padding: 88px 0 72px;
    }}
    h1 {{
      letter-spacing: 0.2em;
      margin-left: 0.2em;
    }}
    .btn {{
      width: 100%;
    }}
    .stat {{
      flex-basis: 100%;
    }}
    .section {{
      padding: 72px 0;
    }}
    .card,
    .code-card {{
      padding: 24px;
    }}
  }}
</style>
</head>
<body>
<main class="page">
  <section class="hero">
    <div class="hero-grid">
      <div>
        <h1>nur</h1>
        <div class="hero-subtitle">collective security intelligence</div>
        <p class="hero-copy">Your industry should be smarter together than any single company is alone.</p>
        <div class="cta-row">
          <a class="btn btn-primary" href="/register">Get Started <span>&rarr;</span></a>
          <a class="btn btn-secondary" href="/dashboard">Dashboard</a>
        </div>
        <div class="stats">
          <div class="stat">
            <span class="stat-num">{total}</span>
            <span class="stat-label">Contributions</span>
          </div>
          <div class="stat">
            <span class="stat-num">{iocs + attacks}</span>
            <span class="stat-label">Threat Signals</span>
          </div>
          <div class="stat">
            <span class="stat-num">36</span>
            <span class="stat-label">Vendors</span>
          </div>
        </div>
        <p class="hero-meta">Built from {iocs} IOC bundles, {attacks} attack maps, and {evals} vendor evaluations. {vendors} unique vendors currently appear in contributed data.</p>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="section-heading">
      <span class="section-label">How It Works</span>
      <h2>Contribute once. Query forever. Verify every result.</h2>
      <p>nur is designed so industries can exchange signal without turning raw incident data into another product for someone else.</p>
    </div>
    <div class="card-grid">
      <article class="card">
        <h3>Contribute</h3>
        <p>Upload anonymized evals, attack maps, or IOCs. Your data is committed, aggregated, and individual values are discarded.</p>
      </article>
      <article class="card">
        <h3>Query</h3>
        <p>Get vendor benchmarks, detection gaps, and remediation intel &mdash; all from aggregate histograms, never individual data.</p>
      </article>
      <article class="card">
        <h3>Verify</h3>
        <p>Every aggregate comes with a cryptographic proof. Merkle trees, commitment hashes, server signatures. Math, not promises.</p>
      </article>
    </div>
  </section>

  <section class="section">
    <div class="section-heading">
      <span class="section-label">Quick Start</span>
      <h2>CLI in four lines.</h2>
      <p>Install the client, initialize your key material locally, register your work email, then contribute an incident report.</p>
    </div>
    <div class="code-card">
      <pre>pip install nur
nur init
nur register you@yourorg.com
nur report incident.json</pre>
    </div>
  </section>

  <footer class="footer">
    <div class="footer-links">
      <a href="/dashboard">dashboard</a>
      <a href="/guide">docs/guide</a>
      <a href="https://github.com/manizzle/nur">github</a>
      <a href="/register">register</a>
    </div>
    <div class="license">
      Attackers share everything. Defenders should be able to share proofs instead of trust.
      <br>
      <a href="https://github.com/manizzle/nur">apache 2.0</a> &bull; <a href="https://github.com/manizzle/nur/blob/main/DATA_LICENSE.md">cdla-permissive-2.0</a>
    </div>
  </footer>
</main>
</body>
</html>"""

    # ── Register ─────────────────────────────────────────────────────

    # Free email providers that can't be used for registration
    _FREE_EMAIL_DOMAINS = {
        "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
        "live.com", "aol.com", "icloud.com", "me.com", "mac.com",
        "mail.com", "protonmail.com", "proton.me", "tutanota.com", "tuta.io",
        "yandex.com", "yandex.ru", "gmx.com", "gmx.net", "zoho.com",
        "fastmail.com", "hushmail.com", "inbox.com", "mail.ru",
        "163.com", "qq.com", "naver.com", "daum.net",
        "guerrillamail.com", "tempmail.com", "throwaway.email",
        "mailinator.com", "sharklasers.com", "guerrillamailblock.com",
        "grr.la", "dispostable.com", "yopmail.com", "temp-mail.org",
    }

    @app.post("/register")
    async def register(body: dict[str, Any]):
        """Register for a free API key. Work email required."""
        import secrets as _secrets
        from sqlalchemy import select
        from .models import APIKeyRecord

        email = (body.get("email") or "").strip().lower()
        org = (body.get("org") or "").strip()
        invite_code = (body.get("invite_code") or "").strip()
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email required")

        # Block free/personal email providers (unless they have an invite code)
        domain = email.split("@")[1]
        if domain in _FREE_EMAIL_DOMAINS and not invite_code:
            raise HTTPException(
                status_code=400,
                detail=f"Work email required. {domain} is not accepted. Use your organization's email or an invite code.",
            )

        db = get_db()
        async with db.session() as s:
            # Check if already registered
            existing = await s.execute(
                select(APIKeyRecord).where(APIKeyRecord.email == email)
            )
            record = existing.scalar_one_or_none()
            if record:
                # Don't reveal that email exists — return same response as new registration
                return {
                    "status": "pending",
                    "message": "If this email is registered, you'll receive a verification link.",
                }

            # Validate invite code if provided
            if invite_code:
                existing_inviter = await s.execute(
                    select(APIKeyRecord).where(APIKeyRecord.invite_codes.contains(invite_code))
                )
                inviter_record = existing_inviter.scalar_one_or_none()
                if not inviter_record:
                    raise HTTPException(status_code=400, detail="Invalid invite code.")

            # Create pending verification with magic link token
            from .models import PendingVerification
            token = _secrets.token_urlsafe(32)
            public_key = (body.get("public_key") or "")[:64] or None
            s.add(PendingVerification(email=email, org_name=org or None, token=token, public_key=public_key, invite_code=invite_code or None))

        # Build the magic link
        host = os.environ.get("NUR_DOMAIN", "nur.saramena.us")
        scheme = "https" if host != "localhost" else "http"
        verify_url = f"{scheme}://{host}/verify/{token}"

        # Try to send verification email
        from .email import send_verification_email
        email_sent = send_verification_email(email, verify_url)

        if email_sent:
            return {
                "status": "pending",
                "message": f"Verification email sent to {email}. Click the link to get your API key.",
            }
        else:
            return {
                "status": "pending",
                "verify_url": verify_url,
                "message": "Could not send email. Visit the link directly.",
            }

    @app.get("/verify/{token}", response_class=HTMLResponse)
    async def verify_email(token: str):
        """Magic link — click to verify email and get API key."""
        import secrets as _secrets
        from sqlalchemy import select
        from .models import PendingVerification, APIKeyRecord

        db = get_db()
        async with db.session() as s:
            result = await s.execute(
                select(PendingVerification).where(PendingVerification.token == token)
            )
            pending = result.scalar_one_or_none()
            if not pending:
                return """<!DOCTYPE html><html><body style="background:#1a1a1e;color:#d55;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><h1>invalid or expired link</h1><p><a href="/register" style="color:#888">try again</a></p></div></body></html>"""

            # Check token expiration (24 hours)
            created = pending.created_at
            if created is not None:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                if created < datetime.now(timezone.utc) - timedelta(hours=24):
                    return """<!DOCTYPE html><html><body style="background:#1a1a1e;color:#d55;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><h1>link expired</h1><p style="color:#888">This verification link has expired (24 hour limit).</p><p><a href="/register" style="color:#888">register again</a></p></div></body></html>"""

            if pending.verified:
                # Already verified — find the key
                existing = await s.execute(
                    select(APIKeyRecord).where(APIKeyRecord.email == pending.email)
                )
                record = existing.scalar_one_or_none()
                api_key = record.api_key if record else "already used"
            else:
                # Verify and create API key
                pending.verified = True
                api_key = "nur_" + _secrets.token_urlsafe(32)
                codes = [f"nur-inv-{_secrets.token_urlsafe(8)}" for _ in range(5)]
                new_record = APIKeyRecord(
                    email=pending.email, api_key=api_key,
                    org_name=pending.org_name, tier="community",
                    public_key=pending.public_key,
                    invite_codes=json.dumps(codes),
                    invited_by=pending.invite_code,
                )
                s.add(new_record)

                # Track invite chain — credit the inviter
                if pending.invite_code:
                    inv_result = await s.execute(
                        select(APIKeyRecord).where(
                            APIKeyRecord.invite_codes.contains(pending.invite_code)
                        )
                    )
                    inviter = inv_result.scalar_one_or_none()
                    if inviter:
                        # Remove used code from inviter's list
                        inviter_codes = json.loads(inviter.invite_codes) if inviter.invite_codes else []
                        if pending.invite_code in inviter_codes:
                            inviter_codes.remove(pending.invite_code)
                            inviter.invite_codes = json.dumps(inviter_codes)
                        inviter.invite_count = (inviter.invite_count or 0) + 1

                    # BDP credibility boost for invited users
                    get_or_create_profile(api_key, invited=True)

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>nur — verified</title>
<style>
  body {{ background:#1a1a1e; color:#c0c0c0; font-family:'Courier New',monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
  .box {{ text-align:center; max-width:500px; padding:40px; }}
  h1 {{ color:#2a5; margin-bottom:16px; }}
  .key {{ background:#111; border:1px solid #2a5; border-radius:4px; padding:16px; margin:24px 0; word-break:break-all; color:#2a5; font-size:1.1em; }}
  .steps {{ text-align:left; color:#888; font-size:0.9em; line-height:2; }}
  .steps code {{ color:#aaa; }}
  a {{ color:#666; }}
</style></head>
<body><div class="box">
  <h1>email verified</h1>
  <p>your API key:</p>
  <div class="key">{api_key}</div>
  <div class="steps">
    <code>pip install nur</code><br>
    <code>nur init</code> &larr; paste your key<br>
    <code>nur report incident.json</code><br>
  </div>
  <br><a href="/">&larr; back to nur</a>
</div></body></html>"""

    # ── Invites ────────────────────────────────────────────────────

    @app.get("/invites")
    async def get_invites(request: Request):
        """Get your invite codes."""
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(status_code=401, detail="API key required")
        db = get_db()
        from sqlalchemy import select
        from .models import APIKeyRecord
        async with db.session() as s:
            result = await s.execute(select(APIKeyRecord).where(APIKeyRecord.api_key == api_key))
            record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=401, detail="Invalid API key")
        codes = json.loads(record.invite_codes) if record.invite_codes else []
        return {
            "invite_codes": codes,
            "invite_count": record.invite_count or 0,
            "remaining": len(codes),
        }

    # ── Dashboard ──────────────────────────────────────────────────

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        db = get_db()
        stats = await db.get_stats()
        total = stats.get("total_contributions", 0)
        by_type = stats.get("by_type", {})
        iocs = by_type.get("ioc_bundle", 0)
        attacks = by_type.get("attack_map", 0)
        evals = by_type.get("eval", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — dashboard</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-YLL9Y97GG0"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag('js',new Date());gtag('config','G-YLL9Y97GG0');</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: dark; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background:
      radial-gradient(circle at top, rgba(34, 197, 94, 0.12), transparent 28%),
      #0a0a0f;
    color: #e4e4e7;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
    padding: 0;
  }}
  a {{
    color: inherit;
    text-decoration: none;
  }}

  /* ── Header ─────────────────────────────────────── */
  .dash-header {{
    max-width: 1240px;
    margin: 0 auto;
    padding: 96px 24px 40px;
    text-align: center;
  }}
  .dash-header h1 {{
    font-size: clamp(2.4rem, 6vw, 3.6rem);
    color: #fafafa;
    letter-spacing: 0.25em;
    margin-bottom: 18px;
  }}
  .dash-header h1 span {{
    color: #22c55e;
  }}
  .hero-stat {{
    font-size: clamp(4rem, 12vw, 6rem);
    font-weight: 800;
    color: #22c55e;
    line-height: 1;
    margin-bottom: 10px;
    text-shadow: 0 0 50px rgba(34, 197, 94, 0.2);
  }}
  .hero-label {{
    font-size: 0.9rem;
    color: #fafafa;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }}
  .dash-subtitle {{
    margin-top: 16px;
    font-size: 0.95rem;
    color: #a1a1aa;
  }}
  .pulse {{
    display: inline-block;
    width: 8px;
    height: 8px;
    background: #22c55e;
    border-radius: 50%;
    margin-right: 8px;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.35; }}
  }}

  /* ── Layout ─────────────────────────────────────── */
  .dash-grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 24px;
    max-width: 1240px;
    margin: 0 auto;
    padding: 0 24px 32px;
  }}
  .dash-section {{
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 20px;
    padding: 32px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .dash-section:hover {{
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  .dash-section:nth-child(odd) {{
    border-right: 1px solid #1e1e2e;
  }}
  .dash-section.full {{
    grid-column: 1 / -1;
  }}
  .section-title {{
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: #a1a1aa;
    margin-bottom: 22px;
  }}
  .section-title::before {{
    content: '/// ';
    color: #22c55e;
  }}

  /* ── Stat boxes ─────────────────────────────────── */
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
  }}
  .stat-box {{
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 24px 18px;
    text-align: center;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .stat-box:hover {{
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}
  .stat-box .num {{
    font-size: 2.35rem;
    font-weight: 800;
    color: #fafafa;
    display: block;
    line-height: 1.1;
  }}
  .stat-box .label {{
    font-size: 0.72rem;
    color: #a1a1aa;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin-top: 8px;
    display: block;
  }}

  /* ── Chart containers ───────────────────────────── */
  .chart-wrap {{
    position: relative;
    width: 100%;
    min-height: 360px;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 18px;
    padding: 20px;
  }}
  .chart-wrap canvas {{
    width: 100% !important;
  }}
  .chart-empty {{
    text-align: center;
    padding: 96px 16px;
    color: #a1a1aa;
    font-size: 0.95rem;
  }}
  .info-panel {{
    padding: 8px 0 0;
  }}
  .info-heading {{
    color: #fafafa;
    font-size: 1.3rem;
    font-weight: 600;
    margin-bottom: 14px;
  }}
  .info-copy {{
    color: #a1a1aa;
    font-size: 0.92rem;
    line-height: 1.9;
  }}
  .inline-link {{
    display: inline-flex;
    margin-top: 18px;
    color: #22c55e;
    border-bottom: 1px solid rgba(34, 197, 94, 0.3);
    padding-bottom: 3px;
    transition: border-color 0.2s ease, color 0.2s ease;
  }}
  .inline-link:hover {{
    border-color: #22c55e;
  }}
  .sim-card {{
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 16px 18px;
  }}
  .sim-card code,
  .cta-install code {{
    color: #e4e4e7;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
    font-size: 0.92rem;
    line-height: 1.9;
  }}

  /* ── CTA section ────────────────────────────────── */
  .cta {{
    text-align: center;
    padding: 56px 32px;
  }}
  .cta-tagline {{
    font-size: clamp(1.5rem, 4vw, 2rem);
    color: #fafafa;
    margin-bottom: 24px;
  }}
  .cta-install {{
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 18px;
    padding: 24px 28px;
    display: block;
    max-width: 420px;
    margin: 0 auto 28px;
    text-align: left;
  }}
  .cta-links {{
    display: flex;
    justify-content: center;
    gap: 20px;
    flex-wrap: wrap;
  }}
  .cta-links a {{
    color: #a1a1aa;
    border-bottom: 1px solid transparent;
    padding-bottom: 2px;
    transition: color 0.2s ease, border-color 0.2s ease;
    font-size: 0.92rem;
  }}
  .cta-links a:hover {{
    color: #22c55e;
    border-color: rgba(34, 197, 94, 0.35);
  }}
  .cta-btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: #22c55e;
    color: #0a0a0f;
    font-weight: 700;
    font-size: 0.96rem;
    padding: 14px 26px;
    border-radius: 999px;
    border: 1px solid #22c55e;
    text-decoration: none;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    margin-bottom: 22px;
  }}
  .cta-btn:hover {{
    transform: translateY(-1px);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }}

  /* ── Footer ─────────────────────────────────────── */
  .dash-footer {{
    text-align: center;
    padding: 8px 24px 56px;
    color: #a1a1aa;
    font-size: 0.8rem;
  }}
  .dash-footer a {{
    color: #fafafa;
  }}

  /* ── Responsive ─────────────────────────────────── */
  @media (max-width: 960px) {{
    .dash-grid {{
      grid-template-columns: 1fr;
    }}
    .dash-section.full {{
      grid-column: auto;
    }}
    .stat-grid {{
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
  }}
  @media (max-width: 640px) {{
    .dash-header {{
      padding: 84px 16px 32px;
    }}
    .dash-grid {{
      padding: 0 16px 24px;
    }}
    .dash-section,
    .cta {{
      padding: 24px;
    }}
    .stat-grid {{
      grid-template-columns: 1fr;
    }}
    .chart-wrap {{
      min-height: 320px;
      padding: 16px;
    }}
    .cta-btn {{
      width: 100%;
    }}
  }}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────── -->
<div class="dash-header">
  <h1>nur <span>dashboard</span></h1>
  <div class="hero-stat" id="hero-total">{total}</div>
  <div class="hero-label">contributions from the community</div>
  <div class="dash-subtitle">
    <span class="pulse"></span> 37 feeds &middot; 36 vendors &middot; live feeds &middot; auto-refresh 60s
  </div>
</div>

<!-- ── Charts row ─────────────────────────────────────────── -->
<div class="dash-grid">

  <!-- Threat Landscape -->
  <div class="dash-section">
    <div class="section-title">What People Are Sharing</div>
    <div class="chart-wrap">
      <canvas id="techniqueChart" height="320"></canvas>
      <div class="chart-empty" id="techniqueEmpty" style="display:none;">
        No submissions yet. Be the first to contribute.
      </div>
    </div>
  </div>

  <!-- Market Intelligence -->
  <div class="dash-section">
    <div class="section-title">Tools Under Evaluation</div>
    <div class="chart-wrap">
      <canvas id="marketChart" height="320"></canvas>
      <div class="chart-empty" id="marketEmpty" style="display:none;">
        No tool data yet. Share your evaluations to populate.
      </div>
    </div>
  </div>

  <!-- Live Activity -->
  <div class="dash-section full">
    <div class="section-title">Live Activity</div>
    <div class="stat-grid">
      <div class="stat-box">
        <span class="num" id="stat-total">{total}</span>
        <span class="label">total contributions</span>
      </div>
      <div class="stat-box">
        <span class="num" id="stat-iocs">{iocs}</span>
        <span class="label">IOC bundles</span>
      </div>
      <div class="stat-box">
        <span class="num" id="stat-attacks">{attacks}</span>
        <span class="label">attack maps</span>
      </div>
      <div class="stat-box">
        <span class="num" id="stat-evals">{evals}</span>
        <span class="label">tool evaluations</span>
      </div>
    </div>
  </div>

  <!-- Attack Intelligence -->
  <div class="dash-section">
    <div class="section-title">Attack Intelligence</div>
    <div class="info-panel">
      <div class="info-heading">Healthcare Ransomware</div>
      <div class="info-copy">
        Initial access: Spearphishing (89%)<br>
        Avg dwell time: 4.2 days<br>
        Most missed technique: T1490 (71%)<br>
        Ransom paid: 12% of cases<br>
        Avg recovery: 2.1 weeks
      </div>
      <a class="inline-link" href="/intelligence/patterns/healthcare">view all patterns &rarr;</a>
    </div>
  </div>

  <!-- Attack Chain Simulator -->
  <div class="dash-section">
    <div class="section-title">Attack Chain Simulator</div>
    <div class="info-panel">
      <div class="sim-card">
        <code>
          nur simulate &#92;<br>
          &nbsp;&nbsp;--stack crowdstrike,splunk,okta &#92;<br>
          &nbsp;&nbsp;--vertical healthcare
        </code>
      </div>
      <div class="info-copy" style="margin-top:16px;">
        Simulates the most common attack chain<br>
        against your tools. Shows exactly where<br>
        your defenses break.
      </div>
      <a class="inline-link" href="/intelligence/simulate">try via API &rarr;</a>
    </div>
  </div>

  <!-- CTA -->
  <div class="dash-section full cta">
    <div class="cta-tagline">give data, get smarter.</div>
    <div class="cta-install">
      <code>
        pip install nur<br>
        nur init<br>
        nur register you@yourorg.com<br>
        nur report incident.json
      </code>
    </div>
    <a class="cta-btn" href="/register">get started &rarr;</a>
    <div class="cta-links">
      <a href="/">home</a>
      <a href="/guide">docs</a>
      <a href="https://github.com/manizzle/nur">github</a>
    </div>
  </div>
</div>

<!-- ── Footer ─────────────────────────────────────────────── -->
<div class="dash-footer">
  <a href="/">nur</a> &bull; a social network for security intelligence &bull; product = protocol + users &bull;
  <a href="https://github.com/manizzle/nur">open source</a>
</div>

<script>
(function() {{
  // ── Color helpers ──────────────────────────────────────────
  function greenGradient(count, max) {{
    var ratio = max > 0 ? count / max : 0;
    var r = Math.round(18 + ratio * 16);
    var g = Math.round(92 + ratio * 105);
    var b = Math.round(45 + ratio * 49);
    return 'rgb(' + r + ',' + g + ',' + b + ')';
  }}

  // ── Chart.js global defaults ───────────────────────────────
  Chart.defaults.color = '#a1a1aa';
  Chart.defaults.borderColor = '#1e1e2e';
  Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";
  Chart.defaults.font.size = 12;

  // ── Submissions by type (donut chart) ────────────────────
  fetch('/stats')
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      var bt = data.by_type || {{}};
      var labels = [];
      var counts = [];
      var colors = ['#22c55e', '#16a34a', '#65a30d', '#14b8a6', '#84cc16'];
      var typeNames = {{
        'ioc_bundle': 'IOC Bundles',
        'attack_map': 'Attack Maps',
        'eval': 'Tool Evaluations',
      }};
      Object.keys(bt).forEach(function(k) {{
        labels.push(typeNames[k] || k);
        counts.push(bt[k]);
      }});
      if (counts.length === 0) {{
        document.getElementById('techniqueChart').style.display = 'none';
        document.getElementById('techniqueEmpty').style.display = 'block';
        return;
      }}
      new Chart(document.getElementById('techniqueChart'), {{
        type: 'doughnut',
        data: {{
          labels: labels,
          datasets: [{{
            data: counts,
            backgroundColor: colors.slice(0, counts.length),
            borderColor: '#0a0a0f',
            borderWidth: 3,
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          cutout: '60%',
          plugins: {{
            legend: {{
              position: 'bottom',
              labels: {{ color: '#a1a1aa', font: {{ size: 12, family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }}, padding: 16 }},
            }},
            tooltip: {{
              backgroundColor: '#111118',
              titleColor: '#fafafa',
              bodyColor: '#e4e4e7',
              borderColor: '#1e1e2e',
              borderWidth: 1,
              titleFont: {{ family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }},
              bodyFont: {{ family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }},
            }},
          }},
        }},
      }});
    }})
    .catch(function(e) {{
      document.getElementById('techniqueChart').style.display = 'none';
      document.getElementById('techniqueEmpty').style.display = 'block';
    }});

  // ── Tools by category (bar chart) ──────────────────────────
  // Show how many tools we track per category
  var catData = {{
    'EDR': 10, 'SIEM': 4, 'CNAPP': 3, 'IAM': 2, 'PAM': 3,
    'Email': 2, 'ZTNA': 3, 'Vuln Mgmt': 3, 'WAF': 3, 'NDR': 2, 'Threat Intel': 1,
  }};
  var catLabels = Object.keys(catData);
  var catCounts = Object.values(catData);
  var catColors = catCounts.map(function(c) {{ return greenGradient(c, 10); }});

  new Chart(document.getElementById('marketChart'), {{
    type: 'bar',
    data: {{
      labels: catLabels,
      datasets: [{{
        label: 'Vendors Tracked',
        data: catCounts,
        backgroundColor: catColors,
        borderColor: 'transparent',
        borderWidth: 0,
        borderRadius: 8,
      }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          backgroundColor: '#111118',
          titleColor: '#fafafa',
          bodyColor: '#e4e4e7',
          borderColor: '#1e1e2e',
          borderWidth: 1,
          titleFont: {{ family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }},
          bodyFont: {{ family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }},
        }},
      }},
      scales: {{
        x: {{
          grid: {{ color: '#1e1e2e' }},
          ticks: {{ color: '#a1a1aa', font: {{ family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }} }},
        }},
        y: {{
          grid: {{ display: false }},
          ticks: {{ color: '#e4e4e7', font: {{ size: 11, family: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" }} }},
        }},
      }},
    }},
  }});

  // ── Auto-refresh stats ─────────────────────────────────────
  function refreshStats() {{
    fetch('/stats')
      .then(function(r) {{ return r.json(); }})
      .then(function(s) {{
        var bt = s.by_type || {{}};
        document.getElementById('hero-total').textContent = s.total_contributions || 0;
        document.getElementById('stat-total').textContent = s.total_contributions || 0;
        document.getElementById('stat-iocs').textContent = bt.ioc_bundle || 0;
        document.getElementById('stat-attacks').textContent = bt.attack_map || 0;
        document.getElementById('stat-evals').textContent = bt.eval || 0;
      }})
      .catch(function(e) {{ console.error('stats refresh error:', e); }});
  }}
  setInterval(refreshStats, 60000);
}})();
</script>
</body>
</html>"""

    @app.get("/register", response_class=HTMLResponse)
    async def register_page():
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — get your API key</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-YLL9Y97GG0"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag("js",new Date());gtag("config","G-YLL9Y97GG0");</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background:
      radial-gradient(circle at top, rgba(34, 197, 94, 0.12), transparent 30%),
      #0a0a0f;
    color: #e4e4e7;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
  }
  a { color: inherit; text-decoration: none; }
  .page {
    width: min(1100px, calc(100% - 48px));
    margin: 0 auto;
    padding: 96px 0 72px;
  }
  .hero {
    padding-bottom: 56px;
  }
  .eyebrow {
    display: inline-block;
    margin-bottom: 18px;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #22c55e;
  }
  h1 {
    font-size: clamp(3rem, 8vw, 4.8rem);
    color: #fafafa;
    line-height: 1.02;
    margin-bottom: 14px;
  }
  .sub {
    max-width: 620px;
    color: #a1a1aa;
    font-size: 1.05rem;
    line-height: 1.8;
  }
  .content-grid {
    display: grid;
    grid-template-columns: 1.2fr 0.8fr;
    gap: 24px;
    padding: 24px 0 88px;
  }
  .card {
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 20px;
    padding: 32px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }
  .card:hover {
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }
  .card h2 {
    font-size: 1.4rem;
    color: #fafafa;
    margin-bottom: 18px;
  }
  pre, code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  }
  .install {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 24px;
  }
  .install code {
    display: block;
    color: #e4e4e7;
    font-size: 0.95rem;
    line-height: 2;
    white-space: pre-wrap;
  }
  .comment { color: #a1a1aa; }
  .cmd { color: #fafafa; }
  .why-list {
    list-style: none;
    display: grid;
    gap: 14px;
    color: #a1a1aa;
    line-height: 1.8;
  }
  .why-list li {
    position: relative;
    padding-left: 18px;
  }
  .why-list li::before {
    content: '';
    position: absolute;
    top: 0.8em;
    left: 0;
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: #22c55e;
  }
  .tiers-section {
    padding-top: 8px;
  }
  .tiers-heading {
    margin-bottom: 22px;
  }
  .tiers-heading span {
    display: inline-block;
    margin-bottom: 14px;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #22c55e;
  }
  .tiers-heading h2 {
    font-size: clamp(2rem, 4vw, 3rem);
    color: #fafafa;
    margin-bottom: 12px;
  }
  .tiers-heading p {
    color: #a1a1aa;
    line-height: 1.8;
  }
  .tiers {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 24px;
  }
  .tier {
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 20px;
    padding: 32px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }
  .tier:hover {
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }
  .tier-name {
    font-size: 1.2rem;
    color: #fafafa;
    margin-bottom: 8px;
  }
  .tier-price {
    font-size: 1.9rem;
    font-weight: 800;
    color: #22c55e;
    margin-bottom: 12px;
  }
  .tier-copy {
    color: #a1a1aa;
    line-height: 1.8;
    margin-bottom: 18px;
  }
  .tier ul {
    list-style: none;
    display: grid;
    gap: 12px;
    color: #e4e4e7;
    line-height: 1.7;
  }
  .tier li {
    position: relative;
    padding-left: 18px;
  }
  .tier li::before {
    content: '';
    position: absolute;
    top: 0.75em;
    left: 0;
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: rgba(34, 197, 94, 0.9);
  }
  .back-link {
    display: inline-flex;
    margin-top: 36px;
    color: #a1a1aa;
    border-bottom: 1px solid transparent;
    padding-bottom: 2px;
    transition: color 0.2s ease, border-color 0.2s ease;
  }
  .back-link:hover {
    color: #22c55e;
    border-color: rgba(34, 197, 94, 0.35);
  }
  @media (max-width: 960px) {
    .content-grid,
    .tiers {
      grid-template-columns: 1fr;
    }
  }
  @media (max-width: 640px) {
    .page {
      width: min(1100px, calc(100% - 32px));
      padding: 80px 0 56px;
    }
    .card,
    .tier {
      padding: 24px;
    }
    .install {
      padding: 18px;
    }
  }
</style>
</head>
<body>
<main class="page">
  <section class="hero">
    <div class="eyebrow">CLI-first registration</div>
    <h1>Get your API key</h1>
    <div class="sub">Register via the CLI. Generates a keypair on your machine.</div>
  </section>

  <section class="content-grid">
    <article class="card">
      <h2>Register in four commands</h2>
      <div class="install">
        <code><span class="comment"># install the client</span>
<span class="cmd">pip install nur</span>

<span class="comment"># save the server URL and generate a local keypair</span>
<span class="cmd">nur init</span>

<span class="comment"># register with your work email</span>
<span class="cmd">nur register you@yourhospital.org</span>

<span class="comment"># click the link in your inbox, then contribute</span>
<span class="cmd">nur report incident.json</span></code>
      </div>
    </article>

    <article class="card">
      <h2>Why CLI-only?</h2>
      <ul class="why-list">
        <li>Generates a cryptographic keypair on your machine</li>
        <li>Private key never leaves your machine</li>
        <li>Every request is signed — stolen API keys are useless</li>
        <li>Work email required (no gmail/yahoo)</li>
      </ul>
    </article>
  </section>

  <section class="tiers-section">
    <div class="tiers-heading">
      <span>Plans</span>
      <h2>Start free. Upgrade when you need guaranteed speed and support.</h2>
      <p>The community tier is enough to contribute data and receive collective intelligence. Paid tiers add response speed, support, and operational guarantees.</p>
    </div>

    <div class="tiers">
      <article class="tier">
        <div class="tier-name">Community</div>
        <div class="tier-price">Free forever</div>
        <div class="tier-copy">For teams that want to contribute data, query shared intelligence, and join the network.</div>
        <ul>
          <li>Contribute data</li>
          <li>Get intelligence</li>
          <li>37 feeds</li>
        </ul>
      </article>

      <article class="tier">
        <div class="tier-name">Pro</div>
        <div class="tier-price">$99/mo</div>
        <div class="tier-copy">For practitioners who need faster aggregate visibility and direct operator support.</div>
        <ul>
          <li>Real-time aggregates</li>
          <li>Priority support</li>
          <li>Custom alerts</li>
        </ul>
      </article>

      <article class="tier">
        <div class="tier-name">Enterprise</div>
        <div class="tier-price">$499/mo</div>
        <div class="tier-copy">For teams running nur as critical infrastructure inside a larger security program.</div>
        <ul>
          <li>Dedicated instance</li>
          <li>SLA</li>
          <li>Integrations</li>
          <li>Unlimited queries</li>
        </ul>
      </article>
    </div>

    <a class="back-link" href="/">&larr; Back to /</a>
  </section>
</main>
</body>
</html>"""

    # ── Health ────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    # ── Stats ─────────────────────────────────────────────────────────

    @app.get("/stats")
    async def stats():
        db = get_db()
        return await db.get_stats()

    # ── Contribute routes ─────────────────────────────────────────────

    @app.post("/contribute/submit")
    async def contribute_eval(body: dict[str, Any], request: Request):
        # Basic field validation for eval records
        d = body.get("data", body)
        vendor = d.get("vendor", "")
        if isinstance(vendor, str) and len(vendor) > 200:
            raise HTTPException(status_code=400, detail="Vendor name too long (max 200 chars)")
        category = d.get("category", "")
        if isinstance(category, str) and len(category) > 100:
            raise HTTPException(status_code=400, detail="Category too long (max 100 chars)")
        notes = d.get("notes", "")
        if isinstance(notes, str) and len(notes) > 10000:
            raise HTTPException(status_code=400, detail="Notes too long (max 10,000 chars)")
        db = get_db()
        cid = await db.store_eval_record(body)
        # BDP profile tracking
        _bdp_key = request.headers.get("X-API-Key")
        _bdp_profile = get_or_create_profile(_bdp_key)
        _bdp_profile.contribution_types.add("eval")
        _bdp_vendor = d.get("vendor", "")
        if _bdp_vendor:
            _bdp_profile.contributed_vendors.add(_bdp_vendor.lower())
        _bdp_profile.total_contributions += 1
        # Proof layer: translate → commit → receipt
        from .proofs import translate_eval
        engine = get_proof_engine()
        vendor, category, values = translate_eval(body)
        receipt = engine.commit_contribution(vendor, category, values)
        return {"status": "accepted", "contribution_id": cid, "receipt": receipt.to_dict()}

    @app.post("/contribute/attack-map")
    async def contribute_attack_map(body: dict[str, Any], request: Request):
        techniques = body.get("techniques", [])
        if len(techniques) > 500:
            raise HTTPException(status_code=400, detail="Too many techniques (max 500)")
        db = get_db()
        cid = await db.store_attack_map(body)
        # BDP profile tracking
        _bdp_profile = get_or_create_profile(request.headers.get("X-API-Key"))
        _bdp_profile.contribution_types.add("attack_map")
        _bdp_profile.total_contributions += 1
        # Proof layer
        from .proofs import translate_attack_map
        engine = get_proof_engine()
        params = translate_attack_map(body)
        receipt = engine.commit_attack_map(**params)
        return {"status": "accepted", "contribution_id": cid, "receipt": receipt.to_dict()}

    @app.post("/contribute/ioc-bundle")
    async def contribute_ioc_bundle(body: dict[str, Any], request: Request):
        iocs = body.get("iocs", [])
        if len(iocs) > 10000:
            raise HTTPException(status_code=400, detail="Too many IOCs (max 10,000)")
        db = get_db()
        cid = await db.store_ioc_bundle(body)
        # BDP profile tracking
        _bdp_profile = get_or_create_profile(request.headers.get("X-API-Key"))
        _bdp_profile.contribution_types.add("ioc_bundle")
        _bdp_profile.total_contributions += 1
        # Proof layer
        from .proofs import translate_ioc_bundle
        engine = get_proof_engine()
        ioc_count, ioc_types = translate_ioc_bundle(body)
        receipt = engine.commit_ioc_bundle(ioc_count, ioc_types)
        return {"status": "accepted", "contribution_id": cid, "receipt": receipt.to_dict()}

    # ── Webhook ingest (wartime integrations) ────────────────────────

    @app.post("/ingest/webhook")
    async def ingest_webhook(body: dict[str, Any], request: Request):
        """Universal webhook — accepts data from Splunk, Sentinel, CrowdStrike,
        syslog/CEF, or generic IOC lists. Auto-detects format and stores."""
        # BDP profile tracking
        _bdp_profile = get_or_create_profile(request.headers.get("X-API-Key"))
        _bdp_profile.contribution_types.add("webhook")
        if "detection" in body:
            _bdp_profile.integration_sources.add("crowdstrike")
        elif "properties" in body:
            _bdp_profile.integration_sources.add("sentinel")
        elif "cef" in body:
            _bdp_profile.integration_sources.add("cef")
        _bdp_profile.total_contributions += 1

        import hashlib

        db = get_db()
        items_stored = 0

        def _hash_ioc(value: str) -> str:
            return hashlib.sha256(value.strip().lower().encode()).hexdigest()

        # ── 1. CrowdStrike detection format ──────────────────────────
        if "detection" in body:
            det = body["detection"]
            technique = det.get("technique", "")
            tactic = det.get("tactic", "")
            severity = det.get("severity", "medium")

            # Store as attack_map if we have a technique
            if technique:
                attack_data = {
                    "threat_name": det.get("scenario", "CrowdStrike Detection"),
                    "techniques": [{
                        "technique_id": technique,
                        "tactic": tactic,
                        "observed": True,
                    }],
                    "source": "crowdstrike",
                    "severity": severity,
                }
                await db.store_attack_map(attack_data)
                items_stored += 1

            # Store IOC if present
            ioc_type = det.get("ioc_type")
            ioc_value = det.get("ioc_value")
            if ioc_type and ioc_value:
                ioc_data = {
                    "iocs": [{
                        "ioc_type": ioc_type,
                        "value_hash": _hash_ioc(ioc_value),
                    }],
                    "source": "crowdstrike",
                }
                await db.store_ioc_bundle(ioc_data)
                items_stored += 1

            # Proof layer
            from .proofs import translate_webhook_crowdstrike
            engine = get_proof_engine()
            translated = translate_webhook_crowdstrike(body)
            receipts = []
            if translated["attack_map_params"]:
                r = engine.commit_attack_map(**translated["attack_map_params"])
                receipts.append(r.to_dict())
            if translated["ioc_params"]:
                r = engine.commit_ioc_bundle(*translated["ioc_params"])
                receipts.append(r.to_dict())

            # Notify via Slack if configured
            slack_url = os.environ.get("NUR_SLACK_WEBHOOK")
            if slack_url and items_stored > 0:
                from .notifications import send_slack_notification, build_remediation_notification
                notif = build_remediation_notification(
                    format_detected="crowdstrike",
                    items_stored=items_stored,
                    engine_stats=engine.get_platform_stats(),
                )
                asyncio.create_task(send_slack_notification(slack_url, notif["title"], notif["fields"]))

            return {
                "status": "accepted",
                "format_detected": "crowdstrike",
                "items_stored": items_stored,
                "receipts": receipts,
            }

        # ── 2. Sentinel incident format ──────────────────────────────
        if "properties" in body:
            props = body["properties"]
            severity = props.get("severity", "Medium").lower()
            tactics = props.get("tactics", [])
            techniques_raw = props.get("techniques", [])
            entities = props.get("entities", [])

            # Convert tactics/techniques to attack_map
            if tactics or techniques_raw:
                technique_entries = []
                for t in techniques_raw:
                    technique_entries.append({
                        "technique_id": t if isinstance(t, str) else str(t),
                        "observed": True,
                    })
                # If we only have tactics but no techniques, store tactics as notes
                attack_data = {
                    "threat_name": props.get("title", "Sentinel Incident"),
                    "techniques": technique_entries,
                    "source": "sentinel",
                    "severity": severity,
                    "notes": f"Tactics: {', '.join(tactics)}" if tactics else None,
                }
                await db.store_attack_map(attack_data)
                items_stored += 1

            # Convert entities to IOC bundle
            iocs = []
            for entity in entities:
                if isinstance(entity, dict):
                    # Sentinel entity types: IP, Host, Account, FileHash, URL, etc.
                    kind = entity.get("kind", entity.get("type", "")).lower()
                    addr = entity.get("address") or entity.get("properties", {}).get("address")
                    host = entity.get("hostName") or entity.get("properties", {}).get("hostName")
                    fhash = entity.get("hashValue") or entity.get("properties", {}).get("hashValue")
                    url = entity.get("url") or entity.get("properties", {}).get("url")
                    name = entity.get("name", "")

                    if kind == "ip" and addr:
                        iocs.append({"ioc_type": "ip", "value_hash": _hash_ioc(addr)})
                    elif kind == "host" and host:
                        iocs.append({"ioc_type": "domain", "value_hash": _hash_ioc(host)})
                    elif kind in ("filehash", "hash") and fhash:
                        iocs.append({"ioc_type": "hash-sha256", "value_hash": _hash_ioc(fhash)})
                    elif kind == "url" and url:
                        iocs.append({"ioc_type": "url", "value_hash": _hash_ioc(url)})
                    elif addr:
                        iocs.append({"ioc_type": "ip", "value_hash": _hash_ioc(addr)})
                    elif host:
                        iocs.append({"ioc_type": "domain", "value_hash": _hash_ioc(host)})

            if iocs:
                ioc_data = {
                    "iocs": iocs,
                    "source": "sentinel",
                }
                await db.store_ioc_bundle(ioc_data)
                items_stored += 1

            # Proof layer
            from .proofs import translate_webhook_sentinel
            engine = get_proof_engine()
            translated = translate_webhook_sentinel(body)
            receipts = []
            if translated["attack_map_params"]:
                r = engine.commit_attack_map(**translated["attack_map_params"])
                receipts.append(r.to_dict())
            if translated["ioc_params"]:
                r = engine.commit_ioc_bundle(*translated["ioc_params"])
                receipts.append(r.to_dict())

            # Notify via Slack if configured
            slack_url = os.environ.get("NUR_SLACK_WEBHOOK")
            if slack_url and items_stored > 0:
                from .notifications import send_slack_notification, build_remediation_notification
                notif = build_remediation_notification(
                    format_detected="sentinel",
                    items_stored=items_stored,
                    engine_stats=engine.get_platform_stats(),
                )
                asyncio.create_task(send_slack_notification(slack_url, notif["title"], notif["fields"]))

            return {
                "status": "accepted",
                "format_detected": "sentinel",
                "items_stored": items_stored,
                "receipts": receipts,
            }

        # ── 3. CEF/Syslog format ────────────────────────────────────
        if "cef" in body:
            from ..integrations.syslog_listener import parse_cef, extract_iocs_from_cef

            cef_str = body["cef"]
            parsed = parse_cef(cef_str)
            if parsed:
                iocs = extract_iocs_from_cef(parsed)
                if iocs:
                    ioc_data = {
                        "iocs": iocs,
                        "source": f"cef:{parsed.get('vendor', 'unknown')}:{parsed.get('product', 'unknown')}",
                    }
                    await db.store_ioc_bundle(ioc_data)
                    items_stored += 1

            return {
                "status": "accepted",
                "format_detected": "cef",
                "items_stored": items_stored,
            }

        # ── 4. Generic IOC list (indicators format) ──────────────────
        if "indicators" in body:
            indicators = body["indicators"]
            if isinstance(indicators, list):
                iocs = []
                for ind in indicators:
                    if isinstance(ind, dict):
                        ioc_type = ind.get("type", "unknown")
                        value = ind.get("value", "")
                        if value:
                            iocs.append({
                                "ioc_type": ioc_type,
                                "value_hash": _hash_ioc(str(value)),
                            })
                if iocs:
                    ioc_data = {
                        "iocs": iocs,
                        "source": body.get("source", "indicators"),
                    }
                    await db.store_ioc_bundle(ioc_data)
                    items_stored += 1

            return {
                "status": "accepted",
                "format_detected": "indicators",
                "items_stored": items_stored,
            }

        # ── 5. Generic / Splunk format (iocs list) ───────────────────
        if "iocs" in body:
            iocs_raw = body["iocs"]
            if isinstance(iocs_raw, list):
                iocs = []
                for ioc in iocs_raw:
                    if isinstance(ioc, dict):
                        ioc_entry: dict[str, Any] = {
                            "ioc_type": ioc.get("ioc_type", "unknown"),
                        }
                        # Support both pre-hashed and raw values
                        if ioc.get("value_hash"):
                            ioc_entry["value_hash"] = ioc["value_hash"]
                        elif ioc.get("value_raw"):
                            ioc_entry["value_hash"] = _hash_ioc(ioc["value_raw"])
                        elif ioc.get("value"):
                            ioc_entry["value_hash"] = _hash_ioc(ioc["value"])
                        else:
                            continue
                        iocs.append(ioc_entry)

                if iocs:
                    ioc_data = {
                        "iocs": iocs,
                        "source": body.get("source", "webhook"),
                    }
                    await db.store_ioc_bundle(ioc_data)
                    items_stored += 1

            return {
                "status": "accepted",
                "format_detected": "generic",
                "items_stored": items_stored,
            }

        raise HTTPException(
            status_code=400,
            detail="Unrecognized webhook format. Expected one of: detection, properties, cef, indicators, iocs",
        )

    # ── Settings routes ────────────────────────────────────────────

    @app.post("/settings/slack")
    async def configure_slack(body: dict[str, Any], request: Request):
        """Configure Slack webhook URL for notifications."""
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(status_code=401, detail="API key required")
        webhook_url = body.get("webhook_url", "").strip()
        if not webhook_url or not webhook_url.startswith("https://hooks.slack.com/"):
            raise HTTPException(status_code=400, detail="Valid Slack webhook URL required (https://hooks.slack.com/...)")
        # For now, store in environment (in production, this would be per-org in DB)
        os.environ["NUR_SLACK_WEBHOOK"] = webhook_url
        return {"status": "configured", "message": "Slack notifications enabled"}

    # ── Analyze route ──────────────────────────────────────────────

    @app.post("/analyze")
    async def analyze(body: dict[str, Any], request: Request):
        db = get_db()
        engine = get_proof_engine()
        # BDP profile tracking
        _bdp_profile = get_or_create_profile(request.headers.get("X-API-Key"))
        _bdp_profile.total_contributions += 1
        from .analyze import (
            analyze_ioc_bundle, analyze_attack_map, analyze_eval_record,
            detect_contribution_type,
        )
        try:
            contrib_type = detect_contribution_type(body)
            _bdp_profile.contribution_types.add(contrib_type)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if contrib_type == "ioc_bundle":
            return await analyze_ioc_bundle(body, db, engine=engine)
        elif contrib_type == "attack_map":
            return await analyze_attack_map(body, db, engine=engine)
        elif contrib_type == "eval":
            return await analyze_eval_record(body, db, engine=engine)
        else:
            raise HTTPException(status_code=400, detail="Unknown contribution type")

    # ── Threat Model ──────────────────────────────────────────────

    @app.post("/threat-model")
    async def threat_model_endpoint(body: dict[str, Any]):
        """Generate a threat model for a given stack and vertical."""
        from ..threat_model import generate_threat_model
        stack = body.get("stack", [])
        if not stack or not isinstance(stack, list):
            raise HTTPException(status_code=400, detail="'stack' must be a non-empty list of tool IDs")
        vertical = body.get("vertical", "healthcare")
        org_name = body.get("org_name", "Organization")
        try:
            return generate_threat_model(
                stack=stack,
                vertical=vertical,
                org_name=org_name,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ── Guide (human-readable docs) ─────────────────────────────

    _GUIDE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — guide</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-YLL9Y97GG0"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());gtag('config','G-YLL9Y97GG0');</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    background:
      radial-gradient(circle at top, rgba(34, 197, 94, 0.12), transparent 24%),
      #0a0a0f;
    color: #e4e4e7;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
    padding: 0;
  }
  a {
    color: inherit;
    text-decoration: none;
  }
  strong { color: #fafafa; }
  .guide-header {
    max-width: 1120px;
    margin: 0 auto;
    text-align: center;
    padding: 96px 24px 40px;
  }
  .guide-header h1 {
    font-size: clamp(2.6rem, 7vw, 4.2rem);
    color: #fafafa;
    letter-spacing: 0.25em;
    margin-bottom: 12px;
  }
  .guide-header h1 span { color: #22c55e; }
  .guide-header p {
    color: #a1a1aa;
    font-size: 1rem;
    line-height: 1.8;
  }
  .guide-nav {
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(10, 10, 15, 0.88);
    border-top: 1px solid #1e1e2e;
    border-bottom: 1px solid #1e1e2e;
    padding: 14px 24px;
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    justify-content: center;
    backdrop-filter: blur(16px);
  }
  .guide-nav a {
    color: #a1a1aa;
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 10px 14px;
    border-radius: 999px;
    border: 1px solid transparent;
    transition: color 0.2s ease, background 0.2s ease, border-color 0.2s ease;
  }
  .guide-nav a:hover {
    color: #fafafa;
    background: rgba(255, 255, 255, 0.02);
    border-color: rgba(34, 197, 94, 0.25);
  }
  .guide-nav a.active {
    color: #0a0a0f;
    background: #22c55e;
    border-color: #22c55e;
  }
  .back-to-top {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #111118;
    border: 1px solid #1e1e2e;
    color: #a1a1aa;
    width: 48px;
    height: 48px;
    border-radius: 999px;
    display: none;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    transition: transform 0.2s ease, color 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    z-index: 100;
  }
  .back-to-top:hover {
    color: #22c55e;
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
    transform: translateY(-1px);
  }
  .guide-content {
    max-width: 1120px;
    margin: 0 auto;
    padding: 8px 24px 88px;
  }
  .guide-section {
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 24px;
    padding: 80px 48px;
    margin-top: 24px;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }
  .guide-section:hover {
    transform: translateY(-2px);
    border-color: rgba(34, 197, 94, 0.35);
    box-shadow: 0 0 20px rgba(34, 197, 94, 0.05);
  }
  .guide-section h2 {
    font-size: 1.2rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: #fafafa;
    margin-bottom: 24px;
  }
  .guide-section h2::before {
    content: '/// ';
    color: #22c55e;
  }
  .guide-section h3 {
    font-size: 1rem;
    color: #fafafa;
    margin: 28px 0 12px;
  }
  .guide-section p,
  .guide-section li {
    font-size: 0.98rem;
    color: #a1a1aa;
    line-height: 1.9;
  }
  .guide-section ul {
    list-style: none;
    padding: 0;
    display: grid;
    gap: 10px;
  }
  .guide-section ul li {
    position: relative;
    padding-left: 18px;
  }
  .guide-section ul li::before {
    content: '';
    position: absolute;
    top: 0.82em;
    left: 0;
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: #22c55e;
  }
  pre {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 18px;
    padding: 22px 24px;
    font-size: 0.92rem;
    color: #e4e4e7;
    overflow-x: auto;
    margin: 16px 0;
    line-height: 1.8;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  }
  code {
    color: #e4e4e7;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  }
  .cmd { color: #fafafa; }
  .comment { color: #71717a; }
  .api-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    margin: 16px 0;
  }
  .api-table th {
    text-align: left;
    color: #a1a1aa;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 12px 14px;
    border-bottom: 1px solid #1e1e2e;
  }
  .api-table td {
    padding: 12px 14px;
    border-bottom: 1px solid #1e1e2e;
    color: #a1a1aa;
    vertical-align: top;
  }
  .api-table td:first-child { color: #22c55e; white-space: nowrap; }
  .api-table td:nth-child(2) { color: #fafafa; }
  .privacy-level {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 16px 18px;
    margin: 12px 0;
  }
  .privacy-level strong { color: #fafafa; }
  .guide-footer {
    text-align: center;
    padding: 0 24px 56px;
    color: #a1a1aa;
    font-size: 0.82rem;
  }
  .guide-footer a { color: #fafafa; }
  @media (max-width: 768px) {
    .guide-header {
      padding: 84px 16px 28px;
    }
    .guide-nav {
      padding: 12px 16px;
      gap: 10px;
    }
    .guide-content { padding: 8px 16px 64px; }
    .guide-section { padding: 56px 20px; }
    pre { font-size: 0.8rem; padding: 16px; }
    .api-table { font-size: 0.74rem; display: block; overflow-x: auto; }
    .back-to-top {
      width: 44px;
      height: 44px;
      right: 16px;
      bottom: 16px;
    }
  }
</style>
</head>
<body>

<div class="guide-header">
  <h1>nur <span>guide</span></h1>
  <p>a social network for security intelligence &mdash; give one eval, get forty back</p>
</div>

<div class="guide-nav">
  <a href="#quick-start">quick start</a>
  <a href="#wartime">wartime</a>
  <a href="#peacetime">peacetime</a>
  <a href="#eval">eval dimensions</a>
  <a href="#api">api reference</a>
  <a href="#privacy">trustless</a>
  <a href="#self-hosting">self-hosting</a>
  <a href="/">home</a>
</div>

<div class="guide-content">

  <!-- Quick Start -->
  <div class="guide-section" id="quick-start">
    <h2>Quick Start</h2>
    <pre><span class="cmd">pip install nur</span>
<span class="cmd">nur init</span>
<span class="cmd">nur register you@yourorg.com</span>    <span class="comment"># work email required</span>
<span class="cmd">nur report incident.json</span>        <span class="comment"># give data, get intelligence</span></pre>
    <p>Data is anonymized locally before it leaves your machine. You get back collective intelligence from everyone who contributed. The integration shares. The human gets remediation back.</p>
    <h3>Data model</h3>
    <p><strong>Query data</strong> (threat models, IOCs, stacks) flows in. <strong>Response data</strong> (tool intel, remediation, pricing) flows back. The protocol IS the product. Math, not promises.</p>
  </div>

  <!-- Wartime -->
  <div class="guide-section" id="wartime">
    <h2>Wartime</h2>
    <p>You're under attack. Upload IOCs, get campaign matches, detection gaps, remediation actions.</p>
    <pre><span class="cmd">nur report incident_iocs.json</span>   <span class="comment"># campaign match + shared IOCs</span>
<span class="cmd">nur report attack_map.json</span>      <span class="comment"># detection gap analysis</span>
<span class="cmd">nur report eval.json</span>            <span class="comment"># benchmark your tools</span>
<span class="cmd">nur report incident.json --json</span> <span class="comment"># machine-readable output</span></pre>
  </div>

  <!-- Peacetime -->
  <div class="guide-section" id="peacetime">
    <h2>Peacetime</h2>
    <p>Build defenses. Market maps, vendor comparisons, threat modeling, attack simulations.</p>
    <pre><span class="cmd">nur eval</span>                                             <span class="comment"># interactive vendor evaluation</span>
<span class="cmd">nur eval --vendor crowdstrike</span>                        <span class="comment"># price, support, detection, decision intel</span>
<span class="cmd">nur market edr</span>                                       <span class="comment"># vendor rankings by category</span>
<span class="cmd">nur search compare crowdstrike sentinelone</span>           <span class="comment"># side-by-side comparison</span>
<span class="cmd">nur threat-model --stack crowdstrike,splunk --vertical healthcare</span>
<span class="cmd">nur simulate --stack crowdstrike,splunk,okta --vertical healthcare</span></pre>
  </div>

  <!-- Eval Dimensions -->
  <div class="guide-section" id="eval">
    <h2>Eval Dimensions</h2>
    <p>The <code>nur eval</code> schema covers six dimensions. All fields are aggregated. All individual values are discarded after commit. Dice chain verification ensures nothing changed in transit.</p>
    <pre>Detection:   overall score, detection rate, false positives
Price:       annual cost, per-seat cost, contract length, discount
Support:     quality, escalation ease, SLA response time
Performance: CPU overhead, agent memory, scan latency, deploy time
Decision:    chose this vendor?, main decision factor
Integrity:   dice chain (client hash == server contribution_hash)

<span class="comment"># All fields aggregated. All individual values discarded.</span>
<span class="comment"># BDP credibility weighting defends against data poisoning.</span></pre>
  </div>

  <!-- API Reference -->
  <div class="guide-section" id="api">
    <h2>API Reference</h2>

    <table class="api-table">
      <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      <tr><td>POST</td><td>/analyze</td><td>Give data, get intelligence report</td></tr>
      <tr><td>POST</td><td>/contribute/submit</td><td>Submit tool evaluation</td></tr>
      <tr><td>POST</td><td>/contribute/attack-map</td><td>Submit attack map with techniques</td></tr>
      <tr><td>POST</td><td>/contribute/ioc-bundle</td><td>Submit IOC bundle</td></tr>
      <tr><td>POST</td><td>/ingest/webhook</td><td>Universal webhook (Splunk, Sentinel, CrowdStrike, CEF)</td></tr>
      <tr><td>POST</td><td>/register</td><td>Register with work email + public key</td></tr>
      <tr><td>POST</td><td>/threat-model</td><td>Generate MITRE-mapped threat model</td></tr>
      <tr><td>GET</td><td>/intelligence/market/{category}</td><td>Vendor market map</td></tr>
      <tr><td>POST</td><td>/intelligence/threat-map</td><td>Threat &rarr; MITRE techniques + coverage gaps</td></tr>
      <tr><td>GET</td><td>/intelligence/danger-radar</td><td>Vendors with hidden risk signals</td></tr>
      <tr><td>GET</td><td>/intelligence/patterns/{vertical}</td><td>Attack patterns for an industry</td></tr>
      <tr><td>POST</td><td>/intelligence/simulate</td><td>Simulate attack chain against your stack</td></tr>
      <tr><td>GET</td><td>/search/vendor/{name}</td><td>Vendor scores and details</td></tr>
      <tr><td>GET</td><td>/search/compare?a=X&amp;b=Y</td><td>Side-by-side vendor comparison</td></tr>
      <tr><td>POST</td><td>/verify/receipt</td><td>Verify contribution receipt (Merkle proof)</td></tr>
      <tr><td>GET</td><td>/verify/aggregate/{vendor}</td><td>Verify aggregate proof for a vendor</td></tr>
      <tr><td>GET</td><td>/proof/stats</td><td>Platform proof stats (Merkle root, counts)</td></tr>
      <tr><td>POST</td><td>/category/propose</td><td>Propose blind category (threshold reveal)</td></tr>
      <tr><td>POST</td><td>/category/reveal</td><td>Vote to reveal a blind category</td></tr>
      <tr><td>GET</td><td>/category/pending</td><td>List pending + revealed categories</td></tr>
      <tr><td>GET</td><td>/dashboard</td><td>Visual dashboard</td></tr>
      <tr><td>GET</td><td>/vendor/{id}</td><td>Vendor profile page (scores, gaps, claim)</td></tr>
      <tr><td>GET</td><td>/vendor/{id}/claim</td><td>Vendor claims their profile (email verification)</td></tr>
      <tr><td>GET</td><td>/proof/bdp-stats</td><td>BDP credibility &amp; poisoning defense stats</td></tr>
      <tr><td>POST</td><td>/invites/generate</td><td>Generate invite codes for peers</td></tr>
      <tr><td>POST</td><td>/invites/redeem</td><td>Redeem an invite code</td></tr>
      <tr><td>POST</td><td>/settings/slack</td><td>Configure Slack webhook for remediation alerts</td></tr>
      <tr><td>GET</td><td>/health</td><td>Liveness check</td></tr>
      <tr><td>GET</td><td>/stats</td><td>Contribution counts (anonymized)</td></tr>
      <tr><td>GET</td><td>/contribute</td><td>Web eval form (mobile-friendly, no auth)</td></tr>
    </table>
    <p>See the <a href="https://github.com/manizzle/nur" style="color:#22c55e;">README</a> for curl examples.</p>
  </div>

  <!-- Trustless Architecture -->
  <div class="guide-section" id="privacy">
    <h2>Trustless Architecture</h2>
    <p>Your data <strong>cannot be mined, sold, or misused</strong> &mdash; not because we promise, but because the math makes it impossible.</p>

    <h3>How it works</h3>
    <ul>
      <li><strong>Your machine anonymizes everything</strong> &mdash; PII scrubbed, IOCs hashed, no free text leaves your machine</li>
      <li><strong>Server commits, aggregates, discards</strong> &mdash; Pedersen commitments + Merkle tree, then individual values are deleted</li>
      <li><strong>Every query comes with a proof</strong> &mdash; Merkle root, contributor count, commitment chain. Anyone can verify.</li>
      <li><strong>You get a receipt</strong> &mdash; commitment hash + Merkle inclusion proof + server signature. Non-repudiable.</li>
      <li><strong>Dice chain verification</strong> &mdash; client hashes payload before sending; receipt contains server's independent hash. Match = end-to-end integrity.</li>
      <li><strong>BDP anti-poisoning</strong> &mdash; Behavioral Differential Privacy tracks credibility signals to defend against data poisoning attacks.</li>
    </ul>

    <h3>Blind category discovery</h3>
    <p>Orgs propose hashed category names. Server counts independent submissions. At threshold (3+), contributors vote to reveal. Server never sees plaintext until quorum.</p>

    <h3>Verification endpoints</h3>
    <p>Use <code>/verify/receipt</code>, <code>/verify/aggregate/{vendor}</code>, and <code>/proof/stats</code> to verify any claim. See the <a href="https://github.com/manizzle/nur/blob/main/ARCHITECTURE.md" style="color:#22c55e;">ARCHITECTURE.md</a> for the detailed three-party flow diagram.</p>

    <p>See <a href="https://github.com/manizzle/nur/blob/main/COMPLIANCE.md" style="color:#22c55e;">COMPLIANCE.md</a> for the full legal analysis covering CIRCIA, NERC CIP, SEC 8-K, and CISA safe harbor.</p>
  </div>

  <!-- Self-Hosting -->
  <div class="guide-section" id="self-hosting">
    <h2>Self-Hosting</h2>
    <p>Run your own nur instance for your industry or organization.</p>

    <h3>Quick deploy</h3>
    <pre><span class="cmd">nur up --vertical healthcare</span>     <span class="comment"># LockBit, HIPAA focus</span>
<span class="cmd">nur up --vertical financial</span>      <span class="comment"># APT28, PCI DSS focus</span>
<span class="cmd">nur up --vertical energy</span>         <span class="comment"># Sandworm, NERC CIP focus</span>
<span class="cmd">nur up --vertical government</span>     <span class="comment"># APT29, FISMA focus</span></pre>

    <h3>Docker Compose</h3>
    <pre><span class="cmd">git clone https://github.com/manizzle/nur.git && cd nur</span>
<span class="cmd">docker compose up -d</span>

<span class="comment"># or with the install script</span>
<span class="cmd">curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/install.sh | bash</span></pre>

    <h3>Environment variables</h3>
    <pre><span class="comment"># .env file</span>
NUR_DB_URL=postgresql+asyncpg://user:pass@db:5432/nur
NUR_API_KEY=your_master_api_key
NUR_AUTO_INGEST=1              <span class="comment"># auto-scrape public feeds every hour</span>
NUR_DOMAIN=nur.yourorg.com     <span class="comment"># for magic link emails</span>
NUR_SMTP_HOST=smtp.yourorg.com <span class="comment"># email verification</span>
NUR_SMTP_PORT=587
NUR_SMTP_USER=nur@yourorg.com
NUR_SMTP_PASS=your_smtp_password</pre>

    <h3>Your users</h3>
    <pre><span class="cmd">pip install nur && nur init && nur register you@org.com</span></pre>
  </div>

</div>

<div class="guide-footer">
  <a href="/">nur</a> &bull; a social network for security intelligence &bull; product = protocol + users &bull;
  <a href="https://github.com/manizzle/nur">open source</a>
</div>

<a href="#" class="back-to-top" id="backToTop">&uarr;</a>

<script>
// Back to top button
var btn = document.getElementById('backToTop');
window.addEventListener('scroll', function() {
  btn.style.display = window.scrollY > 300 ? 'flex' : 'none';
});

// Scroll spy — highlight active nav link
var sections = document.querySelectorAll('.guide-section');
var navLinks = document.querySelectorAll('.guide-nav a[href^="#"]');
window.addEventListener('scroll', function() {
  var current = '';
  sections.forEach(function(section) {
    var top = section.offsetTop - 80;
    if (window.scrollY >= top) { current = section.id; }
  });
  navLinks.forEach(function(link) {
    link.classList.remove('active');
    if (link.getAttribute('href') === '#' + current) {
      link.classList.add('active');
    }
  });
});
</script>

</body>
</html>"""

    @app.get("/guide", response_class=HTMLResponse)
    async def guide():
        return _GUIDE_HTML

    @app.get("/docs", response_class=HTMLResponse)
    async def docs_redirect():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/guide")

    # ── v1 API endpoints (agent/CLI consumption) ─────────────────────

    @app.get("/api/v1/remediation")
    async def api_remediation(threat: str | None = None, techniques: str | None = None):
        """What remediation worked for this threat -- aggregate only."""
        engine = get_proof_engine()
        stats = engine.get_remediation_stats()
        technique_data = []
        if techniques:
            for tid in techniques.split(","):
                tid = tid.strip()
                freq = engine._technique_freq.get(tid, 0)
                technique_data.append({"technique_id": tid, "frequency": freq})
        return {
            "threat": threat,
            "total_attack_reports": stats["attack_map_count"],
            "remediation": {
                "by_category": stats.get("by_category", {}),
                "severity_distribution": stats.get("severity_distribution", {}),
                "typical_detect_time": stats.get("time_to_detect", {}),
                "typical_contain_time": stats.get("time_to_contain", {}),
            },
            "techniques": technique_data if technique_data else None,
            "proof": {
                "merkle_root": engine.merkle_root,
                "total_contributions": engine.total_contributions,
            },
        }

    @app.get("/api/v1/coverage")
    async def api_coverage(tools: str):
        """Detection gap analysis for your tool stack."""
        engine = get_proof_engine()
        tool_list = [t.strip() for t in tools.split(",")]
        coverage = engine.get_technique_coverage(tool_list)
        return {
            **coverage,
            "proof": {
                "merkle_root": engine.merkle_root,
                "total_contributions": engine.total_contributions,
            },
        }

    @app.get("/api/v1/benchmark")
    async def api_benchmark(vertical: str, org_size: str | None = None):
        """Org benchmarking -- how do peers in your vertical compare."""
        db = get_db()
        engine = get_proof_engine()
        stats = await db.get_stats()
        platform_stats = engine.get_platform_stats()
        return {
            "vertical": vertical,
            "org_size": org_size,
            "platform": {
                "total_contributions": stats.get("total_contributions", 0),
                "unique_vendors": platform_stats.get("unique_vendors", 0),
                "unique_techniques": platform_stats.get("unique_techniques", 0),
            },
            "proof": {
                "merkle_root": engine.merkle_root,
                "total_contributions": engine.total_contributions,
            },
        }

    # ── Vendor metadata API (used by /contribute form) ───────────────

    @app.get("/api/v1/vendor-meta")
    async def vendor_metadata(vendor: str):
        """Get category and competitors for a vendor."""
        from ..vendor_metadata import get_category, get_competitors
        cat = get_category(vendor)
        competitors = get_competitors(vendor, cat)
        return {"vendor": vendor, "category": cat, "competitors": competitors}

    @app.get("/api/v1/vendor-search")
    async def vendor_search(q: str, limit: int = 20):
        """Autocomplete vendor search — returns matching vendor names."""
        if not q or len(q) < 2:
            return {"results": []}
        q_lower = q.lower()
        matches = [v for v in VENDORS if q_lower in v.lower()][:limit]
        return {"results": matches}

    # ── Web contribute form (mobile-first, no auth) ──────────────────

    @app.get("/contribute", response_class=HTMLResponse)
    async def contribute_form():
        # Only include top 50 vendors in HTML — rest via API autocomplete
        _vendor_options = "\n      ".join(f'<option value="{v}">' for v in VENDORS[:50])
        _html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — rate your security tool</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0f; color: #e4e4e7; font-family: 'Inter', sans-serif; min-height: 100vh; }
  .container { max-width: 480px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 1.5rem; color: #fafafa; margin-bottom: 4px; }
  h1 span { color: #22c55e; }
  .subtitle { color: #71717a; font-size: 0.85rem; margin-bottom: 24px; }
  input, select { width: 100%; padding: 14px 16px; background: #111118; border: 1px solid #1e1e2e; border-radius: 8px; color: #e4e4e7; font-size: 16px; font-family: 'Inter', sans-serif; margin-bottom: 8px; -webkit-appearance: none; }
  input:focus, select:focus { outline: none; border-color: #22c55e; }
  select { background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2371717a' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 16px center; padding-right: 40px; }
  select option { background: #111118; color: #e4e4e7; }
  button[type="submit"] { width: 100%; padding: 16px; background: #22c55e; color: #0a0a0f; border: none; border-radius: 8px; font-size: 18px; font-weight: 700; cursor: pointer; font-family: 'Inter', sans-serif; margin-top: 16px; }
  button[type="submit"]:active { background: #16a34a; }
  label { display: block; font-size: 14px; color: #888; margin-bottom: 6px; margin-top: 16px; }
  .required { color: #22c55e; }
  input[type="range"] { -webkit-appearance: none; width: 100%; height: 8px; background: #1e1e2e; border-radius: 4px; outline: none; border: none; padding: 0; margin: 0; }
  input[type="range"]::-webkit-slider-thumb { -webkit-appearance: none; width: 32px; height: 32px; background: #22c55e; border-radius: 50%; cursor: pointer; }
  input[type="range"]::-moz-range-thumb { width: 32px; height: 32px; background: #22c55e; border-radius: 50%; cursor: pointer; border: none; }
  .score-display { font-size: 2em; color: #fafafa; text-align: center; font-weight: 700; margin: 8px 0; }
  .toggle-group { display: flex; gap: 12px; margin-bottom: 8px; }
  .toggle-btn { flex: 1; padding: 14px; border: 2px solid #1e1e2e; border-radius: 8px; background: #111118; color: #e4e4e7; font-size: 16px; text-align: center; cursor: pointer; font-family: 'Inter', sans-serif; transition: all 0.15s; }
  .toggle-btn.selected { border-color: #22c55e; background: #0a1f0a; color: #22c55e; }
  .optional { font-size: 12px; color: #555; }
  .note { font-size: 12px; color: #71717a; margin-top: 4px; }
  .privacy-note { margin-top: 24px; padding: 16px; background: rgba(34, 197, 94, 0.05); border: 1px solid #1e1e2e; border-radius: 8px; font-size: 13px; color: #71717a; line-height: 1.6; }
  .privacy-note strong { color: #a1a1aa; }
  .back-link { display: block; text-align: center; margin-top: 16px; color: #71717a; font-size: 13px; text-decoration: none; }
  .back-link:hover { color: #22c55e; }
</style>
</head>
<body>
<div class="container">
  <h1>nur <span>eval</span></h1>
  <p class="subtitle">Rate your security tool in 60 seconds. Anonymous + cryptographic receipt.</p>

  <!-- Voice recording option -->
  <div id="voice-section" style="margin-bottom:24px;padding:20px;background:#111118;border:1px solid #1e1e2e;border-radius:12px;text-align:center;">
    <p style="color:#a1a1aa;font-size:14px;margin-bottom:12px;">Don't want to type? Just tell us.</p>
    <button type="button" id="voice-btn" onclick="toggleRecording()" style="width:100%;padding:16px;background:#1e1e2e;color:#e4e4e7;border:2px solid #333;border-radius:8px;font-size:16px;cursor:pointer;font-family:'Inter',sans-serif;transition:all 0.2s;">
      Tap to record your eval
    </button>
    <p id="voice-status" style="color:#555;font-size:12px;margin-top:8px;display:none;"></p>
    <p style="color:#555;font-size:11px;margin-top:8px;">Example: "I use CrowdStrike for EDR, pay about 50K a year, support is great, 9 out of 10, would buy again"</p>
    <div id="voice-done" style="display:none;margin-top:12px;">
      <p style="color:#22c55e;font-weight:600;margin-bottom:8px;">Recorded!</p>
      <input type="email" id="voice-email" placeholder="Work email (required)" style="width:100%;padding:12px;background:#0a0a0f;border:1px solid #1e1e2e;border-radius:8px;color:#e4e4e7;font-size:16px;font-family:'Inter',sans-serif;margin-bottom:8px;">
      <button type="button" id="voice-submit" onclick="submitVoice()" style="width:100%;padding:14px;background:#22c55e;color:#0a0a0f;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;">Submit voice eval</button>
    </div>
  </div>

  <div style="text-align:center;color:#555;font-size:13px;margin-bottom:20px;">— or fill out the form below —</div>

  <form method="post" action="/contribute" id="evalForm">
    <label>What tool are you evaluating? <span class="required">*</span></label>
    <input type="text" name="vendor" list="vendor-list" required placeholder="e.g. CrowdStrike, Wiz, Okta...">
    <datalist id="vendor-list">
      %%VENDOR_OPTIONS%%
    </datalist>

    <label>Category</label>
    <select name="category">
      <option value="">Select category...</option>
      <option value="edr">EDR</option>
      <option value="siem">SIEM</option>
      <option value="cloud_security">Cloud Security</option>
      <option value="identity">Identity</option>
      <option value="email_security">Email Security</option>
      <option value="network_security">Network Security</option>
      <option value="vulnerability_management">Vulnerability Management</option>
      <option value="waf">WAF</option>
      <option value="ndr">NDR</option>
      <option value="soar">SOAR</option>
      <option value="compliance">Compliance</option>
      <option value="security_awareness">Security Awareness</option>
      <option value="mdr">MDR</option>
      <option value="other">Other</option>
    </select>
    <div id="competitors-section" style="display:none;"></div>

    <label>Replacing anything? <span class="optional">(optional)</span></label>
    <select name="replacing">
      <option value="">Not replacing / new purchase</option>
      <option value="crowdstrike">CrowdStrike</option>
      <option value="sentinelone">SentinelOne</option>
      <option value="microsoft_defender">Microsoft Defender</option>
      <option value="cortex_xdr">Cortex XDR</option>
      <option value="splunk">Splunk</option>
      <option value="elastic">Elastic</option>
      <option value="qradar">IBM QRadar</option>
      <option value="carbon_black">Carbon Black</option>
      <option value="other">Other (being replaced)</option>
    </select>
    <div class="note">This churn data helps the collective understand what's working and what isn't.</div>

    <label>Overall score <span class="required">*</span></label>
    <div class="score-display" id="overall-val">5</div>
    <input type="range" name="overall_score" min="1" max="10" value="5" oninput="document.getElementById('overall-val').textContent=this.value">

    <label>Would you buy it again?</label>
    <div class="toggle-group">
      <div class="toggle-btn" onclick="setBuy('yes',this)">Yes</div>
      <div class="toggle-btn" onclick="setBuy('no',this)">No</div>
    </div>
    <input type="hidden" name="would_buy" id="would_buy" value="">

    <label>Annual cost <span class="optional">(optional)</span></label>
    <input type="text" name="annual_cost" placeholder="$50,000" inputmode="numeric">

    <label>Support quality <span class="optional">(optional)</span></label>
    <div class="score-display" id="support-val" style="font-size:1.4em;color:#71717a;">-</div>
    <input type="range" name="support_quality" min="1" max="10" value="0" oninput="if(this.value>0){document.getElementById('support-val').textContent=this.value;document.getElementById('support-val').style.color='#fafafa';}">

    <label>What drove your decision? <span class="optional">(optional)</span></label>
    <select name="decision_factor">
      <option value="">Select...</option>
      <option value="detection_quality">Detection quality</option>
      <option value="price">Price</option>
      <option value="support">Support</option>
      <option value="integration">Integration</option>
      <option value="compliance">Compliance</option>
      <option value="executive_mandate">Executive mandate</option>
      <option value="peer_recommendation">Peer recommendation</option>
      <option value="analyst_report">Analyst report</option>
    </select>

    <label>Work email <span class="required">*</span></label>
    <input type="email" name="email" required placeholder="you@company.com">
    <div class="note">Required for verification. Gmail/Yahoo not accepted.</div>

    <button type="submit">Submit eval</button>
  </form>

  <div class="privacy-note">
    <strong>What happens to your data:</strong><br><br>
    <strong>1. Your scores go into a running average.</strong> We add your 9/10 to the sum, increment the count, and <em>delete your individual score</em>. The server literally cannot retrieve it after commit.<br><br>
    <strong>2. Your email is never linked to your scores.</strong> Email is for verification only (to block spam). It's stored separately from eval data with no join path.<br><br>
    <strong>3. You get a cryptographic receipt.</strong> A Pedersen commitment hash + Merkle inclusion proof. This proves your eval was included in the aggregate — the server can't deny receiving it or alter it after the fact.<br><br>
    <strong>4. Nobody can reverse-engineer your score.</strong> The aggregate says "42 practitioners scored CrowdStrike 9.1 avg." It does not say "Hospital X gave it a 9." That data doesn't exist anymore.<br><br>
    <strong>What the collective gets from your 60 seconds:</strong> one more real data point that makes the aggregate more accurate for everyone. Give one eval, get forty back.
  </div>
  <a href="/" class="back-link">nur.saramena.us</a>
</div>
<script>
// Auto-fill category and show competitors
let vendorInput = document.querySelector('input[name="vendor"]');
let categorySelect = document.querySelector('select[name="category"]');

vendorInput.addEventListener('change', fetchVendorMeta);
vendorInput.addEventListener('blur', fetchVendorMeta);

// Live vendor autocomplete via /api/v1/vendor-search
let vendorList = document.getElementById('vendor-list');
let searchTimeout = null;
vendorInput.addEventListener('input', function() {
  clearTimeout(searchTimeout);
  let q = vendorInput.value.trim();
  if (q.length < 2) return;
  searchTimeout = setTimeout(async () => {
    try {
      let resp = await fetch('/api/v1/vendor-search?q=' + encodeURIComponent(q));
      let data = await resp.json();
      vendorList.innerHTML = data.results.map(v => '<option value="' + v + '">').join('');
    } catch(e) {}
  }, 200);
});

async function fetchVendorMeta() {
  let vendor = vendorInput.value.trim();
  if (!vendor) return;

  try {
    let resp = await fetch('/api/v1/vendor-meta?vendor=' + encodeURIComponent(vendor));
    let data = await resp.json();

    // Auto-fill category
    if (data.category && categorySelect) {
      categorySelect.value = data.category;
    }

    // Show competitors
    let compSection = document.getElementById('competitors-section');
    if (data.competitors && data.competitors.length > 0) {
      let html = '<label style="margin-top:16px;">Did you also evaluate? <span class="optional">(select any)</span></label>';
      html += '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px;">';
      data.competitors.forEach(c => {
        html += '<label style="display:flex;align-items:center;gap:6px;padding:8px 12px;background:#111118;border:1px solid #1e1e2e;border-radius:6px;cursor:pointer;font-size:14px;">';
        html += '<input type="checkbox" name="also_evaluated" value="' + c + '" style="width:auto;margin:0;">';
        html += c + '</label>';
      });
      html += '</div>';
      compSection.innerHTML = html;
      compSection.style.display = 'block';
    }
  } catch(e) {}
}

function setBuy(val, el) {
  document.getElementById('would_buy').value = val;
  document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('selected'));
  el.classList.add('selected');
}

// Voice recording
let mediaRecorder = null;
let audioChunks = [];
let isRecording = false;

async function toggleRecording() {
  const btn = document.getElementById('voice-btn');
  const status = document.getElementById('voice-status');
  status.style.display = 'block';

  if (!isRecording) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorder = new MediaRecorder(stream);
      audioChunks = [];
      mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
      mediaRecorder.onstop = () => {
        stream.getTracks().forEach(t => t.stop());
        document.getElementById('voice-done').style.display = 'block';
        btn.textContent = 'Re-record';
        btn.style.borderColor = '#22c55e';
        status.textContent = 'Recording saved. Add your email and submit.';
      };
      mediaRecorder.start();
      isRecording = true;
      btn.textContent = 'Tap to stop recording';
      btn.style.background = '#1a0a0a';
      btn.style.borderColor = '#ef4444';
      status.textContent = 'Recording...';
    } catch (e) {
      status.textContent = 'Microphone access denied. Use the form below instead.';
    }
  } else {
    mediaRecorder.stop();
    isRecording = false;
  }
}

async function submitVoice() {
  const email = document.getElementById('voice-email').value.trim();
  if (!email || !email.includes('@')) {
    alert('Work email required');
    return;
  }
  const blob = new Blob(audioChunks, { type: 'audio/webm' });
  const formData = new FormData();
  formData.append('audio', blob, 'eval.webm');
  formData.append('email', email);

  document.getElementById('voice-submit').textContent = 'Submitting...';
  document.getElementById('voice-submit').disabled = true;

  try {
    const resp = await fetch('/contribute/voice', { method: 'POST', body: formData });
    if (resp.ok) {
      const data = await resp.json();
      window.location.href = '/contribute/thanks?receipt=' + data.receipt_id + '&vendor=voice-eval';
    } else {
      const err = await resp.json();
      alert(err.detail || 'Error submitting. Try the form below.');
      document.getElementById('voice-submit').textContent = 'Submit voice eval';
      document.getElementById('voice-submit').disabled = false;
    }
  } catch (e) {
    alert('Network error. Try the form below.');
    document.getElementById('voice-submit').textContent = 'Submit voice eval';
    document.getElementById('voice-submit').disabled = false;
  }
}
</script>
</body>
</html>"""
        return _html.replace("%%VENDOR_OPTIONS%%", _vendor_options)

    @app.post("/contribute")
    async def contribute_web_form(request: Request):
        form = await request.form()
        vendor = str(form.get("vendor", "")).strip()
        category = str(form.get("category", "")).strip()
        overall_score = form.get("overall_score")
        would_buy = form.get("would_buy")
        annual_cost = str(form.get("annual_cost", "")).strip()
        support_quality = form.get("support_quality")
        decision_factor = str(form.get("decision_factor", "")).strip()
        email = str(form.get("email", "")).strip().lower()

        # Validate
        if not vendor or not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Vendor and work email required")

        domain = email.split("@")[1]
        if domain in _FREE_EMAIL_DOMAINS:
            raise HTTPException(status_code=400, detail=f"Work email required. {domain} not accepted.")

        # Build payload matching /contribute/submit shape
        payload: dict[str, Any] = {"data": {"vendor": vendor, "category": category or "general"}}
        if overall_score:
            payload["data"]["overall_score"] = float(overall_score)
        if would_buy:
            payload["data"]["would_buy"] = would_buy == "yes"
        if annual_cost:
            try:
                payload["data"]["annual_cost"] = float(annual_cost.replace("$", "").replace(",", ""))
            except (ValueError, TypeError):
                pass
        if support_quality and str(support_quality) != "0":
            payload["data"]["support_quality"] = float(support_quality)
        if decision_factor:
            payload["data"]["decision_factor"] = decision_factor
        also_evaluated = form.getlist("also_evaluated")
        if also_evaluated:
            payload["data"]["also_evaluated"] = list(also_evaluated)
        replacing = str(form.get("replacing", "")).strip()
        if replacing:
            payload["data"]["replacing"] = replacing

        # Store through trustless pipeline
        db = get_db()
        cid = await db.store_eval_record(payload)

        # Proof layer
        from .proofs import translate_eval
        engine = get_proof_engine()
        v, cat, values = translate_eval(payload)
        receipt = engine.commit_contribution(v, cat, values)

        # BDP tracking
        profile = get_or_create_profile(None)
        profile.contribution_types.add("eval")
        if vendor:
            profile.contributed_vendors.add(vendor.lower())
        profile.total_contributions += 1

        # Redirect to thank-you page
        from fastapi.responses import RedirectResponse
        import urllib.parse
        receipt_id = receipt.receipt_id
        return RedirectResponse(
            url=f"/contribute/thanks?receipt={receipt_id}&vendor={urllib.parse.quote(vendor)}&score={payload['data'].get('overall_score', '')}",
            status_code=303,
        )

    @app.post("/contribute/voice")
    async def contribute_voice(request: Request):
        """Accept a voice recording for eval. Store audio for later processing."""
        form = await request.form()
        email = str(form.get("email", "")).strip().lower()
        audio = form.get("audio")

        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Work email required")

        domain = email.split("@")[1]
        if domain in _FREE_EMAIL_DOMAINS:
            raise HTTPException(status_code=400, detail=f"Work email required. {domain} not accepted.")

        # Store audio file
        import uuid
        audio_id = str(uuid.uuid4())[:8]
        audio_dir = "/tmp/nur-voice-evals"
        os.makedirs(audio_dir, exist_ok=True)
        audio_path = f"{audio_dir}/{audio_id}.webm"

        if audio:
            content = await audio.read()
            with open(audio_path, "wb") as f:
                f.write(content)

        # Create a placeholder contribution
        db = get_db()
        engine = get_proof_engine()
        payload = {"data": {"vendor": "voice-pending", "category": "pending", "notes_audio": audio_id}}
        cid = await db.store_eval_record(payload)
        receipt = engine.commit_contribution("voice-pending", "pending", {"audio_id": audio_id})

        # BDP tracking
        profile = get_or_create_profile(None)
        profile.contribution_types.add("voice_eval")
        profile.total_contributions += 1

        return {"status": "accepted", "receipt_id": receipt.receipt_id, "audio_id": audio_id}

    @app.get("/contribute/thanks", response_class=HTMLResponse)
    async def contribute_thanks(receipt: str = "", vendor: str = "", score: str = ""):
        import urllib.parse
        vendor_display = urllib.parse.unquote(vendor) if vendor else "this tool"
        engine = get_proof_engine()
        contributor_count = engine.total_contributions

        # Get aggregate for this vendor to show instant comparison
        agg = engine.get_aggregate(vendor_display) if vendor_display != "this tool" else None
        your_score = float(score) if score else None
        agg_html = ""
        if agg:
            avg = agg.get("avg_overall_score")
            count = agg.get("contributor_count", 0)
            buy_pct = agg.get("would_buy_pct")
            avg_cost = agg.get("avg_annual_cost")

            agg_html = '<div style="background:#0a1f0a;border:1px solid #22c55e33;border-radius:12px;padding:20px;margin:20px 0;text-align:center;">'
            agg_html += f'<p style="color:#22c55e;font-size:1.8em;font-weight:800;margin-bottom:4px;">{vendor_display}</p>'
            if avg is not None:
                agg_html += f'<p style="color:#fafafa;font-size:2.4em;font-weight:800;">{avg:.1f}<span style="font-size:0.5em;color:#71717a;">/10</span></p>'
                agg_html += f'<p style="color:#888;font-size:13px;">avg across {count} practitioner{"s" if count != 1 else ""}</p>'
                if your_score is not None and avg is not None:
                    diff = your_score - avg
                    if diff > 0:
                        agg_html += f'<p style="color:#22c55e;font-size:14px;margin-top:8px;font-weight:600;">You scored it {your_score:.0f} — above average</p>'
                    elif diff < 0:
                        agg_html += f'<p style="color:#f59e0b;font-size:14px;margin-top:8px;font-weight:600;">You scored it {your_score:.0f} — below average</p>'
                    else:
                        agg_html += f'<p style="color:#888;font-size:14px;margin-top:8px;font-weight:600;">You scored it {your_score:.0f} — exactly average</p>'
            if buy_pct is not None:
                agg_html += f'<p style="color:#a1a1aa;font-size:14px;margin-top:12px;">{buy_pct:.0f}% would buy again</p>'
            if avg_cost is not None:
                agg_html += f'<p style="color:#a1a1aa;font-size:14px;">avg cost: ${avg_cost:,.0f}/yr</p>'
            agg_html += '</div>'
        elif vendor_display != "this tool" and vendor_display != "voice-eval":
            agg_html = '<div style="background:#111118;border:1px solid #1e1e2e;border-radius:12px;padding:20px;margin:20px 0;text-align:center;">'
            agg_html += f'<p style="color:#22c55e;font-weight:700;">{vendor_display}</p>'
            agg_html += '<p style="color:#888;font-size:14px;margin-top:8px;">You\'re the first to evaluate this tool. Share with a colleague to start building the comparison.</p>'
            agg_html += '</div>'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — thanks</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: dark; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0f; color: #e4e4e7; font-family: 'Inter', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
  .container {{ max-width: 480px; margin: 0 auto; padding: 24px 16px; text-align: center; }}
  .check {{ font-size: 3rem; margin-bottom: 16px; }}
  h1 {{ font-size: 1.5rem; color: #fafafa; margin-bottom: 8px; }}
  h1 span {{ color: #22c55e; }}
  .receipt {{ background: #111118; border: 1px solid #1e1e2e; border-radius: 8px; padding: 16px; margin: 20px 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; color: #71717a; word-break: break-all; }}
  .receipt strong {{ color: #a1a1aa; }}
  .stat {{ color: #22c55e; font-size: 1.1rem; font-weight: 600; margin: 16px 0; }}
  .actions {{ margin-top: 24px; }}
  .actions a {{ display: block; padding: 14px; border: 1px solid #1e1e2e; border-radius: 8px; color: #e4e4e7; text-decoration: none; margin-bottom: 10px; font-size: 15px; }}
  .actions a:hover {{ border-color: #22c55e; }}
  .actions a.primary {{ background: #22c55e; color: #0a0a0f; border-color: #22c55e; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
  <div class="check">&#10003;</div>
  <h1>Committed. Your eval for <span>{vendor_display}</span> is in the aggregate.</h1>

  {agg_html}

  <div class="receipt">
    <strong>Your cryptographic receipt</strong><br><br>
    <strong>Receipt ID:</strong> {receipt}<br>
    <strong>What this proves:</strong> Your score was sealed (Pedersen commitment), added to the Merkle tree, and included in the running aggregate. The server cannot alter it, deny receiving it, or recover your individual score.
  </div>

  <p class="stat">{contributor_count} practitioners have contributed</p>

  <div style="text-align:left;background:#111118;border:1px solid #1e1e2e;border-radius:8px;padding:16px;margin:20px 0;font-size:13px;color:#71717a;line-height:1.7;">
    <strong style="color:#a1a1aa;">What just happened:</strong><br>
    1. Your score was added to the running sum for {vendor_display}<br>
    2. Your individual score was <strong style="color:#22c55e;">deleted</strong> — only the sum survives<br>
    3. A commitment hash was added to the Merkle tree<br>
    4. This receipt proves you were included — keep it<br><br>
    <strong style="color:#a1a1aa;">What the collective now knows:</strong><br>
    "{vendor_display}: avg X.X across {contributor_count} practitioners"<br>
    It does NOT know: "you gave it a 9."
  </div>

  <div class="actions">
    <a href="/contribute" class="primary">Rate another tool</a>
    <a href="/contribute">Share with a colleague at RSA</a>
    <a href="/">Back to nur.saramena.us</a>
  </div>
</div>
</body>
</html>"""

    # ── Quick eval form (zero-typing, RSA hallway speed) ─────────────

    @app.get("/contribute/quick", response_class=HTMLResponse)
    async def quick_contribute_form():
        _quick_html = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur &mdash; quick eval</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0f; color: #e4e4e7; font-family: 'Inter', sans-serif; min-height: 100vh; }
  .container { max-width: 480px; margin: 0 auto; padding: 24px 16px; }
  h2 { font-size: 1.4rem; color: #fafafa; margin-bottom: 16px; text-align: center; }
  .step { display: none; }
  .step.active { display: block; }
  .progress { display: flex; justify-content: center; gap: 8px; margin-bottom: 24px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: #1e1e2e; transition: background 0.2s; }
  .dot.active { background: #22c55e; }
  .dot.done { background: #16a34a; }
  .tool-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .tool-btn { padding: 16px; background: #111118; border: 2px solid #1e1e2e; border-radius: 10px; color: #e4e4e7; font-size: 16px; font-weight: 600; cursor: pointer; text-align: center; font-family: 'Inter', sans-serif; transition: all 0.15s; -webkit-tap-highlight-color: transparent; }
  .tool-btn.selected { border-color: #22c55e; background: #0a1f0a; color: #22c55e; }
  .tool-btn:active { transform: scale(0.97); }
  #other-vendor { width: 100%; padding: 14px 16px; background: #111118; border: 1px solid #1e1e2e; border-radius: 8px; color: #e4e4e7; font-size: 16px; font-family: 'Inter', sans-serif; margin-top: 12px; -webkit-appearance: none; }
  #other-vendor:focus { outline: none; border-color: #22c55e; }
  .big-score { font-size: 4em; font-weight: 800; color: #fafafa; text-align: center; margin: 16px 0; }
  input[type="range"] { -webkit-appearance: none; width: 100%; height: 8px; background: #1e1e2e; border-radius: 4px; outline: none; border: none; padding: 0; margin: 16px 0; }
  input[type="range"]::-webkit-slider-thumb { -webkit-appearance: none; width: 36px; height: 36px; background: #22c55e; border-radius: 50%; cursor: pointer; }
  input[type="range"]::-moz-range-thumb { width: 36px; height: 36px; background: #22c55e; border-radius: 50%; cursor: pointer; border: none; }
  .big-buttons { display: flex; gap: 12px; }
  .yes-btn { flex: 1; padding: 24px; font-size: 20px; font-weight: 700; border-radius: 12px; background: #22c55e; color: #0a0a0f; border: none; cursor: pointer; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; }
  .yes-btn:active { background: #16a34a; }
  .no-btn { flex: 1; padding: 24px; font-size: 20px; font-weight: 700; border-radius: 12px; background: #1e1e2e; color: #e4e4e7; border: none; cursor: pointer; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; }
  .no-btn:active { background: #2a2a3e; }
  .competitor-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
  .chip { padding: 10px 16px; background: #111118; border: 2px solid #1e1e2e; border-radius: 20px; color: #e4e4e7; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.15s; -webkit-tap-highlight-color: transparent; }
  .chip.selected { border-color: #22c55e; background: #0a1f0a; color: #22c55e; }
  .next-btn { width: 100%; padding: 16px; background: #22c55e; color: #0a0a0f; border: none; border-radius: 8px; font-size: 18px; font-weight: 700; cursor: pointer; font-family: 'Inter', sans-serif; margin-top: 16px; -webkit-tap-highlight-color: transparent; }
  .next-btn:active { background: #16a34a; }
  .skip-btn { width: 100%; padding: 12px; background: transparent; color: #71717a; border: none; font-size: 14px; cursor: pointer; font-family: 'Inter', sans-serif; margin-top: 8px; }
  #quick-email { width: 100%; padding: 14px 16px; background: #111118; border: 1px solid #1e1e2e; border-radius: 8px; color: #e4e4e7; font-size: 16px; font-family: 'Inter', sans-serif; margin-bottom: 16px; -webkit-appearance: none; }
  #quick-email:focus { outline: none; border-color: #22c55e; }
  .branding { text-align: center; margin-bottom: 16px; font-size: 1.2rem; color: #fafafa; font-weight: 700; }
  .branding span { color: #22c55e; }
  .subtitle { text-align: center; color: #71717a; font-size: 0.8rem; margin-bottom: 20px; }
  .error-msg { color: #ef4444; font-size: 13px; margin-top: 8px; text-align: center; display: none; }
</style>
</head>
<body>
<div class="container">
  <div class="branding">nur <span>quick eval</span></div>
  <p class="subtitle">5 taps + email. 15 seconds.</p>
  <div class="progress" id="progress">
    <div class="dot active"></div>
    <div class="dot"></div>
    <div class="dot"></div>
    <div class="dot"></div>
    <div class="dot"></div>
  </div>

  <div id="step1" class="step active">
    <h2>What do you use?</h2>
    <div class="tool-grid" id="tool-grid"></div>
    <input type="text" id="other-vendor" placeholder="Other tool...">
  </div>

  <div id="step2" class="step">
    <h2>Score it</h2>
    <div class="big-score" id="score-display">5</div>
    <input type="range" min="1" max="10" value="5" id="score-slider">
    <button class="next-btn" onclick="nextStep(3)">Next &#8594;</button>
  </div>

  <div id="step3" class="step">
    <h2>Would you buy it again?</h2>
    <div class="big-buttons">
      <button class="yes-btn" onclick="setBuyAgain(true)">Yes</button>
      <button class="no-btn" onclick="setBuyAgain(false)">No</button>
    </div>
  </div>

  <div id="step4" class="step">
    <h2>Replacing anything?</h2>
    <div class="tool-grid" style="margin-bottom:16px;">
      <button class="tool-btn" onclick="setReplacing('nothing')">New purchase</button>
      <button class="tool-btn" onclick="setReplacing('other')">Yes, replacing...</button>
    </div>
    <div id="replacing-chips" style="display:none;">
      <p style="color:#71717a;font-size:13px;margin-bottom:8px;">What are you replacing?</p>
      <div class="competitor-chips" id="competitor-chips">
        <p style="color:#71717a;font-size:14px;">Loading...</p>
      </div>
    </div>
    <button class="next-btn" onclick="nextStep(5)">Next &#8594;</button>
    <button class="skip-btn" onclick="nextStep(5)">Skip</button>
  </div>

  <div id="step5" class="step">
    <h2>Almost done</h2>
    <input type="email" id="quick-email" placeholder="Work email" required>
    <div class="error-msg" id="email-error"></div>
    <button class="next-btn" onclick="submitQuick()">Submit &#8594;</button>
  </div>
</div>

<script>
var VENDORS = ["CrowdStrike","SentinelOne","Microsoft Defender","Palo Alto","Splunk","Wiz","Okta","Zscaler","Fortinet","Check Point","Proofpoint","Elastic","Tenable","Qualys","Rapid7","Darktrace","CyberArk","Cloudflare","Netskope","Snyk"];
var selectedVendor = "";
var score = 5;
var buyAgain = null;
var competitors = [];
var currentStep = 1;

var grid = document.getElementById("tool-grid");
VENDORS.forEach(function(v) {
  var btn = document.createElement("button");
  btn.className = "tool-btn";
  btn.textContent = v;
  btn.onclick = function() { selectVendor(v, btn); };
  grid.appendChild(btn);
});

function selectVendor(v, btn) {
  document.querySelectorAll(".tool-btn").forEach(function(b) { b.classList.remove("selected"); });
  btn.classList.add("selected");
  selectedVendor = v;
  document.getElementById("other-vendor").value = "";
  fetchCompetitors(v);
  setTimeout(function() { nextStep(2); }, 200);
}

document.getElementById("other-vendor").addEventListener("change", function() {
  if (this.value.trim()) {
    document.querySelectorAll(".tool-btn").forEach(function(b) { b.classList.remove("selected"); });
    selectedVendor = this.value.trim();
    fetchCompetitors(selectedVendor);
    setTimeout(function() { nextStep(2); }, 200);
  }
});

document.getElementById("score-slider").addEventListener("input", function() {
  score = parseInt(this.value);
  document.getElementById("score-display").textContent = score;
});

function nextStep(n) {
  document.getElementById("step" + currentStep).classList.remove("active");
  document.getElementById("step" + n).classList.add("active");
  var dots = document.querySelectorAll(".dot");
  for (var i = 0; i < dots.length; i++) {
    dots[i].classList.remove("active", "done");
    if (i < n - 1) dots[i].classList.add("done");
    if (i === n - 1) dots[i].classList.add("active");
  }
  currentStep = n;
}

var replacingVendor = "";

function setBuyAgain(val) {
  buyAgain = val;
  nextStep(4);
}

function setReplacing(val) {
  if (val === "nothing") {
    replacingVendor = "";
    nextStep(5);
  } else {
    document.getElementById("replacing-chips").style.display = "block";
    // Reuse competitor chips as replacing options
  }
}

function fetchCompetitors(vendor) {
  fetch("/api/v1/vendor-meta?vendor=" + encodeURIComponent(vendor))
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      var chips = document.getElementById("competitor-chips");
      chips.innerHTML = "";
      var comps = data.competitors || [];
      if (comps.length === 0) {
        chips.innerHTML = '<p style="color:#71717a;font-size:14px;">No competitors found</p>';
        return;
      }
      comps.forEach(function(c) {
        var chip = document.createElement("button");
        chip.className = "chip";
        chip.textContent = c;
        chip.onclick = function() {
          chip.classList.toggle("selected");
          if (chip.classList.contains("selected")) {
            competitors.push(c);
          } else {
            competitors = competitors.filter(function(x) { return x !== c; });
          }
        };
        chips.appendChild(chip);
      });
    })
    .catch(function() {
      document.getElementById("competitor-chips").innerHTML = '<p style="color:#71717a;font-size:14px;">Could not load competitors</p>';
    });
}

function submitQuick() {
  var email = document.getElementById("quick-email").value.trim();
  var errorEl = document.getElementById("email-error");
  errorEl.style.display = "none";
  if (!email || email.indexOf("@") === -1) {
    errorEl.textContent = "Work email required";
    errorEl.style.display = "block";
    return;
  }
  var vendor = selectedVendor;
  if (!vendor) {
    errorEl.textContent = "Please go back and select a vendor";
    errorEl.style.display = "block";
    return;
  }
  var formData = new FormData();
  formData.append("vendor", vendor);
  formData.append("overall_score", score);
  formData.append("would_buy", buyAgain === true ? "yes" : buyAgain === false ? "no" : "");
  formData.append("email", email);
  if (replacingVendor) formData.append("replacing", replacingVendor);
  competitors.forEach(function(c) { formData.append("also_evaluated", c); });
  fetch("/contribute", { method: "POST", body: formData, redirect: "follow" })
    .then(function(resp) {
      if (resp.redirected) {
        window.location.href = resp.url;
      } else if (resp.ok) {
        window.location.href = "/contribute/thanks?vendor=" + encodeURIComponent(vendor) + "&score=" + score;
      } else {
        return resp.text().then(function(text) {
          errorEl.textContent = text || "Submit failed";
          errorEl.style.display = "block";
        });
      }
    })
    .catch(function() {
      errorEl.textContent = "Network error — try again";
      errorEl.style.display = "block";
    });
}
</script>
</body>
</html>'''
        return _quick_html

    @app.get("/api/v1/scrape-stats")
    async def scrape_stats():
        """Stats on scraped data sources."""
        db = get_db()
        return await db.get_scrape_stats()

    return app


# Default app instance for `uvicorn nur.server.app:app`
# Reads DB URL from NUR_DB_URL env var (for Docker deployment)
app = create_app(db_url=os.environ.get("NUR_DB_URL", "sqlite+aiosqlite:///nur.db"))
