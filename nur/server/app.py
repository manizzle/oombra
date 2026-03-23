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


def get_or_create_profile(api_key: str | None) -> BehavioralProfile:
    """Get or create a behavioral profile for a participant.

    Key is SHA-256 of the API key — server never stores raw keys in profiles.
    """
    if not api_key:
        return BehavioralProfile(participant_id="anonymous")
    pid = _hashlib_mod.sha256(api_key.encode()).hexdigest()[:16]
    if pid not in _profiles:
        _profiles[pid] = BehavioralProfile(
            participant_id=pid,
            first_seen_ts=time.time(),
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
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email required")

        # Block free/personal email providers
        domain = email.split("@")[1]
        if domain in _FREE_EMAIL_DOMAINS:
            raise HTTPException(
                status_code=400,
                detail=f"Work email required. {domain} is not accepted. Use your organization's email.",
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

            # Create pending verification with magic link token
            from .models import PendingVerification
            token = _secrets.token_urlsafe(32)
            public_key = (body.get("public_key") or "")[:64] or None
            s.add(PendingVerification(email=email, org_name=org or None, token=token, public_key=public_key))

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
                s.add(APIKeyRecord(
                    email=pending.email, api_key=api_key,
                    org_name=pending.org_name, tier="community",
                    public_key=pending.public_key,
                ))

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
  <a href="/">nur</a> &bull; collective security intelligence &bull;
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
  <p>quick reference &mdash; see <a href="https://github.com/manizzle/nur" style="color:#22c55e;">README</a> for full docs</p>
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
    <p>Data is anonymized locally before it leaves your machine. You get back collective intelligence from everyone who contributed.</p>
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
      <tr><td>GET</td><td>/health</td><td>Liveness check</td></tr>
      <tr><td>GET</td><td>/stats</td><td>Contribution counts (anonymized)</td></tr>
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
  <a href="/">nur</a> &bull; collective security intelligence &bull;
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

    return app


# Default app instance for `uvicorn nur.server.app:app`
# Reads DB URL from NUR_DB_URL env var (for Docker deployment)
app = create_app(db_url=os.environ.get("NUR_DB_URL", "sqlite+aiosqlite:///nur.db"))
