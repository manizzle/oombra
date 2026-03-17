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
from pydantic import BaseModel

from .db import Database
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
    global _db
    db_url = app.state.db_url if hasattr(app.state, "db_url") else "sqlite+aiosqlite:///nur.db"
    _db = Database(db_url)
    await _db.init()

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
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #1a1a1e;
    color: #c0c0c0;
    font-family: 'Courier New', monospace;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .container {{
    max-width: 640px;
    padding: 40px 24px;
    text-align: center;
  }}
  h1 {{
    font-size: 4em;
    color: #f0f0f0;
    letter-spacing: 0.3em;
    margin-bottom: 8px;
    text-shadow: 0 0 40px rgba(255,255,255,0.1);
  }}
  .meaning {{
    margin-bottom: 40px;
  }}
  .meaning-scripts {{
    font-size: 1.5em;
    color: #555;
    margin-bottom: 12px;
    letter-spacing: 0.2em;
  }}
  .meaning-scripts span {{
    margin: 0 12px;
  }}
  .meaning-langs {{
    font-size: 0.7em;
    color: #3a3a3a;
    letter-spacing: 0.1em;
    margin-bottom: 10px;
  }}
  .meaning-text {{
    font-size: 0.85em;
    color: #999;
    font-style: italic;
  }}
  .tagline {{
    font-size: 1.1em;
    color: #888;
    margin-bottom: 48px;
    line-height: 1.6;
  }}
  .stats {{
    display: flex;
    justify-content: center;
    gap: 32px;
    margin-bottom: 48px;
    flex-wrap: wrap;
  }}
  .stat {{
    text-align: center;
  }}
  .stat-num {{
    font-size: 2em;
    color: #f0f0f0;
    display: block;
  }}
  .stat-label {{
    font-size: 0.75em;
    color: #999;
    text-transform: uppercase;
    letter-spacing: 0.15em;
  }}
  .divider {{
    border: none;
    border-top: 1px solid #333;
    margin: 40px 0;
  }}
  .install {{
    background: #222228;
    border: 1px solid #333;
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 32px;
    text-align: left;
    font-size: 0.9em;
  }}
  .install code {{
    color: #aaa;
  }}
  .install .cmd {{
    color: #e0e0e0;
  }}
  .install .comment {{
    color: #777;
  }}
  .links {{
    display: flex;
    justify-content: center;
    gap: 24px;
    margin-bottom: 40px;
    flex-wrap: wrap;
  }}
  .links a {{
    color: #888;
    text-decoration: none;
    border-bottom: 1px solid #333;
    padding-bottom: 2px;
    transition: color 0.2s, border-color 0.2s;
    font-size: 0.9em;
  }}
  .links a:hover {{
    color: #f0f0f0;
    border-color: #666;
  }}
  .footer {{
    color: #999;
    font-size: 0.8em;
    margin-top: 48px;
    line-height: 1.8;
  }}
  .footer a {{
    color: #aaa;
    text-decoration: none;
  }}
  .pulse {{
    display: inline-block;
    width: 6px;
    height: 6px;
    background: #2a5;
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.3; }}
  }}
</style>
</head>
<body>
<div class="container">

  <h1>nur</h1>
  <div class="meaning">
    <div class="meaning-scripts">
      <span dir="rtl">نور</span>
      <span dir="rtl">ܢܘܪܐ</span>
      <span>nûr</span>
      <span>nuru</span>
    </div>
    <div class="meaning-text">
      "light" &mdash; one word, shared across languages, cultures, and continents
    </div>
  </div>
  <div class="tagline">
    collective security intelligence for industries.<br>
    give data, get smarter.
  </div>

  <div class="stats">
    <div class="stat">
      <span class="stat-num">{total}</span>
      <span class="stat-label">contributions</span>
    </div>
    <div class="stat">
      <span class="stat-num">{iocs + attacks}</span>
      <span class="stat-label">threat signals</span>
    </div>
    <div class="stat">
      <span class="stat-num">36</span>
      <span class="stat-label">vendors tracked</span>
    </div>
    <div class="stat">
      <span class="stat-num">37</span>
      <span class="stat-label">live feeds</span>
    </div>
  </div>

  <div class="install">
    <code>
      <span class="cmd">pip install nur</span><br>
      <span class="cmd">nur init</span><br>
      <span class="cmd">nur register you@yourorg.com</span><br>
      <span class="cmd">nur report incident.json</span>
    </code>
  </div>

  <div style="text-align:center;margin-bottom:24px;">
    <a href="/register" style="display:inline-block;background:#3b7;color:#1a1a1e;font-family:'Courier New',monospace;font-weight:bold;font-size:0.9em;padding:10px 28px;border-radius:3px;text-decoration:none;letter-spacing:0.05em;">get started &rarr;</a>
  </div>

  <div class="links">
    <a href="/dashboard">dashboard</a>
    <a href="/guide">docs</a>
    <a href="https://github.com/manizzle/nur">github</a>
    <a href="https://github.com/manizzle/nur/issues/4">add your feed</a>
  </div>

  <hr class="divider">

  <div class="footer">
    <span class="pulse"></span> live &mdash; scraping 37 threat feeds<br><br>
    attackers share everything.<br>
    defenders share nothing.<br>
    nur fixes that.<br><br>
    <a href="https://github.com/manizzle/nur">apache 2.0</a> &bull;
    <a href="https://github.com/manizzle/nur/blob/main/DATA_LICENSE.md">cdla-permissive-2.0</a>
  </div>

</div>
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
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #1a1a1e;
    color: #c0c0c0;
    font-family: 'Courier New', monospace;
    min-height: 100vh;
    padding: 0;
  }}

  /* ── Header ─────────────────────────────────────── */
  .dash-header {{
    text-align: center;
    padding: 48px 24px 32px;
    border-bottom: 1px solid #333338;
  }}
  .dash-header h1 {{
    font-size: 2.4em;
    color: #f0f0f0;
    letter-spacing: 0.25em;
    margin-bottom: 12px;
  }}
  .dash-header h1 span {{
    color: #3b7;
  }}
  .hero-stat {{
    font-size: 4.5em;
    font-weight: bold;
    color: #3b7;
    line-height: 1;
    margin-bottom: 8px;
    text-shadow: 0 0 60px rgba(34,170,85,0.3);
  }}
  .hero-label {{
    font-size: 0.85em;
    color: #999;
    letter-spacing: 0.1em;
  }}
  .dash-subtitle {{
    margin-top: 12px;
    font-size: 0.8em;
    color: #777;
  }}
  .pulse {{
    display: inline-block;
    width: 6px;
    height: 6px;
    background: #3b7;
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.3; }}
  }}

  /* ── Layout ─────────────────────────────────────── */
  .dash-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    max-width: 1200px;
    margin: 0 auto;
  }}
  .dash-section {{
    padding: 32px 28px;
    border-bottom: 1px solid #333338;
  }}
  .dash-section:nth-child(odd) {{
    border-right: 1px solid #333338;
  }}
  .dash-section.full {{
    grid-column: 1 / -1;
    border-right: none;
  }}
  .section-title {{
    font-size: 0.7em;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: #888;
    margin-bottom: 20px;
  }}
  .section-title::before {{
    content: '/// ';
    color: #666;
  }}

  /* ── Stat boxes ─────────────────────────────────── */
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }}
  .stat-box {{
    background: #222228;
    border: 1px solid #333338;
    border-radius: 4px;
    padding: 20px 16px;
    text-align: center;
    transition: border-color 0.3s;
  }}
  .stat-box:hover {{
    border-color: #3b7;
  }}
  .stat-box .num {{
    font-size: 2.2em;
    font-weight: bold;
    color: #f0f0f0;
    display: block;
    line-height: 1.1;
  }}
  .stat-box .label {{
    font-size: 0.65em;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-top: 6px;
    display: block;
  }}

  /* ── Chart containers ───────────────────────────── */
  .chart-wrap {{
    position: relative;
    width: 100%;
    background: #222228;
    border: 1px solid #333338;
    border-radius: 4px;
    padding: 16px;
  }}
  .chart-wrap canvas {{
    width: 100% !important;
  }}
  .chart-empty {{
    text-align: center;
    padding: 48px 16px;
    color: #666;
    font-size: 0.85em;
  }}

  /* ── CTA section ────────────────────────────────── */
  .cta {{
    text-align: center;
    padding: 48px 24px;
  }}
  .cta-tagline {{
    font-size: 1.3em;
    color: #888;
    margin-bottom: 24px;
  }}
  .cta-install {{
    background: #222228;
    border: 1px solid #333;
    border-radius: 4px;
    padding: 20px 28px;
    display: block;
    max-width: 380px;
    margin: 0 auto 24px;
    text-align: left;
    font-size: 0.9em;
  }}
  .cta-install code {{ color: #aaa; }}
  .cta-install .cmd {{ color: #e0e0e0; }}
  .cta-install .comment {{ color: #777; }}
  .cta-links {{
    display: flex;
    justify-content: center;
    gap: 20px;
    flex-wrap: wrap;
  }}
  .cta-links a {{
    color: #888;
    text-decoration: none;
    border-bottom: 1px solid #333;
    padding-bottom: 2px;
    transition: color 0.2s, border-color 0.2s;
    font-size: 0.9em;
  }}
  .cta-links a:hover {{
    color: #3b7;
    border-color: #3b7;
  }}
  .cta-btn {{
    display: inline-block;
    background: #3b7;
    color: #1a1a1e;
    font-family: 'Courier New', monospace;
    font-weight: bold;
    font-size: 0.9em;
    padding: 10px 28px;
    border-radius: 3px;
    text-decoration: none;
    letter-spacing: 0.05em;
    transition: background 0.2s;
    margin-bottom: 20px;
  }}
  .cta-btn:hover {{
    background: #3b6;
  }}

  /* ── Footer ─────────────────────────────────────── */
  .dash-footer {{
    text-align: center;
    padding: 24px;
    color: #666;
    font-size: 0.7em;
    border-top: 1px solid #333338;
  }}
  .dash-footer a {{
    color: #777;
    text-decoration: none;
  }}

  /* ── Responsive ─────────────────────────────────── */
  @media (max-width: 768px) {{
    .dash-grid {{
      grid-template-columns: 1fr;
    }}
    .dash-section:nth-child(odd) {{
      border-right: none;
    }}
    .stat-grid {{
      grid-template-columns: repeat(2, 1fr);
    }}
    .hero-stat {{
      font-size: 3em;
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
    <div style="padding:16px;">
      <div style="color:#ccc;font-size:1.1em;margin-bottom:12px;">Healthcare Ransomware</div>
      <div style="color:#888;font-size:0.85em;line-height:1.8;">
        Initial access: Spearphishing (89%)<br>
        Avg dwell time: 4.2 days<br>
        Most missed technique: T1490 (71%)<br>
        Ransom paid: 12% of cases<br>
        Avg recovery: 2.1 weeks
      </div>
      <a href="/intelligence/patterns/healthcare" style="color:#3b7;font-size:0.8em;text-decoration:none;border-bottom:1px solid #333;">view all patterns &rarr;</a>
    </div>
  </div>

  <!-- Attack Chain Simulator -->
  <div class="dash-section">
    <div class="section-title">Attack Chain Simulator</div>
    <div style="padding:16px;">
      <div style="background:#222228;border:1px solid #333;border-radius:4px;padding:12px;font-size:0.85em;">
        <code style="color:#aaa;">
          nur simulate &#92;<br>
          &nbsp;&nbsp;--stack crowdstrike,splunk,okta &#92;<br>
          &nbsp;&nbsp;--vertical healthcare
        </code>
      </div>
      <div style="color:#888;font-size:0.8em;margin-top:12px;line-height:1.6;">
        Simulates the most common attack chain<br>
        against your tools. Shows exactly where<br>
        your defenses break.
      </div>
      <a href="/intelligence/simulate" style="color:#3b7;font-size:0.8em;text-decoration:none;border-bottom:1px solid #333;">try via API &rarr;</a>
    </div>
  </div>

  <!-- CTA -->
  <div class="dash-section full cta">
    <div class="cta-tagline">give data, get smarter.</div>
    <div class="cta-install">
      <code>
        <span class="cmd">pip install nur</span><br>
        <span class="cmd">nur init</span><br>
        <span class="cmd">nur register you@yourorg.com</span><br>
        <span class="cmd">nur report incident.json</span>
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
    var r = Math.round(10 + ratio * 24);
    var g = Math.round(60 + ratio * 110);
    var b = Math.round(20 + ratio * 65);
    return 'rgb(' + r + ',' + g + ',' + b + ')';
  }}

  // ── Chart.js global defaults ───────────────────────────────
  Chart.defaults.color = '#666';
  Chart.defaults.borderColor = '#1a1a1a';
  Chart.defaults.font.family = "'Courier New', monospace";
  Chart.defaults.font.size = 11;

  // ── Submissions by type (donut chart) ────────────────────
  fetch('/stats')
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      var bt = data.by_type || {{}};
      var labels = [];
      var counts = [];
      var colors = ['#3b7', '#2980b9', '#e67e22', '#9b59b6', '#e74c3c'];
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
            borderColor: '#1a1a1e',
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
              labels: {{ color: '#aaa', font: {{ size: 12, family: "'Courier New', monospace" }}, padding: 16 }},
            }},
            tooltip: {{
              backgroundColor: '#222',
              titleColor: '#f0f0f0',
              bodyColor: '#aaa',
              borderColor: '#3b7',
              borderWidth: 1,
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
        borderRadius: 2,
      }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          backgroundColor: '#222',
          titleColor: '#f0f0f0',
          bodyColor: '#aaa',
          borderColor: '#3b7',
          borderWidth: 1,
        }},
      }},
      scales: {{
        x: {{
          grid: {{ color: '#2a2a30' }},
          ticks: {{ color: '#888' }},
        }},
        y: {{
          grid: {{ display: false }},
          ticks: {{ color: '#ccc', font: {{ size: 11 }} }},
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
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #1a1a1e; color: #c0c0c0; font-family: 'Courier New', monospace; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { max-width: 520px; padding: 40px 24px; text-align: center; }
  h1 { font-size: 2em; color: #f0f0f0; margin-bottom: 8px; }
  .sub { color: #999; margin-bottom: 32px; font-size: 0.9em; }
  .install { background: #222228; border: 1px solid #222; border-radius: 4px; padding: 20px; text-align: left; font-size: 0.9em; margin-bottom: 32px; }
  .install code { color: #aaa; }
  .install .cmd { color: #e0e0e0; }
  .install .comment { color: #777; }
  .tiers { text-align: left; font-size: 0.8em; color: #888; line-height: 1.8; }
  .tiers strong { color: #888; }
  a { color: #999; }
</style>
</head>
<body>
<div class="container">
  <h1>get your API key</h1>
  <div class="sub">register via the CLI. generates a keypair on your machine.</div>

  <div class="install">
    <code>
      <span class="comment"># install</span><br>
      <span class="cmd">pip install nur</span><br><br>
      <span class="comment"># set up (saves server URL, generates keypair)</span><br>
      <span class="cmd">nur init</span><br><br>
      <span class="comment"># register with your work email</span><br>
      <span class="cmd">nur register you@yourhospital.org</span><br><br>
      <span class="comment"># check your email, click the link, get your key</span><br>
      <span class="comment"># then start reporting</span><br>
      <span class="cmd">nur report incident.json</span>
    </code>
  </div>

  <div class="tiers">
    <strong>why CLI-only registration?</strong><br>
    &bull; generates a cryptographic keypair on your machine<br>
    &bull; private key never leaves your machine<br>
    &bull; every request is signed — stolen API keys are useless<br>
    &bull; work email required (no gmail/yahoo)<br><br>
    <strong>community tier</strong> (free, forever):<br>
    &bull; contribute data, get intelligence reports<br>
    &bull; 37 threat feed sources<br><br>
    <strong>enterprise tier</strong> (coming soon):<br>
    &bull; real-time aggregate data<br>
    &bull; custom verticals, SLA, integrations<br><br>
    <a href="/">&larr; back to nur</a>
  </div>
</div>
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
    async def contribute_eval(body: dict[str, Any]):
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
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/attack-map")
    async def contribute_attack_map(body: dict[str, Any]):
        techniques = body.get("techniques", [])
        if len(techniques) > 500:
            raise HTTPException(status_code=400, detail="Too many techniques (max 500)")
        db = get_db()
        cid = await db.store_attack_map(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/ioc-bundle")
    async def contribute_ioc_bundle(body: dict[str, Any]):
        iocs = body.get("iocs", [])
        if len(iocs) > 10000:
            raise HTTPException(status_code=400, detail="Too many IOCs (max 10,000)")
        db = get_db()
        cid = await db.store_ioc_bundle(body)
        return {"status": "accepted", "contribution_id": cid}

    # ── Webhook ingest (wartime integrations) ────────────────────────

    @app.post("/ingest/webhook")
    async def ingest_webhook(body: dict[str, Any]):
        """Universal webhook — accepts data from Splunk, Sentinel, CrowdStrike,
        syslog/CEF, or generic IOC lists. Auto-detects format and stores."""
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

            return {
                "status": "accepted",
                "format_detected": "crowdstrike",
                "items_stored": items_stored,
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

            return {
                "status": "accepted",
                "format_detected": "sentinel",
                "items_stored": items_stored,
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
    async def analyze(body: dict[str, Any]):
        db = get_db()
        from .analyze import (
            analyze_ioc_bundle, analyze_attack_map, analyze_eval_record,
            detect_contribution_type,
        )
        try:
            contrib_type = detect_contribution_type(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if contrib_type == "ioc_bundle":
            return await analyze_ioc_bundle(body, db)
        elif contrib_type == "attack_map":
            return await analyze_attack_map(body, db)
        elif contrib_type == "eval":
            return await analyze_eval_record(body, db)
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
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #1a1a1e;
    color: #c0c0c0;
    font-family: 'Courier New', monospace;
    min-height: 100vh;
    padding: 0;
  }
  .guide-header {
    text-align: center;
    padding: 48px 24px 32px;
    border-bottom: 1px solid #333338;
  }
  .guide-header h1 {
    font-size: 2.4em;
    color: #f0f0f0;
    letter-spacing: 0.25em;
    margin-bottom: 8px;
  }
  .guide-header h1 span { color: #3b7; }
  .guide-header p {
    color: #888;
    font-size: 0.9em;
  }
  html { scroll-behavior: smooth; }
  .guide-nav {
    position: sticky;
    top: 0;
    z-index: 100;
    background: #1a1a1e;
    border-bottom: 1px solid #333338;
    padding: 12px 24px;
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    justify-content: center;
    backdrop-filter: blur(8px);
  }
  .guide-nav a {
    color: #888;
    text-decoration: none;
    font-size: 0.8em;
    padding: 4px 8px;
    border-radius: 3px;
    transition: color 0.2s, background 0.2s;
  }
  .guide-nav a:hover { color: #3b7; background: #222228; }
  .guide-nav a.active { color: #3b7; background: #222228; }
  .back-to-top {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #222228;
    border: 1px solid #333;
    color: #888;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: none;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    font-size: 1.2em;
    transition: color 0.2s, border-color 0.2s;
    z-index: 100;
  }
  .back-to-top:hover { color: #3b7; border-color: #3b7; }
  .guide-content {
    max-width: 900px;
    margin: 0 auto;
    padding: 0 24px 64px;
  }
  .guide-section {
    padding: 40px 0 32px;
    border-bottom: 1px solid #2a2a2e;
  }
  .guide-section:last-child { border-bottom: none; }
  .guide-section h2 {
    font-size: 1.1em;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #f0f0f0;
    margin-bottom: 20px;
  }
  .guide-section h2::before {
    content: '/// ';
    color: #3b7;
  }
  .guide-section h3 {
    font-size: 0.9em;
    color: #ccc;
    margin: 20px 0 10px;
  }
  .guide-section p, .guide-section li {
    font-size: 0.85em;
    color: #999;
    line-height: 1.8;
  }
  .guide-section ul {
    list-style: none;
    padding: 0;
  }
  .guide-section ul li::before {
    content: '- ';
    color: #3b7;
  }
  pre {
    background: #222228;
    border: 1px solid #333;
    border-radius: 4px;
    padding: 16px 20px;
    font-size: 0.85em;
    color: #aaa;
    overflow-x: auto;
    margin: 12px 0;
    line-height: 1.7;
  }
  code {
    color: #aaa;
    font-family: 'Courier New', monospace;
  }
  .cmd { color: #e0e0e0; }
  .comment { color: #666; }
  .api-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8em;
    margin: 12px 0;
  }
  .api-table th {
    text-align: left;
    color: #888;
    font-weight: normal;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 8px 12px;
    border-bottom: 1px solid #333;
  }
  .api-table td {
    padding: 8px 12px;
    border-bottom: 1px solid #2a2a2e;
    color: #aaa;
    vertical-align: top;
  }
  .api-table td:first-child { color: #3b7; white-space: nowrap; }
  .api-table td:nth-child(2) { color: #ccc; }
  .privacy-level {
    background: #222228;
    border: 1px solid #333;
    border-radius: 4px;
    padding: 12px 16px;
    margin: 8px 0;
  }
  .privacy-level strong { color: #ccc; }
  .guide-footer {
    text-align: center;
    padding: 24px;
    color: #666;
    font-size: 0.7em;
    border-top: 1px solid #333338;
  }
  .guide-footer a { color: #777; text-decoration: none; }
  @media (max-width: 768px) {
    .guide-content { padding: 0 16px 48px; }
    pre { font-size: 0.75em; padding: 12px; }
    .api-table { font-size: 0.7em; }
  }
</style>
</head>
<body>

<div class="guide-header">
  <h1>nur <span>guide</span></h1>
  <p>everything you need to know to use nur</p>
</div>

<div class="guide-nav">
  <a href="#quick-start">quick start</a>
  <a href="#wartime">wartime</a>
  <a href="#peacetime">peacetime</a>
  <a href="#integrations">integrations</a>
  <a href="#api">api reference</a>
  <a href="#privacy">privacy</a>
  <a href="#self-hosting">self-hosting</a>
  <a href="/">home</a>
  <a href="/guide">docs</a>
</div>

<div class="guide-content">

  <!-- Quick Start -->
  <div class="guide-section" id="quick-start">
    <h2>Quick Start</h2>
    <p>Install the CLI, register with your work email, start contributing.</p>
    <pre><span class="comment"># install</span>
<span class="cmd">pip install nur</span>

<span class="comment"># initialize (saves server URL, generates keypair)</span>
<span class="cmd">nur init</span>

<span class="comment"># register with your work email (gmail/yahoo blocked)</span>
<span class="cmd">nur register you@yourorg.com</span>

<span class="comment"># check your email, click the magic link, get your API key</span>
<span class="comment"># then start reporting</span>
<span class="cmd">nur report incident.json</span></pre>
    <p>That's it. Your data is anonymized locally before it leaves your machine. You get back collective intelligence from everyone who contributed.</p>
  </div>

  <!-- Wartime -->
  <div class="guide-section" id="wartime">
    <h2>Wartime Commands</h2>
    <p>You're under attack. Upload IOCs, get campaign matches, detection gaps, remediation actions.</p>

    <h3>Report IOCs</h3>
    <pre><span class="cmd">nur report incident_iocs.json</span>

<span class="comment"># Response:</span>
  Campaign Match: Yes &mdash; 4 other healthcare orgs
  Shared IOCs: 32 &middot; Threat Actor: LockBit

  Actions:
    [CRITICAL] Block C2 domains at firewall
    [CRITICAL] Deploy T1490 detection &mdash; your tools miss it
    [HIGH]     Hunt for RDP lateral movement

  What worked at other orgs:
    - Isolated RDP across all subnets (stopped_attack)
    - Deployed Sigma rule for vssadmin delete (stopped_attack)</pre>

    <h3>Report attack maps</h3>
    <pre><span class="cmd">nur report attack_map.json</span>     <span class="comment"># detection gap analysis</span></pre>

    <h3>Report tool evaluations</h3>
    <pre><span class="cmd">nur report eval.json</span>            <span class="comment"># benchmark your tools</span></pre>

    <h3>JSON output</h3>
    <pre><span class="cmd">nur report incident.json --json | jq '.intelligence.actions'</span></pre>
  </div>

  <!-- Peacetime -->
  <div class="guide-section" id="peacetime">
    <h2>Peacetime Commands</h2>
    <p>Build defenses. Market maps, vendor comparisons, threat modeling, attack simulations.</p>

    <h3>Market intelligence</h3>
    <pre><span class="cmd">nur market edr</span>                                       <span class="comment"># vendor rankings by category</span>
<span class="cmd">nur search vendor crowdstrike</span>                        <span class="comment"># real scores, not Gartner</span>
<span class="cmd">nur search compare crowdstrike sentinelone</span>           <span class="comment"># side-by-side comparison</span></pre>

    <h3>Threat modeling</h3>
    <pre><span class="cmd">nur threat-model --stack crowdstrike,splunk,okta --vertical healthcare</span>

<span class="comment"># Response:</span>
  Coverage: 75% (6/8 priority techniques)
  Gaps: T1566 Spearphishing &rarr; add email security
        T1048 Exfiltration &rarr; add NDR or DLP
  Compliance: HIPAA &check; &middot; NIST CSF &check; &middot; HITECH &cross;

<span class="comment"># Export as HCL (threatcl-compatible)</span>
<span class="cmd">nur threat-model --stack crowdstrike,splunk --hcl --output model.hcl</span></pre>

    <h3>Attack patterns</h3>
    <pre><span class="cmd">nur patterns healthcare</span>          <span class="comment"># attack methodology patterns for a vertical</span>
<span class="cmd">nur patterns financial</span>           <span class="comment"># what APT groups target finance</span></pre>

    <h3>Attack simulation</h3>
    <pre><span class="cmd">nur simulate --stack crowdstrike,splunk,okta --vertical healthcare</span>

<span class="comment"># Simulates the most common attack chain against your stack</span>
<span class="comment"># Shows exactly where your defenses break, step by step</span></pre>
  </div>

  <!-- Integrations -->
  <div class="guide-section" id="integrations">
    <h2>Integrations</h2>
    <p>Plug nur into your existing security stack. 10 integration points.</p>

    <h3>SIEM / EDR</h3>
    <pre><span class="cmd">nur integrate splunk</span>             <span class="comment"># forward alerts from Splunk</span>
<span class="cmd">nur integrate sentinel</span>           <span class="comment"># forward incidents from Microsoft Sentinel</span>
<span class="cmd">nur integrate crowdstrike</span>        <span class="comment"># forward detections from CrowdStrike</span></pre>

    <h3>Syslog / Webhook</h3>
    <pre><span class="cmd">nur integrate syslog --port 1514</span> <span class="comment"># listen for CEF/syslog events</span>
<span class="comment"># or POST to /ingest/webhook with any supported format</span></pre>

    <h3>Import</h3>
    <pre><span class="cmd">nur import navigator layer.json</span>  <span class="comment"># import MITRE ATT&amp;CK Navigator layers</span>
<span class="cmd">nur import stack inventory.csv</span>   <span class="comment"># import your tool inventory</span>
<span class="cmd">nur import compliance soc2.json</span>  <span class="comment"># import compliance framework mappings</span>
<span class="cmd">nur import rfp responses.json</span>    <span class="comment"># import vendor RFP responses</span></pre>

    <h3>Export</h3>
    <pre><span class="cmd">nur export stix</span>                  <span class="comment"># export intelligence as STIX 2.1</span>
<span class="cmd">nur export misp</span>                  <span class="comment"># export as MISP events</span></pre>

    <h3>Python SDK</h3>
    <pre>from nur import load_file, anonymize, submit
data  = load_file("incident.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="https://nur.saramena.us") for c in clean]</pre>
  </div>

  <!-- API Reference -->
  <div class="guide-section" id="api">
    <h2>API Reference</h2>
    <p>All endpoints. Full API documentation with examples.</p>

    <table class="api-table">
      <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      <tr><td>POST</td><td>/analyze</td><td>Give data, get intelligence report</td></tr>
      <tr><td>POST</td><td>/contribute/submit</td><td>Submit tool evaluation</td></tr>
      <tr><td>POST</td><td>/contribute/attack-map</td><td>Submit attack map with techniques</td></tr>
      <tr><td>POST</td><td>/contribute/ioc-bundle</td><td>Submit IOC bundle</td></tr>
      <tr><td>POST</td><td>/ingest/webhook</td><td>Universal webhook (Splunk, Sentinel, CrowdStrike, CEF, generic)</td></tr>
      <tr><td>POST</td><td>/register</td><td>Register with work email + public key</td></tr>
      <tr><td>POST</td><td>/threat-model</td><td>Generate MITRE-mapped threat model for your stack</td></tr>
      <tr><td>GET</td><td>/intelligence/market/{category}</td><td>Vendor market map by category</td></tr>
      <tr><td>POST</td><td>/intelligence/threat-map</td><td>Map threat to MITRE techniques, show coverage gaps</td></tr>
      <tr><td>GET</td><td>/intelligence/danger-radar</td><td>Vendors with hidden risk signals</td></tr>
      <tr><td>GET</td><td>/intelligence/patterns/{vertical}</td><td>Attack methodology patterns for an industry</td></tr>
      <tr><td>POST</td><td>/intelligence/simulate</td><td>Simulate attack chain against your stack</td></tr>
      <tr><td>GET</td><td>/search/vendor/{name}</td><td>Vendor scores and details</td></tr>
      <tr><td>GET</td><td>/search/compare?a=X&amp;b=Y</td><td>Side-by-side vendor comparison</td></tr>
      <tr><td>GET</td><td>/dashboard</td><td>Visual dashboard with charts</td></tr>
      <tr><td>GET</td><td>/guide</td><td>This documentation page</td></tr>
      <tr><td>GET</td><td>/health</td><td>Liveness check</td></tr>
      <tr><td>GET</td><td>/stats</td><td>Contribution counts (anonymized)</td></tr>
    </table>

    <h3>Example: analyze IOCs</h3>
    <pre>curl -X POST https://nur.saramena.us/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: nur_yourkey" \
  -d '{"iocs": [{"ioc_type": "ip", "value": "203.0.113.42"}]}'</pre>

    <h3>Example: threat model</h3>
    <pre>curl -X POST https://nur.saramena.us/threat-model \
  -H "Content-Type: application/json" \
  -H "X-API-Key: nur_yourkey" \
  -d '{"stack": ["crowdstrike", "splunk"], "vertical": "healthcare"}'</pre>

    <h3>Example: simulate attack</h3>
    <pre>curl -X POST https://nur.saramena.us/intelligence/simulate \
  -H "Content-Type: application/json" \
  -d '{"stack": ["crowdstrike", "splunk", "okta"], "vertical": "healthcare"}'</pre>
  </div>

  <!-- Trustless Architecture -->
  <div class="guide-section" id="privacy">
    <h2>Trustless Architecture</h2>
    <p>In the age of AI data mining, nur is designed so your data <strong>cannot be mined, sold, or misused</strong> &mdash; not because we promise, but because the math makes it impossible.</p>

    <h3>How it works</h3>
    <div class="privacy-level">
      <strong>1. Your machine anonymizes everything</strong>
      <p style="color:#999;font-size:0.85em;margin-top:4px;">
        PII scrubbed, IOCs hashed, org identity bucketed. All fields are numeric or categorical &mdash; no free text.
        Optional Laplace noise on numeric values for differential privacy.
      </p>
    </div>

    <div class="privacy-level">
      <strong>2. Server commits, aggregates, and discards</strong>
      <p style="color:#999;font-size:0.85em;margin-top:4px;">
        Every value is committed (Pedersen-style hash). Commitments go into a Merkle tree.
        Running aggregate sums are updated. <strong>Individual values are then discarded.</strong>
        The server retains only: commitment hashes + aggregate sums.
      </p>
    </div>

    <div class="privacy-level">
      <strong>3. Every query comes with a proof</strong>
      <p style="color:#999;font-size:0.85em;margin-top:4px;">
        When anyone queries an aggregate ("CrowdStrike avg score"), the server returns
        the answer <strong>plus a cryptographic proof chain</strong>: Merkle root, contributor count,
        commitment hashes. Anyone can verify the aggregate is real.
      </p>
    </div>

    <div class="privacy-level">
      <strong>4. You get a receipt</strong>
      <p style="color:#999;font-size:0.85em;margin-top:4px;">
        Every contribution returns a cryptographic receipt: commitment hash,
        Merkle inclusion proof, server signature. You can prove your data was
        included correctly. The server can't deny receiving it.
      </p>
    </div>

    <h3>Crypto primitives</h3>
    <ul>
      <li><strong>Pedersen Commitments</strong> &mdash; server can't alter values after receipt</li>
      <li><strong>Merkle Tree</strong> &mdash; server can't add/remove contributions undetected</li>
      <li><strong>ZKP Range Proofs</strong> &mdash; proves scores are valid without revealing them</li>
      <li><strong>Secure Histograms</strong> &mdash; technique frequency from binary vector sums</li>
      <li><strong>BDP Credibility</strong> &mdash; behavior-based lie detection for data poisoning</li>
      <li><strong>Platform Attestation</strong> &mdash; proves "N real contributions" with Merkle proof</li>
    </ul>

    <h3>What the server stores</h3>
    <ul>
      <li>Commitment hashes (opaque SHA-256 strings)</li>
      <li>Running aggregate sums per vendor (a single number, not a list of scores)</li>
      <li>Technique frequency counters (T1566 &rarr; 47, not who reported it)</li>
      <li>Merkle tree of all commitments</li>
    </ul>

    <h3>What the server does NOT store</h3>
    <ul>
      <li>Individual scores, detection rates, or boolean flags</li>
      <li>Which org contributed which data</li>
      <li>Raw IOCs, IPs, domains, or indicators</li>
      <li>Free-text notes or remediation descriptions</li>
      <li>Your private key or org identity</li>
    </ul>
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
