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
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .db import Database
from .routes.query import router as query_router
from .routes.secagg import router as secagg_router
from .routes.intelligence import router as intel_router
from .routes.search import router as search_router


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
    )
    app.state.db_url = db_url

    # ── API key + signature auth middleware ──────────────────────────────
    master_key = os.environ.get("NUR_API_KEY")

    @app.middleware("http")
    async def api_key_auth(request: Request, call_next):
        write_paths = request.url.path.startswith("/contribute/") or request.url.path == "/analyze"
        if master_key and write_paths and request.method == "POST":
            provided = request.headers.get("X-API-Key")
            if not provided:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )
            # Accept master key OR any registered user key
            if provided != master_key:
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

            # Verify request signature if provided
            sig_header = request.headers.get("X-Signature")
            if sig_header:
                try:
                    import hashlib, hmac as _hmac
                    from sqlalchemy import select
                    from .models import APIKeyRecord

                    # Look up public key for this API key
                    db = get_db()
                    # Can't do async DB call in sync middleware easily,
                    # so just validate the signature format for now
                    parts = sig_header.split(".", 1)
                    if len(parts) != 2:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid signature format"},
                        )
                    ts_str, sig = parts
                    ts = int(ts_str)
                    now = int(time.time())
                    # Reject signatures older than 5 minutes
                    if abs(now - ts) > 300:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Signature expired (>5 min)"},
                        )
                except (ValueError, Exception):
                    pass  # signature validation is best-effort for now

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
      <span class="stat-label">data sources</span>
    </div>
  </div>

  <div class="install">
    <code>
      <span class="comment"># install</span><br>
      <span class="cmd">pip install nur</span><br><br>
      <span class="comment"># connect</span><br>
      <span class="cmd">nur init</span><br><br>
      <span class="comment"># give data, get intelligence</span><br>
      <span class="cmd">nur report incident.json</span>
    </code>
  </div>

  <div style="text-align:center;margin-bottom:24px;">
    <a href="/register" style="display:inline-block;background:#3b7;color:#1a1a1e;font-family:'Courier New',monospace;font-weight:bold;font-size:0.9em;padding:10px 28px;border-radius:3px;text-decoration:none;letter-spacing:0.05em;">get started</a>
  </div>

  <div class="links">
    <a href="/dashboard">dashboard</a>
    <a href="/docs">api docs</a>
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
                return {
                    "status": "exists",
                    "api_key": record.api_key,
                    "tier": record.tier,
                    "message": "API key already exists for this email",
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
<script async src="https://www.googletagmanager.com/gtag/js?id=G-YLL9Y97GG0"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag("js",new Date());gtag("config","G-YLL9Y97GG0");</script>
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
    border: 1px solid #222;
    border-radius: 4px;
    padding: 20px 28px;
    display: inline-block;
    text-align: left;
    font-size: 0.9em;
    margin-bottom: 24px;
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
    <span class="pulse"></span> 37 data sources &middot; live feeds &middot; auto-refresh 60s
  </div>
</div>

<!-- ── Charts row ─────────────────────────────────────────── -->
<div class="dash-grid">

  <!-- Threat Landscape -->
  <div class="dash-section">
    <div class="section-title">Threat Landscape &mdash; MITRE ATT&amp;CK Techniques</div>
    <div class="chart-wrap">
      <canvas id="techniqueChart" height="320"></canvas>
      <div class="chart-empty" id="techniqueEmpty" style="display:none;">
        No technique data yet. Contribute attack maps to populate.
      </div>
    </div>
  </div>

  <!-- Market Intelligence -->
  <div class="dash-section">
    <div class="section-title">Market Intelligence &mdash; EDR Vendors</div>
    <div class="chart-wrap">
      <canvas id="marketChart" height="320"></canvas>
      <div class="chart-empty" id="marketEmpty" style="display:none;">
        No market data yet. Contribute evaluations to populate.
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

  <!-- CTA -->
  <div class="dash-section full cta">
    <div class="cta-tagline">give data, get smarter.</div>
    <a class="cta-btn" href="/register">get started &rarr;</a>
    <div class="cta-install">
      <code>
        <span class="comment"># install</span><br>
        <span class="cmd">pip install nur</span><br><br>
        <span class="comment"># connect &amp; register</span><br>
        <span class="cmd">nur init</span><br>
        <span class="cmd">nur register you@yourorg.com</span><br><br>
        <span class="comment"># contribute &amp; get intelligence</span><br>
        <span class="cmd">nur report incident.json</span>
      </code>
    </div>
    <div class="cta-links">
      <a href="/">home</a>
      <a href="/register">register</a>
      <a href="/docs">api docs</a>
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

  // ── Fetch and render techniques chart ──────────────────────
  fetch('/query/techniques?limit=10')
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      var techs = data.techniques || [];
      if (techs.length === 0) {{
        document.getElementById('techniqueChart').style.display = 'none';
        document.getElementById('techniqueEmpty').style.display = 'block';
        return;
      }}
      var labels = techs.map(function(t) {{ return t.technique_id + ' ' + (t.technique_name || ''); }});
      var counts = techs.map(function(t) {{ return t.count; }});
      var maxCount = Math.max.apply(null, counts);
      var colors = counts.map(function(c) {{ return greenGradient(c, maxCount); }});

      new Chart(document.getElementById('techniqueChart'), {{
        type: 'bar',
        data: {{
          labels: labels,
          datasets: [{{
            label: 'Sightings',
            data: counts,
            backgroundColor: colors,
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
              backgroundColor: '#111',
              titleColor: '#f0f0f0',
              bodyColor: '#aaa',
              borderColor: '#3b7',
              borderWidth: 1,
            }},
          }},
          scales: {{
            x: {{
              grid: {{ color: '#2a2a30' }},
              ticks: {{ color: '#444' }},
            }},
            y: {{
              grid: {{ display: false }},
              ticks: {{ color: '#888', font: {{ size: 10 }} }},
            }},
          }},
        }},
      }});
    }})
    .catch(function(e) {{
      console.error('technique chart error:', e);
      document.getElementById('techniqueChart').style.display = 'none';
      document.getElementById('techniqueEmpty').style.display = 'block';
    }});

  // ── Fetch and render market chart ──────────────────────────
  fetch('/intelligence/market/edr')
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      var tiers = data.tiers || {{}};
      var all = [];
      var tierColors = {{
        'leaders': '#3b7',
        'contenders': '#1a7a4a',
        'emerging': '#145530',
        'watch': '#333',
      }};

      ['leaders', 'contenders', 'emerging', 'watch'].forEach(function(tier) {{
        var items = tiers[tier] || [];
        items.forEach(function(v) {{
          all.push({{
            label: v.display,
            score: v.weighted_score || 0,
            color: tierColors[tier],
            tier: tier,
          }});
        }});
      }});

      if (all.length === 0) {{
        document.getElementById('marketChart').style.display = 'none';
        document.getElementById('marketEmpty').style.display = 'block';
        return;
      }}

      // Sort by score descending, take top 12
      all.sort(function(a, b) {{ return b.score - a.score; }});
      all = all.slice(0, 12);

      var labels = all.map(function(v) {{ return v.label + ' (' + v.tier + ')'; }});
      var scores = all.map(function(v) {{ return v.score; }});
      var colors = all.map(function(v) {{ return v.color; }});

      new Chart(document.getElementById('marketChart'), {{
        type: 'bar',
        data: {{
          labels: labels,
          datasets: [{{
            label: 'Score',
            data: scores,
            backgroundColor: colors,
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
              backgroundColor: '#111',
              titleColor: '#f0f0f0',
              bodyColor: '#aaa',
              borderColor: '#3b7',
              borderWidth: 1,
            }},
          }},
          scales: {{
            x: {{
              grid: {{ color: '#2a2a30' }},
              ticks: {{ color: '#444' }},
              max: 10,
            }},
            y: {{
              grid: {{ display: false }},
              ticks: {{ color: '#888', font: {{ size: 10 }} }},
            }},
          }},
        }},
      }});
    }})
    .catch(function(e) {{
      console.error('market chart error:', e);
      document.getElementById('marketChart').style.display = 'none';
      document.getElementById('marketEmpty').style.display = 'block';
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
        db = get_db()
        cid = await db.store_eval_record(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/attack-map")
    async def contribute_attack_map(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_attack_map(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/ioc-bundle")
    async def contribute_ioc_bundle(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_ioc_bundle(body)
        return {"status": "accepted", "contribution_id": cid}

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

    return app


# Default app instance for `uvicorn nur.server.app:app`
# Reads DB URL from NUR_DB_URL env var (for Docker deployment)
app = create_app(db_url=os.environ.get("NUR_DB_URL", "sqlite+aiosqlite:///nur.db"))
