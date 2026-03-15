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

    # ── API key auth middleware ──────────────────────────────────────────
    api_key = os.environ.get("NUR_API_KEY")

    @app.middleware("http")
    async def api_key_auth(request: Request, call_next):
        if api_key and (request.url.path.startswith("/contribute/") or request.url.path == "/analyze") and request.method == "POST":
            provided = request.headers.get("X-API-Key")
            if provided != api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )
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
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0a0a0a;
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
    color: #444;
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
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.15em;
  }}
  .divider {{
    border: none;
    border-top: 1px solid #1a1a1a;
    margin: 40px 0;
  }}
  .install {{
    background: #111;
    border: 1px solid #222;
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
    color: #444;
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
    color: #333;
    font-size: 0.75em;
    margin-top: 48px;
    line-height: 1.8;
  }}
  .footer a {{
    color: #444;
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
      <span class="stat-num">{vendors}</span>
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

  <div class="links">
    <a href="/register">get your API key</a>
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
            s.add(PendingVerification(email=email, org_name=org or None, token=token))

        # Build the magic link
        host = os.environ.get("NUR_DOMAIN", "nur.saramena.us")
        scheme = "https" if host != "localhost" else "http"
        verify_url = f"{scheme}://{host}/verify/{token}"

        return {
            "status": "pending",
            "verify_url": verify_url,
            "message": f"Verification link generated. In production, this would be emailed to {email}. For now, visit the link directly.",
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
                return """<!DOCTYPE html><html><body style="background:#0a0a0a;color:#d55;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><h1>invalid or expired link</h1><p><a href="/register" style="color:#888">try again</a></p></div></body></html>"""

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
                ))

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>nur — verified</title>
<style>
  body {{ background:#0a0a0a; color:#c0c0c0; font-family:'Courier New',monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
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

    @app.get("/register", response_class=HTMLResponse)
    async def register_page():
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — get your API key</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0a; color: #c0c0c0; font-family: 'Courier New', monospace; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { max-width: 480px; padding: 40px 24px; text-align: center; }
  h1 { font-size: 2em; color: #f0f0f0; margin-bottom: 8px; }
  .sub { color: #666; margin-bottom: 32px; font-size: 0.9em; }
  form { text-align: left; }
  label { display: block; color: #666; font-size: 0.8em; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.1em; }
  input { width: 100%; padding: 10px; background: #111; border: 1px solid #333; border-radius: 4px; color: #e0e0e0; font-family: 'Courier New', monospace; font-size: 0.9em; margin-bottom: 16px; }
  input:focus { outline: none; border-color: #555; }
  button { width: 100%; padding: 12px; background: #1a1a1a; border: 1px solid #444; border-radius: 4px; color: #e0e0e0; font-family: 'Courier New', monospace; font-size: 1em; cursor: pointer; }
  button:hover { background: #222; border-color: #666; }
  .result { margin-top: 24px; padding: 16px; background: #111; border: 1px solid #2a5; border-radius: 4px; display: none; }
  .result code { color: #2a5; word-break: break-all; }
  .tiers { margin-top: 32px; text-align: left; font-size: 0.8em; color: #555; line-height: 1.8; }
  .tiers strong { color: #888; }
  a { color: #666; }
</style>
</head>
<body>
<div class="container">
  <h1>get your API key</h1>
  <div class="sub">free. work email required. takes 5 seconds.</div>

  <form id="reg" onsubmit="return doRegister(event)">
    <label>work email (no gmail/yahoo)</label>
    <input type="email" id="email" placeholder="you@yourhospital.org" required>
    <label>organization (optional)</label>
    <input type="text" id="org" placeholder="Acme Health System">
    <button type="submit">get key</button>
  </form>

  <div id="error" style="display:none; margin-top:16px; padding:12px; background:#1a0a0a; border:1px solid #a33; border-radius:4px; color:#d55; font-size:0.9em;"></div>
  <div class="result" id="result">
    <div>your API key:</div>
    <code id="key"></code>
    <br><br>
    <div style="color:#666;font-size:0.85em">
      run: <code style="color:#aaa">nur init</code> and paste this key.<br>
      then: <code style="color:#aaa">nur report incident.json</code>
    </div>
  </div>

  <div class="tiers">
    <strong>community tier</strong> (free, forever):<br>
    &bull; contribute data, get intelligence reports<br>
    &bull; aggregate data delayed 90 days<br>
    &bull; 37 threat feed sources<br><br>
    <strong>enterprise tier</strong> (coming soon):<br>
    &bull; real-time aggregate data (no 90-day delay)<br>
    &bull; custom vertical configuration<br>
    &bull; SLA + priority support<br>
    &bull; SIEM/SOAR integrations<br><br>
    <a href="/">← back to nur</a>
  </div>
</div>
<script>
async function doRegister(e) {
  e.preventDefault();
  const res = await fetch('/register', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: document.getElementById('email').value, org: document.getElementById('org').value})
  });
  const data = await res.json();
  if (res.ok) {
    if (data.api_key) {
      document.getElementById('key').textContent = data.api_key;
      document.getElementById('result').style.display = 'block';
    } else if (data.verify_url) {
      document.getElementById('result').innerHTML = '<div style="color:#888">Check your email for a verification link.</div><br><div style="color:#555;font-size:0.85em">Or click directly: <a href="' + data.verify_url + '" style="color:#2a5">' + data.verify_url + '</a></div>';
      document.getElementById('result').style.display = 'block';
    }
    document.getElementById('result').style.borderColor = '#2a5';
    document.getElementById('error').style.display = 'none';
  } else {
    document.getElementById('error').textContent = data.detail || 'Registration failed';
    document.getElementById('error').style.display = 'block';
    document.getElementById('result').style.display = 'none';
  }
}
</script>
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
