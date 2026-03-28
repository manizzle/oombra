"""
Admin dashboard — internal analytics for network effects.
Protected by NUR_API_KEY (master key).
"""
from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(request: Request) -> None:
    master = os.environ.get("NUR_API_KEY")
    provided = (
        request.headers.get("X-API-Key")
        or request.query_params.get("key")
    )
    if not master or not provided or not secrets.compare_digest(provided, master):
        raise HTTPException(status_code=403, detail="Admin access required")


def _get_db():
    from ..app import get_db
    return get_db()


# ── JSON API endpoints ──────────────────────────────────────────────

@router.get("/api/contributions-timeline")
async def contributions_timeline(request: Request, days: int = 90):
    _require_admin(request)
    return await _get_db().get_contributions_over_time(days)


@router.get("/api/contributions-by-type")
async def contributions_by_type(request: Request, days: int = 90):
    _require_admin(request)
    return await _get_db().get_contributions_by_type_over_time(days)


@router.get("/api/distributions/{dimension}")
async def distributions(request: Request, dimension: str):
    _require_admin(request)
    if dimension not in ("industry", "org_size", "role"):
        raise HTTPException(status_code=400, detail="Invalid dimension")
    return await _get_db().get_distribution(dimension)


@router.get("/api/top-vendors")
async def top_vendors(request: Request, limit: int = 20):
    _require_admin(request)
    return await _get_db().get_top_vendors(limit)


@router.get("/api/top-categories")
async def top_categories(request: Request, limit: int = 20):
    _require_admin(request)
    return await _get_db().get_top_categories(limit)


@router.get("/api/users-timeline")
async def users_timeline(request: Request, days: int = 90):
    _require_admin(request)
    return await _get_db().get_users_over_time(days)


@router.get("/api/user-activity")
async def user_activity(request: Request):
    _require_admin(request)
    return await _get_db().get_user_activity_distribution()


@router.get("/api/tiers")
async def tiers(request: Request):
    _require_admin(request)
    return await _get_db().get_tier_distribution()


@router.get("/api/invites")
async def invites(request: Request):
    _require_admin(request)
    return await _get_db().get_invite_metrics()


@router.get("/api/usage-timeline")
async def usage_timeline(request: Request, days: int = 30):
    _require_admin(request)
    return await _get_db().get_api_usage_over_time(days)


@router.get("/api/network-health")
async def network_health(request: Request):
    _require_admin(request)
    return await _get_db().get_network_health()


@router.get("/api/funnel")
async def engagement_funnel(request: Request):
    _require_admin(request)
    return await _get_db().get_engagement_funnel()


@router.get("/api/retention")
async def retention_cohorts(request: Request, weeks: int = 8):
    _require_admin(request)
    return await _get_db().get_retention_cohorts(weeks)


# ── Dashboard HTML ──────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    _require_admin(request)
    key = request.query_params.get("key", "")

    # Pre-fetch stats for server-rendered hero numbers
    db = _get_db()
    health = await db.get_network_health()
    funnel = await db.get_engagement_funnel()
    invite = await db.get_invite_metrics()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur — admin dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: dark; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background:
      radial-gradient(circle at top, rgba(99, 102, 241, 0.12), transparent 28%),
      #0a0a0f;
    color: #e4e4e7;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
    padding: 0;
  }}
  a {{ color: inherit; text-decoration: none; }}

  .header {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 64px 24px 32px;
  }}
  .header h1 {{
    font-size: 1.8rem;
    color: #fafafa;
    letter-spacing: 0.2em;
  }}
  .header h1 span {{ color: #818cf8; }}
  .header-sub {{
    font-size: 0.85rem;
    color: #71717a;
    margin-top: 6px;
    letter-spacing: 0.08em;
  }}

  .grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
    max-width: 1400px;
    margin: 0 auto;
    padding: 0 24px 24px;
  }}
  .card {{
    background: #111118;
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 24px;
    transition: border-color 0.2s;
  }}
  .card:hover {{
    border-color: rgba(129, 140, 248, 0.3);
  }}
  .card.span-2 {{ grid-column: span 2; }}
  .card.span-3 {{ grid-column: span 3; }}
  .card-title {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: #a1a1aa;
    margin-bottom: 16px;
  }}
  .card-title::before {{ content: '/// '; color: #818cf8; }}

  .stat-row {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
  }}
  .stat {{
    flex: 1;
    min-width: 120px;
    background: rgba(255,255,255,0.02);
    border: 1px solid #1e1e2e;
    border-radius: 12px;
    padding: 20px 16px;
    text-align: center;
  }}
  .stat .num {{
    font-size: 2rem;
    font-weight: 800;
    color: #fafafa;
    display: block;
    line-height: 1.1;
  }}
  .stat .num.green {{ color: #22c55e; }}
  .stat .num.indigo {{ color: #818cf8; }}
  .stat .num.amber {{ color: #f59e0b; }}
  .stat .num.red {{ color: #ef4444; }}
  .stat .lbl {{
    font-size: 0.68rem;
    color: #a1a1aa;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-top: 6px;
    display: block;
  }}

  .chart-box {{
    position: relative;
    width: 100%;
    min-height: 280px;
    background: rgba(255,255,255,0.02);
    border: 1px solid #1e1e2e;
    border-radius: 12px;
    padding: 16px;
  }}
  .chart-box canvas {{ width: 100% !important; }}

  .funnel {{
    display: flex;
    align-items: flex-end;
    gap: 8px;
    height: 200px;
    padding: 12px 0;
  }}
  .funnel-bar {{
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    height: 100%;
  }}
  .funnel-bar .bar {{
    width: 100%;
    background: linear-gradient(to top, #818cf8, #6366f1);
    border-radius: 8px 8px 0 0;
    min-height: 4px;
    transition: height 0.6s ease;
  }}
  .funnel-bar .bar-num {{
    font-size: 1.4rem;
    font-weight: 700;
    color: #fafafa;
    margin-bottom: 6px;
  }}
  .funnel-bar .bar-lbl {{
    font-size: 0.65rem;
    color: #a1a1aa;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-top: 8px;
    text-align: center;
  }}

  @media (max-width: 1100px) {{
    .grid {{ grid-template-columns: repeat(2, 1fr); }}
    .card.span-3 {{ grid-column: span 2; }}
  }}
  @media (max-width: 700px) {{
    .grid {{ grid-template-columns: 1fr; }}
    .card.span-2, .card.span-3 {{ grid-column: auto; }}
    .stat-row {{ flex-direction: column; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>nur <span>admin</span></h1>
  <div class="header-sub">network effects dashboard &middot; internal only</div>
</div>

<div class="grid">

  <!-- ── Network Health Stats ─────────────────── -->
  <div class="card span-3">
    <div class="card-title">Network Health</div>
    <div class="stat-row">
      <div class="stat">
        <span class="num">{health['total_contributions']}</span>
        <span class="lbl">contributions</span>
      </div>
      <div class="stat">
        <span class="num indigo">{health['total_users']}</span>
        <span class="lbl">registered users</span>
      </div>
      <div class="stat">
        <span class="num amber">{health['supply_demand_ratio']}</span>
        <span class="lbl">supply / demand</span>
      </div>
      <div class="stat">
        <span class="num {'green' if health['velocity_pct'] >= 0 else 'red'}">{'+'if health['velocity_pct'] >= 0 else ''}{health['velocity_pct']}%</span>
        <span class="lbl">velocity (week / week)</span>
      </div>
      <div class="stat">
        <span class="num">{health['this_week']}</span>
        <span class="lbl">this week</span>
      </div>
      <div class="stat">
        <span class="num">{health['unique_industries']}</span>
        <span class="lbl">industries</span>
      </div>
      <div class="stat">
        <span class="num">{health['unique_categories']}</span>
        <span class="lbl">categories</span>
      </div>
    </div>
  </div>

  <!-- ── Engagement Funnel ────────────────────── -->
  <div class="card span-2">
    <div class="card-title">Engagement Funnel</div>
    <div class="funnel" id="funnel">
      {"".join(f'''
      <div class="funnel-bar">
        <div class="bar-num">{funnel[k]}</div>
        <div class="bar" style="height: {max(4, (funnel[k] / max(funnel['registered'], 1)) * 100)}%"></div>
        <div class="bar-lbl">{k}</div>
      </div>''' for k in ['registered', 'verified', 'contributed', 'queried', 'returned'])}
    </div>
  </div>

  <!-- ── Viral Metrics ────────────────────────── -->
  <div class="card">
    <div class="card-title">Viral Metrics</div>
    <div class="stat-row" style="flex-direction:column; gap:12px;">
      <div class="stat">
        <span class="num indigo">{invite['viral_coefficient']}</span>
        <span class="lbl">k-factor</span>
      </div>
      <div class="stat">
        <span class="num">{invite['inviters']}</span>
        <span class="lbl">users who invited ({invite['inviter_pct']}%)</span>
      </div>
      <div class="stat">
        <span class="num green">{invite['total_invited']}</span>
        <span class="lbl">total invited</span>
      </div>
    </div>
  </div>

  <!-- ── Contributions Over Time ──────────────── -->
  <div class="card span-2">
    <div class="card-title">Contributions Over Time</div>
    <div class="chart-box"><canvas id="contribTimeline" height="260"></canvas></div>
  </div>

  <!-- ── By Type (Stacked) ────────────────────── -->
  <div class="card">
    <div class="card-title">By Type</div>
    <div class="chart-box"><canvas id="contribByType" height="260"></canvas></div>
  </div>

  <!-- ── Industry Distribution ────────────────── -->
  <div class="card">
    <div class="card-title">Industry</div>
    <div class="chart-box"><canvas id="industryChart" height="260"></canvas></div>
  </div>

  <!-- ── Org Size Distribution ────────────────── -->
  <div class="card">
    <div class="card-title">Org Size</div>
    <div class="chart-box"><canvas id="orgSizeChart" height="260"></canvas></div>
  </div>

  <!-- ── Role Distribution ────────────────────── -->
  <div class="card">
    <div class="card-title">Role</div>
    <div class="chart-box"><canvas id="roleChart" height="260"></canvas></div>
  </div>

  <!-- ── Registered Users Over Time ───────────── -->
  <div class="card">
    <div class="card-title">Registrations</div>
    <div class="chart-box"><canvas id="usersTimeline" height="260"></canvas></div>
  </div>

  <!-- ── API Usage Over Time ──────────────────── -->
  <div class="card">
    <div class="card-title">API Requests (30d)</div>
    <div class="chart-box"><canvas id="usageTimeline" height="260"></canvas></div>
  </div>

  <!-- ── Top Vendors ──────────────────────────── -->
  <div class="card">
    <div class="card-title">Top Vendors</div>
    <div class="chart-box"><canvas id="vendorChart" height="260"></canvas></div>
  </div>

  <!-- ── User Activity ────────────────────────── -->
  <div class="card">
    <div class="card-title">User Activity</div>
    <div class="chart-box"><canvas id="activityChart" height="260"></canvas></div>
  </div>

  <!-- ── Tier Distribution ────────────────────── -->
  <div class="card">
    <div class="card-title">Tiers</div>
    <div class="chart-box"><canvas id="tierChart" height="260"></canvas></div>
  </div>

  <!-- ── Retention Cohorts ────────────────────── -->
  <div class="card span-3">
    <div class="card-title">Retention Cohorts</div>
    <div class="chart-box"><canvas id="retentionChart" height="220"></canvas></div>
  </div>

</div>

<script>
const KEY = '{key}';
const BASE = '/admin/api';
const Q = KEY ? '?key=' + KEY : '';

Chart.defaults.color = '#a1a1aa';
Chart.defaults.borderColor = 'rgba(255,255,255,0.04)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

async function api(path) {{
  const sep = path.includes('?') ? '&' : '?';
  const url = BASE + path + (KEY ? sep + 'key=' + KEY : '');
  const r = await fetch(url);
  return r.json();
}}

const INDIGO = '#818cf8';
const GREEN = '#22c55e';
const AMBER = '#f59e0b';
const RED = '#ef4444';
const COLORS = [INDIGO, GREEN, AMBER, '#06b6d4', '#ec4899', '#8b5cf6'];

function lineChart(id, labels, datasets) {{
  new Chart(document.getElementById(id), {{
    type: 'line',
    data: {{ labels, datasets }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{ legend: {{ display: datasets.length > 1 }} }},
      scales: {{
        x: {{ grid: {{ display: false }} }},
        y: {{ beginAtZero: true }}
      }}
    }}
  }});
}}

function barChart(id, labels, data, color) {{
  new Chart(document.getElementById(id), {{
    type: 'bar',
    data: {{
      labels,
      datasets: [{{ data, backgroundColor: color || INDIGO, borderRadius: 6 }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ beginAtZero: true, grid: {{ display: false }} }},
        y: {{ grid: {{ display: false }} }}
      }}
    }}
  }});
}}

function doughnut(id, labels, data, colors) {{
  new Chart(document.getElementById(id), {{
    type: 'doughnut',
    data: {{
      labels,
      datasets: [{{ data, backgroundColor: colors || COLORS, borderWidth: 0 }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      cutout: '65%',
      plugins: {{ legend: {{ position: 'bottom', labels: {{ padding: 12 }} }} }}
    }}
  }});
}}

// Load all charts
(async function() {{
  // Contributions timeline
  const ct = await api('/contributions-timeline');
  if (ct.length) {{
    lineChart('contribTimeline',
      ct.map(d => d.date),
      [{{ label: 'Contributions', data: ct.map(d => d.count), borderColor: INDIGO, backgroundColor: 'rgba(129,140,248,0.1)', fill: true, tension: 0.3 }}]
    );
  }}

  // By type
  const bt = await api('/contributions-by-type');
  if (bt.length) {{
    const types = [...new Set(bt.map(d => d.type))];
    const dates = [...new Set(bt.map(d => d.date))].sort();
    const datasets = types.map((t, i) => ({{
      label: t,
      data: dates.map(d => (bt.find(b => b.date === d && b.type === t) || {{}}).count || 0),
      borderColor: COLORS[i % COLORS.length],
      backgroundColor: COLORS[i % COLORS.length] + '22',
      fill: true, tension: 0.3
    }}));
    lineChart('contribByType', dates, datasets);
  }}

  // Distributions
  for (const [dim, chartId] of [['industry', 'industryChart'], ['org_size', 'orgSizeChart'], ['role', 'roleChart']]) {{
    const d = await api('/distributions/' + dim);
    if (d.length) barChart(chartId, d.map(x => x.value), d.map(x => x.count), INDIGO);
  }}

  // Users timeline
  const ut = await api('/users-timeline');
  if (ut.length) {{
    lineChart('usersTimeline',
      ut.map(d => d.date),
      [{{ label: 'Registrations', data: ut.map(d => d.count), borderColor: GREEN, backgroundColor: 'rgba(34,197,94,0.1)', fill: true, tension: 0.3 }}]
    );
  }}

  // API usage
  const au = await api('/usage-timeline');
  if (au.length) {{
    lineChart('usageTimeline',
      au.map(d => d.date),
      [{{ label: 'Requests', data: au.map(d => d.count), borderColor: AMBER, backgroundColor: 'rgba(245,158,11,0.1)', fill: true, tension: 0.3 }}]
    );
  }}

  // Top vendors
  const tv = await api('/top-vendors');
  if (tv.length) barChart('vendorChart', tv.map(x => x.vendor), tv.map(x => x.count), GREEN);

  // User activity (doughnut)
  const ua = await api('/user-activity');
  if (ua) {{
    doughnut('activityChart',
      ['Active (30d)', 'Inactive'],
      [ua.active_last_30d, ua.inactive],
      [GREEN, '#27272a']
    );
  }}

  // Tiers
  const ti = await api('/tiers');
  if (ti.length) {{
    doughnut('tierChart', ti.map(t => t.tier), ti.map(t => t.count));
  }}

  // Retention cohorts
  const rc = await api('/retention');
  if (rc.length) {{
    const weeks = rc.map(c => c.week);
    lineChart('retentionChart', weeks, [
      {{ label: 'Cohort size', data: rc.map(c => c.size), borderColor: INDIGO, tension: 0.3 }},
      {{ label: 'Week 1', data: rc.map(c => c.retained_1w), borderColor: GREEN, tension: 0.3 }},
      {{ label: 'Week 2', data: rc.map(c => c.retained_2w), borderColor: AMBER, tension: 0.3 }},
      {{ label: 'Week 4', data: rc.map(c => c.retained_4w), borderColor: RED, tension: 0.3 }},
    ]);
  }}
}})();
</script>
</body>
</html>"""
