#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  nur — one-command deploy to any Linux server
#
#  Usage:
#    # On your server (Ubuntu/Debian):
#    curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/deploy.sh | bash
#
#    # Or clone and run:
#    git clone https://github.com/manizzle/nur.git
#    cd nur
#    ./deploy.sh
#
#  What it does:
#    1. Installs Docker if not present
#    2. Clones nur (if not already in repo)
#    3. Creates .env from template
#    4. Starts PostgreSQL + nur + Caddy (HTTPS)
#    5. Seeds with 37 live threat feeds
#    6. Prints the URL
# ═══════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ┌─────────────────────────────────────┐"
echo "  │  nur — deploying                    │"
echo "  └─────────────────────────────────────┘"
echo -e "${NC}"

# ── 1. Install Docker if needed ────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo "  Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "  Docker installed. You may need to log out and back in."
fi

if ! command -v docker compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "  ERROR: docker compose not found. Install Docker Desktop or docker-compose-plugin."
    exit 1
fi

# ── 2. Clone if not in repo ────────────────────────────────────
if [ ! -f "pyproject.toml" ]; then
    echo "  Cloning nur..."
    git clone https://github.com/manizzle/nur.git
    cd nur
fi

# ── 3. Create .env ─────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env

    # Generate a random API key
    API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)
    PG_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || openssl rand -base64 16)

    sed -i "s/^NUR_API_KEY=.*/NUR_API_KEY=${API_KEY}/" .env 2>/dev/null || true
    sed -i "s/^# POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${PG_PASS}/" .env 2>/dev/null || true

    echo -e "  ${GREEN}Generated .env with:${NC}"
    echo "    API Key:  ${API_KEY}"
    echo "    PG Pass:  ${PG_PASS}"
    echo ""
    echo "  Edit .env to add your domain and API keys for premium feeds."
fi

# ── 4. Ask for domain ──────────────────────────────────────────
if [ -z "$NUR_DOMAIN" ]; then
    echo ""
    read -p "  Domain name (or press Enter for localhost): " NUR_DOMAIN
    NUR_DOMAIN=${NUR_DOMAIN:-localhost}
fi

export NUR_DOMAIN

# ── 5. Start services ─────────────────────────────────────────
echo ""
echo "  Starting nur..."

if [ "$NUR_DOMAIN" = "localhost" ]; then
    # Dev mode — no Caddy, just postgres + nur
    docker compose --profile production up -d
    URL="http://localhost:8000"
else
    # Production — postgres + nur + Caddy (auto-HTTPS)
    docker compose --profile production --profile web up -d
    URL="https://${NUR_DOMAIN}"
fi

# ── 6. Wait for health ────────────────────────────────────────
echo "  Waiting for server..."
for i in $(seq 1 30); do
    if curl -sf "${URL}/health" > /dev/null 2>&1 || curl -sf "http://localhost:8000/health" > /dev/null 2>&1; then
        break
    fi
    sleep 2
done

# ── 7. Seed with demo data ────────────────────────────────────
echo "  Seeding with demo data..."
docker compose exec -T nur-prod python -c "
import json, urllib.request, os, glob

api_url = 'http://127.0.0.1:8000'

# Upload pre-scraped feed data
for f in glob.glob('data/feeds/*.json'):
    try:
        data = json.load(open(f))
        if isinstance(data, list) and data:
            # IOC list — wrap in bundle
            bundle = {'iocs': data[:50], 'source': 'threat-feed', 'tools_in_scope': []}
            payload = json.dumps(bundle).encode()
            req = urllib.request.Request(f'{api_url}/contribute/ioc-bundle', data=payload)
            req.add_header('Content-Type', 'application/json')
            api_key = os.environ.get('NUR_API_KEY', '')
            if api_key:
                req.add_header('X-API-Key', api_key)
            urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

# Upload demo contribution files
for f in glob.glob('demo/eval_*.json') + glob.glob('demo/attack_map_*.json') + glob.glob('demo/ioc_bundle_*.json'):
    try:
        data = json.load(open(f))
        if 'iocs' in data:
            route = '/contribute/ioc-bundle'
        elif 'techniques' in data:
            route = '/contribute/attack-map'
        else:
            route = '/contribute/submit'
        payload = json.dumps(data).encode()
        req = urllib.request.Request(f'{api_url}{route}', data=payload)
        req.add_header('Content-Type', 'application/json')
        api_key = os.environ.get('NUR_API_KEY', '')
        if api_key:
            req.add_header('X-API-Key', api_key)
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

print('  Seeded.')
" 2>/dev/null || echo "  (seeding will happen on first scrape)"

# ── Done ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  nur is running!${NC}"
echo ""
echo "  URL:     ${URL}"
echo "  API docs: ${URL}/docs"
echo "  Health:  ${URL}/health"
echo ""
echo "  API Key: $(grep NUR_API_KEY .env | cut -d= -f2)"
echo ""
echo "  Your users:"
echo "    pip install nur"
echo "    nur init    # enter: ${URL}"
echo "    nur report incident.json"
echo ""
echo -e "${GREEN}  ══════════════════════════════════════════════${NC}"
