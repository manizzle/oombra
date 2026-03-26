#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  nur — install and run in 30 seconds
#
#  curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/install.sh | bash
# ═══════════════════════════════════════════════════════════════

set -e

echo ""
echo "  nur — collective security intelligence"
echo "  ══════════════════════════════════════"
echo ""

# ── Create directory ───────────────────────────────────────────
mkdir -p nur && cd nur

# ── Pull files ─────────────────────────────────────────────────
echo "  Pulling config files..."
curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/docker-compose.prod.yml -o docker-compose.yml
curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/Caddyfile -o Caddyfile

# ── Create .env only if it doesn't exist (never overwrite) ────
if [ ! -f ".env" ]; then
    curl -sSL https://raw.githubusercontent.com/manizzle/nur/main/.env.example -o .env

    # ── Generate secrets ───────────────────────────────────────
    API_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
    PG_PASS=$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

    sed -i.bak "s/^NUR_API_KEY=.*/NUR_API_KEY=${API_KEY}/" .env
    sed -i.bak "s/^# POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${PG_PASS}/" .env
    rm -f .env.bak

    # ── Domain ─────────────────────────────────────────────────
    echo ""
    read -p "  Domain (press Enter for localhost): " DOMAIN
    DOMAIN=${DOMAIN:-localhost}

    if [ "$DOMAIN" != "localhost" ]; then
        sed -i.bak "s/^# NUR_DOMAIN=.*/NUR_DOMAIN=${DOMAIN}/" .env
        rm -f .env.bak
    fi
else
    echo "  .env already exists, keeping current config"
    DOMAIN=$(grep '^NUR_DOMAIN=' .env 2>/dev/null | cut -d= -f2 || echo "localhost")
    API_KEY=$(grep '^NUR_API_KEY=' .env 2>/dev/null | cut -d= -f2 || echo "")
fi

# ── Start ──────────────────────────────────────────────────────
echo ""
echo "  Starting nur..."
docker compose up -d

# ── Wait for health ────────────────────────────────────────────
echo "  Waiting for server..."
URL="http://localhost:${NUR_PORT:-8000}"
for i in $(seq 1 30); do
    curl -sf "${URL}/health" > /dev/null 2>&1 && break
    sleep 2
done

# ── Done ───────────────────────────────────────────────────────
echo ""
echo "  ══════════════════════════════════════"
echo "  nur is running!"
echo ""
if [ "$DOMAIN" != "localhost" ]; then
    echo "  URL:      https://${DOMAIN}"
    echo "  API docs: https://${DOMAIN}/docs"
else
    echo "  URL:      ${URL}"
    echo "  API docs: ${URL}/docs"
fi
echo "  API Key:  ${API_KEY}"
echo ""
echo "  Your users:"
echo "    pip install nur"
echo "    nur init"
echo "    nur report incident.json"
echo ""
echo "  ══════════════════════════════════════"
