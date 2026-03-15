#!/usr/bin/env bash
# Scrape real intel, start server, seed it, ready for vigil report
set -e
cd "$(dirname "$0")/.."

echo "  Scraping real threat intelligence..."
python demo/scrape_real_intel.py demo/seed/

echo "  Starting vigil server..."
rm -f demo_seeded.db
vigil serve --port 8000 --db sqlite+aiosqlite:///demo_seeded.db > /dev/null 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/vigil_server.pid
sleep 2

echo "  Uploading all seed data..."
count=0
for f in demo/seed/ioc_bundle_*.json demo/seed/attack_map_*.json; do
    vigil upload "$f" --api-url http://localhost:8000 --yes > /dev/null 2>&1
    count=$((count + 1))
done

# Also upload the original demo data for more coverage
for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json demo/eval_wiz.json demo/eval_palo_alto_prisma_cloud.json demo/ioc_bundle_1.json demo/ioc_bundle_2.json demo/attack_map_apt28.json demo/attack_map_lockbit.json; do
    if [ -f "$f" ]; then
        vigil upload "$f" --api-url http://localhost:8000 --yes > /dev/null 2>&1
        count=$((count + 1))
    fi
done

echo ""
echo "  ══════════════════════════════════════════════════"
echo "  Server ready with $count contributions from real feeds"
echo "  ══════════════════════════════════════════════════"
echo ""
echo "  Try:"
echo "    vigil report demo/ioc_bundle_2.json --api-url http://localhost:8000"
echo "    vigil report demo/attack_map_lockbit.json --api-url http://localhost:8000"
echo "    vigil report demo/eval_crowdstrike.json --api-url http://localhost:8000"
echo ""
echo "  Stop server: kill \$(cat /tmp/vigil_server.pid)"
