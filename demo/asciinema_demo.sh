#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  vigil — peace mode + war mode, one platform
#
#  Record: asciinema rec demo/vigil-demo.cast -c "./demo/asciinema_demo.sh"
#  Upload: asciinema upload demo/vigil-demo.cast
# ═══════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

type_cmd() {
    echo ""
    echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do
        echo -n "$char"
        sleep 0.03
    done
    echo ""
    sleep 0.3
    eval "$1"
    sleep 1
}

narrate() { echo "  $1"; sleep 0.8; }
bold() { echo ""; echo "  >>> $1"; sleep 1.2; }

divider() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sleep 2
}

clear

echo ""
echo "  ┌───────────────────────────────────────────────────────┐"
echo "  │                                                       │"
echo "  │   vigil — threat intel sharing platform              │"
echo "  │                                                       │"
echo "  │   PEACE MODE: strengthen your defenses                │"
echo "  │   WAR MODE:   you're getting hacked, act now          │"
echo "  │                                                       │"
echo "  │   One platform. One database. Give data, get intel.   │"
echo "  │                                                       │"
echo "  └───────────────────────────────────────────────────────┘"
echo ""
sleep 4

# ── Seed silently ─────────────────────────────────────────────
python demo/scrape_real_intel.py demo/seed/ > /dev/null 2>&1
rm -f demo_asciinema.db
vigil serve --port 8765 --db sqlite+aiosqlite:///demo_asciinema.db > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2
for f in demo/seed/ioc_bundle_*.json demo/seed/attack_map_*.json demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json demo/eval_wiz.json demo/eval_palo_alto_prisma_cloud.json demo/ioc_bundle_1.json demo/ioc_bundle_2.json demo/attack_map_apt28.json demo/attack_map_lockbit.json; do
    [ -f "$f" ] && vigil upload "$f" --api-url http://localhost:8765 --yes > /dev/null 2>&1
done

narrate "Platform loaded: real IOCs from ThreatFox, Feodo, CISA KEV"
narrate "+ contributions from 4 hospitals and practitioner tool evals."
echo ""

type_cmd "curl -s http://localhost:8765/stats | python3 -m json.tool"
sleep 2

# ═══════════════════════════════════════════════════════════════
# PEACE MODE
# ═══════════════════════════════════════════════════════════════

divider "PEACE MODE — Strengthen your defenses"

narrate "No incident. You're planning. Building your stack."
narrate "What tools should I buy? Where are my gaps?"
sleep 1

echo ""
bold "1. Market map — who leads in EDR?"

type_cmd "vigil market edr --api-url http://localhost:8765"

narrate "Leaders, contenders, emerging — based on weighted practitioner scores."
sleep 2

bold "2. Vendor deep dive"

type_cmd "vigil search vendor crowdstrike --api-url http://localhost:8765"

narrate "Real scores from real incidents. Not Gartner. Not vendor marketing."
sleep 2

bold "3. Side-by-side comparison"

type_cmd "vigil search compare crowdstrike sentinelone --api-url http://localhost:8765"

narrate "Objective comparison. Data from the pool."
sleep 2

bold "4. Threat coverage analysis"

type_cmd "vigil threat-map 'ransomware lateral movement' --tools crowdstrike,splunk --api-url http://localhost:8765"

narrate "Before the attack — know your gaps. Close them."
sleep 3

# ═══════════════════════════════════════════════════════════════
# WAR MODE
# ═══════════════════════════════════════════════════════════════

divider "WAR MODE — 2:17 AM, Ohio Children's Hospital, LockBit"

narrate "EHR encrypted. NICU monitors offline. Ransom note on every screen."
narrate "The IR team pulls IOCs. They need answers NOW."
sleep 2

bold "5. Give IOCs → Get campaign match"

type_cmd "vigil report demo/ioc_bundle_2.json --api-url http://localhost:8765"

narrate "Campaign confirmed. 3 other hospitals hit. Actions prioritized."
sleep 3

bold "6. Give attack map → Get detection gaps"

type_cmd "vigil report demo/attack_map_lockbit.json --api-url http://localhost:8765"

narrate "7 gaps found. T1490 is critical. Deploy detection rules NOW."
sleep 3

bold "7. Give tool eval → Get real benchmarks"

type_cmd "vigil report demo/eval_crowdstrike.json --api-url http://localhost:8765"

narrate "CrowdStrike 9.2 — above avg. But 5 known gaps. Supplement, don't switch."
sleep 2

# ── Cleanup ───────────────────────────────────────────────────
kill $SERVER_PID 2>/dev/null
rm -f demo_asciinema.db

# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  PEACE MODE                    WAR MODE"
echo "  vigil market edr             vigil report iocs.json"
echo "  vigil search vendor X        vigil report attack.json"
echo "  vigil search compare X Y     vigil report eval.json"
echo "  vigil threat-map '...'       "
echo ""
echo "  Same database. Same give-to-get."
echo "  Your peacetime eval helps someone in wartime."
echo "  Their wartime IOCs help your peacetime planning."
echo ""
echo "  Deploy for any vertical:"
echo "    vigil up --vertical healthcare"
echo "    vigil up --vertical financial"
echo "    vigil up --vertical energy"
echo ""
echo "  Data: LGPL-3.0 (open data)"
echo "  Code: Apache 2.0"
echo "  Feeds: abuse.ch (CC0), CISA KEV (public domain), MITRE (Apache 2.0)"
echo ""
echo "  pip install vigil"
echo "  github.com/manizzle/oombra"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
