#!/usr/bin/env bash
# Record the nur demo GIF with a real server + real CLI commands.
# Usage: asciinema rec demo/nur-demo.cast -c 'bash demo/record_trustless.sh' --cols 85 --rows 42
set -e
cd "$(dirname "$0")/.."

DB_FILE="/tmp/nur_demo_$$.db"
PORT=8799
API_URL="http://127.0.0.1:$PORT"

type_cmd() {
    echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do echo -n "$char"; sleep 0.025; done
    echo ""; sleep 0.2; eval "$1"; sleep 0.5
}
section() { echo ""; echo "  ── $1 ──"; echo ""; sleep 0.8; }
cleanup() { kill $SERVER_PID 2>/dev/null; rm -f "$DB_FILE"; }
trap cleanup EXIT

# ── Start server ─────────────────────────────────────────────────────
clear
echo ""
echo "  ┌───────────────────────────────────────────────────────────────────────┐"
echo "  │  nur — trustless collective security intelligence                    │"
echo "  │  commit · prove · discard · verify                                   │"
echo "  │  37 feeds · 36 vendors · 575 tests                                  │"
echo "  └───────────────────────────────────────────────────────────────────────┘"
echo ""
sleep 2

section "Starting server"
nur serve --port $PORT --db "sqlite+aiosqlite:///$DB_FILE" &>/dev/null &
SERVER_PID=$!
sleep 2
echo "  Server running on $API_URL"
sleep 1

# ── Seed data ────────────────────────────────────────────────────────
section "1. Seed: upload evaluations from multiple orgs"
for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json; do
    NAME=$(basename "$f" .json | sed 's/eval_//')
    type_cmd "nur upload $f --api-url $API_URL --yes"
    sleep 0.3
done
sleep 1

# ── Wartime: IOC report ──────────────────────────────────────────────
section "2. Wartime: report IOCs — campaign match"
type_cmd "nur report demo/ioc_bundle_2.json --api-url $API_URL"
sleep 1.5

# ── Wartime: Attack map ──────────────────────────────────────────────
section "3. Wartime: attack map — detection gaps"
type_cmd "nur report demo/attack_map_lockbit.json --api-url $API_URL"
sleep 1.5

# ── Peacetime: Eval ──────────────────────────────────────────────────
section "4. Peacetime: tool evaluation — benchmarks"
type_cmd "nur report demo/eval_crowdstrike.json --api-url $API_URL"
sleep 1.5

# ── Peacetime: Market map ────────────────────────────────────────────
section "5. Peacetime: market map — vendor rankings"
type_cmd "nur market edr --api-url $API_URL"
sleep 1.5

# ── Verify proofs ────────────────────────────────────────────────────
section "6. Verify: proof stats"
type_cmd "curl -s $API_URL/proof/stats | python3 -m json.tool"
sleep 1.5

section "7. Verify: CrowdStrike aggregate proof"
echo "$ curl -s $API_URL/verify/aggregate/CrowdStrike"
curl -s "$API_URL/verify/aggregate/CrowdStrike" | python3 -c "
import sys, json
data = json.load(sys.stdin)
proof = data.get('proof', {})
verif = data.get('verification', {})
print(f'  Contributors: {proof.get(\"contributor_count\", \"?\")}')
print(f'  Merkle root:  {str(proof.get(\"merkle_root\", \"?\"))[:40]}...')
print(f'  Valid:         {verif.get(\"valid\", \"?\")}')
for check, passed in verif.get('checks', {}).items():
    print(f'    {check}: {\"PASS\" if passed else \"FAIL\"}')
"
sleep 1.5

# ── Blind category discovery ─────────────────────────────────────────
section "8. Blind category discovery: 3 hospitals find DarkAngel"
HASH=$(python3 -c "from nur.server.blind_categories import hash_category; print(hash_category('DarkAngel', 'shared-salt'))")
echo "  H = SHA-256(\"DarkAngel:shared-salt\")"
echo "  = ${HASH:0:40}..."
echo "  Server sees ONLY the hash, never the name."
echo ""
for ORG in hospital-a hospital-b hospital-c; do
    echo "$ curl -s -X POST $API_URL/category/propose ... ($ORG)"
    RESULT=$(curl -s -X POST "$API_URL/category/propose" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"category_type\": \"threat_actor\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} ({d.get(\"supporter_count\")}/{d.get(\"threshold\")})')"
    sleep 0.5
done
echo ""
echo "  Threshold met! Voting to reveal..."
for ORG in hospital-a hospital-b; do
    RESULT=$(curl -s -X POST "$API_URL/category/reveal" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"plaintext\": \"DarkAngel\", \"salt\": \"shared-salt\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} {d.get(\"revealed_name\", \"\")}')"
    sleep 0.5
done
sleep 1.5

# ── Summary ──────────────────────────────────────────────────────────
section "Trust architecture"
echo "  STORED                          CANNOT SEE"
echo "  ──────                          ──────────"
echo "  Commitment hashes (SHA-256)     Individual scores"
echo "  Running sums per vendor         Per-org attribution"
echo "  Technique frequency counters    Free-text notes"
echo "  Merkle tree                     Sigma rules, action strings"
echo "  Blind category hashes           Raw IOC values"
echo ""
echo "  575 tests. Zero individual values. Math, not promises."
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────"
echo "  nur.saramena.us · github.com/manizzle/nur"
echo "  ─────────────────────────────────────────────────────────────────────────"
sleep 4
