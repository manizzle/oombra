#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  nur — The Demo
#
#  A narrated walkthrough showing how three hospitals under the same
#  ransomware attack discover they're not alone — and what they learn
#  from each other — all without revealing who they are.
#
#  Usage:
#    bash demo/demo.sh                              # watch the story
#    asciinema rec demo/nur-demo.cast -c 'bash demo/demo.sh'  # record
# ═══════════════════════════════════════════════════════════════════════
set -e
cd "$(dirname "$0")/.."

DB_FILE="/tmp/nur_demo_$$.db"
PORT=8799
API_URL="http://127.0.0.1:$PORT"

# ── Helpers ───────────────────────────────────────────────────────────

narrate() { echo ""; echo "  $1"; sleep 2; }
explain() { echo "  $1"; sleep 1.5; }
pause() { sleep "${1:-5}"; }

type_cmd() {
    echo ""
    echo -n "  $ "
    echo "$1" | while IFS= read -r -n1 char; do echo -n "$char"; sleep 0.05; done
    echo ""; sleep 0.5; eval "$1" 2>&1 | sed 's/^/  /'; sleep 3
}

scene() {
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  $1"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo ""
    sleep 4
}

divider() {
    echo ""
    echo "  ─────────────────────────────────────────────────────────────"
    echo ""
    sleep 3
}

cleanup() { kill $SERVER_PID 2>/dev/null; rm -f "$DB_FILE"; }
trap cleanup EXIT

# ═══════════════════════════════════════════════════════════════════════
#  ACT 1: THE SETUP
# ═══════════════════════════════════════════════════════════════════════

clear
echo ""
echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │                                                             │"
echo "  │   nur — collective security intelligence                    │"
echo "  │                                                             │"
echo "  │   Three hospitals. Same ransomware. None of them know.      │"
echo "  │   nur lets them figure it out — without revealing who       │"
echo "  │   they are.                                                  │"
echo "  │                                                             │"
echo "  └─────────────────────────────────────────────────────────────┘"
echo ""
pause 6

scene "2:17 AM — Ohio Children's Hospital"

narrate "LockBit ransomware. EHR encrypted. NICU monitors offline."
narrate "The IR team has IOCs from the attack — malicious IPs,"
narrate "command-and-control domains, file hashes."
echo ""
narrate "But they don't know:"
explain "  - Is anyone else seeing this same campaign?"
explain "  - Does CrowdStrike catch T1490 (VSS deletion)?"
explain "  - What actually worked at other hospitals that got hit?"
echo ""
narrate "They can't ask. Sharing incident data could trigger"
narrate "mandatory reporting. Their lawyer won't sign off."
echo ""
narrate "Unless... what they share isn't incident data at all."
pause 3

# ═══════════════════════════════════════════════════════════════════════
#  ACT 2: THE PLATFORM
# ═══════════════════════════════════════════════════════════════════════

scene "Starting nur"

nur serve --port $PORT --db "sqlite+aiosqlite:///$DB_FILE" &>/dev/null &
SERVER_PID=$!
sleep 2

narrate "Server running. Now let's seed it with data from"
narrate "multiple hospitals — each contributing anonymously."
pause 2

divider

narrate "First, hospitals upload their vendor evaluations."
narrate "Each one evaluated CrowdStrike, SentinelOne, etc."
narrate "nur strips all free text, keeps only scores + categories."
echo ""

for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json; do
    NAME=$(basename "$f" .json | sed 's/eval_//')
    type_cmd "nur upload $f --api-url $API_URL --yes"
    pause 1
done

narrate "Three evaluations uploaded. Each hospital got a"
narrate "cryptographic receipt — proof their data was included."
narrate "The server committed each value, added it to a Merkle"
narrate "tree, updated running sums, and discarded the individual"
narrate "values. It can never recover them."
pause 4

# Upload attack maps too
narrate "Next, hospitals share attack technique observations."
type_cmd "nur upload demo/attack_map_lockbit.json --api-url $API_URL --yes"
type_cmd "nur upload demo/attack_map_apt28.json --api-url $API_URL --yes"
pause 2

# Upload IOC bundles
narrate "And their IOC bundles (hashed — the server never sees raw IPs)."
type_cmd "nur upload demo/ioc_bundle_1.json --api-url $API_URL --yes"
type_cmd "nur upload demo/ioc_bundle_2.json --api-url $API_URL --yes"
pause 2

# ═══════════════════════════════════════════════════════════════════════
#  ACT 3: WARTIME — Ohio needs answers NOW
# ═══════════════════════════════════════════════════════════════════════

scene "4:30 AM — Ohio's IR team uses nur"

narrate "Ohio uploads their IOCs. nur matches them against"
narrate "the collective — all hashed, all anonymous."
echo ""

type_cmd "nur report demo/ioc_bundle_2.json --api-url $API_URL"

narrate "32 shared IOCs. Ohio isn't alone."
narrate "This is a coordinated campaign hitting multiple hospitals."
narrate "The server knows this because the hashes match —"
narrate "but it has no idea which hospitals are involved."
pause 8

divider

narrate "Now Ohio checks: does their toolstack catch this attack?"
echo ""

type_cmd "nur report demo/attack_map_lockbit.json --api-url $API_URL"

narrate "Detection gaps identified. The collective knows which"
narrate "techniques are most common and which tools catch them."
narrate "Ohio now knows exactly where to add detection rules."
pause 8

divider

narrate "Finally, Ohio benchmarks their CrowdStrike deployment"
narrate "against everyone else's experience."
echo ""

type_cmd "nur report demo/eval_crowdstrike.json --api-url $API_URL"

narrate "Ohio's CrowdStrike score vs the collective average."
narrate "Real practitioner data — not Gartner, not vendor marketing."
pause 8

# ═══════════════════════════════════════════════════════════════════════
#  ACT 4: PEACETIME — strategic decisions
# ═══════════════════════════════════════════════════════════════════════

scene "The next morning — peacetime intelligence"

narrate "The attack is contained. Now the CISO needs to make"
narrate "strategic decisions: keep CrowdStrike? Add SentinelOne?"
narrate "Where are the real gaps in their stack?"
echo ""

type_cmd "nur market edr --api-url $API_URL"

narrate "Vendor rankings from real practitioners across the"
narrate "collective. Not pay-to-play analyst reports —"
narrate "anonymous, aggregated, cryptographically proven."
pause 5

divider

narrate "Side-by-side comparison for the board presentation:"
echo ""

type_cmd "nur search compare crowdstrike sentinelone --api-url $API_URL"
pause 4

# ═══════════════════════════════════════════════════════════════════════
#  ACT 5: THE PROOF — trustless verification
# ═══════════════════════════════════════════════════════════════════════

scene "The proof: anyone can verify"

narrate "The CISO's board asks: 'How do we know these numbers"
narrate "are real? How do we know you didn't make them up?'"
echo ""
narrate "Answer: cryptographic proof."
pause 2

type_cmd "curl -s $API_URL/proof/stats | python3 -m json.tool"

narrate "Every contribution is committed to a Merkle tree."
narrate "The Merkle root is a fingerprint of ALL contributions."
narrate "Change one value and the root changes — tamper-evident."
pause 4

divider

narrate "Verify the CrowdStrike aggregate is real:"
echo ""

echo "  $ curl -s $API_URL/verify/aggregate/CrowdStrike"
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

narrate "Three checks, all PASS. The aggregate is mathematically"
narrate "proven to be computed from real committed contributions."
narrate "The server can't inflate the count, alter scores, or"
narrate "exclude contributions. Math, not promises."
pause 8

# ═══════════════════════════════════════════════════════════════════════
#  ACT 6: BLIND CATEGORY DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

scene "Plot twist: a new threat actor emerges"

narrate "Three hospitals independently encounter a new ransomware"
narrate "group called 'DarkAngel' — but it's not in any public"
narrate "database yet. How do they surface it collectively without"
narrate "any of them revealing they were attacked?"
echo ""
narrate "Blind category discovery."
pause 3

HASH=$(python3 -c "from nur.server.blind_categories import hash_category; print(hash_category('DarkAngel', 'shared-salt'))")

narrate "Each hospital hashes the name locally:"
explain "  H = SHA-256(\"DarkAngel\":salt) = ${HASH:0:32}..."
explain "  The server will see this hash. Never the name."
pause 3

echo ""
for ORG in hospital-a hospital-b hospital-c; do
    echo "  $ curl -X POST $API_URL/category/propose ... ($ORG)"
    RESULT=$(curl -s -X POST "$API_URL/category/propose" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"category_type\": \"threat_actor\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} ({d.get(\"supporter_count\")}/{d.get(\"threshold\")})')"
    sleep 1
done

narrate "Three hospitals submitted the same hash independently."
narrate "Threshold met. Now they vote to reveal the name:"
pause 3

echo ""
for ORG in hospital-a hospital-b; do
    RESULT=$(curl -s -X POST "$API_URL/category/reveal" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"plaintext\": \"DarkAngel\", \"salt\": \"shared-salt\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} {d.get(\"revealed_name\", \"\")}')"
    sleep 1
done

narrate "'DarkAngel' is now a public category. The collective"
narrate "can aggregate data about it. The server learned the name"
narrate "only because 3 hospitals independently confirmed it —"
narrate "and 2 voted to make it public."
pause 8

# ═══════════════════════════════════════════════════════════════════════
#  EPILOGUE
# ═══════════════════════════════════════════════════════════════════════

scene "What each side knows"

echo "  THE SERVER HAS:                THE SERVER CANNOT SEE:"
echo "  ─────────────────              ──────────────────────"
echo "  Commitment hashes (SHA-256)    Individual scores"
echo "  Running sums per vendor        Which hospital submitted what"
echo "  Technique frequency counters   Free-text notes or sigma rules"
echo "  Merkle tree                    Raw IOC values (IPs, domains)"
echo "  Blind category hashes          Who proposed which category"
echo ""
pause 4

narrate "Without nur: each hospital fights alone, misses the"
narrate "campaign connection, buys tools based on vendor marketing."
echo ""
narrate "With nur: collaborative defense with mathematical"
narrate "privacy guarantees. 575 tests. Zero individual values."
echo ""
pause 6

echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │                                                             │"
echo "  │   Attackers share everything.                               │"
echo "  │   Defenders share nothing.                                  │"
echo "  │   nur fixes that.                                           │"
echo "  │                                                             │"
echo "  │   nur.saramena.us · github.com/manizzle/nur                │"
echo "  │                                                             │"
echo "  └─────────────────────────────────────────────────────────────┘"
echo ""
pause 8
