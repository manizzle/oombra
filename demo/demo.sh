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

pause() { sleep "${1:-5}"; }

# Display a block of text all at once, then pause for reading
block() {
    echo ""
    while IFS= read -r line; do
        echo "  $line"
    done <<< "$1"
    sleep "${2:-4}"
}

type_cmd() {
    echo ""
    echo -n "  $ "
    echo "$1" | while IFS= read -r -n1 char; do echo -n "$char"; sleep 0.04; done
    echo ""; sleep 0.3; eval "$1" 2>&1 | sed 's/^/  /'; sleep 3
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

block "LockBit ransomware. EHR encrypted. NICU monitors offline.
The IR team has IOCs from the attack — malicious IPs,
command-and-control domains, file hashes." 5

block "But they don't know:
  - Is anyone else seeing this same campaign?
  - Does CrowdStrike catch T1490 (VSS deletion)?
  - What actually worked at other hospitals that got hit?" 5

block "They can't ask. Sharing incident data could trigger
mandatory reporting. Their lawyer won't sign off.

Unless... what they share isn't incident data at all." 5

# ═══════════════════════════════════════════════════════════════════════
#  ACT 2: THE PLATFORM
# ═══════════════════════════════════════════════════════════════════════

scene "Starting nur"

nur serve --port $PORT --db "sqlite+aiosqlite:///$DB_FILE" &>/dev/null &
SERVER_PID=$!
sleep 2

block "Server running. Now let's seed it with data from
multiple hospitals — each contributing anonymously." 3

divider

block "First, hospitals upload their vendor evaluations.
Each one evaluated CrowdStrike, SentinelOne, etc.
nur strips all free text, keeps only scores + categories." 3

for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json; do
    NAME=$(basename "$f" .json | sed 's/eval_//')
    type_cmd "nur upload $f --api-url $API_URL --yes"
done

block "Three evaluations uploaded. Each hospital got a
cryptographic receipt — proof their data was included.
The server committed each value, added it to a Merkle tree,
updated running sums, and DISCARDED the individual values.
It can never recover them." 6

# Upload attack maps too
block "Next, hospitals share attack technique observations." 2
type_cmd "nur upload demo/attack_map_lockbit.json --api-url $API_URL --yes"
type_cmd "nur upload demo/attack_map_apt28.json --api-url $API_URL --yes"

block "And their IOC bundles (hashed — the server never sees raw IPs)." 2
type_cmd "nur upload demo/ioc_bundle_1.json --api-url $API_URL --yes"
type_cmd "nur upload demo/ioc_bundle_2.json --api-url $API_URL --yes"

# ═══════════════════════════════════════════════════════════════════════
#  ACT 3: WARTIME — Ohio needs answers NOW
# ═══════════════════════════════════════════════════════════════════════

scene "4:30 AM — Ohio's IR team uses nur"

block "Ohio uploads their IOCs. nur matches them against
the collective — all hashed, all anonymous." 3

type_cmd "nur report demo/ioc_bundle_2.json --api-url $API_URL"

block "32 shared IOCs. Ohio isn't alone.
This is a coordinated campaign hitting multiple hospitals.
The server knows this because the hashes match —
but it has no idea which hospitals are involved." 8

divider

block "Now Ohio checks: does their toolstack catch this attack?" 2

type_cmd "nur report demo/attack_map_lockbit.json --api-url $API_URL"

block "Detection gaps identified. The collective knows which
techniques are most common and which tools catch them.
Ohio now knows exactly where to add detection rules." 6

divider

block "Finally, Ohio benchmarks their CrowdStrike deployment
against everyone else's experience." 2

type_cmd "nur report demo/eval_crowdstrike.json --api-url $API_URL"

block "Ohio's CrowdStrike score vs the collective average.
Real practitioner data — not Gartner, not vendor marketing." 6

# ═══════════════════════════════════════════════════════════════════════
#  ACT 4: PEACETIME — strategic decisions
# ═══════════════════════════════════════════════════════════════════════

scene "The next morning — peacetime intelligence"

block "The attack is contained. Now the CISO needs to make
strategic decisions: keep CrowdStrike? Add SentinelOne?
Where are the real gaps in their stack?" 3

type_cmd "nur market edr --api-url $API_URL"

block "Vendor rankings from real practitioners across the
collective. Not pay-to-play analyst reports —
anonymous, aggregated, cryptographically proven." 6

divider

block "Side-by-side comparison for the board presentation:" 2

type_cmd "nur search compare crowdstrike sentinelone --api-url $API_URL"
pause 5

# ═══════════════════════════════════════════════════════════════════════
#  ACT 5: THE PROOF — trustless verification
# ═══════════════════════════════════════════════════════════════════════

scene "The proof: anyone can verify"

narrate "The CISO's board asks: 'How do we know these numbers"
block "are real? How do we know you didn't make them up?'

Answer: cryptographic proof." 3

type_cmd "curl -s $API_URL/proof/stats | python3 -m json.tool"

block "Every contribution is committed to a Merkle tree.
The Merkle root is a fingerprint of ALL contributions.
Change one value and the root changes — tamper-evident." 5

divider

block "Verify the CrowdStrike aggregate is real:" 2

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

block "Three checks, all PASS. The aggregate is mathematically
proven to be computed from real committed contributions.
The server can't inflate the count, alter scores, or
exclude contributions. Math, not promises." 8

# ═══════════════════════════════════════════════════════════════════════
#  ACT 6: BLIND CATEGORY DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

scene "Plot twist: a new threat actor emerges"

block "Three hospitals independently encounter a new ransomware
group called 'DarkAngel' — but it's not in any public
database yet. How do they surface it collectively
without any of them revealing they were attacked?

Blind category discovery." 5

HASH=$(python3 -c "from nur.server.blind_categories import hash_category; print(hash_category('DarkAngel', 'shared-salt'))")

block "Each hospital hashes the name locally:
  H = SHA-256(\"DarkAngel\":salt) = ${HASH:0:32}...
  The server will see this hash. Never the name." 4

echo ""
for ORG in hospital-a hospital-b hospital-c; do
    echo "  $ curl -X POST $API_URL/category/propose ... ($ORG)"
    RESULT=$(curl -s -X POST "$API_URL/category/propose" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"category_type\": \"threat_actor\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} ({d.get(\"supporter_count\")}/{d.get(\"threshold\")})')"
    sleep 1
done

block "Three hospitals submitted the same hash independently.
Threshold met. Now they vote to reveal the name:" 4

echo ""
for ORG in hospital-a hospital-b; do
    RESULT=$(curl -s -X POST "$API_URL/category/reveal" \
        -H 'Content-Type: application/json' \
        -d "{\"category_hash\": \"$HASH\", \"plaintext\": \"DarkAngel\", \"salt\": \"shared-salt\", \"submitter_id\": \"$ORG\"}")
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  {\"$ORG\"}: {d.get(\"status\")} {d.get(\"revealed_name\", \"\")}')"
    sleep 1
done

block "'DarkAngel' is now a public category. The collective
can aggregate data about it. The server learned the name
only because 3 hospitals independently confirmed it —
and 2 voted to make it public." 8

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

block "Without nur: each hospital fights alone, misses the
campaign connection, buys tools based on vendor marketing.

With nur: collaborative defense with mathematical
privacy guarantees. 595 tests. Zero individual values." 6

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
