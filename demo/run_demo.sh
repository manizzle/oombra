#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  oombra Real-World Demo: Healthcare Sector Incident Response
# ═══════════════════════════════════════════════════════════════════════
#
#  SCENARIO: Three hospitals are being targeted by the same ransomware
#  campaign (LockBit 3.0). None of them know the others are affected.
#  They want to:
#    1. Share what they found WITHOUT revealing patient data or network details
#    2. Compare IOCs to discover they're hit by the SAME campaign
#    3. See which tools caught what (anonymized benchmarking)
#    4. Get cryptographic proof that privacy was preserved
#
#  This demo shows exactly how oombra makes that possible.
# ═══════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

step() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  STEP $1: $2${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

pause() {
    echo ""
    echo -e "${YELLOW}  Press Enter to continue...${NC}"
    read -r
}

# ── Setup ─────────────────────────────────────────────────────────────
echo -e "${RED}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║         oombra — Real-World Healthcare Demo              ║"
echo "  ║                                                           ║"
echo "  ║  Three hospitals. Same ransomware. No one knows.         ║"
echo "  ║  oombra lets them figure it out — privately.             ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

pause

# ── Step 1: What the raw data looks like ──────────────────────────────

step 1 "Hospital A discovers suspicious activity"

echo -e "  Hospital A's IR team found IOCs during incident response."
echo -e "  Their raw data contains ${RED}sensitive info${NC} — internal IPs, hostnames, analyst names."
echo ""
echo -e "  Raw IOC bundle (demo/ioc_bundle_2.json):"
echo -e "  ${RED}─────────────────────────────────────────${NC}"
python3 -c "
import json
data = json.load(open('demo/ioc_bundle_2.json'))
print(json.dumps(data, indent=2)[:600])
print('  ...')
"
echo -e "  ${RED}─────────────────────────────────────────${NC}"
echo ""
echo -e "  ${RED}Problem:${NC} They can't share this raw — it reveals their network."

pause

# ── Step 2: oombra anonymizes locally ─────────────────────────────────

step 2 "oombra anonymizes LOCALLY — nothing leaves the machine"

echo -e "  ${GREEN}Running: oombra preview demo/ioc_bundle_2.json${NC}"
echo ""
oombra preview demo/ioc_bundle_2.json
echo ""
echo -e "  ${GREEN}✓ Raw IOC values → HMAC-SHA256 hashed with org-local secret${NC}"
echo -e "  ${GREEN}✓ Only hash fingerprints would be sent, never raw values${NC}"
echo -e "  ${GREEN}✓ Different hospitals hash the same IOC differently (rainbow-table resistant)${NC}"

pause

# ── Step 3: Attack map shows technique coverage ───────────────────────

step 3 "Hospital B shares their attack map (which tools caught what)"

echo -e "  Hospital B ran a LockBit simulation. Here's what they saw:"
echo ""
echo -e "  ${GREEN}Running: oombra preview demo/attack_map_lockbit.json${NC}"
echo ""
oombra preview demo/attack_map_lockbit.json
echo ""
echo -e "  ${GREEN}✓ MITRE ATT&CK techniques with detection/miss attribution${NC}"
echo -e "  ${GREEN}✓ No org name, no analyst names, no internal details${NC}"

pause

# ── Step 4: Tool evaluation with DP noise ─────────────────────────────

step 4 "Hospital C shares their CrowdStrike evaluation (with DP noise)"

echo -e "  Hospital C wants to share their EDR evaluation but is extra cautious."
echo -e "  They add differential privacy noise (epsilon=5.0):"
echo ""
echo -e "  ${YELLOW}WITHOUT noise:${NC}"
oombra preview demo/eval_crowdstrike.json
echo ""
echo -e "  ${YELLOW}WITH noise (epsilon=5.0):${NC}"
oombra preview demo/eval_crowdstrike.json --epsilon 5.0
echo ""
echo -e "  ${GREEN}✓ Scores have calibrated Laplace noise — can't pinpoint exact values${NC}"
echo -e "  ${GREEN}✓ But aggregate across many contributors → noise cancels out${NC}"

pause

# ── Step 5: Cryptographic attestation ─────────────────────────────────

step 5 "Generate attestation chain (ADTC) — cryptographic proof of privacy"

echo -e "  The receiving platform needs PROOF that data was properly anonymized."
echo -e "  oombra's Attested Data Transformation Chain provides this:"
echo ""
echo -e "  ${GREEN}Running: oombra attest demo/eval_crowdstrike.json --epsilon 5.0${NC}"
echo ""
oombra attest demo/eval_crowdstrike.json --epsilon 5.0
echo ""
echo -e "  ${GREEN}✓ Each CDI is HMAC-linked to the previous — break any step, chain fails${NC}"
echo -e "  ${GREEN}✓ VAP (Verifiable Absence Proof) confirms ZERO PII patterns in output${NC}"
echo -e "  ${GREEN}✓ Both sender and receiver independently verify — bilateral trust${NC}"

pause

# ── Step 6: Server receives and aggregates ────────────────────────────

step 6 "Start oombra server and upload anonymized contributions"

echo -e "  Starting server in background..."
oombra serve --port 8765 --db sqlite+aiosqlite:///demo_oombra.db &
SERVER_PID=$!
sleep 2
echo -e "  ${GREEN}✓ Server running on http://localhost:8765${NC}"
echo ""

echo -e "  Uploading all contributions (auto-approved)..."
echo ""

for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json demo/eval_wiz.json demo/eval_palo_alto_prisma_cloud.json; do
    NAME=$(basename "$f" .json | sed 's/eval_//')
    oombra upload "$f" --api-url http://localhost:8765 --yes 2>/dev/null
    echo -e "  ${GREEN}✓ Uploaded${NC} $NAME"
done

oombra upload demo/attack_map_apt28.json --api-url http://localhost:8765 --yes 2>/dev/null
echo -e "  ${GREEN}✓ Uploaded${NC} APT28 attack map"

oombra upload demo/attack_map_lockbit.json --api-url http://localhost:8765 --yes 2>/dev/null
echo -e "  ${GREEN}✓ Uploaded${NC} LockBit attack map"

oombra upload demo/ioc_bundle_1.json --api-url http://localhost:8765 --yes 2>/dev/null
echo -e "  ${GREEN}✓ Uploaded${NC} IOC bundle (APT28)"

oombra upload demo/ioc_bundle_2.json --api-url http://localhost:8765 --yes 2>/dev/null
echo -e "  ${GREEN}✓ Uploaded${NC} IOC bundle (LockBit)"

pause

# ── Step 7: Query aggregated intelligence ─────────────────────────────

step 7 "Query the aggregated intelligence (only aggregates returned)"

echo -e "  ${BOLD}Platform stats:${NC}"
curl -s http://localhost:8765/stats | python3 -m json.tool
echo ""

echo -e "  ${BOLD}EDR category comparison:${NC}"
curl -s http://localhost:8765/query/category/edr | python3 -m json.tool
echo ""

echo -e "  ${BOLD}Top MITRE techniques seen across all contributors:${NC}"
curl -s http://localhost:8765/query/techniques | python3 -m json.tool
echo ""

echo -e "  ${BOLD}IOC type distribution:${NC}"
curl -s http://localhost:8765/query/ioc-stats | python3 -m json.tool
echo ""

echo -e "  ${GREEN}✓ Only aggregates are returned — no individual contribution is ever exposed${NC}"
echo -e "  ${GREEN}✓ Hospital A can see they're being targeted by the same campaign as others${NC}"
echo -e "  ${GREEN}✓ All three hospitals now know CrowdStrike detected T1486 but missed T1490${NC}"

pause

# ── Step 8: Graph intelligence ────────────────────────────────────────

step 8 "Build threat graph and find campaign clusters"

echo -e "  ${GREEN}Running: oombra graph build + analyze${NC}"
echo ""
oombra graph build demo/attack_map_apt28.json demo/attack_map_lockbit.json demo/ioc_bundle_1.json demo/ioc_bundle_2.json -o /tmp/threat_graph.json
echo ""
oombra graph analyze demo/attack_map_apt28.json demo/attack_map_lockbit.json demo/ioc_bundle_1.json demo/ioc_bundle_2.json --clusters 2
echo ""
echo -e "  ${GREEN}✓ Graph built from anonymized data — no raw IOCs in the graph${NC}"
echo -e "  ${GREEN}✓ Campaign clusters identified using embedding similarity${NC}"
echo -e "  ${GREEN}✓ Each org keeps their graph local, shares only model parameters${NC}"

pause

# ── Step 9: Audit trail ───────────────────────────────────────────────

step 9 "Verify the audit trail"

echo -e "  Everything that happened is logged locally:"
echo ""
oombra audit --last 5
echo ""
echo -e "  ${GREEN}Receipts:${NC}"
oombra receipts
echo ""
echo -e "  ${GREEN}✓ Compliance can verify exactly what left the machine${NC}"
echo -e "  ${GREEN}✓ Receipts prove you contributed without revealing content${NC}"

# ── Cleanup ───────────────────────────────────────────────────────────
kill $SERVER_PID 2>/dev/null
rm -f demo_oombra.db

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  DEMO COMPLETE${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}What the three hospitals gained:${NC}"
echo ""
echo -e "  1. ${GREEN}Discovery${NC} — All three learned they're targeted by the same campaign"
echo -e "  2. ${GREEN}Detection gaps${NC} — SentinelOne catches T1490 (VSS deletion),"
echo -e "     CrowdStrike misses it — now all three know to add coverage"
echo -e "  3. ${GREEN}Benchmarking${NC} — Anonymous aggregate: CrowdStrike 9.2, SentinelOne 8.8"
echo -e "  4. ${GREEN}Privacy${NC} — Zero patient data, zero network details, zero org names exposed"
echo -e "  5. ${GREEN}Proof${NC} — ADTC attestation chain + VAP = cryptographic guarantee"
echo ""
echo -e "  ${BOLD}Without oombra:${NC} Each hospital fights alone, misses the campaign connection."
echo -e "  ${BOLD}With oombra:${NC} Collaborative defense with mathematical privacy guarantees."
echo ""
