# Strategy Visualization

Visual maps of nur's business strategy — stakeholders, data flows, revenue, GTM channels.

## Toolchain

| Tool | Purpose | When |
|------|---------|------|
| Excalidraw | Rough sketching | First-pass thinking |
| Kumu | Interactive relationship map | Real exploration |
| Mermaid | Repo-embedded diagrams | Final stable form |

## Kumu Import

1. Go to [kumu.io](https://kumu.io) and create a new project
2. Import `kumu-nodes.csv` as elements
3. Import `kumu-edges.csv` as connections
4. Set element type colors: party=blue, data_source=green, product_surface=orange, revenue_stream=red
5. Set connection type colors: contributes=green, receives=blue, pays=red, distributes=purple, trusts=gold, recruits=cyan
6. Use the "Timing" field to filter by Now/Near/Later
7. Use the "Priority" field to cluster by P0/P1/P2/P3

## Files

- [kumu-nodes.csv](kumu-nodes.csv) — 33 nodes with metadata fields (timing, priority, trust risk, free/paid value)
- [kumu-edges.csv](kumu-edges.csv) — 51 edges across 6 relationship types
- [stakeholder-map.md](stakeholder-map.md) — Who is connected to whom
- [data-flow.md](data-flow.md) — Query inputs through the protocol to response outputs
- [revenue-model.md](revenue-model.md) — Supply side (free) to demand side (pays)
- [gtm-channels.md](gtm-channels.md) — 4 channels: Direct/WWT, ISACs, Vendor Marketplace, Community Flywheel
- [flywheel.md](flywheel.md) — Peacetime evals feed wartime response and back

## Node Types

| Type | Count | Examples |
|------|-------|---------|
| party | 19 | Murtaza, Yusuf, WWT, Practitioners, CISOs, E-ISAC |
| data_source | 6 | Vendor Evaluations, Attack Maps, IOC Bundles, Threat Feeds |
| product_surface | 3 | Community Free, Pro $99/mo, Enterprise $499/mo |
| revenue_stream | 5 | WWT Pilot, Vendor Listings, Tier Revenue |

## Edge Types

| Type | Count | Meaning |
|------|-------|---------|
| contributes | 15 | Feeds data into something |
| receives | 5 | Consumes value from something |
| pays | 9 | Money flows |
| distributes | 16 | Channel/introduction relationships |
| trusts | 3 | Validation/credibility |
| recruits | 1 | Brings new participants |
