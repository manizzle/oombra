"""CLI: oombra — privacy-preserving threat intelligence tool."""
from __future__ import annotations
import click
from . import pipeline, load_file, anonymize, render
from .models import ContribContext, Industry, OrgSize, Role


@click.group()
def main():
    """oombra — privacy-preserving threat intelligence contribution tool."""
    pass


# ── Upload ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", required=True, envvar="OOMBRA_API_URL", help="Target platform URL")
@click.option("--api-key", default=None, envvar="OOMBRA_API_KEY")
@click.option("--industry", type=click.Choice([i.value for i in Industry]), default=None)
@click.option("--org-size", type=click.Choice([s.value for s in OrgSize]), default=None)
@click.option("--role", type=click.Choice([r.value for r in Role]), default=None)
@click.option("--epsilon", type=float, default=None, help="Differential privacy budget (e.g. 1.0)")
@click.option("--yes", is_flag=True, help="Skip review prompt (non-interactive)")
def upload(file, api_url, api_key, industry, org_size, role, epsilon, yes):
    """Extract, anonymize, review, and submit a contribution file."""
    ctx = ContribContext(
        industry=Industry(industry) if industry else None,
        org_size=OrgSize(org_size) if org_size else None,
        role=Role(role) if role else None,
    )
    results = pipeline(
        file, api_url=api_url, context=ctx, api_key=api_key,
        auto_approve=yes, epsilon=epsilon,
    )
    ok = sum(1 for r in results if r.success)
    click.echo(f"\n  {ok}/{len(results)} contributions submitted.")

    # Show receipts
    for r in results:
        if r.receipt_hash:
            click.echo(f"  Receipt: {r.receipt_hash[:16]}...")

    # Show privacy budget warning if DP was used
    if epsilon is not None:
        from .dp import PrivacyBudget
        budget = PrivacyBudget.load()
        budget.spend(epsilon, f"upload {file}")
        budget.save()
        if budget.warning:
            click.echo(f"  {budget.warning}")


# ── Preview ──────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--epsilon", type=float, default=None, help="Preview with DP noise")
def preview(file, epsilon):
    """Preview what would be sent without submitting anything."""
    contribs = load_file(file)
    for c in contribs:
        click.echo(render(anonymize(c, epsilon=epsilon)))


# ── Audit log ────────────────────────────────────────────────────────────────

@main.command()
@click.option("--last", type=int, default=20, help="Show last N entries")
def audit(last):
    """View the local audit log — what was scrubbed and sent."""
    from .audit import read_log
    entries = read_log(last_n=last)
    if not entries:
        click.echo("  No audit entries yet.")
        return
    for entry in entries:
        ts = entry.get("timestamp", "")[:19]
        event = entry.get("event", "?")
        details = {k: v for k, v in entry.items() if k not in ("timestamp", "event")}
        detail_str = ", ".join(f"{k}={v}" for k, v in details.items())
        click.echo(f"  [{ts}] {event}: {detail_str}")


# ── Receipts ─────────────────────────────────────────────────────────────────

@main.command()
def receipts():
    """List contribution receipts — prove you contributed without revealing content."""
    from .client import list_receipts
    rcpts = list_receipts()
    if not rcpts:
        click.echo("  No receipts yet.")
        return
    for r in rcpts:
        ts = r.get("timestamp", "")[:19]
        h = r.get("receipt_hash", "?")[:16]
        click.echo(f"  [{ts}] {h}...")


# ── Privacy budget ───────────────────────────────────────────────────────────

@main.command()
def budget():
    """Show privacy budget status (epsilon spent across sessions)."""
    from .dp import PrivacyBudget
    b = PrivacyBudget.load()
    click.echo(f"  Total epsilon spent: {b.total_epsilon:.2f} / {b.threshold:.1f}")
    click.echo(f"  Remaining: {b.remaining:.2f}")
    if b.warning:
        click.echo(f"  {b.warning}")
    if b.sessions:
        click.echo(f"\n  Recent sessions:")
        for s in b.sessions[-5:]:
            click.echo(f"    epsilon={s['epsilon']:.2f}  {s.get('description', '')}")


# ── Attestation ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--epsilon", type=float, default=None, help="Apply DP noise")
@click.option("--json-out", is_flag=True, help="Output full attestation as JSON")
@click.option("--verify-only", is_flag=True, help="Verify an existing attestation chain")
def attest(file, epsilon, json_out, verify_only):
    """Generate or verify an ADTC attestation chain for a file."""
    from .attest import attest_pipeline, verify_chain

    if verify_only:
        import json as json_mod
        chain_data = json_mod.loads(open(file).read())
        from .attest.chain import AttestationChain
        chain = AttestationChain.from_dict(chain_data.get("attestation", chain_data))
        payload = chain_data.get("payload")
        result = verify_chain(chain, payload)
        click.echo(f"\n  {result.summary}")
        if result.errors:
            for e in result.errors:
                click.echo(f"    ERROR: {e}")
        if result.stage_results:
            for sr in result.stage_results:
                click.echo(f"    Stage {sr['stage_id']}: {'OK' if sr['valid'] else 'FAIL'}")
        return

    results = attest_pipeline(file, epsilon=epsilon)

    for ac in results:
        if json_out:
            click.echo(ac.to_json())
        else:
            chain = ac.attestation
            click.echo(f"\n  ADTC Attestation Chain")
            click.echo(f"  {'=' * 50}")
            click.echo(f"  Chain ID:  {chain.chain_id[:16]}...")
            click.echo(f"  Org Key:   {chain.org_key_fingerprint[:16]}...")
            click.echo(f"  Root CDI:  {chain.root_cdi[:16]}...")
            click.echo(f"  Stages:    {chain.stage_count}")
            click.echo(f"  Version:   {chain.version}")
            click.echo()
            for stage in chain.stages:
                click.echo(f"  Stage {stage.stage_num}: {stage.stage_id}")
                click.echo(f"    CDI:     {stage.cdi[:16]}...")
                click.echo(f"    Input:   {stage.input_hash[:16]}...")
                click.echo(f"    Output:  {stage.output_hash[:16]}...")
                if stage.stage_id == "anonymize":
                    vap = stage.evidence.get("vap", {})
                    scrubbed = stage.evidence.get("total_items_scrubbed", 0)
                    clean = vap.get("scan_clean", "?")
                    click.echo(f"    VAP:     {'CLEAN' if clean else 'DIRTY'}")
                    click.echo(f"    Scrubbed: {scrubbed} items")
                elif stage.stage_id == "dp":
                    eps = stage.evidence.get("epsilon", "?")
                    fields = stage.evidence.get("field_count", 0)
                    click.echo(f"    Epsilon: {eps}")
                    click.echo(f"    Fields:  {fields} noised")
                elif stage.stage_id == "extract":
                    count = stage.evidence.get("contributions_extracted", 0)
                    click.echo(f"    Extracted: {count} contributions")
            click.echo()

            # Self-verify
            vr = verify_chain(chain, ac.payload)
            status = "VALID" if vr.valid else "INVALID"
            click.echo(f"  Self-verification: {status}")
            if vr.vap_clean:
                click.echo(f"  VAP: No PII patterns detected in output")
            click.echo()


# ── Server ───────────────────────────────────────────────────────────────────

@main.command()
@click.option("--port", type=int, default=8000)
@click.option("--host", default="0.0.0.0")
@click.option("--db", default="sqlite+aiosqlite:///oombra.db", help="Database URL")
def serve(port, host, db):
    """Start the oombra server."""
    try:
        import uvicorn
        from .server.app import create_app
    except ImportError:
        click.echo("Server requires: pip install oombra[server]")
        raise SystemExit(1)
    app = create_app(db_url=db)
    click.echo(f"  oombra server starting on {host}:{port}")
    click.echo(f"  Database: {db}")
    uvicorn.run(app, host=host, port=port)


# ── PSI ──────────────────────────────────────────────────────────────────────

@main.group()
def psi():
    """Private Set Intersection — compare IOCs without revealing them."""
    pass


@psi.command("query")
@click.option("--peer", required=True, help="Peer URL for PSI")
@click.argument("file", type=click.Path(exists=True))
def psi_query(peer, file):
    """Run PSI against a peer to find shared IOCs."""
    from .models import IOCBundle
    contribs = load_file(file)
    ioc_bundles = [c for c in contribs if isinstance(c, IOCBundle)]
    if not ioc_bundles:
        click.echo("  No IOC bundles found in file.")
        return

    all_iocs = []
    for bundle in ioc_bundles:
        for ioc in bundle.iocs:
            if ioc.value_raw:
                all_iocs.append(ioc.value_raw)

    if not all_iocs:
        click.echo("  No raw IOC values found (already hashed?).")
        return

    click.echo(f"  Loaded {len(all_iocs)} IOCs for PSI query.")
    click.echo(f"  Peer: {peer}")

    try:
        import httpx
        # Send PSI init request
        from .psi import PSIClient
        from .protocol import PSIMessage, PSIRound
        import uuid

        client = PSIClient()
        session_id = str(uuid.uuid4())

        # Blind our IOCs
        blinded = client.blind(all_iocs)
        encoded = PSIMessage.encode_points(blinded)

        # Send to peer
        msg = PSIMessage(
            round=PSIRound.BLIND,
            session_id=session_id,
            party_id="initiator",
            points=encoded,
        )
        with httpx.Client(timeout=30) as http:
            resp = http.post(f"{peer.rstrip('/')}/psi/exchange", json=msg.model_dump(mode="json"))
        if resp.status_code == 200:
            result = resp.json()
            cardinality = result.get("cardinality", "unknown")
            click.echo(f"\n  You share {cardinality} IOCs in common with this peer.")
        else:
            click.echo(f"  PSI query failed: {resp.status_code}")
    except ImportError:
        click.echo("  PSI requires: pip install oombra[crypto]")
    except Exception as e:
        click.echo(f"  PSI query error: {e}")


# ── Graph Intelligence ──────────────────────────────────────────────────────

@main.group()
def graph():
    """Threat graph intelligence — build and analyze attack graphs."""
    pass


@graph.command("build")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output graph JSON")
def graph_build(files, output):
    """Build a local threat graph from contribution files."""
    from .graph.local import build_graph

    all_contribs = []
    for f in files:
        contribs = load_file(f)
        all_contribs.extend(contribs)

    if not all_contribs:
        click.echo("  No contributions found in provided files.")
        return

    g = build_graph(all_contribs)
    click.echo(f"  Built graph: {g.node_count()} nodes, {g.edge_count()} edges")

    if output:
        import json
        with open(output, "w") as fp:
            json.dump(g.to_dict(), fp, indent=2)
        click.echo(f"  Saved to {output}")
    else:
        from collections import Counter
        type_counts = Counter(n.node_type.value for n in g.nodes)
        for t, c in sorted(type_counts.items()):
            click.echo(f"    {t}: {c}")


@graph.command("analyze")
@click.argument("graph_file", type=click.Path(exists=True))
@click.option("--clusters", type=int, default=5, help="Number of campaign clusters")
def graph_analyze(graph_file, clusters):
    """Analyze a threat graph — find campaigns and patterns."""
    import json
    from .graph.schema import ThreatGraph
    from .graph.embeddings import Node2VecLite
    from .graph.correlate import cluster_campaigns, campaign_summary

    with open(graph_file) as fp:
        data = json.load(fp)
    g = ThreatGraph.from_dict(data)
    click.echo(f"  Loaded graph: {g.node_count()} nodes, {g.edge_count()} edges")

    if g.node_count() == 0:
        click.echo("  Empty graph, nothing to analyze.")
        return

    n2v = Node2VecLite(dimensions=64, walk_length=10, num_walks=20)
    embeddings = n2v.fit(g, epochs=5, lr=0.025)
    click.echo(f"  Computed {len(embeddings)} node embeddings")

    k = min(clusters, len(embeddings))
    cluster_map = cluster_campaigns(embeddings, n_clusters=k)
    summaries = campaign_summary(g, cluster_map)

    click.echo(f"\n  Found {len(summaries)} campaign clusters:\n")
    for s in summaries:
        click.echo(f"  Cluster {s['cluster_id']} ({s['node_count']} nodes)")
        if s["techniques"]:
            click.echo(f"    Techniques: {', '.join(s['techniques'][:5])}")
        if s["actors"]:
            click.echo(f"    Actors: {', '.join(s['actors'])}")
        if s["tools"]:
            click.echo(f"    Tools: {', '.join(s['tools'][:5])}")
        if s["ioc_types"]:
            click.echo(f"    IOC types: {', '.join(s['ioc_types'])}")
        click.echo()


@graph.command("compare")
@click.argument("our_graph", type=click.Path(exists=True))
@click.argument("their_embeddings_file", type=click.Path(exists=True))
@click.option("--threshold", type=float, default=0.75, help="Similarity threshold")
def graph_compare(our_graph, their_embeddings_file, threshold):
    """Compare graphs via embeddings to find shared campaigns."""
    import json
    import numpy as np
    from .graph.schema import ThreatGraph
    from .graph.embeddings import Node2VecLite
    from .graph.correlate import detect_shared_campaigns

    with open(our_graph) as fp:
        g = ThreatGraph.from_dict(json.load(fp))
    click.echo(f"  Our graph: {g.node_count()} nodes, {g.edge_count()} edges")

    n2v = Node2VecLite(dimensions=64, walk_length=10, num_walks=20)
    our_emb = n2v.fit(g, epochs=5, lr=0.025)

    with open(their_embeddings_file) as fp:
        their_raw = json.load(fp)
    their_emb = {k: np.array(v) for k, v in their_raw.items()}
    click.echo(f"  Their embeddings: {len(their_emb)} nodes")

    campaigns = detect_shared_campaigns(g, our_emb, their_emb, threshold=threshold)

    if not campaigns:
        click.echo("\n  No shared campaigns detected at this threshold.")
    else:
        for c in campaigns:
            click.echo(f"\n  Shared campaign detected:")
            click.echo(f"    Shared techniques: {c['shared_technique_count']}")
            click.echo(f"    Shared IOCs: {c['shared_ioc_count']}")
            click.echo(f"    Confidence: {c['confidence']}")
            click.echo(f"    Total matches: {c['total_matches']}")
            if c.get("techniques"):
                for t in c["techniques"][:5]:
                    click.echo(f"      - {t['technique']} (sim={t['similarity']})")


# ── Secure Aggregation ──────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--session", required=True, help="Aggregation session ID")
@click.option("--coordinator", required=True, help="Coordinator URL")
@click.option("--n-parties", type=int, default=3, help="Number of parties")
def aggregate(file, session, coordinator, n_parties):
    """Submit evaluation data via secure aggregation."""
    contribs = load_file(file)
    from .models import EvalRecord
    evals = [c for c in contribs if isinstance(c, EvalRecord)]
    if not evals:
        click.echo("  No EvalRecords found in file.")
        return

    from .client import Client
    client = Client(api_url=coordinator)
    for ev in evals:
        clean = anonymize(ev)
        result = client.submit_secagg(clean, session, coordinator, n_parties)
        if result.success:
            click.echo(f"  Submitted shares for {clean.vendor} to session {session}")
        else:
            click.echo(f"  Failed: {result.error}")


# ── Federated Learning ────────────────────────────────────────────────────────

@main.group()
def fl():
    """Federated learning — train models collaboratively."""
    pass


@fl.command("create")
@click.option("--model", "model_type", type=click.Choice(["malware", "anomaly", "ioc_scorer"]),
              required=True)
@click.option("--rounds", type=int, default=10)
@click.option("--min-clients", type=int, default=2)
@click.option("--aggregation", type=click.Choice(
    ["fedavg", "trimmed_mean", "krum", "geometric_median"]), default="fedavg")
@click.option("--coordinator", required=True, help="Coordinator URL")
def fl_create(model_type, rounds, min_clients, aggregation, coordinator):
    """Create a new FL training session."""
    try:
        import httpx
    except ImportError:
        click.echo("  FL requires: pip install httpx")
        raise SystemExit(1)

    with httpx.Client(timeout=30) as http:
        resp = http.post(f"{coordinator.rstrip('/')}/fl/create-session", json={
            "model_type": model_type,
            "max_rounds": rounds,
            "min_clients": min_clients,
            "aggregation": aggregation,
        })
    if resp.status_code == 200:
        data = resp.json()
        click.echo(f"  Session created: {data['session_id']}")
        click.echo(f"  Model: {model_type}, Rounds: {rounds}, Aggregation: {aggregation}")
    else:
        click.echo(f"  Failed to create session: {resp.status_code} {resp.text}")


@fl.command("join")
@click.option("--session", required=True)
@click.option("--coordinator", required=True)
@click.argument("data_file", type=click.Path(exists=True))
@click.option("--epsilon", type=float, default=None, help="DP budget for gradient noise")
def fl_join(session, coordinator, data_file, epsilon):
    """Join an FL session and train on local data."""
    import uuid
    try:
        import httpx
        import numpy as np
    except ImportError:
        click.echo("  FL requires: pip install httpx numpy")
        raise SystemExit(1)

    from .fl.models import MalwareClassifier, AnomalyDetector, IOCScorer
    from .fl.client import FLClient
    from .fl.protocol import serialize_params, deserialize_params

    client_id = str(uuid.uuid4())[:8]

    # Load data
    data = np.load(data_file, allow_pickle=True)
    if isinstance(data, np.lib.npyio.NpzFile):
        X = data["X"]
        y = data.get("y", None)
    else:
        X = data
        y = None

    with httpx.Client(timeout=60) as http:
        # Join session
        resp = http.post(f"{coordinator.rstrip('/')}/fl/join", json={
            "session_id": session,
            "client_id": client_id,
        })
        if resp.status_code != 200:
            click.echo(f"  Failed to join: {resp.status_code}")
            return

        join_data = resp.json()
        click.echo(f"  Joined session {session} as {client_id}")
        click.echo(f"  Status: {join_data['status']}, Clients: {join_data['n_clients']}")

        # Get session info for model type
        resp = http.get(f"{coordinator.rstrip('/')}/fl/session/{session}")
        session_info = resp.json()
        model_type = session_info["model_type"]

        # Create model
        model_map = {
            "malware": lambda: MalwareClassifier(input_dim=X.shape[1]),
            "anomaly": lambda: AnomalyDetector(input_dim=X.shape[1]),
            "ioc_scorer": lambda: IOCScorer(input_dim=X.shape[1]),
        }
        model = model_map[model_type]()

        local_data = (X, y) if y is not None else X
        fl_client = FLClient(model, local_data, epsilon=epsilon)

        # Get global params and train
        global_params = deserialize_params(join_data.get("global_params", {}))
        if global_params:
            delta = fl_client.train_round(global_params, epochs=3, lr=0.01)
        else:
            delta = fl_client.train_round(epochs=3, lr=0.01)

        # Submit update
        serialized = serialize_params(delta)
        resp = http.post(f"{coordinator.rstrip('/')}/fl/submit-update", json={
            "session_id": session,
            "client_id": client_id,
            "round_num": session_info["round_num"],
            "params": serialized,
            "metrics": fl_client.evaluate(local_data),
            "n_samples": int(X.shape[0]),
        })
        if resp.status_code == 200:
            result = resp.json()
            click.echo(f"  Update submitted. Status: {result['status']}")
        else:
            click.echo(f"  Failed to submit update: {resp.status_code}")


# ── Graph Intelligence ────────────────────────────────────────────────────────

@main.group()
def graph():
    """Threat graph intelligence — build and analyze attack graphs."""
    pass


@graph.command("build")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output graph JSON")
def graph_build(files, output):
    """Build a local threat graph from contribution files."""
    if not files:
        click.echo("  No files provided.")
        return

    from .graph.local import build_graph
    all_contribs = []
    for f in files:
        all_contribs.extend(load_file(f))

    g = build_graph(all_contribs)
    click.echo(f"  Built graph: {g.node_count()} nodes, {g.edge_count()} edges")

    # Show breakdown
    from collections import Counter
    type_counts = Counter(n.node_type.value for n in g.nodes)
    for t, c in sorted(type_counts.items()):
        click.echo(f"    {t}: {c}")

    if output:
        import json
        with open(output, "w") as fp:
            json.dump(g.to_dict(), fp, indent=2)
        click.echo(f"  Saved to {output}")


@graph.command("analyze")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--clusters", type=int, default=3, help="Number of campaign clusters")
def graph_analyze(files, clusters):
    """Analyze threat data — find campaigns and patterns."""
    if not files:
        click.echo("  No files provided.")
        return

    from .graph.local import build_graph
    from .graph.embeddings import Node2VecLite
    from .graph.correlate import cluster_campaigns, campaign_summary

    all_contribs = []
    for f in files:
        all_contribs.extend(load_file(f))

    g = build_graph(all_contribs)
    click.echo(f"  Graph: {g.node_count()} nodes, {g.edge_count()} edges")

    if g.node_count() < 2:
        click.echo("  Not enough nodes to analyze.")
        return

    # Compute embeddings
    n2v = Node2VecLite(dimensions=32, walk_length=5, num_walks=10)
    embeddings = n2v.fit(g)
    click.echo(f"  Computed {len(embeddings)} node embeddings")

    # Cluster
    k = min(clusters, g.node_count())
    campaign_clusters = cluster_campaigns(embeddings, n_clusters=k)
    summaries = campaign_summary(g, campaign_clusters)

    click.echo(f"\n  Found {len(summaries)} campaign clusters:")
    for s in summaries:
        click.echo(f"\n  Cluster {s['cluster_id']} ({s['node_count']} nodes)")
        if s.get("techniques"):
            click.echo(f"    Techniques: {', '.join(s['techniques'][:5])}")
        if s.get("ioc_types"):
            click.echo(f"    IOC types: {', '.join(f'{v}x {k}' for k, v in s['ioc_types'].items())}")
        if s.get("tools"):
            click.echo(f"    Tools: {', '.join(s['tools'][:5])}")


@graph.command("compare")
@click.argument("our_files", nargs=-1, type=click.Path(exists=True))
@click.option("--their-embeddings", required=True, type=click.Path(exists=True),
              help="Peer embeddings JSON file")
@click.option("--threshold", type=float, default=0.75)
def graph_compare(our_files, their_embeddings, threshold):
    """Compare graphs via embeddings to find shared campaigns."""
    import json
    import numpy as np
    from .graph.local import build_graph
    from .graph.embeddings import Node2VecLite
    from .graph.correlate import find_similar_nodes

    all_contribs = []
    for f in our_files:
        all_contribs.extend(load_file(f))

    g = build_graph(all_contribs)
    n2v = Node2VecLite(dimensions=32, walk_length=5, num_walks=10)
    our_emb = n2v.fit(g)

    with open(their_embeddings) as fp:
        their_data = json.load(fp)
    their_emb = {k: np.array(v) for k, v in their_data.items()}

    similar = find_similar_nodes(our_emb, their_emb, threshold=threshold)
    click.echo(f"  Found {len(similar)} similar node pairs (threshold={threshold})")
    for s in similar[:10]:
        click.echo(f"    {s['our_node'][:16]}... ↔ {s['their_node'][:16]}... "
                    f"(similarity={s['similarity']:.3f})")


# ── Zero-Knowledge Proofs ─────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--verify-only", is_flag=True, help="Verify existing proof bundle")
@click.option("--json-out", is_flag=True, help="Output as JSON")
def prove(file, verify_only, json_out):
    """Generate or verify zero-knowledge proofs for a contribution."""
    import json as json_mod

    if verify_only:
        data = json_mod.loads(open(file).read())
        from .zkp.verify import ZKPVerifier
        from .zkp.contrib_proofs import ContributionProofBundle
        bundle = ContributionProofBundle.from_dict(data)
        verifier = ZKPVerifier()
        result = verifier.verify_contribution(bundle)
        click.echo(f"\n  {result.summary}")
        if not result.valid:
            for f in result.failed_proofs:
                click.echo(f"    FAILED: {f}")
        return

    contribs = load_file(file)
    from .zkp.contrib_proofs import EvalRecordProof, AttackMapProof, IOCBundleProof
    from .models import EvalRecord, AttackMap, IOCBundle

    for c in contribs:
        clean = anonymize(c)
        if isinstance(clean, EvalRecord):
            prover = EvalRecordProof()
        elif isinstance(clean, AttackMap):
            prover = AttackMapProof()
        elif isinstance(clean, IOCBundle):
            prover = IOCBundleProof()
        else:
            click.echo(f"  Unsupported type: {type(clean)}")
            continue

        bundle = prover.prove(clean)
        if json_out:
            click.echo(json_mod.dumps(bundle.to_dict(), indent=2))
        else:
            click.echo(f"\n  ZK Proof Bundle")
            click.echo(f"  {'=' * 40}")
            click.echo(f"  Type:   {bundle.contribution_type}")
            click.echo(f"  Proofs: {len(bundle.proofs)}")
            for p in bundle.proofs:
                click.echo(f"    {p.get('proof_type', '?'):12s} {p.get('field', '')}")

            # Self-verify
            result = prover.verify(bundle)
            click.echo(f"\n  Self-verification: {result.summary}")
