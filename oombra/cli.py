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
