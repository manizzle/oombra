"""CLI: nur — light on what your industry knows."""
from __future__ import annotations
import json
import os
from pathlib import Path
import click
from . import pipeline, load_file, anonymize, render
from .models import ContribContext, Industry, OrgSize, Role


_CONFIG_PATH = Path.home() / ".nur" / "config.json"


def _load_config() -> dict:
    """Load saved config from ~/.nur/config.json."""
    if _CONFIG_PATH.exists():
        try:
            return json.loads(_CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _get_api_url(explicit: str | None) -> str | None:
    """Resolve API URL: explicit flag > env var > saved config."""
    if explicit:
        return explicit
    env = os.environ.get("NUR_API_URL")
    if env:
        return env
    return _load_config().get("api_url")


def _get_api_key(explicit: str | None) -> str | None:
    """Resolve API key: explicit flag > env var > saved config."""
    if explicit:
        return explicit
    env = os.environ.get("NUR_API_KEY")
    if env:
        return env
    return _load_config().get("api_key")


@click.group()
def main():
    """nur — light on what your industry knows.

    \b
    Full loop:
      nur up                          # start server + scrape live feeds
      nur report incident_iocs.json   # give data, get intelligence
    """
    pass


# ── Init ────────────────────────────────────────────────────────────────────

@main.command()
def init():
    """Set up nur — save your server URL and API key so you never type them again."""
    config = _load_config()

    click.echo("\n  nur setup")
    click.echo("  " + "=" * 40)

    current_url = config.get("api_url", "")
    url = click.prompt(
        "  Server URL",
        default=current_url or "http://localhost:8000",
        show_default=True,
    )
    config["api_url"] = url.rstrip("/")

    current_key = config.get("api_key", "")
    key = click.prompt(
        "  API key (leave blank for none)",
        default=current_key or "",
        show_default=False,
    )
    if key:
        config["api_key"] = key
    elif "api_key" in config:
        del config["api_key"]

    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    # Generate keypair for public-key auth
    from .keystore import get_public_key_hex
    pub_hex = get_public_key_hex()
    config["public_key"] = pub_hex
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    click.echo(f"\n  Saved to {_CONFIG_PATH}")
    click.echo(f"  Server: {config['api_url']}")
    click.echo(f"  API key: {'***' + config['api_key'][-4:] if config.get('api_key') else 'none'}")
    click.echo(f"  Public key: {pub_hex[:16]}...")
    click.echo("\n  You're ready. Try: nur report <file>")
    click.echo()


# ── Register ─────────────────────────────────────────────────────────────────

@main.command()
@click.argument("email")
@click.option("--org", default=None, help="Organization name")
@click.option("--invite", default=None, help="Invite code from an existing user")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
def register(email, org, invite, api_url):
    """Register for an API key with your work email. Generates a keypair and sends a verification link."""
    import httpx
    from .keystore import get_public_key_hex

    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    pub_hex = get_public_key_hex()

    click.echo(f"\n  Registering {email}...")
    click.echo(f"  Public key: {pub_hex[:16]}...")

    with httpx.Client(timeout=30) as http:
        resp = http.post(f"{api_url.rstrip('/')}/register", json={
            "email": email,
            "org": org or "",
            "public_key": pub_hex,
            "invite_code": invite or "",
        })

    if resp.status_code != 200:
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        click.echo(f"  Error: {data.get('detail', resp.text[:200])}")
        return

    data = resp.json()

    if data.get("api_key"):
        # Already registered — got key back immediately
        config = _load_config()
        config["api_key"] = data["api_key"]
        config["public_key"] = pub_hex
        _CONFIG_PATH.write_text(json.dumps(config, indent=2))
        click.echo(f"  API key: {data['api_key']}")
        click.echo(f"  Saved to {_CONFIG_PATH}")
    else:
        click.echo(f"  {data.get('message', 'Check your email for the verification link.')}")
        if data.get("verify_url"):
            click.echo(f"  Verify: {data['verify_url']}")

    click.echo()


# ── Invites ──────────────────────────────────────────────────────────────────

@main.command()
@click.option("--api-url", default=None, help="Server URL")
@click.option("--api-key", default=None, help="API key")
def invites(api_url, api_key):
    """Show your invite codes -- share with peers to grow the community."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url or not api_key:
        click.echo("  Run: nur init")
        return
    import httpx
    with httpx.Client(timeout=10) as http:
        resp = http.get(f"{api_url.rstrip('/')}/invites", headers={"X-API-Key": api_key})
    if resp.status_code != 200:
        click.echo(f"  Error: {resp.text[:200]}")
        return
    data = resp.json()
    click.echo(f"\n  Your invite codes ({data['remaining']} remaining):")
    for code in data.get("invite_codes", []):
        click.echo(f"    {code}")
    click.echo(f"\n  People you've invited: {data['invite_count']}")
    click.echo("  Share a code: nur register --invite <code>")


# ── Upload ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--industry", type=click.Choice([i.value for i in Industry]), default=None)
@click.option("--org-size", type=click.Choice([s.value for s in OrgSize]), default=None)
@click.option("--role", type=click.Choice([r.value for r in Role]), default=None)
@click.option("--epsilon", type=float, default=None, help="Differential privacy budget (e.g. 1.0)")
@click.option("--yes", is_flag=True, help="Skip review prompt (non-interactive)")
@click.option("--json", "json_output", is_flag=True, help="Output result as JSON")
def upload(file, api_url, api_key, industry, org_size, role, epsilon, yes, json_output):
    """Extract, anonymize, review, and submit a contribution file."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
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

    if json_output:
        output = {
            "success": ok == len(results) and ok > 0,
            "count": len(results),
            "submitted": ok,
            "receipts": [r.receipt_hash for r in results if r.receipt_hash],
        }
        click.echo(json.dumps(output, indent=2))
        return

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


# ── Report (actionable intelligence) ─────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def report(file, api_url, api_key, json_output):
    """Give your incident data, get back intelligence. The main command."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    contribs = load_file(file)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    # Sign requests with private key
    try:
        from .keystore import get_or_create_keypair, sign_request
        _, priv_key = get_or_create_keypair()
    except Exception:
        priv_key = None

    for c in contribs:
        clean = anonymize(c)
        from .client import _serialize
        payload = _serialize(clean)

        # Dice chain: compute local hash of what we're about to send
        import hashlib as _hashlib
        import json as _json
        local_hash = _hashlib.sha256(
            _json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()

        if priv_key:
            body_bytes = json.dumps(payload, sort_keys=True).encode()
            headers["X-Signature"] = sign_request(body_bytes, priv_key)

        with httpx.Client(timeout=30) as http:
            resp = http.post(f"{api_url.rstrip('/')}/analyze", json=payload, headers=headers)

        if resp.status_code != 200:
            click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
            continue

        result = resp.json()

        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo("\n  Analysis Report")
            click.echo(f"  {'=' * 50}")
            click.echo(f"  Status: {result.get('status', 'unknown')}")
            cid = result.get("contribution_id", "?")
            click.echo(f"  Contribution ID: {cid[:16]}...")

            # Show receipt if present
            receipt = result.get("receipt")
            if receipt:
                click.echo(f"  Receipt: {receipt.get('commitment_hash', '?')[:32]}...")
                click.echo(f"  Merkle proof: {len(receipt.get('merkle_proof', []))} nodes")
                # Dice chain verification
                server_hash = receipt.get("contribution_hash", "")
                if server_hash and local_hash == server_hash:
                    click.echo("  Dice chain: VERIFIED")
                elif server_hash:
                    click.echo(f"  Dice chain: MISMATCH (local={local_hash[:16]}... server={server_hash[:16]}...)")

            intel = result.get("intelligence", {})

            # IOC bundle specific
            if "campaign_match" in intel:
                click.echo(f"  Campaign Match: {'Yes' if intel['campaign_match'] else 'No'}")
                click.echo(f"  Shared IOCs: {intel.get('shared_ioc_count', 0)}")
                ioc_dist = intel.get("ioc_type_distribution", {})
                if ioc_dist:
                    click.echo(f"  IOC Types: {', '.join(f'{k}={v}' for k, v in ioc_dist.items())}")

            # Attack map specific
            if "coverage_score" in intel:
                score_pct = int(intel["coverage_score"] * 100)
                click.echo(f"  Coverage Score: {score_pct}%")
                gaps = intel.get("detection_gaps", [])
                if gaps:
                    click.echo(f"  Detection Gaps: {len(gaps)}")
                    for g in gaps[:5]:
                        freq = g.get('frequency', '')
                        click.echo(f"    - {g['technique_id']}: {freq}x observed, {g.get('caught_by_count', '?')} tools detect it")
                hints = intel.get("remediation_hints")
                if hints:
                    cats = hints.get("most_effective_categories", [])
                    if cats:
                        best = cats[0]
                        click.echo(f"  Best Remediation: {best['category']} ({int(best['success_rate'] * 100)}% success rate)")

            # Eval record specific
            if "your_vendor" in intel:
                click.echo(f"  Vendor: {intel['your_vendor']}")
                click.echo(f"  Your Score: {intel.get('your_score', '?')}")
                click.echo(f"  Category Avg: {intel.get('category_avg', '?')}")
                click.echo(f"  Percentile: {intel.get('percentile', '?')}th")
                if intel.get("contributor_count"):
                    click.echo(f"  Based On: {intel['contributor_count']} evaluations")
                gaps_count = intel.get("known_gaps_count", 0)
                if gaps_count > 0:
                    click.echo(f"  Detection Gaps: {gaps_count} techniques")

            # Actions (common to all types)
            actions = intel.get("actions", [])
            if actions:
                click.echo(f"\n  Actions ({len(actions)}):")
                for a in actions:
                    priority = a.get("priority", "?").upper()
                    click.echo(f"    [{priority}] {a.get('action', '')}")
                    if a.get("detail"):
                        click.echo(f"           {a['detail']}")
            click.echo()


# ── Preview ──────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--epsilon", type=float, default=None, help="Preview with DP noise")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def preview(file, epsilon, json_output):
    """Preview what would be sent without submitting anything."""
    contribs = load_file(file)
    for c in contribs:
        contrib = anonymize(c, epsilon=epsilon)
        if json_output:
            click.echo(json.dumps(contrib.model_dump(mode="json"), indent=2))
        else:
            click.echo(render(contrib))


# ── Eval (interactive vendor evaluation) ──────────────────────────────────────

@main.command()
@click.option("--vendor", default=None, help="Vendor slug (e.g. crowdstrike)")
@click.option("--file", "eval_file", default=None, type=click.Path(exists=True), help="Load eval from JSON file")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON instead of submitting")
def eval(vendor, eval_file, api_url, api_key, json_output):
    """Submit a tool evaluation. Interactive or from file.

    \b
    Examples:
      nur eval                                # interactive walkthrough
      nur eval --vendor crowdstrike           # skip vendor prompt
      nur eval --file my_eval.json            # load from file
    """
    import httpx

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)

    if eval_file:
        # Load from file
        data = json.loads(open(eval_file).read())
    elif vendor:
        # Semi-interactive with vendor pre-filled
        data = _interactive_eval(vendor)
    else:
        # Fully interactive
        click.echo("\n  Tool Evaluation")
        click.echo("  " + "=" * 40)
        click.echo("  Rate a security tool you've used.\n")

        vendor = click.prompt("  Vendor slug", type=str)
        data = _interactive_eval(vendor)

    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    # Submit directly — eval data is already in the right format
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        from .keystore import get_or_create_keypair, sign_request
        _, priv_key = get_or_create_keypair()
    except Exception:
        priv_key = None

    body = json.dumps(data, sort_keys=True).encode()
    if priv_key:
        headers["X-Signature"] = sign_request(body, priv_key)

    with httpx.Client(timeout=30) as http:
        resp = http.post(f"{api_url.rstrip('/')}/analyze", json=data, headers=headers)

    if resp.status_code == 200:
        result = resp.json()
        intel = result.get("intelligence", {})
        click.echo(f"\n  Submitted! Your {data.get('vendor', '?')} eval is in the pool.")
        if intel.get("your_score") and intel.get("category_avg"):
            click.echo(f"  Your score: {intel['your_score']} vs category avg: {intel['category_avg']}")
        if intel.get("known_gaps"):
            click.echo(f"  Known gaps: {', '.join(intel['known_gaps'][:5])}")
        click.echo()
    else:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")


def _interactive_eval(vendor: str) -> dict:
    """Walk the user through an interactive tool evaluation."""
    categories = ["edr", "siem", "cnapp", "iam", "pam", "email", "ztna", "vm", "waf", "ndr", "soar", "dlp", "threat-intel"]
    industries = ["healthcare", "financial", "tech", "government", "energy", "manufacturing", "retail", "education", "other"]
    sizes = ["1-100", "100-500", "500-1000", "1000-5000", "5000-10000", "10000+"]

    category = click.prompt("  Category", type=click.Choice(categories), default="edr")
    score = click.prompt("  Overall score (0-10)", type=float, default=7.0)
    detection = click.prompt("  Detection rate % (0-100, or skip)", default="", show_default=False)
    fp_rate = click.prompt("  False positive rate % (or skip)", default="", show_default=False)
    deploy = click.prompt("  Deploy days (or skip)", default="", show_default=False)
    would_buy = click.confirm("  Would you buy again?", default=True)
    strength = click.prompt("  Top strength (one line)", default="", show_default=False)
    friction = click.prompt("  Top friction (one line)", default="", show_default=False)
    industry = click.prompt("  Your industry", type=click.Choice(industries), default="tech")
    org_size = click.prompt("  Org size", type=click.Choice(sizes), default="1000-5000")

    # Price (optional)
    click.echo("\n  Pricing (optional — skip with Enter):")
    annual_cost = click.prompt("  Annual cost ($)", default="", show_default=False)
    per_seat_cost = click.prompt("  Per-seat/endpoint cost ($)", default="", show_default=False)
    contract_length = click.prompt("  Contract length (months)", default="", show_default=False)
    discount_pct = click.prompt("  Discount off list price (%)", default="", show_default=False)

    # Support (optional)
    click.echo("\n  Support experience (optional):")
    support_quality = click.prompt("  Support quality (1-10)", default="", show_default=False)
    escalation_ease = click.prompt("  Escalation ease (1-10)", default="", show_default=False)
    support_sla = click.prompt("  SLA response time (hours)", default="", show_default=False)

    # Decision
    click.echo("\n  Decision:")
    chose = click.prompt("  Did you choose this vendor? (y/n)", default="", show_default=False)
    decision_factor = click.prompt("  Main decision factor (price/detection/support/integration/compliance)", default="", show_default=False)

    data = {
        "vendor": vendor,
        "category": category,
        "overall_score": score,
        "would_buy": would_buy,
        "context": {"industry": industry, "org_size": org_size},
    }
    if detection:
        data["detection_rate"] = float(detection)
    if fp_rate:
        data["fp_rate"] = float(fp_rate)
    if deploy:
        data["deploy_days"] = int(deploy)
    if strength:
        data["top_strength"] = strength
    if friction:
        data["top_friction"] = friction
    if annual_cost:
        data["annual_cost"] = float(annual_cost)
    if per_seat_cost:
        data["per_seat_cost"] = float(per_seat_cost)
    if contract_length:
        data["contract_length_months"] = int(contract_length)
    if discount_pct:
        data["discount_pct"] = float(discount_pct)
    if support_quality:
        data["support_quality"] = float(support_quality)
    if escalation_ease:
        data["escalation_ease"] = float(escalation_ease)
    if support_sla:
        data["support_sla_hours"] = float(support_sla)
    if chose:
        data["chose_this_vendor"] = chose.lower().startswith("y")
    if decision_factor:
        data["decision_factor"] = decision_factor

    click.echo("\n  Preview:")
    click.echo(f"    Vendor:    {vendor}")
    click.echo(f"    Category:  {category}")
    click.echo(f"    Score:     {score}/10")
    click.echo(f"    Would buy: {'yes' if would_buy else 'no'}")
    if not click.confirm("\n  Submit this evaluation?", default=True):
        click.echo("  Cancelled.")
        raise SystemExit(0)

    return data


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
        click.echo("\n  Recent sessions:")
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
            click.echo("\n  ADTC Attestation Chain")
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
                click.echo("  VAP: No PII patterns detected in output")
            click.echo()


# ── Scrape (threat feed + vendor intelligence ingestion) ──────────────────────

@main.command()
@click.option("--feed", multiple=True, help="Specific IOC feed(s) or vendor scraper(s) to run (repeatable)")
@click.option("--list", "list_feeds", is_flag=True, help="Show all available sources")
@click.option("--dry-run", is_flag=True, help="Scrape but don't upload, just show counts")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
def scrape(feed, list_feeds, dry_run, api_url, api_key):
    """Scrape public threat intelligence feeds and vendor evaluations."""
    from .feeds import FEEDS, scrape_feed, bundle_iocs, ingest_to_server
    from .scrapers import SCRAPERS, run_scraper, ingest_evals_to_server
    from datetime import datetime, timezone

    if list_feeds:
        click.echo("\n  IOC Feeds:")
        for name, info in FEEDS.items():
            click.echo(f"    {name:20s}{info['description']}")
        click.echo()
        click.echo("  Vendor Intelligence:")
        for name, info in SCRAPERS.items():
            click.echo(f"    {name:20s}{info['description']}")
        click.echo()
        return

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not dry_run and not api_url:
        click.echo("  No server URL configured. Run: nur init  (or use --dry-run)")
        raise SystemExit(1)

    # Determine which sources to run
    all_sources = {**{k: "feed" for k in FEEDS}, **{k: "scraper" for k in SCRAPERS}}
    requested = list(feed) if feed else list(all_sources.keys())

    # Validate names
    for name in requested:
        if name not in all_sources:
            click.echo(f"  Unknown source: {name}. Use --list to see available sources.")
            raise SystemExit(1)

    # Load existing feed status for timestamp tracking
    feed_status_path = Path.home() / ".nur" / "feed_status.json"
    feed_status: dict = {}
    if feed_status_path.exists():
        try:
            feed_status = json.loads(feed_status_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    total_iocs = 0
    total_evals = 0
    total_uploaded = 0
    sources_ok = 0

    for name in requested:
        kind = all_sources[name]

        if kind == "feed":
            click.echo(f"  Fetching {name}...", nl=False)
            try:
                iocs = scrape_feed(name)
            except Exception as e:
                click.echo(f" error: {e}")
                continue
            click.echo(f" {len(iocs)} IOCs")
            total_iocs += len(iocs)
            if iocs:
                sources_ok += 1
            # Record feed timestamp
            feed_status[name] = {
                "last_scraped": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                "ioc_count": len(iocs),
            }
            if not dry_run and iocs and api_url:
                bundles = bundle_iocs(iocs, name)
                uploaded = ingest_to_server(api_url, bundles, api_key=api_key)
                total_uploaded += uploaded

        else:  # scraper
            click.echo(f"  Scraping {name}...", nl=False)
            try:
                evals = run_scraper(name)
            except Exception as e:
                click.echo(f" error: {e}")
                continue
            click.echo(f" {len(evals)} evaluations")
            total_evals += len(evals)
            if evals:
                sources_ok += 1
            # Record scraper timestamp
            feed_status[name] = {
                "last_scraped": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                "ioc_count": len(evals),
            }
            if not dry_run and evals and api_url:
                uploaded = ingest_evals_to_server(api_url, evals, api_key=api_key)
                total_uploaded += uploaded

    # Save feed status timestamps
    try:
        feed_status_path.parent.mkdir(parents=True, exist_ok=True)
        feed_status_path.write_text(json.dumps(feed_status, indent=2))
    except OSError:
        pass

    click.echo()
    parts = []
    if total_iocs:
        parts.append(f"{total_iocs} IOCs")
    if total_evals:
        parts.append(f"{total_evals} evaluations")
    summary = " + ".join(parts) if parts else "0 results"
    if dry_run:
        click.echo(f"  [dry-run] Scraped {summary} from {sources_ok} sources (nothing uploaded)")
    else:
        click.echo(f"  Ingested {summary} from {sources_ok} sources ({total_uploaded} uploads)")
    click.echo()


# ── SEC EDGAR breach scraper ─────────────────────────────────────────────────

@main.command("scrape-sec")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--max", "max_filings", default=50, help="Max filings to scrape")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
def scrape_sec(api_url, api_key, max_filings, json_output):
    """Scrape SEC EDGAR for cybersecurity breach filings (8-K Item 1.05)."""
    import asyncio
    from .sec_breach import scrape_and_ingest

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL. Run: nur init")
        return

    results = asyncio.run(scrape_and_ingest(api_url, api_key, max_filings))

    if json_output:
        click.echo(json.dumps(results, indent=2))
    else:
        click.echo("\n  SEC EDGAR Cybersecurity Breach Scraper")
        click.echo(f"  {'=' * 45}")
        click.echo(f"  Filings found: {results['total']}")
        click.echo(f"  Ingested: {results['ingested']}")
        click.echo(f"  Errors: {results['errors']}")
        if results["filings"]:
            click.echo("\n  Recent breaches:")
            for f in results["filings"][:10]:
                techs = ", ".join(f["techniques"][:3]) if f["techniques"] else "unknown"
                rems = ", ".join(f["remediation"][:3]) if f["remediation"] else "unknown"
                click.echo(f"    {f['company']} ({f['date']})")
                click.echo(f"      techniques: {techs}")
                click.echo(f"      remediation: {rems}")


# ── HHS Breach Portal scraper ───────────────────────────────────────────────

@main.command("scrape-hhs")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
def scrape_hhs(api_url, api_key, json_output):
    """Ingest HHS breach portal data — healthcare breaches (public)."""
    import asyncio
    from .feeds.hhs_breach import ingest_hhs_breaches

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL. Run: nur init")
        return

    results = asyncio.run(ingest_hhs_breaches(api_url, api_key))

    if json_output:
        click.echo(json.dumps(results, indent=2))
    else:
        click.echo("\n  HHS Breach Portal")
        click.echo(f"  {'=' * 35}")
        click.echo(f"  Breaches: {results['total']}")
        click.echo(f"  Ingested: {results['ingested']}")
        if results['breaches']:
            click.echo("\n  Major breaches ingested:")
            for b in results['breaches'][:5]:
                click.echo(f"    {b['entity']} — {b['affected']:,} affected ({b['type']})")


@main.command("scrape-pacer")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--max", "max_cases", default=25, help="Max cases to search")
@click.option("--json", "json_output", is_flag=True)
def scrape_pacer(api_url, api_key, max_cases, json_output):
    """Scrape PACER for breach lawsuits — court records (costs $0.10/page)."""
    import asyncio

    from .feeds.pacer import scrape_and_ingest

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL. Run: nur init")
        return

    click.echo("  Note: PACER charges $0.10/page. First $30/quarter is free.")
    results = asyncio.run(scrape_and_ingest(api_url, api_key, max_cases=max_cases))

    if json_output:
        click.echo(json.dumps(results, indent=2))
    else:
        click.echo("\n  PACER Court Records")
        click.echo(f"  {'=' * 35}")
        click.echo(f"  Cases found: {results['total']}")
        click.echo(f"  Ingested: {results['ingested']}")
        click.echo(f"  Errors: {results['errors']}")
        if results.get("cases"):
            click.echo("\n  Breach cases:")
            for c in results["cases"][:10]:
                click.echo(f"    {c['case']} ({c['court']}, {c['date']})")


# ── Up (full loop — server + feeds + ready) ──────────────────────────────────

@main.command()
@click.option("--port", type=int, default=8000)
@click.option("--host", default="0.0.0.0")
@click.option("--db", default="sqlite+aiosqlite:///nur.db", help="Database URL")
@click.option("--skip-feeds", is_flag=True, help="Start server without scraping feeds")
@click.option("--vertical", default=None,
              type=click.Choice(["healthcare", "financial", "energy", "government"]),
              help="Industry vertical (customizes threat actors, techniques, actions)")
def up(port, host, db, skip_feeds, vertical):
    """Start nur: server + live threat feeds. One command, full loop.

    \b
    After this, open another terminal and run:
      nur report incident_iocs.json
    """
    import time

    try:
        import uvicorn
        from .server.app import create_app
    except ImportError:
        click.echo("  Server requires: pip install nur[server]")
        raise SystemExit(1)

    api_url = f"http://127.0.0.1:{port}"

    # Save config so `nur report` works without flags
    config = _load_config()
    config["api_url"] = api_url
    if vertical:
        config["vertical"] = vertical
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    click.echo()
    if vertical:
        from .verticals import get_vertical
        v = get_vertical(vertical)
        click.echo("  ┌─────────────────────────────────────────┐")
        click.echo(f"  │  nur up — {v.display_name[:27]:27s}│")
        click.echo("  └─────────────────────────────────────────┘")
        click.echo(f"  Threat actors: {', '.join(v.threat_actors[:4])}")
        click.echo(f"  Compliance: {', '.join(v.compliance[:3])}")
    else:
        click.echo("  ┌─────────────────────────────────────────┐")
        click.echo("  │  nur up                              │")
        click.echo("  └─────────────────────────────────────────┘")
    click.echo()

    app = create_app(db_url=db)
    app.state.port = port

    if not skip_feeds:
        # Start server in background, scrape feeds, then foreground the server
        import threading

        server_config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        server = uvicorn.Server(server_config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        # Wait for server to be ready
        import httpx
        for _ in range(30):
            try:
                resp = httpx.get(f"{api_url}/health", timeout=1)
                if resp.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.3)

        click.echo(f"  Server running on {api_url}")
        click.echo()

        # Scrape feeds
        click.echo("  Scraping live threat feeds...")
        from .feeds import FEEDS, scrape_feed, bundle_iocs, ingest_to_server
        total_iocs = 0
        for name in FEEDS:
            try:
                iocs = scrape_feed(name)
                click.echo(f"    {name}: {len(iocs)} IOCs", nl=False)
                total_iocs += len(iocs)
                if iocs:
                    bundles = bundle_iocs(iocs, name)
                    ingest_to_server(api_url, bundles, api_key=config.get("api_key"))
                    click.echo(" ✓")
                else:
                    click.echo()
            except Exception as e:
                click.echo(f" error: {e}")

        # Also seed demo/seed hospital bundles if they exist
        seed_dir = Path(__file__).parent.parent / "demo" / "seed"
        demo_dir = Path(__file__).parent.parent / "demo"
        seed_files = []
        if seed_dir.exists():
            seed_files = sorted(seed_dir.glob("*.json"))
        # Also check for demo data
        for pattern in ["ioc_bundle_*.json", "attack_map_*.json", "eval_*.json"]:
            seed_files.extend(sorted(demo_dir.glob(pattern)))

        if seed_files:
            seed_count = 0
            for f in seed_files:
                if f.name == "cisa_kev_reference.json":
                    continue
                try:
                    contribs = load_file(str(f))
                    for c in contribs:
                        clean = anonymize(c)
                        from .client import _serialize, _route_for
                        payload = _serialize(clean)
                        route = _route_for(clean)
                        import httpx as _hx
                        _hx.post(f"{api_url}{route}", json=payload, timeout=5)
                        seed_count += 1
                except Exception:
                    continue
            if seed_count:
                click.echo(f"  Loaded {seed_count} demo contributions")

        click.echo()
        click.echo(f"  Total: {total_iocs} IOCs from live feeds + {seed_count if seed_files else 0} demo contributions")
        click.echo()
        click.echo("  ──────────────────────────────────────────")
        click.echo("  Ready. In another terminal, run:")
        click.echo()
        click.echo("    nur report <your_incident_file.json>")
        click.echo()
        click.echo("  ──────────────────────────────────────────")
        click.echo()

        # Block until Ctrl+C
        try:
            thread.join()
        except KeyboardInterrupt:
            click.echo("\n  Shutting down...")
            server.should_exit = True
            thread.join(timeout=3)
    else:
        click.echo(f"  Server starting on {host}:{port}")
        click.echo("  Config saved — run: nur report <file>")
        click.echo()
        uvicorn.run(app, host=host, port=port)


# ── Server (raw, no feeds) ────────────────────────────────────────────────

@main.command()
@click.option("--port", type=int, default=8000)
@click.option("--host", default="0.0.0.0")
@click.option("--db", default="sqlite+aiosqlite:///nur.db", help="Database URL")
def serve(port, host, db):
    """Start the nur server (without feed ingestion)."""
    try:
        import uvicorn
        from .server.app import create_app
    except ImportError:
        click.echo("Server requires: pip install nur[server]")
        raise SystemExit(1)
    app = create_app(db_url=db)
    app.state.port = port
    click.echo(f"  nur server starting on {host}:{port}")
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
        click.echo("  PSI requires: pip install nur[crypto]")
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


# ── Threat Model ──────────────────────────────────────────────────────────────

@main.command("threat-model")
@click.option("--stack", required=True, help="Comma-separated list of tools (e.g. crowdstrike,splunk,okta)")
@click.option("--vertical", default="healthcare",
              type=click.Choice(["healthcare", "financial", "energy", "government"]),
              help="Industry vertical")
@click.option("--org", default="Organization", help="Organization name")
@click.option("--json", "json_output", is_flag=True, help="Output full JSON")
@click.option("--hcl", "hcl_output", is_flag=True, help="Output threatcl HCL format")
@click.option("--output", "-o", default=None, help="Save output to file")
def threat_model_cmd(stack, vertical, org, json_output, hcl_output, output):
    """Generate a threat model for your security stack.

    \b
    Examples:
      nur threat-model --stack crowdstrike,splunk,okta --vertical healthcare
      nur threat-model --stack crowdstrike,splunk --vertical financial --hcl
      nur threat-model --stack crowdstrike,splunk,okta --hcl --output model.hcl
    """
    from .threat_model import generate_threat_model

    tools = [t.strip() for t in stack.split(",") if t.strip()]
    if not tools:
        click.echo("  No tools provided. Use --stack tool1,tool2,tool3")
        raise SystemExit(1)

    model = generate_threat_model(stack=tools, vertical=vertical, org_name=org)

    if json_output:
        # Full JSON output
        import json as json_mod
        text = json_mod.dumps(model, indent=2)
        if output:
            Path(output).write_text(text)
            click.echo(f"  Saved JSON to {output}")
        else:
            click.echo(text)
        return

    if hcl_output:
        # HCL output
        text = model["threatcl_hcl"]
        if output:
            Path(output).write_text(text)
            click.echo(f"  Saved HCL to {output}")
        else:
            click.echo(text)
        return

    # Default: human-readable summary
    click.echo()
    click.echo(f"  Threat Model: {model['org_name']}")
    click.echo(f"  Vertical: {model['vertical_display']}")
    click.echo(f"  {'=' * 56}")

    # Stack
    click.echo(f"\n  Stack ({len(model['stack'])} tools):")
    for t in model["stack"]:
        click.echo(f"    - {t['display_name']} ({t['category']})")

    # Coverage score
    score_pct = int(model["coverage_score"] * 100)
    covered = len(model["coverage"])
    total = covered + len(model["gaps"])
    click.echo(f"\n  Coverage: {score_pct}% ({covered}/{total} priority techniques)")

    # Covered techniques
    if model["coverage"]:
        click.echo("\n  Covered Techniques:")
        for tech_id, info in model["coverage"].items():
            tool_names = ", ".join(t["display_name"] for t in info["tools"])
            click.echo(f"    [{tech_id}] {info['name']}")
            click.echo(f"      Covered by: {tool_names}")

    # Gaps
    if model["gaps"]:
        click.echo(f"\n  Gaps ({len(model['gaps'])} uncovered):")
        for gap in model["gaps"]:
            click.echo(f"    [{gap['id']}] {gap['name']}")
            click.echo(f"      {gap['why']}")
            if gap.get("suggested_categories"):
                click.echo(f"      Suggested: {', '.join(gap['suggested_categories'][:3])}")

    # Compliance
    click.echo("\n  Compliance:")
    for fw, info in model["compliance"].items():
        status = "COVERED" if info["covered"] else "GAP"
        tool_str = f" ({', '.join(info['tools'])})" if info["tools"] else ""
        click.echo(f"    {fw}: {status}{tool_str}")

    # Threat actors
    click.echo(f"\n  Threat Actors: {', '.join(model['threat_actors'][:5])}")

    # Recommendations
    if model["recommendations"]:
        click.echo("\n  Recommendations:")
        for rec in model["recommendations"][:8]:
            priority = rec["priority"].upper()
            click.echo(f"    [{priority}] {rec['action']}")
            click.echo(f"      {rec['detail']}")

    click.echo()

    if output:
        import json as json_mod
        Path(output).write_text(json_mod.dumps(model, indent=2))
        click.echo(f"  Full model saved to {output}")
        click.echo()


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
            click.echo("\n  ZK Proof Bundle")
            click.echo(f"  {'=' * 40}")
            click.echo(f"  Type:   {bundle.contribution_type}")
            click.echo(f"  Proofs: {len(bundle.proofs)}")
            for p in bundle.proofs:
                click.echo(f"    {p.get('proof_type', '?'):12s} {p.get('field', '')}")

            # Self-verify
            result = prover.verify(bundle)
            click.echo(f"\n  Self-verification: {result.summary}")


# ── Search commands ──────────────────────────────────────────────────────────

@main.group()
def search():
    """Search vendor intelligence — scores, rankings, comparisons."""
    pass


@search.command("vendor")
@click.argument("name")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_vendor(name, api_url, api_key, json_output):
    """Look up a vendor with weighted scores and metadata."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/search/vendor/{name}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  {data.get('vendor_display', name)}")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Category:       {data.get('category', '?')}")
    click.echo(f"  Weighted Score: {data.get('weighted_score', '?')}")
    click.echo(f"  Confidence:     {data.get('confidence', '?')}")
    click.echo(f"  Eval Count:     {data.get('eval_count', 0)}")
    if data.get('price_range'):
        click.echo(f"  Price Range:    {data['price_range']}")
    if data.get('certifications'):
        click.echo(f"  Certifications: {', '.join(data['certifications'])}")
    if data.get('insurance_carriers'):
        click.echo(f"  Insurance:      {', '.join(data['insurance_carriers'])}")
    if data.get('known_issues'):
        click.echo(f"  Known Issues:   {data['known_issues'][:80]}")
    metrics = data.get('metrics', {})
    if any(v is not None for v in metrics.values()):
        click.echo("\n  Metrics:")
        if metrics.get('detection_rate') is not None:
            click.echo(f"    Detection Rate: {metrics['detection_rate']}")
        if metrics.get('fp_rate') is not None:
            click.echo(f"    FP Rate:        {metrics['fp_rate']}")
        if metrics.get('deploy_days') is not None:
            click.echo(f"    Deploy Days:    {metrics['deploy_days']}")
    click.echo()


@search.command("category")
@click.argument("name")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_category(name, api_url, api_key, json_output):
    """Rank vendors within a category by weighted score."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/search/category/{name}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Category: {data.get('category', name)}")
    click.echo(f"  {'=' * 50}")
    vendors = data.get("vendors", [])
    if not vendors:
        click.echo("  No vendors found.")
        return
    for i, v in enumerate(vendors, 1):
        score = v.get("weighted_score")
        score_str = f"{score:.1f}" if score is not None else "  ?"
        conf = v.get("confidence", "?")
        click.echo(f"  {i:2d}. {v.get('vendor_display', '?'):25s}  score={score_str}  confidence={conf}")
    click.echo()


@search.command("compare")
@click.argument("vendor_a")
@click.argument("vendor_b")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_compare(vendor_a, vendor_b, api_url, api_key, json_output):
    """Side-by-side comparison of two vendors."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(
            f"{api_url.rstrip('/')}/search/compare",
            params={"a": vendor_a, "b": vendor_b},
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    a = data.get("vendor_a", {})
    b = data.get("vendor_b", {})
    click.echo(f"\n  {'':30s} {'A':>12s}  {'B':>12s}")
    click.echo(f"  {'Vendor':30s} {a.get('vendor_display','?'):>12s}  {b.get('vendor_display','?'):>12s}")
    click.echo(f"  {'=' * 56}")

    def _fmt(val):
        if val is None:
            return "?"
        if isinstance(val, float):
            return f"{val:.1f}"
        return str(val)

    click.echo(f"  {'Weighted Score':30s} {_fmt(a.get('weighted_score')):>12s}  {_fmt(b.get('weighted_score')):>12s}")
    click.echo(f"  {'Confidence':30s} {_fmt(a.get('confidence')):>12s}  {_fmt(b.get('confidence')):>12s}")
    click.echo(f"  {'Eval Count':30s} {_fmt(a.get('eval_count')):>12s}  {_fmt(b.get('eval_count')):>12s}")
    click.echo(f"  {'Category':30s} {_fmt(a.get('category')):>12s}  {_fmt(b.get('category')):>12s}")
    if a.get('price_range') or b.get('price_range'):
        click.echo(f"  {'Price Range':30s} {_fmt(a.get('price_range')):>12s}  {_fmt(b.get('price_range')):>12s}")
    click.echo()


# ── Market command ───────────────────────────────────────────────────────────

@main.command()
@click.argument("category")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def market(category, api_url, api_key, json_output):
    """Market map for a category — leaders, contenders, emerging, watch."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/intelligence/market/{category}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Market Map: {data.get('category', category)}")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Total vendors: {data.get('vendor_count', 0)}")

    tiers = data.get("tiers", {})
    for tier_name in ("leaders", "contenders", "emerging", "watch"):
        vendors = tiers.get(tier_name, [])
        if vendors:
            click.echo(f"\n  {tier_name.upper()} ({len(vendors)}):")
            for v in vendors:
                score = v.get("weighted_score")
                score_str = f"{score:.1f}" if score is not None else "  ?"
                click.echo(f"    {v.get('display', '?'):25s}  score={score_str}  conf={v.get('confidence', '?')}")
    click.echo()


# ── Threat Map command ───────────────────────────────────────────────────────

@main.command("threat-map")
@click.argument("threat_description")
@click.option("--tools", default=None, help="Comma-separated list of current tools")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def threat_map(threat_description, tools, api_url, api_key, json_output):
    """Coverage gap analysis — map a threat to MITRE techniques and find gaps."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {"Content-Type": "application/json"}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    current_tools = [t.strip() for t in tools.split(",")] if tools else []

    with httpx.Client(timeout=30) as http:
        resp = http.post(
            f"{api_url.rstrip('/')}/intelligence/threat-map",
            json={"threat": threat_description, "current_tools": current_tools},
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Threat Map: {data.get('threat', threat_description)}")
    click.echo(f"  {'=' * 50}")

    summary = data.get("coverage_summary", {})
    click.echo(f"  Coverage: {summary.get('covered', 0)}/{summary.get('total_techniques', 0)} techniques covered")
    click.echo(f"  Gaps: {summary.get('gaps', 0)}")

    kill_chain = data.get("kill_chain", [])
    if kill_chain:
        click.echo("\n  Kill Chain:")
        for step in kill_chain:
            status = "COVERED" if not step.get("gap") else "GAP"
            coverage = step.get("your_coverage") or ""
            click.echo(f"    [{status:7s}] {step.get('technique_id', '?'):8s} {step.get('technique_name', '?')}")
            if coverage:
                click.echo(f"              Covered by: {coverage}")
            if step.get("gap") and step.get("recommended"):
                recs = [r["vendor_display"] for r in step["recommended"][:2]]
                click.echo(f"              Consider: {', '.join(recs)}")

    recs = data.get("gap_recommendations", [])
    if recs:
        click.echo("\n  Recommendations:")
        for r in recs:
            click.echo(f"    - {r}")
    click.echo()


# ── Admin ────────────────────────────────────────────────────────────────────

@main.group()
def admin():
    """Admin tools — server status, sources, database, exports, key management."""
    pass


@admin.command()
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
def status(api_url, api_key):
    """Server health, contribution counts, and feed freshness."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)

    click.echo("\n  nur admin status")
    click.echo("  " + "=" * 50)

    # Server health
    if api_url:
        import urllib.request as _ur
        try:
            req = _ur.Request(f"{api_url.rstrip('/')}/health")
            if api_key:
                req.add_header("X-API-Key", api_key)
            with _ur.urlopen(req, timeout=5) as resp:
                health = json.loads(resp.read().decode())
            click.echo(f"  Server:  {api_url}")
            click.echo(f"  Health:  {health.get('status', 'unknown')}")
        except Exception as e:
            click.echo(f"  Server:  {api_url} (unreachable: {e})")

        # Stats
        try:
            req = _ur.Request(f"{api_url.rstrip('/')}/stats")
            if api_key:
                req.add_header("X-API-Key", api_key)
            with _ur.urlopen(req, timeout=5) as resp:
                stats = json.loads(resp.read().decode())
            click.echo("\n  Contributions:")
            for k, v in stats.items():
                click.echo(f"    {k:30s} {v}")
        except Exception:
            click.echo("  Stats:   unavailable")
    else:
        click.echo("  Server:  not configured (run: nur init)")

    # Feed freshness
    feed_status_path = Path.home() / ".nur" / "feed_status.json"
    if feed_status_path.exists():
        try:
            feed_status = json.loads(feed_status_path.read_text())
            click.echo("\n  Feed Freshness:")
            for name, info in sorted(feed_status.items()):
                ts = info.get("last_scraped", "?")
                count = info.get("ioc_count", 0)
                click.echo(f"    {name:20s} last={ts}  count={count}")
        except (json.JSONDecodeError, OSError):
            click.echo("  Feed status: unavailable")
    else:
        click.echo("\n  Feed status: no scrape history (run: nur scrape --dry-run)")
    click.echo()


@admin.command()
def sources():
    """List ALL known data sources with implementation status."""
    from .scrapers.sources import (
        TIER_1_FEEDS, TIER_2_LABS, TIER_3_COMMUNITY,
        TIER_4_MARKET, TIER_5_PLATFORMS, ALL_SOURCES,
    )

    tiers = [
        ("TIER 1: Direct Feeds", TIER_1_FEEDS),
        ("TIER 2: Independent Labs", TIER_2_LABS),
        ("TIER 3: Community Sources", TIER_3_COMMUNITY),
        ("TIER 4: Market Intelligence", TIER_4_MARKET),
        ("TIER 5: Threat Platforms", TIER_5_PLATFORMS),
    ]

    implemented = sum(1 for s in ALL_SOURCES.values() if s.get("status") == "implemented")
    planned = sum(1 for s in ALL_SOURCES.values() if s.get("status") == "planned")

    click.echo(f"\n  nur data sources ({len(ALL_SOURCES)} total: {implemented} implemented, {planned} planned)")
    click.echo("  " + "=" * 70)

    for tier_name, tier_dict in tiers:
        click.echo(f"\n  {tier_name} ({len(tier_dict)})")
        click.echo(f"  {'-' * 68}")
        for name, info in tier_dict.items():
            status_str = info.get("status", "?")
            tag = "[OK]" if status_str == "implemented" else "[--]"
            data_desc = info.get("data", "")[:50]
            click.echo(f"    {tag} {name:25s} {data_desc}")
    click.echo()


@admin.command("db-stats")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
def db_stats(api_url, api_key):
    """Detailed database statistics — contributions by type, vendors, techniques, IOCs."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    import urllib.request as _ur

    click.echo("\n  nur database statistics")
    click.echo("  " + "=" * 50)

    try:
        req = _ur.Request(f"{api_url.rstrip('/')}/stats")
        if api_key:
            req.add_header("X-API-Key", api_key)
        with _ur.urlopen(req, timeout=10) as resp:
            stats = json.loads(resp.read().decode())
    except Exception as e:
        click.echo(f"  Error fetching stats: {e}")
        raise SystemExit(1)

    click.echo("\n  Overview:")
    total = stats.get("total_contributions", stats.get("total", 0))
    click.echo(f"    Total contributions:  {total}")

    for k, v in stats.items():
        if k in ("total_contributions", "total"):
            continue
        click.echo(f"    {k:30s} {v}")
    click.echo()


@admin.command()
@click.option("--format", "fmt", type=click.Choice(["json"]), default="json", help="Export format")
@click.option("--output", "-o", default=None, help="Output file (default: nur_export.json)")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
def export(fmt, output, api_url, api_key):
    """Export all aggregated data to a file."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    import urllib.request as _ur
    from datetime import datetime, timezone

    output = output or f"nur_export.{fmt}"

    click.echo(f"\n  Exporting data from {api_url}...")

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    export_data: dict = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "server": api_url,
    }

    # Fetch stats
    try:
        req = _ur.Request(f"{api_url.rstrip('/')}/stats")
        for k, v in headers.items():
            req.add_header(k, v)
        with _ur.urlopen(req, timeout=10) as resp:
            export_data["stats"] = json.loads(resp.read().decode())
        click.echo("  Fetched stats")
    except Exception:
        export_data["stats"] = {}

    # Fetch health
    try:
        req = _ur.Request(f"{api_url.rstrip('/')}/health")
        for k, v in headers.items():
            req.add_header(k, v)
        with _ur.urlopen(req, timeout=5) as resp:
            export_data["health"] = json.loads(resp.read().decode())
        click.echo("  Fetched health")
    except Exception:
        export_data["health"] = {}

    # Try known query endpoints
    for endpoint in ("/search/categories", "/intelligence/market/edr"):
        try:
            req = _ur.Request(f"{api_url.rstrip('/')}{endpoint}")
            for k, v in headers.items():
                req.add_header(k, v)
            with _ur.urlopen(req, timeout=10) as resp:
                key = endpoint.strip("/").replace("/", "_")
                export_data[key] = json.loads(resp.read().decode())
            click.echo(f"  Fetched {endpoint}")
        except Exception:
            pass

    with open(output, "w") as fp:
        json.dump(export_data, fp, indent=2)

    click.echo(f"\n  Exported to {output}")
    click.echo()


@admin.command("rotate-key")
def rotate_key():
    """Generate a new random API key and save it to config."""
    import secrets

    new_key = secrets.token_urlsafe(32)
    config = _load_config()
    config["api_key"] = new_key
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    click.echo("\n  New API key generated:")
    click.echo(f"  {new_key}")
    click.echo(f"\n  Saved to {_CONFIG_PATH}")
    click.echo("  Set this on your server to authenticate requests.")
    click.echo()


@admin.command()
@click.option("--older-than", default="30d", help="Remove data older than this (e.g. 30d, 7d)")
def purge(older_than):
    """Remove old contributions (requires direct DB access)."""
    click.echo(f"\n  Purge requested: older than {older_than}")
    click.echo()
    click.echo("  WARNING: Purge requires direct database access.")
    click.echo("  Use SQL to delete old contributions:")
    click.echo()
    click.echo(f"    DELETE FROM contributions WHERE created_at < NOW() - INTERVAL '{older_than}';")
    click.echo()
    click.echo("  Or connect to the nur DB and run a migration.")
    click.echo()


# ── Import (peacetime integrations) ──────────────────────────────────────────

@main.group("import")
def import_cmd():
    """Import security data from external tools and formats.

    \b
    Peacetime integrations — auto-populate stack info:
      nur import navigator layer.json       # MITRE ATT&CK Navigator layer
      nur import stack inventory.csv         # tool inventory (CSV/JSON)
      nur import compliance drata.json       # compliance status
    """
    pass


@import_cmd.command("navigator")
@click.argument("layer_file", type=click.Path(exists=True))
@click.option("--vertical", default="healthcare",
              type=click.Choice(["healthcare", "financial", "energy", "government"]),
              help="Industry vertical")
@click.option("--json", "json_output", is_flag=True, help="Output full JSON")
@click.option("--output", "-o", default=None, help="Save output to file")
def import_navigator(layer_file, vertical, json_output, output):
    """Import a MITRE ATT&CK Navigator layer for instant gap analysis.

    \b
    Examples:
      nur import navigator layer.json --vertical healthcare
      nur import navigator coverage.json --json -o model.json
    """
    from .integrations.navigator import import_navigator_layer

    model = import_navigator_layer(layer_file, vertical=vertical)

    if json_output:
        import json as json_mod
        text = json_mod.dumps(model, indent=2)
        if output:
            Path(output).write_text(text)
            click.echo(f"  Saved JSON to {output}")
        else:
            click.echo(text)
        return

    # Human-readable summary
    nav = model.get("navigator_source", {})
    click.echo()
    click.echo(f"  Navigator Import: {nav.get('layer_name', '?')}")
    click.echo(f"  {'=' * 56}")
    click.echo(f"  Techniques in layer: {nav.get('total_techniques', 0)}")
    click.echo(f"  Covered (score > 50): {nav.get('covered_count', 0)}")
    click.echo(f"  Gaps (score <= 50): {nav.get('gap_count', 0)}")

    inferred = nav.get("inferred_stack", [])
    if inferred:
        click.echo(f"\n  Inferred stack ({len(inferred)} tools):")
        for t in model.get("stack", []):
            click.echo(f"    - {t['display_name']} ({t['category']})")

    score_pct = int(model.get("coverage_score", 0) * 100)
    covered = len(model.get("coverage", {}))
    total = covered + len(model.get("gaps", []))
    click.echo(f"\n  Coverage: {score_pct}% ({covered}/{total} priority techniques)")

    gaps = model.get("gaps", [])
    if gaps:
        click.echo("\n  Top gaps:")
        for gap in gaps[:5]:
            click.echo(f"    [{gap['id']}] {gap['name']}")

    recs = model.get("recommendations", [])
    if recs:
        click.echo("\n  Recommendations:")
        for rec in recs[:5]:
            click.echo(f"    [{rec['priority'].upper()}] {rec['action']}")
    click.echo()

    if output:
        import json as json_mod
        Path(output).write_text(json_mod.dumps(model, indent=2))
        click.echo(f"  Full model saved to {output}")
        click.echo()


@import_cmd.command("stack")
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["csv", "json", "auto"]), default="auto",
              help="File format (default: auto-detect from extension)")
@click.option("--vertical", default="healthcare",
              type=click.Choice(["healthcare", "financial", "energy", "government"]),
              help="Industry vertical for threat model")
@click.option("--threat-model", "gen_model", is_flag=True, help="Also generate a threat model")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def import_stack(file, fmt, vertical, gen_model, json_output):
    """Import tool inventory from CSV or JSON.

    \b
    Examples:
      nur import stack inventory.csv
      nur import stack tools.json --threat-model --vertical healthcare
    """
    from .integrations.asset_inventory import import_from_csv, import_from_json

    p = Path(file)
    if fmt == "auto":
        fmt = "csv" if p.suffix.lower() == ".csv" else "json"

    if fmt == "csv":
        slugs = import_from_csv(file)
    else:
        slugs = import_from_json(file)

    if json_output:
        result = {"matched_vendors": slugs, "count": len(slugs)}
        if gen_model:
            from .threat_model import generate_threat_model
            model = generate_threat_model(stack=slugs, vertical=vertical)
            result["threat_model"] = model
        click.echo(json.dumps(result, indent=2))
        return

    click.echo()
    click.echo(f"  Imported {len(slugs)} tools from {p.name}")
    click.echo(f"  {'=' * 46}")
    from .server.vendors import VENDOR_REGISTRY
    for slug in slugs:
        vendor = VENDOR_REGISTRY.get(slug)
        name = vendor["display_name"] if vendor else slug
        cat = vendor["category"] if vendor else "?"
        click.echo(f"    {slug:20s} {name} ({cat})")
    click.echo()

    if gen_model and slugs:
        click.echo("  Generating threat model...")
        from .threat_model import generate_threat_model
        model = generate_threat_model(stack=slugs, vertical=vertical)
        score_pct = int(model.get("coverage_score", 0) * 100)
        click.echo(f"  Coverage: {score_pct}%")
        gaps = model.get("gaps", [])
        if gaps:
            click.echo(f"  Gaps: {len(gaps)}")
            for g in gaps[:5]:
                click.echo(f"    [{g['id']}] {g['name']}")
        click.echo()


@import_cmd.command("compliance")
@click.argument("file", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def import_compliance(file, json_output):
    """Import compliance status from a Drata/Vanta-like export.

    \b
    Accepts:
      - Structured JSON: {"controls": [{"id": "AC-1", "status": "passing", "framework": "NIST 800-53"}]}
      - Simple JSON: {"HIPAA": true, "PCI_DSS": false}
      - CSV: framework,control_id,status
    """
    from .integrations.compliance import import_compliance_status

    status = import_compliance_status(file)

    if json_output:
        click.echo(json.dumps(status, indent=2))
        return

    click.echo()
    click.echo(f"  Compliance Status ({len(status)} frameworks)")
    click.echo(f"  {'=' * 46}")
    for fw, covered in sorted(status.items()):
        icon = "COVERED" if covered else "GAP"
        click.echo(f"    {fw:25s} {icon}")
    covered_count = sum(1 for v in status.values() if v)
    click.echo(f"\n  {covered_count}/{len(status)} frameworks covered")
    click.echo()


# ── Export (peacetime integrations) ──────────────────────────────────────────

@main.group("export")
def export_cmd():
    """Export nur data in standard formats.

    \b
    Export for interop with other security tools:
      nur export navigator --stack crowdstrike,splunk     # ATT&CK Navigator layer
      nur export stix                                     # STIX 2.1 bundle
      nur export misp                                     # MISP event
      nur export csv                                      # CSV
    """
    pass


@export_cmd.command("navigator")
@click.option("--stack", required=True, help="Comma-separated list of tools")
@click.option("--vertical", default="healthcare",
              type=click.Choice(["healthcare", "financial", "energy", "government"]))
@click.option("--org", default="Organization", help="Organization name")
@click.option("--output", "-o", default=None, help="Save to file (default: stdout)")
def export_navigator(stack, vertical, org, output):
    """Export a threat model as an ATT&CK Navigator layer JSON.

    \b
    Generate, then open in https://mitre-attack.github.io/attack-navigator/
    """
    from .threat_model import generate_threat_model
    from .integrations.export import export_navigator_layer

    tools = [t.strip() for t in stack.split(",") if t.strip()]
    if not tools:
        click.echo("  No tools provided.")
        raise SystemExit(1)

    model = generate_threat_model(stack=tools, vertical=vertical, org_name=org)
    layer_json = export_navigator_layer(model)

    if output:
        Path(output).write_text(layer_json)
        click.echo(f"  Navigator layer saved to {output}")
        click.echo("  Open in: https://mitre-attack.github.io/attack-navigator/")
    else:
        click.echo(layer_json)


@export_cmd.command("stix")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save to file")
def export_stix(files, output):
    """Export contributions as a STIX 2.1 bundle."""
    from .integrations.export import export_stix_bundle

    contribs = _load_contributions_from_files(files)
    stix_json = export_stix_bundle(contribs)

    if output:
        Path(output).write_text(stix_json)
        click.echo(f"  STIX bundle saved to {output}")
    else:
        click.echo(stix_json)


@export_cmd.command("misp")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save to file")
def export_misp(files, output):
    """Export contributions as a MISP event."""
    from .integrations.export import export_misp_event

    contribs = _load_contributions_from_files(files)
    misp_json = export_misp_event(contribs)

    if output:
        Path(output).write_text(misp_json)
        click.echo(f"  MISP event saved to {output}")
    else:
        click.echo(misp_json)


@export_cmd.command("csv")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save to file")
def export_csv_cmd(files, output):
    """Export contributions as CSV."""
    from .integrations.export import export_csv

    contribs = _load_contributions_from_files(files)
    csv_text = export_csv(contribs)

    if output:
        Path(output).write_text(csv_text)
        click.echo(f"  CSV saved to {output}")
    else:
        click.echo(csv_text)


def _load_contributions_from_files(files: tuple) -> list[dict]:
    """Load contribution files and convert to plain dicts for export."""
    contribs: list[dict] = []
    for f in files:
        try:
            items = load_file(f)
            for item in items:
                if hasattr(item, "model_dump"):
                    contribs.append(item.model_dump(mode="json"))
                elif isinstance(item, dict):
                    contribs.append(item)
        except Exception as e:
            click.echo(f"  Warning: could not load {f}: {e}")
    return contribs


# ── RFP comparison ───────────────────────────────────────────────────────────

@main.command("rfp")
@click.argument("candidates", nargs=-1, required=True)
@click.option("--category", default="edr", help="Tool category (edr, siem, iam, etc.)")
@click.option("--vertical", default="healthcare",
              type=click.Choice(["healthcare", "financial", "energy", "government"]))
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--output", "-o", default=None, help="Save to file")
def rfp(candidates, category, vertical, json_output, output):
    """Generate a vendor comparison report for procurement/RFP.

    \b
    Examples:
      nur rfp crowdstrike sentinelone ms-defender --category edr
      nur rfp splunk ms-sentinel elastic-siem --category siem --json
    """
    from .integrations.rfp import generate_rfp_comparison

    result = generate_rfp_comparison(
        candidates=list(candidates),
        category=category,
        vertical=vertical,
    )

    if json_output:
        text = json.dumps(result, indent=2)
        if output:
            Path(output).write_text(text)
            click.echo(f"  Saved to {output}")
        else:
            click.echo(text)
        return

    click.echo()
    click.echo(f"  RFP Comparison: {category.upper()}")
    click.echo(f"  Vertical: {vertical}")
    click.echo(f"  {'=' * 60}")

    table = result.get("comparison_table", [])
    if table:
        # Header
        click.echo(f"\n  {'Vendor':30s} {'Overall':>8s} {'Technique':>10s} {'Compliance':>11s} {'Deploy':>7s}")
        click.echo(f"  {'-' * 30} {'-' * 8} {'-' * 10} {'-' * 11} {'-' * 7}")
        for row in table:
            click.echo(
                f"  {row['vendor']:30s} {row['overall']:>8d} "
                f"{row['technique_coverage']:>10d} {row['compliance_score']:>11d} "
                f"{str(row['deploy_days']) + 'd':>7s}"
            )

    not_found = result.get("not_found", [])
    if not_found:
        click.echo(f"\n  Not found in registry: {', '.join(not_found)}")

    rec = result.get("recommendation", "")
    if rec:
        click.echo("\n  Recommendation:")
        click.echo(f"  {rec}")

    # Show detail for each candidate
    for c in result.get("candidates", []):
        if not c.get("found"):
            continue
        click.echo(f"\n  {c['display_name']}")
        click.echo(f"    Price:          {c.get('price_range', '?')}")
        click.echo(f"    Certifications: {', '.join(c.get('certifications', [])[:4])}")
        click.echo(f"    Insurance:      {', '.join(c.get('insurance_carriers', [])[:3]) or 'None'}")
        if c.get("known_issues"):
            click.echo(f"    Known Issues:   {c['known_issues'][:80]}")
    click.echo()

    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        click.echo(f"  Full report saved to {output}")
        click.echo()


# ── Integrate (wartime integrations) ─────────────────────────────────────────

@main.group()
def integrate():
    """Wartime integrations — auto-submit incident data from security tools.

    \b
    Supported:
      nur integrate splunk          Generate Splunk app config
      nur integrate sentinel        Generate Sentinel playbook ARM template
      nur integrate crowdstrike     Pull detections from CrowdStrike Falcon
      nur integrate syslog          Start CEF syslog listener
      nur integrate webhook-test    Test the webhook endpoint
    """
    pass


@integrate.command("splunk")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
@click.option("--output", "-o", default="splunk_app", help="Output directory for Splunk app")
def integrate_splunk(api_url, api_key, output):
    """Generate a Splunk app that forwards alerts to nur."""
    from .integrations.splunk import generate_splunk_app

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    if not api_key:
        click.echo("  No API key configured. Run: nur init")
        raise SystemExit(1)

    files = generate_splunk_app(api_url, api_key)

    output_dir = Path(output)
    for filepath, content in files.items():
        full_path = output_dir / filepath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)

    click.echo(f"\n  Splunk app generated in {output_dir}/")
    click.echo(f"  Files created: {len(files)}")
    for f in sorted(files.keys()):
        click.echo(f"    {f}")
    click.echo(f"\n  Install: cp -r {output_dir} $SPLUNK_HOME/etc/apps/nur_integration/")
    click.echo("  Then restart Splunk.")
    click.echo()


@integrate.command("sentinel")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
@click.option("--output", "-o", default="sentinel_playbook.json", help="Output file")
def integrate_sentinel(api_url, api_key, output):
    """Generate an Azure Sentinel playbook ARM template."""
    from .integrations.sentinel import generate_sentinel_playbook

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    if not api_key:
        click.echo("  No API key configured. Run: nur init")
        raise SystemExit(1)

    arm_json = generate_sentinel_playbook(api_url, api_key)
    Path(output).write_text(arm_json)

    click.echo(f"\n  Sentinel playbook generated: {output}")
    click.echo("\n  Deploy with:")
    click.echo(f"    az deployment group create -g <resource-group> --template-file {output}")
    click.echo()


@integrate.command("crowdstrike")
@click.option("--client-id", required=True, help="CrowdStrike OAuth2 client ID")
@click.option("--client-secret", required=True, help="CrowdStrike OAuth2 client secret")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
@click.option("--since-hours", type=int, default=24, help="Pull detections from last N hours")
@click.option("--pull", is_flag=True, help="Actually pull detections (default: dry run info)")
def integrate_crowdstrike(client_id, client_secret, api_url, api_key, since_hours, pull):
    """Pull detections from CrowdStrike Falcon and submit to nur."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    if not api_key:
        click.echo("  No API key configured. Run: nur init")
        raise SystemExit(1)

    if not pull:
        click.echo("\n  CrowdStrike integration ready.")
        click.echo(f"  Client ID: {client_id[:8]}...")
        click.echo(f"  API URL: {api_url}")
        click.echo(f"  Since: last {since_hours} hours")
        click.echo("\n  Add --pull to actually fetch and submit detections.")
        click.echo()
        return

    from .integrations.crowdstrike import pull_crowdstrike_detections

    click.echo(f"  Pulling CrowdStrike detections (last {since_hours}h)...")
    try:
        count = pull_crowdstrike_detections(
            client_id=client_id,
            client_secret=client_secret,
            api_url=api_url,
            nur_api_key=api_key,
            since_hours=since_hours,
        )
        click.echo(f"  Submitted {count} detections to nur.")
    except Exception as e:
        click.echo(f"  Error: {e}")
    click.echo()


@integrate.command("syslog")
@click.option("--port", type=int, default=514, help="UDP port to listen on")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
def integrate_syslog(port, api_url, api_key):
    """Start a CEF syslog listener that forwards events to nur."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key) or ""
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    from .integrations.syslog_listener import start_syslog_listener

    click.echo(f"\n  Starting syslog/CEF listener on UDP port {port}")
    click.echo(f"  Forwarding to: {api_url}/ingest/webhook")
    if port < 1024:
        click.echo(f"  Note: Port {port} may require root/sudo")
    click.echo()

    start_syslog_listener(port=port, api_url=api_url, api_key=api_key)


@integrate.command("webhook-test")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
@click.option("--payload", default=None, help="JSON payload string to send")
@click.option("--format", "fmt",
              type=click.Choice(["generic", "crowdstrike", "sentinel", "cef", "indicators"]),
              default="generic", help="Payload format to test")
def integrate_webhook_test(api_url, api_key, payload, fmt):
    """Test the webhook endpoint with a sample payload."""
    import httpx

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    # Build test payload
    if payload:
        try:
            test_payload = json.loads(payload)
        except json.JSONDecodeError as e:
            click.echo(f"  Invalid JSON payload: {e}")
            raise SystemExit(1)
    else:
        test_payloads = {
            "generic": {
                "iocs": [
                    {"ioc_type": "ip", "value_raw": "192.168.1.100"},
                    {"ioc_type": "domain", "value_raw": "evil.example.com"},
                    {"ioc_type": "hash-sha256", "value_raw": "abc123def456"},
                ],
                "source": "webhook-test",
            },
            "crowdstrike": {
                "detection": {
                    "technique": "T1486",
                    "tactic": "Impact",
                    "ioc_type": "ip",
                    "ioc_value": "10.0.0.99",
                    "severity": "high",
                    "scenario": "Test CrowdStrike Detection",
                },
            },
            "sentinel": {
                "properties": {
                    "severity": "High",
                    "title": "Test Sentinel Incident",
                    "tactics": ["InitialAccess", "Execution"],
                    "techniques": ["T1566", "T1059"],
                    "entities": [
                        {"kind": "ip", "address": "10.0.0.50"},
                        {"kind": "host", "hostName": "malware.example.com"},
                    ],
                },
            },
            "cef": {
                "cef": "CEF:0|TestVendor|TestProduct|1.0|100|Test Event|5|"
                       "src=192.168.1.1 dst=10.0.0.1 dhost=evil.test.com",
                "source_ip": "192.168.1.1",
            },
            "indicators": {
                "indicators": [
                    {"type": "ip", "value": "172.16.0.99"},
                    {"type": "domain", "value": "phishing.example.com"},
                ],
                "source": "test",
            },
        }
        test_payload = test_payloads[fmt]

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    webhook_url = f"{api_url.rstrip('/')}/ingest/webhook"
    click.echo(f"\n  Testing webhook: {webhook_url}")
    click.echo(f"  Format: {fmt}")
    click.echo(f"  Payload: {json.dumps(test_payload, indent=2)[:500]}")
    click.echo()

    try:
        with httpx.Client(timeout=30) as http:
            resp = http.post(webhook_url, json=test_payload, headers=headers)
        click.echo(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            result = resp.json()
            click.echo(f"  Format detected: {result.get('format_detected', '?')}")
            click.echo(f"  Items stored: {result.get('items_stored', 0)}")
        else:
            click.echo(f"  Response: {resp.text[:300]}")
    except Exception as e:
        click.echo(f"  Error: {e}")
    click.echo()


# -- Attack Pattern Intelligence & Simulator CLI commands --------------------


@main.command("patterns")
@click.argument("vertical", default="healthcare")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
def patterns_cmd(vertical, as_json, api_url, api_key):
    """Show attack methodology patterns for an industry vertical.

    \b
    Examples:
      nur patterns healthcare
      nur patterns financial --json
      nur patterns energy
    """
    api_url = _get_api_url(api_url)

    # Try server first, fall back to local analysis
    if api_url:
        try:
            import httpx
            headers = {}
            api_key = _get_api_key(api_key)
            if api_key:
                headers["X-API-Key"] = api_key
            with httpx.Client(timeout=30) as http:
                resp = http.get(
                    f"{api_url.rstrip('/')}/intelligence/patterns/{vertical}",
                    headers=headers,
                )
            if resp.status_code == 200:
                result = resp.json()
            else:
                click.echo(f"  Server error ({resp.status_code}): {resp.text[:200]}")
                click.echo("  Falling back to local analysis...")
                result = _local_patterns(vertical)
        except Exception:
            click.echo("  Server unreachable. Using local analysis...")
            result = _local_patterns(vertical)
    else:
        result = _local_patterns(vertical)

    if as_json:
        click.echo(json.dumps(result, indent=2))
        return

    _render_patterns(result)


def _local_patterns(vertical: str) -> dict:
    """Generate patterns locally without a server."""
    from .intelligence import extract_attack_patterns

    return extract_attack_patterns(
        db_stats={"total_contributions": 0, "by_type": {}},
        techniques=[],
        contributions=[],
        vertical=vertical,
    )


def _render_patterns(result: dict) -> None:
    """Render attack patterns in human-readable format."""
    vertical_display = result.get("vertical_display", result.get("vertical", "?"))
    click.echo()
    click.echo(f"  Attack Pattern Intelligence: {vertical_display}")
    click.echo("  " + "=" * 55)
    click.echo()

    actors = result.get("threat_actors", [])
    if actors:
        click.echo(f"  Threat Actors: {', '.join(actors[:5])}")
        click.echo()

    patterns = result.get("patterns", {})

    # Initial access
    ia = patterns.get("initial_access", {})
    if ia:
        click.echo("  Initial Access Vectors:")
        for name, info in ia.items():
            label = name.replace("_", " ").title()
            click.echo(f"    {label:<25} {info['pct']:>3}%  ({info['technique']})")
        click.echo()

    # Common chains
    chains = patterns.get("common_chains", [])
    if chains:
        click.echo("  Common Attack Chains:")
        for chain in chains:
            click.echo(f"    {chain['name']}")
            click.echo(f"      Frequency:  {chain['frequency']}")
            click.echo(f"      Dwell time: {chain['avg_dwell_time']}")
            steps = chain.get("steps", [])
            if steps:
                step_str = " -> ".join(s.split("(")[0] for s in steps[:6])
                click.echo(f"      Chain:      {step_str}")
            click.echo()

    # Tool effectiveness
    tool_eff = patterns.get("tool_effectiveness", {})
    if tool_eff:
        click.echo("  Tool Effectiveness (from collective data):")
        for tool, info in sorted(
            tool_eff.items(),
            key=lambda x: x[1].get("detection_pct", 0),
            reverse=True,
        )[:8]:
            from .server.vendors import VENDOR_REGISTRY

            display = VENDOR_REGISTRY.get(tool, {}).get("display_name", tool)
            misses = info.get("misses", [])
            miss_str = f"  Misses: {', '.join(misses[:3])}" if misses else ""
            click.echo(
                f"    {display:<30} {info['detection_pct']:>3}% detection"
                f"  ({info['avg_detect_time']}){miss_str}"
            )
        click.echo()

    # Remediation insights
    rem = patterns.get("remediation_insights", {})
    if rem:
        click.echo("  Remediation Insights:")
        click.echo(f"    Avg recovery time:  {rem.get('avg_recovery_time', '?')}")
        click.echo(f"    With backups:       {rem.get('with_backups', '?')}")
        click.echo(f"    Ransom paid:        {rem.get('ransom_paid_pct', '?')}%")
        effective = rem.get("most_effective", [])
        if effective:
            click.echo("    Most effective actions:")
            for a in effective[:4]:
                click.echo(f"      - {a}")
        click.echo()

    # Minimum viable stack
    mvs = patterns.get("minimum_viable_stack", {})
    if mvs:
        click.echo("  Minimum Viable Stack:")
        click.echo(f"    Categories: {', '.join(mvs.get('tools', []))}")
        click.echo(f"    Coverage:   {mvs.get('coverage', '?')}")
        click.echo(f"    Est. cost:  {mvs.get('estimated_cost', '?')}")
        click.echo()


@main.command("simulate")
@click.option(
    "--stack", required=True,
    help="Comma-separated tool list (e.g., crowdstrike,splunk,okta)",
)
@click.option("--vertical", default="healthcare", help="Industry vertical")
@click.option(
    "--attack", default=None,
    help="Attack type (ransomware, apt, ics, supply-chain, bec)",
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.option("--api-url", default=None, help="nur API URL (default: from nur init)")
@click.option("--api-key", default=None, help="nur API key (default: from nur init)")
def simulate_cmd(stack, vertical, attack, as_json, api_url, api_key):
    """Simulate an attack chain against your security stack.

    \b
    Examples:
      nur simulate --stack crowdstrike,splunk,okta --vertical healthcare
      nur simulate --stack crowdstrike,splunk --vertical financial --attack apt
      nur simulate --stack crowdstrike --json
    """
    stack_list = [s.strip() for s in stack.split(",") if s.strip()]
    if not stack_list:
        click.echo("  Error: --stack must contain at least one tool")
        raise SystemExit(1)

    api_url = _get_api_url(api_url)

    # Try server first, fall back to local
    if api_url:
        try:
            import httpx

            headers = {"Content-Type": "application/json"}
            api_key_val = _get_api_key(api_key)
            if api_key_val:
                headers["X-API-Key"] = api_key_val
            body = {"stack": stack_list, "vertical": vertical}
            if attack:
                body["attack_type"] = attack
            with httpx.Client(timeout=30) as http:
                resp = http.post(
                    f"{api_url.rstrip('/')}/intelligence/simulate",
                    json=body,
                    headers=headers,
                )
            if resp.status_code == 200:
                result = resp.json()
            else:
                click.echo(f"  Server error ({resp.status_code}): {resp.text[:200]}")
                click.echo("  Falling back to local simulation...")
                result = _local_simulate(stack_list, vertical, attack)
        except Exception:
            click.echo("  Server unreachable. Using local simulation...")
            result = _local_simulate(stack_list, vertical, attack)
    else:
        result = _local_simulate(stack_list, vertical, attack)

    if as_json:
        click.echo(json.dumps(result, indent=2))
        return

    _render_simulation(result)


def _local_simulate(stack: list[str], vertical: str, attack_type: str | None) -> dict:
    """Run simulation locally without a server."""
    from .simulator import simulate_attack

    return simulate_attack(stack=stack, vertical=vertical, attack_type=attack_type)


def _render_simulation(result: dict) -> None:
    """Render simulation results in human-readable format."""
    attack_name = result.get("attack_name", result.get("attack_type", "?"))
    vertical_display = result.get("vertical_display", result.get("vertical", "?"))

    click.echo()
    click.echo(f"  Attack Chain Simulation: {vertical_display} {attack_name}")
    click.echo("  " + "=" * 55)
    click.echo()

    chain = result.get("chain", [])
    for step in chain:
        step_num = step["step"]
        tid = step["technique_id"]
        name = step["technique_name"]
        coverage = step.get("your_coverage")
        res = step["result"]
        det_time = step.get("detection_time")

        # Format the result
        if res == "BLOCKED":
            status = f"{coverage}: BLOCKED"
            symbol = "+"
        elif res == "DETECTED":
            time_str = f" (avg {det_time})" if det_time else ""
            status = f"{coverage}: DETECTED{time_str}"
            symbol = "+"
        else:
            status = "No coverage: PASS THROUGH"
            symbol = "x"

        click.echo(f"  Step {step_num}: {tid} {name:<28} -> {status} {symbol}")

    click.echo()

    breaks_at = result.get("chain_breaks_at")
    break_prob = result.get("break_probability", 0)
    if_bypassed = result.get("if_bypassed", "?")
    weakest = result.get("weakest_link", "?")
    coverage_pct = result.get("coverage_pct", 0)

    if breaks_at:
        click.echo(f"  Chain breaks at: Step {breaks_at} ({break_prob}% of attempts blocked)")
    else:
        click.echo("  Chain breaks at: NEVER -- attack completes undetected")

    click.echo(f"  If bypassed:     {if_bypassed}")
    click.echo(f"  Weakest links:   {weakest}")
    click.echo(f"  Coverage:        {coverage_pct}%")
    click.echo()

    recommendations = result.get("recommendations", [])
    if recommendations:
        click.echo("  Recommendations:")
        for rec in recommendations[:6]:
            priority = rec.get("priority", "?")
            action = rec.get("action", "?")
            detail = rec.get("detail", "")
            cost = rec.get("cost", "")
            click.echo(f"    [{priority:<8}] {action}")
            if detail:
                click.echo(f"              {detail}")
            if cost:
                click.echo(f"              Cost: {cost}")
        click.echo()

    min_imp = result.get("minimum_improvement")
    if min_imp:
        click.echo(f"  Minimum viable improvement: {min_imp}")
        click.echo()

    cost_to_close = result.get("cost_to_close")
    if cost_to_close:
        click.echo(f"  Cost to close all gaps: {cost_to_close}")
        click.echo()


@main.command("privacy-levels")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
def privacy_levels_cmd(as_json):
    """Show available privacy-utility tradeoff levels.

    \b
    Examples:
      nur privacy-levels
      nur privacy-levels --json
    """
    from .privacy import list_privacy_levels, PRIVACY_LEVELS

    levels = list_privacy_levels()

    if as_json:
        click.echo(json.dumps(PRIVACY_LEVELS, indent=2))
        return

    click.echo()
    click.echo("  Privacy-Utility Tradeoff Levels")
    click.echo("  " + "=" * 45)
    click.echo()

    for level in levels:
        name = level["name"]
        desc = level["description"]
        config = PRIVACY_LEVELS[name]
        click.echo(f"  {name.upper()}")
        click.echo(f"    {desc}")
        click.echo(f"    IOC hashing:    {config['ioc_hashing']}")
        click.echo(f"    Text scrubbing: {config['text_scrubbing']}")
        click.echo(f"    DP noise:       {config['dp_noise']} (epsilon={config['dp_epsilon']})")
        click.echo(f"    Min-k:          {config['min_k']}")
        click.echo(f"    Strip timing:   {config['strip_timing']}")
        click.echo()


# ── Compare (side-by-side vendor comparison) ────────────────────────────

@main.command()
@click.argument("vendors", nargs=-1, required=True)
@click.option("--vertical", default=None, help="Filter by vertical (healthcare, energy, financial)")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def compare(vendors, vertical, api_url, api_key, json_output):
    """Compare security vendors side-by-side on price, detection, support."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    vendor_list = list(vendors)
    if len(vendor_list) < 2:
        click.echo("  Need at least 2 vendors to compare.")
        raise SystemExit(1)

    # Compare pairs — first two directly, additional ones merged
    all_results = []
    pairs = [(vendor_list[i], vendor_list[i + 1]) for i in range(0, len(vendor_list) - 1, 2)]
    # If odd number, pair last with first
    if len(vendor_list) > 2 and len(vendor_list) % 2 == 1:
        pairs.append((vendor_list[-1], vendor_list[0]))

    with httpx.Client(timeout=30) as http:
        for a, b in pairs:
            params = {"a": a, "b": b}
            if vertical:
                params["vertical"] = vertical
            resp = http.get(
                f"{api_url.rstrip('/')}/search/compare",
                params=params,
                headers=headers,
            )
            if resp.status_code != 200:
                click.echo(f"  Error comparing {a} vs {b}: {resp.status_code} {resp.text[:200]}")
                continue
            all_results.append(resp.json())

    if not all_results:
        click.echo("  No comparison data returned.")
        return

    if json_output:
        output = {
            "comparisons": all_results,
            "vendors": vendor_list,
            "vertical": vertical,
        }
        click.echo(json.dumps(output, indent=2))
        return

    # Human-readable comparison table
    for comp in all_results:
        a = comp.get("vendor_a", {})
        b = comp.get("vendor_b", {})
        click.echo(f"\n  {'':30s} {'A':>12s}  {'B':>12s}")
        click.echo(f"  {'Vendor':30s} {a.get('vendor_display', '?'):>12s}  {b.get('vendor_display', '?'):>12s}")
        click.echo(f"  {'=' * 56}")

        def _fmt(val):
            if val is None:
                return "?"
            if isinstance(val, float):
                return f"{val:.1f}"
            return str(val)

        click.echo(f"  {'Weighted Score':30s} {_fmt(a.get('weighted_score')):>12s}  {_fmt(b.get('weighted_score')):>12s}")
        click.echo(f"  {'Confidence':30s} {_fmt(a.get('confidence')):>12s}  {_fmt(b.get('confidence')):>12s}")
        click.echo(f"  {'Eval Count':30s} {_fmt(a.get('eval_count')):>12s}  {_fmt(b.get('eval_count')):>12s}")
        click.echo(f"  {'Category':30s} {_fmt(a.get('category')):>12s}  {_fmt(b.get('category')):>12s}")
        if a.get("price_range") or b.get("price_range"):
            click.echo(f"  {'Price Range':30s} {_fmt(a.get('price_range')):>12s}  {_fmt(b.get('price_range')):>12s}")
    click.echo()


# ── Benchmark (org benchmarking against peers) ──────────────────────────

@main.command()
@click.option("--vertical", required=True, help="Industry vertical")
@click.option("--org-size", default=None, help="Organization size range (e.g., 200-500)")
@click.option("--metric", default=None, help="Specific metric (budget, headcount, tools)")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def benchmark(vertical, org_size, metric, api_url, api_key, json_output):
    """How does your org compare to peers in your vertical?"""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    params = {"vertical": vertical}
    if org_size:
        params["org_size"] = org_size

    with httpx.Client(timeout=30) as http:
        resp = http.get(
            f"{api_url.rstrip('/')}/api/v1/benchmark",
            params=params,
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Benchmark: {data.get('vertical', vertical)}")
    click.echo(f"  {'=' * 50}")
    platform = data.get("platform", {})
    click.echo(f"  Total contributions:  {platform.get('total_contributions', 0)}")
    click.echo(f"  Unique vendors:       {platform.get('unique_vendors', 0)}")
    click.echo(f"  Unique techniques:    {platform.get('unique_techniques', 0)}")
    proof = data.get("proof", {})
    if proof.get("merkle_root"):
        click.echo(f"  Merkle root:          {proof['merkle_root'][:16]}...")
    click.echo()


# ── Remediation (what worked when peers got hit) ────────────────────────

@main.command()
@click.option("--threat", default=None, help="Threat name (e.g., lockbit, apt29)")
@click.option("--techniques", default=None, help="MITRE technique IDs (comma-separated)")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def remediation(threat, techniques, api_url, api_key, json_output):
    """What remediation worked when peers got hit by this threat?"""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    params = {}
    if threat:
        params["threat"] = threat
    if techniques:
        params["techniques"] = techniques

    with httpx.Client(timeout=30) as http:
        resp = http.get(
            f"{api_url.rstrip('/')}/api/v1/remediation",
            params=params,
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo("\n  Remediation Intelligence")
    click.echo(f"  {'=' * 50}")
    if data.get("threat"):
        click.echo(f"  Threat: {data['threat']}")
    click.echo(f"  Total attack reports: {data.get('total_attack_reports', 0)}")
    rem = data.get("remediation", {})
    by_cat = rem.get("by_category", {})
    if by_cat:
        click.echo("\n  By category:")
        for cat, effs in by_cat.items():
            total = sum(effs.values())
            click.echo(f"    {cat}: {total} actions")
    sev = rem.get("severity_distribution", {})
    if sev:
        click.echo("\n  Severity distribution:")
        for level, count in sev.items():
            click.echo(f"    {level}: {count}")
    techs = data.get("techniques")
    if techs:
        click.echo("\n  Techniques:")
        for t in techs:
            click.echo(f"    {t['technique_id']}: {t['frequency']}x observed")
    proof = data.get("proof", {})
    if proof.get("merkle_root"):
        click.echo(f"\n  Merkle root: {proof['merkle_root'][:16]}...")
    click.echo()


# ── Coverage (detection gap analysis) ───────────────────────────────────

@main.command()
@click.option("--tools", required=True, help="Your tools (comma-separated)")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def coverage(tools, api_url, api_key, json_output):
    """What are your detection gaps based on your tool stack?"""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(
            f"{api_url.rstrip('/')}/api/v1/coverage",
            params={"tools": tools},
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo("\n  Coverage Analysis")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Tools: {', '.join(data.get('tools', []))}")
    click.echo(f"  Total techniques: {data.get('total_techniques', 0)}")
    click.echo(f"  Covered: {data.get('covered', 0)}")
    click.echo(f"  Gaps: {data.get('gaps', 0)}")
    click.echo(f"  Coverage: {data.get('coverage_pct', 0)}%")
    gap_details = data.get("gap_details", [])
    if gap_details:
        click.echo("\n  Top detection gaps:")
        for g in gap_details[:10]:
            catchers = ", ".join(g.get("caught_by", [])[:3])
            click.echo(f"    {g['technique_id']}: {g.get('frequency', 0)}x observed — caught by: {catchers or 'none'}")
    proof = data.get("proof", {})
    if proof.get("merkle_root"):
        click.echo(f"\n  Merkle root: {proof['merkle_root'][:16]}...")
    click.echo()


# ── Match (IOC matching against collective) ─────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def match(file, api_url, api_key, json_output):
    """Check if your IOCs match known campaigns in the collective."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    contribs = load_file(file)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        from .keystore import get_or_create_keypair, sign_request
        _, priv_key = get_or_create_keypair()
    except Exception:
        priv_key = None

    all_matches = []
    for c in contribs:
        clean = anonymize(c)
        from .client import _serialize
        payload = _serialize(clean)

        if priv_key:
            body_bytes = json.dumps(payload, sort_keys=True).encode()
            headers["X-Signature"] = sign_request(body_bytes, priv_key)

        with httpx.Client(timeout=30) as http:
            resp = http.post(f"{api_url.rstrip('/')}/analyze", json=payload, headers=headers)

        if resp.status_code != 200:
            click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
            continue

        result = resp.json()
        intel = result.get("intelligence", {})
        match_result = {
            "contribution_id": result.get("contribution_id"),
            "campaign_match": intel.get("campaign_match", False),
            "shared_ioc_count": intel.get("shared_ioc_count", 0),
            "ioc_type_distribution": intel.get("ioc_type_distribution", {}),
            "coverage_score": intel.get("coverage_score"),
            "detection_gaps": intel.get("detection_gaps", []),
        }
        if result.get("receipt"):
            match_result["proof"] = {
                "commitment_hash": result["receipt"].get("commitment_hash"),
                "merkle_root": result["receipt"].get("merkle_root"),
            }
        all_matches.append(match_result)

    if json_output:
        click.echo(json.dumps({"matches": all_matches, "total": len(all_matches)}, indent=2))
        return

    click.echo("\n  IOC Match Results")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Files processed: {len(all_matches)}")
    for i, m in enumerate(all_matches, 1):
        click.echo(f"\n  Match {i}:")
        click.echo(f"    Campaign match: {'Yes' if m.get('campaign_match') else 'No'}")
        click.echo(f"    Shared IOCs: {m.get('shared_ioc_count', 0)}")
        ioc_dist = m.get("ioc_type_distribution", {})
        if ioc_dist:
            click.echo(f"    IOC types: {', '.join(f'{k}={v}' for k, v in ioc_dist.items())}")
        if m.get("coverage_score") is not None:
            click.echo(f"    Coverage: {int(m['coverage_score'] * 100)}%")
        gaps = m.get("detection_gaps", [])
        if gaps:
            click.echo(f"    Detection gaps: {len(gaps)}")
            for g in gaps[:5]:
                click.echo(f"      - {g.get('technique_id', '?')}")
    click.echo()


# ── Slack Integration ────────────────────────────────────────────────────

@main.command("integrate-slack")
@click.argument("webhook_url")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
def integrate_slack(webhook_url, api_url, api_key):
    """Connect Slack — get remediation alerts when webhooks fire."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url or not api_key:
        click.echo("  Run: nur init")
        return
    import httpx
    with httpx.Client(timeout=10) as http:
        resp = http.post(
            f"{api_url.rstrip('/')}/settings/slack",
            json={"webhook_url": webhook_url},
            headers={"X-API-Key": api_key},
        )
    if resp.status_code == 200:
        click.echo("  Slack notifications enabled!")
        click.echo("  When webhooks fire, you'll get remediation alerts in your channel.")
    else:
        click.echo(f"  Error: {resp.text[:200]}")


# ── Lab Data Seeder ─────────────────────────────────────────────────────

@main.command("seed-labs")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True)
def seed_labs(api_url, api_key, json_output):
    """Seed with MITRE ATT&CK Evals + AV-TEST lab data (public baseline)."""
    import asyncio

    from .feeds.mitre_evals import ingest_lab_data

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL. Run: nur init")
        return

    results = asyncio.run(ingest_lab_data(api_url, api_key))

    if json_output:
        click.echo(json.dumps(results, indent=2))
    else:
        click.echo("\n  Lab Data Seeder")
        click.echo(f"  {'=' * 35}")
        click.echo(f"  MITRE ATT&CK Evals: {results['mitre_ingested']} ingested")
        click.echo(f"  AV-TEST results:    {results['avtest_ingested']} ingested")
        click.echo(f"  Errors:             {results['errors']}")
        click.echo("\n  Lab baseline established. Practitioner evals build on top.")
