"""CLI: oombra upload <file>"""
from __future__ import annotations
import click
from . import pipeline, load_file, anonymize, render
from .models import ContribContext, Industry, OrgSize, Role


@click.group()
def main():
    """oombra — privacy-preserving threat intelligence contribution tool."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", required=True, envvar="OOMBRA_API_URL", help="Target platform URL")
@click.option("--api-key", default=None, envvar="OOMBRA_API_KEY")
@click.option("--industry", type=click.Choice([i.value for i in Industry]), default=None)
@click.option("--org-size", type=click.Choice([s.value for s in OrgSize]), default=None)
@click.option("--role", type=click.Choice([r.value for r in Role]), default=None)
@click.option("--yes", is_flag=True, help="Skip review prompt (non-interactive)")
def upload(file, api_url, api_key, industry, org_size, role, yes):
    """Extract, anonymize, review, and submit a contribution file."""
    ctx = ContribContext(
        industry=Industry(industry) if industry else None,
        org_size=OrgSize(org_size) if org_size else None,
        role=Role(role) if role else None,
    )
    results = pipeline(file, api_url=api_url, context=ctx, api_key=api_key, auto_approve=yes)
    ok = sum(1 for r in results if r.success)
    click.echo(f"\n  {ok}/{len(results)} contributions submitted.")


@main.command()
@click.argument("file", type=click.Path(exists=True))
def preview(file):
    """Preview what would be sent without submitting anything."""
    contribs = load_file(file)
    for c in contribs:
        click.echo(render(anonymize(c)))
