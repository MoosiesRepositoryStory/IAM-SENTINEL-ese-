"""IAM Sentinel command-line interface (the evolved ``iam_audit.py``).

Examples
--------
    iam-sentinel init-db
    iam-sentinel checks
    iam-sentinel scan --name "Acme" --inventory users.csv --policies pol.json --logs auth.log
    iam-sentinel export --run 1 --format json -o report.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from app.analysis import REGISTRY
from app.analysis.risk import posture_grade
from app.db import create_all, session_scope
from app.domain.records import Thresholds
from app.services import create_account, run_scan, run_to_csv, run_to_json


@click.group()
@click.version_option(package_name="iam-sentinel")
def cli() -> None:
    """IAM Sentinel — cloud IAM posture & entitlement analysis."""


@cli.command("init-db")
def init_db() -> None:
    """Create all database tables (dev/demo fast path; prod uses Alembic)."""
    create_all()
    click.secho("Database initialized.", fg="green")


@cli.command("checks")
def list_checks() -> None:
    """List every registered check in the rule registry."""
    click.echo(f"{len(REGISTRY)} checks registered:\n")
    for cid in sorted(REGISTRY):
        meta = REGISTRY[cid].meta
        click.echo(
            f"  {click.style(cid, fg='cyan'):<48} "
            f"{meta.default_severity.value:<9} {meta.category.value}"
        )


@cli.command("scan")
@click.option("--name", default="CLI Scan", help="Account name to create/scan.")
@click.option(
    "--source",
    type=click.Choice(["file", "moto_aws"]),
    default="file",
    show_default=True,
    help="Ingestion source: local files, or the simulated 'Acme Corp' moto AWS org.",
)
@click.option("--inventory", type=click.Path(exists=True), help="Users CSV path (file source).")
@click.option("--policies", type=click.Path(exists=True), help="Policies JSON path (file source).")
@click.option("--logs", type=click.Path(exists=True), help="Auth/CloudTrail log path (file source).")
@click.option("--inactivity-days", default=90, show_default=True)
@click.option("--password-age-days", default=90, show_default=True)
@click.option("--key-age-days", default=90, show_default=True)
@click.option("--failed-logins", default=5, show_default=True)
@click.option("-o", "--output", type=click.Path(), help="Write a JSON report to this path.")
def scan(
    name: str,
    source: str,
    inventory: str | None,
    policies: str | None,
    logs: str | None,
    inactivity_days: int,
    password_age_days: int,
    key_age_days: int,
    failed_logins: int,
    output: str | None,
) -> None:
    """Run a scan and print a findings summary.

    ``--source file`` (default) scans the CSV/JSON/log paths; ``--source moto_aws``
    scans a genuine-boto3 read of the simulated Acme org (no files needed).
    """
    if source == "file" and not any([inventory, policies, logs]):
        raise click.UsageError("Provide at least one of --inventory / --policies / --logs.")

    create_all()
    thresholds = Thresholds(
        inactivity_days=inactivity_days,
        password_age_days=password_age_days,
        key_age_days=key_age_days,
        failed_logins=failed_logins,
    )
    source_config: dict[str, object] = {**thresholds.to_dict()}
    if source == "file":
        source_config.update(
            inventory_path=inventory, policies_path=policies, logs_path=logs
        )

    with session_scope() as session:
        account = create_account(
            session, name=name, source_type=source, source_config=source_config
        )
        run = run_scan(session, account.id, thresholds=thresholds)
        run_id = run.id
        score = run.composite_score or 0
        summary = run.summary
        totals = {
            "total": summary.total_findings if summary else 0,
            "critical": summary.count_critical if summary else 0,
            "high": summary.count_high if summary else 0,
            "medium": summary.count_medium if summary else 0,
            "low": summary.count_low if summary else 0,
        }
        report = run_to_json(session, run_id) if output else None

    click.secho(f"\nScan complete — run #{run_id}", fg="green", bold=True)
    click.echo(
        f"  Posture score: {score}/100  (grade {posture_grade(score)})\n"
        f"  Findings: {totals['total']}  "
        f"[{click.style(str(totals['critical']) + ' critical', fg='red')}, "
        f"{click.style(str(totals['high']) + ' high', fg='yellow')}, "
        f"{totals['medium']} medium, {totals['low']} low]"
    )
    if output and report is not None:
        Path(output).write_text(report, encoding="utf-8")
        click.echo(f"  Report written to {output}")


@cli.command("export")
@click.option("--run", "run_id", type=int, required=True, help="Run id to export.")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@click.option("-o", "--output", type=click.Path(), help="Output file (default: stdout).")
def export(run_id: int, fmt: str, output: str | None) -> None:
    """Export a run's findings as JSON or CSV."""
    with session_scope() as session:
        content = run_to_json(session, run_id) if fmt == "json" else run_to_csv(session, run_id)
    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Wrote {fmt} to {output}")
    else:
        sys.stdout.write(content)


if __name__ == "__main__":
    cli()
