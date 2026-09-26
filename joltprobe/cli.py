from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from joltprobe import __version__
from joltprobe.checks import ALL_CHECKS, CATEGORIES, CHECK_BY_ID
from joltprobe.checks.base import CheckResult, Severity, Status
from joltprobe.connection import ScanConfig, ScanSession
from joltprobe.report.renderer import render_report

console = Console()

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_STATUS_STYLE = {
    Status.PASS: "green",
    Status.FAIL: "bold red",
    Status.ERROR: "bold yellow",
    Status.SKIP: "dim",
    Status.INCONCLUSIVE: "magenta",
}

_STATUS_ICON = {
    Status.PASS: "✓",
    Status.FAIL: "✗",
    Status.ERROR: "!",
    Status.SKIP: "–",
    Status.INCONCLUSIVE: "?",
}


@click.group()
@click.version_option(__version__, prog_name="joltprobe")
def cli() -> None:
    """JoltProbe — OCPP security assessment tool."""


# ──────────────────────────────────────────────────────────────
# scan command
# ──────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--charger-id", required=True, help="Charger ID to use for the scan session")
@click.option("--version", "ocpp_version", default="1.6", type=click.Choice(["1.6", "2.0.1"]), show_default=True, help="OCPP protocol version")
@click.option("--checks", "check_filter", default=None, help="Comma-separated check categories or IDs (e.g. tls,auth)")
@click.option("--security-profile", type=int, default=None, help="Declared security profile of the target (1–3)")
@click.option("--timeout", type=float, default=10.0, show_default=True, help="Per-check response timeout in seconds")
@click.option("--output", type=click.Path(), default=None, help="Save report to file (.json / .md / .html)")
@click.option("--enable-dos", is_flag=True, default=False, help="Enable DoS checks (requires written authorisation)")
@click.option("--username", default=None, help="HTTP Basic Auth username for the session")
@click.option("--password", default=None, help="HTTP Basic Auth password for the session")
@click.option("--credential-list", type=click.Path(exists=True), default=None, help="Path to credential list YAML for auth.default-credentials")
@click.option("--idtag-attempts", type=int, default=20, show_default=True, help="Maximum idTag probe attempts for auth.idtag-enumeration")
@click.option("--soap", "enable_soap", is_flag=True, default=False, help="Enable SOAP/XML injection check (injection.soap)")
@click.option("--id-tag", default=None, help="A valid idTag for checks that require an authorised transaction (e.g. session.concurrent-transactions)")
def scan(
    target: str,
    charger_id: str,
    ocpp_version: str,
    check_filter: Optional[str],
    security_profile: Optional[int],
    timeout: float,
    output: Optional[str],
    enable_dos: bool,
    username: Optional[str],
    password: Optional[str],
    credential_list: Optional[str],
    idtag_attempts: int,
    enable_soap: bool,
    id_tag: Optional[str],
) -> None:
    """Run a security scan against TARGET (e.g. ws://csms.example.com:9000/ocpp)."""
    asyncio.run(
        _run_scan(
            target=target,
            charger_id=charger_id,
            ocpp_version=ocpp_version,
            check_filter=check_filter,
            security_profile=security_profile,
            timeout=timeout,
            output=output,
            enable_dos=enable_dos,
            username=username,
            password=password,
            credential_list=credential_list,
            idtag_attempts=idtag_attempts,
            enable_soap=enable_soap,
            id_tag=id_tag,
        )
    )


async def _run_scan(
    *,
    target: str,
    charger_id: str,
    ocpp_version: str,
    check_filter: Optional[str],
    security_profile: Optional[int],
    timeout: float,
    output: Optional[str],
    enable_dos: bool,
    username: Optional[str],
    password: Optional[str],
    credential_list: Optional[str],
    idtag_attempts: int = 20,
    enable_soap: bool = False,
    id_tag: Optional[str] = None,
) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    console.print(Panel.fit(
        f"[bold]JoltProbe v{__version__}[/bold]\n"
        f"Target:    [cyan]{target}[/cyan]\n"
        f"Charger:   [cyan]{charger_id}[/cyan]\n"
        f"Protocol:  OCPP {ocpp_version}\n"
        f"Timestamp: {timestamp}",
        title="[bold blue]JoltProbe[/bold blue]",
        border_style="blue",
    ))

    if enable_dos:
        console.print("[bold yellow]⚠  DoS checks enabled — only run with written authorisation[/bold yellow]")

    if enable_soap:
        console.print("[bold yellow]⚠  SOAP injection enabled — ensure you have authorisation to test this endpoint[/bold yellow]")

    # Select checks
    selected_classes = _select_checks(check_filter, ocpp_version, enable_dos, enable_soap)
    if not selected_classes:
        console.print("[bold red]No checks selected. Use --checks or remove filters.[/bold red]")
        sys.exit(1)

    console.print(f"\nRunning [bold]{len(selected_classes)}[/bold] checks...\n")

    config = ScanConfig(
        target=target,
        charger_id=charger_id,
        version=ocpp_version,
        username=username,
        password=password,
        timeout=timeout,
        security_profile=security_profile,
        enable_dos=enable_dos,
        credential_list=credential_list,
        idtag_attempts=idtag_attempts,
        enable_soap=enable_soap,
        id_tag=id_tag,
    )
    session = ScanSession(config)

    # Run SHARED-mode checks first, then close the shared connection before
    # DEDICATED checks so that CSMS implementations that enforce one connection
    # per charger ID can accept the dedicated check connections.
    shared_checks = [c for c in selected_classes if c.connection_mode.value == "SHARED"]
    dedicated_checks = [c for c in selected_classes if c.connection_mode.value != "SHARED"]

    if shared_checks:
        setup_err = await session.setup()
        if setup_err:
            console.print(f"[yellow]⚠  Shared connection setup failed: {setup_err}[/yellow]")
            console.print("[dim]   Checks that require a shared connection will report ERROR.[/dim]\n")

    results: list[CheckResult] = []
    shared_closed = False
    try:
        for check_class in shared_checks + dedicated_checks:
            if not shared_closed and check_class not in shared_checks:
                await session.close_shared()
                shared_closed = True

            check = check_class(session)
            session.reset_transcripts()
            try:
                result = await check.run()
            except Exception as exc:
                result = check._error(f"Unhandled exception: {exc}")

            if not result.transcript:
                result.transcript = session.collect_transcript()
            results.append(result)
            _print_result_line(result)
    finally:
        await session.close()

    _print_summary(results)

    if output:
        meta = {
            "target": target,
            "charger_id": charger_id,
            "version": ocpp_version,
            "timestamp": timestamp,
            "security_profile": security_profile,
        }
        try:
            render_report(meta, results, output)
            console.print(f"\n[green]Report saved to:[/green] {output}")
        except Exception as e:
            console.print(f"\n[red]Failed to save report: {e}[/red]")

    # CI-friendly exit code: 1 if any findings at HIGH or above
    failures = [r for r in results if r.status == Status.FAIL and r.severity in (Severity.CRITICAL, Severity.HIGH)]
    if failures:
        sys.exit(1)


def _select_checks(
    check_filter: Optional[str],
    version: str,
    enable_dos: bool,
    enable_soap: bool = False,
) -> list[type]:
    if check_filter:
        tokens = [t.strip() for t in check_filter.split(",")]
        classes = []
        for token in tokens:
            if token in CATEGORIES:
                classes.extend(CATEGORIES[token])
            elif token in CHECK_BY_ID:
                classes.append(CHECK_BY_ID[token])
            else:
                console.print(f"[yellow]Unknown check or category: '{token}' (ignored)[/yellow]")
        selected = list(dict.fromkeys(classes))  # deduplicate, preserve order
    else:
        selected = list(ALL_CHECKS)

    # Filter by version
    selected = [c for c in selected if version in c.applies_to]

    # DoS checks are opt-in
    if not enable_dos:
        selected = [c for c in selected if not c.id.startswith("dos.")]

    # SOAP injection is opt-in
    if not enable_soap:
        selected = [c for c in selected if c.id != "injection.soap"]

    return selected


def _print_result_line(result: CheckResult) -> None:
    icon = _STATUS_ICON[result.status]
    status_style = _STATUS_STYLE[result.status]
    sev_style = _SEV_STYLE[result.severity]
    console.print(
        f"  [{status_style}]{icon}[/{status_style}] "
        f"[dim]{result.id:<38}[/dim] "
        f"[{sev_style}]{result.severity.value:<8}[/{sev_style}] "
        f"[{status_style}]{result.status.value}[/{status_style}]"
    )


def _print_summary(results: list[CheckResult]) -> None:
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    failures = [r for r in results if r.status == Status.FAIL]
    counts = {s: sum(1 for r in failures if r.severity.value == s) for s in severities}

    console.print()
    table = Table(title="Summary", box=box.ROUNDED, border_style="blue")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Checks run", str(len(results)))
    table.add_row("PASS", f"[green]{sum(1 for r in results if r.status == Status.PASS)}[/green]")
    table.add_row("FAIL", f"[bold red]{len(failures)}[/bold red]")
    table.add_row("SKIP", str(sum(1 for r in results if r.status == Status.SKIP)))
    table.add_row("ERROR", f"[yellow]{sum(1 for r in results if r.status == Status.ERROR)}[/yellow]")
    table.add_row("", "")
    for sev in severities:
        style = _SEV_STYLE.get(Severity(sev), "")
        table.add_row(sev, f"[{style}]{counts[sev]}[/{style}]")
    console.print(table)

    overall = next((s for s in severities if counts[s] > 0), "PASS")
    if overall == "PASS":
        console.print("\n[bold green]Overall Risk: PASS — No findings[/bold green]")
    else:
        style = _SEV_STYLE.get(Severity(overall), "bold")
        console.print(f"\n[{style}]Overall Risk: {overall}[/{style}]")

    if failures:
        console.print("\n[bold]Findings:[/bold]")
        for r in failures:
            sev_style = _SEV_STYLE[r.severity]
            console.print(
                f"  [{sev_style}]{r.severity.value:<8}[/{sev_style}]  "
                f"[bold]{r.id}[/bold] — {r.name}"
            )


# ──────────────────────────────────────────────────────────────
# checks subcommands
# ──────────────────────────────────────────────────────────────

@cli.group(name="checks")
def checks_group() -> None:
    """List and run individual checks."""


@checks_group.command(name="list")
@click.option("--category", default=None, help="Filter by category (tls, auth, session, downgrade, cert, firmware, message, billing, websocket, dos)")
def list_checks(category: Optional[str]) -> None:
    """List all available checks."""
    table = Table(title="Available Checks", box=box.ROUNDED, border_style="blue")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Applies To")
    table.add_column("CWE")
    table.add_column("Name")

    for check_class in ALL_CHECKS:
        cat = check_class.id.split(".")[0]
        if category and cat != category:
            continue
        sev_style = _SEV_STYLE.get(check_class.severity, "")
        table.add_row(
            check_class.id,
            f"[{sev_style}]{check_class.severity.value}[/{sev_style}]",
            cat,
            ", ".join(check_class.applies_to),
            ", ".join(check_class.cwe) or "—",
            check_class.name,
        )
    console.print(table)


@checks_group.command(name="run")
@click.argument("check_id")
@click.option("--target", required=True, help="OCPP endpoint URL")
@click.option("--charger-id", required=True, help="Charger ID")
@click.option("--version", "ocpp_version", default="1.6", type=click.Choice(["1.6", "2.0.1"]))
@click.option("--timeout", type=float, default=10.0)
@click.option("--security-profile", type=int, default=None)
@click.option("--username", default=None)
@click.option("--password", default=None)
def run_check(
    check_id: str,
    target: str,
    charger_id: str,
    ocpp_version: str,
    timeout: float,
    security_profile: Optional[int],
    username: Optional[str],
    password: Optional[str],
) -> None:
    """Run a single check by ID."""
    if check_id not in CHECK_BY_ID:
        console.print(f"[red]Unknown check ID: '{check_id}'[/red]")
        console.print(f"Run [cyan]joltprobe checks list[/cyan] to see available checks.")
        sys.exit(1)

    asyncio.run(
        _run_single_check(
            check_id=check_id,
            target=target,
            charger_id=charger_id,
            ocpp_version=ocpp_version,
            timeout=timeout,
            security_profile=security_profile,
            username=username,
            password=password,
        )
    )


async def _run_single_check(
    *,
    check_id: str,
    target: str,
    charger_id: str,
    ocpp_version: str,
    timeout: float,
    security_profile: Optional[int],
    username: Optional[str],
    password: Optional[str],
) -> None:
    check_class = CHECK_BY_ID[check_id]
    config = ScanConfig(
        target=target,
        charger_id=charger_id,
        version=ocpp_version,
        username=username,
        password=password,
        timeout=timeout,
        security_profile=security_profile,
        enable_dos=check_id.startswith("dos."),
        credential_list=None,
    )
    session = ScanSession(config)

    if check_class.connection_mode.value == "SHARED":
        err = await session.setup()
        if err:
            console.print(f"[yellow]Shared connection setup: {err}[/yellow]")

    check = check_class(session)
    session.reset_transcripts()
    try:
        result = await check.run()
    except Exception as exc:
        result = check._error(f"Unhandled exception: {exc}")

    # Collect the transcript before closing, since close() clears the connections.
    if not result.transcript:
        result.transcript = session.collect_transcript()
    await session.close()

    console.print()
    console.print(Panel.fit(
        f"[bold]{result.name}[/bold]  ([dim]{result.id}[/dim])\n\n"
        f"Severity:  [{_SEV_STYLE[result.severity]}]{result.severity.value}[/{_SEV_STYLE[result.severity]}]\n"
        f"Status:    [{_STATUS_STYLE[result.status]}]{result.status.value}[/{_STATUS_STYLE[result.status]}]\n\n"
        f"[bold]Description:[/bold] {result.description}\n\n"
        + (f"[bold]Evidence:[/bold]\n{json.dumps(result.evidence, indent=2)}\n\n" if result.evidence else "")
        + (f"[bold]Remediation:[/bold] {result.remediation}\n\n" if result.remediation else "")
        + (f"[bold]CWE:[/bold] {', '.join(result.cwe)}\n\n" if result.cwe else "")
        + (f"[bold]References:[/bold] {', '.join(result.references)}\n\n" if result.references else "")
        + (f"[bold]Transcript:[/bold] {len(result.transcript)} frame(s) recorded" if result.transcript else ""),
        title=f"[bold blue]Check Result[/bold blue]",
        border_style=_STATUS_STYLE[result.status].replace("bold ", ""),
    ))

    if result.status == Status.FAIL:
        sys.exit(1)
