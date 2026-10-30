"""Render scan results as a terminal table or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def to_dict(scan: ScanResult) -> dict:
    """Structured view of a scan result (used for the JSON output)."""
    return {
        # Output schema version. Bumped to 2 when findings gained a stable
        # ``id`` and components became keyed by (kind, slug).
        "schema_version": 2,
        "target": scan.target,
        "is_wordpress": scan.is_wordpress,
        "version": scan.version,
        # Completeness of this scan: "complete" | "partial" | "failed". A
        # downstream consumer must not treat a partial/failed scan as a
        # trustworthy baseline. ``failed_checks`` names the checks that did not
        # complete (a conditional non-WordPress skip is not one of them).
        "scan_status": scan.scan_status,
        "failed_checks": scan.failed_checks,
        "summary": _counts(scan),
        "components": [
            {"kind": c.kind, "slug": c.slug, "version": c.version}
            for c in scan.components
        ],
        "checks": [
            {
                "check": r.check,
                "ran": r.ran,
                "status": r.status,
                "error": r.error,
                "incomplete_reasons": r.incomplete_reasons,
                "findings": [asdict(f) | {"severity": f.severity.label} for f in r.findings],
            }
            for r in scan.results
        ],
    }


def to_json(scan: ScanResult) -> str:
    """Serialize a full scan result (including skipped checks) to JSON."""
    return json.dumps(to_dict(scan), indent=2, ensure_ascii=False)


def _counts(scan: ScanResult) -> dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    for f in scan.findings:
        counts[f.severity.label] += 1
    return counts


def render(scan: ScanResult, console: Console | None = None) -> None:
    """Print a human-readable report to the terminal."""
    console = console or Console()

    header = f"[bold]{scan.target}[/bold]\n"
    if scan.is_wordpress:
        header += "WordPress: [green]detected[/green]"
        header += f"   version: [bold]{scan.version or 'unknown'}[/bold]"
    else:
        header += "WordPress: [red]not detected[/red]"
    console.print(Panel(header, title="wp-detect", expand=False))

    findings = scan.sorted_findings()
    if not findings:
        console.print("[dim]No findings.[/dim]")
    else:
        table = Table(show_lines=False, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Check", no_wrap=True, style="dim")
        table.add_column("Finding")
        table.add_column("Evidence", style="dim")
        for f in findings:
            style = _SEVERITY_STYLE[f.severity]
            table.add_row(
                f"[{style}]{f.severity.label}[/{style}]",
                f.check,
                f.title,
                f.evidence,
            )
        console.print(table)

    # Note any checks that did not run.
    skipped = [r for r in scan.results if not r.ran]
    if skipped:
        console.print("\n[dim]Checks not run:[/dim]")
        for r in skipped:
            console.print(f"  [dim]- {r.check}: {r.error}[/dim]")

    counts = _counts(scan)
    summary = "  ".join(
        f"[{_SEVERITY_STYLE[s]}]{s.label}: {counts[s.label]}[/{_SEVERITY_STYLE[s]}]"
        for s in sorted(Severity, reverse=True)
    )
    console.print(f"\nSummary: {summary}")
