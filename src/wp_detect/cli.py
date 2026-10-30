"""Command-line interface for wp-detect."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from . import __version__
from .checks import registry  # noqa: F401 — imported for its registration side effect
from .checks.base import ordered_checks
from .http import Client, normalize_target, safe_display
from .report import render, to_json
from .scanner import scan

_AUTH_NOTICE = (
    "wp-detect performs read-only, benign detection only. "
    "Scan sites you own or are explicitly authorized to test."
)


def _normalize_target(raw: str) -> str:
    """Validate/normalize the scan target (scheme defaults to https). Rejects
    credentials, query/fragment and control characters; errors never echo the
    raw URL (it may hold a secret)."""
    return normalize_target(raw)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp-detect",
        description=(
            "Benign, read-only probes to identify WordPress and its version and "
            "inspect security-relevant HTTP response headers. Further checks can "
            "be added as plugins (see --list-checks)."
        ),
        epilog=_AUTH_NOTICE,
    )
    p.add_argument(
        "target",
        nargs="?",
        help="Site URL or host (e.g. https://example.com). The scheme is "
        "optional and defaults to https; a query string or fragment (even an "
        "empty '?'/'#') is rejected.",
    )
    p.add_argument("--version", action="version", version=f"wp-detect {__version__}")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    p.add_argument(
        "--list-checks", action="store_true", help="List available checks and exit"
    )
    p.add_argument(
        "--only",
        metavar="IDS",
        help="Comma-separated check ids to run (detection always runs)",
    )
    p.add_argument(
        "--skip", metavar="IDS", help="Comma-separated check ids to skip"
    )
    net = p.add_argument_group("network")
    net.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s)")
    net.add_argument(
        "--delay", type=float, default=0.3, help="Delay between requests (s), be polite"
    )
    net.add_argument(
        "--max-requests", type=int, default=200, help="Hard cap on total requests"
    )
    net.add_argument(
        "--insecure", action="store_true", help="Do not verify TLS certificates"
    )
    net.add_argument(
        "--user-agent",
        default=None,
        metavar="UA",
        help="Override the User-Agent: an alias (chrome/firefox/safari/edge/iphone/android) or a full string",
    )
    # Let each check contribute its own CLI options.
    for cls in ordered_checks():
        cls.add_arguments(p)
    return p


def _split_ids(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    err = Console(stderr=True)

    if args.list_checks:
        for cls in ordered_checks():
            console.print(f"[bold]{cls.id}[/bold] — {cls.description}")
        return 0

    if not args.target:
        parser.print_usage(sys.stderr)
        err.print("[red]error:[/red] a target is required")
        return 2

    try:
        target = _normalize_target(args.target)
    except ValueError as exc:
        err.print(f"[red]error:[/red] {exc}")
        return 2

    # Hand parsed args to each check that wants configuration.
    for cls in ordered_checks():
        cls.configure(args)

    from .http import resolve_user_agent

    ua = resolve_user_agent(args.user_agent)
    ua_kwargs = {"user_agent": ua} if ua else {}
    try:
        with Client(
            target,
            timeout=args.timeout,
            delay=args.delay,
            max_requests=args.max_requests,
            verify_tls=not args.insecure,
            **ua_kwargs,
        ) as client:
            if not args.json:
                err.print(f"[dim]{_AUTH_NOTICE}[/dim]")
                err.print(f"[dim]Scanning {target} ...[/dim]")
            result = scan(
                client,
                only=_split_ids(args.only),
                skip=_split_ids(args.skip),
                on_check=(
                    None
                    if args.json
                    else (lambda c: err.print(f"[dim]  running {c.id} ...[/dim]"))
                ),
            )
    except KeyError as exc:
        err.print(f"[red]error:[/red] {exc}")
        return 2
    except Exception as exc:  # network/connection failures
        err.print(f"[red]error:[/red] could not scan {safe_display(target)}: {type(exc).__name__}")
        return 1

    if args.json:
        print(to_json(result))
    else:
        render(result, console)

    # Exit non-zero when anything above INFO was found, for CI use.
    from .models import Severity

    worst = max((f.severity for f in result.findings), default=Severity.INFO)
    return 1 if worst >= Severity.MEDIUM else 0
