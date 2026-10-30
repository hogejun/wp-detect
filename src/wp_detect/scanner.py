"""Scan orchestration: run selected checks against one target."""

from __future__ import annotations

from typing import Iterable

from .checks import registry
from .checks.base import Check, ordered_checks
from .http import BudgetExceeded, Client
from .models import CheckResult, ScanResult


def select_checks(only: Iterable[str] | None, skip: Iterable[str] | None) -> list[type[Check]]:
    """Resolve the set of check classes to run.

    ``only`` restricts to the named ids (detection is always kept); ``skip``
    removes named ids. Unknown ids raise ``KeyError`` so typos surface early.
    """
    checks = ordered_checks()
    if only:
        wanted = set(only)
        unknown = wanted - set(registry)
        if unknown:
            raise KeyError(f"unknown check id(s): {', '.join(sorted(unknown))}")
        # Pull in each wanted check's requirements transitively (e.g. a matcher
        # that consumes a fingerprint check's output).
        frontier = list(wanted)
        while frontier:
            dep = registry[frontier.pop()]
            for req in dep.requires:
                if req not in wanted:
                    if req not in registry:
                        raise KeyError(f"check {dep.id!r} requires unknown check {req!r}")
                    wanted.add(req)
                    frontier.append(req)
        checks = [c for c in checks if c.id in wanted or c.id == "detect"]
    if skip:
        unknown = set(skip) - set(registry)
        if unknown:
            raise KeyError(f"unknown check id(s): {', '.join(sorted(unknown))}")
        # Never skip detection; later checks depend on it.
        checks = [c for c in checks if c.id not in skip or c.id == "detect"]

    # A check's requirements may have been excluded by --skip (or simply not
    # pulled in). Refuse rather than run a check with a missing dependency —
    # i.e. --skip removed a check that another selected check requires.
    selected = {c.id for c in checks}
    for c in checks:
        missing = [r for r in c.requires if r not in selected]
        if missing:
            raise KeyError(
                f"check {c.id!r} requires {', '.join(sorted(missing))}, "
                "which --only/--skip excluded"
            )
    return checks


def scan(
    client: Client,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
    on_check: "callable[[Check], None] | None" = None,
) -> ScanResult:
    """Run checks against the target behind ``client`` and collect results."""
    result = ScanResult(target=client.base_url)
    for cls in select_checks(only, skip):
        check = cls()
        if check.requires_wordpress and not result.is_wordpress:
            # Skip WP-specific checks on a non-WP target, but record why.
            result.results.append(
                CheckResult(
                    check.id,
                    ran=False,
                    status="skipped",
                    error="skipped: target is not WordPress",
                )
            )
            continue
        if on_check:
            on_check(check)
        try:
            result.results.append(check.run(client, result))
        except BudgetExceeded as exc:
            result.results.append(
                CheckResult(check.id, ran=False, status="failed", error=str(exc))
            )
            break  # no point continuing once the budget is gone
        except Exception as exc:
            if check.id == "detect":
                # Detection is foundational: if we cannot even fetch the
                # homepage (DNS/connection failure), the target is unreachable.
                # Propagate so the caller reports an error instead of silently
                # claiming "not WordPress".
                raise
            # Otherwise one bad check must not kill the whole scan.
            result.results.append(
                CheckResult(
                    check.id,
                    ran=False,
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return result
