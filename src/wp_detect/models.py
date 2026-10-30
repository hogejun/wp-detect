"""Core data models shared across the scanner.

These types describe *findings*, not exploits. Every check in this package is
read-only: it sends a benign request and reports what it observes. Nothing here
mutates the target site.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Relative severity of a finding.

    Ordered so results can be sorted highest-first with ``reverse=True``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass(slots=True)
class Finding:
    """A single observation produced by a check.

    Attributes:
        check: Machine-readable id of the check that produced this.
        title: Short human-readable summary.
        severity: How much this matters, from an exposure standpoint.
        detail: Longer explanation of what was observed.
        evidence: Concrete proof (a URL, a header value, a snippet).
        remediation: Optional hint on how to address the exposure.
        id: Stable semantic identity for change tracking — built from the
            check id plus the resource/vulnerability it concerns (never the
            title, severity, evidence text or a timestamp, which change). A
            downstream consumer can key findings by this so a reworded title or
            a changed count is not mistaken for a new/resolved finding. ``None``
            falls back to ``(check, title)``; it is the last field so existing
            positional/keyword construction is unaffected.
    """

    check: str
    title: str
    severity: Severity
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    id: str | None = None


@dataclass(slots=True)
class CheckResult:
    """Outcome of running one check against a target.

    ``status`` is an explicit outcome code so completeness never has to be
    inferred from the free-text ``error`` string:
        "ok"      — the check ran fully.
        "skipped" — intentionally not run for a benign reason (e.g. a
                    WordPress-only check against a non-WordPress target).
        "partial" — the check produced a result but some best-effort probe did
                    not complete (``ran`` stays True); ``incomplete_reasons``
                    records what failed. This must NOT count as complete.
        "failed"  — the check could not complete at all (exception, connection
                    failure, or the request budget ran out); ``ran`` is False.

    ``incomplete_reasons`` holds short, secret-free notes (path + exception
    type, never a raw URL or message) about probes that did not complete.
    """

    check: str
    ran: bool = True
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)
    status: str = "ok"
    incomplete_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Component:
    """An installed plugin or theme discovered during a scan."""

    kind: str  # "plugin" | "theme"
    slug: str
    version: str | None = None


@dataclass(slots=True)
class ScanResult:
    """Aggregate result for a whole scan of one target."""

    target: str
    is_wordpress: bool = False
    version: str | None = None
    results: list[CheckResult] = field(default_factory=list)
    # Populated by the components check; consumed by the known-vulns matcher.
    components: list[Component] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    @property
    def failed_checks(self) -> list[str]:
        """Checks that did not complete for a non-benign reason.

        A WordPress-only check skipped on a non-WordPress target is *not*
        failed — that is an expected, conditional skip. A "partial" check
        (it ran but a best-effort probe failed) counts as not fully complete.
        """
        return [
            r.check
            for r in self.results
            if (not r.ran or r.status in ("failed", "partial")) and r.status != "skipped"
        ]

    @property
    def scan_status(self) -> str:
        """Overall completeness: ``"complete"``, ``"partial"`` or ``"failed"``.

        ``"failed"`` when the foundational detection check itself did not run
        (we cannot trust anything else); ``"partial"`` when some other check
        did not complete; ``"complete"`` when every check either ran or was
        intentionally skipped.
        """
        detect = next((r for r in self.results if r.check == "detect"), None)
        if detect is None or not detect.ran:
            return "failed"
        return "partial" if self.failed_checks else "complete"
