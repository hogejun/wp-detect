"""Identify whether the target runs WordPress and, if so, its version.

All signals here come from normal, publicly served resources (the homepage,
``readme.html``, the RSS feed, the REST root). Nothing probed here is
sensitive on its own, but a precisely known core version is the pivot for
matching against public advisories, so we surface it.
"""

from __future__ import annotations

import re

from ..http import BudgetExceeded
from ..models import CheckResult, Finding, Severity
from .base import Check, register

_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)?',
    re.IGNORECASE,
)
_FEED_GENERATOR = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>",
    re.IGNORECASE,
)
# A run of "insignificant" characters between tokens: whitespace, HTML entities
# and tags. Lets us span the markup that readme.html puts around its version,
# while never crossing ordinary words (so it can't jump across prose).
_VERSION_GAP = r"(?:\s|&nbsp;|&#0*160;|<[^>]+>)+"

# Match the core version from the readme *logo* heading specifically:
#
#     <a href="https://wordpress.org/">WordPress</a>
#     <br /> Version 6.4
#
# Anchoring on the "WordPress ... Version N.N" shape avoids false positives from
# unrelated lines such as "PHP version 7.4 or greater" further down the file.
_README_VERSION = re.compile(
    rf"WordPress{_VERSION_GAP}Version{_VERSION_GAP}([0-9]+(?:\.[0-9]+){{1,2}})",
    re.IGNORECASE,
)

# Markers that strongly imply WordPress even without a version string.
_WP_MARKERS = (
    "/wp-content/",
    "/wp-includes/",
    "wp-json",
    "wp-emoji-release.min.js",
)


@register
class DetectCheck(Check):
    id = "detect"
    name = "WordPress detection"
    description = "Fingerprint WordPress and extract the core version."
    requires_wordpress = False
    order = 0  # foundational: must run before every other check

    def run(self, client, scan) -> CheckResult:  # type: ignore[no-untyped-def]
        result = CheckResult(self.id)
        markers: list[str] = []
        version: str | None = None

        # 1. Homepage: meta generator + path markers.
        home = client.get("/")
        for m in _WP_MARKERS:
            if m in home.text:
                markers.append(m)
        gen = _META_GENERATOR.search(home.text)
        if gen:
            markers.append("meta generator")
            if gen.group(1):
                version = gen.group(1)

        # Secondary probes are best-effort: a single flaky endpoint must not
        # abort detection once the homepage has been fetched. (The homepage GET
        # above is intentionally unguarded — if that fails the target is
        # unreachable and the scanner treats it as fatal.)
        #
        # But a failed probe is NOT "no result": it is recorded so the scan is
        # reported as partial rather than silently complete. BudgetExceeded is
        # re-raised so the scanner stops and marks detection failed; everything
        # else (off-origin/redirect refusals, timeouts, transport errors) is
        # noted — by path + exception type only, never a raw URL/message — and
        # treated as a missing signal.
        probe_failures: list[str] = []

        def _try_get(path):  # type: ignore[no-untyped-def]
            try:
                return client.get(path)
            except BudgetExceeded:
                raise
            except Exception as exc:
                probe_failures.append(f"{path}: {type(exc).__name__}")
                return None

        # 2. REST API root is a reliable modern marker.
        rest = _try_get("/wp-json/")
        if rest and rest.status == 200 and ("rest_route" in rest.text or '"namespaces"' in rest.text):
            markers.append("/wp-json/ REST root")

        # 3. readme.html often reveals the exact version.
        if version is None:
            readme = _try_get("/readme.html")
            if readme and readme.status == 200 and "WordPress" in readme.text:
                markers.append("readme.html")
                rm = _README_VERSION.search(readme.text)
                if rm:
                    version = rm.group(1)

        # 4. RSS feed generator tag as a fallback for the version.
        if version is None:
            feed = _try_get("/feed/")
            if feed:
                fm = _FEED_GENERATOR.search(feed.text)
                if fm:
                    markers.append("RSS feed generator")
                    version = fm.group(1)

        scan.is_wordpress = bool(markers)
        scan.version = version

        # Any best-effort probe that did not complete makes this check partial,
        # even if WordPress was still identified from the homepage — the scan
        # must not read as fully complete.
        if probe_failures:
            result.status = "partial"
            result.incomplete_reasons = probe_failures

        if not scan.is_wordpress:
            result.findings.append(
                Finding(
                    check=self.id,
                    id="detect:not-wordpress",
                    title="WordPress not detected",
                    severity=Severity.INFO,
                    detail="No WordPress markers were found on the target.",
                    evidence=f"homepage status {home.status}",
                )
            )
            return result

        result.findings.append(
            Finding(
                check=self.id,
                id="detect:wordpress",
                title="WordPress detected",
                severity=Severity.INFO,
                detail="Target appears to be running WordPress.",
                evidence="markers: " + ", ".join(dict.fromkeys(markers)),
            )
        )
        if version:
            result.findings.append(
                Finding(
                    check=self.id,
                    id="detect:version",
                    title=f"WordPress version disclosed: {version}",
                    severity=Severity.LOW,
                    detail=(
                        "The exact core version is publicly visible. This lets "
                        "anyone map the site to known advisories for that release."
                    ),
                    evidence=f"version={version}",
                    remediation=(
                        "Remove the generator meta/feed tags and restrict access "
                        "to readme.html; keep core updated regardless."
                    ),
                )
            )
        return result
