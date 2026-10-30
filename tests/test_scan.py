"""Integration tests: run the scanner against the mock servers.

The core package ships two checks — ``detect`` (is this WordPress, and which
version) and ``headers`` (security-relevant response headers / cookie flags)."""

from __future__ import annotations

import importlib.metadata

import pytest

from wp_detect.http import Client
from wp_detect.scanner import scan

# A plugin distribution adds checks by exposing them in the `wp_detect.checks`
# entry-point group; the core distribution declares none. So "is anything but
# the two built-ins installed?" is answered by whether that group is non-empty
# — without naming any particular plugin. The "core alone = exactly two checks"
# guarantee is asserted only where it holds: a core-only install (no plugins).
_PLUGINS_INSTALLED = bool(list(importlib.metadata.entry_points(group="wp_detect.checks")))
_core_only = pytest.mark.skipif(
    _PLUGINS_INSTALLED,
    reason="check plugins installed (e.g. the dev workspace); core-only guarantee is checked in a core-only install",
)


def _titles(result) -> list[str]:
    return [f.title for f in result.findings]


def test_detects_wordpress_and_version(wp_client: Client) -> None:
    result = scan(wp_client)
    assert result.is_wordpress is True
    assert result.version == "6.4.2"


def test_every_finding_has_a_stable_id(wp_client: Client) -> None:
    from wp_detect.report import to_dict

    d = to_dict(scan(wp_client))
    for ch in d["checks"]:
        for f in ch["findings"]:
            assert isinstance(f.get("id"), str) and f["id"], \
                f"{ch['check']}: {f.get('title')!r} has no id"


def test_core_builtins_present(wp_client: Client) -> None:
    result = scan(wp_client)
    assert {"detect", "headers"} <= {r.check for r in result.results}


@_core_only
def test_core_alone_registers_exactly_two(wp_client: Client) -> None:
    # Core distribution alone registers exactly the two built-ins.
    result = scan(wp_client)
    assert {r.check for r in result.results} == {"detect", "headers"}


def test_header_findings_fire(wp_client: Client) -> None:
    result = scan(wp_client)
    titles = " ".join(_titles(result))
    assert "X-Pingback" in titles
    assert "Cookie" in titles


def test_non_wordpress_skips_wp_checks(plain_url: str) -> None:
    with Client(plain_url, delay=0, verify_tls=False) as client:
        result = scan(client)
    assert result.is_wordpress is False
    skipped = {r.check for r in result.results if not r.ran}
    assert "headers" in skipped
    assert "detect" not in skipped


@_core_only
def test_list_checks_shows_only_core(capsys) -> None:
    from wp_detect.cli import main as cli_main

    assert cli_main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    # Each listed check is "<id> — <description>"; the id set is exactly the
    # two built-ins (no need to name what must be absent).
    ids = {line.split("—", 1)[0].strip() for line in out.splitlines() if "—" in line}
    assert ids == {"detect", "headers"}


def test_help_description_matches_core_scope() -> None:
    from wp_detect.cli import build_parser

    desc = build_parser().description.lower()
    # accurate for the core scope...
    assert "header" in desc
    assert "wordpress" in desc
    # ...and not overclaiming a general vulnerability scanner
    assert "vulnerabilities and exposures" not in desc


def test_unreachable_target_errors_not_silent() -> None:
    from wp_detect.cli import main as cli_main

    code = cli_main(["https://nope.invalid", "--max-requests", "3", "--timeout", "3"])
    assert code != 0


def test_scanner_propagates_detect_connection_error() -> None:
    import pytest as _pytest

    from wp_detect.scanner import scan as run_scan

    with Client("https://nope.invalid", delay=0, timeout=3, max_requests=3) as c:
        with _pytest.raises(Exception):
            run_scan(c)
