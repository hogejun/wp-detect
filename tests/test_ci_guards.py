"""Tests for the public repository's CI guard scripts (forbidden-scan /
commit-lint). They subprocess bash + git over throwaway trees/repos, so they
run the real scripts rather than re-implementing their logic.

Example forbidden terms live in scripts/ci/forbidden-samples.txt (a data file
the scan deliberately excludes), so this test's own source carries no forbidden
literal — otherwise forbidden-scan would flag this file."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

_CI = Path(__file__).resolve().parent.parent / "scripts" / "ci"
SCAN = _CI / "forbidden-scan.sh"
LINT = _CI / "commit-lint.sh"
_SAMPLES = [s for s in (_CI / "forbidden-samples.txt").read_text().splitlines() if s.strip()]

ALLOWED_NAME = "hogejun"
ALLOWED_EMAIL = "7918106+hogejun@users.noreply.github.com"


def _run(script: Path, cwd: Path, env_extra: dict | None = None) -> int:
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(["bash", str(script)], cwd=cwd, env=env,
                          capture_output=True, text=True).returncode


# -- forbidden-scan ------------------------------------------------------

def test_scan_clean_tree_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("a perfectly ordinary file\n")
    assert _run(SCAN, tmp_path) == 0


@pytest.mark.parametrize("term", _SAMPLES)
def test_scan_detects_forbidden_term(tmp_path: Path, term: str) -> None:
    (tmp_path / "bad.md").write_text(f"mentions {term} somewhere\n")
    assert _run(SCAN, tmp_path) == 1


# -- commit-lint ---------------------------------------------------------

def _git(repo: Path, *args: str, **env_extra: str) -> None:
    env = {**os.environ, **env_extra}
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env,
                   capture_output=True, text=True)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    return repo


def _commit(repo: Path, msg: str, name: str, email: str) -> None:
    (repo / "f").write_text(os.urandom(4).hex())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg,
         GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
         GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)


def _lint(repo: Path) -> int:
    return _run(LINT, repo, {"RANGE": "HEAD"})


def test_lint_accepts_allowed_identity(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, "initial commit", ALLOWED_NAME, ALLOWED_EMAIL)
    assert _lint(repo) == 0


def test_lint_rejects_other_identity(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, "a change", "Other Person", "other@example.org")
    assert _lint(repo) == 1


def test_lint_rejects_coauthor_trailer(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, "a change\n\nCo-authored-by: Someone <s@example.org>",
            ALLOWED_NAME, ALLOWED_EMAIL)
    assert _lint(repo) == 1


def test_lint_rejects_signed_off_trailer(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, f"a change\n\nSigned-off-by: hogejun <{ALLOWED_EMAIL}>",
            ALLOWED_NAME, ALLOWED_EMAIL)
    assert _lint(repo) == 1


def test_lint_rejects_forbidden_term_in_message(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, f"fix the {_SAMPLES[0]} matcher", ALLOWED_NAME, ALLOWED_EMAIL)
    assert _lint(repo) == 1


def test_lint_fails_closed_on_bad_range(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, "initial commit", ALLOWED_NAME, ALLOWED_EMAIL)
    assert _run(LINT, repo, {"RANGE": "deadbeefdeadbeef..HEAD"}) == 2


def test_lint_requires_a_range(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _commit(repo, "initial commit", ALLOWED_NAME, ALLOWED_EMAIL)
    assert _run(LINT, repo) == 2  # no RANGE / BASE_SHA / HEAD_SHA
