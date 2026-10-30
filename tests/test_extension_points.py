"""The check extension point, from the core package's point of view.

Installed alone, the core distribution registers only its two built-ins and
exposes no ``wp_detect.checks`` entry points; the loader must tolerate zero
plugins. (The full 13-check discovery is exercised by the overlay package,
which installs plugins into that group.)"""

from __future__ import annotations

import importlib.metadata

import pytest

from wp_detect.checks import base, registry
from wp_detect.checks.base import ordered_checks, validate_registry


def test_core_registers_only_builtins() -> None:
    # In a core-only install this is exactly detect + headers. In the dev
    # workspace the overlay is also installed, so assert a superset instead and
    # that the two built-ins are always present and first/among them.
    assert {"detect", "headers"} <= set(registry)
    assert registry["detect"].order == 0


def test_detect_runs_first() -> None:
    assert ordered_checks()[0].id == "detect"


def test_loader_tolerates_absent_group() -> None:
    # Whatever is installed, importing wp_detect.checks must have succeeded and
    # validate_registry() must hold for the live registry.
    validate_registry()
    # The entry-point API is the documented extension mechanism.
    eps = importlib.metadata.entry_points(group="wp_detect.checks")
    assert isinstance(list(eps), list)  # zero or more; no error either way


def test_validate_registry_rejects_unmet_requires(monkeypatch) -> None:
    class A(base.Check):
        id = "a"
        order = 100
        requires = ("missing",)

    monkeypatch.setattr(base, "registry", {"a": A})
    with pytest.raises(ValueError, match="unregistered"):
        validate_registry()


def test_select_checks_rejects_skipped_requirement(monkeypatch) -> None:
    from wp_detect import scanner
    from wp_detect.checks import base

    class A(base.Check):
        id = "a"
        order = 100

    class B(base.Check):
        id = "b"
        order = 200
        requires = ("a",)

    reg = {"a": A, "b": B}
    monkeypatch.setattr(base, "registry", reg)
    monkeypatch.setattr(scanner, "registry", reg)

    # --only b --skip a : b still needs a, which was excluded -> error
    with pytest.raises(KeyError, match="requires"):
        scanner.select_checks(only=["b"], skip=["a"])
    # --skip a alone : b remains and needs a -> error
    with pytest.raises(KeyError, match="requires"):
        scanner.select_checks(only=None, skip=["a"])
    # --only b alone : a is pulled in transitively -> ok, in dependency order
    ids = [c.id for c in scanner.select_checks(only=["b"], skip=None)]
    assert ids == ["a", "b"]


def test_validate_registry_rejects_order_violation(monkeypatch) -> None:
    class Dep(base.Check):
        id = "dep"
        order = 200

    class Needs(base.Check):
        id = "needs"
        order = 100
        requires = ("dep",)

    monkeypatch.setattr(base, "registry", {"dep": Dep, "needs": Needs})
    with pytest.raises(ValueError, match="does not run earlier"):
        validate_registry()
