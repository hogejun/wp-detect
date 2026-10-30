"""Vulnerability/exposure checks.

Each check is a subclass of :class:`~wp_detect.checks.base.Check`. Checks are
read-only probes: they send benign requests and report observations.

Discovery:
  * Built-in checks (``detect``, ``headers``) are imported directly below.
  * Any other check is discovered from the ``wp_detect.checks`` entry-point
    group — a distribution exposes the check's module there, and importing it
    runs ``@register``. A failing entry point is fatal (never silently
    skipped: a missing check is a coverage gap).
"""

from __future__ import annotations

import importlib.metadata

from .base import Check, register, registry, validate_registry

# Importing the built-in modules registers their checks as a side effect.
from . import detect, headers  # noqa: E402,F401

# Load plugin / overlay checks from entry points, deterministically by name.
for _ep in sorted(
    importlib.metadata.entry_points(group="wp_detect.checks"),
    key=lambda e: (e.name, e.value),
):
    try:
        _ep.load()  # importing the module runs @register
    except Exception as exc:  # fail loud, naming the offending entry point
        raise RuntimeError(
            f"failed to load check entry point {_ep.name!r} ({_ep.value})"
        ) from exc

# Reject misconfigured dependency/order declarations before any scan runs.
validate_registry()

__all__ = ["Check", "register", "registry"]
