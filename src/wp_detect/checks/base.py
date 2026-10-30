"""Check base class, registry, and the plugin extension contract.

A check is discovered either as a built-in (imported by :mod:`wp_detect.checks`)
or as a plugin: a distribution exposes the check's module in the
``wp_detect.checks`` entry-point group, and importing it runs ``@register``.
This module — together with :mod:`wp_detect.models` and ``wp_detect.http.Client``
— is the stable plugin API (the 0.x contract may still evolve).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import CheckResult

if TYPE_CHECKING:
    import argparse

    from ..http import Client
    from ..models import ScanResult


class Check:
    """Base class for all checks.

    Subclasses set ``id``, ``name`` and ``description`` and implement
    :meth:`run`. ``requires_wordpress`` lets the scanner skip a check when the
    target was not identified as WordPress.

    Ordering/plugin contract:
        order: Run order; lower runs earlier. ``detect`` is 0 (others depend on
            its WordPress/version facts); leave the default unless ordering
            matters. A check that consumes another's output runs later (e.g.
            200).
        requires: Ids of checks whose output this one consumes. When a run is
            narrowed with ``--only``, requirements are pulled in transitively.
            Each required check must be registered and run earlier (lower
            ``order``); this is validated at startup.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    requires_wordpress: bool = True
    order: int = 100
    requires: tuple[str, ...] = ()

    @classmethod
    def add_arguments(cls, parser: "argparse.ArgumentParser") -> None:
        """Hook: register this check's own CLI options. Default: no-op.

        Plugins should namespace their flags (e.g. by check id) to avoid
        collisions with other checks.
        """

    @classmethod
    def configure(cls, args: "argparse.Namespace") -> None:
        """Hook: receive the parsed CLI args once, before scanning. Default:
        no-op."""

    def run(self, client: "Client", scan: "ScanResult") -> CheckResult:
        """Probe the target and return a :class:`CheckResult`.

        ``scan`` is the in-progress result, so a check can read facts gathered
        by earlier checks (e.g. the detected version).
        """
        raise NotImplementedError


# -- registry ------------------------------------------------------------
registry: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    """Class decorator that adds a check to the global registry."""
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define an id")
    if cls.id in registry:
        raise ValueError(f"duplicate check id: {cls.id}")
    registry[cls.id] = cls
    return cls


def ordered_checks() -> list[type[Check]]:
    """Registered checks in a stable run order: ascending ``(order, id)``.
    ``detect`` (order 0) runs first; ties break by id."""
    return sorted(registry.values(), key=lambda c: (c.order, c.id))


def validate_registry() -> None:
    """Fail loudly if any check's ``requires`` are unmet: a requirement must be
    registered and run earlier (strictly lower ``order``). Called once after
    all checks are registered (built-ins + entry-point plugins)."""
    for c in registry.values():
        for req in c.requires:
            dep = registry.get(req)
            if dep is None:
                raise ValueError(f"check {c.id!r} requires unregistered check {req!r}")
            if dep.order >= c.order:
                raise ValueError(
                    f"check {c.id!r} (order {c.order}) requires {req!r} "
                    f"(order {dep.order}) which does not run earlier"
                )
