"""wp-detect: benign, read-only detection of widely-known WordPress exposures.

This package probes a WordPress site for well-known, publicly documented
weaknesses using harmless requests. It is a *detector*: it never attempts to
exploit, authenticate, write, or disrupt. Use only against sites you own or are
explicitly authorized to test.
"""

from __future__ import annotations

__version__ = "0.1.0"


def main() -> None:
    """Console-script entry point (see ``[project.scripts]``)."""
    import sys

    from .cli import main as _main

    sys.exit(_main())
