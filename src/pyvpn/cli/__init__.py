"""CLI entry point. Placeholder from Phase 0; stream A owns the real commands."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from pyvpn import __version__


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pyvpn", description="Per-process policy routing")
    parser.add_argument("--version", action="version", version=f"pyvpn {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0
