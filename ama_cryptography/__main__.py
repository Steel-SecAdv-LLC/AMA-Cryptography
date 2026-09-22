# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point: ``python -m ama_cryptography`` runs the demonstration."""

import argparse
import sys

from ama_cryptography.legacy_compat import main


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    """Accept no positional arguments; ``--help`` prints usage and exits.

    Before this parser existed every argument was ignored and the full
    demonstration ran, so ``python -m ama_cryptography --help`` produced a
    verification transcript instead of usage.
    """
    parser = argparse.ArgumentParser(
        prog="python -m ama_cryptography",
        description=(
            "Run the AMA Cryptography demonstration: generate a key-management "
            "system, create a signed and encrypted package, and verify it. The "
            "exit code is the verification verdict."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    _parse_args()
    # main() returns the demonstration's verdict as an exit code: a real
    # verification failure must exit non-zero, not print "FAILED" and exit 0.
    sys.exit(main())
