#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Module Integrity Digest Management CLI
=======================================

Usage:
    python -m ama_cryptography.integrity --update    # Regenerate digest
    python -m ama_cryptography.integrity --verify    # Verify current digest
    python -m ama_cryptography.integrity --show      # Show current digest
"""

import argparse
import sys

from ama_cryptography._self_test import (
    _compute_module_digest,
    update_integrity_digest,
    verify_module_integrity,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMA Cryptography module integrity digest management"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--update", action="store_true", help="Regenerate the integrity digest after code changes"
    )
    group.add_argument(
        "--verify", action="store_true", help="Verify module integrity against stored digest"
    )
    group.add_argument("--show", action="store_true", help="Show the current computed digest")
    args = parser.parse_args()

    if args.update:
        digest = update_integrity_digest()
        print(f"Integrity digest updated: {digest}")
    elif args.verify:
        if verify_module_integrity():
            print("Module integrity: OK")
        else:
            print("Module integrity: FAILED", file=sys.stderr)
            sys.exit(1)
    elif args.show:
        print(_compute_module_digest())


if __name__ == "__main__":
    main()
