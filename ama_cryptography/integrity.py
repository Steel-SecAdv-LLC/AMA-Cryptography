#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Module Integrity Digest Management CLI
=======================================

Usage:
    python -m ama_cryptography.integrity --verify    # Verify integrity
    python -m ama_cryptography.integrity --show      # Show current digest

The --update subcommand is build-pipeline-only.  It regenerates the
integrity digest and (when invoked with ``--sign``) the signed
``_integrity_signature.py`` artefact.  Users running ``--update``
post-install would silently bypass the FIPS 140-3 §4.9.1 tamper-
detection contract: any local edit would be re-blessed by the user's
own machine and the next import would pass verification.

To prevent that, ``--update`` is gated behind the environment variable
``AMA_BUILD_PIPELINE=1``.  The wheel build (setup.py post-build hook /
CMake post-install step) sets the variable before invoking this CLI;
no other invocation should.  Users who actually want to live-modify
source after install must rebuild the wheel — that's the supported
flow for source modifications to a FIPS-validated module.

The signing pipeline lives in ``ama_cryptography._build_sign`` and is
invoked as ``--update --sign``; it uses the in-tree ``ama_ed25519_*``
C kernels via ctypes (INVARIANT-1: no PyCA dependency).
"""

import argparse
import os
import sys

from ama_cryptography._self_test import (
    _compute_module_digest,
    update_integrity_digest,
    verify_module_integrity,
)

_BUILD_PIPELINE_ENV = "AMA_BUILD_PIPELINE"


def _build_pipeline_active() -> bool:
    """Return True when the wheel build pipeline has marked itself active.

    The wheel build (setup.py post-build hook / CMake post-install step)
    sets ``AMA_BUILD_PIPELINE=1`` before invoking ``--update``.  Any other
    invocation (a user's interactive shell, a third-party orchestrator)
    must not be able to silently re-bless tampered sources.
    """
    return os.environ.get(_BUILD_PIPELINE_ENV) == "1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AMA Cryptography module integrity digest management"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--update",
        action="store_true",
        help=(
            "Regenerate the integrity digest after code changes "
            f"(build pipeline only — requires {_BUILD_PIPELINE_ENV}=1)"
        ),
    )
    group.add_argument(
        "--verify", action="store_true", help="Verify module integrity"
    )
    group.add_argument("--show", action="store_true", help="Show the current computed digest")
    parser.add_argument(
        "--sign",
        action="store_true",
        help=(
            "When combined with --update, also regenerate the signed "
            "integrity artefact (_integrity_signature.py) via the "
            "ama_cryptography._build_sign Ed25519 pipeline.  Requires "
            "the native library to be built.  Build pipeline only."
        ),
    )
    args = parser.parse_args()

    if args.update:
        if not _build_pipeline_active():
            print(
                f"ERROR: --update is build-pipeline-only.  Set {_BUILD_PIPELINE_ENV}=1 "
                "if you are the wheel build script; otherwise rebuild the wheel "
                "instead of mutating an installed module's integrity digest.",
                file=sys.stderr,
            )
            return 2
        if args.sign:
            # Delegate to _build_sign which handles digest + Ed25519
            # signing in one shot.  We control its argv here so the
            # caller does not need to know the inner CLI surface.
            import runpy

            saved_argv = sys.argv
            sys.argv = ["ama_cryptography._build_sign"]
            try:
                # Use runpy so __name__ == "__main__" inside _build_sign
                # and its sys.exit() path is honoured via the
                # SystemExit it raises.
                try:
                    runpy.run_module(
                        "ama_cryptography._build_sign", run_name="__main__"
                    )
                except SystemExit as exc:
                    return int(exc.code or 0)
            finally:
                sys.argv = saved_argv
            return 0
        digest = update_integrity_digest()
        print(f"Integrity digest updated: {digest}")
        return 0
    if args.verify:
        passed, detail = verify_module_integrity()
        if passed:
            print(f"Module integrity: OK ({detail})")
            return 0
        print(f"Module integrity: FAILED — {detail}", file=sys.stderr)
        return 1
    # --show
    print(_compute_module_digest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
