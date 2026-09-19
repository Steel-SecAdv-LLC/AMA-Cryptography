#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Emit ``-DAMA_IC_HAVE_<FEATURE>=0`` for primitives a library does not export.

``benchmarks/ic_driver.c`` is ONE source compiled against TWO libraries by the
A/B lane in ``ci-build-test.yml``: the head build and the merge-base build. A
base commit that predates a primitive does not export it, and the link fails
outright — measured, ``main`` at 2dcef5c has no ``ama_sha512``, which this
branch added, so without this the base driver does not build and the entire
A/B comparison is dead on arrival.

Everything defaults to present in the driver, so a normal build needs no flags
at all. A primitive is opted OUT explicitly, from evidence read out of the
library with ``nm``, rather than being silently skipped.

The gate then compares the INTERSECTION: a primitive that exists only on the
head has nothing to be compared against, which is correct — it is new, and its
first measurement is its baseline.

Usage:  ic_symbol_flags.py <library.a|library.so>
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

#: feature -> the exported symbol whose presence decides it.  One
#: representative symbol per feature: the driver guards a whole primitive at a
#: time, and a library exporting half a primitive is a different defect.
FEATURE_SYMBOLS: dict[str, str] = {
    "SHA3_256": "ama_sha3_256",
    "SHA3_512": "ama_sha3_512",
    "SHA512": "ama_sha512",
    "HMAC_SHA3_256": "ama_hmac_sha3_256",
    "HKDF": "ama_hkdf",
    "ED25519": "ama_ed25519_sign",
    "X25519": "ama_x25519_key_exchange",
    "AES_GCM": "ama_aes256_gcm_encrypt",
    "CHACHA": "ama_chacha20poly1305_encrypt",
    "SECP256K1": "ama_secp256k1_ecdsa_sign",
    "KYBER": "ama_kyber_encapsulate",
    "DILITHIUM": "ama_dilithium_sign",
}


def exported_symbols(library: Path) -> set[str]:
    """Every global text symbol the library defines."""
    if shutil.which("nm") is None:
        raise RuntimeError("nm is not installed; cannot probe the library")
    completed = subprocess.run(
        ["nm", "--defined-only", "-g", str(library)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"nm failed on {library}: {completed.stderr.strip()}")
    symbols: set[str] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        # "<addr> T <name>" for a defined text symbol; archive member headers
        # and undefined entries have a different shape.
        if len(parts) >= 3 and parts[-2] in {"T", "t", "W", "D"}:
            symbols.add(parts[-1])
    return symbols


def missing_features(library: Path) -> list[str]:
    present = exported_symbols(library)
    return sorted(feature for feature, symbol in FEATURE_SYMBOLS.items() if symbol not in present)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args = parser.parse_args(argv)

    if not args.library.is_file():
        print(f"FATAL: {args.library} does not exist.", file=sys.stderr)
        return 2

    try:
        absent = missing_features(args.library)
    except RuntimeError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    present_count = len(FEATURE_SYMBOLS) - len(absent)
    if present_count == 0:
        print(
            f"FATAL: {args.library} exports none of the expected primitives. "
            f"That is a broken library, not an old one.",
            file=sys.stderr,
        )
        return 2

    if absent:
        print(f"# {args.library.name}: {len(absent)} primitive(s) absent", file=sys.stderr)
        for feature in absent:
            print(f"#   {feature} ({FEATURE_SYMBOLS[feature]})", file=sys.stderr)
    print(" ".join(f"-DAMA_IC_HAVE_{feature}=0" for feature in absent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
