#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Wheel-build integrity signing pipeline
=======================================

Single-purpose CLI invoked by the wheel build pipeline (setup.py
post-build hook / CMake post-install step / explicit ``pip wheel``
wrapper) to:

  1. Generate an *ephemeral, per-build* Ed25519 keypair using the
     in-tree ``ama_ed25519_keypair`` C symbol via ctypes — INVARIANT-1
     forbids a PyCA dependency anywhere in the runtime tree, and this
     module ships as part of the runtime tree so the build-time
     signer must also obey that contract.
  2. Compute the SHA3-256 digest over the package's ``.py`` files
     (the same algorithm ``_self_test._compute_module_digest`` uses
     at import time).
  3. Sign the digest with the per-build private key using
     ``ama_ed25519_sign``.
  4. Write ``ama_cryptography/_integrity_signature.py`` containing
     the embedded public key, signature, and digest as Python
     literals — the only artefact that ships with the wheel.
  5. Discard the private key (it never leaves the build host's
     memory, never lands in the wheel, never gets cached).

Threat model: post-build tamper detection.  See ``SECURITY.md``
"Module Integrity Verification" for the full design rationale.

Invocation (build-pipeline only):

    AMA_BUILD_PIPELINE=1 python -m ama_cryptography._build_sign

Verification (at import time, see ``_self_test._verify_integrity``):

    The runtime path loads ``_integrity_signature.py``, recomputes
    the digest, and calls ``ama_ed25519_verify`` with the embedded
    (pubkey, signature) pair.  Mismatch → ERROR state, all crypto
    operations refused.  Missing artefact → fall back to digest-only
    verification with a logged warning (editable installs).
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import sys
from pathlib import Path
from typing import Tuple


_BUILD_PIPELINE_ENV = "AMA_BUILD_PIPELINE"


def _require_build_pipeline() -> None:
    """Refuse to run outside the wheel build pipeline.

    Mirrors the gate on ``integrity --update``: a user who runs this
    locally could otherwise generate their own (pubkey, signature)
    pair over tampered .py files and the import-time verifier would
    accept it.  The wheel build pipeline sets AMA_BUILD_PIPELINE=1
    immediately before invoking this CLI.
    """
    if os.environ.get(_BUILD_PIPELINE_ENV) != "1":
        print(
            f"ERROR: _build_sign is build-pipeline-only.  Set "
            f"{_BUILD_PIPELINE_ENV}=1 if you are the wheel build "
            "script; otherwise rebuild the wheel instead of "
            "regenerating an installed module's integrity signature.",
            file=sys.stderr,
        )
        sys.exit(2)


def _compute_package_digest(pkg_dir: Path) -> bytes:
    """Compute SHA3-256 over ``pkg_dir``'s ``.py`` files.

    Mirrors ``_self_test._compute_module_digest`` byte-for-byte:
    sorted glob over ``*.py`` at the top level, name + content with
    CRLF normalised to LF.  Returns raw 32 bytes (the import-time
    verifier compares raw, not hex).
    """
    hasher = hashlib.sha3_256()
    for py_file in sorted(pkg_dir.glob("*.py")):
        # Exclude the generated artefact from the digest — otherwise
        # the digest would depend on the signature it covers, making
        # the construction self-referential.
        if py_file.name == "_integrity_signature.py":
            continue
        hasher.update(py_file.name.encode("utf-8"))
        content = py_file.read_bytes().replace(b"\r\n", b"\n")
        hasher.update(content)
    return hasher.digest()


def _generate_keypair_and_sign(digest: bytes) -> Tuple[bytes, bytes]:
    """Generate an ephemeral Ed25519 keypair and sign ``digest``.

    Uses the in-tree C kernel via ctypes — INVARIANT-1 forbids PyCA
    anywhere in this tree.  The private key is held only in a local
    bytearray and overwritten with ``secure_memzero`` before return
    so it does not survive on the build host's heap.

    Returns:
        ``(pubkey_32, signature_64)`` — both raw bytes.

    Raises:
        RuntimeError: if the native library is not loadable or the
            signing call fails.  Either is a hard build error — the
            wheel must not ship without a valid signature.
    """
    # Late imports so this module is importable in environments that
    # cannot find the native library (e.g. doc builders): the failure
    # surfaces only when sign is actually requested.
    from ama_cryptography.pqc_backends import _find_native_library  # noqa: WPS433
    from ama_cryptography.secure_memory import secure_memzero  # noqa: WPS433

    lib = _find_native_library()
    if lib is None:
        raise RuntimeError(
            "Cannot find the native AMA Cryptography library; build "
            "the C extension first (cmake -B build && cmake --build "
            "build).  The signing pipeline depends on the in-tree "
            "Ed25519 kernel (INVARIANT-1: no PyCA dependency)."
        )

    # ama_ed25519_keypair(public_key[32], secret_key[64])
    #   The 32-byte seed is read from secret_key[0..31] and the
    #   computed public key is written into both `public_key` and
    #   secret_key[32..63].  We seed with os.urandom for the
    #   one-shot per-build key.
    lib.ama_ed25519_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.ama_ed25519_keypair.restype = ctypes.c_int

    lib.ama_ed25519_sign.argtypes = [
        ctypes.c_char_p,  # signature[64]
        ctypes.c_char_p,  # message
        ctypes.c_size_t,  # message_len
        ctypes.c_char_p,  # secret_key[64]
    ]
    lib.ama_ed25519_sign.restype = ctypes.c_int

    pk = bytearray(32)
    sk = bytearray(64)
    seed = os.urandom(32)
    sk[0:32] = seed

    pk_buf = (ctypes.c_char * 32).from_buffer(pk)
    sk_buf = (ctypes.c_char * 64).from_buffer(sk)
    rc = lib.ama_ed25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        secure_memzero(sk)
        secure_memzero(pk)
        raise RuntimeError(
            f"ama_ed25519_keypair returned rc={rc}; the native build "
            "may be miscompiled."
        )

    sig = bytearray(64)
    sig_buf = (ctypes.c_char * 64).from_buffer(sig)
    msg_buf = (ctypes.c_char * len(digest))(*digest)
    rc = lib.ama_ed25519_sign(sig_buf, msg_buf, len(digest), sk_buf)
    if rc != 0:
        secure_memzero(sk)
        secure_memzero(sig)
        secure_memzero(pk)
        raise RuntimeError(
            f"ama_ed25519_sign returned rc={rc}; the native build "
            "may be miscompiled."
        )

    pubkey_out = bytes(pk)
    signature_out = bytes(sig)

    # Discard the ephemeral private key from memory.  The bytearray
    # backing the secure-memzero is the only copy left after this
    # function returns; the seed was already consumed by ama_ed25519_keypair.
    secure_memzero(sk)
    secure_memzero(sig)
    secure_memzero(pk)
    # Locals will be GC'd at function return.

    return pubkey_out, signature_out


_SIGNATURE_TEMPLATE = '''"""
Auto-generated by ama_cryptography._build_sign at wheel build time.

DO NOT EDIT.  Any modification invalidates the import-time integrity
check (`ama_cryptography._self_test._verify_integrity`) and the
module enters the ERROR state on next import.

The (public_key, signature) pair below is the build-time Ed25519
signature over the SHA3-256 digest of the package's .py files.  The
private key was discarded immediately after signing — see
SECURITY.md "Module Integrity Verification" for the threat model.
"""

# SHA3-256 digest of the package's .py files at build time (raw 32 bytes,
# hex-encoded for embeddability).
INTEGRITY_DIGEST_HEX = "{digest_hex}"

# Ephemeral build-time Ed25519 public key (raw 32 bytes, hex-encoded).
INTEGRITY_PUBKEY_HEX = "{pubkey_hex}"

# Ed25519 signature over the raw digest above (raw 64 bytes, hex-encoded).
INTEGRITY_SIGNATURE_HEX = "{signature_hex}"

# Build metadata — informational only, not part of the integrity contract.
BUILD_PIPELINE_VERSION = "1"
'''


def _write_signature_module(
    pkg_dir: Path, digest: bytes, pubkey: bytes, signature: bytes
) -> Path:
    """Emit ``_integrity_signature.py`` as a Python literal module."""
    out_path = pkg_dir / "_integrity_signature.py"
    out_path.write_text(
        _SIGNATURE_TEMPLATE.format(
            digest_hex=digest.hex(),
            pubkey_hex=pubkey.hex(),
            signature_hex=signature.hex(),
        ),
        encoding="utf-8",
    )
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Wheel-build integrity signer (INVARIANT-1: no PyCA dependency)."
        )
    )
    parser.add_argument(
        "--package-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help=(
            "Path to the ama_cryptography package directory.  Defaults "
            "to the directory containing this module."
        ),
    )
    parser.add_argument(
        "--digest-only",
        action="store_true",
        help=(
            "Skip signing — only refresh ama_cryptography/_integrity_digest.txt. "
            "Equivalent to `integrity --update` and used by environments where "
            "the native library is not available at build time (rare)."
        ),
    )
    args = parser.parse_args()

    _require_build_pipeline()

    pkg_dir = args.package_dir.resolve()
    digest = _compute_package_digest(pkg_dir)
    digest_hex = digest.hex()

    # Always refresh the legacy digest-only artefact so the
    # digest-fallback verifier path stays in sync.
    (pkg_dir / "_integrity_digest.txt").write_text(digest_hex + "\n")
    print(f"Integrity digest refreshed: {digest_hex}")

    if args.digest_only:
        return 0

    try:
        pubkey, signature = _generate_keypair_and_sign(digest)
    except RuntimeError as exc:
        print(
            f"ERROR: {exc}\n"
            "Falling back to digest-only signing — the import-time "
            "verifier will accept this artefact but the wheel will "
            "lack the signed-integrity protection.  Build the native "
            "library before running _build_sign for full protection.",
            file=sys.stderr,
        )
        return 1

    out_path = _write_signature_module(pkg_dir, digest, pubkey, signature)
    print(
        f"Signed integrity artefact written: {out_path}\n"
        f"  digest    = {digest_hex}\n"
        f"  pubkey    = {pubkey.hex()}\n"
        f"  signature = {signature.hex()[:32]}... (64 B)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
