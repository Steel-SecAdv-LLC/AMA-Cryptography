#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Wheel-build integrity signing pipeline
=======================================

Single-purpose CLI invoked by the wheel build pipeline (setup.py
post-build hook / CMake post-install step / explicit ``pip wheel``
wrapper) to:

  1. Generate an *ephemeral, per-build* Ed25519 keypair using the
     in-tree ``ama_ed25519_keypair`` C symbol via ctypes — or, in
     release CI, derive it from ``AMA_INTEGRITY_SIGNING_SEED_HEX`` and
     require it to match the trust anchor compiled into the native
     library.  INVARIANT-1 forbids a PyCA dependency anywhere in the
     runtime tree, and this module ships as part of the runtime tree so
     the build-time signer must also obey that contract.
  2. Compute the SHA3-256 digest over the package's ``.py`` files
     (the same algorithm ``_self_test._compute_module_digest`` uses
     at import time), a second SHA3-256 over the native library
     (``libama_cryptography``) that will ship in the wheel, AND a
     per-file SHA3-256 map of the compiled binding extensions
     (``ed25519_binding`` et al. — they execute at import, before POST
     can examine them, and the release pipeline ships them
     byte-identical to the build).
  3. Sign the **v3 composite** ``SHA3-256(domain_v3 || py_digest ||
     native_digest || serialized_binding_digests)`` with the per-build
     private key using ``ama_ed25519_sign``.  Signing the composite
     binds every compiled artefact in the package into the same
     signature that covers the Python wrapper, so a tampered ``.so``
     or binding extension is caught at import
     (``_self_test._verify_signed_integrity``).
  4. Write ``ama_cryptography/_integrity_signature.py`` containing
     the embedded public key, signature, .py digest, native digest and
     binding-digest map as Python literals — the only artefact that
     ships with the wheel.
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
import contextlib
import ctypes
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

_BUILD_PIPELINE_ENV = "AMA_BUILD_PIPELINE"
_INTEGRITY_SIGNING_SEED_ENV = "AMA_INTEGRITY_SIGNING_SEED_HEX"
_INTEGRITY_TRUST_ANCHOR_ENV = "AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX"
_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV = "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR"
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}


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


#: Format tag for the package digest.  MUST equal
#: ``_self_test._PACKAGE_DIGEST_FORMAT`` byte for byte; pinned by
#: ``tests/test_native_integrity.py``.  See the framing note in
#: ``_self_test._compute_module_digest`` for what it separates and why.
_PACKAGE_DIGEST_FORMAT = b"AMA-package-digest-v2\x00"


class _Absorbing(Protocol):
    """The only thing :func:`_absorb_entry` needs from a hash object.

    A structural type rather than ``hashlib._Hash``: that name is private to
    the standard library, and naming it here would also add a reference to the
    ``hashlib`` module inside a file the INVARIANT-1 stdlib-hash boundary
    counts exactly — this helper takes a hasher, it does not construct one.
    """

    def update(self, data: bytes, /) -> None:  # pragma: no cover - protocol
        """Absorb ``data``.  Never called: a Protocol body is a type, not code.

        A docstring rather than ``...`` — the ellipsis is an expression
        statement with no effect, which is exactly what CodeQL's
        "Statement has no effect" rule reports, and a suppression comment
        would hide the rule rather than answer it.
        """


def _absorb_entry(hasher: _Absorbing, section: bytes, name: str, content: bytes) -> None:
    """Absorb one (section, name, content) entry with every field framed.

    Byte-for-byte mirror of ``_self_test._absorb_entry``.  The two modules
    deliberately do not import each other (build-time vs runtime separation,
    INVARIANT-1), so the duplication is intentional and pinned by tests.
    """
    name_bytes = name.encode("utf-8")
    body = content.replace(b"\r\n", b"\n")
    hasher.update(len(section).to_bytes(4, "big"))
    hasher.update(section)
    hasher.update(len(name_bytes).to_bytes(4, "big"))
    hasher.update(name_bytes)
    hasher.update(len(body).to_bytes(8, "big"))
    hasher.update(body)


def _compute_package_digest(pkg_dir: Path) -> bytes:
    """Compute SHA3-256 over ``pkg_dir``'s ``.py`` files and POST KAT vectors.

    Mirrors ``_self_test._compute_module_digest`` byte-for-byte: the top-level
    ``*.py`` files (excluding the generated ``_integrity_signature.py``), then
    every file under ``_post_kats/`` ordered by name, each contributing its name
    plus content with CRLF normalised to LF, every field length-prefixed and
    every section tagged.  Covering ``_post_kats/`` binds the Known Answer
    vectors so a swapped vector fails the import-time integrity check.  Returns
    raw 32 bytes (the verifier compares raw, not hex).

    The framing is load-bearing — see the note in the runtime mirror.  Without
    it this hash commits to the CONCATENATION of names and contents rather than
    to the mapping, and two different package trees were demonstrated to
    produce one digest, which one signature then covered.
    """
    hasher = hashlib.sha3_256()
    hasher.update(_PACKAGE_DIGEST_FORMAT)

    # Exclude the generated artefact from the digest — otherwise the digest
    # would depend on the signature it covers, making the construction
    # self-referential.
    #
    # RECURSIVE and keyed by package-relative POSIX path, byte-for-byte with
    # the runtime mirror (_self_test._compute_module_digest): a non-recursive
    # glob would leave a subpackage .py silently unsigned, and a name-only
    # key would collide `a/x.py` with `b/x.py`.  For the current flat layout
    # the relative path equals the name, so no existing signature changes.
    py_files = [
        p
        for p in sorted(pkg_dir.rglob("*.py"))
        if p.name != "_integrity_signature.py" and "__pycache__" not in p.parts
    ]
    hasher.update(len(py_files).to_bytes(4, "big"))
    for py_file in py_files:
        _absorb_entry(hasher, b"py", py_file.relative_to(pkg_dir).as_posix(), py_file.read_bytes())

    kat_dir = pkg_dir / "_post_kats"
    kat_files = (
        sorted((p for p in kat_dir.iterdir() if p.is_file()), key=lambda p: p.name)
        if kat_dir.is_dir()
        else []
    )
    hasher.update(len(kat_files).to_bytes(4, "big"))
    for kat_file in kat_files:
        _absorb_entry(hasher, b"post_kats", kat_file.name, kat_file.read_bytes())
    return hasher.digest()


# Domain-separation tag binding the .py digest and the native-library digest
# under one signature.  MUST equal ``_self_test._INTEGRITY_SIG_DOMAIN`` byte for
# byte — the runtime verifier reconstructs the signed message from these same
# bytes.  The two modules deliberately do not import each other (build-time vs
# runtime separation, INVARIANT-1); ``tests/test_native_integrity.py`` pins the
# constants equal so a drift fails CI rather than silently invalidating every
# signature.
_INTEGRITY_SIG_DOMAIN = b"AMA-integrity-signature-v2\x00"


def _compute_native_library_digest(path: str) -> bytes:
    """SHA3-256 over the raw bytes of the native library at ``path``.

    Follows symlinks so the SONAME chain resolves to the one real object whose
    bytes the loader maps — the same bytes the runtime verifier will hash.
    """
    with open(path, "rb") as handle:
        return hashlib.sha3_256(handle.read()).digest()


def _composite_integrity_message(py_digest: bytes, native_digest: bytes) -> bytes:
    """The exact bytes the Ed25519 integrity signature covers (v2 format).

    ``SHA3-256(domain || py_digest || native_digest)``.  Mirrored byte-for-byte
    in ``_self_test._composite_integrity_message``.  Retained for the verifier's
    legacy path and its pinning tests; the signer now emits v3 exclusively.
    """
    return hashlib.sha3_256(_INTEGRITY_SIG_DOMAIN + py_digest + native_digest).digest()


# v3 domain: the signed message additionally binds every compiled binding
# extension.  A distinct domain string means a v3 signature can never verify
# against a v2-shaped message or vice versa, even if an attacker moves fields
# between artefact schemas.  MUST equal ``_self_test._INTEGRITY_SIG_DOMAIN_V3``
# byte for byte; pinned by ``tests/test_binding_integrity.py``.
_INTEGRITY_SIG_DOMAIN_V3 = b"AMA-integrity-signature-v3\x00"

#: The compiled extension modules the package ships besides the native
#: library.  Everything in the package directory with an extension-module
#: suffix must be either the native library (bound via
#: ``INTEGRITY_NATIVE_DIGEST_HEX``) or carry one of these stems —
#: ``_iter_binding_files`` refuses to sign a tree containing an extension it
#: does not recognise, so a new binding cannot ship uncovered by forgetting
#: this inventory.
_BINDING_STEMS = (
    "dilithium_binding",
    "ed25519_binding",
    "hkdf_binding",
    "hmac_binding",
    "math_engine",
    "sha3_binding",
)

#: Suffixes an extension module can carry across the shipped platforms
#: (``.cpython-311-x86_64-linux-gnu.so``, ``.cpython-311-darwin.so``,
#: ``.pyd``).  ``.dylib`` is included so a macOS native-library file is
#: recognised (and excluded by prefix) rather than treated as unknown.
_EXTENSION_SUFFIXES = (".so", ".pyd", ".dylib")

#: The native library's filename prefixes on the shipped platforms —
#: ``libama_cryptography.so*`` / ``libama_cryptography*.dylib`` /
#: ``libama_cryptography.dll`` / ``ama_cryptography.dll``.  These are covered
#: by ``INTEGRITY_NATIVE_DIGEST_HEX``, not the binding dict.
_NATIVE_LIB_PREFIXES = ("libama_cryptography", "ama_cryptography.dll")


def _iter_binding_files(pkg_dir: Path) -> List[Path]:
    """Every compiled binding-extension file in the package directory.

    Enumerates the directory rather than trusting a static filename list:
    the suffix is platform- and interpreter-specific, so identity is carried
    by the stem.  Fails closed on an extension whose stem is not in
    :data:`_BINDING_STEMS` — an unrecognised compiled module must be added to
    the inventory (and ``_self_test``'s verification updated by the same
    commit's tests) or it would ship executing code the signature never
    covered.
    """
    out: List[Path] = []
    for path in sorted(pkg_dir.iterdir()):
        if not path.is_file() or path.suffix not in _EXTENSION_SUFFIXES:
            continue
        if path.name.startswith(_NATIVE_LIB_PREFIXES):
            continue
        stem = path.name.split(".", 1)[0]
        if stem not in _BINDING_STEMS:
            raise RuntimeError(
                f"unknown compiled extension {path.name!r} in the package "
                "directory: add its stem to _BINDING_STEMS so it is bound "
                "into the integrity signature, or remove the file"
            )
        out.append(path)
    return out


def _compute_binding_digests(pkg_dir: Path) -> Dict[str, bytes]:
    """SHA3-256 of every binding extension, keyed by exact filename."""
    return {
        path.name: hashlib.sha3_256(path.read_bytes()).digest()
        for path in _iter_binding_files(pkg_dir)
    }


def _serialize_binding_digests(binding_digests: Dict[str, bytes]) -> bytes:
    """Canonical byte serialization of the binding-digest map.

    Count- and length-prefixed, entries in sorted-name order, so the framing
    is UNCONDITIONALLY injective: no concatenation of entries collides with any
    other map, regardless of what a name or digest contains.  This matches the
    length-prefixed framing ``_self_test._absorb_entry`` uses for the module
    digest and replaces the earlier ``name || 0x00 || digest`` form, whose
    injectivity relied on filenames never containing NUL.  Mirrored
    byte-for-byte in ``_self_test``.
    """
    out = bytearray()
    out += len(binding_digests).to_bytes(4, "big")
    for name in sorted(binding_digests):
        name_bytes = name.encode("utf-8")
        digest = binding_digests[name]
        out += len(name_bytes).to_bytes(4, "big")
        out += name_bytes
        out += len(digest).to_bytes(4, "big")
        out += digest
    return bytes(out)


def _composite_integrity_message_v3(
    py_digest: bytes, native_digest: bytes, binding_digests: Dict[str, bytes]
) -> bytes:
    """The exact bytes the Ed25519 integrity signature covers (v3 format).

    ``SHA3-256(domain_v3 || py_digest || native_digest ||
    serialized_binding_digests)``.  Mirrored byte-for-byte in
    ``_self_test._composite_integrity_message_v3``.
    """
    return hashlib.sha3_256(
        _INTEGRITY_SIG_DOMAIN_V3
        + py_digest
        + native_digest
        + _serialize_binding_digests(binding_digests)
    ).digest()


def _env_flag_enabled(name: str) -> bool:
    """Return True when a boolean environment variable is explicitly enabled."""
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


def _load_hex_env_bytes(
    name: str,
    expected_len: int,
) -> Optional[bytes]:
    """Load an optional hex-encoded byte string from an environment variable."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be hex-encoded: {exc}") from exc
    if len(value) != expected_len:
        raise RuntimeError(f"{name} has {len(value)} bytes; expected {expected_len}")
    return value


def _load_native_trust_anchor(
    lib: ctypes.CDLL,
) -> Optional[bytes]:
    """Return the C-compiled integrity trust anchor, if this build has one.

    All native-call failures (ctypes OSError, non-ASCII bytes, missing
    NUL terminator) are normalised to ``RuntimeError`` so the CLI's
    ``main()`` exception handler can produce a stable, single-line
    failure message instead of a raw traceback from the ctypes layer.
    """
    if not hasattr(lib, "ama_integrity_trust_anchor_pubkey_hex"):
        return None
    try:
        lib.ama_integrity_trust_anchor_pubkey_hex.argtypes = []
        lib.ama_integrity_trust_anchor_pubkey_hex.restype = ctypes.c_char_p
        raw = lib.ama_integrity_trust_anchor_pubkey_hex()
        decoded = raw.decode("ascii").strip() if raw else ""
    except Exception as exc:
        raise RuntimeError(f"native trust-anchor lookup failed: {exc}") from exc
    if not decoded:
        return None
    try:
        value = bytes.fromhex(decoded)
    except ValueError as exc:
        raise RuntimeError(f"native integrity trust anchor is not valid hex: {exc}") from exc
    if len(value) != 32:
        raise RuntimeError(f"native integrity trust anchor has {len(value)} bytes; expected 32")
    return value


def _generate_keypair_and_sign(
    digest: bytes,
    seed_override: Optional[bytes] = None,
    trusted_pubkey: Optional[bytes] = None,
    require_trust_anchor: bool = False,
    native_lib: Optional[Any] = None,
) -> Tuple[bytes, bytes, str]:
    """Generate an ephemeral Ed25519 keypair and sign ``digest``.

    Uses the in-tree C kernel via ctypes — INVARIANT-1 forbids PyCA
    anywhere in this tree.  The private key is held only in a local
    bytearray and overwritten with ``secure_memzero`` before return
    so it does not survive on the build host's heap.

    Returns:
        ``(pubkey_32, signature_64, anchor_source)`` — raw bytes plus
        a string identifying which trust source pinned the keypair:
        ``"native"`` (CMake ``-DAMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX``),
        ``"env"`` (``AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX`` env var
        only), or ``"none"`` (unanchored developer build).

    Raises:
        RuntimeError: if the native library is not loadable or the
            signing call fails.  Either is a hard build error — the
            wheel must not ship without a valid signature.
    """
    # Late imports so this module is importable in environments that
    # cannot find the native library (e.g. doc builders): the failure
    # surfaces only when sign is actually requested.
    from ama_cryptography.pqc_backends import _find_native_library
    from ama_cryptography.secure_memory import secure_memzero

    # The caller normally hands in the handle it already resolved, under the
    # narrowly-scoped signing override.  Re-discovering here would run outside
    # that scope and refuse the very library being blessed — and would widen
    # the override's window if it were extended to cover this call instead.
    lib = native_lib if native_lib is not None else _find_native_library()
    if lib is None:
        raise RuntimeError(
            "Cannot find the native AMA Cryptography library; build "
            "the C extension first (cmake -B build && cmake --build "
            "build).  The signing pipeline depends on the in-tree "
            "Ed25519 kernel (INVARIANT-1: no PyCA dependency)."
        )

    native_trust_anchor = _load_native_trust_anchor(lib)
    anchor_source = "none"
    if native_trust_anchor is not None:
        if trusted_pubkey is not None and trusted_pubkey != native_trust_anchor:
            raise RuntimeError(
                f"{_INTEGRITY_TRUST_ANCHOR_ENV} does not match the trust anchor "
                "compiled into the native library."
            )
        trusted_pubkey = native_trust_anchor
        anchor_source = "native"
    elif trusted_pubkey is not None:
        anchor_source = "env"
    if require_trust_anchor and trusted_pubkey is None:
        raise RuntimeError(
            f"{_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV}=1 requires either a native "
            f"CMake {_INTEGRITY_TRUST_ANCHOR_ENV} build anchor or "
            f"{_INTEGRITY_TRUST_ANCHOR_ENV} to pin the expected build public key."
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
    # The per-build signing seed deliberately does NOT route through the
    # error-state-gated ``secure_token_bytes`` draw that INVARIANT-41 requires
    # of runtime key material: this signer's defining use case is repairing a
    # stale artefact, which it does from the ERROR state — where the gated
    # draw refuses by design, and routing through it would wall the repair
    # tool off behind the fault it exists to clear.  The health property the
    # gate would have provided is applied directly instead: the FIPS 140-3
    # continuous-test comparison of consecutive draws, which a catastrophically
    # stuck entropy source fails.
    if seed_override is not None:
        seed = bytearray(seed_override)
    else:
        first_draw = os.urandom(32)
        second_draw = os.urandom(32)
        if first_draw == second_draw:
            raise RuntimeError(
                "os.urandom returned two identical 32-byte draws — entropy "
                "source stuck; refusing to mint an integrity-signing key"
            )
        seed = bytearray(second_draw)
    sk[0:32] = seed
    secure_memzero(seed)

    pk_buf = (ctypes.c_char * 32).from_buffer(pk)
    sk_buf = (ctypes.c_char * 64).from_buffer(sk)
    rc = lib.ama_ed25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        secure_memzero(sk)
        secure_memzero(pk)
        raise RuntimeError(
            f"ama_ed25519_keypair returned rc={rc}; the native build " "may be miscompiled."
        )

    if trusted_pubkey is not None and bytes(pk) != trusted_pubkey:
        secure_memzero(sk)
        secure_memzero(pk)
        raise RuntimeError(
            "Generated integrity signing public key does not match "
            f"{_INTEGRITY_TRUST_ANCHOR_ENV}; refusing to write an unanchored signature."
        )

    sig = bytearray(64)
    sig_buf = (ctypes.c_char * 64).from_buffer(sig)
    # from_buffer_copy gives mypy a `bytes`-compatible factory and avoids
    # unpacking the digest into per-byte int arguments (which the
    # c_char array constructor rejects under strict typing).
    msg_buf = (ctypes.c_char * len(digest)).from_buffer_copy(digest)
    rc = lib.ama_ed25519_sign(sig_buf, msg_buf, len(digest), sk_buf)
    if rc != 0:
        secure_memzero(sk)
        secure_memzero(sig)
        secure_memzero(pk)
        raise RuntimeError(
            f"ama_ed25519_sign returned rc={rc}; the native build " "may be miscompiled."
        )

    pubkey_out = bytes(pk)
    signature_out = bytes(sig)

    # Discard the ephemeral private key from memory.  The seed was
    # wiped immediately after copy into sk (line above); sk, sig, and
    # pk are the only mutable copies remaining.
    secure_memzero(sk)
    secure_memzero(sig)
    secure_memzero(pk)
    # Locals will be GC'd at function return.

    return pubkey_out, signature_out, anchor_source


_SIGNATURE_TEMPLATE = '''# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
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

# SHA3-256 digest of the native library (libama_cryptography) at build time.
# This is what binds the shared object that performs every cryptographic
# operation into the same signature that covers the .py files — without it the
# signature attested to the Python wrapper only, and the implementation the
# wrapper calls into was covered by nothing.
INTEGRITY_NATIVE_DIGEST_HEX = "{native_digest_hex}"

# SHA3-256 digests of the compiled binding extensions at build time, keyed by
# exact filename.  These modules contain compiled kernels and execute at import
# — before POST can examine them — and the release pipeline ships them
# byte-identical to the build (auditwheel/delocate graft nothing: the native
# library resolves in-package via $ORIGIN/@loader_path; Windows repair is
# disabled), so the build-time digest is the runtime file's digest on every
# platform.  Verified by ama_cryptography._self_test._check_binding_extensions.
INTEGRITY_BINDING_DIGESTS_HEX: dict[str, str] = {binding_digests_literal}

# Ephemeral build-time Ed25519 public key (raw 32 bytes, hex-encoded).
INTEGRITY_PUBKEY_HEX = "{pubkey_hex}"

# Ed25519 signature over SHA3-256(domain_v3 || py_digest || native_digest ||
# serialized_binding_digests) — the v3 composite that makes all three
# inseparable.  See ama_cryptography._self_test._composite_integrity_message_v3.
INTEGRITY_SIGNATURE_HEX = "{signature_hex}"

# Build metadata — informational only, not part of the integrity contract.
BUILD_PIPELINE_VERSION = "3"
'''


def _binding_digests_literal(binding_digests: Dict[str, bytes]) -> str:
    """Render the binding-digest map as a stable Python dict literal."""
    if not binding_digests:
        return "{}"
    entries = ",\n".join(
        f'    "{name}": "{binding_digests[name].hex()}"' for name in sorted(binding_digests)
    )
    return "{\n" + entries + ",\n}"


def _artefact_mode(out_path: Path) -> int:
    """The mode the rewritten ``_integrity_signature.py`` must end up with.

    ``mkstemp`` creates the staging file 0o600 so a half-written artefact is
    unreadable, which is right for the staging file and wrong for the artefact
    every installed reader has to import.  The mode therefore has to be set
    before the rename — but not to a constant.

    A hardcoded ``0o644`` here was wrong in both directions, and CodeQL was
    right to flag it (alert #642).  It ignored the operator's umask, so a
    build host running ``umask 077`` got a world-readable artefact it never
    asked for; and it discarded the mode an existing artefact already carried.
    Neither matches ``Path.write_text``, which this atomic writer replaced:
    ``"w"`` on an EXISTING file leaves its mode untouched, so an artefact
    stored 0o600 stayed 0o600 across every re-sign.  Silently widening it was
    a regression introduced with the atomic write, not a pre-existing state.

    So: preserve the mode when there is an artefact to preserve, and otherwise
    use exactly what creating a file would have produced.  Reading the umask
    requires momentarily setting it, which is process-global; that is safe
    here because this module runs only in the single-threaded
    ``python -m ama_cryptography.integrity --update --sign`` build CLI, and it
    is the same read-then-restore the standard library itself uses.
    """
    try:
        return stat.S_IMODE(out_path.stat().st_mode)
    except FileNotFoundError:
        mask = os.umask(0)
        os.umask(mask)
        return 0o666 & ~mask


def _write_signature_module(
    pkg_dir: Path,
    digest: bytes,
    native_digest: bytes,
    binding_digests: Dict[str, bytes],
    pubkey: bytes,
    signature: bytes,
) -> Path:
    """Emit ``_integrity_signature.py`` as a Python literal module.

    Written to a sibling temporary file and renamed over the target, never
    truncated in place.  ``Path.write_text`` opens with ``"w"``, which empties
    the file before the first byte of the new content lands, so between those
    two moments the artefact exists and is empty — and an empty artefact used
    to parse to zero literals, answer ``None`` to every digest lookup, and send
    both pre-load gates down their nothing-to-check branch.  ``_artefact_source``
    now refuses a literal-free artefact outright, which is the right rule and
    would have turned that window into a hard ImportError for any concurrent
    import.  ``os.replace`` removes the window instead of relying on nobody
    looking: readers see either the whole old artefact or the whole new one.

    newline="\n" pins the artefact to LF on every platform.  Windows' default
    text-mode translation would emit CRLF, making the working tree diverge from
    the committed blob byte-for-byte — which the checkout byte-identity gate
    (tools/check_line_endings.py) correctly rejects.  The bytes written are
    identical to what ``write_text`` produced, so the reproducible-build
    byte-equality gate is unaffected.
    """
    out_path = pkg_dir / "_integrity_signature.py"
    payload = _SIGNATURE_TEMPLATE.format(
        digest_hex=digest.hex(),
        native_digest_hex=native_digest.hex(),
        binding_digests_literal=_binding_digests_literal(binding_digests),
        pubkey_hex=pubkey.hex(),
        signature_hex=signature.hex(),
    )
    fd, tmp_name = tempfile.mkstemp(
        dir=str(out_path.parent), prefix="._integrity_signature.", suffix=".tmp"
    )
    fd_is_ours = True
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        fd_is_ours = False  # ownership transferred to ``handle``
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Settle the mode on the STAGING path, before the rename makes the
        # artefact visible: a reader must never see it at mkstemp's 0o600.
        os.chmod(tmp_name, _artefact_mode(out_path))
        os.replace(tmp_name, out_path)
    except BaseException:
        if fd_is_ours:
            # fdopen never took the descriptor, so closing it here is correct
            # and cannot double-close.
            os.close(fd)
        # Already consumed by os.replace, or never created: a missing staging
        # file is the one benign case and the only one suppressed.
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise
    # Drop any cached bytecode compiled from the PREVIOUS artefact.  CPython
    # validates a .pyc by (mtime-seconds, size) — and this rewrite produces a
    # file of IDENTICAL size (fixed-width hex fields), often within the same
    # second in a build pipeline.  The stale .pyc then still validates, the
    # next import reads the OLD digests, and the runtime reports a
    # native-digest mismatch against a signature that no longer exists on
    # disk.  This is not hypothetical: it failed the Alpine Docker build on
    # PR #391, where the per-image re-sign and its verification import ran
    # 250 ms apart.  Unlinking the cache forces the next import to compile
    # the bytes just written.
    for cached in (out_path.parent / "__pycache__").glob("_integrity_signature.*.pyc"):
        with contextlib.suppress(OSError):
            cached.unlink()
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=("Wheel-build integrity signer (INVARIANT-1: no PyCA dependency).")
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
    parser.add_argument(
        "--require-trust-anchor",
        action="store_true",
        help=(
            "Refuse to sign unless the signature verifies against a "
            "configured trust anchor — the same enforcement "
            "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 requests via the "
            "environment.  setup.py passes this flag when the INSTALLING "
            "environment had that variable enabled: the variable itself is "
            "scrubbed from the signer child (it would otherwise fail the "
            "child's own import-time POST, which necessarily runs against a "
            "tree whose artefact has just been moved aside), and without "
            "this flag the scrub silently dropped the operator's demanded "
            "anchor enforcement along with it."
        ),
    )
    parser.add_argument(
        "--bind-extensions",
        action="store_true",
        help=(
            "Bind the compiled binding extensions into the signed artefact. "
            "Both callers pass it: setup.py after syncing the staged "
            "extensions into the package dir, and the repair flow "
            "(`integrity --update --sign`), which binds whatever the tree it "
            "is repairing currently holds.  An artefact that does not bind "
            "them leaves every extension in the tree reported as 'present "
            "but not covered by the signed artefact' — a warning and a "
            "below-full integrity strength on developer builds, a hard "
            "failure on anchored ones — and those extensions execute at "
            "import unverified.  This flag is what closes that, so a build "
            "or repair that omits it produces the state the artefact exists "
            "to prevent. "
            "The flag remains explicit rather than implicit because "
            "--digest-only and a bindings-free v3 artefact stay reachable "
            "for the environments that genuinely have no extensions to bind."
        ),
    )
    args = parser.parse_args()

    _require_build_pipeline()

    pkg_dir = args.package_dir.resolve()
    digest = _compute_package_digest(pkg_dir)
    digest_hex = digest.hex()

    # Always refresh the legacy digest-only artefact so the
    # digest-fallback verifier path stays in sync.  newline="\n" keeps the
    # artefact LF on Windows too (see _write_signature_module).
    (pkg_dir / "_integrity_digest.txt").write_text(
        digest_hex + "\n", encoding="utf-8", newline="\n"
    )
    print(f"Integrity digest refreshed: {digest_hex}")

    if args.digest_only:
        return 0

    try:
        # Locate the native library and hash the exact object that will ship in
        # the wheel.  This runs BEFORE signing so the digest is bound into the
        # signed message: the signature covers the composite of the .py digest
        # and this native digest, not the .py digest alone.  _find_native_library
        # is the same discovery the runtime uses, so the file hashed here is the
        # file the runtime will load and re-hash.
        from ama_cryptography.pqc_backends import (
            _find_native_library,
            _find_native_library_path,
            unverified_load_for_signing,
        )

        # The file to bind is chosen by PATH discovery, and its digest is taken
        # by reading it.  Deriving the path from a loaded handle is wrong in
        # exactly the case this flow exists for: the operator rebuilt the
        # library, so its digest no longer matches the artefact, so the
        # (correctly) unconditional pre-load check refuses to map it — and a
        # loader-based signer would then walk past the file it was asked to
        # re-bless and sign whichever later candidate still happened to match.
        # Signing the wrong file is worse than failing to sign.
        #
        # _find_native_library_path applies the same search order and the same
        # AMA_CRYPTO_LIB_PATH rules (secure-execution suppression included), so
        # the file hashed here is the file the runtime will select.
        native_path_obj = _find_native_library_path()
        if native_path_obj is None:
            raise RuntimeError(
                "native library not found; cannot bind it into the integrity "
                "signature. Build it first: cmake -B build "
                "-DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )
        native_path = str(native_path_obj)
        native_digest = _compute_native_library_digest(native_path)

        # The signature itself is produced by the in-tree Ed25519 kernel
        # (INVARIANT-1: no PyCA dependency), so the library does have to be
        # mapped here — and it is the very object whose digest does not match
        # the artefact being replaced.  unverified_load_for_signing() is the
        # narrowly-scoped, in-process opt-in for exactly that: it is entered
        # around this discovery call and nowhere else, so an ordinary import
        # in a process carrying the build environment is unaffected.  It is
        # revoked under secure-execution mode.
        with unverified_load_for_signing():
            native_lib = _find_native_library()
        if native_lib is None:
            raise RuntimeError(
                f"native library at {native_path} could not be loaded; the "
                "signing pipeline needs the in-tree Ed25519 kernel "
                "(INVARIANT-1: no PyCA dependency). Check the architecture, "
                "the SONAME and the library's own dependencies (ldd/otool)."
            )
        # The two discoveries must have agreed on the file: with the override
        # active nothing is digest-refused, so both select the first existing
        # candidate.  A disagreement would mean signing a digest for a
        # different object than the one just loaded, so it is an error rather
        # than a warning.
        from ama_cryptography.pqc_backends import _LOAD_DIAGNOSTICS as _LD

        loaded_path = _LD.get("path")
        if loaded_path and Path(loaded_path).resolve() != native_path_obj.resolve():
            raise RuntimeError(
                f"discovery disagreement: hashing {native_path} but loaded "
                f"{loaded_path}. Refusing to sign a digest for an object other "
                f"than the one this process is running."
            )
        # Bind the compiled binding extensions into the same signature (v3).
        # These load and execute before POST can
        # examine them, and the release pipeline ships them byte-identical to
        # the build (verified on the published v4.0.0 wheels: auditwheel and
        # delocate graft nothing — the library resolves in-package via
        # $ORIGIN/@loader_path — and Windows repair is disabled), so a
        # build-time digest is checkable at import time on every platform.
        # An artefact written without --bind-extensions carries an EMPTY map
        # (still v3): the message format stays schema-selected.  That is now
        # only reachable for a tree with no extensions to bind — both callers
        # pass the flag — because an empty map over a tree that HAS extensions
        # is the "present but not covered" state, not a neutral one.
        binding_digests = _compute_binding_digests(pkg_dir) if args.bind_extensions else {}
        signed_message = _composite_integrity_message_v3(digest, native_digest, binding_digests)

        seed_override = _load_hex_env_bytes(_INTEGRITY_SIGNING_SEED_ENV, 32)
        trusted_pubkey_env = _load_hex_env_bytes(_INTEGRITY_TRUST_ANCHOR_ENV, 32)
        pubkey, signature, anchor_source = _generate_keypair_and_sign(
            signed_message,
            seed_override=seed_override,
            trusted_pubkey=trusted_pubkey_env,
            require_trust_anchor=(
                args.require_trust_anchor or _env_flag_enabled(_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV)
            ),
            native_lib=native_lib,
        )
    except Exception as exc:
        # Catch every exception (RuntimeError, ctypes OSError, KeyboardInterrupt
        # excluded by the bare Exception base) so build pipelines see a stable
        # exit code 1 with a one-line cause instead of a Python traceback.
        # KeyboardInterrupt / SystemExit are intentionally NOT swallowed.
        print(
            f"ERROR: {exc}\n"
            "Refusing to write a signed-integrity artefact.  Build the "
            "native library first and, for anchored release builds, compile "
            "it with -DAMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX=<pubkey>.",
            file=sys.stderr,
        )
        return 1

    out_path = _write_signature_module(
        pkg_dir, digest, native_digest, binding_digests, pubkey, signature
    )
    print(
        f"Signed integrity artefact written: {out_path}\n"
        f"  digest        = {digest_hex}\n"
        f"  native digest = {native_digest.hex()}\n"
        f"  bindings      = {len(binding_digests)} extension(s) bound\n"
        f"  pubkey        = {pubkey.hex()}\n"
        f"  signature     = {signature.hex()[:32]}... (64 B)"
    )
    # Report the *actual* enforcement state — native-compiled anchor, env-var
    # anchor, or unanchored — so CI logs cannot mislead packagers about
    # whether the wheel they just produced is release-grade or developer-grade.
    if anchor_source == "native":
        print("  trust     = enforced by native AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX (CMake)")
    elif anchor_source == "env":
        print(f"  trust     = enforced by {_INTEGRITY_TRUST_ANCHOR_ENV} env var")
    else:
        print("  trust     = unanchored (developer build; per-build ephemeral key)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
