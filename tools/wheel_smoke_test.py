#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Release Wheel Smoke Test
===========================================

Runs against an **installed wheel**, inside the throwaway virtualenv that
``cibuildwheel`` creates after building each wheel.  It is the last gate a
binary artefact passes before it is signed and published, so it checks the
things that can only be wrong in a *packaged* build:

  * the native extension actually loaded on this platform/interpreter;
  * the power-on self test (signed-integrity check + KATs) passes;
  * no primitive silently degraded to a fallback backend (INVARIANT-7);
  * every shipped algorithm family round-trips, and rejects tampering.

INVARIANT-20 (constant-time AES) is deliberately *not* probed here: it is
enforced at CMake configure time, where a table-S-box build fails outright
unless ``-DAMA_AES_TABLE_INSECURE=ON`` is passed explicitly.  That is a
stronger guarantee than a runtime probe, and the C library's active AES
backend is not exposed through the Python API to assert against.

Why a script instead of ``python -c``
-------------------------------------
This used to be a ``python -c "..."`` one-liner embedded in a YAML folded
scalar (``>-``) in ``release.yml``.  Folding joined the block's lines with a
space, so the payload reaching the interpreter began with a space::

    python -c " import ama_cryptography as a; ..."
                ^
    IndentationError: unexpected indent

Every wheel on every platform built correctly and then failed that command,
and because ``release.yml`` only ran on a tag push nothing caught it until a
release was attempted.  An executable file has no quoting or folding layer
between what is written and what runs, and it can be executed locally, which
is the whole point.

Wheel-not-source guard
----------------------
The script deliberately refuses to run against a source checkout.  A smoke
test that imports the repository instead of the installed artefact reports
success for a wheel it never touched — the failure mode that makes a release
gate worse than no gate at all.

Usage
-----
    python tools/wheel_smoke_test.py

Exit status is ``0`` when every check passes and ``1`` otherwise, with the
failing check named on stderr.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

# NOTE: no import of anything in this repository.  The module under test must
# be the installed distribution, resolved through the normal import system.
#
# All three use the plain `import` form rather than mixing in `from ... import`
# (CodeQL py/import-and-import-from).  The top-level module object is needed
# anyway for the wheel-not-source guard, which reads its ``__file__``.
import ama_cryptography
import ama_cryptography.crypto_api as crypto_api
import ama_cryptography.pqc_backends as pqc_backends

_FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record one named assertion without aborting the remaining checks."""
    if condition:
        print(f"  ok    {name}")
        return
    suffix = f" — {detail}" if detail else ""
    print(f"  FAIL  {name}{suffix}")
    _FAILURES.append(f"{name}{suffix}")


def check_installed_not_source() -> None:
    """Fail if the imported package came from this repository, not a wheel.

    ``cibuildwheel`` runs the test command from a scratch directory with the
    wheel installed in a fresh virtualenv, so the only way the repository copy
    wins is a misconfiguration — exactly what this guard exists to surface.
    """
    module_file = getattr(ama_cryptography, "__file__", None)
    if module_file is None:
        check("package resolves to a real file", False, "__file__ is None")
        return

    module_dir = Path(module_file).resolve().parent
    repo_package = Path(__file__).resolve().parent.parent / "ama_cryptography"
    check(
        "imported from an installed distribution, not the source tree",
        module_dir != repo_package,
        f"imported {module_dir}, which is this repository's source package",
    )


def check_module_health() -> None:
    """Power-on self test must report OPERATIONAL with no failed sub-test."""
    status = ama_cryptography.module_status()
    check("power-on self test status is OPERATIONAL", status == "OPERATIONAL", f"status={status!r}")

    if status != "OPERATIONAL":
        reason = ama_cryptography.module_error_reason()
        print(f"        module_error_reason(): {reason!r}")

    # module_self_test_results() yields (name, passed, detail) triples, one per
    # power-on KAT.  Report the detail string for anything that did not pass —
    # "ML-KEM-1024 KAT failed" is actionable, a bare name is not.
    results = ama_cryptography.module_self_test_results()
    failed = [f"{name}: {detail}" for name, passed, detail in results if not passed]
    check(
        f"all {len(results)} power-on self tests passed",
        not failed,
        "; ".join(failed),
    )


def check_binding_extensions_are_bound() -> None:
    """A release wheel must ship the EXACT binding extensions it signed.

    Since 5.0.0 the six Cython binding extensions are digest-bound into the v3
    integrity artefact, so this is checkable — and it needs checking, because
    the thing that breaks it is a post-signing step in the packaging pipeline,
    which no unit test can see.  The 5.0.0 release dry run found precisely
    that: `delocate-wheel` runs after the signer on macOS and rewrites each
    extension's Mach-O load commands, so all five bindings in the macOS wheels
    mismatched their signed digests.

    An import failure would surface it too — the pre-import gate refuses a
    mismatch outright — but this states the requirement instead of relying on
    a side effect, and it distinguishes "mismatch" (tampering or a rewriting
    build step) from "uncovered" (the wheel was built without
    `--bind-extensions`), which are different pipeline faults with different
    fixes.
    """
    results = ama_cryptography.module_self_test_results()
    integrity = [detail for name, _passed, detail in results if name == "integrity"]
    check("the POST integrity stage ran", bool(integrity), "no integrity stage in the results")
    if not integrity:
        return

    detail = integrity[0]
    check(
        "no binding extension mismatches its signed digest",
        "MISMATCH" not in detail,
        detail,
    )
    # "PARTIALLY covered" is the developer-tree wording; a release wheel is an
    # anchored build and must be fully covered.
    check(
        "every shipped binding extension is covered by the signature",
        "PARTIALLY covered" not in detail and "not covered by the signed artefact" not in detail,
        detail,
    )
    # Parse the COUNT, not the sentence.  `_check_binding_extensions` returns
    # f"{len(binding_digests)} binding extension(s) verified", so an artefact
    # that binds nothing yields "0 binding extension(s) verified" — which
    # contains the substring this used to test for.  The two checks above pass
    # on that string too ("MISMATCH" absent, "PARTIALLY covered" absent), so all
    # three assertions were green for a wheel whose integrity artefact covered
    # no extension at all: exactly the "the wheel was built without
    # --bind-extensions" pipeline fault this function's docstring claims to
    # distinguish from a mismatch.
    bound = _bound_extension_count(detail)
    check(
        "the artefact binds at least one binding extension",
        bound is not None and bound > 0,
        f"expected a non-zero verified-bindings count; got: {detail}",
    )


_BOUND_COUNT_RE = re.compile(r"(?<!\d)(\d+)\s+binding extension\(s\) verified")


def _bound_extension_count(detail: str) -> int | None:
    """The integer in ``"<n> binding extension(s) verified"``, or None.

    None means the sentence is absent or unparseable, which the caller treats
    as a failure — a smoke test that cannot read the count must not pass.
    """
    match = _BOUND_COUNT_RE.search(detail)
    return int(match.group(1)) if match else None


def check_integrity_anchoring() -> None:
    """A canonical-repository release must ship an ANCHORED wheel (audit H3).

    An anchored wheel compiles a long-lived trust-anchor public key into the
    native library; the import-time integrity check then requires the
    signature's key to equal it, so re-signing edited ``.py`` files with an
    attacker-chosen key no longer verifies.  An unanchored wheel is signed with
    a per-build ephemeral key and is self-referential — tamper-evident against
    accidental corruption, not against a re-sign.

    ``release.yml`` sets ``AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR`` iff the
    trust-anchor variable is configured, and cibuildwheel forwards it into the
    test environment, so it is the honest signal for "this build was meant to be
    anchored".  Forks legitimately build unanchored, so anchoring is ENFORCED
    only when that flag is set; otherwise the status is reported and allowed.

    When the flag IS set, the build-time signer already refuses to emit an
    unanchored artefact — this check is a second, independent confirmation that
    the anchor actually reached the compiled ``.so`` (a forward-to-signer-only
    bug would leave the signature anchored and the library not), which is the
    property audit H3 is about.

    ``ama_cryptography._self_test`` is a submodule of the INSTALLED wheel under
    test, not a source-tree import; its ``_load_integrity_trust_anchor`` is the
    same resolver POST and the signer consult, so reusing it (and the module's
    own env-flag semantics) cannot drift from what the wheel itself enforces.
    """
    # Deferred to call time (the module under test must have completed its own
    # import, POST included, before this runs) and spelled as a submodule
    # ``import`` rather than ``from ama_cryptography import _self_test``:
    # module scope already binds ``ama_cryptography`` with a plain ``import``,
    # and mixing the two forms for one module is CodeQL's
    # py/import-and-import-from (the class swept with alert 647).
    import ama_cryptography._self_test as _self_test

    anchor_hex, error = _self_test._load_integrity_trust_anchor()
    anchored = anchor_hex is not None and error is None
    required = _self_test._env_flag_enabled(_self_test._INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV)

    status = "ANCHORED" if anchored else "unanchored (per-build ephemeral key)"
    print(f"        integrity trust anchor: {status}" + (f" — {error}" if error else ""))

    if required:
        check(
            "release wheel is anchored to a long-lived trust anchor",
            anchored,
            error
            or "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR is set but the compiled library carries no anchor",
        )
    else:
        # Off the canonical path unanchored is allowed, but the status must be
        # READABLE — a resolver error (a malformed anchor, a library that could
        # not answer) is a real fault even when anchoring is not required.
        check(
            "integrity anchor status is readable (unanchored allowed off the canonical repo)",
            error is None,
            error or "",
        )


def check_no_fallback_backends() -> None:
    """INVARIANT-7: a shipped wheel must not degrade to a fallback backend.

    Every ``*_AVAILABLE`` flag must be true and every ``*_BACKEND`` must name a
    compiled implementation (``native`` or ``cython``).  ``None`` is the value
    the package uses when a primitive could not be loaded, which in a released
    wheel means the native library did not build for this platform.
    """
    compiled = {"native", "cython"}
    unavailable: list[str] = []
    degraded: list[str] = []

    for name in sorted(dir(pqc_backends)):
        if name.startswith("__"):
            continue
        value = getattr(pqc_backends, name)
        if name.endswith("_AVAILABLE") and value is not True:
            unavailable.append(f"{name}={value!r}")
        elif name.endswith("_BACKEND") and value not in compiled:
            degraded.append(f"{name}={value!r}")

    check("every primitive reports available", not unavailable, "; ".join(unavailable))
    check("every backend is compiled (native/cython)", not degraded, "; ".join(degraded))


def check_ml_kem() -> None:
    """ML-KEM-1024 (FIPS 203): encapsulation and decapsulation must agree."""
    kem = crypto_api.KyberProvider()
    keypair = kem.generate_keypair()
    encapsulated = kem.encapsulate(keypair.public_key)
    recovered = kem.decapsulate(encapsulated.ciphertext, keypair.secret_key)
    check("ML-KEM-1024 shared secrets agree", encapsulated.shared_secret == recovered)

    # Implicit rejection (FIPS 203 §6.3): a corrupted ciphertext must not
    # yield the original secret.  It is not required to raise — the standard
    # mandates a deterministic *different* secret — so compare, don't catch.
    corrupted = bytearray(encapsulated.ciphertext)
    corrupted[0] ^= 0xFF
    rejected = kem.decapsulate(bytes(corrupted), keypair.secret_key)
    check("ML-KEM-1024 rejects a corrupted ciphertext", rejected != encapsulated.shared_secret)


def check_x25519() -> None:
    """X25519 (RFC 7748): both sides must derive the same shared secret."""
    alice_public, alice_secret = pqc_backends.native_x25519_keypair()
    bob_public, bob_secret = pqc_backends.native_x25519_keypair()
    check(
        "X25519 key agreement is symmetric",
        pqc_backends.native_x25519_key_exchange(alice_secret, bob_public)
        == pqc_backends.native_x25519_key_exchange(bob_secret, alice_public),
    )


def check_signatures() -> None:
    """FIPS 204 / FIPS 205 / RFC 8032 signatures: sign, verify, reject tamper."""
    message = b"ama-cryptography release wheel smoke test"

    for label, provider in (
        ("ML-DSA-65", crypto_api.MLDSAProvider()),
        ("SLH-DSA", crypto_api.SphincsProvider()),
        ("Ed25519", crypto_api.Ed25519Provider()),
    ):
        keypair = provider.generate_keypair()
        signed = provider.sign(message, keypair.secret_key)
        check(
            f"{label} verifies its own signature",
            provider.verify(message, signed.signature, keypair.public_key),
        )
        check(
            f"{label} rejects a modified message",
            not provider.verify(message + b"!", signed.signature, keypair.public_key),
        )

        forged = bytearray(signed.signature)
        forged[0] ^= 0xFF
        check(
            f"{label} rejects a modified signature",
            not provider.verify(message, bytes(forged), keypair.public_key),
        )


def check_aes_gcm() -> None:
    """AES-256-GCM (SP 800-38D): round-trip plus authentication-tag rejection."""
    aead = crypto_api.AESGCMProvider()
    key = ama_cryptography.secure_token_bytes(32)
    plaintext = b"ama-cryptography release wheel smoke test"
    aad = b"release-gate"

    sealed = aead.encrypt(plaintext, key, aad=aad)
    opened = aead.decrypt(sealed["ciphertext"], key, sealed["nonce"], sealed["tag"], aad=aad)
    check("AES-256-GCM round-trips", opened == plaintext)

    # The provider names the implementation that served the call.  A wheel that
    # fell back to a pure-Python path would say so here, and must not ship.
    backend = sealed.get("backend")
    check(
        "AES-256-GCM ran on the compiled backend",
        isinstance(backend, str) and backend.startswith("native"),
        f"backend={backend!r}",
    )

    corrupted = bytearray(sealed["ciphertext"])
    corrupted[0] ^= 0xFF
    try:
        aead.decrypt(bytes(corrupted), key, sealed["nonce"], sealed["tag"], aad=aad)
    except ValueError:
        check("AES-256-GCM rejects a corrupted ciphertext", True)
    else:
        check(
            "AES-256-GCM rejects a corrupted ciphertext",
            False,
            "decrypt() returned instead of raising",
        )


def check_chacha20_poly1305() -> None:
    """ChaCha20-Poly1305 (RFC 8439): round-trip plus tag rejection."""
    key = ama_cryptography.secure_token_bytes(32)
    nonce = ama_cryptography.secure_token_bytes(12)
    plaintext = b"ama-cryptography release wheel smoke test"
    aad = b"release-gate"

    ciphertext, tag = pqc_backends.native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
    opened = pqc_backends.native_chacha20poly1305_decrypt(key, nonce, ciphertext, tag, aad)
    check("ChaCha20-Poly1305 round-trips", opened == plaintext)

    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0xFF
    try:
        pqc_backends.native_chacha20poly1305_decrypt(key, nonce, bytes(corrupted), tag, aad)
    # Any refusal is acceptable here; silently returning plaintext is not, so
    # the except clause is deliberately broad and the else branch is the fail.
    except Exception:
        check("ChaCha20-Poly1305 rejects a corrupted ciphertext", True)
    else:
        check(
            "ChaCha20-Poly1305 rejects a corrupted ciphertext",
            False,
            "decrypt returned instead of raising",
        )


def check_secp256k1() -> None:
    """RFC 6979 determinism, a verifying signature, and the zero-key refusal.

    The zero-key case is not a formality. Until this release the private-key
    range check was written as

        bad = (1 ^ sc_from_bytes(&d, key)) | sc_is_zero(&d);

    whose two calls are only indeterminately sequenced (C11 6.5.2.2p10), so a
    right-to-left evaluator read ``d`` before the key was loaded into it. On
    MSVC that rejected valid keys AND signed successfully under an all-zero
    key. No Linux or macOS lane could see it, because gcc and clang evaluate
    left to right. A smoke test that only signs and verifies would have
    shipped it, so the refusal is checked here explicitly.
    """
    print("secp256k1 ECDSA")
    digest = pqc_backends.native_sha256(b"ama-cryptography release wheel smoke test")
    privkey = pqc_backends.native_sha256(b"smoke-test private key seed")
    signature = pqc_backends.native_secp256k1_ecdsa_sign(digest, privkey)
    check(
        "secp256k1: RFC 6979 signing is deterministic",
        signature == pqc_backends.native_secp256k1_ecdsa_sign(digest, privkey),
        "two signatures over the same (key, digest) differ",
    )
    pubkey = pqc_backends.native_secp256k1_pubkey_decompress(
        pqc_backends.native_secp256k1_pubkey_from_privkey(privkey)
    )
    check(
        "secp256k1: the signature verifies under its own public key",
        pqc_backends.native_secp256k1_ecdsa_verify(signature, digest, pubkey),
    )
    try:
        pqc_backends.native_secp256k1_ecdsa_sign(digest, b"\x00" * 32)
    except (RuntimeError, ValueError):
        check("secp256k1: an all-zero private key is refused", True)
    else:
        check(
            "secp256k1: an all-zero private key is refused",
            False,
            "signing succeeded with d = 0 — the scalar range check is reading "
            "the wrong bytes (see the sequencing note in src/c/ama_secp256k1.c)",
        )


def check_private_storage_is_owner_only() -> None:
    """The key store and the nonce ledger must be owner-only in the WHEEL.

    ``0o600`` is a POSIX sentence: on Windows ``os.chmod`` toggles the
    read-only attribute and nothing else, ``mkdir(mode=...)`` is ignored, and
    ``os.fchmod`` does not exist -- so a store created under a profile root
    inherited that root's ACEs. ``ama_cryptography._owner_only`` states the
    property once and enforces it per platform, and this reads the
    enforcement back off files the installed package actually created, rather
    than trusting that the source tree's unit tests covered the shipped
    artefact.
    """
    print("private storage")
    from ama_cryptography import _owner_only
    from ama_cryptography.key_management import SecureKeyStorage
    from ama_cryptography.monitoring import NonceTracker

    check(
        "owner-only access is enforceable on this platform",
        _owner_only.is_enforceable(),
        "the key store and nonce ledger would be left at whatever the parent " "directory grants",
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        store_dir = root / "keystore"
        store = SecureKeyStorage(store_dir, "wheel smoke test passphrase")
        store.store_key("smoke", b"\x01" * 32)
        check(
            "the key store retrieves what it stored",
            store.retrieve_key("smoke") == b"\x01" * 32,
        )
        expected_dir = _owner_only.expected_owner_only_description(directory=True)
        actual_dir = _owner_only.access_description(store_dir)
        check(
            "the key store directory is owner-only",
            actual_dir == expected_dir,
            f"access is {actual_dir}, expected {expected_dir}",
        )

        ledger = root / "nonces.dat"
        tracker = NonceTracker(persist_path=str(ledger))
        check(
            "the nonce ledger records a fresh nonce",
            tracker.check_and_record(b"smoke", b"\x00" * 12) is None,
        )
        check(
            "the nonce ledger detects reuse",
            tracker.check_and_record(b"smoke", b"\x00" * 12) is not None,
        )
        check(
            "the nonce ledger survives a restart",
            NonceTracker(persist_path=str(ledger)).check_and_record(b"smoke", b"\x00" * 12)
            is not None,
        )
        expected_file = _owner_only.expected_owner_only_description()
        actual_file = _owner_only.access_description(ledger)
        check(
            "the nonce ledger is owner-only",
            actual_file == expected_file,
            f"access is {actual_file}, expected {expected_file}",
        )


def check_control_flow_integrity() -> None:
    """Every shipped ELF object must carry the architecture's CFI marking.

    CMakeLists.txt compiles the library with ``-fcf-protection=full`` (x86:
    IBT + shadow stack) or ``-mbranch-protection=standard`` (AArch64: BTI +
    PAC-RET), and setup.py now gives the binding extensions the same flags.
    Both are probed, both fail soft, and a wheel built by a toolchain that
    silently dropped them is indistinguishable from a correct one -- unless
    something reads the built object.  That is this check.

    Only what the platform can actually carry is required: the GNU property
    note is an ELF construct, so this is a no-op on macOS and Windows.
    """
    if not sys.platform.startswith("linux"):
        print("  SKIP  control-flow integrity (GNU property notes are ELF-only)")
        return
    readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
    if readelf is None:
        print("  SKIP  control-flow integrity (no readelf on PATH)")
        return

    machine = platform.machine().lower()
    wanted: tuple[str, ...]
    if machine in ("x86_64", "amd64"):
        wanted, label = ("IBT", "SHSTK"), "x86 CET (IBT + SHSTK)"
    elif machine in ("aarch64", "arm64"):
        wanted, label = ("BTI",), "AArch64 BTI"
    else:
        print(f"  SKIP  control-flow integrity (no CFI marking defined for {machine})")
        return

    package_dir = Path(ama_cryptography.__file__).parent
    objects = sorted(package_dir.glob("*.so")) + sorted(package_dir.glob("*.so.*"))
    objects = [obj for obj in objects if not obj.is_symlink()]
    check(
        "control-flow integrity: there are ELF objects to inspect",
        bool(objects),
        f"{package_dir} contains no .so files",
    )
    for obj in objects:
        try:
            out = subprocess.run(
                [readelf, "-nW", str(obj)], capture_output=True, text=True, timeout=120
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
            check(f"control-flow integrity: {obj.name} readable", False, str(exc))
            continue
        missing = [token for token in wanted if token not in out]
        check(
            f"control-flow integrity: {obj.name} carries {label}",
            not missing,
            f"missing {missing} from the GNU property note; the toolchain dropped "
            f"the CFI flag for this object",
        )


def main() -> int:
    print("=" * 70)
    print("AMA Cryptography — release wheel smoke test")
    print("=" * 70)
    print(f"  version      {ama_cryptography.__version__}")
    print(f"  interpreter  {sys.version.split()[0]} ({sys.implementation.name})")
    print(f"  platform     {sys.platform}")
    print(f"  package      {getattr(ama_cryptography, '__file__', '<unknown>')}")
    print("-" * 70)

    # Each group runs even if an earlier one raised.  A wheel that is broken
    # enough to throw is usually broken in more than one place, and seeing all
    # of it beats re-running the release to discover the next fault.
    for group in (
        check_installed_not_source,
        check_module_health,
        check_binding_extensions_are_bound,
        check_integrity_anchoring,
        check_no_fallback_backends,
        check_ml_kem,
        check_x25519,
        check_signatures,
        check_aes_gcm,
        check_chacha20_poly1305,
        check_secp256k1,
        check_private_storage_is_owner_only,
        check_control_flow_integrity,
    ):
        try:
            group()
        # Broad by design: an exception from a check IS a failed check, and a
        # release gate that lets one escape uncaught reports fewer faults than
        # the wheel actually has.
        except Exception as exc:
            print(f"  FAIL  {group.__name__} raised {type(exc).__name__}: {exc}")
            _FAILURES.append(f"{group.__name__} raised {type(exc).__name__}: {exc}")
            traceback.print_exc()

    print("-" * 70)
    if _FAILURES:
        print(f"SMOKE TEST FAILED — {len(_FAILURES)} check(s) did not pass:", file=sys.stderr)
        for failure in _FAILURES:
            print(f"  * {failure}", file=sys.stderr)
        print(
            "\nThis wheel must not be signed or published.  A failure here means the"
            "\nbinary artefact is broken on this platform even though it built.",
            file=sys.stderr,
        )
        return 1

    print("SMOKE TEST PASSED — wheel is fit to sign and publish.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
