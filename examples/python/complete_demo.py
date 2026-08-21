#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Complete Feature Demonstration
==============================================

Comprehensive demonstration of all AMA Cryptography capabilities:
- Algorithm-agnostic cryptographic API
- Hierarchical deterministic key derivation
- Key rotation and management
- Hybrid classical+PQC signatures
- Double-helix evolution engine (all 18+ variants)
- Performance benchmarking

.. warning::

   **DEMONSTRATION CODE — NOT FOR PRODUCTION USE.**

   This walkthrough favours a single readable script over safe operations:

   * ``master_password="strong_master_password_123!"`` is hardcoded; a real
     deployment must source the passphrase from an operator prompt, a secrets
     manager, or an HSM.
   * The key store is created inside a temporary directory that is deleted on
     exit — keys created here are unrecoverable by design.
   * The double-helix / 3R sections are **non-cryptographic** analytics and
     must not be relied on for any security property (see the module
     docstring of ``ama_cryptography.double_helix_engine``).

   See ``IMPLEMENTATION_GUIDE.md`` before adapting any of this for real use.
"""

import sys
import time
from importlib.util import find_spec
from pathlib import Path
from typing import Any


def _make_stdio_encodable() -> None:
    """Stop a legacy output encoding from killing the demo mid-run.

    This script prints check/cross verdicts and Greek letters in its labels. On
    Windows, Python uses the *locale* encoding — cp1252 on a default install —
    for stdout whenever it is redirected rather than attached to a console, so
    a user doing ``python complete_demo.py > out.txt``, or any CI job capturing
    the output, got::

        UnicodeEncodeError: 'charmap' codec can't encode character '\\u2713'

    part-way through, followed by a *second* traceback from the ``except``
    handler trying to print ``✗`` with the same encoder.  The demo died
    somewhere in the middle with two stack traces and no summary.

    Reconfiguring to UTF-8 fixes the redirected case outright and is a no-op on
    a console, which Python already drives as UTF-8 on Windows.  ``errors``
    falls back to ``replace`` so that a stream which genuinely cannot represent
    a character degrades to ``?`` rather than aborting: a demo that prints a
    slightly wrong glyph has still demonstrated something, and one that raises
    has not.

    Deliberately done here rather than by setting ``PYTHONUTF8=1`` in CI. The
    environment variable would make the *test* pass while leaving the defect
    in place for every user who runs the script by hand.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - non-TextIOWrapper stream
            # Not a ``TextIOWrapper``: a ``StringIO``, a binary stream, or a
            # sink installed by a harness.  None of those has an encoding to
            # change, and none of them raises ``UnicodeEncodeError`` from a
            # console redirect, which is the only failure this function exists
            # to prevent.  Nothing to do and nothing to report.
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except ValueError:  # pragma: no cover - closed or detached stream
            # Measured, not guessed: ``ValueError`` is the *only* exception
            # this call raises, and only for a stream that is already closed
            # ("I/O operation on closed file") or detached ("underlying buffer
            # has been detached").  An earlier revision also caught ``OSError``
            # and retried as ``reconfigure(errors="replace")``; neither was
            # reachable — ``OSError`` never occurs, and the retry hits the same
            # closed stream for the same reason, so it was dead code ending in
            # a silent ``pass``.
            #
            # Continuing is the right answer rather than a shrug: a closed
            # stream cannot carry output at all — the next ``print`` to it
            # fails on the stream, not on the encoding — so there is nothing to
            # preserve and no working channel to report through.  Continuing
            # also keeps the demo usable when only *one* of the two streams was
            # closed by a harness, which is the single case where this branch
            # changes anything.
            continue


_make_stdio_encodable()

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# numpy is optional here, and deliberately so.
#
# ama_cryptography has zero runtime dependencies — its numerics live in
# ama_cryptography._numeric — so a shipped example that fails at import on a
# clean install is not demonstrating the library, it is demonstrating a
# dependency the library does not have. numpy is nevertheless the array type
# most callers arrive with, and AmaEquationEngine accepts it, so when it *is*
# installed this demo uses it: that way the ndarray path is exercised by
# running the example rather than only asserted about in a test.
try:
    import numpy as np

    HAVE_NUMPY = True
except ImportError:  # pragma: no cover - exercised on installs without numpy
    np = None  # type: ignore[assignment]
    HAVE_NUMPY = False

from ama_cryptography import _numeric
from ama_cryptography.crypto_api import (
    AlgorithmType,
    AmaCryptography,
    quick_kem,
    quick_sign,
    quick_verify,
)
from ama_cryptography.double_helix_engine import AmaEquationEngine
from ama_cryptography.key_management import (
    HDKeyDerivation,
    KeyRotationManager,
    SecureKeyStorage,
)


def random_state(size: int, scale: float = 1.0, seed: int = 0) -> Any:
    """Build a random state vector, preferring numpy when it is installed.

    Returns a ``numpy.ndarray`` where numpy is available and an
    ``ama_cryptography._numeric.Vec`` otherwise.  ``AmaEquationEngine`` accepts
    either, which is the point of returning whichever one is to hand instead of
    converting.
    """
    if HAVE_NUMPY:
        return np.random.default_rng(seed).standard_normal(size) * scale
    _numeric.random.seed(seed)
    return _numeric.random.randn(size) * scale


def array_backend_name() -> str:
    """Name the array type this run is feeding the engine."""
    return f"numpy.ndarray (numpy {np.__version__})" if HAVE_NUMPY else "_numeric.Vec"


def demo_crypto_api() -> None:
    """Demonstrate algorithm-agnostic crypto API"""
    print("\n" + "=" * 70)
    print("1. ALGORITHM-AGNOSTIC CRYPTOGRAPHIC API")
    print("=" * 70)

    # Test different algorithms
    algorithms = [
        (AlgorithmType.ED25519, "Ed25519 (Classical)"),
        (AlgorithmType.ML_DSA_65, "ML-DSA-65 (Post-Quantum)"),
        (AlgorithmType.HYBRID_SIG, "Hybrid (Ed25519 + ML-DSA-65)"),
    ]

    message = b"AMA Cryptography protects people, data, and networks!"

    for algorithm, name in algorithms:
        print(f"\n{name}:")
        print("-" * 70)

        try:
            # Quick sign and verify
            keypair, signature = quick_sign(message, algorithm=algorithm)

            print(f"  Public key size:  {len(keypair.public_key)} bytes")
            print(f"  Secret key size:  {len(keypair.secret_key)} bytes")
            print(f"  Signature size:   {len(signature.signature)} bytes")

            # Verify
            valid = quick_verify(
                message, signature.signature, keypair.public_key, algorithm=algorithm
            )

            print(f"  Signature valid:  {'✓ PASS' if valid else '✗ FAIL'}")

            # Try to verify with wrong message
            wrong_msg = b"Wrong message"
            invalid = quick_verify(
                wrong_msg, signature.signature, keypair.public_key, algorithm=algorithm
            )

            print(f"  Wrong msg rejects: {'✓ PASS' if not invalid else '✗ FAIL'}")

        except Exception as e:
            print(f"  Error: {e}")


def demo_kem() -> None:
    """Demonstrate key encapsulation"""
    print("\n" + "=" * 70)
    print("2. KEY ENCAPSULATION MECHANISM (KEM)")
    print("=" * 70)

    try:
        # Generate keypair and encapsulate
        keypair, encapsulated = quick_kem(algorithm=AlgorithmType.KYBER_1024)

        print("\nKyber-1024 KEM:")
        print("-" * 70)
        print(f"  Public key size:    {len(keypair.public_key)} bytes")
        print(f"  Ciphertext size:    {len(encapsulated.ciphertext)} bytes")
        print(f"  Shared secret size: {len(encapsulated.shared_secret)} bytes")

        # Decapsulate
        crypto = AmaCryptography(algorithm=AlgorithmType.KYBER_1024)
        recovered_secret = crypto.decapsulate(encapsulated.ciphertext, keypair.secret_key)

        # Verify shared secrets match
        match = crypto.constant_time_compare(encapsulated.shared_secret, recovered_secret)

        print(f"  Shared secret match: {'✓ PASS' if match else '✗ FAIL'}")

    except Exception as e:
        print(f"  Error: {e}")


def demo_hd_keys() -> None:
    """Demonstrate HD key derivation"""
    print("\n" + "=" * 70)
    print("3. HIERARCHICAL DETERMINISTIC KEY DERIVATION")
    print("=" * 70)

    # Create HD derivation from seed phrase
    seed_phrase = "ama cryptography quantum resistant cryptography protection"
    hd = HDKeyDerivation(seed_phrase=seed_phrase)

    print(f'\nSeed phrase: "{seed_phrase}"')
    print("-" * 70)

    # Derive keys for different purposes
    purposes = [
        ("m/44'/0'/0'/0/0", "First signing key"),
        ("m/44'/0'/0'/0/1", "Second signing key"),
        ("m/44'/0'/1'/0/0", "First encryption key"),
        ("m/44'/1'/0'/0/0", "Alternative purpose key"),
    ]

    for path, description in purposes:
        key, chain = hd.derive_path(path)
        print(f"  {description:30s} {path:20s} -> {key.hex()[:32]}...")

    # Demonstrate determinism
    print("\n  Verification (same seed phrase produces same keys):")
    hd2 = HDKeyDerivation(seed_phrase=seed_phrase)
    key1, _ = hd.derive_path("m/44'/0'/0'/0/0")
    key2, _ = hd2.derive_path("m/44'/0'/0'/0/0")
    print(f"  Keys match: {'✓ PASS' if key1 == key2 else '✗ FAIL'}")


def demo_key_rotation() -> None:
    """Demonstrate key rotation"""
    print("\n" + "=" * 70)
    print("4. KEY ROTATION AND LIFECYCLE MANAGEMENT")
    print("=" * 70)

    from datetime import timedelta

    # Create rotation manager
    rotation_mgr = KeyRotationManager(rotation_period=timedelta(days=90))

    print("\nRegistering keys:")
    print("-" * 70)

    # Register multiple key versions
    key1 = rotation_mgr.register_key(
        "signing-key-v1", "signing", max_usage=1000, expires_in=timedelta(days=30)
    )
    print(f"  Registered: {key1.key_id} (version {key1.version})")

    key2 = rotation_mgr.register_key("signing-key-v2", "signing", parent_id="signing-key-v1")
    print(f"  Registered: {key2.key_id} (version {key2.version})")

    print(f"\n  Active key: {rotation_mgr.get_active_key()}")

    # Simulate usage
    for i in range(5):
        rotation_mgr.increment_usage("signing-key-v1")

    print(f"  Usage count: {rotation_mgr.keys['signing-key-v1'].usage_count}")

    # Check if rotation needed
    should_rotate = rotation_mgr.should_rotate("signing-key-v1")
    print(f"  Should rotate: {should_rotate}")

    # Perform rotation
    print("\n  Initiating rotation...")
    rotation_mgr.initiate_rotation("signing-key-v1", "signing-key-v2")
    print(f"  New active key: {rotation_mgr.get_active_key()}")
    print(f"  Old key status: {rotation_mgr.keys['signing-key-v1'].status.name}")

    # Complete rotation
    rotation_mgr.complete_rotation("signing-key-v1")
    print(f"  Rotation complete: {rotation_mgr.keys['signing-key-v1'].status.name}")


def demo_secure_storage() -> None:
    """Demonstrate secure key storage"""
    print("\n" + "=" * 70)
    print("5. SECURE KEY STORAGE")
    print("=" * 70)

    import secrets
    import tempfile

    # Create temporary storage
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = SecureKeyStorage(Path(tmpdir), master_password="strong_master_password_123!")

        print(f"\nStorage path: {tmpdir}")
        print("-" * 70)

        # Generate and store keys
        keys_to_store = {
            "master-signing-key": secrets.token_bytes(32),
            "master-encryption-key": secrets.token_bytes(32),
            "backup-key": secrets.token_bytes(64),
        }

        for key_id, key_data in keys_to_store.items():
            storage.store_key(
                key_id, key_data, metadata={"size": len(key_data), "purpose": "demonstration"}
            )
            print(f"  Stored: {key_id} ({len(key_data)} bytes)")

        # Retrieve and verify
        print("\n  Retrieving keys:")
        all_match = True
        for key_id, original_key in keys_to_store.items():
            retrieved_key = storage.retrieve_key(key_id)
            matches = retrieved_key == original_key
            all_match = all_match and matches
            print(f"    {key_id}: {'✓ MATCH' if matches else '✗ MISMATCH'}")

        print(f"\n  All keys verified: {'✓ PASS' if all_match else '✗ FAIL'}")

        # Clean up
        for key_id in keys_to_store.keys():
            storage.delete_key(key_id)

        print("  Cleanup: ✓ All keys securely deleted")


def demo_helix_engine() -> None:
    """Demonstrate double-helix evolution engine"""
    print("\n" + "=" * 70)
    print("6. DOUBLE-HELIX EVOLUTION ENGINE (18+ VARIANTS)")
    print("=" * 70)

    # Create engine
    engine = AmaEquationEngine(state_dim=100, random_seed=42)

    from ama_cryptography.equations import PHI_CUBED

    print("\nEngine configuration:")
    print("-" * 70)
    print(f"  State dimension: {engine.state_dim}")
    # Read the weight off the engine, not off `config`.  `config` holds only
    # the *overrides* a caller passed, so on a default-constructed engine it is
    # empty and `config.get("alpha", 0)` reported the φ³ amplification of every
    # default build as 0.0000.
    print(f"  α (purity) weight: {engine.alpha:.4f} = {engine.alpha / PHI_CUBED:.4f} × φ³")
    print("  All 18+ variants enabled")

    # Run convergence.  The engine takes a numpy.ndarray, an _numeric.Vec, or
    # any 1-D array-like of state_dim numbers and normalises it on entry; the
    # returned state is always a Vec.
    print(f"\n  Running convergence (initial state: {array_backend_name()})...")
    initial_state = random_state(100, scale=0.5, seed=42)
    start_time = time.perf_counter()
    final_state, history = engine.converge(initial_state, max_steps=50)
    elapsed = time.perf_counter() - start_time

    print(f"  Execution time: {elapsed * 1000:.2f}ms")
    print(f"  Iterations: {len(history)}")
    print(f"  Initial Lyapunov: {history[0]:.6f}")
    print(f"  Final Lyapunov: {history[-1]:.6f}")
    # State the direction rather than printing a "convergence %" that goes
    # negative.  With the default GA weights the exploration terms dominate and
    # V rises; converge() detects that (V̇ > 0), rolls the step back and stops,
    # which is the honest outcome for this configuration and not a failure.
    delta = (history[-1] - history[0]) / history[0] * 100 if history[0] else 0.0
    direction = "fell" if delta < 0 else "rose"
    print(f"  Lyapunov {direction} {abs(delta):.2f}% over {len(history)} step(s)")
    if delta > 0:
        print("    (default weights are exploration-dominated; converge() stops")
        print("     on the first V̇ > 0 after its five-step warm-up)")

    if HAVE_NUMPY:
        # Round-trip back to the caller's array type.
        as_array = np.asarray(final_state)
        print(f"  numpy.asarray(final_state): shape={as_array.shape} dtype={as_array.dtype}")

    # Calculate sigma_quadratic
    from ama_cryptography.equations import calculate_sigma_quadratic

    sigma = calculate_sigma_quadratic(final_state, engine.ethical_matrix)
    print(f"  σ_quadratic: {sigma:.6f} ({'✓ PASS' if sigma >= 0.96 else '✗ FAIL'} ≥ 0.96)")


def _pure_matrix_vector(matrix: Any, vector: Any) -> list[float]:
    """A naive pure-Python matrix-vector product.

    The speed baseline for the Cython kernel below.  numpy's ``@`` is BLAS and
    would flatter nothing, so the honest "what does compiling this buy you"
    figure is measured against Python; numpy stays only the *correctness*
    oracle.
    """
    rows, cols = matrix.shape
    result = [0.0] * rows
    for i in range(rows):
        row = matrix[i]
        acc = 0.0
        for j in range(cols):
            acc += float(row[j]) * float(vector[j])
        result[i] = acc
    return result


def demo_performance() -> None:
    """The pure-Python engine, and the Cython kernels that actually ship."""
    print("\n" + "=" * 70)
    print("7. PERFORMANCE BENCHMARKING")
    print("=" * 70)

    # Section subject: AmaEquationEngine.step runs in pure Python.  Time it.
    engine = AmaEquationEngine(state_dim=100, random_seed=42)
    state = random_state(100, seed=1)
    start = time.perf_counter()
    for i in range(100):
        state = engine.step(state, i)
    time_engine = time.perf_counter() - start
    print(
        f"\n  AmaEquationEngine.step (pure Python): "
        f"{time_engine * 1000:.2f}ms over 100 iterations"
    )

    # The Cython acceleration this project ships is the `math_engine` extension,
    # which `make python` builds.  An earlier draft of this demo probed
    # `helix_engine_complete` instead — a reference source the default build
    # does not compile — so its "run: make python" hint could never take effect.
    # Report the extension that actually ships, and, when it and numpy are both
    # present, show a real Cython-vs-pure-Python figure on a kernel it
    # implements, checked against numpy before it is quoted so the number cannot
    # drift from the computation it describes.
    if find_spec("ama_cryptography.math_engine") is None:
        print("  math_engine Cython kernels:           not built (run `make python`)")
        return
    if not HAVE_NUMPY:
        print("  math_engine Cython kernels:           built (install numpy to benchmark them)")
        return

    from ama_cryptography import math_engine

    rng = np.random.default_rng(7)
    matrix = rng.standard_normal((160, 160))
    vector = rng.standard_normal(160)

    cython_result = math_engine.matrix_vector_multiply(matrix, vector)
    if not np.allclose(cython_result, matrix @ vector, rtol=0, atol=1e-9):
        print(
            "  math_engine.matrix_vector_multiply:   built, but disagreed with "
            "the reference product — not timed"
        )
        return

    iterations = 40
    start = time.perf_counter()
    for _ in range(iterations):
        math_engine.matrix_vector_multiply(matrix, vector)
    time_cython = time.perf_counter() - start
    start = time.perf_counter()
    for _ in range(iterations):
        _pure_matrix_vector(matrix, vector)
    time_pure = time.perf_counter() - start
    print(f"  math_engine.matrix_vector_multiply:   built; 160x160 @ vector x{iterations}")
    print(
        f"    Cython {time_cython * 1000:.2f}ms  vs  pure Python "
        f"{time_pure * 1000:.2f}ms  ->  {time_pure / time_cython:.1f}x"
    )


def main() -> int:
    """Run all demonstrations"""
    print("=" * 70)
    print("AMA CRYPTOGRAPHY COMPLETE FEATURE DEMONSTRATION")
    print("=" * 70)
    from ama_cryptography import __version__

    print(f"\nDemonstrating all capabilities of AMA Cryptography {__version__}")
    print("Production-grade multi-language PQC system")
    print(f"Array backend for the math demos: {array_backend_name()}")
    print()

    try:
        demo_crypto_api()
        demo_kem()
        demo_hd_keys()
        demo_key_rotation()
        demo_secure_storage()
        demo_helix_engine()
        demo_performance()

        print("\n" + "=" * 70)
        print("✓ ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print("\nAMA Cryptography - Protecting people, data, and networks")
        print("with quantum-resistant cryptography and ethical AI")
        print()

    except Exception as e:
        print(f"\n✗ Error during demonstration: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
