#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Benchmark Runner
================================

Performance regression detection for CI/CD pipelines.
Compares current performance against baseline.json and fails if
any benchmark regresses more than the configured threshold.

Usage:
    python benchmarks/benchmark_runner.py [--verbose]

Refreshing a baseline is deliberately NOT a flag on this runner.
`--update-baseline` used to be accepted here and then ignored — the parsed value
was never read, so a maintainer recalibrating floors saw a normal green run and
believed baseline.json had been rewritten.  Baselines are edited by hand, and
every changed line needs a justification entry that
`benchmarks/check_baseline_justification.py` enforces; an automatic write-back
would route around that gate.

Exit codes:
    0 - All benchmarks within acceptable range
    1 - Performance regression detected (>10% slower than baseline)
    2 - Error running benchmarks
"""

import argparse
import json
import os
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    description: str
    ops_per_second: float
    baseline_value: float
    tolerance_percent: float
    regression_percent: float
    passed: bool
    optional: bool = False


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline configuration from JSON file."""
    with open(baseline_path) as f:
        return cast(Dict[str, Any], json.load(f))


_RUNNER_CLASS_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "arm64": "aarch64",
    "aarch64": "aarch64",
}


def normalize_runner_cpu_class(value: str) -> str:
    """Normalize common runner architecture spellings for baseline matching."""
    return _RUNNER_CLASS_ALIASES.get(value.strip().lower(), value.strip().lower())


def validate_baseline_contract(
    baseline: Dict[str, Any],
    baseline_path: Path,
    expected_runner_cpu_class: str = "",
    require_populated_baseline: bool = False,
) -> None:
    """Validate baseline metadata before benchmark comparisons run."""
    metadata = baseline.get("metadata", {})
    actual = normalize_runner_cpu_class(str(metadata.get("runner_cpu_class", "")))
    expected = normalize_runner_cpu_class(expected_runner_cpu_class)
    if expected:
        if not actual:
            raise ValueError(
                f"{baseline_path} is missing metadata.runner_cpu_class; "
                f"expected {expected_runner_cpu_class!r}"
            )
        if actual != expected:
            raise ValueError(
                f"{baseline_path} targets runner_cpu_class={actual!r}, "
                f"but this runner is {expected!r}"
            )

    if not require_populated_baseline:
        return

    zero_entries = []
    for section in ("benchmarks", "pqc_benchmarks"):
        for name, entry in baseline.get(section, {}).items():
            if entry.get("baseline_value") == 0:
                zero_entries.append(name)
    if zero_entries:
        joined = ", ".join(sorted(zero_entries))
        raise ValueError(f"{baseline_path} contains unpopulated zero baselines: {joined}")


#: Minimum wall-clock a single timed batch must span, in seconds.
#:
#: The per-call ``iterations`` defaults (20-100) were chosen per primitive and
#: are three orders of magnitude apart in cost, so they bought wildly different
#: amounts of signal: 20 ML-DSA-65 signatures is about 6 ms of measurement, and
#: the whole 19-benchmark suite finished in roughly 0.4 s of wall clock on the
#: CI runner.  On a shared, unpinned GitHub-hosted runner a single scheduler
#: preemption is larger than that, so the reported number was dominated by
#: whatever else the host was doing.  Observed directly: three consecutive runs
#: of one unchanged binary measured 917, 1845 and 3086 ops/sec for
#: ``dilithium_sign`` -- a 3.4x spread with the code held constant, against a
#: 10% regression threshold.  A gate whose noise exceeds its threshold by 34x
#: cannot fail for the reason it claims to, which is the failure mode
#: ``tests/test_benchmark_baseline_freshness.py`` was written about.
#:
#: Batches are therefore sized from a calibration run rather than fixed, so
#: every primitive gets a comparable amount of signal regardless of its cost.
_MIN_SAMPLE_SECONDS = 0.15

#: Timed batches per benchmark; the fastest is reported.
#:
#: Throughput noise on a shared runner is one-sided -- interference can only
#: make an operation look slower, never faster -- so the fastest of several
#: batches is the best available estimate of the machine's actual capability
#: and is far more stable than the mean.  This is the estimator
#: ``benchmark_operation_best_of`` already applied to the two composite
#: package benchmarks; it is now what every benchmark gets.
_ROUNDS = 3

#: Ceiling on a calibrated batch, so a primitive that gets much faster cannot
#: turn the benchmark job into a long-running one.
_MAX_ITERATIONS = 500_000

#: Distinct inputs cycled through by benchmarks of rejection-sampled
#: primitives (see ``_cycle``).
_INPUT_POOL = 256


def _cycle(items: "List[Any]") -> Callable[[], Any]:
    """Return a callable that yields ``items`` round-robin, one per call.

    ML-DSA-65 signing is FIPS 204's *deterministic* variant here (rnd = 0), so
    for a fixed (key, message) pair the rejection-loop count — and therefore
    the running time — is a constant, not a random variable.  A benchmark that
    signs one fixed message under one per-process keypair measures the luck of
    that single pair: across six runs of this suite on the ubuntu-24.04-arm CI
    runner, ``dilithium_sign`` reported 1,396 to 7,474 ops/sec (a 5.35x
    spread) while every non-rejection-sampled primitive on the same runs
    agreed within 3%.  ``full_package_create`` carries the same signature
    inside it and showed the same bimodality (2,701 vs 5,481).

    Cycling a pool of distinct inputs makes every timed batch average over
    ``_INPUT_POOL`` independent draws of the rejection count, so the reported
    number converges on the *expected* signing rate — the quantity a
    regression floor can meaningfully be set against.  The per-call cost of
    the cycling itself is two attribute loads and an integer increment,
    negligible against the >100 us primitives it is applied to.
    """
    n = len(items)
    state = {"i": 0}

    def next_item() -> Any:
        i = state["i"]
        state["i"] = (i + 1) % n
        return items[i]

    return next_item


def _timed_batch(operation: Callable[[], object], iterations: int) -> tuple[float, float]:
    """One timed batch, as ``(operations_per_second, elapsed_seconds)``."""
    start = time.perf_counter()
    for _ in range(iterations):
        operation()
    elapsed = time.perf_counter() - start
    ops = iterations / elapsed if elapsed > 0 else float("inf")
    return ops, elapsed


#: Hard stop on re-sizing, so a pathological operation cannot loop forever.
_MAX_SIZING_ATTEMPTS = 12


def _required_batch(rate: float) -> int:
    """Iterations needed to span ``_MIN_SAMPLE_SECONDS`` at ``rate`` ops/sec."""
    if rate <= 0.0 or rate == float("inf"):
        return 1
    return min(_MAX_ITERATIONS, max(1, int(rate * _MIN_SAMPLE_SECONDS) + 1))


def benchmark_operation(
    operation: Callable[[], object],
    iterations: int = 100,
    warmup: int = 5,
    rounds: int = _ROUNDS,
) -> float:
    """
    Benchmark an operation and return operations per second.

    ``iterations`` is a *floor*, not the batch size.  Batches are sized to span
    at least ``_MIN_SAMPLE_SECONDS`` at the fastest rate observed so far, so a
    cheap primitive gets many more iterations than an expensive one and both
    are measured over a comparable window.  ``rounds`` full-window batches are
    run and the fastest is reported (see ``_ROUNDS``).

    The target is recomputed after *every* batch rather than from one
    up-front calibration.  Sizing once is not enough in either direction: a
    calibration that lands during interference reports a low rate and sizes
    the next batch too small, and — the subtler case — a batch that is slow
    because it was unlucky satisfies the elapsed-time target with very few
    iterations, so the undersized batch would then be reused for every
    remaining round.  Keying the target off the fastest rate seen recovers
    from both, because throughput noise is one-sided: interference can only
    make an operation look slower than it is, never faster.

    Only full-window batches are eligible to be reported.  An undersized
    batch can report a lucky-high rate off a very short window, and since the
    baselines this feeds are *floors*, an inflated number makes the gate
    weaker — so those batches inform sizing and nothing else.

    Args:
        operation: Callable to benchmark
        iterations: Minimum iterations per timed batch
        warmup: Number of warmup iterations (not counted)
        rounds: Full-window batches to run; the fastest is reported

    Returns:
        Operations per second
    """
    for _ in range(warmup):
        operation()

    batch = max(1, iterations)
    observed = 0.0  # fastest rate seen anywhere, used only for sizing
    best = 0.0  # fastest rate seen at a full-window batch, reported
    completed = 0
    for _attempt in range(rounds + _MAX_SIZING_ATTEMPTS):
        if completed >= rounds:
            break
        ops, _elapsed = _timed_batch(operation, batch)
        if ops == float("inf"):
            return ops
        observed = max(observed, ops)
        target = _required_batch(observed)
        if batch >= target:
            best = max(best, ops)
            completed += 1
        else:
            # Grow toward the target, capped at 8x a step so one wild
            # extrapolation cannot jump straight to _MAX_ITERATIONS.
            batch = min(_MAX_ITERATIONS, max(batch + 1, min(target, batch * 8)))
            completed = 0
            best = 0.0

    return best if best > 0.0 else observed


def benchmark_operation_best_of(
    operation: Callable[[], object],
    iterations: int,
    warmup: int,
    rounds: int,
) -> float:
    """Benchmark latency-spiky composite operations and keep the fastest round.

    Retained because callers and tests name it directly.  ``benchmark_operation``
    now takes the fastest of several batches for every benchmark, so this adds
    only the caller's explicit round count on top of that.
    """
    measurements = [
        benchmark_operation(operation, iterations=iterations, warmup=warmup) for _ in range(rounds)
    ]
    return max(measurements)


def run_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark AMA native C SHA3-256 hashing (FIPS 202)."""
    from ama_cryptography.pqc_backends import native_sha3_256

    data = b"A" * 1024  # 1KB data

    def operation() -> None:
        native_sha3_256(data)

    return benchmark_operation(operation, iterations)


def run_hmac_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark HMAC-SHA3-256 using project's own implementation."""
    from ama_cryptography.legacy_compat import hmac_authenticate

    key = secrets.token_bytes(32)
    data = b"A" * 1024

    def operation() -> None:
        hmac_authenticate(data, key)

    return benchmark_operation(operation, iterations)


def run_ed25519_keygen_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 key generation using native C backend."""
    from ama_cryptography.legacy_compat import generate_ed25519_keypair

    def operation() -> None:
        generate_ed25519_keypair()

    return benchmark_operation(operation, iterations)


def run_ed25519_sign_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 signing using native C backend."""
    from ama_cryptography.legacy_compat import ed25519_sign, generate_ed25519_keypair

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10

    def operation() -> None:
        ed25519_sign(message, keypair.private_key)

    return benchmark_operation(operation, iterations)


def run_ed25519_verify_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 verification using native C backend."""
    from ama_cryptography.legacy_compat import (
        ed25519_sign,
        ed25519_verify,
        generate_ed25519_keypair,
    )

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10
    signature = ed25519_sign(message, keypair.private_key)

    def operation() -> None:
        ed25519_verify(message, signature, keypair.public_key)

    return benchmark_operation(operation, iterations)


def run_hkdf_derive_benchmark(iterations: int = 100) -> float:
    """Benchmark HKDF key derivation using native C backend."""
    from ama_cryptography.pqc_backends import native_hkdf

    master_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    info = b"benchmark-test"

    def operation() -> None:
        native_hkdf(master_secret, 96, salt, info)

    return benchmark_operation(operation, iterations)


def run_full_package_create_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package creation (4-layer, hybrid signature).

    Measures :func:`ama_cryptography.crypto_api.create_crypto_package` — the
    shipped flagship API — under a long-lived signing identity
    (:class:`~ama_cryptography.crypto_api.KeypairCache`), which mirrors the
    agent flow the API documents and keeps the workload comparable to the
    pre-4.0.0 benchmark that reused one KMS across calls.  The deprecated
    ``legacy_compat`` shim this used to time emitted a ``DeprecationWarning``
    per call and measured a code path new integrations are told not to take.

    Package creation embeds an ML-DSA-65 signature, so the content is cycled
    for the same reason ``run_dilithium_sign_benchmark`` cycles its message
    (see ``_cycle``): with deterministic signing, one fixed (key, content)
    pair pins one rejection count, and the benchmark measures that pair's
    luck instead of the expected rate.
    """
    from ama_cryptography.crypto_api import (
        CryptoPackageConfig,
        KeypairCache,
        create_crypto_package,
    )

    cache = KeypairCache()
    public_key, secret_key = cache.get_or_generate()
    config = CryptoPackageConfig(signing_keypair=(public_key, secret_key))
    base = b"Benchmark package content " * 8
    next_content = _cycle([base + i.to_bytes(2, "big") for i in range(_INPUT_POOL)])

    def operation() -> None:
        create_crypto_package(next_content(), config)

    return benchmark_operation_best_of(operation, iterations, warmup=2, rounds=5)


def run_full_package_verify_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package verification (4-layer, anchored).

    Measures :func:`ama_cryptography.crypto_api.verify_crypto_package` with
    ``expected_public_key`` supplied, so the timed path is the one 4.0.0
    callers must take for ``all_valid`` to mean anything (the unanchored form
    caps the result at ``core_valid``).  Verification is deterministic — no
    rejection sampling — so a fixed package is the right fixture.
    """
    from ama_cryptography.crypto_api import (
        CryptoPackageConfig,
        KeypairCache,
        create_crypto_package,
        verify_crypto_package,
    )

    cache = KeypairCache()
    public_key, secret_key = cache.get_or_generate()
    config = CryptoPackageConfig(signing_keypair=(public_key, secret_key))
    content = b"Benchmark package content for verification " * 4
    package = create_crypto_package(content, config)

    def operation() -> None:
        verify_crypto_package(content, package, expected_public_key=public_key)

    return benchmark_operation(operation, iterations, warmup=2)


def run_dilithium_keygen_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 key generation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        def operation() -> None:
            generate_dilithium_keypair()

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_sign_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 signing via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        # Deterministic signing makes the rejection count a constant per
        # (key, message) pair — cycle distinct messages so the batch averages
        # over the rejection distribution instead of sampling one pair's luck
        # (see _cycle).
        base = b"Test message for ML-DSA-65 signing" * 10
        next_message = _cycle([base + i.to_bytes(2, "big") for i in range(_INPUT_POOL)])

        def operation() -> None:
            dilithium_sign(next_message(), kp.secret_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_verify_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 verification via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        message = b"Test message for ML-DSA-65 signing" * 10
        signature = dilithium_sign(message, kp.secret_key)

        def operation() -> None:
            dilithium_verify(message, signature, kp.public_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_kyber_keygen_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-KEM-1024 key pair generation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
        )

        if not KYBER_AVAILABLE:
            return None

        def operation() -> None:
            generate_kyber_keypair()

        return benchmark_operation(operation, iterations, warmup=2)
    except Exception:
        return None


def run_kyber_encapsulate_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-KEM-1024 encapsulation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_encapsulate,
        )

        if not KYBER_AVAILABLE:
            return None

        kp = generate_kyber_keypair()

        def operation() -> None:
            kyber_encapsulate(kp.public_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except Exception:
        return None


def run_aes_gcm_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark AES-256-GCM encryption of 1KB data via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024)
        aad = b"benchmark-aad"

        # Probe once — native_aes256_gcm_encrypt raises RuntimeError if unavailable.
        native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        def operation() -> None:
            native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_chacha20poly1305_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark ChaCha20-Poly1305 encryption of 1KB data via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_chacha20poly1305_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024)
        aad = b"benchmark-aad"

        # Probe once — native_chacha20poly1305_encrypt raises RuntimeError if unavailable.
        native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)

        def operation() -> None:
            native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_x25519_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark X25519 key exchange (scalar mult) via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        scalar = secrets.token_bytes(32)
        point = secrets.token_bytes(32)

        # Probe once — native_x25519_key_exchange raises RuntimeError if unavailable.
        native_x25519_key_exchange(scalar, point)

        def operation() -> None:
            native_x25519_key_exchange(scalar, point)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_x25519_batch4_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark X25519 batch-4 DH via native_x25519_scalarmult_batch.

    Reports the per-batch (count=4) ops/sec, NOT the per-op rate.  A
    canonical-host run that yields ~13K single-shot ops/sec should
    yield ~12.5K batch-of-4 ops/sec under the default dispatch policy
    (the batch is four sequential scalar ladders plus the wrapper's
    per-batch overhead — wrapper overhead is what brings batch-of-4
    throughput slightly under single-shot, NOT a regression).  A
    significantly slower number typically means the AVX2 4-way kernel
    was accidentally selected as the default; that is a regression on
    every shipped Broadwell+/Zen+ part (see PR #273 design note).
    """
    try:
        from ama_cryptography.pqc_backends import (
            _X25519_NATIVE_AVAILABLE,
            _native_lib,
            native_x25519_scalarmult_batch,
        )

        if (
            _native_lib is None
            or not _X25519_NATIVE_AVAILABLE
            or not hasattr(_native_lib, "ama_x25519_scalarmult_batch")
        ):
            return None

        scalars = [secrets.token_bytes(32) for _ in range(4)]
        points = [secrets.token_bytes(32) for _ in range(4)]

        # Probe once to trip availability checks before timing.
        native_x25519_scalarmult_batch(scalars, points)

        def operation() -> None:
            native_x25519_scalarmult_batch(scalars, points)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


# secp256k1 field prime p — used to decompress a SEC1 compressed public key
# (0x02/0x03 || X, what native_secp256k1_pubkey_from_privkey returns) into the
# 64-byte X||Y form ama_secp256k1_ecdsa_verify expects.
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_BENCH_PRIVKEY = bytes.fromhex(
    "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0"
)
_SECP256K1_BENCH_DIGEST = bytes(range(1, 33))


def _secp256k1_uncompressed_pubkey(privkey: bytes) -> bytes:
    """Return the 64-byte uncompressed (X||Y) public key for ``privkey``.

    The native pubkey export is 33-byte SEC1 *compressed*; recover Y from X via
    the curve equation (secp256k1's p ≡ 3 mod 4, so the modular square root is a
    single exponentiation) and pick the parity the compression prefix encodes.
    """
    from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

    compressed = native_secp256k1_pubkey_from_privkey(privkey)
    prefix, x_bytes = compressed[0], compressed[1:]
    x = int.from_bytes(x_bytes, "big")
    alpha = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    y = pow(alpha, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if (y & 1) != (prefix & 1):
        y = _SECP256K1_P - y
    return x_bytes + y.to_bytes(32, "big")


def run_secp256k1_ecdsa_sign_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark secp256k1 ECDSA signing (RFC 6979 deterministic) via native C."""
    try:
        from ama_cryptography.pqc_backends import (
            _SECP256K1_NATIVE_AVAILABLE,
            native_secp256k1_ecdsa_sign,
        )

        if not _SECP256K1_NATIVE_AVAILABLE:
            return None

        # Probe once — surfaces any availability error before timing.
        native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)

        def operation() -> None:
            native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_secp256k1_ecdsa_verify_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark secp256k1 ECDSA verification via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            _SECP256K1_NATIVE_AVAILABLE,
            native_secp256k1_ecdsa_sign,
            native_secp256k1_ecdsa_verify,
        )

        if not _SECP256K1_NATIVE_AVAILABLE:
            return None

        signature = native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)
        pubkey = _secp256k1_uncompressed_pubkey(_SECP256K1_BENCH_PRIVKEY)

        # Probe once — confirms the fixture verifies before timing.
        native_secp256k1_ecdsa_verify(signature, _SECP256K1_BENCH_DIGEST, pubkey)

        def operation() -> None:
            native_secp256k1_ecdsa_verify(signature, _SECP256K1_BENCH_DIGEST, pubkey)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_all_benchmarks(baseline: Dict[str, Any], verbose: bool = False) -> List[BenchmarkResult]:
    """Run all benchmarks and compare against baseline."""
    results = []
    threshold = baseline["thresholds"]["regression_threshold_percent"]

    benchmark_functions: dict[str, Callable[[], Optional[float]]] = {
        "ama_sha3_256_hash": run_sha3_256_benchmark,
        "hmac_sha3_256": run_hmac_sha3_256_benchmark,
        "ed25519_keygen": run_ed25519_keygen_benchmark,
        "ed25519_sign": run_ed25519_sign_benchmark,
        "ed25519_verify": run_ed25519_verify_benchmark,
        "hkdf_derive": run_hkdf_derive_benchmark,
        "full_package_create": run_full_package_create_benchmark,
        "full_package_verify": run_full_package_verify_benchmark,
        # secp256k1 ECDSA sign/verify are HARD-gated (core, not the soft PQC
        # loop): the signing path (RFC 6979 nonce + base-point ladder + Fermat
        # inversion mod n) and the verify path (two scalar mults + canonical-
        # pubkey + curve checks). A regression in the ECDSA-specific scalar
        # arithmetic fails the build, not merely warns — the pubkey ladder the C
        # reporting harness covered is not enough. They return None only on a
        # build without native secp256k1 (never the benchmark CI job, which is
        # AMA_USE_NATIVE_PQC=ON); the None-skip below handles that gracefully.
        "secp256k1_ecdsa_sign": run_secp256k1_ecdsa_sign_benchmark,
        "secp256k1_ecdsa_verify": run_secp256k1_ecdsa_verify_benchmark,
    }

    pqc_benchmark_functions: dict[str, Callable[[], Optional[float]]] = {
        "dilithium_keygen": run_dilithium_keygen_benchmark,
        "dilithium_sign": run_dilithium_sign_benchmark,
        "dilithium_verify": run_dilithium_verify_benchmark,
        "kyber_keygen": run_kyber_keygen_benchmark,
        "kyber_encapsulate": run_kyber_encapsulate_benchmark,
        "aes_256_gcm_encrypt": run_aes_gcm_benchmark,
        "chacha20poly1305_encrypt": run_chacha20poly1305_benchmark,
        "x25519_scalarmult": run_x25519_benchmark,
        # PR #277, Devin review #10: x25519_scalarmult_batch4 pins the
        # batch wrapper's throughput so a future change that flips the
        # AVX2 4-way kernel to default-on is caught by CI rather than
        # silently regressing per-batch latency.
        "x25519_scalarmult_batch4": run_x25519_batch4_benchmark,
    }

    # Run standard benchmarks
    for name, func in benchmark_functions.items():
        if name not in baseline["benchmarks"]:
            continue

        config = baseline["benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        ops_per_sec = func()
        # A core benchmark whose primitive is genuinely absent from this build
        # (returns None) is skipped rather than crashing the run. The shipped
        # core benchmarks never return None; this only spares an ECDSA/secp256k1
        # entry on a non-native-PQC build. In the benchmark CI job (always
        # AMA_USE_NATIVE_PQC=ON) the number is present and hard-gated below.
        if ops_per_sec is None:
            if verbose:
                print("SKIPPED (primitive not available in this build)")
            continue

        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        # Calculate percent change from baseline.
        # Positive = faster than baseline, negative = slower than baseline.
        # When baseline_value is 0 ("first run on this runner class — record
        # current measurement as the new baseline"), there is no prior
        # number to regress against, so report the recorded value as a
        # PASS rather than dividing by zero.
        if baseline_value == 0:
            pct_change = 0.0
        else:
            pct_change = ((ops_per_sec - baseline_value) / baseline_value) * 100
        # Only fail on regressions (slower).  Improvements always pass.
        regression = -pct_change  # positive = slower
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
            )
        )

        if verbose:
            status = "PASS" if passed else "FAIL"
            print(f"{ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    # Run PQC benchmarks (optional)
    for name, pqc_func in pqc_benchmark_functions.items():
        if name not in baseline.get("pqc_benchmarks", {}):
            continue

        config = baseline["pqc_benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        pqc_ops_per_sec = pqc_func()

        if pqc_ops_per_sec is None:
            if verbose:
                print("SKIPPED (PQC not available)")
            continue

        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        # Same baseline_value==0 first-run guard as the core benchmark loop:
        # avoid ZeroDivisionError when seeding a fresh runner-class baseline.
        if baseline_value == 0:
            pct_change = 0.0
        else:
            pct_change = ((pqc_ops_per_sec - baseline_value) / baseline_value) * 100
        regression = -pct_change
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=pqc_ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
                optional=True,
            )
        )

        if verbose:
            status = "PASS" if passed else "WARN"
            print(f"{pqc_ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    return results


def generate_report(results: List[BenchmarkResult]) -> Dict[str, Any]:
    """Generate a JSON report of benchmark results."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed and not r.optional),
            "warnings": sum(1 for r in results if not r.passed and r.optional),
        },
        "results": [
            {
                "name": r.name,
                "description": r.description,
                "ops_per_second": round(r.ops_per_second, 2),
                "baseline_value": r.baseline_value,
                "regression_percent": round(r.regression_percent, 2),
                "tolerance_percent": r.tolerance_percent,
                "passed": r.passed,
                "optional": r.optional,
            }
            for r in results
        ],
    }


def generate_markdown_report(results: List[BenchmarkResult], report: Dict[str, Any]) -> str:
    """Generate a markdown report with tables and bar chart."""
    lines = []
    lines.append("# Benchmark Regression Report")
    lines.append("")
    lines.append(f"**Timestamp:** {report['timestamp']}")
    summary = report["summary"]
    lines.append(
        f"**Results:** {summary['passed']}/{summary['total']} passed, "
        f"{summary['failed']} failed, {summary['warnings']} warnings"
    )
    lines.append("")

    # Results table
    lines.append("## Results")
    lines.append("")
    lines.append("| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |")
    lines.append("|-----------|--------:|---------:|------:|----------:|--------|")
    for r in results:
        status = "PASS" if r.passed else ("WARN" if r.optional else "**FAIL**")
        lines.append(
            f"| {r.description} | {r.ops_per_second:,.0f} | {r.baseline_value:,.0f} "
            f"| {r.regression_percent:+.1f}% | {r.tolerance_percent:.0f}% | {status} |"
        )
    lines.append("")

    # ASCII bar chart
    if results:
        lines.append("## Throughput Comparison")
        lines.append("")
        lines.append("```")
        max_ops = max(r.ops_per_second for r in results) if results else 1
        max_label = max(len(r.name) for r in results)
        bar_width = 40
        for r in results:
            bar_len = int((r.ops_per_second / max_ops) * bar_width) if max_ops > 0 else 0
            bar = "\u2588" * bar_len
            marker = " " if r.passed else " !"
            lines.append(f"{r.name:>{max_label}} |{marker}{bar} {r.ops_per_second:,.0f}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AMA Cryptography Benchmark Runner - Performance Regression Detection"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).parent / "baseline.json",
        help="Path to baseline.json file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write JSON report",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--require-runner-class",
        default=os.environ.get("AMA_RUNNER_CPU_CLASS", ""),
        help=(
            "Require baseline metadata.runner_cpu_class to match this runner "
            "(defaults to AMA_RUNNER_CPU_CLASS when set)."
        ),
    )
    parser.add_argument(
        "--require-populated-baseline",
        action="store_true",
        help="Fail if any selected baseline_value is zero.",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        help="Path to write markdown report with tables and charts",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("AMA CRYPTOGRAPHY - BENCHMARK REGRESSION DETECTION")
    print("=" * 60)
    print()

    # Load baseline
    try:
        baseline = load_baseline(args.baseline)
        validate_baseline_contract(
            baseline,
            args.baseline,
            expected_runner_cpu_class=args.require_runner_class,
            require_populated_baseline=args.require_populated_baseline,
        )
        print(f"Loaded baseline: {args.baseline}")
        print(f"Regression threshold: {baseline['thresholds']['regression_threshold_percent']}%")
        print()
    except Exception as e:
        print(f"ERROR: Failed to load baseline: {e}")
        return 2

    # Run benchmarks
    print("Running benchmarks...")
    print("-" * 60)

    try:
        results = run_all_benchmarks(baseline, verbose=args.verbose)
    except Exception as e:
        print(f"ERROR: Benchmark execution failed: {e}")
        import traceback

        traceback.print_exc()
        return 2

    print("-" * 60)
    print()

    # Generate report
    report = generate_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to: {args.output}")

    if args.markdown:
        md = generate_markdown_report(results, report)
        with open(args.markdown, "w") as f:
            f.write(md)
        print(f"Markdown report written to: {args.markdown}")

    # Summary
    summary = report["summary"]
    print("SUMMARY")
    print(f"  Total benchmarks: {summary['total']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Warnings (optional): {summary['warnings']}")
    print()

    # Check for failures
    failed = [r for r in results if not r.passed and not r.optional]

    if failed:
        print("REGRESSION DETECTED!")
        print("-" * 60)
        for r in failed:
            print(f"  {r.name}: {r.regression_percent:+.1f}% (threshold: {r.tolerance_percent}%)")
        print()
        print("CI will fail due to performance regression.")
        return 1

    print("All benchmarks within acceptable range.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
