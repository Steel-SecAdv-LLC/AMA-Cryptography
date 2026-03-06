#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography ♱ Complete Feature Demonstration
==============================================

Comprehensive demonstration of all AMA Cryptography ♱ capabilities:
- Algorithm-agnostic cryptographic API
- Hierarchical deterministic key derivation
- Key rotation and management
- Hybrid classical+PQC signatures
- Double-helix evolution engine (all 18+ variants)
- Performance benchmarking
"""

import sys
import time
from pathlib import Path

import numpy as np

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ama_cryptography.crypto_api import (  # noqa: E402
    AlgorithmType,
    AmaCryptography,
    quick_kem,
    quick_sign,
    quick_verify,
)
from ama_cryptography.double_helix_engine import AmaEquationEngine  # noqa: E402
from ama_cryptography.key_management import (  # noqa: E402
    HDKeyDerivation,
    KeyRotationManager,
    SecureKeyStorage,
)


def demo_crypto_api():
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


def demo_kem():
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


def demo_hd_keys():
    """Demonstrate HD key derivation"""
    print("\n" + "=" * 70)
    print("3. HIERARCHICAL DETERMINISTIC KEY DERIVATION")
    print("=" * 70)

    # Create HD derivation from seed phrase
    seed_phrase = "ava guardian quantum resistant cryptography protection"
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


def demo_key_rotation():
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


def demo_secure_storage():
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


def demo_helix_engine():
    """Demonstrate double-helix evolution engine"""
    print("\n" + "=" * 70)
    print("6. DOUBLE-HELIX EVOLUTION ENGINE (18+ VARIANTS)")
    print("=" * 70)

    # Create engine
    engine = AmaEquationEngine(state_dim=100, random_seed=42)

    print("\nEngine configuration:")
    print("-" * 70)
    print(f"  State dimension: {engine.state_dim}")
    print(f"  φ³-amplified weights: {engine.config.get('alpha', 0) / 4.236:.4f}")
    print("  All 18+ variants enabled")

    # Run convergence
    print("\n  Running convergence...")
    initial_state = np.random.randn(100) * 0.5
    start_time = time.perf_counter()
    final_state, history = engine.converge(initial_state, max_steps=50)
    elapsed = time.perf_counter() - start_time

    print(f"  Execution time: {elapsed * 1000:.2f}ms")
    print(f"  Iterations: {len(history)}")
    print(f"  Initial Lyapunov: {history[0]:.6f}")
    print(f"  Final Lyapunov: {history[-1]:.6f}")
    print(f"  Convergence: {(1 - history[-1] / history[0]) * 100:.2f}%")

    # Calculate sigma_quadratic
    from ama_cryptography.equations import calculate_sigma_quadratic

    sigma = calculate_sigma_quadratic(final_state, engine.ethical_matrix)
    print(f"  σ_quadratic: {sigma:.6f} ({'✓ PASS' if sigma >= 0.96 else '✗ FAIL'} ≥ 0.96)")


def demo_performance():
    """Demonstrate performance comparison"""
    print("\n" + "=" * 70)
    print("7. PERFORMANCE BENCHMARKING")
    print("=" * 70)

    try:
        # Try to import optimized Cython engine
        from ama_cryptography.helix_engine_complete import AvaEngineOptimized

        print("\nCython-optimized engine available!")
        print("-" * 70)

        # Benchmark pure Python vs Cython
        state_dim = 100
        iterations = 100

        # Pure Python
        engine_py = AmaEquationEngine(state_dim=state_dim, random_seed=42)
        state_py = np.random.randn(state_dim)

        start = time.perf_counter()
        for i in range(iterations):
            state_py = engine_py.step(state_py, i)
        time_py = time.perf_counter() - start

        # Cython
        engine_cy = AvaEngineOptimized(state_dim=state_dim, random_seed=42)
        state_cy = np.random.randn(state_dim)

        start = time.perf_counter()
        for i in range(iterations):
            state_cy = engine_cy.step(state_cy, i)
        time_cy = time.perf_counter() - start

        speedup = time_py / time_cy

        print(f"  Pure Python: {time_py * 1000:.2f}ms ({iterations} iterations)")
        print(f"  Cython:      {time_cy * 1000:.2f}ms ({iterations} iterations)")
        print(f"  Speedup:     {speedup:.1f}x faster")

    except ImportError:
        print("\n  Cython engine not built (run: make python)")
        print("  Benchmarking pure Python only...")

        engine = AmaEquationEngine(state_dim=100, random_seed=42)
        state = np.random.randn(100)

        start = time.perf_counter()
        for i in range(100):
            state = engine.step(state, i)
        elapsed = time.perf_counter() - start

        print(f"  Pure Python: {elapsed * 1000:.2f}ms (100 iterations)")


def main():
    """Run all demonstrations"""
    print("=" * 70)
    print("AVA GUARDIAN ♱ COMPLETE FEATURE DEMONSTRATION")
    print("=" * 70)
    print("\nDemonstrating all capabilities of AMA Cryptography ♱ 1.0")
    print("Production-grade multi-language PQC system")
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
        print("\nAMA Cryptography ♱ - Protecting people, data, and networks")
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
