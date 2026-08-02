#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Basic Usage Example
===================================

Quick start guide demonstrating core cryptographic operations:
- Signing and verifying messages
- Key generation and management
- Creating protected data packages

This example requires minimal setup and shows the most common use cases.

Usage:
    python basic_usage.py

Requirements:
    pip install cryptography
    # Optional: build native C library for quantum-resistant signatures

.. warning::

   **DEMONSTRATION CODE — NOT FOR PRODUCTION USE.**

   This example is written for readability, not for deployment.  Specifically:

   * ``master_password="your_secure_password_here"`` is a hardcoded literal.
     Production code must take the passphrase from an operator prompt, a
     secrets manager, or an HSM — never from source.
   * Generated keypairs are ephemeral and are discarded when the process
     exits; no key backup, escrow, or rotation policy is applied.
   * No access control, rate limiting, or audit logging is performed around
     the cryptographic operations.

   See ``IMPLEMENTATION_GUIDE.md`` for production key-management guidance and
   ``SECURITY.md`` for the supported deployment posture.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def example_1_simple_signing():
    """
    Example 1: Simple Message Signing

    Sign a message with Ed25519 (classical) or ML-DSA-65 (quantum-resistant).
    """
    print("\n" + "=" * 60)
    print("Example 1: Simple Message Signing")
    print("=" * 60)

    from ama_cryptography.crypto_api import (
        AlgorithmType,
        quick_sign,
        quick_verify,
    )

    # Your message to sign
    message = b"Hello, AMA Cryptography! Protect my data."

    # Sign with Ed25519 (always available)
    keypair, signature = quick_sign(message, algorithm=AlgorithmType.ED25519)

    print(f"\nMessage: {message.decode()}")
    print("Algorithm: Ed25519")
    print(f"Public key: {keypair.public_key.hex()[:32]}...")
    print(f"Signature: {signature.signature.hex()[:32]}...")

    # Verify the signature
    is_valid = quick_verify(
        message,
        signature.signature,
        keypair.public_key,
        algorithm=AlgorithmType.ED25519,
    )
    print(f"Signature valid: {is_valid}")

    # Try quantum-resistant signing if available
    try:
        keypair_pqc, signature_pqc = quick_sign(message, algorithm=AlgorithmType.ML_DSA_65)
        print("\nQuantum-resistant (ML-DSA-65) also available!")
        print(f"PQC signature size: {len(signature_pqc.signature)} bytes")
    except Exception as e:
        print(f"\nNote: PQC not available ({e})")
        print("Build native C library for quantum resistance.")


def example_2_key_management():
    """
    Example 2: Key Management

    Generate, store, and rotate cryptographic keys securely.
    """
    print("\n" + "=" * 60)
    print("Example 2: Key Management")
    print("=" * 60)

    import secrets
    import tempfile
    from datetime import timedelta

    from ama_cryptography.key_management import (
        HDKeyDerivation,
        KeyRotationManager,
        SecureKeyStorage,
    )

    # HD Key Derivation - derive multiple keys from one seed
    print("\n--- HD Key Derivation ---")
    seed_phrase = "my secure seed phrase for key derivation"
    hd = HDKeyDerivation(seed_phrase=seed_phrase)

    # Derive keys for different purposes
    signing_key, _ = hd.derive_path("m/44'/0'/0'/0/0")
    encryption_key, _ = hd.derive_path("m/44'/0'/0'/0/1")

    print(f"Signing key:    {signing_key.hex()[:32]}...")
    print(f"Encryption key: {encryption_key.hex()[:32]}...")

    # Key Rotation - manage key lifecycle
    print("\n--- Key Rotation ---")
    rotation_mgr = KeyRotationManager(rotation_period=timedelta(days=90))

    rotation_mgr.register_key("key-v1", "signing", max_usage=1000)
    rotation_mgr.register_key("key-v2", "signing")

    print(f"Active key: {rotation_mgr.get_active_key()}")

    # Simulate rotation
    rotation_mgr.initiate_rotation("key-v1", "key-v2")
    print(f"After rotation: {rotation_mgr.get_active_key()}")

    # Secure Storage - encrypt keys at rest
    print("\n--- Secure Storage ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = SecureKeyStorage(
            Path(tmpdir),
            master_password="your_secure_password_here",
        )

        # Store a key
        test_key = secrets.token_bytes(32)
        storage.store_key("my-key", test_key, metadata={"purpose": "demo"})
        print("Key stored securely")

        # Retrieve the key
        retrieved = storage.retrieve_key("my-key")
        print(f"Key retrieved: {retrieved == test_key}")


def example_3_data_protection():
    """
    Example 3: Complete Data Protection

    Create a cryptographically protected package with multiple security layers.
    """
    print("\n" + "=" * 60)
    print("Example 3: Complete Data Protection")
    print("=" * 60)

    from ama_cryptography.crypto_api import (
        CryptoPackageConfig,
        create_crypto_package,
        verify_crypto_package,
    )

    # Your sensitive data.  The package API works on bytes, so encode whatever
    # record format you already have — JSON, protobuf, CBOR, plain text.
    sensitive_data = b"Patient ID: 12345, Diagnosis: Confidential"

    # Create protected package.  create_crypto_package() generates the signing
    # keypair, the HMAC key and the HKDF material itself and returns them on
    # the result; pass `signing_keypair` to use one you already hold.
    print("\nCreating protected package...")
    package = create_crypto_package(
        sensitive_data,
        config=CryptoPackageConfig(
            include_timestamp=False,  # True requests an RFC 3161 token. AMA
            # verifies the §2.4.2 message-imprint binding only — not the TSA's
            # signature or certificate chain — so it is not third-party
            # attestation, and verify_crypto_package() does not check it.
        ),
    )

    signing_key = package.keypairs["HYBRID_SIG"]

    print("\nPackage created:")
    print(f"  Layer 1  content hash (SHA3-256):    {package.content_hash[:32]}...")
    print(f"  Layer 2  HMAC tag (HMAC-SHA3-256):   {package.hmac_tag.hex()[:32]}...")
    print(
        f"  Layer 3  signature ({package.primary_signature.algorithm.name}): "
        f"{package.primary_signature.signature.hex()[:32]}..."
    )
    print(f"  Layer 4  derived keys (HKDF):        {len(package.derived_keys)}")
    print(f"  Signing public key:                  {signing_key.public_key.hex()[:32]}...")

    # Verify the package.
    #
    # `expected_public_key` is the whole point of this call, not an optional
    # extra.  Every key needed to check a package travels *inside* it, so
    # verifying a package against its own material proves integrity and
    # internal consistency and nothing about who produced it — anyone can build
    # a package that passes.  Pin the signing key you obtained out of band
    # (config, enrollment, a directory you trust) and `all_valid` becomes an
    # origin claim.  Without it, `all_valid` is False by design as of 4.0.0.
    print("\nVerifying package (anchored against the expected signing key)...")
    results = verify_crypto_package(
        sensitive_data,
        package,
        expected_public_key=signing_key.public_key,
    )

    print("Verification results:")
    for check, passed in results.items():
        print(f"  {check}: {'PASS' if passed else 'FAIL'}")

    # The same call without the anchor, so the difference is visible rather
    # than described.  Layers 1-4 still pass — `core_valid` reports that — but
    # nothing has been established about origin, so `all_valid` is False.
    unanchored = verify_crypto_package(sensitive_data, package)
    print(
        f"\nWithout an anchor: core_valid={unanchored['core_valid']}, "
        f"key_pinned={unanchored['key_pinned']}, all_valid={unanchored['all_valid']}"
    )

    if not results["all_valid"]:
        raise RuntimeError(f"anchored verification failed: {results}")


def example_4_humanitarian_use_case():
    """
    Example 4: Humanitarian Use Case

    Protect sensitive crisis response data with quantum-resistant security.
    """
    print("\n" + "=" * 60)
    print("Example 4: Humanitarian Use Case")
    print("=" * 60)

    from ama_cryptography.crypto_api import (
        AlgorithmType,
        CryptoPackageConfig,
        create_crypto_package,
        verify_crypto_package,
    )

    # Crisis response data
    crisis_data = b"""
    CRISIS RESPONSE REPORT
    ----------------------
    Location: 34.0522, -118.2437
    Type: Natural Disaster
    Victims: 150 displaced
    Safe Houses: 3 active
    Medical Needs: Critical
    """

    # HYBRID_SIG is Ed25519 + ML-DSA-65: a forger must break both.  It is the
    # default; naming it here makes the choice explicit in the example.
    package = create_crypto_package(
        crisis_data,
        config=CryptoPackageConfig(signature_algorithm=AlgorithmType.HYBRID_SIG),
    )
    signing_key = package.keypairs[package.primary_signature.algorithm.name]

    print("\nCrisis data protected with:")
    print("  - SHA3-256 content hash")
    print("  - HMAC-SHA3-256 authentication")
    print(f"  - {package.primary_signature.algorithm.name} digital signature")
    print(f"  - {len(package.derived_keys)} independently derived HKDF keys")

    # Report the quantum layer from what the package actually carries, rather
    # than from a build-time flag: the hybrid signature falls back to Ed25519
    # alone when the native PQC backend is missing.
    pqc_status = package.metadata.get("pqc_status", "UNKNOWN")
    if pqc_status == "AVAILABLE":
        print("  - ML-DSA-65 quantum-resistant signature (inside the hybrid)")
    else:
        print(f"  - (Quantum signatures unavailable: pqc_status={pqc_status}.")
        print("     Build the native C library for quantum resistance.)")

    # Verify integrity, anchored against the signing key — see Example 3 for
    # why the anchor is what turns this into an authenticity check.
    results = verify_crypto_package(
        crisis_data,
        package,
        expected_public_key=signing_key.public_key,
    )
    print(f"\nData integrity verified: {results['all_valid']}")

    # A tampered copy must fail, and a demonstration that only shows the happy
    # path has not shown anything.
    tampered = crisis_data.replace(b"150 displaced", b"  0 displaced")
    tampered_results = verify_crypto_package(
        tampered,
        package,
        expected_public_key=signing_key.public_key,
    )
    print(f"Tampered copy rejected:  {not tampered_results['all_valid']}")

    if not results["all_valid"] or tampered_results["all_valid"]:
        raise RuntimeError(
            f"verification did not behave as documented: "
            f"genuine={results}, tampered={tampered_results}"
        )


def main():
    """Run all examples."""
    print("=" * 60)
    print("AMA CRYPTOGRAPHY - BASIC USAGE EXAMPLES")
    print("=" * 60)
    print("\nThese examples demonstrate core AMA Cryptography capabilities.")
    print("For full documentation, see: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography")

    try:
        example_1_simple_signing()
        example_2_key_management()
        example_3_data_protection()
        example_4_humanitarian_use_case()

        print("\n" + "=" * 60)
        print("ALL EXAMPLES COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nNext steps:")
        print("  - See flask_integration.py for web app integration")
        print("  - See fastapi_integration.py for async API integration")
        print("  - See complete_demo.py for advanced features")
        print()

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
