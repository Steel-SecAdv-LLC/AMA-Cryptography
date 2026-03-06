#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ava Guardian ♱ Basic Usage Example
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

    from ava_guardian.crypto_api import (
        AlgorithmType,
        quick_sign,
        quick_verify,
    )

    # Your message to sign
    message = b"Hello, Ava Guardian! Protect my data."

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

    from ava_guardian.key_management import (
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

    from code_guardian_secure import (
        create_crypto_package,
        generate_key_management_system,
        verify_crypto_package,
    )

    # Your sensitive data
    sensitive_data = "Patient ID: 12345, Diagnosis: Confidential"
    data_params = [(1.0, 2.0), (1.5, 2.5)]  # Helix parameters

    # Generate key management system
    print("\nGenerating keys...")
    kms = generate_key_management_system("My Organization")

    # Create protected package
    print("Creating protected package...")
    package = create_crypto_package(
        dna_codes=sensitive_data,
        helix_params=data_params,
        kms=kms,
        author="Data Owner",
        use_rfc3161=False,  # Set True for trusted timestamp
    )

    print("\nPackage created:")
    print(f"  Content hash: {package.content_hash[:32]}...")
    print(f"  HMAC tag: {package.hmac_tag[:32]}...")
    print(f"  Ed25519 signature: {package.ed25519_signature[:32]}...")
    print(f"  Timestamp: {package.timestamp}")

    # Verify the package
    print("\nVerifying package...")
    results = verify_crypto_package(
        dna_codes=sensitive_data,
        helix_params=data_params,
        pkg=package,
        hmac_key=kms.hmac_key,
    )

    print("Verification results:")
    for check, passed in results.items():
        status = "PASS" if passed else ("SKIP" if passed is None else "FAIL")
        print(f"  {check}: {status}")


def example_4_humanitarian_use_case():
    """
    Example 4: Humanitarian Use Case

    Protect sensitive crisis response data with quantum-resistant security.
    """
    print("\n" + "=" * 60)
    print("Example 4: Humanitarian Use Case")
    print("=" * 60)

    from code_guardian_secure import (
        create_crypto_package,
        generate_key_management_system,
        verify_crypto_package,
    )

    # Crisis response data
    crisis_data = """
    CRISIS RESPONSE REPORT
    ----------------------
    Location: 34.0522, -118.2437
    Type: Natural Disaster
    Victims: 150 displaced
    Safe Houses: 3 active
    Medical Needs: Critical
    """

    helix_params = [(1.0, 1.5)]

    # Protect the data
    kms = generate_key_management_system("Crisis Response Unit")
    package = create_crypto_package(
        dna_codes=crisis_data,
        helix_params=helix_params,
        kms=kms,
        author="Field Operator",
        use_rfc3161=False,
    )

    print("\nCrisis data protected with:")
    print("  - SHA3-256 content hash")
    print("  - HMAC-SHA3-256 authentication")
    print("  - Ed25519 digital signature")

    # Check if quantum protection is available
    if package.dilithium_signature:
        print("  - ML-DSA-65 quantum-resistant signature")
    else:
        print("  - (Quantum signatures available with native C library)")

    # Verify integrity
    results = verify_crypto_package(
        dna_codes=crisis_data,
        helix_params=helix_params,
        pkg=package,
        hmac_key=kms.hmac_key,
    )

    all_passed = all(v is True for v in results.values() if v is not None)
    print(f"\nData integrity verified: {all_passed}")


def main():
    """Run all examples."""
    print("=" * 60)
    print("AVA GUARDIAN ♱ - BASIC USAGE EXAMPLES")
    print("=" * 60)
    print("\nThese examples demonstrate core Ava Guardian ♱ capabilities.")
    print("For full documentation, see: https://github.com/Steel-SecAdv-LLC/Ava-Guardian")

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
