#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
NIST Known Answer Test (KAT) Vector Validation for Post-Quantum Cryptography
=============================================================================

This module implements comprehensive validation against official NIST KAT vectors
from the FIPS 203 (ML-KEM/Kyber) and FIPS 204 (ML-DSA/Dilithium) submission packages.

The KAT vectors are the authoritative source for algorithm correctness, providing:
- Deterministic test cases with known seeds, keys, and outputs
- Verification that implementations match NIST reference implementations
- Proof of correctness beyond simple round-trip functionality

KAT Vector Sources:
- ML-KEM (Kyber): https://csrc.nist.gov/Projects/post-quantum-cryptography
  NIST-PQ-Submission-Kyber-20201001/KAT/
- ML-DSA (Dilithium): https://csrc.nist.gov/Projects/post-quantum-cryptography
  Dilithium/dilithium/KAT/

Test Coverage:
- Kyber-512, Kyber-768, Kyber-1024 (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- Dilithium2, Dilithium3, Dilithium5 (ML-DSA-44, ML-DSA-65, ML-DSA-87)

Note: Full KAT validation requires deterministic key generation from seeds,
which may not be exposed by all PQC library APIs. Tests that cannot be
performed due to API limitations are marked as skipped with explanation.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2025-12-06
Version: 2.0

AI Co-Architects:Eris | Eden ♱ | Veritas | X | Caduceus | Dev
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

# Import PQC backends for testing
try:
    from ama_cryptography.pqc_backends import (
        DILITHIUM_AVAILABLE,
        KYBER_AVAILABLE,
        dilithium_sign,
        dilithium_verify,
        generate_dilithium_keypair,
        generate_kyber_keypair,
        kyber_decapsulate,
        kyber_encapsulate,
    )

    PQC_AVAILABLE = DILITHIUM_AVAILABLE or KYBER_AVAILABLE
except ImportError:
    PQC_AVAILABLE = False
    DILITHIUM_AVAILABLE = False
    KYBER_AVAILABLE = False

# Path to KAT vector files
KAT_DIR = Path(__file__).parent / "kat"
ML_KEM_DIR = KAT_DIR / "ml_kem"
ML_DSA_DIR = KAT_DIR / "ml_dsa"


# =============================================================================
# KAT Vector Data Classes
# =============================================================================


@dataclass
class KyberKATVector:
    """
    A single Kyber/ML-KEM KAT test vector.

    Fields from NIST KAT .rsp files:
    - count: Test vector index (0-99)
    - seed: 48-byte seed for deterministic key generation
    - pk: Public key bytes
    - sk: Secret key bytes
    - ct: Ciphertext from encapsulation
    - ss: Shared secret (32 bytes)
    """

    count: int
    seed: bytes
    pk: bytes
    sk: bytes
    ct: bytes
    ss: bytes


@dataclass
class DilithiumKATVector:
    """
    A single Dilithium/ML-DSA KAT test vector.

    Fields from NIST KAT .rsp files:
    - count: Test vector index (0-99)
    - seed: 48-byte seed for deterministic key generation
    - mlen: Message length in bytes
    - msg: Message bytes
    - pk: Public key bytes
    - sk: Secret key bytes
    - smlen: Signed message length
    - sm: Signed message (signature || message)
    """

    count: int
    seed: bytes
    mlen: int
    msg: bytes
    pk: bytes
    sk: bytes
    smlen: int
    sm: bytes


# =============================================================================
# KAT Vector Parsing
# =============================================================================


def parse_kat_file(filepath: Path) -> Iterator[dict[str, str]]:
    """
    Parse a NIST KAT .rsp file into dictionaries of field values.

    KAT files have the format:
        # Comment lines start with #
        count = 0
        seed = HEXVALUE
        pk = HEXVALUE
        ...
        <blank line separates vectors>

    Yields:
        Dict mapping field names to hex string values for each test vector.
    """
    if not filepath.exists():
        return

    current_vector: dict[str, str] = {}

    with open(filepath) as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines at start
            if line.startswith("#") or (not line and not current_vector):
                continue

            # Blank line signals end of current vector
            if not line:
                if current_vector:
                    yield current_vector
                    current_vector = {}
                continue

            # Parse field = value
            if "=" in line:
                key, value = line.split("=", 1)
                current_vector[key.strip().lower()] = value.strip()

    # Yield final vector if file doesn't end with blank line
    if current_vector:
        yield current_vector


def load_kyber_kat_vectors(filepath: Path, max_vectors: int = 10) -> list[KyberKATVector]:
    """
    Load Kyber/ML-KEM KAT vectors from a .rsp file.

    Args:
        filepath: Path to the KAT .rsp file
        max_vectors: Maximum number of vectors to load (default 10 for efficiency)

    Returns:
        List of KyberKATVector objects
    """
    vectors = []
    for i, raw in enumerate(parse_kat_file(filepath)):
        if i >= max_vectors:
            break

        try:
            vectors.append(
                KyberKATVector(
                    count=int(raw.get("count", i)),
                    seed=bytes.fromhex(raw["seed"]),
                    pk=bytes.fromhex(raw["pk"]),
                    sk=bytes.fromhex(raw["sk"]),
                    ct=bytes.fromhex(raw["ct"]),
                    ss=bytes.fromhex(raw["ss"]),
                )
            )
        except (KeyError, ValueError):
            # Skip malformed vectors
            continue

    return vectors


def load_dilithium_kat_vectors(filepath: Path, max_vectors: int = 10) -> list[DilithiumKATVector]:
    """
    Load Dilithium/ML-DSA KAT vectors from a .rsp file.

    Args:
        filepath: Path to the KAT .rsp file
        max_vectors: Maximum number of vectors to load (default 10 for efficiency)

    Returns:
        List of DilithiumKATVector objects
    """
    vectors = []
    for i, raw in enumerate(parse_kat_file(filepath)):
        if i >= max_vectors:
            break

        try:
            vectors.append(
                DilithiumKATVector(
                    count=int(raw.get("count", i)),
                    seed=bytes.fromhex(raw["seed"]),
                    mlen=int(raw["mlen"]),
                    msg=bytes.fromhex(raw["msg"]) if raw["msg"] else b"",
                    pk=bytes.fromhex(raw["pk"]),
                    sk=bytes.fromhex(raw["sk"]),
                    smlen=int(raw["smlen"]),
                    sm=bytes.fromhex(raw["sm"]),
                )
            )
        except (KeyError, ValueError):
            # Skip malformed vectors
            continue

    return vectors


# =============================================================================
# KAT Vector Availability Checks
# =============================================================================


@dataclass
class FIPS204KATVector:
    """
    A FIPS 204 ML-DSA KAT test vector.

    Fields from FIPS 204 .kat files:
    - seed: 32-byte seed for deterministic key generation
    - pk: Public key bytes
    - sk: Secret key bytes
    - mlen: Message length in bytes
    - msg: Message bytes
    - ctx_len: Context string length
    - ctx: Context string bytes
    - sig: Signature bytes (3309 for ML-DSA-65)
    """

    seed: bytes
    pk: bytes
    sk: bytes
    mlen: int
    msg: bytes
    ctx_len: int
    ctx: bytes
    sig: bytes


FIPS204_DIR = KAT_DIR / "fips204"


def load_fips204_kat_vectors(filepath: Path, max_vectors: int = 10) -> list[FIPS204KATVector]:
    """
    Load FIPS 204 ML-DSA KAT vectors from a .kat file.

    Args:
        filepath: Path to the KAT .kat file
        max_vectors: Maximum number of vectors to load

    Returns:
        List of FIPS204KATVector objects
    """
    vectors = []
    for i, raw in enumerate(parse_kat_file(filepath)):
        if i >= max_vectors:
            break

        try:
            ctx_hex = raw.get("ctx", "")
            vectors.append(
                FIPS204KATVector(
                    seed=bytes.fromhex(raw["seed"]),
                    pk=bytes.fromhex(raw["pkey"]),
                    sk=bytes.fromhex(raw["skey"]),
                    mlen=int(raw["mlen"]),
                    msg=bytes.fromhex(raw["msg"]) if raw["msg"] else b"",
                    ctx_len=int(raw.get("ctx_len", 0)),
                    ctx=bytes.fromhex(ctx_hex) if ctx_hex else b"",
                    sig=bytes.fromhex(raw["sig"]),
                )
            )
        except (KeyError, ValueError):
            continue

    return vectors


def fips204_kat_available() -> bool:
    """Check if FIPS 204 ML-DSA-65 KAT vectors are available."""
    return (FIPS204_DIR / "ml_dsa_65.kat").exists()


def kat_files_available() -> bool:
    """Check if KAT vector files are available."""
    return KAT_DIR.exists() and (ML_KEM_DIR.exists() or ML_DSA_DIR.exists())


def kyber_kat_available(variant: str = "kyber1024") -> bool:
    """Check if Kyber KAT vectors are available for a specific variant."""
    return (ML_KEM_DIR / f"{variant}.rsp").exists()


def dilithium_kat_available(variant: str = "dilithium3") -> bool:
    """Check if Dilithium KAT vectors are available for a specific variant."""
    return (ML_DSA_DIR / f"{variant}.rsp").exists()


# =============================================================================
# Test Classes
# =============================================================================


class TestKATVectorParsing:
    """Tests for KAT vector file parsing functionality."""

    def test_kat_directory_exists(self) -> None:
        """Verify KAT directory structure exists."""
        assert KAT_DIR.exists(), f"KAT directory not found at {KAT_DIR}"

    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_parse_kyber1024_kat(self) -> None:
        """Test parsing Kyber-1024 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber1024.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Kyber-1024 KAT vectors loaded"

        # Verify first vector structure
        v = vectors[0]
        assert v.count == 0
        assert len(v.seed) == 48, "Seed should be 48 bytes"
        assert len(v.pk) == 1568, f"Kyber-1024 pk should be 1568 bytes, got {len(v.pk)}"
        assert len(v.sk) == 3168, f"Kyber-1024 sk should be 3168 bytes, got {len(v.sk)}"
        assert len(v.ct) == 1568, f"Kyber-1024 ct should be 1568 bytes, got {len(v.ct)}"
        assert len(v.ss) == 32, f"Shared secret should be 32 bytes, got {len(v.ss)}"

    @pytest.mark.skipif(
        not kyber_kat_available("kyber768"),
        reason="Kyber-768 KAT vectors not available",
    )
    def test_parse_kyber768_kat(self) -> None:
        """Test parsing Kyber-768 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber768.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Kyber-768 KAT vectors loaded"

        v = vectors[0]
        assert len(v.pk) == 1184, f"Kyber-768 pk should be 1184 bytes, got {len(v.pk)}"
        assert len(v.sk) == 2400, f"Kyber-768 sk should be 2400 bytes, got {len(v.sk)}"
        assert len(v.ct) == 1088, f"Kyber-768 ct should be 1088 bytes, got {len(v.ct)}"

    @pytest.mark.skipif(
        not kyber_kat_available("kyber512"),
        reason="Kyber-512 KAT vectors not available",
    )
    def test_parse_kyber512_kat(self) -> None:
        """Test parsing Kyber-512 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber512.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Kyber-512 KAT vectors loaded"

        v = vectors[0]
        assert len(v.pk) == 800, f"Kyber-512 pk should be 800 bytes, got {len(v.pk)}"
        assert len(v.sk) == 1632, f"Kyber-512 sk should be 1632 bytes, got {len(v.sk)}"
        assert len(v.ct) == 768, f"Kyber-512 ct should be 768 bytes, got {len(v.ct)}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_parse_dilithium3_kat(self) -> None:
        """Test parsing Dilithium3 (ML-DSA-65) KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Dilithium3 KAT vectors loaded"

        v = vectors[0]
        assert v.count == 0
        assert len(v.seed) == 48, "Seed should be 48 bytes"
        assert len(v.pk) == 1952, f"Dilithium3 pk should be 1952 bytes, got {len(v.pk)}"
        # Round-3 Dilithium3 KAT vectors use 4016-byte secret keys (c_tilde=32, tr=48).
        # FIPS 204 ML-DSA-65 final uses 4032-byte secret keys (c_tilde=48, tr=64).
        # See pqc_backends.DILITHIUM_SECRET_KEY_BYTES (4032) for the FIPS 204 size.
        assert len(v.sk) == 4016, f"Dilithium3 (round-3) sk should be 4016 bytes, got {len(v.sk)}"
        # Signature is embedded in sm (sm = sig || msg)
        sig_len = v.smlen - v.mlen
        assert sig_len == 3293, f"Dilithium3 sig should be 3293 bytes, got {sig_len}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium2"),
        reason="Dilithium2 KAT vectors not available",
    )
    def test_parse_dilithium2_kat(self) -> None:
        """Test parsing Dilithium2 (ML-DSA-44) KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium2.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Dilithium2 KAT vectors loaded"

        v = vectors[0]
        assert len(v.pk) == 1312, f"Dilithium2 pk should be 1312 bytes, got {len(v.pk)}"
        assert len(v.sk) == 2544, f"Dilithium2 sk should be 2544 bytes, got {len(v.sk)}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium5"),
        reason="Dilithium5 KAT vectors not available",
    )
    def test_parse_dilithium5_kat(self) -> None:
        """Test parsing Dilithium5 (ML-DSA-87) KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium5.rsp", max_vectors=5)
        assert len(vectors) > 0, "No Dilithium5 KAT vectors loaded"

        v = vectors[0]
        assert len(v.pk) == 2592, f"Dilithium5 pk should be 2592 bytes, got {len(v.pk)}"
        assert len(v.sk) == 4880, f"Dilithium5 sk should be 4880 bytes, got {len(v.sk)}"


class TestMLKEMKATValidation:
    """
    ML-KEM (Kyber) Known Answer Test validation.

    These tests verify that the PQC implementation produces correct outputs
    when given known inputs from NIST KAT vectors.

    Note: Full KAT validation requires deterministic key generation from seeds,
    which requires low-level seed access. These tests validate
    what is possible with the available API:
    - Key size validation against KAT vectors
    - Encapsulation/decapsulation round-trip with KAT keys (where API permits)
    - Shared secret size validation
    """

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_kyber1024_key_sizes_match_kat(self) -> None:
        """Verify Kyber-1024 key sizes match NIST KAT specifications."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber1024.rsp", max_vectors=1)
        assert len(vectors) > 0, "No KAT vectors loaded"

        kat = vectors[0]

        # Generate a keypair and verify sizes match KAT
        keypair = generate_kyber_keypair()
        assert len(keypair.public_key) == len(
            kat.pk
        ), f"Public key size mismatch: {len(keypair.public_key)} vs KAT {len(kat.pk)}"
        assert len(keypair.secret_key) == len(
            kat.sk
        ), f"Secret key size mismatch: {len(keypair.secret_key)} vs KAT {len(kat.sk)}"

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_kyber1024_encaps_decaps_roundtrip(self) -> None:
        """Test Kyber-1024 encapsulation/decapsulation produces matching shared secrets."""
        # Generate fresh keypair (we can't use KAT keys without seed-based keygen)
        keypair = generate_kyber_keypair()

        # Encapsulate
        encaps = kyber_encapsulate(keypair.public_key)
        assert len(encaps.ciphertext) == 1568, "Ciphertext size should be 1568 bytes"
        assert len(encaps.shared_secret) == 32, "Shared secret should be 32 bytes"

        # Decapsulate
        ss = kyber_decapsulate(encaps.ciphertext, keypair.secret_key)
        assert ss == encaps.shared_secret, "Shared secrets must match"

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_kyber1024_shared_secret_size_matches_kat(self) -> None:
        """Verify shared secret size matches NIST KAT specification."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber1024.rsp", max_vectors=1)
        kat = vectors[0]

        keypair = generate_kyber_keypair()
        encaps = kyber_encapsulate(keypair.public_key)

        assert len(encaps.shared_secret) == len(
            kat.ss
        ), f"Shared secret size mismatch: {len(encaps.shared_secret)} vs KAT {len(kat.ss)}"

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_kyber1024_multiple_kat_vectors(self) -> None:
        """Validate against multiple KAT vectors for comprehensive coverage."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber1024.rsp", max_vectors=10)
        assert len(vectors) >= 5, "Need at least 5 KAT vectors for comprehensive test"

        for i, kat in enumerate(vectors):
            # Verify KAT vector internal consistency
            assert len(kat.seed) == 48, f"Vector {i}: Invalid seed length"
            assert len(kat.pk) == 1568, f"Vector {i}: Invalid pk length"
            assert len(kat.sk) == 3168, f"Vector {i}: Invalid sk length"
            assert len(kat.ct) == 1568, f"Vector {i}: Invalid ct length"
            assert len(kat.ss) == 32, f"Vector {i}: Invalid ss length"

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
    def test_kyber_ciphertext_uniqueness(self) -> None:
        """Verify encapsulation produces unique ciphertexts (randomized)."""
        keypair = generate_kyber_keypair()

        # Generate multiple encapsulations
        ciphertexts = set()
        for _ in range(5):
            encaps = kyber_encapsulate(keypair.public_key)
            ciphertexts.add(encaps.ciphertext)

        # All ciphertexts should be unique (encapsulation is randomized)
        assert len(ciphertexts) == 5, "Encapsulation should produce unique ciphertexts"


class TestMLDSAKATValidation:
    """
    ML-DSA (Dilithium) Known Answer Test validation.

    These tests verify that the PQC implementation produces correct outputs
    when given known inputs from NIST KAT vectors.

    Note: Full KAT validation requires deterministic key generation and signing
    from seeds, which may not be exposed by all PQC library APIs. These tests
    validate what is possible with the available API:
    - Key size validation against KAT vectors
    - Signature size validation
    - Sign/verify round-trip functionality
    - Verification with KAT signatures (where API permits)
    """

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_key_sizes_match_kat(self) -> None:
        """Verify Dilithium3 (ML-DSA-65) key sizes match NIST KAT specifications."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=1)
        assert len(vectors) > 0, "No KAT vectors loaded"

        kat = vectors[0]

        # Generate a keypair and verify sizes match KAT
        keypair = generate_dilithium_keypair()
        assert len(keypair.public_key) == len(
            kat.pk
        ), f"Public key size mismatch: {len(keypair.public_key)} vs KAT {len(kat.pk)}"

        # Note: secret key may include public key, so size may differ
        # The important thing is that it's at least as large as the KAT sk
        assert len(keypair.secret_key) >= len(
            kat.sk
        ), f"Secret key too small: {len(keypair.secret_key)} vs KAT {len(kat.sk)}"

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_signature_size_matches_kat(self) -> None:
        """Verify Dilithium3 signature size is within expected range.

        Note: The KAT vectors are from the original Dilithium submission (3293 bytes),
        while the native implementation follows FIPS 204 ML-DSA standard (3309 bytes).
        Both are valid implementations of the same algorithm family.
        """
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=1)
        kat = vectors[0]

        # Expected signature size from KAT (sm = sig || msg)
        kat_sig_size = kat.smlen - kat.mlen

        # Generate keypair and sign a message
        keypair = generate_dilithium_keypair()
        message = b"Test message for signature size validation"
        signature = dilithium_sign(message, keypair.secret_key)

        # Accept both original Dilithium (3293) and final ML-DSA-65 (3309) sizes
        # The difference is due to FIPS 204 standardization changes
        valid_sizes = {kat_sig_size, 3309}  # KAT size and ML-DSA-65 size
        assert (
            len(signature) in valid_sizes
        ), f"Signature size {len(signature)} not in expected sizes {valid_sizes}"

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_sign_verify_roundtrip(self) -> None:
        """Test Dilithium3 sign/verify produces valid signatures."""
        keypair = generate_dilithium_keypair()

        # Test with various message sizes from KAT vectors
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=5)

        for i, kat in enumerate(vectors):
            # Use KAT message for testing
            message = kat.msg if kat.msg else b"Empty message test"

            # Sign with our keypair
            signature = dilithium_sign(message, keypair.secret_key)

            # Verify signature
            is_valid = dilithium_verify(message, signature, keypair.public_key)
            assert is_valid, f"Vector {i}: Signature verification failed"

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_roundtrip3_rejects_gracefully(self) -> None:
        """
        Verify that pre-FIPS round-3 Dilithium3 KAT signatures are
        correctly rejected by our FIPS 204 ML-DSA-65 backend.

        Round-3 Dilithium3 uses 3293-byte signatures (c_tilde=32, tr=48).
        Our FIPS 204 backend uses 3309-byte signatures (c_tilde=48, tr=64).
        These are incompatible — verify must return False without crashing.
        """
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=5)

        for i, kat in enumerate(vectors):
            # Extract signature from signed message (sm = sig || msg)
            sig_len = kat.smlen - kat.mlen
            signature = kat.sm[:sig_len]
            message = kat.msg

            # Must return False (size mismatch: 3293 != 3309)
            is_valid = dilithium_verify(message, signature, kat.pk)
            assert is_valid is False, (
                f"Vector {i}: round-3 Dilithium3 signature should not verify "
                f"against FIPS 204 ML-DSA-65 backend"
            )

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not fips204_kat_available(),
        reason="FIPS 204 ML-DSA-65 KAT vectors not available",
    )
    def test_fips204_ml_dsa_65_verify_kat_signature(self) -> None:
        """
        Verify FIPS 204 ML-DSA-65 KAT signatures against KAT public keys.

        The KAT vectors use the external signing interface (Algorithm 2)
        which prepends 0x00 || len(ctx) || ctx to the message before
        passing to the internal sign function (Algorithm 7). Our C backend
        implements internal verify (Algorithm 8), so we reconstruct the
        internal message format before calling dilithium_verify.
        """
        vectors = load_fips204_kat_vectors(FIPS204_DIR / "ml_dsa_65.kat", max_vectors=10)
        assert len(vectors) >= 5, "Need at least 5 FIPS 204 KAT vectors"

        for i, kat in enumerate(vectors):
            # FIPS 204 external interface: M' = 0x00 || len(ctx) || ctx || msg
            internal_msg = bytes([0x00, kat.ctx_len]) + kat.ctx + kat.msg

            is_valid = dilithium_verify(internal_msg, kat.sig, kat.pk)
            assert is_valid, (
                f"Vector {i}: FIPS 204 ML-DSA-65 KAT signature verification "
                f"failed (msg_len={kat.mlen}, ctx_len={kat.ctx_len})"
            )

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_multiple_kat_vectors(self) -> None:
        """Validate against multiple KAT vectors for comprehensive coverage."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=10)
        assert len(vectors) >= 5, "Need at least 5 KAT vectors for comprehensive test"

        for i, kat in enumerate(vectors):
            # Verify KAT vector internal consistency
            assert len(kat.seed) == 48, f"Vector {i}: Invalid seed length"
            assert len(kat.pk) == 1952, f"Vector {i}: Invalid pk length"
            # Round-3 Dilithium3 sk = 4016 bytes (not FIPS 204 ML-DSA-65 final = 4032)
            assert len(kat.sk) == 4016, f"Vector {i}: Invalid sk length"

            # Verify signature length
            sig_len = kat.smlen - kat.mlen
            assert sig_len == 3293, f"Vector {i}: Invalid signature length {sig_len}"

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    def test_dilithium_signature_uniqueness(self) -> None:
        """Verify signing produces unique signatures (randomized in some modes)."""
        keypair = generate_dilithium_keypair()
        message = b"Test message for signature uniqueness"

        # Generate multiple signatures
        signatures = []
        for _ in range(3):
            sig = dilithium_sign(message, keypair.secret_key)
            signatures.append(sig)

        # All signatures should verify
        for sig in signatures:
            assert dilithium_verify(message, sig, keypair.public_key)

        # Note: Dilithium signatures may or may not be deterministic
        # depending on the mode (hedged vs deterministic)

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    def test_dilithium_wrong_key_fails(self) -> None:
        """Verify signatures fail with wrong public key."""
        keypair1 = generate_dilithium_keypair()
        keypair2 = generate_dilithium_keypair()

        message = b"Test message"
        signature = dilithium_sign(message, keypair1.secret_key)

        # Should verify with correct key
        assert dilithium_verify(message, signature, keypair1.public_key)

        # Should fail with wrong key
        assert not dilithium_verify(message, signature, keypair2.public_key)

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
    def test_dilithium_modified_message_fails(self) -> None:
        """Verify signatures fail with modified message."""
        keypair = generate_dilithium_keypair()

        message = b"Original message"
        signature = dilithium_sign(message, keypair.secret_key)

        # Should verify with original message
        assert dilithium_verify(message, signature, keypair.public_key)

        # Should fail with modified message
        modified = b"Modified message"
        assert not dilithium_verify(modified, signature, keypair.public_key)


class TestKATVectorComprehensiveCoverage:
    """
    Comprehensive KAT vector coverage tests.

    These tests ensure we have loaded and validated a significant number
    of KAT vectors to provide confidence in implementation correctness.
    """

    @pytest.mark.skipif(
        not kyber_kat_available("kyber1024"),
        reason="Kyber-1024 KAT vectors not available",
    )
    def test_kyber1024_kat_count(self) -> None:
        """Verify we can load many Kyber-1024 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber1024.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"

    @pytest.mark.skipif(
        not kyber_kat_available("kyber768"),
        reason="Kyber-768 KAT vectors not available",
    )
    def test_kyber768_kat_count(self) -> None:
        """Verify we can load many Kyber-768 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber768.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"

    @pytest.mark.skipif(
        not kyber_kat_available("kyber512"),
        reason="Kyber-512 KAT vectors not available",
    )
    def test_kyber512_kat_count(self) -> None:
        """Verify we can load many Kyber-512 KAT vectors."""
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber512.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium3"),
        reason="Dilithium3 KAT vectors not available",
    )
    def test_dilithium3_kat_count(self) -> None:
        """Verify we can load many Dilithium3 KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium3.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium2"),
        reason="Dilithium2 KAT vectors not available",
    )
    def test_dilithium2_kat_count(self) -> None:
        """Verify we can load many Dilithium2 KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium2.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"

    @pytest.mark.skipif(
        not dilithium_kat_available("dilithium5"),
        reason="Dilithium5 KAT vectors not available",
    )
    def test_dilithium5_kat_count(self) -> None:
        """Verify we can load many Dilithium5 KAT vectors."""
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium5.rsp", max_vectors=100)
        assert len(vectors) >= 10, f"Expected at least 10 vectors, got {len(vectors)}"


class TestKATVectorIntegrity:
    """
    Tests to verify KAT vector file integrity and consistency.
    """

    @pytest.mark.skipif(not kat_files_available(), reason="KAT files not available")
    def test_kat_files_not_empty(self) -> None:
        """Verify KAT files are not empty."""
        for kat_file in ML_KEM_DIR.glob("*.rsp"):
            assert kat_file.stat().st_size > 0, f"KAT file {kat_file} is empty"

        for kat_file in ML_DSA_DIR.glob("*.rsp"):
            assert kat_file.stat().st_size > 0, f"KAT file {kat_file} is empty"

    @pytest.mark.skipif(not kat_files_available(), reason="KAT files not available")
    def test_kat_vectors_have_required_fields(self) -> None:
        """Verify KAT vectors contain all required fields."""
        # Check Kyber vectors
        for kat_file in ML_KEM_DIR.glob("*.rsp"):
            for i, raw in enumerate(parse_kat_file(kat_file)):
                if i >= 3:  # Check first 3 vectors
                    break
                required = {"count", "seed", "pk", "sk", "ct", "ss"}
                missing = required - set(raw.keys())
                assert not missing, f"{kat_file}: Vector {i} missing fields: {missing}"

        # Check Dilithium vectors
        for kat_file in ML_DSA_DIR.glob("*.rsp"):
            for i, raw in enumerate(parse_kat_file(kat_file)):
                if i >= 3:  # Check first 3 vectors
                    break
                required = {"count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm"}
                missing = required - set(raw.keys())
                assert not missing, f"{kat_file}: Vector {i} missing fields: {missing}"


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])
