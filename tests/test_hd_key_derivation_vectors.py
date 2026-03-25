#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for HD (BIP32-style) key derivation in key_management.py.

Covers master key generation, child key derivation, derivation path
parsing, consistency, uniqueness, key metadata, chain codes, and
multi-level derivation.

All tests use hardened derivation paths only so that the native
secp256k1 public-key function is not required.
"""

import os

import pytest

from ama_cryptography.key_management import HDKeyDerivation


# ---- helpers ----------------------------------------------------------------

_FIXED_SEED = bytes(range(64))  # deterministic 64-byte seed


@pytest.fixture
def hd() -> HDKeyDerivation:
    """HDKeyDerivation initialised with a fixed seed for reproducibility."""
    return HDKeyDerivation(seed=_FIXED_SEED)


# ---- tests ------------------------------------------------------------------


class TestMasterKeyGeneration:
    """Tests for master key / chain code generation."""

    def test_master_key_length(self, hd: HDKeyDerivation) -> None:
        """Master key must be 32 bytes."""
        assert len(hd.master_key) == 32

    def test_master_chain_code_length(self, hd: HDKeyDerivation) -> None:
        """Master chain code must be 32 bytes."""
        assert len(hd.master_chain_code) == 32

    def test_random_seed_generation(self) -> None:
        """When no seed is provided a random 64-byte master seed is used."""
        hd = HDKeyDerivation()
        assert len(hd.master_seed) == 64
        assert len(hd.master_key) == 32

    def test_seed_phrase_derivation(self) -> None:
        """A seed phrase should produce a deterministic master key."""
        hd1 = HDKeyDerivation(seed_phrase="test mnemonic phrase")
        hd2 = HDKeyDerivation(seed_phrase="test mnemonic phrase")
        assert hd1.master_key == hd2.master_key
        assert hd1.master_chain_code == hd2.master_chain_code


class TestChildKeyDerivation:
    """Tests for child key derivation from master."""

    def test_derive_path_returns_tuple(self, hd: HDKeyDerivation) -> None:
        """derive_path() must return (key, chain_code) both of 32 bytes."""
        key, chain = hd.derive_path("m/44'/0'/0'/0'/0'")
        assert len(key) == 32
        assert len(chain) == 32

    def test_derive_key_convenience(self, hd: HDKeyDerivation) -> None:
        """derive_key() should return a 32-byte key."""
        key = hd.derive_key(purpose=44, account=0, change=0, index=0)
        assert len(key) == 32


class TestDerivationPathParsing:
    """Tests for path string parsing."""

    def test_path_must_start_with_m(self, hd: HDKeyDerivation) -> None:
        """Paths not starting with 'm' must raise ValueError."""
        with pytest.raises(ValueError, match="must start with 'm'"):
            hd.derive_path("44'/0'/0'/0/0")

    def test_hardened_marker_parsed(self, hd: HDKeyDerivation) -> None:
        """A path with hardened markers (') should derive without error."""
        key, chain = hd.derive_path("m/44'/0'")
        assert len(key) == 32

    def test_single_level_path(self, hd: HDKeyDerivation) -> None:
        """A single-level hardened path should succeed."""
        key, chain = hd.derive_path("m/0'")
        assert len(key) == 32


class TestConsistency:
    """Tests for deterministic derivation."""

    def test_same_seed_same_key(self) -> None:
        """Two instances with the same seed must produce identical keys."""
        hd1 = HDKeyDerivation(seed=_FIXED_SEED)
        hd2 = HDKeyDerivation(seed=_FIXED_SEED)
        k1, c1 = hd1.derive_path("m/44'/0'/0'/0'/0'")
        k2, c2 = hd2.derive_path("m/44'/0'/0'/0'/0'")
        assert k1 == k2
        assert c1 == c2

    def test_different_paths_different_keys(self, hd: HDKeyDerivation) -> None:
        """Different derivation paths must yield different keys."""
        k1, _ = hd.derive_path("m/44'/0'/0'/0'/0'")
        k2, _ = hd.derive_path("m/44'/0'/0'/0'/1'")
        assert k1 != k2

    def test_different_seeds_different_keys(self) -> None:
        """Different seeds must produce different master keys."""
        hd1 = HDKeyDerivation(seed=os.urandom(64))
        hd2 = HDKeyDerivation(seed=os.urandom(64))
        assert hd1.master_key != hd2.master_key


class TestChainCodeHandling:
    """Tests for chain code propagation."""

    def test_chain_code_differs_across_levels(self, hd: HDKeyDerivation) -> None:
        """Chain codes at different derivation depths must differ."""
        _, c1 = hd.derive_path("m/44'")
        _, c2 = hd.derive_path("m/44'/0'")
        assert c1 != c2

    def test_chain_code_is_deterministic(self, hd: HDKeyDerivation) -> None:
        """The same path must always yield the same chain code."""
        _, c1 = hd.derive_path("m/44'/0'/0'")
        _, c2 = hd.derive_path("m/44'/0'/0'")
        assert c1 == c2


class TestMultipleLevelsOfDerivation:
    """Tests for multi-level derivation paths."""

    def test_five_level_path(self, hd: HDKeyDerivation) -> None:
        """A full five-level BIP44-style hardened path should work."""
        key, chain = hd.derive_path("m/44'/0'/0'/0'/0'")
        assert len(key) == 32 and len(chain) == 32

    def test_deeper_path_still_works(self, hd: HDKeyDerivation) -> None:
        """Paths deeper than five levels should still derive correctly."""
        key, chain = hd.derive_path("m/44'/0'/0'/0'/0'/99'/1'")
        assert len(key) == 32 and len(chain) == 32

    def test_intermediate_keys_differ(self, hd: HDKeyDerivation) -> None:
        """Each intermediate level should produce a distinct key."""
        keys = set()
        for depth in range(1, 6):
            path = "m/" + "/".join(["0'"] * depth)
            k, _ = hd.derive_path(path)
            keys.add(k)
        assert len(keys) == 5, "All intermediate derivation levels should differ"
