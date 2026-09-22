#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The expanded Ed25519 signing form: INVARIANT-51 verified at key load
====================================================================

``ama_ed25519_sign`` derives ``A = [a]B`` on every signature to refuse a
64-byte key whose stored public half is not the one its seed generates.
``ama_ed25519_expand_secret_key`` does that once and binds ``a``, the nonce
prefix and ``A`` under a tag; ``ama_ed25519_sign_expanded`` re-checks the tag
instead.  :class:`~ama_cryptography.pqc_backends.Ed25519SigningKey` is the
Python owner of that form.

What is pinned here, and against what:

* **Conformance** — the RFC 8032 §7.1 vectors through the expanded path,
  and (where PyCA ``cryptography`` is installed) an independent verifier
  accepting the signatures.  A path consistent only with itself is not
  Ed25519.
* **Equivalence** — the 24 keypair-then-sign records of the frozen oracle
  (answers recorded from a backend that no longer exists in this tree), and
  fresh keys over a message-length sweep that crosses the 4 KiB stack
  threshold, all byte-equal to the per-call path.
* **The property** — a corrupted public half is refused at load with nothing
  retained; a corruption of the loaded form (every byte of it, through the
  buffer the object owns) is refused at signing with ``RuntimeError``; the
  two-signature transcript the fault attack needs cannot be produced.
* **Lifetime (INVARIANT-6)** — ``close()`` zeroes the buffer and the key
  refuses afterwards; the context manager closes; the seed path runs the
  INVARIANT-41 pairwise test once, at load, not per signature.

Every positive assertion compares against an independent oracle; every
negative one is a refusal.  No signature of this path's own is pinned.
"""

from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path
from typing import Any

import pytest

import ama_cryptography.pqc_backends as pb
from ama_cryptography import crypto_api
from ama_cryptography._module_state import pairwise_test_signature as _real_pct

pytestmark = pytest.mark.skipif(
    not pb._ED25519_NATIVE_AVAILABLE,
    reason="native Ed25519 backend not available in this build",
)

ORACLE = Path(__file__).parent / "oracle" / "ed25519_frozen_oracle.txt"

# RFC 8032 §7.1: (seed, public key, message, signature)
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]

LENGTHS = [0, 1, 2, 31, 32, 33, 63, 64, 65, 255, 256, 1023, 1024, 4095, 4096, 4097, 8192, 65536]

_HAVE_PYCA = importlib.util.find_spec("cryptography") is not None


def _oracle_sign_records() -> list[tuple[bytes, bytes, bytes, bytes]]:
    """The ``K seed pk msg sig`` records: keypair-then-sign, halves consistent."""
    out = []
    for line in ORACLE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("K "):
            continue
        _, seed, pk, msg, sig = line.split()
        out.append(
            (
                bytes.fromhex(seed),
                bytes.fromhex(pk),
                b"" if msg == "-" else bytes.fromhex(msg),
                bytes.fromhex(sig),
            )
        )
    return out


def _fresh() -> tuple[bytes, bytes]:
    pk, sk = pb.native_ed25519_keypair()
    return bytes(pk), bytes(sk)


def _pyca_verifies(public_key: bytes, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


class TestConformance:
    @pytest.mark.parametrize("seed_hex, pk_hex, msg_hex, sig_hex", RFC8032)
    def test_rfc8032_vectors_through_the_expanded_path(
        self, seed_hex: str, pk_hex: str, msg_hex: str, sig_hex: str
    ) -> None:
        seed = bytes.fromhex(seed_hex)
        # From the seed (the INVARIANT-41 arm) and from the 64-byte key.
        for secret in (seed, pb.native_ed25519_keypair_from_seed(seed)[1]):
            with pb.Ed25519SigningKey(secret) as key:
                assert key.public_key == bytes.fromhex(pk_hex)
                assert key.sign(bytes.fromhex(msg_hex)) == bytes.fromhex(sig_hex)

    @pytest.mark.skipif(not _HAVE_PYCA, reason="PyCA cryptography not installed")
    def test_an_independent_verifier_accepts_expanded_path_signatures(self) -> None:
        pk, sk = _fresh()
        with pb.Ed25519SigningKey(sk) as key:
            for n in LENGTHS:
                msg = bytes((i * 7 + n) & 0xFF for i in range(n))
                assert _pyca_verifies(pk, key.sign(msg), msg), n


class TestEquivalenceWithThePerCallPath:
    def test_the_frozen_oracle_sign_records(self) -> None:
        records = _oracle_sign_records()
        assert len(records) == 24, "fixture changed: tests/oracle/ed25519_frozen_oracle.txt"
        for seed, pk, msg, sig in records:
            _, sk = pb.native_ed25519_keypair_from_seed(seed)
            with pb.Ed25519SigningKey(sk) as key:
                assert key.public_key == pk
                assert key.sign(msg) == sig

    def test_fresh_keys_over_a_length_sweep(self) -> None:
        for _ in range(4):
            pk, sk = _fresh()
            with pb.Ed25519SigningKey(sk) as key:
                assert key.public_key == pk
                for n in LENGTHS:
                    msg = bytes((i * 13 + n) & 0xFF for i in range(n))
                    sig = key.sign(msg)
                    assert sig == pb.native_ed25519_sign(msg, sk)
                    assert pb.native_ed25519_verify(sig, msg, pk) is True

    def test_a_bytearray_key_is_borrowed_not_retained(self) -> None:
        """The caller's storage is what INVARIANT-6 asks them to wipe; the
        object must not depend on it after load."""
        pk, sk = _fresh()
        storage = bytearray(sk)
        key = pb.Ed25519SigningKey(storage)
        sig_before = key.sign(b"borrowed")
        for i in range(len(storage)):
            storage[i] = 0
        assert key.sign(b"borrowed") == sig_before
        assert pb.native_ed25519_verify(sig_before, b"borrowed", pk)
        key.close()

    def test_the_provider_hook_returns_the_same_signer(self) -> None:
        pk, sk = _fresh()
        provider = crypto_api.Ed25519Provider()
        msg = b"provider path"
        with provider.signing_key(sk[:32]) as from_seed, provider.signing_key(sk) as from_key:
            assert from_seed.sign(msg) == from_key.sign(msg) == provider.sign(msg, sk).signature
            assert from_seed.public_key == pk


class TestTheProperty:
    @pytest.mark.parametrize("bit", [0, 1, 7, 128, 255])
    def test_a_flipped_public_half_is_refused_at_load(self, bit: int) -> None:
        _pk, sk = _fresh()
        bad = bytearray(sk)
        bad[32 + bit // 8] ^= 1 << (bit % 8)
        with pytest.raises(ValueError, match="INVARIANT-51"):
            pb.Ed25519SigningKey(bytes(bad))

    def test_another_keys_public_half_is_refused_at_load(self) -> None:
        _pk_a, sk_a = _fresh()
        pk_b, _sk_b = _fresh()
        with pytest.raises(ValueError, match="INVARIANT-51"):
            pb.Ed25519SigningKey(sk_a[:32] + pk_b)

    def test_an_all_zero_public_half_is_refused_at_load(self) -> None:
        _pk, sk = _fresh()
        with pytest.raises(ValueError, match="INVARIANT-51"):
            pb.Ed25519SigningKey(sk[:32] + bytes(32))

    def test_every_byte_of_the_loaded_form_is_load_bearing(self) -> None:
        """Corrupt the buffer the object owns, one byte at a time, through
        ctypes: the shape a fault in the process produces after load.  Each
        corruption is refused at signing; restoring it restores signing."""
        _pk, sk = _fresh()
        key = pb.Ed25519SigningKey(sk)
        msg = b"post-load corruption"
        good = key.sign(msg)
        buf = key._expanded
        for i in range(pb.ED25519_EXPANDED_KEY_BYTES):
            original = buf[i]
            buf[i] = bytes([original[0] ^ 0x01])
            with pytest.raises(RuntimeError):
                key.sign(msg)
            buf[i] = original
            assert key.sign(msg) == good
        key.close()

    def test_the_two_signatures_the_attack_needs_cannot_both_exist(self) -> None:
        """s1 - s2 = (h1 - h2) * a needs two signatures over one message under
        two public halves sharing R.  Neither the load-time nor the sign-time
        refusal lets the second one be produced."""
        pk, sk = _fresh()
        msg = b"one message, two halves"
        key = pb.Ed25519SigningKey(sk)
        genuine = key.sign(msg)
        assert pb.native_ed25519_verify(genuine, msg, pk)

        corrupted = bytearray(sk)
        corrupted[40] ^= 0x10
        with pytest.raises(ValueError):
            pb.Ed25519SigningKey(bytes(corrupted))

        off = pb.ED25519_EXPANDED_PUBLIC_KEY_OFFSET + 8
        original = key._expanded[off]
        key._expanded[off] = bytes([original[0] ^ 0x10])
        with pytest.raises(RuntimeError):
            key.sign(msg)
        key._expanded[off] = original
        assert key.sign(msg) == genuine
        key.close()

    def test_a_wrong_length_is_refused(self) -> None:
        for n in (0, 31, 33, 63, 65, 128):
            with pytest.raises(ValueError, match="32 bytes"):
                pb.Ed25519SigningKey(bytes(n))


class TestLifetime:
    def test_close_zeroes_the_buffer_and_the_key_refuses(self) -> None:
        _pk, sk = _fresh()
        key = pb.Ed25519SigningKey(sk)
        buf = key._expanded
        assert any(buf.raw)
        key.close()
        assert key.closed
        assert buf.raw == bytes(pb.ED25519_EXPANDED_KEY_BYTES)
        with pytest.raises(RuntimeError, match="closed"):
            key.sign(b"after close")
        key.close()  # idempotent

    def test_the_context_manager_closes(self) -> None:
        _pk, sk = _fresh()
        with pb.Ed25519SigningKey(sk) as key:
            key.sign(b"inside")
        assert key.closed
        assert key._expanded.raw == bytes(pb.ED25519_EXPANDED_KEY_BYTES)

    def test_the_public_key_survives_close(self) -> None:
        pk, sk = _fresh()
        key = pb.Ed25519SigningKey(sk)
        key.close()
        assert key.public_key == pk

    def test_the_seed_path_runs_the_pairwise_test_once_at_load(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """INVARIANT-41: a seed-derived keypair is pairwise-tested before it is
        used.  Here that happens at load, and signing does not repeat it."""
        _pk, sk = _fresh()
        calls: list[str] = []

        def counting(*args: Any, **kwargs: Any) -> None:
            calls.append("pct")
            _real_pct(*args, **kwargs)

        monkeypatch.setattr(pb, "pairwise_test_signature", counting)
        key = pb.Ed25519SigningKey(sk[:32])
        assert calls == ["pct"]
        for _ in range(5):
            key.sign(b"no pct here")
        assert calls == ["pct"]
        key.close()

    def test_a_64_byte_key_does_not_re_run_key_generation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _pk, sk = _fresh()

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("64-byte load must not re-derive through keygen")

        monkeypatch.setattr(pb, "native_ed25519_keypair_from_seed", forbidden)
        with pb.Ed25519SigningKey(sk) as key:
            key.sign(b"direct expansion")

    def test_the_ctypes_buffer_is_sized_by_the_header_constant(self) -> None:
        _pk, sk = _fresh()
        with pb.Ed25519SigningKey(sk) as key:
            assert ctypes.sizeof(key._expanded) == pb.ED25519_EXPANDED_KEY_BYTES == 128
