#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Wipeable secrets, the native entropy seam, and the constant-time codecs.

INVARIANT-6 asks that secret material live where it can be zeroed.  The tests
here pin the mechanisms that make that true in the Python layer:

* every secret the library mints comes back in a ``bytearray``;
* a container's finalizer zeroes only what dies with it -- the
  extract-from-a-temporary bug zeroed a caller's key mid-statement;
* ``secure_random_fill`` draws in place from the native CSPRNG through one
  seam, with the continuous health test, and zeroes on any failure;
* ``_take_secret`` leaves no populated ctypes buffer behind;
* the PEM body regex compiles to no character-class bitmap (a table indexed
  by the private key's characters, INVARIANT-12 rule 4);
* the native Base64 codec and the BIP32 seckey operations are wired through
  ctypes with their refusals mapped.

Each test's docstring names what fails without its guard; those labelled
PIN were checked by reverting the guard (AGENTS.md 6.2).
"""

from __future__ import annotations

import base64
import ctypes
import dataclasses
import gc
import importlib
import json
import sys
from typing import Any, Callable, ClassVar

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _secret_material as sm
from ama_cryptography import key_formats as kf
from ama_cryptography.exceptions import (
    CryptoModuleError,
    KeyFormatError,
    NativeBackendUnavailableError,
)


@pytest.fixture
def restore_rng_state() -> Any:
    saved = ms._rng_state["previous"]
    saved_state, saved_reason = ms._MODULE_STATE, ms._ERROR_REASON
    yield
    ms._rng_state["previous"] = saved
    ms._MODULE_STATE, ms._ERROR_REASON = saved_state, saved_reason


# ---------------------------------------------------------------------------
# The extract-from-a-temporary bug (Critical, 2026-10-08)
# ---------------------------------------------------------------------------


def test_a_key_taken_from_a_temporary_keypair_is_not_zeroed() -> None:
    """PIN.  ``sk = generate_kyber_keypair().secret_key`` drops the keypair in
    the same statement, and its finalizer zeroed the caller's key: an all-zero
    ML-KEM decapsulation key, which implicit rejection does not refuse.
    Reverting ``_wipe_if_last_owner`` to an unconditional zero fails this."""
    pk, sk = (lambda kp: (kp.public_key, kp.secret_key))(pb.generate_kyber_keypair())
    assert any(sk), "the extracted secret key was zeroed by the dying keypair"
    enc = pb.kyber_encapsulate(pk)
    assert pb.kyber_decapsulate(enc.ciphertext, sk) == enc.shared_secret


@pytest.fixture
def zeroed_ids(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the id of every object the wipe path zeroes.

    Observing the buffer any other way -- a memoryview, a ctypes view --
    makes the observer a second holder, and the last-owner rule then
    (correctly) declines to wipe.  An id is not a reference.
    """
    seen: list[int] = []
    real = sm.zeroize

    def recording(value: Any) -> None:
        seen.append(id(value))
        real(value)

    monkeypatch.setattr(sm, "_zero", recording)
    return seen


def test_a_secret_only_the_container_holds_is_zeroed_when_it_dies(
    zeroed_ids: list[int],
) -> None:
    """PIN.  The other half of the rule: with no other holder, collection
    zeroes.  Removing the zeroing from ``_wipe_if_last_owner`` fails this."""
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=bytearray(b"\x5a" * 32))
    target = id(kp.secret_key)
    del kp
    assert target in zeroed_ids


def test_wipe_is_unconditional() -> None:
    held = bytearray(b"\x33" * 16)
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=held)
    kp.wipe()
    assert held == bytearray(16), "an explicit wipe() zeroes even a shared buffer"


@dataclasses.dataclass
class _Box(sm.SecretMaterial):
    """A container holding the same buffer more than once."""

    _SECRET_ATTRS: ClassVar[tuple[str, ...]] = ("a", "b", "c")
    a: Any
    b: Any
    c: list[Any]

    def __post_init__(self) -> None:
        self._adopt_secrets()


def test_a_buffer_held_twice_by_one_container_is_zeroed_when_it_dies(
    zeroed_ids: list[int],
) -> None:
    """PIN.  Two attributes naming one buffer: both references die with the
    container, but each read as an owner elsewhere, so the buffer was freed
    unwiped (PR #415 review).  Counting the container's own holdings fixes
    it; reverting the ``own - 1`` allowance fails this."""
    buf = bytearray(b"\x5a" * 16)
    box = _Box(buf, buf, [])
    ident = id(buf)
    del buf
    del box
    assert ident in zeroed_ids


def test_a_buffer_held_by_an_attribute_and_a_list_entry_is_zeroed(
    zeroed_ids: list[int],
) -> None:
    """PIN by the two allowances together: the attribute's finalizer and the
    list's each reach the buffer, so either allowance alone wipes it (6.3) --
    reverting both fails this, reverting one does not."""
    buf = bytearray(b"\x5b" * 16)
    box = _Box(buf, None, [buf])
    ident = id(buf)
    del buf
    del box
    assert ident in zeroed_ids


def test_a_buffer_held_twice_in_one_list_is_zeroed(zeroed_ids: list[int]) -> None:
    """PIN of the list-entry allowance alone: only the list path reaches a
    buffer no attribute names.  Reverting it fails this."""
    buf = bytearray(b"\x5d" * 16)
    box = _Box(None, None, [buf, buf])
    ident = id(buf)
    del buf
    del box
    assert ident in zeroed_ids


def test_an_aliased_buffer_someone_else_holds_is_spared(zeroed_ids: list[int]) -> None:
    """PIN, the boundary: one holder outside the container still keeps the
    buffer.  Over-counting the container's own holdings fails this."""
    buf = bytearray(b"\x5c" * 16)
    box = _Box(buf, buf, [buf])
    del box
    assert id(buf) not in zeroed_ids
    assert buf == bytearray(b"\x5c" * 16)


def test_adopt_converts_bytes_to_a_wipeable_bytearray() -> None:
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=b"\x01" * 3168)
    assert isinstance(kp.secret_key, bytearray)


# ---------------------------------------------------------------------------
# Every secret the library mints is a bytearray
# ---------------------------------------------------------------------------

_SECRET_OUTPUTS: dict[str, Callable[[], Any]] = {
    "native_ed25519_keypair": lambda: pb.native_ed25519_keypair()[1],
    "native_x25519_keypair": lambda: pb.native_x25519_keypair()[1],
    "native_nistp_keypair": lambda: pb.native_nistp_keypair("P-256")[1],
    "native_ml_kem_keypair": lambda: pb.native_ml_kem_keypair(768)[1],
    "native_ml_dsa_keypair": lambda: pb.native_ml_dsa_keypair(65)[1],
    "generate_kyber_keypair": lambda: pb.generate_kyber_keypair().secret_key,
    "kyber_encapsulate": lambda: pb.kyber_encapsulate(
        pb.generate_kyber_keypair().public_key
    ).shared_secret,
    "native_ml_kem_encapsulate": lambda: pb.native_ml_kem_encapsulate(
        768, pb.native_ml_kem_keypair(768)[0]
    )[1],
    "native_x25519_key_exchange": lambda: pb.native_x25519_key_exchange(
        pb.native_x25519_keypair()[1], pb.native_x25519_keypair()[0]
    ),
    "native_nistp_ecdh": lambda: pb.native_nistp_ecdh(
        "P-256", pb.native_nistp_keypair("P-256")[1], pb.native_nistp_keypair("P-256")[0]
    ),
    "native_hkdf (bytes, Cython)": lambda: pb.native_hkdf(b"k" * 32, 32),
    "native_hkdf (bytearray)": lambda: pb.native_hkdf(bytearray(b"k" * 32), 32),
    "native_hkdf (memoryview, ctypes)": lambda: pb.native_hkdf(memoryview(b"k" * 32), 32),
    "native_hkdf_sha384": lambda: pb.native_hkdf_sha384(b"k" * 32, 48),
    "native_pbkdf2_hmac_sha256": lambda: pb.native_pbkdf2_hmac_sha256(b"pw", b"salt", 2, 32),
    "native_argon2id": lambda: pb.native_argon2id(
        b"pw", b"saltsalt", t_cost=1, m_cost=64, parallelism=1
    ),
    "native_hmac_sha512_prf": lambda: pb.native_hmac_sha512_prf(b"k", b"m"),
    "native_secp256k1_seckey_tweak_add": lambda: pb.native_secp256k1_seckey_tweak_add(
        b"\x00" * 31 + b"\x05", b"\x00" * 31 + b"\x07"
    ),
    "frost dealt share": lambda: pb.frost_keygen_trusted_dealer(2, 3)[1][0],
    "secure_token_bytearray": lambda: ms.secure_token_bytearray(32),
    "ascon.generate_key": lambda: importlib.import_module("ama_cryptography.ascon").generate_key(),
    "PrivateKey.to_pkcs8": lambda: _p256()[1].to_pkcs8(),
    "PrivateKey.to_pem": lambda: _p256()[1].to_pem(),
    "PrivateKey.to_jwk": lambda: _p256()[1].to_jwk(),
    "PrivateKey.to_cose": lambda: _p256()[1].to_cose(),
    "private_key_to_jwk": lambda: kf.private_key_to_jwk(_p256()[1]),
    "private_key_to_cose": lambda: kf.private_key_to_cose(_p256()[1]),
    "encode_pem": lambda: kf.encode_pem(b"\x30\x03\x02\x01\x01", "PRIVATE KEY"),
    "decode_pem": lambda: kf.decode_pem(
        kf.encode_pem(b"\x30\x03\x02\x01\x01", "PRIVATE KEY"), "PRIVATE KEY"
    )[1],
}


@pytest.mark.parametrize("name", sorted(_SECRET_OUTPUTS))
def test_every_minted_secret_is_a_bytearray(name: str) -> None:
    """RANGE: the return-type contract across the secret-output surface."""
    value = _SECRET_OUTPUTS[name]()
    assert isinstance(value, bytearray), f"{name} returned {type(value).__name__}"
    assert any(value), f"{name} returned an all-zero secret"


@pytest.mark.parametrize("direction", ["encrypt", "decrypt"])
def test_an_ascon_key_reaches_c_in_place(monkeypatch: pytest.MonkeyPatch, direction: str) -> None:
    """PIN.  The AEAD wrappers copied the key into ``bytes`` (``_as_bytes``),
    leaving an unwipeable copy of a ``bytearray`` key on every call (PR #415
    review).  The key is now borrowed: what reaches C is the caller's own
    buffer.  Restoring ``_as_bytes`` for the key fails this."""
    ascon = importlib.import_module("ama_cryptography.ascon")
    key, nonce = ascon.generate_key(), ascon.generate_nonce()
    ciphertext, tag = ascon.aead128_encrypt(key, nonce, b"plaintext")
    symbol = f"ama_ascon_aead128_{direction}"
    real = getattr(ascon._lib, symbol)
    seen: list[Any] = []

    def recording(*args: Any) -> Any:
        seen.append(args[0])
        return real(*args)

    monkeypatch.setattr(ascon._lib, symbol, recording)
    if direction == "encrypt":
        ascon.aead128_encrypt(key, nonce, b"plaintext")
    else:
        assert ascon.aead128_decrypt(key, nonce, ciphertext, tag) == b"plaintext"
    address = ctypes.addressof((ctypes.c_char * len(key)).from_buffer(key))
    assert isinstance(seen[0], ctypes.Array) and ctypes.addressof(seen[0]) == address


def test_a_mac_tag_stays_bytes() -> None:
    """Tags are public; only the PRF form of HMAC-SHA-512 is a secret."""
    assert isinstance(pb.native_hmac_sha512(b"k", b"m"), bytes)
    assert pb.native_hmac_sha512(b"k", b"m") == bytes(pb.native_hmac_sha512_prf(b"k", b"m"))


# ---------------------------------------------------------------------------
# The native entropy seam
# ---------------------------------------------------------------------------


def test_secure_random_fill_writes_in_place() -> None:
    buf = bytearray(64)
    ident = id(buf)
    ms.secure_random_fill(buf)
    assert id(buf) == ident and any(buf)


def test_a_short_draw_is_filled_and_health_tested(restore_rng_state: Any) -> None:
    """A draw under the 32-byte window takes a separate window draw and is
    filled from it; the window's digest is what the state keeps."""
    ms._rng_state["previous"] = None
    buf = bytearray(7)
    ms.secure_random_fill(buf)
    assert any(buf)
    assert ms._rng_state["previous"] is not None
    assert ms._rng_state["previous"] != bytes(buf)


def test_a_read_only_buffer_is_refused() -> None:
    with pytest.raises(TypeError, match="writable"):
        ms.secure_random_fill(memoryview(b"\x00" * 32))


def test_a_failing_source_leaves_the_buffer_zeroed(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  A source that writes and then fails must not leave its partial
    output in the caller's buffer.  Removing the zeroing in
    ``secure_random_fill``'s exception path fails this."""

    def half_then_fail(view: Any) -> None:
        memoryview(view).cast("B")[:16] = b"\xa5" * 16
        raise CryptoModuleError("entropy source failed")

    monkeypatch.setattr(ms, "_entropy_fill", half_then_fail)
    buf = bytearray(b"\x00" * 32)
    with pytest.raises(CryptoModuleError):
        ms.secure_random_fill(buf)
    assert buf == bytearray(32)


def test_a_stuck_source_enters_the_error_state(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    def stuck(view: Any) -> None:
        out = memoryview(view).cast("B")
        out[:] = b"\x42" * out.nbytes

    monkeypatch.setattr(ms, "_entropy_fill", stuck)
    ms._rng_state["previous"] = None
    ms.secure_random_fill(bytearray(32))
    second = bytearray(32)
    with pytest.raises(CryptoModuleError, match="Continuous RNG"):
        ms.secure_random_fill(second)
    assert second == bytearray(32), "the refused draw was zeroed"
    assert ms.module_status() == "ERROR"


def test_post_draws_through_the_same_seam(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  POST's RNG stage examines the source the library draws from: a
    substituted source is the one it sees.  Pointing the stage back at a
    different source (``secrets``, or the native fill directly) fails this."""
    from ama_cryptography import _self_test as st

    seen: list[int] = []

    def recording(view: Any) -> None:
        out = memoryview(view).cast("B")
        seen.append(out.nbytes)
        out[:] = bytes((len(seen) * 7 + i) & 0xFF for i in range(out.nbytes))

    monkeypatch.setattr(ms, "_entropy_fill", recording)
    saved = list(st._SELF_TEST_RESULTS)
    try:
        passed, reason = st._run_rng_stage()
    finally:
        st._SELF_TEST_RESULTS[:] = saved
    assert passed, reason
    assert seen == [32, 32]


# ---------------------------------------------------------------------------
# _take_secret
# ---------------------------------------------------------------------------


def test_take_secret_wipes_the_ctypes_buffer() -> None:
    """PIN.  The ctypes staging buffer is zeroed once the bytearray is made;
    removing the ``_wipe`` from ``_take_secret`` fails this."""
    buf = ctypes.create_string_buffer(b"\x77" * 24, 24)
    out = pb._take_secret(buf, 20)
    assert out == bytearray(b"\x77" * 20)
    assert buf.raw == bytes(24)


def test_an_ed25519_key_that_fails_its_pairwise_test_is_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A key that fails the INVARIANT-41 pairwise test is zeroed before
    the error propagates (INVARIANT-6, every exit path); before 2026-10-08 it
    was dropped intact.  Moving the test outside the zeroing guard fails this."""
    seen: list[bytearray] = []

    def failing_pct(sign: Any, verify: Any, sk: bytearray, pk: bytes, name: str) -> None:
        seen.append(sk)
        assert any(sk), "the pairwise test must see the real key"
        raise CryptoModuleError(f"{name} pairwise consistency test failed (simulated)")

    monkeypatch.setattr(pb, "pairwise_test_signature", failing_pct)
    with pytest.raises(CryptoModuleError, match="simulated"):
        pb.native_ed25519_keypair()
    assert len(seen) == 1
    assert seen[0] == bytearray(len(seen[0]))


def _key_forms() -> list[Any]:
    return [
        bytearray(b"\x5a" * 32),
        memoryview(bytearray(b"\x5a" * 32)),
        ctypes.create_string_buffer(b"\x5a" * 32, 32),
    ]


def _raw(key: Any) -> bytes:
    return key.raw if isinstance(key, ctypes.Array) else bytes(key)


@pytest.mark.parametrize("form", range(3), ids=["bytearray", "memoryview", "ctypes"])
@pytest.mark.parametrize("which", ["signature", "kem", "agreement"])
def test_a_key_that_fails_any_pairwise_test_is_zeroed(
    which: str, form: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PIN.  The three pairwise-test helpers zero the key they were handed
    when the test raises, in every buffer form a keygen passes them; deleting
    the scrub in ``_KeyReleasedOnlyIfConsistent.__exit__`` fails all nine."""
    monkeypatch.setattr(ms, "_set_error", lambda reason: None)
    key = _key_forms()[form]

    def boom(*_args: Any) -> Any:
        raise ValueError("simulated fault")

    with pytest.raises(CryptoModuleError):
        if which == "signature":
            ms.pairwise_test_signature(boom, boom, key, b"pk", "test")
        elif which == "kem":
            ms.pairwise_test_kem(boom, boom, b"pk", key, "test")
        else:
            ms.pairwise_test_agreement(boom, (b"epk", bytearray(32)), key, b"pk", "test")
    assert _raw(key) == bytes(32)


def test_a_key_that_passes_is_left_intact() -> None:
    """SMOKE.  The guard acts on failure only."""
    key = bytearray(b"\x5a" * 32)
    ms.pairwise_test_signature(lambda m, k: b"sig", lambda m, s, p: True, key, b"pk", "test")
    assert key == bytearray(b"\x5a" * 32)


def test_a_key_whose_test_could_not_run_is_zeroed_too() -> None:
    """PIN.  A test that could not run (the backend refused) releases no key
    either, so its key is zeroed although the module stays OPERATIONAL."""
    key = bytearray(b"\x5a" * 32)

    def refused(*_args: Any) -> Any:
        raise pb.NativeBackendUnavailableError("not built")

    with pytest.raises(pb.NativeBackendUnavailableError):
        ms.pairwise_test_signature(refused, refused, key, b"pk", "test")
    assert key == bytearray(32)


# ---------------------------------------------------------------------------
# The PEM body is scanned, not matched: no table indexed by a secret character
# ---------------------------------------------------------------------------


def test_the_pem_block_is_scanned_without_a_regular_expression() -> None:
    """PIN.  A regex engine compiles a set of more than two runs to a 256-bit
    bitmap indexed by each character -- for a private-key PEM, by the key
    (INVARIANT-12 rule 4) -- and ``re.Match.group`` on a ``bytearray`` subject
    returns ``bytes``.  The block is now scanned by index in a ``bytearray``
    (``tests/test_private_key_export.py`` pins the scanner's calls); the
    module holds no ``re`` and no compiled PEM pattern.  Reintroducing either
    fails this."""
    assert "re" not in vars(kf), "key_formats imports re again"
    assert not hasattr(kf, "_PEM_RE"), "a compiled PEM pattern is back"


def test_crlf_pem_is_still_accepted() -> None:
    public, _ = _p256()
    crlf = public.to_pem().replace("\n", "\r\n")
    assert kf.load_spki(crlf) == public


def _p256() -> Any:
    _, secret = pb.native_nistp_keypair("P-256")
    key = kf.PrivateKey("P-256", secret)
    return key.public(), key


# ---------------------------------------------------------------------------
# The native Base64 codec through ctypes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 2, 3, 31, 32, 33, 64, 65, 2592])
def test_the_native_codec_agrees_with_the_stdlib_reference(length: int) -> None:
    data = bytes((i * 167 + 13) & 0xFF for i in range(length))
    std = pb.native_base64_encode(data, pb.BASE64_STANDARD_PADDED)
    url = pb.native_base64_encode(data, pb.BASE64_URL_UNPADDED)
    assert bytes(std) == base64.b64encode(data)
    assert bytes(url) == base64.urlsafe_b64encode(data).rstrip(b"=")
    assert pb.native_base64_decode(bytes(std), pb.BASE64_STANDARD_PADDED) == data
    assert pb.native_base64_decode(bytes(url), pb.BASE64_URL_UNPADDED) == data


@pytest.mark.parametrize(
    "text,variant",
    [
        (b"Zh==", pb.BASE64_STANDARD_PADDED),  # pad bits
        (b"Zg=", pb.BASE64_STANDARD_PADDED),  # length
        (b"Zm9v!g==", pb.BASE64_STANDARD_PADDED),  # alphabet
        (b"Zg==", pb.BASE64_URL_UNPADDED),  # padding in url
        (b"Zm+v", pb.BASE64_URL_UNPADDED),  # standard alphabet in url
        (b"Z", pb.BASE64_URL_UNPADDED),  # impossible length
    ],
)
def test_the_native_codec_refuses_non_canonical_text(text: bytes, variant: int) -> None:
    with pytest.raises(ValueError, match="canonical"):
        pb.native_base64_decode(text, variant)


def test_an_unknown_variant_is_refused() -> None:
    with pytest.raises(ValueError, match="variant"):
        pb.native_base64_encode(b"x", 0)


def test_a_pem_with_a_space_in_its_body_is_refused() -> None:
    public, _ = _p256()
    pem = kf.encode_pem(public.to_spki(), "PUBLIC KEY").decode("ascii")
    lines = pem.split("\n")
    lines[1] = lines[1][:10] + " " + lines[1][11:]
    with pytest.raises(KeyFormatError, match="base64"):
        kf.load_spki("\n".join(lines))


# ---------------------------------------------------------------------------
# BIP32 through the native seckey operations
# ---------------------------------------------------------------------------

_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def test_seckey_verify_bounds() -> None:
    assert pb.native_secp256k1_seckey_verify((1).to_bytes(32, "big"))
    assert pb.native_secp256k1_seckey_verify((_N - 1).to_bytes(32, "big"))
    assert not pb.native_secp256k1_seckey_verify(bytes(32))
    assert not pb.native_secp256k1_seckey_verify(_N.to_bytes(32, "big"))


def test_seckey_tweak_add_matches_modular_addition() -> None:
    for k, t in [(5, 7), (_N - 1, _N - 1), (_N - 10, 9), (1, 0)]:
        out = pb.native_secp256k1_seckey_tweak_add(k.to_bytes(32, "big"), t.to_bytes(32, "big"))
        assert int.from_bytes(out, "big") == (k + t) % _N


def test_seckey_tweak_add_refuses_a_zero_sum_and_an_oversized_tweak() -> None:
    with pytest.raises(ValueError, match="tweak refused"):
        pb.native_secp256k1_seckey_tweak_add((1).to_bytes(32, "big"), (_N - 1).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="tweak refused"):
        pb.native_secp256k1_seckey_tweak_add((1).to_bytes(32, "big"), _N.to_bytes(32, "big"))


def test_an_invalid_child_is_reported_as_bip32_says(monkeypatch: pytest.MonkeyPatch) -> None:
    """BIP32: I_L >= n or a zero child means "proceed with the next index"."""
    from ama_cryptography.key_management import HDKeyDerivation

    hd = HDKeyDerivation(seed=bytes(range(64)))

    def refuse(_key: Any, _tweak: Any) -> bytearray:
        raise ValueError("secp256k1 tweak refused")

    monkeypatch.setattr(pb, "native_secp256k1_seckey_tweak_add", refuse)
    with pytest.raises(ValueError, match="Try next index"):
        hd.derive_path("m/0'")


def test_an_invalid_master_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from ama_cryptography.key_management import HDKeyDerivation

    monkeypatch.setattr(pb, "native_secp256k1_seckey_verify", lambda _key: False)
    with pytest.raises(ValueError, match="Invalid BIP32 master key"):
        HDKeyDerivation(seed=bytes(range(64)))


def test_derive_path_returns_fresh_buffers_not_the_masters() -> None:
    """``m`` hands back copies: a caller wiping its result must not zero the
    hierarchy's own master key."""
    from ama_cryptography.key_management import HDKeyDerivation

    hd = HDKeyDerivation(seed=bytes(range(64)))
    key, _chain = hd.derive_path("m")
    assert key == hd.master_key and key is not hd.master_key
    key[:] = bytes(32)
    assert any(hd.master_key)


def test_a_private_key_is_unhashable_by_decision() -> None:
    """PIN.  ``__hash__`` is None, as for any unhashable type, so ``hash()``
    refuses and ``collections.abc.Hashable`` says so too -- the former
    raising ``__hash__`` method left ``Hashable`` reporting True (CodeQL).
    Without ``_unhashable`` the frozen dataclass generates a field hash, which
    ``isinstance(key, Hashable)`` reports as hashable.  Equality still works,
    and a key built from ``bytes`` is unhashable too."""
    import collections.abc

    _public, key = _p256()
    assert kf.PrivateKey.__hash__ is None
    assert not isinstance(key, collections.abc.Hashable)
    with pytest.raises(TypeError, match="unhashable"):
        hash(key)
    from_bytes = kf.PrivateKey(key.algorithm, bytes(key.key), key.public_key, None)
    assert not isinstance(from_bytes, collections.abc.Hashable)
    assert key == from_bytes


def test_private_key_equality_compares_the_secrets_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The dataclass-generated ``__eq__`` compared the key with
    ``bytearray.__eq__`` -- ``memcmp``, which stops at the first difference
    -- so comparing a candidate with a held key leaked where they differ
    (INVARIANT-12; PR #415 review).  Equality now goes through the native
    constant-time comparison for ``key`` and ``seed``, and every field is
    compared whichever differs.  Removing ``@constant_time_equality()`` from
    ``PrivateKey`` fails this."""
    from ama_cryptography import secure_memory

    calls: list[tuple[bytes, bytes]] = []
    real = secure_memory.constant_time_compare

    def recording(a: Any, b: Any) -> bool:
        calls.append((bytes(a), bytes(b)))
        return real(a, b)

    monkeypatch.setattr(ms, "_secret_comparator", recording)
    _public, key = _p256()
    same = kf.PrivateKey(key.algorithm, bytes(key.key), key.public_key, None)
    other = kf.PrivateKey(key.algorithm, bytes(_p256()[1].key), key.public_key, None)
    assert key == same
    assert key != other
    assert (bytes(key.key), bytes(same.key)) in calls
    assert (bytes(key.key), bytes(other.key)) in calls


def _secret_containers() -> list[type]:
    # Importing a module defines its containers, which registers them as
    # subclasses.
    for module in ("crypto_api", "hybrid_combiner", "key_formats", "legacy_compat"):
        importlib.import_module(f"ama_cryptography.{module}")

    found: list[type] = []
    pending = list(sm.SecretMaterial.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if dataclasses.is_dataclass(cls) and cls.__module__.startswith("ama_cryptography."):
            found.append(cls)
    return [*found, pb.DilithiumKeyPair, pb.KyberKeyPair, pb.SphincsKeyPair]


@pytest.mark.parametrize("cls", _secret_containers(), ids=lambda c: c.__qualname__)
def test_every_secret_container_compares_in_constant_time(cls: type) -> None:
    """RANGE (an inventory): every dataclass holding secrets carries the
    constant-time ``__eq__``, so a new container that forgets it fails here.
    Removing the decorator from any one of them fails its row."""
    fields = getattr(cls.__eq__, "constant_time_secret_fields", None)
    assert fields, f"{cls.__qualname__} compares its secrets with the generated __eq__"


# ---------------------------------------------------------------------------
# A refused key import zeroes the secret it had already sliced out
# ---------------------------------------------------------------------------


@pytest.fixture
def zeroed_values(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The contents of every bytearray ``key_formats`` zeroes, just before:
    directly (its ``_zero``) and through ``ScrubOnRaise``.

    Only those.  ``_secret_material``'s ``_zero`` also serves every
    finalizer, and a test's own throwaway key built from the same seed is
    wiped by its finalizer when it dies -- recording that made a test pass
    with the guard under test removed (measured: three mutants survived).
    """
    seen: list[bytes] = []
    _record_scrubs_only(monkeypatch, seen)
    real = sm.zeroize

    def recording(value: Any) -> None:
        if isinstance(value, bytearray):
            seen.append(bytes(value))
        real(value)

    monkeypatch.setattr(kf, "_zero", recording)
    return seen


def _record_scrubs_only(monkeypatch: pytest.MonkeyPatch, seen: list[bytes]) -> None:
    """Record what ``ScrubOnRaise`` zeroes, and nothing a finalizer does."""
    scrubbing = [False]
    real_exit = sm.ScrubOnRaise.__exit__
    real_zero = sm.zeroize

    def exiting(self: Any, *exc: Any) -> None:
        scrubbing[0] = True
        try:
            real_exit(self, *exc)
        finally:
            scrubbing[0] = False

    def zeroing(value: Any) -> None:
        if scrubbing[0] and isinstance(value, bytearray):
            seen.append(bytes(value))
        real_zero(value)

    monkeypatch.setattr(sm.ScrubOnRaise, "__exit__", exiting)
    monkeypatch.setattr(sm, "_zero", zeroing)


def _two_p256() -> tuple[Any, Any]:
    return _p256()[1], _p256()[1]


def _ml_dsa(seed: bytes) -> Any:
    alg = kf._lookup("ML-DSA-65")
    public, secret = pb.native_ml_dsa_keypair_from_seed(alg.pq_set, seed)
    return kf.PrivateKey("ML-DSA-65", secret, public, seed)


_SEED_A, _SEED_B = bytes(range(32)), bytes(range(32, 64))


def test_a_refused_ec_pkcs8_zeroes_its_secret(zeroed_values: list[bytes]) -> None:
    """PIN.  The public half names another key, so the import is refused after
    the scalar was sliced out.  Removing ``held(secret)`` from the EC arm of
    ``_pkcs8_private_key_checked`` fails this."""
    a, b = _two_p256()
    der = kf.PrivateKey("P-256", bytes(a.key), b.public().key).to_pkcs8(include_public_key=True)
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.load_pkcs8(der)
    assert bytes(a.key) in zeroed_values


def test_a_refused_ec_private_key_body_zeroes_its_secret(zeroed_values: list[bytes]) -> None:
    """PIN.  An ECPrivateKey field tag [2] is refused inside the RFC 5915
    parser, after the scalar was sliced.  Removing ``held(...)`` from
    ``_parse_ec_private_key`` fails this."""
    a, _ = _two_p256()
    der = a.to_pkcs8(include_public_key=True)
    tampered = der.replace(bytes.fromhex("a144"), bytes.fromhex("a244"), 1)
    assert tampered != der
    with pytest.raises(KeyFormatError, match="unexpected ECPrivateKey field tag 0xA2"):
        kf.load_pkcs8(tampered)
    assert bytes(a.key) in zeroed_values


def test_a_refused_okp_pkcs8_zeroes_its_secret(zeroed_values: list[bytes]) -> None:
    """PIN.  Removing ``held(...)`` from the OKP arm fails this."""
    seed_a, seed_b = bytes(range(32)), bytes(range(1, 33))
    public_b = kf.PrivateKey("Ed25519", seed_b).public().key
    der = kf.PrivateKey("Ed25519", seed_a, public_b).to_pkcs8(include_public_key=True)
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.load_pkcs8(der)
    assert seed_a in zeroed_values


def test_an_inconsistent_both_form_zeroes_all_three_secrets(zeroed_values: list[bytes]) -> None:
    """PIN.  The seed of key B with the expanded key of key A: refused under
    RFC 9881 8.2.  The seed, the supplied expanded key and the expansion of
    the seed (B's expanded key, minted only to be compared) are all zeroed.
    Removing ``held`` from the both arm, or the ``_zero(from_seed)``, fails
    this."""
    a, b = _ml_dsa(_SEED_A), _ml_dsa(_SEED_B)
    der = a.to_pkcs8(pq_format="both", include_public_key=False).replace(_SEED_A, _SEED_B, 1)
    with pytest.raises(KeyFormatError, match="'both' private key is inconsistent"):
        kf.load_pkcs8(der, verify_pq_consistency=True)
    assert _SEED_B in zeroed_values
    assert bytes(a.key) in zeroed_values
    assert bytes(b.key) in zeroed_values


def test_a_consistent_both_form_zeroes_only_the_comparison_copy(
    zeroed_values: list[bytes],
) -> None:
    """PIN.  On success the seed's expansion is still zeroed (it was minted
    only to be compared) and the key keeps its own copy.  Removing the
    ``_zero(from_seed)`` fails this."""
    a = _ml_dsa(_SEED_A)
    loaded = kf.load_pkcs8(
        a.to_pkcs8(pq_format="both", include_public_key=False), verify_pq_consistency=True
    )
    assert bytes(a.key) in zeroed_values
    assert loaded.key == a.key and loaded.seed == _SEED_A


@pytest.mark.parametrize("pq_format", ["seed", "expandedKey"])
def test_a_refused_pq_pkcs8_zeroes_its_secret_and_seed(
    zeroed_values: list[bytes], pq_format: str
) -> None:
    """PIN.  The outer publicKey is key B's: refused in ``_finish_pq_import``,
    after the parse returned.  Removing ``held(secret)`` / ``held(seed)`` from
    the PQ arm of ``_pkcs8_private_key_checked`` fails this."""
    a, b = _ml_dsa(_SEED_A), _ml_dsa(_SEED_B)
    seed = _SEED_A if pq_format == "seed" else None
    mixed = kf.PrivateKey("ML-DSA-65", bytes(a.key), b.public_key, seed)
    der = mixed.to_pkcs8(pq_format=pq_format, include_public_key=True)
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.load_pkcs8(der, verify_pq_consistency=True)
    assert bytes(a.key) in zeroed_values
    if seed is not None:
        assert _SEED_A in zeroed_values


def _ml_dsa_pkcs8(inner: bytes) -> bytes:
    """A PKCS#8 for ML-DSA-65 whose privateKey OCTET STRING holds ``inner``."""
    from ama_cryptography._asn1 import der_integer, der_octet_string, der_sequence

    valid = _ml_dsa(_SEED_A).to_pkcs8(pq_format="seed", include_public_key=False)
    assert valid[5:7] == b"\x30\x0b"  # the 13-octet AlgorithmIdentifier
    return der_sequence(der_integer(0), valid[5:18], der_octet_string(inner))


def test_a_refused_seed_arm_zeroes_its_seed(zeroed_values: list[bytes]) -> None:
    """PIN.  A 31-octet seed is sliced out, then refused by the expansion.
    Removing ``held(...)`` from the seed arm of ``_parse_pq_private_key``
    fails this."""
    from ama_cryptography._asn1 import der_tagged

    short = _SEED_B[:31]
    with pytest.raises(KeyFormatError, match="seed must be 32 bytes"):
        kf.load_pkcs8(_ml_dsa_pkcs8(der_tagged(0, short, constructed=False)))
    assert short in zeroed_values


def test_a_refused_expanded_key_arm_zeroes_its_key(zeroed_values: list[bytes]) -> None:
    """PIN.  Trailing data after the expandedKey is refused once it has been
    sliced.  Removing ``held(...)`` from the expandedKey arm fails this."""
    from ama_cryptography._asn1 import der_octet_string

    a = _ml_dsa(_SEED_A)
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(_ml_dsa_pkcs8(der_octet_string(bytes(a.key)) + b"\x05\x00"))
    assert bytes(a.key) in zeroed_values


def test_a_refused_jwk_zeroes_its_decoded_d(zeroed_values: list[bytes]) -> None:
    """PIN.  ``d`` decodes into a fresh bytearray; ``x``/``y`` name another
    key.  Removing ``held(...)`` from ``jwk_to_private_key`` fails this."""
    a, b = _two_p256()
    jwk = json.loads(kf.private_key_to_jwk(a))
    jwk.update({k: v for k, v in kf.public_key_to_jwk(b.public()).items() if k in "xy"})
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.jwk_to_private_key(jwk)
    assert bytes(a.key) in zeroed_values


def test_a_refused_cose_key_zeroes_its_d(zeroed_values: list[bytes]) -> None:
    """PIN.  ``d`` is decoded from a bytearray copy, so it is a wipeable
    slice; ``x``/``y`` name another key.  Removing ``held(...)`` from
    ``cose_to_private_key``, or decoding from ``bytes`` again, fails this."""
    a, b = _two_p256()
    other = kf.PublicKey("P-256", b.public().key)
    mixed = kf.PrivateKey("P-256", bytes(a.key), other.key)
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.cose_to_private_key(mixed.to_cose())
    assert bytes(a.key) in zeroed_values


def test_an_accepted_cose_key_zeroes_its_working_copy(zeroed_values: list[bytes]) -> None:
    """PIN.  The whole COSE_Key (which contains ``d``) is copied once to
    decode from; that copy is zeroed, and the key holds a bytearray.
    Removing the ``_zero(buf)`` from ``_load_cose`` fails this."""
    a, _ = _two_p256()
    encoded = a.to_cose()
    loaded = kf.cose_to_private_key(encoded)
    assert encoded in zeroed_values
    assert isinstance(loaded.key, bytearray) and loaded.key == a.key


def test_a_private_cose_key_with_a_byte_string_label_still_parses() -> None:
    """PIN.  Decoding from a bytearray makes every byte string a bytearray,
    and a bytearray map key is unhashable: ``mapping[key] = ...`` raised
    TypeError past the KeyFormatError boundary.  A COSE_Key is an open map,
    so an unknown label -- a byte string included -- must not make it
    unparseable.  Removing the map-key ``bytes(key)`` in ``_CborReader``
    fails this."""
    from ama_cryptography._asn1 import cbor_decode_canonical, cbor_encode_canonical

    a, _ = _two_p256()
    decoded = cbor_decode_canonical(a.to_cose())
    decoded[b"label"] = 0
    loaded = kf.cose_to_private_key(cbor_encode_canonical(decoded))
    assert loaded.key == a.key


def test_deriving_an_ed25519_public_key_zeroes_the_expanded_secret(
    zeroed_values: list[bytes],
) -> None:
    """PIN.  The keygen returns the 64-octet ``seed || pk`` alongside the
    public half; it is zeroed.  Restoring ``public, _ = ...`` fails this."""
    seed = bytes(range(7, 39))
    public = kf.PrivateKey("Ed25519", seed).derive_public_key().key
    assert seed + public in zeroed_values


def test_wiping_a_package_result_wipes_every_keypair_it_owns() -> None:
    """PIN.  ``CryptoPackageResult`` owns and exposes its keypairs; an
    explicit ``wipe()`` zeroes their private halves too.  Removing
    ``_SECRET_CHILDREN`` from the class, or the cascade from
    ``SecretMaterial.wipe``, fails this."""
    from ama_cryptography.crypto_api import (
        AlgorithmType,
        CryptoPackageConfig,
        create_crypto_package,
    )

    result = create_crypto_package(
        b"cascade", CryptoPackageConfig(signature_algorithm=AlgorithmType.HYBRID_SIG)
    )
    secrets = [kp.secret_key for kp in result.keypairs.values()]
    assert len(secrets) >= 1 and all(any(sk) for sk in secrets)
    result.wipe()
    assert not any(any(sk) for sk in secrets)
    assert not any(result.hmac_key)


def test_wiping_a_key_management_system_wipes_both_signing_keys() -> None:
    """PIN.  ``KeyManagementSystem.wipe()`` reaches the Ed25519 and ML-DSA
    keypairs it holds.  Removing ``_SECRET_CHILDREN`` fails this."""
    from ama_cryptography.legacy_compat import generate_key_management_system

    kms = generate_key_management_system("cascade")
    ed_secret = kms.ed25519_keypair.private_key
    assert kms.dilithium_keypair is not None
    ml_secret = kms.dilithium_keypair.secret_key
    assert any(ed_secret) and any(ml_secret)
    kms.wipe()
    assert not any(ed_secret) and not any(ml_secret) and not any(kms.master_secret)


class _Holder:
    """A child secret holder whose ``wipe()`` can be made to fail first."""

    def __init__(self, fail: bool = False) -> None:
        self.secret = bytearray(b"\x5a" * 8)
        self.fail = fail

    def wipe(self) -> None:
        if self.fail:
            raise RuntimeError("this child's wipe failed")
        sm.zeroize(self.secret)


class _Parent(sm.SecretMaterial):
    _SECRET_ATTRS: ClassVar[tuple[str, ...]] = ("key",)
    _SECRET_CHILDREN: ClassVar[tuple[str, ...]] = ("first", "second")

    def __init__(self, first: Any, second: Any) -> None:
        self.key = bytearray(b"\xa5" * 8)
        self.first = first
        self.second = second


def test_a_failed_child_wipe_does_not_spare_its_siblings() -> None:
    """PIN.  A child whose ``wipe()`` raises does not stop the cascade over
    the others in the same dict; the failure still propagates.  Looping over
    the children with a bare ``child.wipe()`` fails this."""
    kept = _Holder()
    parent = _Parent({"bad": _Holder(fail=True), "good": kept}, None)
    with pytest.raises(RuntimeError, match="this child's wipe failed"):
        parent.wipe()
    assert not any(kept.secret)


def test_a_failed_child_wipe_does_not_spare_the_next_attribute() -> None:
    """PIN.  The same across ``_SECRET_CHILDREN`` attributes, as in
    ``KeyManagementSystem``: the second attribute's child is wiped after the
    first attribute's fails.  A loop over the attributes fails this."""
    kept = _Holder()
    parent = _Parent(_Holder(fail=True), kept)
    with pytest.raises(RuntimeError, match="this child's wipe failed"):
        parent.wipe()
    assert not any(kept.secret) and not any(parent.key)


def test_a_failed_attribute_wipe_does_not_spare_the_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  Zeroing the object's own attributes and cascading to its
    children share one exit stack, so a failure in the first does not skip
    the second.  Two stacks in sequence fail this."""

    def failing_zero(value: Any) -> None:
        raise RuntimeError("this attribute's wipe failed")

    monkeypatch.setattr(sm, "_zero", failing_zero)
    kept = _Holder()
    parent = _Parent(None, kept)
    with pytest.raises(RuntimeError, match="this attribute's wipe failed"):
        parent.wipe()
    assert not any(kept.secret)
    # Restored before ``parent`` is collected, so its finalizer zeroes
    # ``key`` with the real helper and records no error.
    monkeypatch.undo()


def test_a_dying_parent_does_not_wipe_a_child_its_caller_kept() -> None:
    """PIN.  Only the explicit wipe cascades.  A caller that keeps a keypair
    from a result it drops keeps a usable key -- the extract-from-a-temporary
    rule.  Cascading from ``__del__`` fails this."""
    from ama_cryptography.crypto_api import create_crypto_package

    keypair = next(iter(create_crypto_package(b"kept").keypairs.values()))
    gc.collect()
    assert any(keypair.secret_key)


def test_a_signing_key_changed_in_place_is_not_served_from_the_memo() -> None:
    """PIN.  ``create_crypto_package`` memoizes the expanded signing key on
    the config, keyed by element identity -- which implied value only while
    keys were immutable ``bytes``.  A bytearray seed overwritten in place with
    another valid key keeps its identity; served from the memo, the package
    would be signed with the PREVIOUS key, silently.  It must be re-expanded,
    and the new seed then fails to match the public key the config carries.
    (A seed wiped to zeros is refused earlier, by the all-zero check, so it
    cannot stand in for this case.)  Removing ``_expansion_still_matches``
    from the memo test fails this."""
    from ama_cryptography.crypto_api import (
        AlgorithmType,
        CryptoPackageConfig,
        create_crypto_package,
    )

    public, expanded = pb.native_ed25519_keypair()
    _other_public, other_expanded = pb.native_ed25519_keypair()
    seed = bytearray(memoryview(expanded)[:32])
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(public, seed)
    )
    create_crypto_package(b"before the change", config)
    seed[:] = memoryview(other_expanded)[:32]
    with pytest.raises(ValueError, match="signing_keypair mismatch"):
        create_crypto_package(b"after the change", config)


# ---------------------------------------------------------------------------
# Secrets minted on a path that later raises (PR #415, review of f300f6f7)
# ---------------------------------------------------------------------------


@pytest.fixture
def sm_zeroed_values(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The contents of every bytearray ``ScrubOnRaise`` zeroes, recorded just
    before (finalizer wipes excluded: see ``zeroed_values``)."""
    seen: list[bytes] = []
    _record_scrubs_only(monkeypatch, seen)
    return seen


@pytest.mark.parametrize("step", ["check_crypto_permitted", "entropy_source", "_resolve_native"])
def test_a_draw_refused_before_it_starts_still_zeroes_the_buffer(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any, step: str
) -> None:
    """PIN.  The error-state check, the source lookup and the digest-kernel
    lookup ran before the zeroing guard, so a refusal left whatever the
    caller's buffer held.  Moving any of them back out fails its row."""

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise CryptoModuleError(f"{step} refused")

    monkeypatch.setattr(ms, step, refuse)
    buf = bytearray(b"\x5a" * 32)
    with pytest.raises(CryptoModuleError):
        ms.secure_random_fill(buf)
    assert buf == bytearray(32)


def test_the_pairwise_guard_zeroes_a_list_of_shares() -> None:
    """PIN.  A FROST dealer's shares are a list; the guard zeroed only a
    single buffer, so a failed test dropped every share intact.  Removing
    the list arm of ``_zero_released_key`` fails this."""
    shares = [bytearray(b"\x11" * 64), bytearray(b"\x22" * 64)]
    # The guard's exit path driven directly, as a ``with`` block whose body
    # raises would drive it: no statement follows an unconditional raise.
    guard = ms._KeyReleasedOnlyIfConsistent(shares)
    guard.__enter__()
    failure = RuntimeError("pairwise test failed")
    guard.__exit__(type(failure), failure, None)
    assert shares == [bytearray(64), bytearray(64)]


def test_frost_nonces_committed_before_a_failure_are_zeroed(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  The dealer's round trip commits every signer's nonce pair before
    round 2 consumes them; a failure in between dropped the unconsumed
    pairs intact.  Removing the ``ScrubOnRaise`` from the round trip fails
    this.  (The failure also fails the pairwise test, which zeroes the
    shares and enters the error state -- restored by the fixture.)"""
    committed: list[bytearray] = []
    real_commit = pb.frost_round1_commit

    def recording_commit(share: Any) -> Any:
        nonce, commitment = real_commit(share)
        committed.append(nonce)
        return nonce, commitment

    def failing_round2(*_args: Any, **_kwargs: Any) -> bytes:
        raise RuntimeError("round 2 failed")

    monkeypatch.setattr(pb, "frost_round1_commit", recording_commit)
    monkeypatch.setattr(pb, "frost_round2_sign", failing_round2)
    with pytest.raises(CryptoModuleError, match="Pairwise test failed for FROST"):
        pb.frost_keygen_trusted_dealer(2, 3)
    assert committed and all(not any(nonce) for nonce in committed)


def _hd_class() -> Any:
    return importlib.import_module("ama_cryptography.key_management").HDKeyDerivation


def test_a_master_chain_code_is_zeroed_when_its_pairwise_test_fails(
    monkeypatch: pytest.MonkeyPatch, sm_zeroed_values: list[bytes]
) -> None:
    """PIN.  The pairwise guard zeroed the master key but not the chain code
    minted beside it.  Removing ``held(chain_code)`` fails this."""
    hd_cls = _hd_class()
    seed = bytes(range(64))
    chain = bytes(pb.native_hmac_sha512_prf(b"AMA Cryptography Master Key", seed))[32:]

    def failing(_key: Any, _label: str) -> None:
        raise CryptoModuleError("pairwise test failed")

    monkeypatch.setattr(hd_cls, "_pairwise_consistency_test", staticmethod(failing))
    with pytest.raises(CryptoModuleError):
        hd_cls(seed=seed)
    assert chain in sm_zeroed_values


def test_a_child_chain_code_is_zeroed_when_its_pairwise_test_fails(
    monkeypatch: pytest.MonkeyPatch, sm_zeroed_values: list[bytes]
) -> None:
    """PIN, likewise for a derived child (hardened, so the HMAC input is
    ``0x00 || k_par || ser32(i)``).  Removing ``held(child_chain)`` fails
    this."""
    hd_cls = _hd_class()
    hd = hd_cls(seed=bytes(range(64)))
    index = 0x80000000
    data = b"\x00" + bytes(hd.master_key) + index.to_bytes(4, "big")
    child_chain = bytes(pb.native_hmac_sha512_prf(bytes(hd.master_chain_code), data))[32:]

    def failing(_key: Any, _label: str) -> None:
        raise CryptoModuleError("pairwise test failed")

    monkeypatch.setattr(hd_cls, "_pairwise_consistency_test", staticmethod(failing))
    with pytest.raises(CryptoModuleError):
        hd.derive_path("m/0'")
    assert child_chain in sm_zeroed_values


def _crypto_api() -> Any:
    return importlib.import_module("ama_cryptography.crypto_api")


def test_a_package_refused_by_its_configuration_draws_no_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``num_derived_keys < 1`` was refused after the HMAC key and the
    master secret had been drawn.  Moving the refusal back below the draws
    fails this."""
    api = _crypto_api()
    draws: list[int] = []
    real = api.secure_token_bytearray

    def counting(n: int) -> bytearray:
        draws.append(n)
        return bytearray(real(n))

    monkeypatch.setattr(api, "secure_token_bytearray", counting)
    with pytest.raises(ValueError, match="num_derived_keys"):
        api.create_crypto_package(b"content", api.CryptoPackageConfig(num_derived_keys=0))
    assert draws == []


def test_a_package_that_fails_late_zeroes_every_secret_it_minted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A failure after the draws -- here the timestamp step -- dropped
    the HMAC key, the HKDF master secret, the derived keys and the generated
    signing key intact.  Removing the ``ScrubOnRaise`` (or any registration)
    fails this."""
    api = _crypto_api()
    minted: list[Any] = []
    real_draw = api.secure_token_bytearray
    real_hkdf = api._hkdf_sha3_256
    real_keygen = api.AmaCryptography.generate_keypair

    def drawing(n: int) -> bytearray:
        out: bytearray = real_draw(n)
        minted.append(out)
        return out

    def deriving(*args: Any, **kwargs: Any) -> Any:
        out = real_hkdf(*args, **kwargs)
        minted.append(out)
        return out

    def generating(self: Any) -> Any:
        keypair = real_keygen(self)
        minted.append(keypair.secret_key)
        return keypair

    def failing_timestamp(*_args: Any) -> Any:
        raise RuntimeError("timestamp authority unreachable")

    monkeypatch.setattr(api, "secure_token_bytearray", drawing)
    monkeypatch.setattr(api, "_hkdf_sha3_256", deriving)
    monkeypatch.setattr(api.AmaCryptography, "generate_keypair", generating)
    monkeypatch.setattr(api, "_acquire_timestamp", failing_timestamp)
    with pytest.raises(RuntimeError, match="timestamp"):
        api.create_crypto_package(b"content")
    assert len(minted) >= 5
    assert all(isinstance(secret, bytearray) and not any(secret) for secret in minted)


def test_a_failed_package_leaves_the_callers_signing_key_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN against over-scrubbing: a signing key the caller supplied is the
    caller's.  Registering the pre-generated keypair fails this."""
    api = _crypto_api()
    public, expanded = pb.native_ed25519_keypair()
    seed = bytearray(memoryview(expanded)[:32])
    config = api.CryptoPackageConfig(
        signature_algorithm=api.AlgorithmType.ED25519, signing_keypair=(public, seed)
    )

    def failing_timestamp(*_args: Any) -> Any:
        raise RuntimeError("timestamp authority unreachable")

    monkeypatch.setattr(api, "_acquire_timestamp", failing_timestamp)
    with pytest.raises(RuntimeError):
        api.create_crypto_package(b"content", config)
    assert seed == bytes(expanded[:32])


def _legacy() -> Any:
    return importlib.import_module("ama_cryptography.legacy_compat")


def test_a_key_management_system_zeroes_the_derived_keys_it_does_not_keep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  Of three derived keys the system keeps the first as its HMAC
    key; the Ed25519 seed (copied by the keypair) and the unused third were
    dropped intact on every successful call.  Removing the loop that zeroes
    them fails this."""
    legacy = _legacy()
    captured: list[list[bytearray]] = []
    real = legacy.derive_keys

    def capturing(*args: Any, **kwargs: Any) -> Any:
        keys, salt = real(*args, **kwargs)
        captured.append(keys)
        return keys, salt

    monkeypatch.setattr(legacy, "derive_keys", capturing)
    kms = legacy.generate_key_management_system("wipe-test")
    keys = captured[0]
    assert keys[0] is kms.hmac_key and any(kms.hmac_key)
    assert not any(keys[1]) and not any(keys[2])


def test_a_key_management_system_that_fails_late_zeroes_its_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A failure after the root draw dropped the master secret, the
    derived keys and the Ed25519 keypair intact.  Removing the
    ``ScrubOnRaise`` fails this."""
    legacy = _legacy()
    minted: list[Any] = []
    real_draw = legacy.secure_token_bytearray
    real_ed = legacy.generate_ed25519_keypair

    def drawing(n: int) -> bytearray:
        out: bytearray = real_draw(n)
        minted.append(out)
        return out

    def generating_ed(seed: Any = None) -> Any:
        keypair = real_ed(seed)
        minted.append(keypair.private_key)
        return keypair

    def failing_dilithium() -> Any:
        raise RuntimeError("ML-DSA keygen failed")

    monkeypatch.setattr(legacy, "secure_token_bytearray", drawing)
    monkeypatch.setattr(legacy, "generate_ed25519_keypair", generating_ed)
    monkeypatch.setattr(legacy, "generate_dilithium_keypair", failing_dilithium)
    monkeypatch.setattr(legacy, "DILITHIUM_AVAILABLE", True)
    with pytest.raises(RuntimeError, match="ML-DSA"):
        legacy.generate_key_management_system("wipe-test")
    assert len(minted) == 2
    assert all(not any(secret) for secret in minted)


# ---------------------------------------------------------------------------
# Review of 83e113c7: hybrid components, staging buffers, borrowed views,
# secret comparisons, and the sweep that followed
# ---------------------------------------------------------------------------


def _hybrid() -> Any:
    return importlib.import_module("ama_cryptography.hybrid_combiner").HybridCombiner()


def _zeroed(*buffers: bytearray) -> bool:
    return all(not any(buf) for buf in buffers)


# The hybrid combiner owns the component secrets its callables return (its
# docstrings state the contract).  PR #415 first decided ownership by
# reference count, which CPython 3.14 makes depend on where the count is read;
# these tests observe the buffers' contents, which no interpreter changes.


def test_a_hybrid_encapsulation_that_fails_zeroes_the_first_component() -> None:
    """PIN.  The second encapsulator raised after the first returned its
    secret.  Removing ``zeroize(classical_ss)`` fails this."""
    first = bytearray(b"\x11" * 32)

    def failing_pqc(_pk: bytes) -> tuple[bytes, bytearray]:
        raise RuntimeError("PQC encapsulation failed")

    with pytest.raises(RuntimeError, match="PQC encapsulation"):
        _hybrid().encapsulate_hybrid(
            lambda _pk: (b"\x01" * 32, first), failing_pqc, b"\x02" * 32, b"\x03" * 32
        )
    assert _zeroed(first)


def test_a_refused_hybrid_encapsulation_zeroes_both_components() -> None:
    """PIN.  An empty ciphertext is refused after both secrets exist.
    Removing ``zeroize(pqc_ss)`` fails this."""
    first, second = bytearray(b"\x11" * 32), bytearray(b"\x22" * 32)
    with pytest.raises(ValueError, match="PQC ciphertext is empty"):
        _hybrid().encapsulate_hybrid(
            lambda _pk: (b"\x01" * 32, first),
            lambda _pk: (b"", second),
            b"\x02" * 32,
            b"\x03" * 32,
        )
    assert _zeroed(first, second)


def test_a_hybrid_encapsulation_that_fails_after_combining_zeroes_the_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The combined secret exists before the result container does; a
    failure building that container dropped it.  Removing
    ``zeroize(combined)`` fails this."""
    hc = importlib.import_module("ama_cryptography.hybrid_combiner")
    combined: list[bytearray] = []
    real_combine = hc.HybridCombiner.combine

    def recording_combine(self: Any, **kwargs: Any) -> bytearray:
        secret: bytearray = real_combine(self, **kwargs)
        combined.append(secret)
        return secret

    def failing_container(**_kwargs: Any) -> Any:
        raise MemoryError("container allocation failed")

    monkeypatch.setattr(hc.HybridCombiner, "combine", recording_combine)
    monkeypatch.setattr(hc, "HybridEncapsulation", failing_container)
    first, second = bytearray(b"\x11" * 32), bytearray(b"\x22" * 32)
    with pytest.raises(MemoryError, match="container allocation"):
        hc.HybridCombiner().encapsulate_hybrid(
            lambda _pk: (b"\x01" * 32, first),
            lambda _pk: (b"\x02" * 32, second),
            b"\x03" * 32,
            b"\x04" * 32,
        )
    assert len(combined) == 1 and _zeroed(combined[0], first, second)


def test_a_successful_hybrid_encapsulation_hands_its_secrets_over_intact() -> None:
    """PIN against over-scrubbing: on success the container holds the
    component secrets, unzeroed.  Zeroing them on every exit fails this."""
    first, second = bytearray(b"\x11" * 32), bytearray(b"\x22" * 32)
    enc = _hybrid().encapsulate_hybrid(
        lambda _pk: (b"\x01" * 32, first),
        lambda _pk: (b"\x02" * 32, second),
        b"\x03" * 32,
        b"\x04" * 32,
    )
    assert enc.classical_shared_secret is first and first == bytearray(b"\x11" * 32)
    assert enc.pqc_shared_secret is second and second == bytearray(b"\x22" * 32)
    assert any(enc.combined_secret)


def test_a_hybrid_decapsulation_whose_second_half_fails_zeroes_the_first() -> None:
    """PIN.  The cleanup began after both decapsulations, so a raising second
    one dropped the first secret.  Moving both calls back outside the guard
    fails this."""
    first = bytearray(b"\x33" * 32)

    def failing_pqc(_ct: bytes, _sk: Any) -> bytearray:
        raise RuntimeError("PQC decapsulation failed")

    with pytest.raises(RuntimeError, match="PQC decapsulation"):
        _hybrid().decapsulate_hybrid(
            lambda _ct, _sk: first,
            failing_pqc,
            b"\x01" * 32,
            b"\x02" * 32,
            b"\x03" * 32,
            b"\x04" * 32,
        )
    assert _zeroed(first)


def test_a_rejected_hybrid_component_secret_is_zeroed() -> None:
    """PIN.  An oversized component is refused, and both are zeroed.
    Removing ``zeroize(pqc_ss)`` from the ``finally`` fails this."""
    first, oversized = bytearray(b"\x44" * 32), bytearray(b"\x55" * 512)
    with pytest.raises(ValueError, match="PQC shared secret too large"):
        _hybrid().decapsulate_hybrid(
            lambda _ct, _sk: first,
            lambda _ct, _sk: oversized,
            b"\x01" * 32,
            b"\x02" * 32,
            b"\x03" * 32,
            b"\x04" * 32,
        )
    assert _zeroed(first, oversized)


def test_a_successful_hybrid_decapsulation_consumes_its_components() -> None:
    """PIN.  The combined secret matches encapsulation, and the components
    are zeroed once combined.  Removing ``zeroize(classical_ss)`` from the
    ``finally`` fails this."""
    hybrid = _hybrid()
    enc = hybrid.encapsulate_hybrid(
        lambda _pk: (b"\x01" * 32, bytearray(b"\x11" * 32)),
        lambda _pk: (b"\x02" * 32, bytearray(b"\x22" * 32)),
        b"\x03" * 32,
        b"\x04" * 32,
    )
    first, second = bytearray(b"\x11" * 32), bytearray(b"\x22" * 32)
    combined = hybrid.decapsulate_hybrid(
        lambda _ct, _sk: first,
        lambda _ct, _sk: second,
        b"\x01" * 32,
        b"\x02" * 32,
        b"\x05" * 32,
        b"\x06" * 32,
        classical_pk=b"\x03" * 32,
        pqc_pk=b"\x04" * 32,
    )
    assert combined == enc.combined_secret
    assert _zeroed(first, second)


def test_borrow_passes_a_whole_read_only_view_without_copying() -> None:
    """PIN.  ``_borrow`` copied every read-only view with ``tobytes()``.  A
    view of a whole ``bytes`` is now that ``bytes``; of a whole
    ``bytearray``, that storage."""
    immutable = b"\x5a" * 32
    assert pb._borrow(memoryview(immutable)) is immutable
    wipeable = bytearray(b"\x5b" * 32)
    borrowed = pb._borrow(memoryview(wipeable).toreadonly())
    expected = ctypes.addressof((ctypes.c_char * 32).from_buffer(wipeable))
    assert isinstance(borrowed, ctypes.Array) and ctypes.addressof(borrowed) == expected


def test_borrow_refuses_a_read_only_view_of_part_of_a_buffer() -> None:
    """PIN.  No copy-free route exists for it, so it is refused, not copied."""
    with pytest.raises(TypeError, match="read-only view of part"):
        pb._borrow(memoryview(b"\x5a" * 64)[:32])


def test_constant_time_compare_borrows_a_whole_read_only_view() -> None:
    """PIN.  ``_borrow_readable`` copied read-only views too; a whole-object
    view is now addressed where it lives."""
    from ama_cryptography import secure_memory

    wipeable = bytearray(b"\x5c" * 16)
    holder, length = secure_memory._borrow_readable(memoryview(wipeable).toreadonly(), "a")
    expected = ctypes.addressof((ctypes.c_char * 16).from_buffer(wipeable))
    assert length == 16 and ctypes.addressof(holder) == expected
    immutable = b"\x5d" * 16
    holder, _ = secure_memory._borrow_readable(memoryview(immutable), "a")
    own = ctypes.cast(ctypes.c_char_p(immutable), ctypes.c_void_p).value
    assert ctypes.cast(holder, ctypes.c_void_p).value == own


def test_constant_time_compare_refuses_a_read_only_slice_of_wipeable_storage() -> None:
    """PIN.  Copying it would leave the secret where its owner's wipe cannot
    reach.  A slice of ``bytes`` is still compared: that storage was never
    wipeable.  Restoring the unconditional copy fails the first assertion."""
    from ama_cryptography import secure_memory

    wipeable = bytearray(b"\x71" * 64)
    with pytest.raises(TypeError, match="part of a writable buffer"):
        secure_memory.constant_time_compare(memoryview(wipeable).toreadonly()[:32], b"\x71" * 32)
    immutable = b"\x72" * 64
    assert secure_memory.constant_time_compare(memoryview(immutable)[:32], b"\x72" * 32)


def test_the_ama_context_kem_pairwise_test_mints_wipeable_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``AmaContext``'s ML-KEM pairwise test turned both shared-secret
    staging buffers into immutable ``bytes``.  Restoring ``bytes(ss)``
    fails this."""
    kinds: list[type] = []
    real = ms.pairwise_test_kem

    def inspecting(encaps: Any, decaps: Any, pk: Any, sk: Any, label: str) -> None:
        ct, ss = encaps(pk)
        kinds.append(type(ss))
        kinds.append(type(decaps(ct, sk)))
        real(encaps, decaps, pk, sk, label)

    monkeypatch.setattr(pb, "pairwise_test_kem", inspecting)
    alg = pb.AmaContext.ALG_KYBER_1024
    with pb.AmaContext(alg) as ctx:
        pk_size, sk_size = pb.AmaContext._KEY_SIZES[alg]
        pk = ctypes.create_string_buffer(pk_size)
        sk = ctypes.create_string_buffer(sk_size)
        assert ctx.keypair_generate(pk, pk_size, sk, sk_size) == 0
    assert kinds == [bytearray, bytearray]


@pytest.mark.parametrize("step", ["encapsulate", "decapsulate"])
def test_a_failing_ama_context_pairwise_step_scrubs_its_staging_buffer(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """PIN.  On success ``_take_secret`` wipes the staging buffer itself; the
    ``finally`` is what scrubs it when the native call wrote output and then
    reported failure.  Removing that ``finally`` fails the step's row."""
    captured: dict[str, Any] = {}
    real = ms.pairwise_test_kem

    def capturing(encaps: Any, decaps: Any, pk: Any, sk: Any, label: str) -> None:
        captured.update(encaps=encaps, decaps=decaps, pk=pk, sk=sk)
        real(encaps, decaps, pk, sk, label)

    monkeypatch.setattr(pb, "pairwise_test_kem", capturing)
    alg = pb.AmaContext.ALG_KYBER_1024
    with pb.AmaContext(alg) as ctx:
        pk_size, sk_size = pb.AmaContext._KEY_SIZES[alg]
        pk = ctypes.create_string_buffer(pk_size)
        sk = ctypes.create_string_buffer(sk_size)
        assert ctx.keypair_generate(pk, pk_size, sk, sk_size) == 0
        staged: list[Any] = []

        def writes_then_fails(*args: Any) -> int:
            out = args[3] if step == "encapsulate" else args[2]
            ctypes.memset(out, 0xAB, len(out))
            staged.append(out)
            return -1

        monkeypatch.setattr(ctx, f"kem_{step}", writes_then_fails)
        with pytest.raises(RuntimeError, match=f"ama_kem_{step} failed"):
            if step == "encapsulate":
                captured["encaps"](captured["pk"])
            else:
                captured["decaps"](b"\x00" * pb.KYBER_CIPHERTEXT_BYTES, captured["sk"])
    assert len(staged) == 1 and not any(staged[0].raw)


@pytest.mark.parametrize("form", ["kem", "dh"])
def test_pairwise_tests_compare_secrets_in_constant_time(
    monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    """PIN.  The KEM and DH pairwise tests compared shared secrets with
    ``!=``.  Restoring it fails the row."""
    from ama_cryptography import secure_memory

    calls: list[int] = []
    real = secure_memory.constant_time_compare

    def recording(a: Any, b: Any) -> bool:
        calls.append(len(a))
        return real(a, b)

    monkeypatch.setattr(ms, "_secret_comparator", recording)
    secret = bytearray(b"\x66" * 32)
    if form == "kem":
        ms.pairwise_test_kem(
            lambda _pk: (b"ct", bytearray(secret)),
            lambda _ct, _sk: bytearray(secret),
            b"pk",
            bytearray(b"\x01" * 32),
            "test-kem",
        )
    else:
        ms.pairwise_test_agreement(
            lambda _own, _peer: bytearray(secret),
            (b"eph-pk", bytearray(b"\x02" * 32)),
            bytearray(b"\x01" * 32),
            b"pk",
            "test-dh",
        )
    assert calls == [32]


def _restricted_binding(agent: Any) -> Any:
    """A binding whose every entry point takes the authority key."""
    return agent.AgentBinding(
        instance_id=bytes(range(agent.AGENT_INSTANCE_ID_BYTES)),
        lifetime=agent.AgentLifetime.PERSISTENT,
        capabilities=agent.AgentCapability.DATA_SIGN | agent.AgentCapability.PERSISTENCE,
        ethical_profile_hash=b"\x42" * 32,
    )


def _address_of(buffer: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))


def test_an_agent_bound_key_is_wipeable_and_its_inputs_borrowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``derive_key`` copied the input keying material and the
    authority key into ``bytes`` and returned the derived key as ``bytes``,
    leaving its ctypes buffer populated.  Restoring ``_as_bytes`` for either
    input, or ``bytes(out)``, fails this."""
    agent = importlib.import_module("ama_cryptography.agent_binding")
    binding = _restricted_binding(agent)
    authority = bytearray(b"\x88" * agent.AUTHORITY_KEY_MIN_BYTES)
    ikm = bytearray(b"\x77" * 32)
    seen: list[tuple[Any, Any]] = []
    lib = agent._require_native()
    real = lib.ama_hkdf_agent_bound

    def recording(*args: Any) -> Any:
        seen.append((args[1], args[5]))
        return real(*args)

    monkeypatch.setattr(lib, "ama_hkdf_agent_bound", recording)
    binding.authorize(authority)
    key = binding.derive_key(ikm, 32, info=b"session", authority_key=authority)
    assert isinstance(key, bytearray) and len(key) == 32
    held_key, held_ikm = seen[0]
    assert isinstance(held_key, ctypes.Array) and ctypes.addressof(held_key) == _address_of(
        authority
    )
    assert isinstance(held_ikm, ctypes.Array) and ctypes.addressof(held_ikm) == _address_of(ikm)


@pytest.mark.parametrize("entry", ["authorize", "check", "signing_context"])
def test_the_authority_key_is_borrowed_by_every_binding_entry_point(
    monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    """PIN.  ``authorize``, ``check`` and ``signing_context`` copied the
    authority key into ``bytes`` as ``derive_key`` did.  Restoring
    ``_as_bytes`` in any one fails its row."""
    agent = importlib.import_module("ama_cryptography.agent_binding")
    binding = _restricted_binding(agent)
    authority = bytearray(b"\x99" * agent.AUTHORITY_KEY_MIN_BYTES)
    if entry != "authorize":
        binding.authorize(authority)
    native = {
        "authorize": "ama_agent_binding_authorize",
        "check": "ama_agent_binding_check",
        "signing_context": "ama_agent_binding_context",
    }[entry]
    seen: list[Any] = []
    lib = agent._require_native()
    real = getattr(lib, native)

    def recording(*args: Any) -> Any:
        seen.append(args[1])
        return real(*args)

    monkeypatch.setattr(lib, native, recording)
    getattr(binding, entry)(authority)
    assert isinstance(seen[0], ctypes.Array) and ctypes.addressof(seen[0]) == _address_of(authority)


@pytest.mark.skipif(
    pb._native_lib is None or not hasattr(pb._native_lib, "ama_argon2id_legacy"),
    reason="the loaded native library does not export ama_argon2id_legacy",
)
@pytest.mark.parametrize("outcome", ["derived", "refused"])
def test_the_legacy_argon2id_tag_is_wipeable_and_its_buffer_scrubbed(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    """PIN.  The legacy derivation returned ``bytes(out_buf.raw)`` and left
    its staging buffer populated on every path.  Restoring that fails the
    ``derived`` row; dropping the ``finally`` alone fails ``refused``, where
    the C side wrote output and then reported failure."""
    staged: list[Any] = []
    real = pb._native_lib.ama_argon2id_legacy

    def staging(*args: Any) -> int:
        staged.append(args[7])
        if outcome == "refused":
            ctypes.memset(args[7], 0xAA, args[8])
            return -1
        return int(real(*args))

    monkeypatch.setattr(pb._native_lib, "ama_argon2id_legacy", staging)
    with pytest.warns(pb.SecurityWarning):
        if outcome == "derived":
            tag = pb.native_argon2id_legacy(
                bytearray(b"password"), b"saltsalt", t_cost=1, m_cost=8, parallelism=1, out_len=16
            )
            assert isinstance(tag, bytearray) and len(tag) == 16 and any(tag)
        else:
            with pytest.raises(RuntimeError, match="ama_argon2id_legacy failed"):
                pb.native_argon2id_legacy(
                    bytearray(b"password"), b"saltsalt", t_cost=1, m_cost=8, parallelism=1
                )
    assert len(staged) == 1 and not any(staged[0].raw)


# ---------------------------------------------------------------------------
# The comparison is injected, not imported (CodeQL py/cyclic-import on 57964b78)
# ---------------------------------------------------------------------------


def test_the_package_wires_the_constant_time_comparison() -> None:
    """PIN.  The package ``__init__`` registers it before POST.  Removing that
    registration fails this; the ``sys.modules`` recovery below would hide it
    from every other test, because ``__init__`` still imports the module."""
    from ama_cryptography import secure_memory

    assert ms._secret_comparator is secure_memory.constant_time_compare


def test_an_unregistered_comparison_is_recovered_through_sys_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A re-run of ``_module_state``'s body loses the registration; the
    loaded ``secure_memory`` is found without an import.  Removing the lookup
    fails this."""
    from ama_cryptography import secure_memory

    calls: list[int] = []
    real = secure_memory.constant_time_compare

    def recording(a: Any, b: Any) -> bool:
        calls.append(len(a))
        return real(a, b)

    monkeypatch.setattr(ms, "_secret_comparator", None)
    monkeypatch.setattr(secure_memory, "constant_time_compare", recording)
    assert ms.secrets_match(bytearray(b"\x31" * 8), b"\x31" * 8)
    assert not ms.secrets_match(bytearray(b"\x31" * 8), b"\x32" * 8)
    assert calls == [8, 8]


def test_a_comparison_with_nothing_to_compare_with_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  No registration and no loaded ``secure_memory``: a could-not-run,
    never a fallback to ``==``.  Replacing the refusal with ``a == b`` fails
    this."""
    monkeypatch.setattr(ms, "_secret_comparator", None)
    monkeypatch.delitem(sys.modules, "ama_cryptography.secure_memory")
    with pytest.raises(NativeBackendUnavailableError, match="Nothing was compared"):
        ms.secrets_match(b"\x41" * 8, b"\x41" * 8)


# ---------------------------------------------------------------------------
# A refused COSE decode zeroes what it already sliced (review of 57964b78)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoded",
    [
        # {-4: h'616263', 1: 0}: the second key sorts before the first.
        pytest.param("a2234361626301" "00", id="map-refused-part-way"),
        # [h'616263', <indefinite length>]: the second element is refused.
        pytest.param("8243616263ff", id="array-refused-part-way"),
        # {-4: h'616263'} followed by a stray octet.
        pytest.param("a12343616263" "00", id="trailing-octet"),
        # h'616263' alone: decoded, then refused as not a map.
        pytest.param("43616263", id="not-a-map"),
    ],
)
def test_a_refused_cose_private_key_zeroes_the_slices_it_took(
    monkeypatch: pytest.MonkeyPatch, encoded: str
) -> None:
    """PIN per row.  Each decode took a ``bytearray`` slice of the private
    buffer -- where ``d`` would be -- before the refusal, and dropped it
    intact.  Removing the scrub on that path fails its row."""
    from ama_cryptography import _asn1

    scrubbed: list[Any] = []
    real = sm.zeroize

    def recording(value: Any) -> None:
        real(value)
        scrubbed.append(value)

    monkeypatch.setattr(_asn1, "zeroize", recording)
    with pytest.raises(KeyFormatError):
        kf.cose_to_private_key(bytes.fromhex(encoded))
    slices = [v for v in scrubbed if isinstance(v, bytearray) and len(v) == 3]
    assert slices and all(v == bytearray(3) for v in slices)


# ---------------------------------------------------------------------------
# Review of d74f44fd: RNG health comparisons, secure-channel secrets
# ---------------------------------------------------------------------------


def _recording_comparator(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    from ama_cryptography import secure_memory

    calls: list[tuple[int, int]] = []
    real = secure_memory.constant_time_compare

    def recording(a: Any, b: Any) -> bool:
        calls.append((len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(ms, "_secret_comparator", recording)
    return calls


def test_the_startup_rng_check_compares_its_draws_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  POST compared its two raw CSPRNG draws with ``==``.  Restoring
    it fails this."""
    st = importlib.import_module("ama_cryptography._self_test")
    monkeypatch.setattr(st, "_SELF_TEST_RESULTS", [])
    monkeypatch.setitem(ms._rng_state, "previous", ms._rng_state["previous"])
    calls = _recording_comparator(monkeypatch)
    assert st._run_rng_stage() == (True, None)
    assert calls == [(32, 32)]


def test_the_continuous_rng_check_compares_digests_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The continuous test compared SHA-256 digests of the caller's
    secret draws with ``==``.  Restoring it fails this."""
    monkeypatch.setitem(ms._rng_state, "previous", ms._rng_state["previous"])
    calls = _recording_comparator(monkeypatch)
    ms.secure_random_fill(bytearray(32))
    ms.secure_random_fill(bytearray(32))
    assert (32, 32) in calls


def _channel_parties() -> tuple[Any, Any]:
    from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
    from ama_cryptography.secure_channel import SecureChannelInitiator, SecureChannelResponder

    kem = HybridKEMProvider().generate_keypair()
    sig = HybridSignatureProvider().generate_keypair()
    return (
        SecureChannelInitiator(kem.public_key),
        SecureChannelResponder(kem.secret_key, sig.secret_key, sig.public_key),
    )


@pytest.mark.parametrize("outcome", ["completed", "rejected"])
def test_the_initiator_zeroes_its_shared_secret_when_the_handshake_ends(outcome: str) -> None:
    """PIN per row.  Both exits only dropped the reference to the KEM's
    wipeable shared secret.  Removing either ``zeroize`` fails its row."""
    import dataclasses as dc

    from ama_cryptography.secure_channel import HandshakeError

    initiator, responder = _channel_parties()
    msg = initiator.create_handshake()
    held = initiator._shared_secret
    assert isinstance(held, bytearray) and any(held)
    response, _ = responder.handle_handshake(msg)
    if outcome == "completed":
        initiator.complete_handshake(response)
    else:
        forged = dc.replace(response, signature=bytes(len(response.signature)))
        with pytest.raises(HandshakeError):
            initiator.complete_handshake(forged)
    assert initiator._shared_secret is None and not any(held)


@pytest.mark.parametrize("outcome", ["completed", "refused"])
def test_the_responder_zeroes_the_secret_it_decapsulated(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    """PIN per row.  ``handle_handshake`` dropped the decapsulated secret
    intact on success and on a later failure.  Removing the ``finally``
    fails both rows."""
    initiator, responder = _channel_parties()
    msg = initiator.create_handshake()
    decapsulated: list[bytearray] = []
    real = responder._kem.decapsulate

    def recording(ct: bytes, sk: Any) -> bytearray:
        secret = bytearray(real(ct, sk))
        decapsulated.append(secret)
        return secret

    monkeypatch.setattr(responder._kem, "decapsulate", recording)
    if outcome == "refused":

        def failing_sign(*_args: Any) -> Any:
            raise RuntimeError("signer unavailable")

        monkeypatch.setattr(responder._sig, "sign", failing_sign)
        with pytest.raises(RuntimeError, match="signer unavailable"):
            responder.handle_handshake(msg)
    else:
        responder.handle_handshake(msg)
    assert len(decapsulated) == 1 and not any(decapsulated[0])


def test_session_keys_are_the_derived_buffers_and_a_failed_derivation_zeroes_the_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  Each HKDF output was copied into a second ``bytearray`` and the
    original dropped unwiped, and a failed second derivation dropped the first
    key intact.  Restoring either fails this."""
    sc = importlib.import_module("ama_cryptography.secure_channel")
    derived: list[bytearray] = []
    real = pb.native_hkdf

    def recording(*args: Any, **kwargs: Any) -> bytearray:
        key: bytearray = real(*args, **kwargs)
        derived.append(key)
        return key

    monkeypatch.setattr(pb, "native_hkdf", recording)
    session = sc._session_from(b"\x21" * 32, b"\x01" * 32, send_info=b"s", recv_info=b"r")
    assert session.send_key is derived[0] and session.recv_key is derived[1]

    derived.clear()
    calls = {"n": 0}

    def second_fails(*args: Any, **kwargs: Any) -> bytearray:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("HKDF failed")
        return recording(*args, **kwargs)

    monkeypatch.setattr(pb, "native_hkdf", second_fails)
    with pytest.raises(RuntimeError, match="HKDF failed"):
        sc._session_from(b"\x21" * 32, b"\x01" * 32, send_info=b"s", recv_info=b"r")
    assert len(derived) == 1 and not any(derived[0])


def test_a_failed_rekey_zeroes_the_new_key_and_keeps_the_old_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``rekey`` copied each new key and, if the second derivation
    failed, dropped the first new key intact.  Restoring either fails this;
    the session keeps its current keys."""
    sc = importlib.import_module("ama_cryptography.secure_channel")
    session = sc._session_from(b"\x21" * 32, b"\x01" * 32, send_info=b"s", recv_info=b"r")
    old_send, old_recv = bytes(session.send_key), bytes(session.recv_key)
    derived: list[bytearray] = []
    real = pb.native_hkdf
    calls = {"n": 0}

    def second_fails(*args: Any, **kwargs: Any) -> bytearray:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("HKDF failed")
        key: bytearray = real(*args, **kwargs)
        derived.append(key)
        return key

    monkeypatch.setattr(pb, "native_hkdf", second_fails)
    with pytest.raises(RuntimeError, match="HKDF failed"):
        session.rekey()
    assert len(derived) == 1 and not any(derived[0])
    assert bytes(session.send_key) == old_send and bytes(session.recv_key) == old_recv

    derived.clear()

    def recording(*args: Any, **kwargs: Any) -> bytearray:
        key: bytearray = real(*args, **kwargs)
        derived.append(key)
        return key

    monkeypatch.setattr(pb, "native_hkdf", recording)
    session.rekey()
    assert session.send_key is derived[0] and session.recv_key is derived[1]


def _kdf_outputs(monkeypatch: pytest.MonkeyPatch, module: Any, name: str) -> list[bytearray]:
    outputs: list[bytearray] = []
    real = getattr(module, name)

    def recording(*args: Any, **kwargs: Any) -> bytearray:
        key: bytearray = real(*args, **kwargs)
        outputs.append(key)
        return key

    monkeypatch.setattr(module, name, recording)
    return outputs


@pytest.mark.parametrize("kdf", ["argon2id", "pbkdf2"])
def test_a_key_store_holds_the_kdf_output_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, kdf: str
) -> None:
    """PIN per row.  The store wrapped the KDF's wipeable output in a second
    ``bytearray``, keeping a copy and dropping the original unwiped.
    Restoring the wrap fails its row."""
    import warnings

    km = importlib.import_module("ama_cryptography.key_management")
    if kdf == "argon2id":
        outputs = _kdf_outputs(monkeypatch, pb, "native_argon2id")
        store = km.SecureKeyStorage(tmp_path, master_password="correct horse battery staple 1!")
    else:
        (tmp_path / ".salt").write_bytes(b"\x07" * 32)
        (tmp_path / ".kdf_metadata.json").write_text(
            json.dumps({"version": 1, "algorithm": "PBKDF2-HMAC-SHA256", "iterations": 100000}),
            encoding="utf-8",
        )
        outputs = _kdf_outputs(monkeypatch, km, "native_pbkdf2_hmac_sha256")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            store = km.SecureKeyStorage(
                tmp_path, master_password="correct horse battery staple 1!", allow_legacy_kdf=True
            )
    assert outputs and store.encryption_key is outputs[-1]


@pytest.mark.parametrize("outcome", ["migrated", "rolled-back"])
def test_kdf_migration_zeroes_the_key_it_retires(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, outcome: str
) -> None:
    """PIN per row.  ``migrate_kdf`` dropped the old key-encryption key
    intact on success, and the new one on a rollback.  Removing the
    ``zeroize(old_key)`` fails ``migrated``; removing the ``ScrubOnRaise``
    registration fails ``rolled-back``."""
    km = importlib.import_module("ama_cryptography.key_management")
    store = km.SecureKeyStorage(tmp_path, master_password="correct horse battery staple 1!")
    store.store_key("k", b"\x11" * 32)
    old_key = store.encryption_key
    old_copy = bytes(old_key)
    outputs = _kdf_outputs(monkeypatch, pb, "native_argon2id")
    if outcome == "migrated":
        assert store.migrate_kdf("correct horse battery staple 1!") is True
        assert store.encryption_key is outputs[-1] and any(outputs[-1])
        assert not any(old_key)
    else:
        real_write = km._atomic_write_bytes
        failed: list[Any] = []

        def first_salt_write_fails(path: Any, data: bytes) -> None:
            # The migration's write of the new salt fails; the rollback's
            # restore of the old one succeeds.
            if path == store.salt_file and not failed:
                failed.append(path)
                raise OSError("disk full")
            real_write(path, data)

        monkeypatch.setattr(km, "_atomic_write_bytes", first_salt_write_fails)
        with pytest.raises(OSError, match="disk full"):
            store.migrate_kdf("correct horse battery staple 1!")
        assert len(outputs) == 1 and not any(outputs[0])
        assert store.encryption_key is old_key and bytes(old_key) == old_copy


_AEAD = {
    "aes256gcm": ("ama_aes256_gcm_decrypt", 32, 12),
    "chacha20poly1305": ("ama_chacha20poly1305_decrypt", 32, 12),
    "ascon128": ("ama_ascon_aead128_decrypt", 16, 16),
}


def _aead(name: str) -> tuple[Any, Any, type[BaseException]]:
    """``(encrypt, decrypt, the exception a forged tag raises)``."""
    if name == "aes256gcm":
        return pb.native_aes256_gcm_encrypt, pb.native_aes256_gcm_decrypt, ValueError
    if name == "chacha20poly1305":
        return (
            pb.native_chacha20poly1305_encrypt,
            pb.native_chacha20poly1305_decrypt,
            RuntimeError,
        )
    ascon = importlib.import_module("ama_cryptography.ascon")
    return ascon.aead128_encrypt, ascon.aead128_decrypt, ascon.AsconVerificationError


@pytest.mark.parametrize("outcome", ["opened", "forged"])
@pytest.mark.parametrize("name", sorted(_AEAD))
def test_an_aead_decryption_scrubs_its_plaintext_staging_buffer(
    monkeypatch: pytest.MonkeyPatch, name: str, outcome: str
) -> None:
    """Each decrypt copied the plaintext out of its ctypes staging buffer and
    left the buffer populated; ``SecureKeyStorage`` decrypts stored keys this
    way.  ``opened`` rows are PIN: removing a ``finally`` fails its row.
    ``forged`` rows are SMOKE, measured: on an authentication failure the C
    side already leaves the buffer zero, so they pass without the ``finally``
    (AGENTS.md 6.3)."""
    symbol, key_len, nonce_len = _AEAD[name]
    encrypt, decrypt, refusal = _aead(name)
    key, nonce, plaintext = bytearray(b"\x42" * key_len), b"\x24" * nonce_len, b"\x5a" * 32
    ciphertext, tag = encrypt(key, nonce, plaintext)
    staged: list[Any] = []
    real = getattr(pb._native_lib, symbol)

    def staging(*args: Any) -> int:
        out = args[-1]
        staged.append(getattr(out, "_obj", out))
        return int(real(*args))

    monkeypatch.setattr(pb._native_lib, symbol, staging)
    if outcome == "opened":
        assert decrypt(key, nonce, ciphertext, tag) == plaintext
    else:
        with pytest.raises(refusal):
            decrypt(key, nonce, ciphertext, bytes(len(tag)))
    assert len(staged) == 1 and not any(bytes(staged[0]))


def _key_store(tmp_path: Any) -> Any:
    km = importlib.import_module("ama_cryptography.key_management")
    store = km.SecureKeyStorage(tmp_path, master_password="correct horse battery staple 1!")
    store.store_key("k1", b"\x11" * 32)
    store.store_key("k2", b"\x22" * 32)
    return store


def test_a_stored_key_comes_back_wipeable(tmp_path: Any) -> None:
    """PIN.  ``retrieve_key`` returned every stored key as ``bytes``, through
    the public decrypt's copy.  Routing it back through that copy fails
    this."""
    store = _key_store(tmp_path)
    key = store.retrieve_key("k1")
    assert isinstance(key, bytearray) and key == b"\x11" * 32


def _retrieved(monkeypatch: pytest.MonkeyPatch, store: Any) -> list[bytearray]:
    keys: list[bytearray] = []
    real = store.retrieve_key

    def recording(key_id: str) -> Any:
        key = real(key_id)
        if key is not None:
            keys.append(key)
        return key

    monkeypatch.setattr(store, "retrieve_key", recording)
    return keys


@pytest.mark.parametrize("outcome", ["migrated", "rolled-back", "metadata-unreadable"])
def test_kdf_migration_zeroes_every_key_it_decrypted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, outcome: str
) -> None:
    """PIN per row.  ``migrate_kdf`` decrypted every stored key to re-encrypt
    it and dropped them all intact.  Removing the ``finally`` fails every
    row; reading a key's metadata before registering the key fails
    ``metadata-unreadable``."""
    km = importlib.import_module("ama_cryptography.key_management")
    store = _key_store(tmp_path)
    keys = _retrieved(monkeypatch, store)
    password = "correct horse battery staple 1!"
    if outcome == "migrated":
        assert store.migrate_kdf(password) is True
    elif outcome == "rolled-back":
        real_write = km._atomic_write_bytes
        failed: list[Any] = []

        def first_salt_write_fails(path: Any, data: bytes) -> None:
            if path == store.salt_file and not failed:
                failed.append(path)
                raise OSError("disk full")
            real_write(path, data)

        monkeypatch.setattr(km, "_atomic_write_bytes", first_salt_write_fails)
        with pytest.raises(OSError, match="disk full"):
            store.migrate_kdf(password)
    else:
        real_load = km.json.load
        loads = {"n": 0}

        def second_load_fails(f: Any) -> Any:
            # The first key file's record (read by retrieve_key) loads; the
            # migration's read of its metadata is the second load, and fails.
            loads["n"] += 1
            if loads["n"] == 2:
                raise ValueError("unreadable metadata")
            return real_load(f)

        monkeypatch.setattr(km.json, "load", second_load_fails)
        with pytest.raises(ValueError, match="unreadable metadata"):
            store.migrate_kdf(password)
    assert keys and all(not any(key) for key in keys)


def test_a_rollback_restores_the_key_even_when_a_restore_write_fails_otherwise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """PIN.  The rollback caught only ``OSError`` from its restore writes;
    anything else stopped it before the in-memory key and salt were put
    back, leaving the store on the new, zeroed key.  Moving the restore out
    of its ``finally`` fails this."""
    km = importlib.import_module("ama_cryptography.key_management")
    store = _key_store(tmp_path)
    old_key, old_salt = store.encryption_key, store.salt
    old_copy = bytes(old_key)

    def every_salt_write_fails(path: Any, data: bytes) -> None:
        if path == store.salt_file:
            raise RuntimeError("restore refused")
        km_write(path, data)

    km_write = km._atomic_write_bytes
    monkeypatch.setattr(km, "_atomic_write_bytes", every_salt_write_fails)
    with pytest.raises(RuntimeError, match="restore refused"):
        store.migrate_kdf("correct horse battery staple 1!")
    assert store.encryption_key is old_key and bytes(old_key) == old_copy
    assert store.salt == old_salt


def test_a_keypair_cache_hands_out_a_copy_the_caller_can_wipe() -> None:
    """PIN.  The secret ``get_or_generate`` returns is the caller's own
    ``bytearray``: wiping it leaves the cache's key intact, and wiping the
    cache's key (``rotate``) leaves no copy the caller can't reach.  Returning
    the cache's own buffer fails the wipe check; returning ``bytes`` fails the
    type check."""
    from ama_cryptography.crypto_api import KeypairCache

    cache = KeypairCache()
    _pk, sk = cache.get_or_generate()
    assert type(sk) is bytearray
    expected = bytes(sk)
    sm.zeroize(sk)
    _pk2, sk2 = cache.get_or_generate()
    assert bytes(sk2) == expected
    assert sk2 is not sk


def test_a_failed_hybrid_keygen_zeroes_the_x25519_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  The X25519 secret is minted before the Kyber keygen; when that
    keygen raises, the secret is zeroed.  Removing the ``finally`` fails this."""
    from ama_cryptography import crypto_api as ca
    from ama_cryptography import pqc_backends as pb_

    minted: list[bytearray] = []
    real_x25519 = pb_.native_x25519_keypair

    def recording_x25519() -> Any:
        pk, sk = real_x25519()
        minted.append(sk)
        return pk, sk

    def kyber_refuses() -> Any:
        raise RuntimeError("kyber refused")

    monkeypatch.setattr(pb_, "native_x25519_keypair", recording_x25519)
    monkeypatch.setattr(ca, "generate_kyber_keypair", kyber_refuses)
    with pytest.raises(RuntimeError, match="kyber refused"):
        ca.HybridKEMProvider().generate_keypair()
    assert len(minted) == 1 and not any(minted[0])


def test_a_refused_hybrid_keypair_zeroes_the_combined_and_kyber_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The combined secret and the Kyber keypair are held until the
    ``KeyPair`` has adopted the combined key.  A refusal while building it
    zeroes both; restoring the bare ``KeyPair(...)`` call fails this."""
    from ama_cryptography import crypto_api as ca

    kyber_minted: list[Any] = []
    real_kyber = pb.generate_kyber_keypair

    def recording_kyber() -> Any:
        kp = real_kyber()
        kyber_minted.append(kp)
        return kp

    combined: list[bytearray] = []

    def keypair_refuses(**kwargs: Any) -> Any:
        combined.append(kwargs["secret_key"])
        raise RuntimeError("keypair refused")

    monkeypatch.setattr(ca, "generate_kyber_keypair", recording_kyber)
    monkeypatch.setattr(ca, "KeyPair", keypair_refuses)
    with pytest.raises(RuntimeError, match="keypair refused"):
        ca.HybridKEMProvider().generate_keypair()
    assert len(combined) == 1 and not any(combined[0])
    assert len(kyber_minted) == 1 and not any(kyber_minted[0].secret_key)


def test_a_refused_hybrid_encapsulation_zeroes_the_combined_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The combined shared secret is held until the result owns it; a
    refusal while building the result zeroes it.  Restoring the bare
    ``EncapsulatedSecret(...)`` call fails this."""
    from ama_cryptography import crypto_api as ca

    provider = ca.HybridKEMProvider()
    public_key = provider.generate_keypair().public_key
    combined: list[bytearray] = []

    def result_refuses(**kwargs: Any) -> Any:
        combined.append(kwargs["shared_secret"])
        raise RuntimeError("result refused")

    monkeypatch.setattr(ca, "EncapsulatedSecret", result_refuses)
    with pytest.raises(RuntimeError, match="result refused"):
        provider.encapsulate(public_key)
    assert len(combined) == 1 and not any(combined[0])


def test_a_successful_hybrid_encapsulation_zeroes_the_kyber_shared_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The Kyber component secret is zeroed explicitly on the success
    path, not left to its finalizer.  Removing the ``wipe()`` fails this."""
    from ama_cryptography import crypto_api as ca

    provider = ca.HybridKEMProvider()
    public_key = provider.generate_keypair().public_key
    encapsulated: list[Any] = []
    real_encaps = pb.kyber_encapsulate

    def recording_encaps(pk: bytes) -> Any:
        result = real_encaps(pk)
        encapsulated.append(result)
        return result

    monkeypatch.setattr(ca, "kyber_encapsulate", recording_encaps)
    provider.encapsulate(public_key)
    assert len(encapsulated) == 1
    assert type(encapsulated[0].shared_secret) is bytearray
    assert not any(encapsulated[0].shared_secret)


def test_a_failed_wipe_of_the_old_rekey_keys_leaves_the_new_keys_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The new keys are installed before the old ones are wiped, and both
    old buffers are attempted even when the first wipe raises.  Installing
    after the wipe fails the install check; stopping at the first failed wipe
    fails the second-buffer check."""
    from ama_cryptography.secure_memory import SecureMemoryError

    sc = importlib.import_module("ama_cryptography.secure_channel")
    session = sc._session_from(b"\x31" * 32, b"\x02" * 32, send_info=b"s", recv_info=b"r")
    old_send, old_recv = session.send_key, session.recv_key
    wiped: list[int] = []
    real_memzero = sc.secure_memzero

    def first_old_wipe_fails(buf: Any) -> None:
        wiped.append(id(buf))
        if buf is old_send:
            raise SecureMemoryError("wipe failed")
        real_memzero(buf)

    monkeypatch.setattr(sc, "secure_memzero", first_old_wipe_fails)
    with pytest.raises(SecureMemoryError, match="wipe failed"):
        session.rekey()
    assert session.send_key is not old_send and session.recv_key is not old_recv
    assert session.rekey_epoch == 1
    assert id(old_send) in wiped and id(old_recv) in wiped
    assert any(session.send_key) and any(session.recv_key)
    assert not any(old_recv)


def _zeroed_on_drop(
    monkeypatch: pytest.MonkeyPatch, make: Callable[[], Any], attrs: tuple[str, ...]
) -> set[str]:
    """Build a holder, drop it, and report which of its ``attrs`` buffers the
    finalizer zeroed.  Identity is recorded without keeping a reference: a
    probe that holds the buffer makes the holder a non-last owner, which the
    finalizer correctly leaves alone."""
    obj = make()
    targets = {name: id(getattr(obj, name)) for name in attrs}
    seen: set[int] = set()
    real = sm._zero

    def spy(value: Any) -> None:
        seen.add(id(value))
        real(value)

    monkeypatch.setattr(sm, "_zero", spy)
    del obj
    gc.collect()
    return {name for name, ident in targets.items() if ident in seen}


def test_a_dropped_key_store_zeroes_its_key_encryption_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """PIN.  The key-encryption key protects every stored key.  Dropping the
    store without ``close()`` zeroes it; before the class was a
    ``SecretMaterial`` nothing did, and a dropped store left it in memory."""
    from ama_cryptography.key_management import SecureKeyStorage

    zeroed = _zeroed_on_drop(
        monkeypatch,
        lambda: SecureKeyStorage(tmp_path / "ks", master_password="correct horse battery 123"),
        ("encryption_key",),
    )
    assert zeroed == {"encryption_key"}


def test_a_dropped_session_zeroes_its_traffic_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  A session dropped without ``close()`` zeroes both live keys.
    Removing ``SecretMaterial`` from ``SecureSession`` fails this."""
    sc = importlib.import_module("ama_cryptography.secure_channel")
    zeroed = _zeroed_on_drop(
        monkeypatch,
        lambda: sc._session_from(b"\x41" * 32, b"\x01" * 32, send_info=b"s", recv_info=b"r"),
        ("send_key", "recv_key"),
    )
    assert zeroed == {"send_key", "recv_key"}


def test_a_dropped_initiator_zeroes_its_shared_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  An initiator dropped mid-handshake zeroes the KEM shared secret it
    holds.  Removing ``SecretMaterial`` from ``SecureChannelInitiator`` fails
    this."""
    from ama_cryptography.crypto_api import HybridKEMProvider

    sc = importlib.import_module("ama_cryptography.secure_channel")
    kem = HybridKEMProvider().generate_keypair()

    def make() -> Any:
        initiator = sc.SecureChannelInitiator(kem.public_key)
        initiator.create_handshake()
        return initiator

    zeroed = _zeroed_on_drop(monkeypatch, make, ("_shared_secret",))
    assert zeroed == {"_shared_secret"}


def test_a_refused_hybrid_signing_keypair_zeroes_its_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The Ed25519 and ML-DSA component keypairs and the combined secret
    are held until the KeyPair adopts the combined key; a refusal zeroes all
    of them.  Restoring the bare ``bytearray(...) + ...`` fails this."""
    from ama_cryptography import crypto_api as ca

    prov = ca.HybridSignatureProvider()
    minted: list[Any] = []
    for sub in (prov.classical_provider, prov.pqc_provider):
        real = sub.generate_keypair

        def recording(real: Any = real) -> Any:
            kp = real()
            minted.append(kp)
            return kp

        monkeypatch.setattr(sub, "generate_keypair", recording)
    combined: list[bytearray] = []
    real_keypair = ca.KeyPair

    def keypair_refuses(**kwargs: Any) -> Any:
        # Only the hybrid's own KeyPair refuses; the components build theirs.
        if "classical_algorithm" not in kwargs["metadata"]:
            return real_keypair(**kwargs)
        combined.append(kwargs["secret_key"])
        raise RuntimeError("keypair refused")

    monkeypatch.setattr(ca, "KeyPair", keypair_refuses)
    with pytest.raises(RuntimeError, match="keypair refused"):
        prov.generate_keypair()
    assert len(minted) == 2 and all(not any(kp.secret_key) for kp in minted)
    assert len(combined) == 1 and not any(combined[0])


def test_a_refused_ed25519_keypair_zeroes_its_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  The 32-byte seed copied out of the 64-byte expanded key is held
    until the KeyPair adopts it.  Restoring the bare copy fails this."""
    from ama_cryptography import crypto_api as ca

    seeds: list[bytearray] = []

    def keypair_refuses(**kwargs: Any) -> Any:
        seeds.append(kwargs["secret_key"])
        raise RuntimeError("keypair refused")

    monkeypatch.setattr(ca, "KeyPair", keypair_refuses)
    with pytest.raises(RuntimeError, match="keypair refused"):
        ca.Ed25519Provider().generate_keypair()
    assert len(seeds) == 1 and not any(seeds[0])


def test_a_refused_legacy_ed25519_keypair_zeroes_its_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The legacy Ed25519 path holds its secret until the container
    adopts it.  Restoring the bare constructor call fails this."""
    from ama_cryptography import legacy_compat as lc

    secrets_seen: list[bytearray] = []

    def container_refuses(**kwargs: Any) -> Any:
        secrets_seen.append(kwargs["private_key"])
        raise RuntimeError("container refused")

    monkeypatch.setattr(lc, "Ed25519KeyPair", container_refuses)
    with pytest.raises(RuntimeError, match="container refused"):
        lc.generate_ed25519_keypair()
    assert len(secrets_seen) == 1 and not any(secrets_seen[0])


def test_the_handshake_ephemeral_secret_is_zeroed_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  The initiator's ephemeral KEM secret is never used, so it is zeroed
    as soon as the public half is read.  Removing the ``wipe()`` fails this."""
    from ama_cryptography.crypto_api import HybridKEMProvider

    sc = importlib.import_module("ama_cryptography.secure_channel")
    kem = HybridKEMProvider().generate_keypair()
    initiator = sc.SecureChannelInitiator(kem.public_key)
    minted: list[Any] = []
    real = initiator._kem.generate_keypair

    def recording() -> Any:
        kp = real()
        minted.append(kp)
        return kp

    monkeypatch.setattr(initiator._kem, "generate_keypair", recording)
    initiator.create_handshake()
    assert len(minted) == 1 and not any(minted[0].secret_key)
    assert minted[0].public_key == initiator._ephemeral_pk


def test_the_post_ed25519_consistency_check_zeroes_its_fresh_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  POST's Ed25519 pairwise draw is zeroed on every path, including a
    failing pairwise verify: only the verify over the pairwise message fails,
    so the draw is reached.  Removing the ``finally`` fails this."""
    st = importlib.import_module("ama_cryptography._self_test")
    minted: list[bytearray] = []
    real_keypair = pb.native_ed25519_keypair
    real_verify = pb.native_ed25519_verify

    def recording_keypair() -> Any:
        pk, sk = real_keypair()
        minted.append(sk)
        return pk, sk

    pairwise_msg = b"FIPS 140-3 Ed25519 pairwise consistency"

    def pairwise_verify_fails(*args: Any, **kwargs: Any) -> bool:
        if args[1] == pairwise_msg:
            raise RuntimeError("verify refused")
        return bool(real_verify(*args, **kwargs))

    monkeypatch.setattr(pb, "native_ed25519_keypair", recording_keypair)
    monkeypatch.setattr(pb, "native_ed25519_verify", pairwise_verify_fails)
    st._kat_ed25519()
    assert len(minted) == 1 and not any(minted[0])
