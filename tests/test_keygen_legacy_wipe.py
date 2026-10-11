#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Exit-path zeroing (INVARIANT-6) for HD derivation, legacy key helpers,
X25519 keygen, password/mnemonic encodings and the two KAT key-pair containers.

Each test injects a fault after a secret exists and before anything owns it,
captures the live buffer from the caller's frame, and checks it is all-zero
when the exception arrives.
"""

from __future__ import annotations

import ctypes
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography.key_management as km
import ama_cryptography.legacy_compat as lc
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _secret_material as sm
from ama_cryptography.exceptions import CryptoModuleError


def _locals_of(function_name: str) -> dict[str, Any]:
    """The locals of the nearest enclosing frame running ``function_name``."""
    frame: Any = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name == function_name:
            return dict(frame.f_locals)
        frame = frame.f_back
    raise AssertionError(f"no frame running {function_name}")


class _Captured:
    """Live secret buffers a spy saw, with what they held at that moment."""

    def __init__(self) -> None:
        self.buffers: dict[str, bytearray] = {}
        self.at_capture: dict[str, bytes] = {}

    def take(self, name: str, value: Any) -> None:
        assert isinstance(value, bytearray), f"{name} is not a bytearray: {type(value)}"
        self.buffers[name] = value
        self.at_capture[name] = bytes(value)

    def assert_all_zeroed(self, expected: list[str]) -> None:
        assert sorted(self.buffers) == sorted(expected)
        for name, buffer in self.buffers.items():
            assert any(self.at_capture[name]), f"{name} was already empty when captured"
            assert not any(buffer), f"{name} was left populated by the exception path"


# ---------------------------------------------------------------------------
# HD master / child derivation (key_management.py)
# ---------------------------------------------------------------------------


def _refuse(*_args: Any, **_kwargs: Any) -> Any:
    raise CryptoModuleError("injected: module moved to ERROR")


@pytest.mark.parametrize(
    "step", ["native_secp256k1_seckey_verify", "native_secp256k1_pubkey_from_privkey"]
)
def test_a_master_key_and_chain_code_are_zeroed_when_a_later_step_raises(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """PIN.  A native call that raises (the seckey check, or the pairwise
    test's first statement) must not drop ``master_key`` or ``chain_code``
    populated; removing either ``held(...)`` in ``_generate_master_key``
    fails both rows."""
    captured = _Captured()

    def spy(*_args: Any, **_kwargs: Any) -> Any:
        scope = _locals_of("_generate_master_key")
        captured.take("master_key", scope["master_key"])
        captured.take("chain_code", scope["chain_code"])
        raise CryptoModuleError("injected: module moved to ERROR")

    monkeypatch.setattr(pb, step, spy)
    with pytest.raises(CryptoModuleError):
        km.HDKeyDerivation(seed=bytes(range(64)))
    captured.assert_all_zeroed(["master_key", "chain_code"])


def test_an_out_of_range_master_key_is_still_refused_and_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMOKE against the unfixed code, which zeroed both halves explicitly
    here and so passes this too; PIN of the refactor that moved the refusal
    under the shared guard: removing either ``held(...)`` fails it
    (measured)."""
    captured = _Captured()

    def invalid(key: Any) -> bool:
        scope = _locals_of("_generate_master_key")
        captured.take("master_key", scope["master_key"])
        captured.take("chain_code", scope["chain_code"])
        return False

    monkeypatch.setattr(pb, "native_secp256k1_seckey_verify", invalid)
    with pytest.raises(ValueError, match="Invalid BIP32 master key"):
        km.HDKeyDerivation(seed=bytes(range(64)))
    captured.assert_all_zeroed(["master_key", "chain_code"])


def test_a_child_chain_code_is_zeroed_when_the_tweak_raises_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  Any exception out of the tweak (not only ``ValueError``) leaves
    ``child_chain`` and the HMAC output zeroed; removing ``held(...)`` or the
    ``secure_memzero(hmac_result)`` fails this."""
    hd = km.HDKeyDerivation(seed=bytes(range(64)))
    captured = _Captured()

    def spy(*_args: Any, **_kwargs: Any) -> Any:
        scope = _locals_of("_ckd_private")
        captured.take("child_chain", scope["child_chain"])
        captured.take("hmac_result", scope["hmac_result"])
        raise CryptoModuleError("injected: module moved to ERROR")

    monkeypatch.setattr(pb, "native_secp256k1_seckey_tweak_add", spy)
    with pytest.raises(CryptoModuleError):
        hd.derive_path("m/1'/2'")
    captured.assert_all_zeroed(["child_chain", "hmac_result"])


@pytest.mark.parametrize("path", ["m/1'", "m/1"], ids=["hardened", "non-hardened"])
def test_a_child_key_and_chain_are_zeroed_when_the_pairwise_derivation_raises(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """PIN.  The pairwise test's first statement derives the public key,
    before its key guard is entered; a raise there dropped ``child_key``
    populated, and the child key was not registered with the scrub at all.
    Removing ``held(...)`` around the tweak's result fails ``child_key``."""
    hd = km.HDKeyDerivation(seed=bytes(range(64)))
    real = pb.native_secp256k1_pubkey_from_privkey
    captured = _Captured()

    def spy(private_key: Any) -> Any:
        try:
            scope = _locals_of("_pairwise_consistency_test")
        except AssertionError:
            return real(private_key)  # the non-hardened HMAC input, not the test
        outer = _locals_of("_ckd_private")
        captured.take("child_key", scope["private_key"])
        captured.take("child_chain", outer["child_chain"])
        raise CryptoModuleError("injected: module moved to ERROR")

    monkeypatch.setattr(pb, "native_secp256k1_pubkey_from_privkey", spy)
    with pytest.raises(CryptoModuleError):
        hd.derive_path(path)
    captured.assert_all_zeroed(["child_key", "child_chain"])


def test_a_successful_derivation_leaves_its_results_intact() -> None:
    """SMOKE.  The guard acts on a raise only: the results are populated,
    32 bytes each, and deterministic for a seed."""
    first = km.HDKeyDerivation(seed=bytes(range(64)))
    key, chain = first.derive_path("m/44'/0'/0'/0/0")
    again, again_chain = km.HDKeyDerivation(seed=bytes(range(64))).derive_path("m/44'/0'/0'/0/0")
    assert len(key) == len(chain) == 32 and any(key) and any(chain)
    assert (key, chain) == (again, again_chain)
    assert any(first.master_key) and any(first.master_chain_code)


# ---------------------------------------------------------------------------
# BIP39 mnemonic and master-password encodings (key_management.py)
# ---------------------------------------------------------------------------

_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def _password_spy(
    monkeypatch: pytest.MonkeyPatch,
    owner: Any,
    name: str,
    result: Callable[[], Any],
    raises: Optional[BaseException] = None,
) -> dict[str, Any]:
    """Replace ``owner.name``; record the password argument it receives (a
    reference and a snapshot), and return ``result()`` or raise."""
    seen: dict[str, Any] = {}

    def spy(password: Any, *_args: Any, **_kwargs: Any) -> Any:
        seen["password"] = password
        seen["snapshot"] = bytes(password)
        if raises is not None:
            raise raises
        return result()

    monkeypatch.setattr(owner, name, spy)
    return seen


def test_the_mnemonic_reaches_pbkdf2_as_a_wipeable_bytearray_zeroed_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The library encoded the mnemonic into an immutable ``bytes``
    that nothing could zero.  Reverting to ``.encode("utf-8")`` fails the
    type check; dropping the ``finally`` fails the zero check."""
    seen = _password_spy(monkeypatch, km, "native_pbkdf2_hmac_sha512", lambda: bytearray(64))
    km.HDKeyDerivation(seed_phrase=_MNEMONIC)
    assert type(seen["password"]) is bytearray
    assert seen["snapshot"] == _MNEMONIC.encode("utf-8")
    assert not any(seen["password"])


def test_the_mnemonic_is_zeroed_when_the_derivation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The failing-KDF exit: dropping the ``finally`` fails this."""
    seen = _password_spy(
        monkeypatch,
        km,
        "native_pbkdf2_hmac_sha512",
        lambda: None,
        raises=CryptoModuleError("injected"),
    )
    with pytest.raises(CryptoModuleError):
        km.HDKeyDerivation(seed_phrase=_MNEMONIC)
    assert type(seen["password"]) is bytearray and not any(seen["password"])


def test_the_mnemonic_seed_matches_the_official_bip39_vector() -> None:
    """SMOKE.  The bytearray encoding changes no byte of the BIP39 seed
    (the official 'abandon ... about' vector, empty passphrase)."""
    hd = km.HDKeyDerivation(seed_phrase=_MNEMONIC)
    assert (
        bytes(hd.master_seed)
        .hex()
        .startswith("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1")
    )


_PASSWORD = "pässwörd-日本"  # non-ASCII, so UTF-8 is observable


def _legacy_store(tmp_path: Path) -> Path:
    store = tmp_path / "legacy"
    store.mkdir()
    (store / ".salt").write_bytes(bytes(range(32)))
    (store / ".kdf_metadata.json").write_text(
        json.dumps({"version": 2, "iterations": 600000}), encoding="utf-8"
    )
    return store


def _open_new_store(tmp_path: Path, password: str) -> None:
    km.SecureKeyStorage(tmp_path / "store", master_password=password)


def _open_legacy_store(tmp_path: Path, password: str) -> None:
    with pytest.warns(km.SecurityWarning, match="policy floor"):
        km.SecureKeyStorage(
            _legacy_store(tmp_path), master_password=password, allow_legacy_kdf=True
        )


def _migrate_store(tmp_path: Path, password: str) -> None:
    km.SecureKeyStorage(tmp_path / "store")._reencrypt_under_current_kdf(password, {})


def _derive_mnemonic(_tmp_path: Path, phrase: str) -> None:
    km.HDKeyDerivation(seed_phrase=phrase)


@pytest.mark.parametrize(
    "entry",
    [_open_new_store, _open_legacy_store, _migrate_store, _derive_mnemonic],
    ids=["new-store", "legacy-store", "migration", "mnemonic"],
)
def test_a_lone_surrogate_secret_fails_exactly_as_str_encode_does(
    tmp_path: Path, entry: Callable[[Path, str], None]
) -> None:
    """PIN.  A password or mnemonic that cannot be UTF-8 encoded raises the
    same ``UnicodeEncodeError`` (same position) as ``str.encode``, at each of
    the four encoding sites."""
    secret = "ab\ud800"
    with pytest.raises(UnicodeEncodeError) as expected:
        secret.encode("utf-8")
    with pytest.raises(UnicodeEncodeError) as raised:
        entry(tmp_path, secret)
    assert str(raised.value) == str(expected.value)
    assert "in position 2" in str(raised.value)


def test_a_new_store_derives_its_key_from_a_wipeable_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PIN.  ``SecureKeyStorage`` encoded the master password into an
    immutable ``bytes`` for Argon2id.  Reverting the encode fails the type
    check; dropping the ``finally`` fails the zero check."""
    seen = _password_spy(monkeypatch, pb, "native_argon2id", lambda: bytearray(32))
    km.SecureKeyStorage(tmp_path / "store", master_password=_PASSWORD)
    assert type(seen["password"]) is bytearray
    assert seen["snapshot"] == _PASSWORD.encode("utf-8")
    assert not any(seen["password"])


def test_a_new_store_zeroes_the_password_when_argon2id_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PIN.  The failing-derivation exit of the same site (the wrapper maps
    RuntimeError to its install hint); dropping the ``finally`` fails this."""
    seen = _password_spy(
        monkeypatch, pb, "native_argon2id", lambda: None, raises=RuntimeError("injected")
    )
    with pytest.raises(RuntimeError):
        km.SecureKeyStorage(tmp_path / "store", master_password=_PASSWORD)
    assert type(seen["password"]) is bytearray and not any(seen["password"])


@pytest.mark.parametrize("fails", [False, True], ids=["derives", "raises"])
def test_a_legacy_pbkdf2_store_derives_from_a_wipeable_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fails: bool
) -> None:
    """PIN.  The PBKDF2-HMAC-SHA256 branch (stores written by KDF version 2)
    had the same immutable encoding.  Reverting it fails the type check on
    both rows; zeroing only after a successful call (no ``finally``) fails the
    ``raises`` row's zero check, and removing the zeroing altogether fails
    both."""
    store = _legacy_store(tmp_path)
    seen = _password_spy(
        monkeypatch,
        km,
        "native_pbkdf2_hmac_sha256",
        lambda: bytearray(32),
        raises=RuntimeError("injected") if fails else None,
    )
    with pytest.warns(km.SecurityWarning, match="policy floor"):
        if fails:
            with pytest.raises(RuntimeError, match="injected"):
                km.SecureKeyStorage(store, master_password=_PASSWORD, allow_legacy_kdf=True)
        else:
            km.SecureKeyStorage(store, master_password=_PASSWORD, allow_legacy_kdf=True)
    assert type(seen["password"]) is bytearray
    assert seen["snapshot"] == _PASSWORD.encode("utf-8")
    assert not any(seen["password"])


@pytest.mark.parametrize("fails", [False, True], ids=["derives", "raises"])
def test_a_kdf_migration_derives_from_a_wipeable_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fails: bool
) -> None:
    """PIN.  ``_reencrypt_under_current_kdf`` encoded the password into an
    immutable ``bytes``, and a failing derivation left nothing to zero.
    Reverting the encode fails the type check on both rows; dropping the
    ``finally`` fails the ``raises`` row's zero check."""
    storage = km.SecureKeyStorage(tmp_path / "store")  # random key, no KDF run
    seen = _password_spy(
        monkeypatch,
        pb,
        "native_argon2id",
        lambda: bytearray(32),
        raises=RuntimeError("injected") if fails else None,
    )
    if fails:
        with pytest.raises(RuntimeError):
            storage._reencrypt_under_current_kdf(_PASSWORD, {})
    else:
        storage._reencrypt_under_current_kdf(_PASSWORD, {})
    assert type(seen["password"]) is bytearray
    assert seen["snapshot"] == _PASSWORD.encode("utf-8")
    assert not any(seen["password"])


# ---------------------------------------------------------------------------
# legacy_compat.py
# ---------------------------------------------------------------------------


def test_derived_keys_are_zeroed_when_a_later_derivation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``derive_keys`` appended each key to a local list and returned
    it; a later ``native_hkdf`` that raised dropped the keys already derived
    populated.  Removing the ``held(...)`` around the derivation fails this."""
    real = pb.native_hkdf
    produced: list[bytearray] = []
    calls = [0]

    def flaky(**kwargs: Any) -> Any:
        calls[0] += 1
        if calls[0] == 3:
            raise CryptoModuleError("injected: module moved to ERROR")
        key = real(**kwargs)
        produced.append(key)
        return key

    monkeypatch.setattr("ama_cryptography.legacy_compat.native_hkdf", flaky)
    with pytest.raises(CryptoModuleError):
        lc.derive_keys(bytearray(b"\x11" * 32), "info", num_keys=4, salt=b"\x22" * 32)
    assert len(produced) == 2
    assert all(not any(key) for key in produced)


def test_derived_keys_are_returned_populated_when_nothing_raises() -> None:
    """SMOKE.  The guard acts on a raise only."""
    keys, salt = lc.derive_keys(bytearray(b"\x11" * 32), "info", num_keys=3, salt=b"\x22" * 32)
    assert len(keys) == 3 and all(len(k) == 32 and any(k) for k in keys)
    assert len({bytes(k) for k in keys}) == 3 and salt == b"\x22" * 32


def _record_expansion(monkeypatch: pytest.MonkeyPatch) -> list[bytearray]:
    real = pb.native_ed25519_keypair_from_seed
    expansions: list[bytearray] = []

    def recording(seed: Any) -> Any:
        public_key, expanded = real(seed)
        expansions.append(expanded)
        return public_key, expanded

    monkeypatch.setattr(
        "ama_cryptography.legacy_compat.native_ed25519_keypair_from_seed", recording
    )
    return expansions


def test_the_seed_expansion_is_zeroed_after_a_legacy_ed25519_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``ed25519_sign(message, seed32)`` expanded the seed into a
    64-byte key, signed with it, and dropped it populated.  Removing the
    ``finally`` fails this; the signature must still verify."""
    seed = bytearray(b"\x07" * 32)
    public_key, _ = pb.native_ed25519_keypair_from_seed(seed)
    expansions = _record_expansion(monkeypatch)
    signature = lc.ed25519_sign(b"message", seed)
    assert lc.ed25519_verify(b"message", signature, public_key)
    assert len(expansions) == 1 and len(expansions[0]) == 64
    assert not any(expansions[0])
    assert seed == bytearray(b"\x07" * 32), "the caller's own seed is the caller's"


def test_the_seed_expansion_is_zeroed_when_the_legacy_sign_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The failing-sign exit; removing the ``finally`` fails this."""
    expansions = _record_expansion(monkeypatch)
    monkeypatch.setattr(lc, "native_ed25519_sign", _refuse)
    with pytest.raises(CryptoModuleError):
        lc.ed25519_sign(b"message", bytearray(b"\x07" * 32))
    assert len(expansions) == 1 and not any(expansions[0])


def test_a_caller_supplied_expanded_key_is_not_zeroed_by_the_legacy_sign() -> None:
    """PIN against over-zealous zeroing (SMOKE against the unfixed code,
    which never zeroed).  A 64-byte key is the caller's, passed through as
    given; wiping it would destroy their key.  Zeroing it in the 64-byte
    branch fails this (measured)."""
    _, expanded = pb.native_ed25519_keypair_from_seed(bytearray(b"\x07" * 32))
    before = bytes(expanded)
    lc.ed25519_sign(b"message", expanded)
    assert bytes(expanded) == before and any(expanded)


def test_a_refused_seeded_legacy_ed25519_keypair_zeroes_the_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``generate_ed25519_keypair(seed)`` holds the 64-byte expansion it
    mints until the container adopts it; a container that refuses (the
    unseeded branch already guarded this) dropped it populated.  Restoring the
    bare constructor call in the seeded branch fails this."""
    seen: list[bytearray] = []
    at_call: list[bytes] = []

    def container_refuses(**kwargs: Any) -> Any:
        seen.append(kwargs["private_key"])
        at_call.append(bytes(kwargs["private_key"]))
        raise RuntimeError("container refused")

    monkeypatch.setattr(lc, "Ed25519KeyPair", container_refuses)
    seed = bytearray(b"\x07" * 32)
    with pytest.raises(RuntimeError, match="container refused"):
        lc.generate_ed25519_keypair(seed)
    assert len(seen) == 1 and len(seen[0]) == 64 and any(at_call[0])
    assert not any(seen[0])
    assert seed == bytearray(b"\x07" * 32), "the caller's own seed is the caller's"


# ---------------------------------------------------------------------------
# native_x25519_keypair (pqc_backends.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("step", ["secure_token_bytearray", "native_x25519_key_exchange"])
@pytest.mark.parametrize(
    "fault",
    [CryptoModuleError("injected: module moved to ERROR"), KeyboardInterrupt()],
    ids=["exception", "keyboard-interrupt"],
)
def test_an_x25519_secret_is_zeroed_when_the_ephemeral_step_raises(
    monkeypatch: pytest.MonkeyPatch, step: str, fault: BaseException
) -> None:
    """PIN.  A refused ephemeral draw or failing base-point multiplication
    must not drop the minted ``secret_key`` populated.  The keyboard-interrupt
    rows pin the guard's breadth (INVARIANT-9): ``except Exception`` fails
    exactly those."""
    captured = _Captured()

    def spy(*_args: Any, **_kwargs: Any) -> Any:
        captured.take("secret_key", _locals_of("native_x25519_keypair")["secret_key"])
        raise fault

    monkeypatch.setattr(pb, step, spy)
    with pytest.raises(type(fault)):
        pb.native_x25519_keypair()
    captured.assert_all_zeroed(["secret_key"])


@pytest.mark.parametrize("fails", [False, True], ids=["agrees", "pairwise-raises"])
def test_the_x25519_ephemeral_scalar_is_zeroed_on_every_exit(
    monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    """PIN.  The throwaway peer scalar of the pairwise test is zeroed by the
    inner ``finally`` of ``native_x25519_keypair``, on success and when the
    test raises.  Removing ``_secure_memzero(eph_secret)`` fails both rows
    (measured).  Its outer guard zeroes ``secret_key`` only, so the two are
    not redundant."""
    drawn: list[bytearray] = []
    real_draw = ms.secure_token_bytearray

    def recording(size: int) -> Any:
        buf = real_draw(size)
        drawn.append(buf)
        return buf

    monkeypatch.setattr(pb, "secure_token_bytearray", recording)
    if fails:
        monkeypatch.setattr(pb, "pairwise_test_agreement", _refuse)
        with pytest.raises(CryptoModuleError):
            pb.native_x25519_keypair()
    else:
        pb.native_x25519_keypair()
    assert len(drawn) == 1 and len(drawn[0]) == 32
    assert not any(drawn[0])


def test_an_x25519_keypair_is_released_populated_when_nothing_raises() -> None:
    """SMOKE.  The guard acts on a raise only."""
    public_key, secret_key = pb.native_x25519_keypair()
    assert len(public_key) == 32 and any(public_key)
    assert isinstance(secret_key, bytearray) and len(secret_key) == 32 and any(secret_key)


# ---------------------------------------------------------------------------
# slhdsa_sign_addrnd (pqc_backends.py)
# ---------------------------------------------------------------------------


class _SignSpyLib:
    """Stand-in for the native library that records the arguments of
    ``ama_slhdsa_sign_addrnd`` and forwards the call to the real one."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.calls: list[tuple[Any, ...]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def ama_slhdsa_sign_addrnd(self, *args: Any) -> Any:
        self.calls.append(args)
        return self._real.ama_slhdsa_sign_addrnd(*args)


def test_slhdsa_sign_addrnd_hands_the_native_call_the_callers_own_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The native call receives the caller's own ``addrnd`` and secret-
    key storage (same address, no immutable copy), and the signature equals
    the one made with a ``bytes`` addrnd."""
    keypair = pb.generate_slhdsa_keypair("SHAKE-128s")
    addrnd = bytearray(b"\xa5" * 16)
    spy = _SignSpyLib(pb._native_lib)
    monkeypatch.setattr(pb, "_native_lib", spy)
    signature = pb.slhdsa_sign_addrnd(b"m", keypair.secret_key, addrnd, param_set="SHAKE-128s")
    assert len(spy.calls) == 1
    handed_addrnd, handed_sk = spy.calls[0][7], spy.calls[0][8]
    assert not isinstance(handed_addrnd, bytes), "an immutable copy of addrnd reached C"
    assert ctypes.addressof(handed_addrnd) == ctypes.addressof(
        (ctypes.c_char * len(addrnd)).from_buffer(addrnd)
    )
    assert not isinstance(handed_sk, bytes), "an immutable copy of the secret key reached C"
    assert ctypes.addressof(handed_sk) == ctypes.addressof(
        (ctypes.c_char * len(keypair.secret_key)).from_buffer(keypair.secret_key)
    )
    monkeypatch.undo()
    assert addrnd == bytearray(b"\xa5" * 16), "the borrow must not zero the caller's addrnd"
    assert signature == pb.slhdsa_sign_addrnd(
        b"m", keypair.secret_key, bytes(addrnd), param_set="SHAKE-128s"
    )
    assert pb.slhdsa_verify(b"m", signature, keypair.public_key, param_set="SHAKE-128s")


# ---------------------------------------------------------------------------
# _DilithiumKATKeyPair / _KyberKATKeyPair (pqc_backends.py)
# ---------------------------------------------------------------------------

_KAT_PAIRS = [
    pytest.param(pb._DilithiumKATKeyPair, pb.DilithiumProvider, id="dilithium"),
    pytest.param(pb._KyberKATKeyPair, pb.KyberProvider, id="kyber"),
]


@pytest.mark.parametrize("cls", [p.values[0] for p in _KAT_PAIRS], ids=["dilithium", "kyber"])
def test_a_kat_key_pair_is_secret_material_with_constant_time_equality(cls: type) -> None:
    """RANGE (an inventory of the two classes; tests/test_secret_wipeability.py
    finds them by subclass traversal and also names them, so removing the mixin
    leaves their rows there and fails here).  Both carry the wipe/finalizer
    mixin, the constant-time ``__eq__`` marker, and ``secret_key`` as the
    named secret."""
    assert issubclass(cls, sm.SecretMaterial)
    assert dataclasses.is_dataclass(cls)
    assert vars(cls)["_SECRET_ATTRS"] == ("secret_key",)
    assert getattr(cls.__eq__, "constant_time_secret_fields", None) == frozenset({"secret_key"})


@pytest.mark.parametrize(
    ("cls", "provider"), [p.values for p in _KAT_PAIRS], ids=["dilithium", "kyber"]
)
def test_a_kat_key_pair_wipe_zeroes_its_secret_key(cls: type, provider: Any) -> None:
    """PIN.  Neither class had a ``wipe()``; removing the mixin fails this
    with AttributeError."""
    pair: Any = provider().generate_keypair()
    assert type(pair).__qualname__ == cls.__qualname__ and any(pair.secret_key)
    key = pair.secret_key
    pair.wipe()
    assert not any(key)


@pytest.mark.parametrize(
    ("cls", "provider"), [p.values for p in _KAT_PAIRS], ids=["dilithium", "kyber"]
)
def test_a_kat_key_pair_zeroes_its_secret_when_it_dies_holding_the_only_reference(
    monkeypatch: pytest.MonkeyPatch, cls: type, provider: Any
) -> None:
    """PIN.  The last-owner finalizer: collection zeroes a secret nothing
    else holds.  Removing the mixin (and so its ``__del__``) fails this."""
    zeroed: list[int] = []
    real = sm.zeroize

    def recording(value: Any) -> None:
        zeroed.append(id(value))
        real(value)

    monkeypatch.setattr(sm, "_zero", recording)
    pair = provider().generate_keypair()
    target = id(pair.secret_key)
    # Only zeroings after the pair exists count: key generation zeroes
    # transient bytearrays of its own, and a freed bytearray's address (its
    # id) is reused by the next one.
    before = len(zeroed)
    del pair
    assert target in zeroed[before:]


@pytest.mark.parametrize("cls", [p.values[0] for p in _KAT_PAIRS], ids=["dilithium", "kyber"])
def test_a_kat_key_pair_built_from_immutable_bytes_holds_a_wipeable_secret(cls: Any) -> None:
    """PIN.  ``__post_init__`` adopts the secret: a caller-supplied immutable
    ``bytes`` is replaced by a ``bytearray`` that ``wipe()`` can zero.  The
    providers hand in a ``bytearray`` already, so only a pair built from
    ``bytes`` reaches this conversion.  Removing ``__post_init__`` leaves the
    ``bytes`` in place and fails this."""
    supplied = b"\x5a" * 64
    pair = cls(public_key=b"p", secret_key=supplied)
    assert type(pair.secret_key) is bytearray and bytes(pair.secret_key) == supplied
    key = pair.secret_key
    pair.wipe()
    assert not any(key)


@pytest.mark.parametrize("provider", [p.values[1] for p in _KAT_PAIRS], ids=["dilithium", "kyber"])
def test_a_kat_key_pair_taken_from_a_temporary_is_not_zeroed(provider: Any) -> None:
    """SMOKE (passes with and without the mixin; not mutation-tested): the
    extract-from-a-temporary bug (see tests/test_secret_wipeability.py,
    where its PIN lives) must not come back through these classes."""
    key = provider().generate_keypair().secret_key
    assert any(key)


@pytest.mark.parametrize("provider", [p.values[1] for p in _KAT_PAIRS], ids=["dilithium", "kyber"])
def test_a_kat_key_pair_repr_does_not_print_its_secret_key(provider: Any) -> None:
    """PIN.  The generated ``repr`` printed ``secret_key=bytearray(...)``.
    Removing ``field(repr=False)`` fails this."""
    pair = provider().generate_keypair()
    text = repr(pair)
    assert "secret_key" not in text
    assert bytes(pair.secret_key[:16]).hex() not in text
    assert str(list(pair.secret_key[:8])) not in text and "bytearray(b" not in text


def test_a_kat_key_pair_compares_its_secret_through_the_constant_time_comparator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``__eq__`` must route the secret through the shared comparator,
    not bytearray ``==``.  Removing the decorator fails this."""
    from ama_cryptography import secure_memory

    calls: list[tuple[bytes, bytes]] = []
    real = secure_memory.constant_time_compare

    def recording(left: Any, right: Any) -> bool:
        calls.append((bytes(left), bytes(right)))
        return real(left, right)

    monkeypatch.setattr(ms, "_secret_comparator", recording)
    left = pb._KyberKATKeyPair(public_key=b"p", secret_key=bytearray(b"\x01" * 8))
    right = pb._KyberKATKeyPair(public_key=b"p", secret_key=bytearray(b"\x01" * 8))
    other = pb._KyberKATKeyPair(public_key=b"p", secret_key=bytearray(b"\x02" * 8))
    assert left == right and left != other
    assert (b"\x01" * 8, b"\x01" * 8) in calls and (b"\x01" * 8, b"\x02" * 8) in calls
