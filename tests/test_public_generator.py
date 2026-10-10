# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The library's public random generator hands out wipeable buffers
(INVARIANT-6): ``secure_random_bytes`` returns a ``bytearray`` written in place
by the native CSPRNG, the wipeable draws are public, and the build-time signer
seeds from the native CSPRNG instead of ``os.urandom``.
"""

from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path
from typing import Any, Callable

import pytest

import ama_cryptography
import ama_cryptography._module_state as ms
from ama_cryptography import _build_sign as bs
from ama_cryptography import secure_memory
from ama_cryptography.exceptions import CryptoModuleError


@pytest.fixture
def restore_rng_state() -> Any:
    saved = ms._rng_state["previous"]
    saved_state, saved_reason = ms._MODULE_STATE, ms._ERROR_REASON
    yield
    ms._rng_state["previous"] = saved
    ms._MODULE_STATE, ms._ERROR_REASON = saved_state, saved_reason


def _counting_source(filled: list[Any]) -> Callable[[Any], None]:
    """An entropy source that records the object it was handed and fills it
    with bytes that differ on every call (so the repeated-output test passes)."""

    def fill(buf: Any) -> None:
        filled.append(buf)
        out = memoryview(buf).cast("B")
        n = len(filled)
        out[:] = bytes((n * 31 + i) & 0xFF for i in range(out.nbytes))

    return fill


# ---------------------------------------------------------------------------
# secure_random_bytes is wipeable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 31, 32, 33, 1000])
def test_secure_random_bytes_returns_a_bytearray(size: int) -> None:
    """RANGE.  The result is exactly a ``bytearray`` of the requested size, 0 included."""
    out = secure_memory.secure_random_bytes(size)
    assert type(out) is bytearray
    assert len(out) == size


def test_secure_random_bytes_returned_object_is_the_one_the_source_filled(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  The buffer the native source wrote IS the returned object, so no
    other copy exists (an extra ``bytearray(...)`` copy fails on identity)."""
    filled: list[Any] = []
    monkeypatch.setattr(ms, "_entropy_fill", _counting_source(filled))
    out = secure_memory.secure_random_bytes(48)
    assert len(filled) == 1
    assert filled[0] is out


def test_secure_random_bytes_result_can_be_wiped() -> None:
    """SMOKE.  The result is zeroable in place by the library's own wipe."""
    out = secure_memory.secure_random_bytes(32)
    assert any(out)
    secure_memory.secure_memzero(out)
    assert out == bytearray(32)


def test_secure_random_bytes_refuses_when_the_source_fails(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  A source that writes and then fails leaves nothing behind: the
    buffer it was handed is zeroed before the exception propagates."""
    handed: list[Any] = []

    def half_then_fail(buf: Any) -> None:
        handed.append(buf)
        memoryview(buf).cast("B")[:16] = b"\xa5" * 16
        raise CryptoModuleError("entropy source failed")

    monkeypatch.setattr(ms, "_entropy_fill", half_then_fail)
    with pytest.raises(CryptoModuleError):
        secure_memory.secure_random_bytes(32)
    assert handed and handed[0] == bytearray(32)


def test_secure_random_bytes_negative_size_raises() -> None:
    with pytest.raises(ValueError):
        secure_memory.secure_random_bytes(-1)


def test_the_wipeable_draws_are_public() -> None:
    """PIN.  The wipeable draws are importable from the public surface, are
    the ``_module_state`` functions, and are in both ``__all__``."""
    for name in ("secure_token_bytearray", "secure_random_fill"):
        assert name in ama_cryptography.__all__
        assert name in secure_memory.__all__
        assert getattr(ama_cryptography, name) is getattr(ms, name)
        assert getattr(secure_memory, name) is getattr(ms, name)
    assert type(ama_cryptography.secure_token_bytearray(16)) is bytearray
    assert type(ama_cryptography.secure_token_bytes(16)) is bytes


def test_secure_memory_still_binds_secure_token_bytes() -> None:
    """PIN.  ``secure_memory.secure_token_bytes`` stays importable (immutable
    ``bytes``, not in ``__all__``)."""
    from ama_cryptography.secure_memory import secure_token_bytes

    assert secure_token_bytes is ms.secure_token_bytes
    assert "secure_token_bytes" not in secure_memory.__all__
    out = secure_token_bytes(24)
    assert type(out) is bytes and len(out) == 24


# ---------------------------------------------------------------------------
# The build-time signer seeds from the native CSPRNG, in place
# ---------------------------------------------------------------------------


class _SpyLib:
    """The real native library with ``ama_random_bytes`` replaced by a spy
    that records the ctypes array each call was given."""

    def __init__(self, real: Any, behaviour: Callable[[int, Any], int]) -> None:
        self._real = real
        self._behaviour = behaviour
        self.arrays: list[Any] = []
        self.contents: list[bytes] = []
        self.lengths: list[int] = []

        def ama_random_bytes(buf: Any, n: int) -> int:
            # The length argument must be the whole seed: less leaves part of
            # it zero, more overruns the buffer.
            self.lengths.append(n)
            assert n == 32 == len(buf), f"ama_random_bytes(n={n}) on a {len(buf)}-byte buffer"
            self.arrays.append(buf)
            rc = self._behaviour(len(self.arrays), buf)
            self.contents.append(bytes(buf))
            return rc

        self.ama_random_bytes = ama_random_bytes

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def _distinct(call: int, buf: Any) -> int:
    ctypes.memmove(buf, bytes([0x10 * call]) * 32, 32)
    return 0


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch) -> Any:
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        pytest.skip("native library not available in this environment")
    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: None)
    monkeypatch.setattr(bs, "_find_native_library", lambda: _native_lib, raising=False)
    return _native_lib


def _no_urandom(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    def boom(_n: int) -> bytes:
        raise AssertionError("os.urandom reached from the build-time signer")

    monkeypatch.setattr(os, "urandom", boom)


def test_signer_seed_is_the_second_native_draw(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PIN.  The signing key derives from the second 32-byte draw of
    ``ama_random_bytes`` on the signing handle; ``os.urandom`` is never called."""
    _no_urandom(monkeypatch)
    spy = _SpyLib(native, _distinct)
    pubkey, _sig, _src = bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=spy)
    assert len(spy.contents) == 2
    assert spy.lengths == [32, 32]
    assert spy.contents == [bytes([0x10]) * 32, bytes([0x20]) * 32]
    expected, _s, _src2 = bs._generate_keypair_and_sign(
        b"\x00" * 32, seed_override=bytes([0x20]) * 32, native_lib=native
    )
    assert pubkey == expected


def test_signer_scrubs_both_draw_buffers(native: Any) -> None:
    """PIN.  After signing, neither draw buffer still holds seed material."""
    spy = _SpyLib(native, _distinct)
    bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=spy)
    assert [bytes(a) for a in spy.arrays] == [bytes(32), bytes(32)]


def test_signer_refuses_a_stuck_source_and_scrubs(native: Any) -> None:
    """PIN.  Two identical draws are refused (FIPS 140-3 continuous test) and
    both buffers are zeroed on the way out."""

    def stuck(_call: int, buf: Any) -> int:
        ctypes.memmove(buf, b"\x42" * 32, 32)
        return 0

    spy = _SpyLib(native, stuck)
    with pytest.raises(RuntimeError, match="identical"):
        bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=spy)
    assert [bytes(a) for a in spy.arrays] == [bytes(32), bytes(32)]


def test_signer_refuses_a_failing_source_without_falling_back(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PIN.  A source failure is refused; ``os.urandom`` is not substituted
    (INVARIANT-7)."""
    _no_urandom(monkeypatch)

    def fail(_call: int, buf: Any) -> int:
        ctypes.memmove(buf, b"\x99" * 32, 32)
        return -1

    spy = _SpyLib(native, fail)
    with pytest.raises(RuntimeError, match="ama_random_bytes returned rc=-1"):
        bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=spy)
    assert all(bytes(a) == bytes(32) for a in spy.arrays)


def test_signer_refuses_a_library_without_the_csprng(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PIN.  A handle lacking ``ama_random_bytes`` is refused, never served
    from another source."""
    _no_urandom(monkeypatch)

    class _NoRandom:
        def __getattr__(self, name: str) -> Any:
            if name == "ama_random_bytes":
                raise AttributeError(name)
            return getattr(native, name)

    with pytest.raises(RuntimeError, match="does not export ama_random_bytes"):
        bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=_NoRandom())


def test_signer_works_from_the_error_state(native: Any, restore_rng_state: Any) -> None:
    """PIN.  The repair tool must sign while the module is in the ERROR state,
    so the seed cannot route through the gated ``secure_random_fill``."""
    ms._set_error("test: simulated POST failure")
    pubkey, signature, _src = bs._generate_keypair_and_sign(b"\x00" * 32, native_lib=native)
    assert len(pubkey) == 32 and len(signature) == 64


# ---------------------------------------------------------------------------
# tools/wheel_smoke_test.py: the AEAD key draws are wiped on every exit
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def smoke_tool() -> Any:
    path = Path(__file__).resolve().parent.parent / "tools" / "wheel_smoke_test.py"
    spec = importlib.util.spec_from_file_location("wheel_smoke_test_wipe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fails", [False, True], ids=["passes", "raises"])
@pytest.mark.parametrize(
    ("check", "helper"),
    [
        ("check_aes_gcm", "_check_aes_gcm_with"),
        ("check_chacha20_poly1305", "_check_chacha20_poly1305_with"),
    ],
)
def test_the_smoke_test_wipes_its_aead_key_on_every_exit(
    smoke_tool: Any, monkeypatch: pytest.MonkeyPatch, check: str, helper: str, fails: bool
) -> None:
    """PIN.  The release smoke test draws its AEAD key into a wipeable
    ``bytearray`` and zeroes it in a ``finally``; the helper is replaced so the
    row isolates the wipe."""
    drawn: list[bytearray] = []
    real_draw = ama_cryptography.secure_token_bytearray

    def recording(size: int) -> Any:
        buf = real_draw(size)
        drawn.append(buf)
        return buf

    seen_live: list[bool] = []

    def fake_helper(*args: Any) -> None:
        seen_live.append(any(drawn[0]))
        if fails:
            raise RuntimeError("injected")

    monkeypatch.setattr(ama_cryptography, "secure_token_bytearray", recording)
    monkeypatch.setattr(smoke_tool, helper, fake_helper)
    if fails:
        with pytest.raises(RuntimeError, match="injected"):
            getattr(smoke_tool, check)()
    else:
        getattr(smoke_tool, check)()
    assert len(drawn) == 1 and len(drawn[0]) == 32
    assert seen_live == [True], "the key was already empty when the helper ran"
    assert not any(drawn[0]), "the key draw was left populated"
