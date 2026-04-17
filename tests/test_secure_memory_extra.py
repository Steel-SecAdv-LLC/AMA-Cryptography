#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Additional coverage for ``ama_cryptography.secure_memory``.

Exercises the less-trivial branches:
    * secure_mlock / secure_munlock with immutable ``bytes`` objects and
      small platform-specific fall-throughs.
    * The pure-Python fallback of ``constant_time_compare`` (by bypassing
      the cached native probe).
    * The public ``get_status`` helper and the backend-selection probes.
    * The ``secure_buffer`` context manager helper.
    * ``_load_native_consttime`` / ``_try_native_ama_memzero`` exception
      branches when the native library is forcibly hidden.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import sys
import typing
from typing import Any, Callable

import pytest

from ama_cryptography import secure_memory as sm

# ``mlock``/``munlock`` may be legitimately unavailable on the runner (no
# native backend, no POSIX libc, or the OS refuses the privileged syscall).
# We deliberately suppress the documented set of exceptions so the happy
# path and the fallback path both get exercised for coverage without
# failing the test when the runner's environment can't provide mlock.
_MLOCK_OPTIONAL = (NotImplementedError, OSError, sm.SecureMemoryError)


class TestGetStatus:
    def test_status_fields(self) -> None:
        status = sm.get_status()
        assert status["available"] is True
        assert status["backend"] == "stdlib"
        assert status["initialized"] is True
        assert isinstance(status["mlock_available"], bool)
        assert isinstance(status["memzero_backend"], str)
        assert status["memzero_backend"] in {
            "native_ama",
            "libc_explicit_bzero",
            "libc_memset_s",
            "python_fallback",
        }


class TestSecureBufferHelper:
    def test_secure_buffer_context(self) -> None:
        """The ``secure_buffer`` function-based context manager zeroes on exit."""
        with sm.secure_buffer(48) as buf:
            for i in range(48):
                buf[i] = 0xA5
            ref = buf
        assert all(b == 0 for b in ref)

    def test_secure_buffer_empty(self) -> None:
        with sm.secure_buffer(0) as buf:
            assert len(buf) == 0


class TestSecureBufferLockedProperty:
    def test_locked_is_false(self) -> None:
        sb = sm.SecureBuffer(16)
        assert sb.locked is False

    def test_data_property_inside_context(self) -> None:
        sb = sm.SecureBuffer(8)
        with sb as _buf:
            assert sb.data is _buf
            assert len(sb.data) == 8


class TestMlockMunlockBytes:
    """Exercise the CPython id-based address path for immutable ``bytes``."""

    @pytest.mark.skipif(
        sys.implementation.name != "cpython",
        reason="id-based address layout is a CPython implementation detail",
    )
    def test_mlock_bytes_does_not_crash(self) -> None:
        # On this platform, secure_mlock may succeed, raise SecureMemoryError
        # (mlock refused), or NotImplementedError (no native/POSIX). All are
        # acceptable — we just exercise the code path so branches get
        # covered.
        with contextlib.suppress(*_MLOCK_OPTIONAL):
            sm.secure_mlock(b"x" * 64)

    @pytest.mark.skipif(
        sys.implementation.name != "cpython",
        reason="id-based address layout is a CPython implementation detail",
    )
    def test_munlock_bytes_does_not_crash(self) -> None:
        with contextlib.suppress(*_MLOCK_OPTIONAL):
            sm.secure_munlock(b"y" * 64)

    def test_mlock_memoryview(self) -> None:
        buf = bytearray(64)
        with contextlib.suppress(*_MLOCK_OPTIONAL):
            sm.secure_mlock(memoryview(buf))

    def test_munlock_memoryview(self) -> None:
        buf = bytearray(64)
        with contextlib.suppress(*_MLOCK_OPTIONAL):
            sm.secure_munlock(memoryview(buf))


class TestConstantTimePurePython:
    """Exercise the pure-Python fallback of ``constant_time_compare``.

    Done by temporarily replacing the module-level cached native pointer
    with ``None`` so the fallback branch executes.
    """

    def test_fallback_equal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_native_consttime_memcmp", None)
        assert sm.constant_time_compare(b"abc", b"abc") is True

    def test_fallback_unequal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_native_consttime_memcmp", None)
        assert sm.constant_time_compare(b"abc", b"abd") is False

    def test_fallback_different_lengths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_native_consttime_memcmp", None)
        assert sm.constant_time_compare(b"short", b"longer") is False

    def test_fallback_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_native_consttime_memcmp", None)
        assert sm.constant_time_compare(b"", b"") is True


class TestIsAvailable:
    def test_is_available(self) -> None:
        assert sm.is_available() is True


class TestNativeLoadFailures:
    """Exercise the exception branches when the native probe is broken.

    ``_load_native_consttime`` and ``_try_native_ama_memzero`` must return
    ``None`` (not propagate) when ``_find_native_library`` raises.
    """

    def test_load_consttime_on_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        def boom() -> None:
            raise OSError("probe failed")

        monkeypatch.setattr(pq, "_find_native_library", boom)
        assert sm._load_native_consttime() is None

    def test_try_native_memzero_on_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        def boom() -> None:
            raise AttributeError("probe failed")

        monkeypatch.setattr(pq, "_find_native_library", boom)
        assert sm._try_native_ama_memzero() is None

    def test_load_consttime_when_lib_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        monkeypatch.setattr(pq, "_find_native_library", lambda: None)
        assert sm._load_native_consttime() is None

    def test_try_native_memzero_when_lib_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        monkeypatch.setattr(pq, "_find_native_library", lambda: None)
        assert sm._try_native_ama_memzero() is None


class TestLibcProbes:
    def test_explicit_bzero_probe_returns_callable_or_none(self) -> None:
        result = sm._try_libc_explicit_bzero()
        assert result is None or callable(result)

    def test_memset_s_probe_returns_callable_or_none(self) -> None:
        result = sm._try_libc_memset_s()
        assert result is None or callable(result)

    def test_explicit_bzero_zeros_bytearray(self) -> None:
        fn: Callable[[bytearray], None] | None = sm._try_libc_explicit_bzero()
        if fn is None:
            pytest.skip("explicit_bzero not available on this platform")
        buf = bytearray(b"\xff" * 32)
        assert fn is not None  # narrow for mypy; pytest.skip already handles None
        fn(buf)
        assert all(b == 0 for b in buf)

    def test_explicit_bzero_win32_short_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        assert sm._try_libc_explicit_bzero() is None

    def test_explicit_bzero_missing_libc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Force find_library to return None → probe returns None via line 168.
        monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
        monkeypatch.setattr(sys, "platform", "linux")
        assert sm._try_libc_explicit_bzero() is None

    def test_explicit_bzero_oserror_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")

        def _fake_find(_name: str) -> str:
            return "libc_not_a_real_path.so.6"

        monkeypatch.setattr(ctypes.util, "find_library", _fake_find)

        class _BadCDLL:
            def __init__(self, _path: str) -> None:
                raise OSError("simulated dlopen failure")

        monkeypatch.setattr(ctypes, "CDLL", _BadCDLL)
        assert sm._try_libc_explicit_bzero() is None

    def test_memset_s_not_on_darwin_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert sm._try_libc_memset_s() is None

    def test_memset_s_darwin_path_no_libc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
        assert sm._try_libc_memset_s() is None

    def test_memset_s_darwin_missing_symbol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")

        class _StubLib:
            pass

        def _fake_cdll(_path: str) -> _StubLib:
            return _StubLib()

        monkeypatch.setattr(ctypes.util, "find_library", lambda name: "libc")
        monkeypatch.setattr(ctypes, "CDLL", _fake_cdll)
        # _StubLib has no memset_s attribute → falls into the hasattr branch.
        assert sm._try_libc_memset_s() is None


class TestDetectMlockFallbacks:
    def test_detect_mlock_win32(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate Windows: native backend missing & sys.platform == "win32".
        import ama_cryptography.pqc_backends as pq

        monkeypatch.setattr(sys, "platform", "win32")

        class _NoMlock:
            pass

        monkeypatch.setattr(pq, "_native_lib", _NoMlock())
        # _NoMlock doesn't have ama_secure_mlock — native probe fails,
        # POSIX fallback skipped on win32, result is False.
        assert sm._detect_mlock_available() is False

    def test_detect_mlock_no_libc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        monkeypatch.setattr(sys, "platform", "linux")

        class _NoMlock:
            pass

        monkeypatch.setattr(pq, "_native_lib", _NoMlock())
        monkeypatch.setattr(ctypes.util, "find_library", lambda _name: None)
        assert sm._detect_mlock_available() is False

    def test_detect_mlock_libc_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        monkeypatch.setattr(sys, "platform", "linux")

        class _NoMlock:
            pass

        monkeypatch.setattr(pq, "_native_lib", _NoMlock())
        monkeypatch.setattr(ctypes.util, "find_library", lambda _name: "libc")

        class _BadCDLL:
            def __init__(self, _path: str) -> None:
                raise OSError("probe denied")

        monkeypatch.setattr(ctypes, "CDLL", _BadCDLL)
        # OSError in libc probe → returns False (logs debug and falls
        # through).
        assert sm._detect_mlock_available() is False


class TestMlockNativeBranches:
    """Exercise the native secure_mlock / secure_munlock success/error paths."""

    def test_mlock_native_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        native = pq._native_lib
        if native is None or not hasattr(native, "ama_secure_mlock"):
            pytest.skip("Native mlock unavailable")

        class _FakeFn:
            argtypes: typing.ClassVar[list[Any]] = []
            restype = None

            def __call__(self, *args: object) -> int:
                return -1

        # Replace the symbol with a stub that returns non-zero rc.
        monkeypatch.setattr(native, "ama_secure_mlock", _FakeFn(), raising=False)
        with pytest.raises(sm.SecureMemoryError, match="mlock"):
            sm.secure_mlock(bytearray(32))

    def test_munlock_native_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ama_cryptography.pqc_backends as pq

        native = pq._native_lib
        if native is None or not hasattr(native, "ama_secure_munlock"):
            pytest.skip("Native munlock unavailable")

        class _FakeFn:
            argtypes: typing.ClassVar[list[Any]] = []
            restype = None

            def __call__(self, *args: object) -> int:
                return -1

        monkeypatch.setattr(native, "ama_secure_munlock", _FakeFn(), raising=False)
        with pytest.raises(sm.SecureMemoryError, match="munlock"):
            sm.secure_munlock(bytearray(32))
