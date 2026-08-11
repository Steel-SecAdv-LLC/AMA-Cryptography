# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``AMA_CRYPTO_LIB_PATH`` must not steer the backend under set-uid/set-gid.

The variable names the shared object that supplies every cryptographic
primitive, and a shared object runs its constructors the moment it is mapped —
before the power-on self-test can execute, and without being covered by the
module-integrity digest (which hashes ``.py`` files only).

The dynamic loader refuses to honour ``LD_PRELOAD``/``LD_LIBRARY_PATH`` in
secure-execution mode precisely so a less-privileged caller cannot choose the
code a privileged process loads.  An override of our own has to follow the same
rule, otherwise it re-opens the hole the platform just closed.
"""

import ctypes
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

import pytest

from ama_cryptography import pqc_backends


class TestSecureExecutionDetection:
    def test_reports_false_when_uid_matches_euid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is False

    def test_reports_true_for_setuid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_reports_true_for_setgid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 0, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True


def _auxv_blob(entries: list[tuple[int, int]]) -> bytes:
    """Serialise ``(type, value)`` pairs the way the kernel lays out auxv."""
    word = ctypes.sizeof(ctypes.c_void_p)
    out = bytearray()
    for key, value in entries:
        out += key.to_bytes(word, sys.byteorder)
        out += value.to_bytes(word, sys.byteorder)
    out += (0).to_bytes(word, sys.byteorder) * 2  # AT_NULL terminator
    return bytes(out)


class TestAtSecureIsConsulted:
    """``AT_SECURE`` covers privilege the uid/gid comparison cannot see.

    A binary carrying file capabilities (``setcap cap_net_bind_service=+ep``)
    executes with ``uid == euid`` and ``gid == egid``, so every comparison in
    the class above answers "not privileged" — while the kernel sets
    ``AT_SECURE=1`` and the dynamic loader duly ignores ``LD_PRELOAD``.  Left
    on the uid check alone, this module would have honoured
    ``AMA_CRYPTO_LIB_PATH`` in exactly the configuration the loader refuses to
    honour its own equivalents, which is the case this class pins.
    """

    def test_parses_at_secure_set(self, tmp_path: Path) -> None:
        blob = tmp_path / "auxv-secure"
        blob.write_bytes(_auxv_blob([(6, 4096), (23, 1), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is True

    def test_parses_at_secure_clear(self, tmp_path: Path) -> None:
        blob = tmp_path / "auxv-plain"
        blob.write_bytes(_auxv_blob([(6, 4096), (23, 0), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is False

    def test_absent_at_secure_reads_as_unknown_not_as_safe(self, tmp_path: Path) -> None:
        """A vector with no AT_SECURE entry must return None, not False.

        None routes the caller to the uid/gid fallback.  Returning False would
        assert "not privileged" on the strength of an entry that was never
        there, which is the fail-open direction.
        """
        blob = tmp_path / "auxv-no-secure"
        blob.write_bytes(_auxv_blob([(6, 4096), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is None

    def test_unreadable_auxv_reads_as_unknown(self, tmp_path: Path) -> None:
        assert pqc_backends._auxv_at_secure(str(tmp_path / "does-not-exist")) is None

    def test_at_secure_wins_when_uid_comparison_sees_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The file-capabilities case: privileged, but uid == euid."""
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: True)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_uid_comparison_still_applies_when_auxv_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Masked procfs must not disable the check that does not need it."""
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    @pytest.mark.skipif(not Path("/proc/self/auxv").exists(), reason="no procfs auxiliary vector")
    def test_agrees_with_the_running_kernel(self) -> None:
        """Non-vacuity: the parser must read the real vector, not just fixtures.

        pytest is not privileged, so the expected answer is False.  A parser
        that returned None here — a wrong word size, a mis-stepped stride —
        would silently fall back to the uid check forever and every fixture
        above would still pass.
        """
        assert pqc_backends._auxv_at_secure() is False


class TestLibcProbesArePreferred:
    """``AT_SECURE`` is asked of libc first, and ``/proc`` only as a fallback.

    Reading ``/proc/self/auxv`` works, but it is the least robust of the three
    kernel-side signals: a hardened container can mask procfs, and a
    bind-mount can replace it.  ``getauxval(3)`` needs no file descriptor and
    cannot be masked; ``issetugid(2)`` is the platform's own answer to exactly
    this question on macOS, the BSDs and Solaris, where there is no auxiliary
    vector to read at all.  Both are resolved through ``dlopen(NULL)`` rather
    than a named libc, so no SONAME is guessed.
    """

    def test_the_kernel_side_signals_match_what_the_platform_can_offer(self) -> None:
        """Non-vacuity for the whole class, stated per platform.

        The first version of this asserted "at least one signal answers" and
        went red on all four Windows lanes — correctly. Windows has no
        ``issetugid``, no ``getauxval`` and no auxiliary vector, so all three
        probes return ``None`` there, which is the documented and desired
        answer, not a defect. Asserting a POSIX property unconditionally made
        a passing platform look broken.

        Both halves are worth pinning, so the expectation is split rather than
        skipped:

        * On POSIX, at least one kernel-side signal **must** answer. Every one
          returning ``None`` would mean the uid/gid comparison is the only
          thing running — the state this work exists to move away from — while
          every fixture below still passed.
        * Off POSIX, all three **must** return ``None`` and
          ``_in_secure_execution_mode()`` must be ``False``. That is the
          "returns False by exhaustion" contract from its docstring, and a
          probe that started guessing on Windows would break it.
        """
        answers = [
            pqc_backends._libc_issetugid(),
            pqc_backends._libc_getauxval_at_secure(),
            pqc_backends._auxv_at_secure(),
        ]
        if os.name == "posix":
            assert any(answer is not None for answer in answers), answers
        else:
            assert answers == [None, None, None], answers
            assert pqc_backends._in_secure_execution_mode() is False

    def test_probes_return_a_bool_or_none_and_nothing_else(self) -> None:
        for probe in (
            pqc_backends._libc_issetugid,
            pqc_backends._libc_getauxval_at_secure,
            pqc_backends._auxv_at_secure,
        ):
            assert probe() in (True, False, None)

    @pytest.mark.skipif(not Path("/proc/self/auxv").exists(), reason="no procfs auxiliary vector")
    def test_getauxval_agrees_with_the_parsed_vector(self) -> None:
        """The two Linux signals must not disagree about the same flag.

        If ``getauxval`` is unavailable this is vacuous, so it is skipped
        rather than passed — a silently-absent probe is the failure mode this
        test is here to notice.
        """
        via_libc = pqc_backends._libc_getauxval_at_secure()
        if via_libc is None:
            pytest.skip("getauxval(3) is not available in this libc")
        assert via_libc == pqc_backends._auxv_at_secure()

    def test_issetugid_wins_where_it_is_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The BSD/macOS case: no auxiliary vector, and uid == euid."""
        monkeypatch.setattr(pqc_backends, "_libc_issetugid", lambda: True)
        monkeypatch.setattr(pqc_backends, "_libc_getauxval_at_secure", lambda: None)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_getauxval_wins_where_procfs_is_masked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pqc_backends, "_libc_issetugid", lambda: None)
        monkeypatch.setattr(pqc_backends, "_libc_getauxval_at_secure", lambda: True)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_a_false_from_one_probe_does_not_veto_a_later_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The OR is the contract, and this is the case that proves it.

        A first-non-None-answer-wins design would return False here.  Each
        signal sees a different subset of privileged execution, so only a
        signal that says *True* is allowed to end the search.
        """
        monkeypatch.setattr(pqc_backends, "_libc_issetugid", lambda: False)
        monkeypatch.setattr(pqc_backends, "_libc_getauxval_at_secure", lambda: False)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: True)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_all_probes_unavailable_falls_through_to_the_uid_comparison(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pqc_backends, "_libc_issetugid", lambda: None)
        monkeypatch.setattr(pqc_backends, "_libc_getauxval_at_secure", lambda: None)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_nothing_available_at_all_reports_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The Windows shape: no probe exists, so the concept has no referent.

        The documented answer is False — the override stays available — and
        this pins that the function does not instead fail closed on ignorance.
        """

        def _no_uid() -> int:
            raise AttributeError("os.getuid does not exist on this platform")

        monkeypatch.setattr(pqc_backends, "_libc_issetugid", lambda: None)
        monkeypatch.setattr(pqc_backends, "_libc_getauxval_at_secure", lambda: None)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", _no_uid, raising=False)

        assert pqc_backends._in_secure_execution_mode() is False

    def test_missing_symbols_read_as_unknown_not_as_unprivileged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A libc without either symbol must yield None, never False."""

        class _NoSymbols:
            def __getattr__(self, name: str) -> Any:
                raise AttributeError(name)

        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: _NoSymbols())
        assert pqc_backends._libc_issetugid() is None
        assert pqc_backends._libc_getauxval_at_secure() is None

    def test_no_libc_handle_reads_as_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: None)
        assert pqc_backends._libc_issetugid() is None
        assert pqc_backends._libc_getauxval_at_secure() is None

    def test_getauxval_reporting_enoent_reads_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``0`` with ``ENOENT`` means "not in the vector", not "not secure".

        Collapsing the two would assert that the process is unprivileged on
        the strength of an entry that was never there.
        """
        import errno

        class _Fn:
            restype: Any = None
            argtypes: Any = None

            def __call__(self, _type: Any) -> int:
                ctypes.set_errno(errno.ENOENT)
                return 0

        class _Libc:
            getauxval = _Fn()

        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: _Libc())
        assert pqc_backends._libc_getauxval_at_secure() is None

    def test_getauxval_reporting_zero_without_errno_reads_as_unprivileged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Fn:
            restype: Any = None
            argtypes: Any = None

            def __call__(self, _type: Any) -> int:
                return 0

        class _Libc:
            getauxval = _Fn()

        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: _Libc())
        assert pqc_backends._libc_getauxval_at_secure() is False

    def test_getauxval_reporting_one_reads_as_privileged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Fn:
            restype: Any = None
            argtypes: Any = None

            def __call__(self, _type: Any) -> int:
                return 1

        class _Libc:
            getauxval = _Fn()

        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: _Libc())
        assert pqc_backends._libc_getauxval_at_secure() is True

    def test_issetugid_nonzero_reads_as_privileged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Fn:
            restype: Any = None
            argtypes: Any = None

            def __call__(self) -> int:
                return 1

        class _Libc:
            issetugid = _Fn()

        monkeypatch.setattr(pqc_backends, "_process_libc", lambda: _Libc())
        assert pqc_backends._libc_issetugid() is True


class TestOverrideIgnoredUnderSecureExecution:
    def test_override_file_is_not_loaded_when_setuid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        tmp_path: Path,
    ) -> None:
        """The planted library must never be opened in secure-execution mode."""
        planted = tmp_path / "libama_cryptography.so"
        planted.write_bytes(b"")
        monkeypatch.setenv("AMA_CRYPTO_LIB_PATH", str(planted))
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: True)
        monkeypatch.setattr(pqc_backends, "_get_search_dirs", list)

        attempted: list[Path] = []

        def _record(path: Path) -> Optional[Any]:
            attempted.append(path)
            return None

        monkeypatch.setattr(pqc_backends, "_try_load_library", _record)

        with caplog.at_level(logging.WARNING):
            result = pqc_backends._find_native_library()

        assert result is None
        assert attempted == [], "override was loaded despite secure-execution mode"
        assert any("secure-execution mode" in r.message for r in caplog.records)

    def test_override_is_honoured_and_logged_when_not_setuid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        tmp_path: Path,
    ) -> None:
        """Outside secure-execution the override still works, but it is visible."""
        planted = tmp_path / "libama_cryptography.so"
        planted.write_bytes(b"")

        sentinel = object()
        monkeypatch.setenv("AMA_CRYPTO_LIB_PATH", str(planted))
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: False)
        monkeypatch.setattr(pqc_backends, "_get_search_dirs", list)
        monkeypatch.setattr(pqc_backends, "_try_load_library", lambda path: sentinel)

        with caplog.at_level(logging.WARNING):
            result = pqc_backends._find_native_library()

        assert result is sentinel
        assert any(
            "AMA_CRYPTO_LIB_PATH" in r.message for r in caplog.records
        ), "an overridden cryptographic backend must be visible in the logs"


class TestLibraryPathEnvIgnoredUnderSecureExecution:
    """LD_LIBRARY_PATH / DYLD_LIBRARY_PATH steer backend selection like the
    override does, and must obey the same secure-execution rule the dynamic
    loader applies — reading them with os.getenv bypasses the loader's own
    stripping on a set-uid/set-gid or file-capability binary."""

    def test_ld_library_path_excluded_when_setuid(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: True)
        monkeypatch.setenv("LD_LIBRARY_PATH", "/attacker/controlled")
        monkeypatch.setenv("DYLD_LIBRARY_PATH", "/attacker/dyld")

        with caplog.at_level(logging.WARNING):
            dirs = [str(d) for d in pqc_backends._get_search_dirs()]

        assert "/attacker/controlled" not in dirs
        assert "/attacker/dyld" not in dirs
        assert any(
            "LD_LIBRARY_PATH" in r.message and "secure-execution" in r.message
            for r in caplog.records
        ), "suppression of a caller-controlled search path must be logged"

    def test_ld_library_path_honoured_when_not_setuid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: False)
        monkeypatch.setenv("LD_LIBRARY_PATH", "/dev/build/lib")

        dirs = [str(d) for d in pqc_backends._get_search_dirs()]
        assert "/dev/build/lib" in dirs, (
            "outside secure-execution the developer's LD_LIBRARY_PATH is a "
            "legitimate way to point at an out-of-tree build"
        )


class TestPartialPopulationVisibility:
    """A library that provides some primitives and not others must not present
    as a clean load — the mixed state has to be aggregated and reachable."""

    def test_diagnostics_exposes_missing_families(self) -> None:
        diag = pqc_backends.native_backend_diagnostics()
        assert "missing_families" in diag
        assert isinstance(diag["missing_families"], list)

    def test_full_build_reports_no_missing_families(self) -> None:
        if pqc_backends._native_lib is None:
            pytest.skip("native library not built in this tree")
        # A complete build — the one this test suite runs against — must not
        # report any family as missing, or the aggregation is miscounting.
        assert pqc_backends.native_backend_diagnostics()["missing_families"] == []

    def test_diagnostics_snapshot_is_a_copy(self) -> None:
        snap = pqc_backends.native_backend_diagnostics()
        snap["missing_families"].append("INJECTED")
        assert "INJECTED" not in pqc_backends._LOAD_DIAGNOSTICS["missing_families"]
