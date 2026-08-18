#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Unit pins for the PRE-LOAD native-library digest verification.

A shared object executes its constructors the moment it is mapped, before any
power-on self-test can examine it — the "raw discovery" boundary the 2026-08
audit recorded.  ``_try_load_library`` now hashes every candidate *before*
``dlopen`` and, when the integrity artefact carries a native digest, refuses
to map a mismatching object at all; on Linux the mapping goes through
``/proc/self/fd`` on the very descriptor that was hashed, so the verified and
mapped bytes cannot be split by a path swap.  The end-to-end direction
(tampered ``.so`` fails the import with "refused before mapping", overrides
honoured) is pinned by ``tests/test_native_integrity.py``; these are the unit
pins for the pieces.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ama_cryptography import pqc_backends as pb
from tests.conftest import native_library_path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

_REAL_SO = native_library_path(PKG_DIR)

needs_native = pytest.mark.skipif(_REAL_SO is None, reason="native library not built in this tree")


class TestExpectedNativeDigest:
    def test_matches_the_artefact(self) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        expected = pb._expected_native_digest()
        if getattr(sig_mod, "INTEGRITY_NATIVE_DIGEST_HEX", None) is None:
            assert expected is None
        else:
            assert expected == bytes.fromhex(sig_mod.INTEGRITY_NATIVE_DIGEST_HEX)

    def test_malformed_hex_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        monkeypatch.setattr(sig_mod, "INTEGRITY_NATIVE_DIGEST_HEX", "not-hex", raising=False)
        assert pb._expected_native_digest() is None

    def test_wrong_length_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        monkeypatch.setattr(sig_mod, "INTEGRITY_NATIVE_DIGEST_HEX", "ab" * 16, raising=False)
        assert pb._expected_native_digest() is None


class TestDigestFd:
    def test_agrees_with_hashlib(self, tmp_path: Path) -> None:
        import hashlib

        payload = os.urandom(3_000_000)  # spans multiple 1 MiB chunks
        target = tmp_path / "blob"
        target.write_bytes(payload)
        # O_BINARY: on Windows a bare os.open defaults to text mode, which
        # translates CRLF and truncates at 0x1A — corrupting binary reads.
        fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            assert pb._digest_fd(fd) == hashlib.sha3_256(payload).digest()
        finally:
            os.close(fd)


@needs_native
class TestPreloadRefusal:
    """Refusal must happen before mapping, and the carve-outs must hold."""

    @pytest.fixture()
    def tampered_so(self, tmp_path: Path) -> Path:
        assert _REAL_SO is not None
        copy = tmp_path / _REAL_SO.name
        blob = bytearray(_REAL_SO.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        copy.write_bytes(bytes(blob))
        return copy

    def test_mismatch_is_refused_without_mapping(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        errors_before = len(pb._LOAD_DIAGNOSTICS["errors"])
        lib = pb._try_load_library(tampered_so)
        assert lib is None
        new_errors = pb._LOAD_DIAGNOSTICS["errors"][errors_before:]
        assert any("refused before mapping" in err for _p, err in new_errors), new_errors
        # Refused means never attributed a mapped digest.
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is None

    def test_unreadable_candidate_is_refused_not_loaded_unverified(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bytes that cannot be read cannot be verified — with a signed digest
        present, a read failure is a refusal, on every platform.  (The first
        draft applied this only on POSIX; on Windows a read error silently
        skipped the check and the DLL loaded unverified.)"""
        import platform

        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)

        def _refuse_read(*_args: object, **_kwargs: object) -> bytes:
            raise OSError("simulated unreadable candidate")

        # Break the digest read on the branch this platform actually takes.
        if platform.system() == "Windows":
            monkeypatch.setattr(Path, "read_bytes", _refuse_read)
        else:
            monkeypatch.setattr(pb, "_digest_fd", _refuse_read)
        errors_before = len(pb._LOAD_DIAGNOSTICS["errors"])
        assert pb._try_load_library(tampered_so) is None
        new_errors = pb._LOAD_DIAGNOSTICS["errors"][errors_before:]
        assert any("pre-load digest read failed" in err for _p, err in new_errors), new_errors
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is None

    def test_the_build_pipeline_environment_variable_no_longer_relaxes_this(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``AMA_BUILD_PIPELINE=1`` used to map a mismatching object anyway.

        ``os.environ`` is read on EVERY import, so that made the refusal
        defeatable by anyone who could set one variable in the target process —
        no code execution required, which is less than this check was ever
        defending against.  The build pipeline's real need is served by
        :func:`pb.unverified_load_for_signing`, an in-process opt-in the
        signing tool enters around its own discovery call.
        """
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: False)
        errors_before = len(pb._LOAD_DIAGNOSTICS["errors"])
        assert (
            pb._try_load_library(tampered_so) is None
        ), "an environment variable must not buy a mapping of unverified bytes"
        new_errors = pb._LOAD_DIAGNOSTICS["errors"][errors_before:]
        assert any("refused before mapping" in err for _p, err in new_errors), new_errors
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is None

    def test_the_signing_override_permits_the_mapping(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Re-signing must be able to map the library it is about to bless.

        The signature is produced by the in-tree Ed25519 kernel (INVARIANT-1
        forbids a PyCA dependency), so the object has to be mapped — and it is
        by definition the one whose digest does not match the artefact yet.
        """
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: False)
        with pb.unverified_load_for_signing():
            lib = pb._try_load_library(tampered_so)
        # The tampered copy still parses as an ELF object, so the load itself
        # succeeds; the point is that the mismatch did not refuse it.
        assert lib is not None
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is not None

    def test_the_signing_override_is_scoped_to_its_block(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scope is the whole security argument; exiting must restore refusal."""
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: False)
        assert pb._SIGNING_LOAD_OVERRIDE is False
        with pb.unverified_load_for_signing():
            assert pb._SIGNING_LOAD_OVERRIDE is True
            # Nesting must not clear the outer entry on the inner exit.
            with pb.unverified_load_for_signing():
                assert pb._SIGNING_LOAD_OVERRIDE is True
            assert pb._SIGNING_LOAD_OVERRIDE is True
        assert pb._SIGNING_LOAD_OVERRIDE is False
        assert pb._try_load_library(tampered_so) is None

    def test_the_signing_override_is_restored_after_an_exception(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: False)

        # Raise through a helper rather than a bare ``raise`` in the ``with``
        # body: CodeQL's py/unreachable-statement does not model
        # ``pytest.raises`` swallowing the exception, so a literal ``raise``
        # marks every following assert unreachable (alert 620 — same false
        # positive, and same source-level resolution, as the ``_explode()``
        # pattern in tests/test_c_buffer_views.py).
        def _explode() -> None:
            raise RuntimeError("signing blew up")

        with pytest.raises(RuntimeError, match="signing blew up"):
            with pb.unverified_load_for_signing():
                _explode()
        assert pb._SIGNING_LOAD_OVERRIDE is False
        assert pb._try_load_library(tampered_so) is None

    def test_secure_execution_revokes_the_signing_override(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A set-uid process must not be talked into mapping unverified bytes.

        Not by an environment variable, and not by the in-process override
        either — the dynamic loader drops LD_PRELOAD under set-uid for the same
        reason, and an override of our own must honour the same rule.
        """
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: True)
        errors_before = len(pb._LOAD_DIAGNOSTICS["errors"])
        with pb.unverified_load_for_signing():
            assert pb._try_load_library(tampered_so) is None
        new_errors = pb._LOAD_DIAGNOSTICS["errors"][errors_before:]
        assert any("refused before mapping" in err for _p, err in new_errors), new_errors

    def test_a_refusal_is_recorded_structurally_not_only_in_prose(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``__init__`` classifies on this, so it must not be a substring test.

        A native-backend failure caused solely by digest refusal is the one
        such failure a re-signing run may complete the import through; anything
        else is a broken build.
        """
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        pb._LOAD_DIAGNOSTICS["digest_refused"] = []
        pb._LOAD_DIAGNOSTICS["errors"] = []
        assert pb._try_load_library(tampered_so) is None
        assert str(tampered_so) in pb._LOAD_DIAGNOSTICS["digest_refused"]

    def test_refused_on_digest_is_false_for_a_loader_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A load failure that is NOT a digest refusal must not be excused.

        Note what this layer can and cannot distinguish.  The digest check runs
        BEFORE dlopen, so any object whose bytes do not match the signed digest
        is a pre-load refusal — a merely-stale library and a corrupt one are
        the same event here, and both are treated as repairable, which is
        correct: the remedy for each is to rebuild and re-sign.  What must stay
        unexcused is a failure the digest check never reached: a loader error
        or an ABI rejection.  Those are reachable when no signed digest exists
        to check against, and they are what "broken build" means.
        """
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(pb, "_native_lib", None, raising=False)
        monkeypatch.setattr(pb, "_expected_native_digest", lambda: None)
        pb._LOAD_DIAGNOSTICS["digest_refused"] = []
        pb._LOAD_DIAGNOSTICS["errors"] = []
        pb._LOAD_DIAGNOSTICS["abi_rejection"] = None

        assert pb.native_backend_refused_on_digest() is False, "no refusal recorded"

        # Force the loader to reject the candidate. Writing junk bytes is not
        # enough to guarantee this: dlopen deduplicates by resolved path and a
        # real library of the same name is already mapped in this process, so
        # the failure has to be injected at the ctypes boundary to be certain
        # which path the test is exercising.
        import ctypes as _ctypes

        def _refuse(*_a: object, **_k: object) -> object:
            raise OSError("simulated loader rejection: wrong ELF class")

        monkeypatch.setattr(_ctypes, "CDLL", _refuse)
        candidate = tmp_path / "libama_cryptography.so"
        candidate.write_bytes(b"not an ELF object" * 64)
        assert pb._try_load_library(candidate) is None
        assert pb._LOAD_DIAGNOSTICS["errors"], "the loader error was not recorded"
        assert pb._LOAD_DIAGNOSTICS["digest_refused"] == []
        assert pb.native_backend_refused_on_digest() is False

    def test_refused_on_digest_requires_every_failure_to_be_a_refusal(
        self, tampered_so: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One stale library plus one unloadable one is a broken build."""
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(pb, "_native_lib", None, raising=False)
        pb._LOAD_DIAGNOSTICS["digest_refused"] = []
        pb._LOAD_DIAGNOSTICS["errors"] = []
        pb._LOAD_DIAGNOSTICS["abi_rejection"] = None

        assert pb._try_load_library(tampered_so) is None
        assert pb.native_backend_refused_on_digest() is True

        # A second candidate that gets past the digest check and then fails to
        # map: the mixture is no longer purely repairable.
        import ctypes as _ctypes

        def _refuse(*_a: object, **_k: object) -> object:
            raise OSError("simulated loader rejection: missing NEEDED")

        monkeypatch.setattr(pb, "_expected_native_digest", lambda: None)
        monkeypatch.setattr(_ctypes, "CDLL", _refuse)
        other = tmp_path / ("other-" + tampered_so.name)
        other.write_bytes(b"not an ELF object" * 64)
        assert pb._try_load_library(other) is None
        assert pb.native_backend_refused_on_digest() is False

    def test_an_abi_rejection_is_never_excused(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A library of the wrong major version is a broken build, not a stale one."""
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(pb, "_native_lib", None, raising=False)
        pb._LOAD_DIAGNOSTICS["digest_refused"] = []
        pb._LOAD_DIAGNOSTICS["errors"] = []
        pb._LOAD_DIAGNOSTICS["abi_rejection"] = None

        assert pb._try_load_library(tampered_so) is None
        assert pb.native_backend_refused_on_digest() is True
        pb._LOAD_DIAGNOSTICS["abi_rejection"] = "reports major 3, this build needs 5"
        assert pb.native_backend_refused_on_digest() is False
        pb._LOAD_DIAGNOSTICS["abi_rejection"] = None

    def test_a_loaded_backend_is_never_reported_as_refused(self) -> None:
        """The predicate describes an ABSENT backend; a present one is not it."""
        if pb._native_lib is None:
            pytest.skip("no native backend loaded in this process")
        assert pb.native_backend_refused_on_digest() is False


class TestARejectedLibraryLeavesNoDigestBehind:
    """The ABI reject branch must disown the object completely.

    The handshake runs once, at module scope, so the branch cannot be reached
    twice in one process — which is exactly why the state-clearing lives in
    :func:`pb._disown_rejected_native_library` and is pinned here directly.

    The defect this pins: the branch cleared ``_native_lib``, the path and the
    override but left ``_NATIVE_LIB_PRELOAD_DIGEST_HEX`` holding the digest of
    the object it had just refused.  ``native_backend_diagnostics()`` then
    published a record that said "nothing is loaded, there is no path, there is
    no override" while still carrying a digest, and the POST integrity stage
    PREFERS that digest over re-reading the path: it took the "I can see the
    executing bytes" branch and reported the rejection as a digest MISMATCH —
    "libama_cryptography has been modified since signing" — recording a stale
    binding, the one fault a re-signing run is meant to clear.  Re-signing a
    wrong-ABI library is the wrong remedy; rebuilding it is.
    """

    _SCRATCH_KEYS = ("errors", "abi_rejection", "loaded", "path", "preload_digest_hex")

    @pytest.fixture()
    def restore_diagnostics(self) -> object:
        """Save and restore the shared scratch record this branch writes to."""
        saved = {key: pb._LOAD_DIAGNOSTICS[key] for key in self._SCRATCH_KEYS}
        saved["errors"] = list(saved["errors"])
        yield
        pb._LOAD_DIAGNOSTICS.update(saved)

    def test_the_preload_digest_is_cleared_with_everything_else(
        self, restore_diagnostics: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sentinel = object()
        monkeypatch.setattr(pb, "_native_lib", sentinel, raising=False)
        monkeypatch.setattr(pb, "_NATIVE_LIB_PATH", "/opt/wrong/libama_cryptography.so")
        monkeypatch.setattr(pb, "_NATIVE_LIB_VIA_OVERRIDE", "/opt/wrong/libama_cryptography.so")
        monkeypatch.setattr(pb, "_NATIVE_LIB_PRELOAD_DIGEST_HEX", "ab" * 32)
        pb._LOAD_DIAGNOSTICS["preload_digest_hex"] = "ab" * 32
        pb._LOAD_DIAGNOSTICS["errors"] = []

        pb._disown_rejected_native_library("reports 4.9.9, this package requires major version 5")

        # Nothing in the module still describes a loaded library.
        assert pb._native_lib is None
        assert pb._NATIVE_LIB_PATH is None
        assert pb._NATIVE_LIB_VIA_OVERRIDE is None
        assert pb._NATIVE_LIB_PRELOAD_DIGEST_HEX is None
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is None
        # The reason survives, durably, so POST can still explain itself.
        assert "4.9.9" in pb._LOAD_DIAGNOSTICS["abi_rejection"]
        assert pb._LOAD_DIAGNOSTICS["errors"], "the rejection was not recorded per-candidate"

    def test_the_published_diagnostics_record_is_self_consistent(
        self, restore_diagnostics: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No loaded library means no digest — the record cannot claim both."""
        monkeypatch.setattr(pb, "_native_lib", object(), raising=False)
        monkeypatch.setattr(pb, "_NATIVE_LIB_PATH", "/opt/wrong/libama_cryptography.so")
        monkeypatch.setattr(pb, "_NATIVE_LIB_PRELOAD_DIGEST_HEX", "cd" * 32)
        pb._LOAD_DIAGNOSTICS["errors"] = []

        pb._disown_rejected_native_library("wrong major version")

        diag = pb.native_backend_diagnostics()
        assert diag["loaded"] is False
        assert diag["path"] is None
        assert diag["override"] is None
        assert diag["preload_digest_hex"] is None, (
            "a record that reports no loaded library must not carry the digest "
            "of the object that was refused"
        )

    def test_a_rejection_never_reads_as_tampering(
        self, restore_diagnostics: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The POST integrity stage must not call an ABI reject a MISMATCH.

        This is the downstream consequence the cleared digest exists to
        prevent, asserted against the real stage rather than by inspection.
        """
        from ama_cryptography import _self_test

        monkeypatch.setattr(pb, "_native_lib", object(), raising=False)
        monkeypatch.setattr(pb, "_NATIVE_LIB_PATH", "/opt/wrong/libama_cryptography.so")
        monkeypatch.setattr(pb, "_NATIVE_LIB_PRELOAD_DIGEST_HEX", "ef" * 32)
        pb._LOAD_DIAGNOSTICS["errors"] = []

        pb._disown_rejected_native_library("wrong major version")

        signed_digest = bytes.fromhex("11" * 32)
        verdict, note, native_ok = _self_test._check_loaded_native_library(
            signed_digest, anchored=True
        )
        assert native_ok is False
        assert "MISMATCH" not in note, note
        assert "modified since signing" not in note, note
        # Absent bytes are unverifiable, and on an anchored build that is fatal.
        assert verdict is False
        assert "UNVERIFIABLE" in note, note


class TestSigningScopeRequiresIntentNotJustIdentity:
    """The environment variable must never be sufficient on its own.

    ``_process_is_the_integrity_signer`` keys on process identity, but
    ``ama_cryptography.integrity`` is a mixed CLI whose ``--verify`` and
    ``--show`` subcommands are the documented way to CHECK an installation
    and write nothing.  While identity alone answered, any process launched
    as that module inherited the pre-load digest escape — so in an
    environment carrying ``AMA_BUILD_PIPELINE=1`` (a Dockerfile ``ENV``, a CI
    runner, a systemd unit) the documented verify command would map a
    shared object that had just failed its digest check, running its ELF
    constructors before printing a verdict.  No attacker code and no control
    of the command line was required, which is the fail-open class this
    check exists to end.

    The combination below — the flag set AND a signer-module argv — is the
    one the earlier suite never drove: its coverage ran under pytest, where
    ``sys.orig_argv`` names pytest, so the identity half was always False and
    the assertion "the variable no longer relaxes this" held for the wrong
    reason.
    """

    @staticmethod
    def _scope(monkeypatch: pytest.MonkeyPatch, *, flag: bool, argv: list[str]) -> bool:
        if flag:
            monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        else:
            monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        monkeypatch.setattr(sys, "orig_argv", argv, raising=False)
        return pb._process_is_the_integrity_signer()

    @pytest.mark.parametrize("subcommand", ["--verify", "--show"])
    def test_read_only_integrity_subcommands_get_no_signing_scope(
        self, monkeypatch: pytest.MonkeyPatch, subcommand: str
    ) -> None:
        assert not self._scope(
            monkeypatch,
            flag=True,
            argv=["python", "-m", "ama_cryptography.integrity", subcommand],
        )

    @pytest.mark.parametrize("argv_tail", [["--update"], ["--update", "--sign"]])
    def test_the_writing_subcommand_keeps_signing_scope(
        self, monkeypatch: pytest.MonkeyPatch, argv_tail: list[str]
    ) -> None:
        """The documented re-signing flow must still work — this is the point."""
        assert self._scope(
            monkeypatch,
            flag=True,
            argv=["python", "-m", "ama_cryptography.integrity", *argv_tail],
        )

    def test_the_joined_dash_m_spelling_is_read_the_same_way(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self._scope(
            monkeypatch, flag=True, argv=["python", "-mama_cryptography.integrity", "--update"]
        )
        assert not self._scope(
            monkeypatch, flag=True, argv=["python", "-mama_cryptography.integrity", "--verify"]
        )

    def test_build_sign_needs_no_subcommand_because_it_only_signs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``_build_sign`` has no read-only mode, so identity is the whole test.

        The release path depends on this: ``tools/resign_wheel.py`` launches
        it with no ``--update``, during the parent import where POST runs.
        """
        assert self._scope(
            monkeypatch, flag=True, argv=["python", "-m", "ama_cryptography._build_sign"]
        )

    def test_the_flag_alone_is_never_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An ordinary program in a build-pipeline environment gets nothing."""
        assert not self._scope(monkeypatch, flag=True, argv=["python", "app.py", "--update"])
        assert not self._scope(monkeypatch, flag=True, argv=["python", "-c", "import x"])

    def test_signing_intent_alone_is_never_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without the flag, even the real signing command has no scope."""
        assert not self._scope(
            monkeypatch,
            flag=False,
            argv=["python", "-m", "ama_cryptography.integrity", "--update", "--sign"],
        )

    def test_a_mixed_mode_module_named_in_main_spec_also_needs_intent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``__main__.__spec__`` window carries the same requirement.

        Once runpy binds the target into ``__main__`` the spec answers, so
        gating only the argv window would leave the identical hole open for
        the rest of the process's life.
        """
        import types

        main_module = types.ModuleType("__main__")
        # monkeypatch.setattr rather than a direct assignment: ModuleType
        # types __spec__ as ModuleSpec | None, and a real ModuleSpec cannot be
        # built for a module that was never loaded from a finder — so a plain
        # assignment needs a type suppression this repository would then have
        # to justify (INVARIANT-13).  Going through monkeypatch also restores
        # the attribute at teardown.
        monkeypatch.setattr(
            main_module, "__spec__", types.SimpleNamespace(name="ama_cryptography.integrity")
        )
        monkeypatch.setitem(sys.modules, "__main__", main_module)
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")

        monkeypatch.setattr(
            sys, "orig_argv", ["python", "-m", "ama_cryptography.integrity", "--verify"]
        )
        assert not pb._process_is_the_integrity_signer()

        monkeypatch.setattr(
            sys, "orig_argv", ["python", "-m", "ama_cryptography.integrity", "--update"]
        )
        assert pb._process_is_the_integrity_signer()
