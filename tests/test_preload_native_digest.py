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
