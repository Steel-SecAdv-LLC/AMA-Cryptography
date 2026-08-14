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
import shutil
from pathlib import Path
from typing import Optional

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

    def test_build_pipeline_demotes_to_warning(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: False)
        lib = pb._try_load_library(tampered_so)
        # The tampered copy still parses as an ELF object, so the load itself
        # succeeds; the point is that the mismatch did not refuse it.
        assert lib is not None
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is not None

    def test_secure_execution_ignores_the_build_pipeline_carve_out(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AMA_BUILD_PIPELINE is an environment variable; in secure-execution
        mode environment variables must not relax a security decision."""
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        monkeypatch.setattr(pb, "_in_secure_execution_mode", lambda: True)
        errors_before = len(pb._LOAD_DIAGNOSTICS["errors"])
        assert pb._try_load_library(tampered_so) is None
        new_errors = pb._LOAD_DIAGNOSTICS["errors"][errors_before:]
        assert any("refused before mapping" in err for _p, err in new_errors), new_errors

    def test_verify_digest_false_records_but_never_refuses(
        self, tampered_so: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The override path: digest recorded for the POST stage, no block."""
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        lib = pb._try_load_library(tampered_so, verify_digest=False)
        assert lib is not None
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] is not None


@needs_native
class TestMatchingLoad:
    def test_genuine_library_loads_and_records_its_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        assert _REAL_SO is not None
        copy = tmp_path / _REAL_SO.name
        shutil.copyfile(_REAL_SO, copy)
        expected: Optional[bytes] = pb._expected_native_digest()
        if expected != hashlib.sha3_256(copy.read_bytes()).digest():
            pytest.skip("tree's artefact digest is stale relative to the built library")
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        lib = pb._try_load_library(copy)
        assert lib is not None
        assert pb._LOAD_DIAGNOSTICS["preload_digest_hex"] == expected.hex()

    def test_no_descriptor_leak(self, tmp_path: Path) -> None:
        """Every load attempt must close the descriptor it hashed from."""
        assert _REAL_SO is not None
        copy = tmp_path / _REAL_SO.name
        shutil.copyfile(_REAL_SO, copy)
        open_fds_before = (
            len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        )
        if open_fds_before is None:
            pytest.skip("no procfs on this platform")
        for _ in range(5):
            pb._try_load_library(copy)
        open_fds_after = len(os.listdir("/proc/self/fd"))
        assert open_fds_after <= open_fds_before + 1  # dlopen itself may cache one
