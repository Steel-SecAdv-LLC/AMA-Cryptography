#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Coverage closure for the AES-256-GCM counter persistence logic inside
``ama_cryptography.crypto_api.AESGCMProvider``.

The persistence code (``_get_persist_path``, ``_load_persisted_counters``,
``_persist_counters``) writes JSON with inter-process locking; these paths
previously had low coverage because the default test fixtures run with
``configure_ephemeral(True)`` to keep the suite hermetic.

These tests point the persistence path at a tmp-dir location, force the
non-ephemeral code paths, and verify:
    * counters persist across provider instantiations
    * corrupt files are detected and quarantined
    * merge-on-persist keeps the max of in-memory and on-disk counters
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ama_cryptography.crypto_api import AESGCMProvider
from ama_cryptography.pqc_backends import _AES_GCM_NATIVE_AVAILABLE, _native_lib


pytestmark = pytest.mark.skipif(
    _native_lib is None or not _AES_GCM_NATIVE_AVAILABLE,
    reason="AES-256-GCM native backend not built",
)


@pytest.fixture
def persist_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point AESGCMProvider at a throwaway directory for this test."""
    target = tmp_path / "aes_gcm_counters.json"
    # Save + restore module-level persistence state so concurrent tests stay
    # hermetic.
    saved = {
        "persist_path": AESGCMProvider._counters_persist_path,
        "ephemeral": AESGCMProvider._ephemeral,
        "loaded": AESGCMProvider._counters_loaded,
        "registered": AESGCMProvider._atexit_registered,
        "counters": dict(AESGCMProvider._encrypt_counters),
        "dirty": AESGCMProvider._counters_dirty,
    }

    AESGCMProvider._counters_persist_path = str(target)
    AESGCMProvider._ephemeral = False
    AESGCMProvider._counters_loaded = False
    AESGCMProvider._atexit_registered = False
    AESGCMProvider._encrypt_counters = {}
    AESGCMProvider._counters_dirty = 0

    try:
        yield target
    finally:
        AESGCMProvider._counters_persist_path = saved["persist_path"]
        AESGCMProvider._ephemeral = saved["ephemeral"]
        AESGCMProvider._counters_loaded = saved["loaded"]
        AESGCMProvider._atexit_registered = saved["registered"]
        AESGCMProvider._encrypt_counters = saved["counters"]
        AESGCMProvider._counters_dirty = saved["dirty"]


class TestPersistenceHappyPath:
    def test_persist_then_reload(self, persist_dir: Path) -> None:
        # Seed counters
        AESGCMProvider._encrypt_counters = {b"\x01" * 32: 42, b"\x02" * 32: 7}
        AESGCMProvider._persist_counters(_raising=True)

        assert persist_dir.exists()
        data = json.loads(persist_dir.read_text())
        assert data[("01" * 32)] == 42
        assert data[("02" * 32)] == 7

        # Clear in-memory and reload; counters should come back.
        AESGCMProvider._encrypt_counters = {}
        AESGCMProvider._load_persisted_counters()
        assert AESGCMProvider._encrypt_counters[b"\x01" * 32] == 42
        assert AESGCMProvider._encrypt_counters[b"\x02" * 32] == 7

    def test_persist_merges_max(self, persist_dir: Path) -> None:
        # Disk has higher count for key1; memory has higher for key2.
        persist_dir.write_text(json.dumps({"0a" * 32: 200, "0b" * 32: 3}))
        AESGCMProvider._encrypt_counters = {
            b"\x0a" * 32: 50,  # lower than disk
            b"\x0b" * 32: 99,  # higher than disk
        }
        AESGCMProvider._persist_counters(_raising=True)
        merged = json.loads(persist_dir.read_text())
        assert merged["0a" * 32] == 200  # keep disk max
        assert merged["0b" * 32] == 99  # keep in-memory max


class TestPersistenceErrorPaths:
    def test_load_bad_json_raises(self, persist_dir: Path) -> None:
        persist_dir.write_text("{ not valid json")
        AESGCMProvider._encrypt_counters = {}
        with pytest.raises(Exception):  # RuntimeError from legacy load
            AESGCMProvider._load_persisted_counters()

    def test_persist_raising_on_corrupt_file(self, persist_dir: Path) -> None:
        persist_dir.write_text("corrupt contents")
        AESGCMProvider._encrypt_counters = {b"\x01" * 32: 1}
        with pytest.raises(RuntimeError):
            AESGCMProvider._persist_counters(_raising=True)

    def test_persist_nonraising_on_corrupt_file(
        self, persist_dir: Path
    ) -> None:
        persist_dir.write_text("still corrupt")
        AESGCMProvider._encrypt_counters = {b"\x01" * 32: 1}
        # With _raising=False the corrupt file is renamed to .corrupt and
        # the fresh in-memory state is persisted.
        AESGCMProvider._persist_counters(_raising=False)
        assert (persist_dir.parent / (persist_dir.name + ".corrupt")).exists()
        assert json.loads(persist_dir.read_text())


class TestGetPersistPath:
    def test_get_persist_path_uses_override(self, persist_dir: Path) -> None:
        path = AESGCMProvider._get_persist_path()
        assert str(path) == str(persist_dir)

    def test_get_persist_path_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Clearing the override returns the default ~/.ama_cryptography path.
        saved = AESGCMProvider._counters_persist_path
        AESGCMProvider._counters_persist_path = None
        try:
            p = AESGCMProvider._get_persist_path()
            assert p.name == "aes_gcm_counters.json"
        finally:
            AESGCMProvider._counters_persist_path = saved
