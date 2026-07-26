#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Regression coverage for the ``SecureKeyStorage`` hardening fixes.

Pins three defects closed in the repository-refinement pass so they cannot
silently regress:

* **Crash-safe ``migrate_kdf``** — an interrupted KDF migration must not leave
  any key encrypted under a key the persisted salt can no longer reproduce
  (previously: guaranteed key loss on *any* mid-migration failure, and the
  in-memory salt was never rolled back).
* **``key_id`` path-traversal guard** — ``retrieve_key``/``delete_key`` must
  reject the same non-alphanumeric ids ``store_key`` rejects, so a crafted id
  cannot escape ``storage_path``.
* **Restrictive, race-free file permissions** — the key store is ``0o700`` and
  key/salt files are ``0o600`` with no world-readable window.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Optional

import pytest

from ama_cryptography.key_management import SecureKeyStorage, _atomic_write_bytes

PASSWORD = "correct horse battery staple 123!"
_KEYS = {"alpha": b"A" * 32, "beta": b"B" * 32, "gamma": b"C" * 32}


def _make_store(path: Path) -> SecureKeyStorage:
    store = SecureKeyStorage(path, PASSWORD)
    for key_id, material in _KEYS.items():
        store.store_key(key_id, material, {"label": key_id})
    return store


class TestKeyIdTraversalGuard:
    def test_store_rejects_traversal(self, tmp_path: Path) -> None:
        store = SecureKeyStorage(tmp_path, PASSWORD)
        with pytest.raises(ValueError):
            store.store_key("../evil", b"x" * 32)

    def test_retrieve_rejects_traversal(self, tmp_path: Path) -> None:
        store = SecureKeyStorage(tmp_path, PASSWORD)
        with pytest.raises(ValueError):
            store.retrieve_key("../../etc/passwd")

    def test_delete_rejects_traversal_and_does_not_touch_outside_file(self, tmp_path: Path) -> None:
        store = SecureKeyStorage(tmp_path / "store", PASSWORD)
        victim = tmp_path / "victim.json"
        victim.write_text('{"do": "not touch"}')
        with pytest.raises(ValueError):
            store.delete_key("../victim")
        assert victim.exists()
        assert victim.read_text() == '{"do": "not touch"}'

    def test_valid_ids_still_work(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert store.retrieve_key("alpha") == _KEYS["alpha"]
        assert store.retrieve_key("does-not-exist") is None
        assert store.delete_key("does-not-exist") is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
class TestFilePermissions:
    def test_store_dir_is_0700(self, tmp_path: Path) -> None:
        store_dir = tmp_path / "keys"
        _make_store(store_dir)
        assert stat.S_IMODE(os.stat(store_dir).st_mode) == 0o700

    def test_key_and_salt_files_are_0600(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        for key_id in _KEYS:
            mode = stat.S_IMODE(os.stat(tmp_path / f"{key_id}.json").st_mode)
            assert mode == 0o600, f"{key_id}.json is {oct(mode)}"
        assert stat.S_IMODE(os.stat(store.salt_file).st_mode) == 0o600


class TestAtomicWriteFdOwnership:
    """Descriptor ownership on the error path of ``_atomic_write_bytes``.

    The first version closed the raw descriptor inside ``except OSError: pass``
    on every failure.  That silently swallowed a double-close: once
    ``os.fdopen`` has taken the descriptor, closing it again either raises
    EBADF or — far worse — closes an unrelated descriptor the runtime has since
    reissued under the same number.  CodeQL flagged the empty handler; the fix
    was to track ownership explicitly rather than to annotate the swallow.
    These tests pin the resulting behaviour.
    """

    def test_write_succeeds_and_leaves_no_staging_file(self, tmp_path: Path) -> None:
        target = tmp_path / "payload.bin"
        _atomic_write_bytes(target, b"contents")
        assert target.read_bytes() == b"contents"
        assert [p.name for p in tmp_path.iterdir()] == ["payload.bin"]

    def test_failure_before_fdopen_closes_fd_and_removes_staging_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force os.fdopen itself to fail: ownership never transfers, so the
        # cleanup path must close the descriptor we still own.
        closed: list[int] = []
        real_close = os.close

        def tracking_close(fd: int) -> None:
            closed.append(fd)
            real_close(fd)

        def exploding_fdopen(*_args: object, **_kwargs: object) -> object:
            raise OSError("simulated fdopen failure")

        # key_management does `import os`, so its `os` IS this module object;
        # patching here intercepts the call it makes.
        monkeypatch.setattr(os, "close", tracking_close)
        monkeypatch.setattr(os, "fdopen", exploding_fdopen)

        with pytest.raises(OSError):
            _atomic_write_bytes(tmp_path / "x.bin", b"data")

        assert closed, "descriptor must be closed when fdopen never took ownership"
        assert list(tmp_path.iterdir()) == [], "staging file must be removed"

    def test_failure_after_fdopen_does_not_double_close(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fail AFTER ownership transferred (during os.replace).  The file object
        # closes the descriptor; the cleanup path must NOT close it again.
        closed: list[int] = []
        real_close = os.close

        def tracking_close(fd: int) -> None:
            closed.append(fd)
            real_close(fd)

        def exploding_replace(*_args: object, **_kwargs: object) -> None:
            raise OSError("simulated replace failure")

        # key_management does `import os`, so its `os` IS this module object;
        # patching here intercepts the call it makes.
        monkeypatch.setattr(os, "close", tracking_close)
        monkeypatch.setattr(os, "replace", exploding_replace)

        with pytest.raises(OSError):
            _atomic_write_bytes(tmp_path / "y.bin", b"data")

        assert closed == [], "fdopen owned the fd; cleanup must not close it again"
        assert list(tmp_path.iterdir()) == [], "staging file must be removed"


class TestMigrationCrashSafety:
    def test_successful_migration_rerotates_salt_and_preserves_keys(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        originals = {k: store.retrieve_key(k) for k in _KEYS}
        salt_before = store.salt_file.read_bytes()

        assert store.migrate_kdf(PASSWORD) is True
        assert store.salt_file.read_bytes() != salt_before  # fresh salt

        # Re-open cold with the same password: keys still decrypt under the new
        # salt/key derived from disk.
        reopened = SecureKeyStorage.from_existing(tmp_path, PASSWORD)
        for key_id, material in originals.items():
            assert reopened.retrieve_key(key_id) == material

    def test_interrupted_migration_preserves_every_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _make_store(tmp_path)
        originals = {k: store.retrieve_key(k) for k in _KEYS}
        salt_before = store.salt_file.read_bytes()
        key_bytes_before = {k: (tmp_path / f"{k}.json").read_bytes() for k in _KEYS}

        # Fail on the second re-encryption, mid-migration.
        real_store = store.store_key
        calls = {"n": 0}

        def flaky_store(
            key_id: str, key_data: bytes, metadata: Optional[dict[str, Any]] = None
        ) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk-full during migration")
            real_store(key_id, key_data, metadata)

        monkeypatch.setattr(store, "store_key", flaky_store)

        with pytest.raises(OSError):
            store.migrate_kdf(PASSWORD)

        # On-disk state fully restored: the salt is unchanged and every key
        # file is byte-identical to its pre-migration content.
        assert store.salt_file.read_bytes() == salt_before
        for key_id in _KEYS:
            assert (tmp_path / f"{key_id}.json").read_bytes() == key_bytes_before[key_id]

        # And a cold re-open with the original password recovers all keys —
        # nothing was orphaned under the discarded new key.
        reopened = SecureKeyStorage.from_existing(tmp_path, PASSWORD)
        for key_id, material in originals.items():
            assert reopened.retrieve_key(key_id) == material
