# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""SecureKeyStorage.delete_key must not write through a planted symlink.

KM-STORE-003.  ``_validate_key_id`` constrains the NAME, which stops path
traversal but says nothing about what the resulting path IS.  The previous
body did ``open(key_file, "wb")`` and wrote 1 KiB of random bytes: with
``<key_id>.json`` replaced by a symlink inside the store, that write landed
on the link's target and the unlink then removed only the link.  The store is
created 0700, so this needs a process that can already write into it -- the
key owner's own account, another tool sharing it, or a restore that
materialised a link -- which is exactly the confused-deputy shape a
security-relevant delete should not have.

The fix opens the path with ``O_NOFOLLOW`` and writes through that
descriptor, and refuses anything that is not a regular file.  These tests
fail against the pre-fix body: the target's contents change.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from ama_cryptography.key_management import SecureKeyStorage

pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW"), reason="no O_NOFOLLOW on this platform"
)


@pytest.fixture()
def storage(tmp_path: pathlib.Path) -> SecureKeyStorage:
    return SecureKeyStorage(tmp_path / "store", master_password="correct horse battery staple")


def test_a_symlinked_key_file_is_refused_and_its_target_survives(
    storage: SecureKeyStorage, tmp_path: pathlib.Path
) -> None:
    victim = tmp_path / "victim.pem"
    victim.write_bytes(b"PRIVATE KEY THAT MUST SURVIVE")
    link = storage.storage_path / "planted.json"
    link.symlink_to(victim)

    with pytest.raises(ValueError, match="Refusing to delete"):
        storage.delete_key("planted")

    assert victim.read_bytes() == b"PRIVATE KEY THAT MUST SURVIVE"
    assert link.is_symlink(), "the link itself must not have been removed either"


def test_a_fifo_in_place_of_a_key_file_is_refused(
    storage: SecureKeyStorage, tmp_path: pathlib.Path
) -> None:
    """O_NOFOLLOW does not cover a FIFO; opening one would also block."""
    if not hasattr(os, "mkfifo"):  # pragma: no cover - platform without FIFOs
        pytest.skip("no mkfifo on this platform")
    fifo = storage.storage_path / "pipe.json"
    os.mkfifo(fifo)
    # O_NOFOLLOW lets a FIFO through, so the open must not block.  This test
    # is the reason O_NONBLOCK is in the flags: without it the write-side open
    # of a reader-less FIFO blocks forever and this test hangs rather than
    # failing.  With it the open returns ENXIO and delete_key refuses.
    with pytest.raises(ValueError, match="Refusing to delete"):
        storage.delete_key("pipe")
    assert fifo.exists()


def test_a_missing_key_still_reports_false(storage: SecureKeyStorage) -> None:
    assert storage.delete_key("no-such-key") is False


def test_a_real_key_file_is_still_overwritten_and_removed(
    storage: SecureKeyStorage,
) -> None:
    """Non-vacuity: the guard must not have broken the ordinary path."""
    key_file = storage.storage_path / "ordinary.json"
    key_file.write_bytes(b"{}")
    assert storage.delete_key("ordinary") is True
    assert not key_file.exists()
