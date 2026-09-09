# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Owner-only access must be *enforced*, on every platform the suite runs on.

``0o600`` is a POSIX sentence. On Windows ``os.chmod`` toggles the read-only
attribute and nothing else, ``os.fchmod`` and ``os.getuid`` do not exist, and
``Path.mkdir(mode=...)`` is ignored — so a private-key store, its metadata,
and the nonce ledger took whatever the parent's inheritable ACEs granted.
``ama_cryptography._owner_only`` states the property once and lets each
platform enforce it; these tests check the property, not the mechanism, so
they assert the same thing on Linux, macOS and Windows rather than skipping
on whichever one they were not written for.

The first test is the important one: it fails on any platform where the
control would silently degrade to a no-op.
"""

from __future__ import annotations

import pathlib

import pytest

from ama_cryptography import _owner_only


class TestTheControlIsEnforceableHere:
    def test_this_platform_can_enforce_owner_only_access(self) -> None:
        """No platform gets a pass.

        If this ever fails, the answer is to implement enforcement for that
        platform — not to skip the tests below. A store that cannot be made
        owner-only is a finding, not a portability footnote.
        """
        assert _owner_only.is_enforceable(), (
            "this platform has no owner-only mechanism; private keys, their "
            "metadata and the nonce ledger would be left at whatever the "
            "parent directory grants"
        )


class TestAFileIsNarrowedToItsOwner:
    def test_a_restricted_file_reads_back_as_owner_only(self, tmp_path: pathlib.Path) -> None:
        secret = tmp_path / "secret.bin"
        secret.write_bytes(b"key material")
        assert _owner_only.restrict_to_owner(secret) is True
        assert (
            _owner_only.access_description(secret) == _owner_only.expected_owner_only_description()
        )

    def test_the_check_is_not_vacuous(self, tmp_path: pathlib.Path) -> None:
        """A wider object must read back as *different*.

        Without this, an ``access_description`` that returned a constant — or
        an ``expected_owner_only_description`` that happened to match every
        file on the host — would let the assertion above pass over an
        unenforced control.
        """
        wide = tmp_path / "wide.bin"
        wide.write_bytes(b"x")
        _widen(wide)
        assert _owner_only.access_description(wide) != (
            _owner_only.expected_owner_only_description()
        )
        assert _owner_only.restrict_to_owner(wide) is True
        assert _owner_only.access_description(wide) == (
            _owner_only.expected_owner_only_description()
        )


class TestADirectoryIsNarrowedToItsOwner:
    def test_a_restricted_directory_reads_back_as_owner_only(self, tmp_path: pathlib.Path) -> None:
        store = tmp_path / "keystore"
        store.mkdir()
        assert _owner_only.restrict_to_owner(store, directory=True) is True
        assert _owner_only.access_description(store) == (
            _owner_only.expected_owner_only_description(directory=True)
        )

    def test_a_directory_is_not_narrowed_with_the_file_rule(self, tmp_path: pathlib.Path) -> None:
        """``directory=True`` must be a real distinction.

        On POSIX a directory at 0600 cannot be traversed, so the store would
        be unusable; on Windows the ACE needs container/object inheritance so
        files created inside it are covered. Either way the two descriptions
        must differ, or one of the call sites is passing the wrong flag with
        no test to catch it.
        """
        assert _owner_only.expected_owner_only_description(directory=True) != (
            _owner_only.expected_owner_only_description()
        )


class TestTheDescriptorFormNarrowsTheSameWay:
    def test_restrict_fd_to_owner_matches_the_path_form(self, tmp_path: pathlib.Path) -> None:
        import os
        import tempfile

        fd, name = tempfile.mkstemp(dir=str(tmp_path))
        try:
            _widen(pathlib.Path(name))
            assert _owner_only.restrict_fd_to_owner(fd, name) is True
        finally:
            os.close(fd)
        assert _owner_only.access_description(name) == (
            _owner_only.expected_owner_only_description()
        )


def _widen(path: pathlib.Path, *, directory: bool = False) -> None:
    """Give ``path`` access wider than owner-only, however this platform says it.

    POSIX: group and world read (plus traverse, for a directory). Windows: an
    unprotected DACL that also grants ``WD`` (Everyone) — differing from the
    protected owner-only DACL in both its ``P`` flag and its ACE list, so a
    non-vacuity check cannot pass by accident.

    Shared with the ledger and key-store gates so "wider than owner-only"
    means one thing across the suite.
    """
    import sys

    if sys.platform == "win32":
        _windows_apply_sddl(path, "D:(A;OICI;FA;;;WD)" if directory else "D:(A;;FA;;;WD)")
        return
    import stat as _stat

    if directory:
        path.chmod(0o755)
        return
    path.chmod(_stat.S_IRUSR | _stat.S_IWUSR | _stat.S_IRGRP | _stat.S_IROTH)


def _windows_apply_sddl(path: pathlib.Path, sddl: str) -> None:  # pragma: no cover - Windows only
    import ctypes
    import sys

    if sys.platform != "win32":
        raise OSError("Windows only")
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise OSError(ctypes.get_last_error(), "building the wide descriptor failed")
    try:
        present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl failed")
        # 0x4 = DACL_SECURITY_INFORMATION, deliberately NOT protected, so the
        # result differs from the owner-only form in the P flag as well.
        status = advapi32.SetNamedSecurityInfoW(str(path), 1, 0x4, None, None, dacl, None)
        if status != 0:
            raise OSError(status, "SetNamedSecurityInfoW failed")
    finally:
        kernel32.LocalFree(descriptor)


if __name__ == "__main__":  # pragma: no cover - convenience
    raise SystemExit(pytest.main([__file__]))
