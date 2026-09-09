# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Owner-only access for files and directories, on POSIX *and* on Windows.

Every place this package stores something private — the private-key store,
its metadata, the nonce ledger — expressed "only the owner may read this" as
``0o600`` / ``0o700``. That is a POSIX statement, and on Windows it is very
nearly a no-op: ``os.chmod`` there toggles the read-only attribute and
nothing else, ``os.fchmod`` and ``os.getuid`` do not exist at all, and
``Path.mkdir(mode=...)`` is ignored. A key store created on Windows took
whatever the parent directory's inheritable ACEs granted — commonly
``Users: Read`` under ``C:\\Users\\<name>`` and rather more on a machine with
a widened profile root.

So the control is expressed once, here, in terms of the *property* rather
than of POSIX mode bits, and each platform's enforcement lives behind it:

* POSIX — ``chmod`` to the caller's mode (``0o600`` for a file, ``0o700``
  for a directory).
* Windows — a **protected** DACL (``SE_DACL_PROTECTED``, so no ACE is
  inherited from the parent) whose single entry grants ``FILE_ALL_ACCESS``
  to the SID of the process token's user, applied with
  ``SetNamedSecurityInfoW``. An Administrator can still take ownership, in
  the same way ``root`` defeats ``0o600``; that is the limit of the analogy
  and of the guarantee.

Nothing outside the standard library is used: the Windows path is ctypes
against ``advapi32``/``kernel32``, so the package keeps its zero runtime
dependencies.

``restrict_to_owner`` returns whether the property was actually enforced, so
a caller can refuse to proceed rather than assume. ``access_description``
reads the enforcement back — ``"0600"`` on POSIX, the DACL's SDDL on Windows
— which is what lets one test assert the same property on both platforms
instead of skipping on whichever one it was not written for.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

__all__ = [
    "OWNER_ONLY_DIR_MODE",
    "OWNER_ONLY_FILE_MODE",
    "access_description",
    "is_enforceable",
    "restrict_to_owner",
]

#: The POSIX modes this module means by "owner only".
OWNER_ONLY_FILE_MODE = 0o600
OWNER_ONLY_DIR_MODE = 0o700

# --- Windows -------------------------------------------------------------

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SDDL_REVISION_1 = 1
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ERROR_SUCCESS = 0


def _windows_user_sid() -> str:
    """The SDDL string form of the process token's user SID."""
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        size = wintypes.DWORD(0)
        # First call sizes the buffer; it is expected to fail with
        # ERROR_INSUFFICIENT_BUFFER, which is why its return is ignored.
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, size, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation(TokenUser) failed")
        # TOKEN_USER is { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } }
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


def windows_owner_only_sddl(*, directory: bool) -> str:
    """The DACL this module applies, as SDDL.

    ``D:P`` is a protected DACL: it blocks inheritance from the parent, which
    is the whole point — a key store under a profile root that grants
    ``Users: Read`` must not pick that up. ``OICI`` propagates the single ACE
    to a directory's children so files created inside it are covered too.
    """
    flags = "OICI" if directory else ""
    return f"D:P(A;{flags};FA;;;{_windows_user_sid()})"


def _windows_restrict(path: Path, *, directory: bool) -> None:
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        windows_owner_only_sddl(directory=directory),
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise OSError(ctypes.get_last_error(), "building the owner-only descriptor failed")
    try:
        present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl failed")
        status = advapi32.SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if status != _ERROR_SUCCESS:
            raise OSError(status, f"SetNamedSecurityInfoW({path}) failed")
    finally:
        kernel32.LocalFree(descriptor)


def _windows_dacl_sddl(path: Path) -> str:
    """The DACL currently on ``path``, as SDDL. Read-back for the gate."""
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")
    import ctypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != _ERROR_SUCCESS:
        raise OSError(status, f"GetNamedSecurityInfoW({path}) failed")
    try:
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            _SDDL_REVISION_1,
            _DACL_SECURITY_INFORMATION,
            ctypes.byref(text),
            None,
        ):
            raise OSError(ctypes.get_last_error(), "converting the descriptor to SDDL failed")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


# --- the platform-independent surface ------------------------------------


def is_enforceable() -> bool:
    """Whether this platform has a mechanism for owner-only access.

    True on POSIX and on Windows. It is a function rather than a constant so
    a caller reads it as a question about the host, and so the answer can
    become False on some future platform without every call site changing.
    """
    return sys.platform == "win32" or hasattr(os, "chmod")


def restrict_to_owner(path: str | os.PathLike[str], *, directory: bool = False) -> bool:
    """Restrict ``path`` to its owner. Returns whether that was enforced.

    Best-effort by contract: a filesystem that refuses the operation (a FAT
    volume, a network share, a container bind mount) leaves the object as it
    was and returns False rather than raising, because refusing to persist a
    nonce is a worse outcome than persisting it with wider access — the
    caller decides. It never returns True without having applied the control.
    """
    target = Path(path)
    if sys.platform == "win32":
        try:
            _windows_restrict(target, directory=directory)
        except OSError:
            return False
        return True
    if not hasattr(os, "chmod"):
        return False
    try:
        os.chmod(target, OWNER_ONLY_DIR_MODE if directory else OWNER_ONLY_FILE_MODE)
    except OSError:
        return False
    return True


def restrict_fd_to_owner(fd: int, path: str | os.PathLike[str], *, directory: bool = False) -> bool:
    """``restrict_to_owner`` for an object still held open by descriptor.

    On POSIX this uses ``fchmod``, so a staging file is narrowed through the
    descriptor that created it and never through a name an attacker could
    have replaced in between. Windows has no descriptor-based equivalent in
    this API, so it falls back to the path form; the staging file there is
    created by ``mkstemp`` in the destination's own directory and renamed
    into place, so the window is the same one ``os.replace`` already has.
    """
    if sys.platform != "win32" and hasattr(os, "fchmod"):
        try:
            os.fchmod(fd, OWNER_ONLY_DIR_MODE if directory else OWNER_ONLY_FILE_MODE)
        except OSError:
            return False
        return True
    return restrict_to_owner(path, directory=directory)


def access_description(path: str | os.PathLike[str]) -> str:
    """How ``path``'s access is currently expressed, for tests and diagnostics.

    ``"0600"``-style octal on POSIX, the DACL's SDDL on Windows. Two
    different alphabets for one question, which is why the gate compares each
    against ``expected_owner_only_description`` rather than against a
    hardcoded ``0o600``.
    """
    target = Path(path)
    if sys.platform == "win32":
        return _windows_dacl_sddl(target)
    return format(stat.S_IMODE(target.stat().st_mode), "04o")


def expected_owner_only_description(*, directory: bool = False) -> str:
    """What ``access_description`` reads back from an owner-only object here."""
    if sys.platform == "win32":
        return windows_owner_only_sddl(directory=directory)
    return format(OWNER_ONLY_DIR_MODE if directory else OWNER_ONLY_FILE_MODE, "04o")
