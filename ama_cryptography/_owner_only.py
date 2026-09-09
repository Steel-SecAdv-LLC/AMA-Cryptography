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

import ctypes
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

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


#: Every Windows entry point this module calls, with its FULL prototype.
#:
#: ctypes does not know a foreign function's signature. With no ``restype`` it
#: assumes ``c_int`` -- 32 bits -- and with no ``argtypes`` it passes Python
#: ints as 32-bit values. On 64-bit Windows a ``HANDLE`` is a pointer, so
#: ``GetCurrentProcess()``'s ``(HANDLE)-1`` pseudo-handle came back truncated
#: and ``OpenProcessToken`` answered ``ERROR_INVALID_HANDLE`` (6). Measured on
#: windows-latest across all five Python versions: 11 failures, every one of
#: them this.
#:
#: The same defect shape as the C sequencing bug this release also fixed -- an
#: implicit language default that is invisible until the platform changes --
#: so it is closed the same way: state the contract explicitly, in one place a
#: test can read on any platform (``TestEveryWindowsCallHasADeclaredPrototype``
#: does exactly that, and runs on Linux).
#:
#: Plain ``ctypes`` types rather than ``ctypes.wintypes``: HANDLE/PSID/PACL/
#: PSECURITY_DESCRIPTOR are all pointers (``c_void_p``, pointer-width on every
#: target), DWORD is ``c_ulong``, BOOL is ``c_int``. That is exact, and it
#: keeps the table constructible off Windows, which is what lets the gate
#: check it here.
_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_ulong
_BOOL = ctypes.c_int
_LPWSTR = ctypes.c_wchar_p
_PVOID = ctypes.c_void_p

_WINDOWS_PROTOTYPES: dict[tuple[str, str], tuple[tuple[Any, ...], Any]] = {
    ("kernel32", "GetCurrentProcess"): ((), _HANDLE),
    ("kernel32", "CloseHandle"): ((_HANDLE,), _BOOL),
    ("kernel32", "LocalFree"): ((_PVOID,), _PVOID),
    ("advapi32", "OpenProcessToken"): (
        (_HANDLE, _DWORD, ctypes.POINTER(_HANDLE)),
        _BOOL,
    ),
    ("advapi32", "GetTokenInformation"): (
        (_HANDLE, ctypes.c_int, _PVOID, _DWORD, ctypes.POINTER(_DWORD)),
        _BOOL,
    ),
    ("advapi32", "ConvertSidToStringSidW"): (
        (_PVOID, ctypes.POINTER(_LPWSTR)),
        _BOOL,
    ),
    ("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW"): (
        (_LPWSTR, _DWORD, ctypes.POINTER(_PVOID), ctypes.POINTER(ctypes.c_ulong)),
        _BOOL,
    ),
    ("advapi32", "ConvertSecurityDescriptorToStringSecurityDescriptorW"): (
        (_PVOID, _DWORD, _DWORD, ctypes.POINTER(_LPWSTR), ctypes.POINTER(ctypes.c_ulong)),
        _BOOL,
    ),
    ("advapi32", "GetSecurityDescriptorDacl"): (
        (_PVOID, ctypes.POINTER(_BOOL), ctypes.POINTER(_PVOID), ctypes.POINTER(_BOOL)),
        _BOOL,
    ),
    ("advapi32", "SetNamedSecurityInfoW"): (
        (_LPWSTR, ctypes.c_int, _DWORD, _PVOID, _PVOID, _PVOID, _PVOID),
        _DWORD,
    ),
    ("advapi32", "GetNamedSecurityInfoW"): (
        (
            _LPWSTR,
            ctypes.c_int,
            _DWORD,
            ctypes.POINTER(_PVOID),
            ctypes.POINTER(_PVOID),
            ctypes.POINTER(_PVOID),
            ctypes.POINTER(_PVOID),
            ctypes.POINTER(_PVOID),
        ),
        _DWORD,
    ),
}


def _win(library: str, function: str) -> Any:
    """One Windows entry point, with its prototype applied from the table.

    Going through here is what makes the table load-bearing rather than
    documentation: a call that skipped it would take ctypes' 32-bit defaults
    again, and the gate below fails any call site that does.
    """
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")
    handle = _WINDOWS_LIBRARIES.get(library)
    if handle is None:
        handle = ctypes.WinDLL(library, use_last_error=True)
        _WINDOWS_LIBRARIES[library] = handle
    entry = getattr(handle, function)
    argtypes, restype = _WINDOWS_PROTOTYPES[(library, function)]
    entry.argtypes = list(argtypes)
    entry.restype = restype
    return entry


_WINDOWS_LIBRARIES: dict[str, Any] = {}


def _windows_user_sid() -> str:
    """The SDDL string form of the process token's user SID."""
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")

    token = _HANDLE()
    if not _win("advapi32", "OpenProcessToken")(
        _win("kernel32", "GetCurrentProcess")(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        size = _DWORD(0)
        get_token_information = _win("advapi32", "GetTokenInformation")
        # First call sizes the buffer; it is expected to fail with
        # ERROR_INSUFFICIENT_BUFFER, which is why its return is ignored.
        get_token_information(token, _TOKEN_USER, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not get_token_information(
            token, _TOKEN_USER, ctypes.cast(buffer, _PVOID), size, ctypes.byref(size)
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation(TokenUser) failed")
        # TOKEN_USER is { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } },
        # so the first pointer-sized field of the buffer is the PSID itself.
        sid = ctypes.cast(buffer, ctypes.POINTER(_PVOID)).contents
        text = _LPWSTR()
        if not _win("advapi32", "ConvertSidToStringSidW")(sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(text.value)
        finally:
            _win("kernel32", "LocalFree")(ctypes.cast(text, _PVOID))
    finally:
        _win("kernel32", "CloseHandle")(token)


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

    descriptor = _PVOID()
    if not _win("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW")(
        windows_owner_only_sddl(directory=directory),
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise OSError(ctypes.get_last_error(), "building the owner-only descriptor failed")
    try:
        present = _BOOL()
        dacl = _PVOID()
        defaulted = _BOOL()
        if not _win("advapi32", "GetSecurityDescriptorDacl")(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl failed")
        status = _win("advapi32", "SetNamedSecurityInfoW")(
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
        _win("kernel32", "LocalFree")(descriptor)


def _normalise_dacl_sddl(sddl: str) -> str:
    """A DACL's SDDL reduced to what it actually GRANTS.

    Windows does not hand back the string it was given. ``SetNamedSecurityInfoW``
    records its own control bits, so a DACL written as ``D:P(...)`` reads back
    as ``D:PAI(...)`` once inheritance has been processed; the ACE order is
    canonicalised; and an access mask is emitted as an abbreviation only when
    it matches one exactly, as a hex literal otherwise. None of that changes
    who may open the file, so comparing the raw strings would fail on a DACL
    that is exactly right.

    So the comparison is made on the part that carries the meaning: the ``P``
    (protected — no inheritance from the parent) flag, and the sorted set of
    ACEs with ``FILE_ALL_ACCESS`` spelled one way. ``AI``/``AR`` are Windows'
    bookkeeping about how the DACL got there, not a statement about access,
    and are dropped.
    """
    body = sddl.split("D:", 1)[1] if "D:" in sddl else sddl
    split = body.find("(")
    flags, rest = (body, "") if split < 0 else (body[:split], body[split:])
    aces = re.findall(r"\(([^)]*)\)", rest)
    #: FILE_ALL_ACCESS. Emitted as `FA` when it matches exactly and as this
    #: hex literal when the converter declines the abbreviation.
    aces = [ace.replace(";0x1f01ff;", ";FA;") for ace in aces]
    protected = "P" if "P" in flags else ""
    return f"D:{protected}" + "".join(f"({ace})" for ace in sorted(aces))


def _windows_dacl_sddl(path: Path) -> str:
    """The DACL currently on ``path``, as SDDL. Read-back for the gate."""
    if sys.platform != "win32":  # pragma: no cover - every caller checks first
        raise OSError("the Windows security API is not available on this platform")

    descriptor = _PVOID()
    dacl = _PVOID()
    status = _win("advapi32", "GetNamedSecurityInfoW")(
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
        text = _LPWSTR()
        if not _win("advapi32", "ConvertSecurityDescriptorToStringSecurityDescriptorW")(
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
            _win("kernel32", "LocalFree")(ctypes.cast(text, _PVOID))
    finally:
        _win("kernel32", "LocalFree")(descriptor)


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
        return _normalise_dacl_sddl(_windows_dacl_sddl(target))
    return format(stat.S_IMODE(target.stat().st_mode), "04o")


def expected_owner_only_description(*, directory: bool = False) -> str:
    """What ``access_description`` reads back from an owner-only object here."""
    if sys.platform == "win32":
        return _normalise_dacl_sddl(windows_owner_only_sddl(directory=directory))
    return format(OWNER_ONLY_DIR_MODE if directory else OWNER_ONLY_FILE_MODE, "04o")
