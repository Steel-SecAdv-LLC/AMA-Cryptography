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


def _restrict_or_explain(path: pathlib.Path, *, directory: bool = False) -> None:
    """``restrict_to_owner``, but a failure names its cause.

    ``restrict_to_owner`` is best-effort by contract: it swallows the OSError
    and returns False, because refusing to persist a nonce is worse than
    persisting it with wider access. That is right for production and wrong
    for a test, where it turns a diagnosable Windows API error into a bare
    ``assert False is True`` — the same shape as the Ninja sub-build that
    reported ``build stopped`` with the compiler error nowhere in the log. So
    on failure the platform primitive is re-run to let the real exception out.
    """
    if _owner_only.restrict_to_owner(path, directory=directory):
        return
    import sys

    if sys.platform == "win32":  # pragma: no cover - Windows only
        _owner_only._windows_restrict(pathlib.Path(path), directory=directory)
    else:
        import os

        os.chmod(
            path,
            _owner_only.OWNER_ONLY_DIR_MODE if directory else _owner_only.OWNER_ONLY_FILE_MODE,
        )
    raise AssertionError(
        "restrict_to_owner reported failure, but re-running the platform "
        "primitive succeeded — the failure is not reproducible and the "
        "best-effort swallow is hiding something"
    )


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
        _restrict_or_explain(secret)
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
        _restrict_or_explain(wide)
        assert _owner_only.access_description(wide) == (
            _owner_only.expected_owner_only_description()
        )


class TestADirectoryIsNarrowedToItsOwner:
    def test_a_restricted_directory_reads_back_as_owner_only(self, tmp_path: pathlib.Path) -> None:
        store = tmp_path / "keystore"
        store.mkdir()
        _restrict_or_explain(store, directory=True)
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
    """Apply an arbitrary DACL, through the module's own declared prototypes.

    Deliberately reuses ``_owner_only._win`` rather than calling ctypes
    directly: a helper with its own undeclared calls would carry exactly the
    32-bit-default defect the gate below exists to prevent, and would fail on
    Win64 for a reason that has nothing to do with what the test is checking.
    """
    import sys

    # Not decoration: `ctypes.get_last_error` is Windows-only in typeshed, so
    # this narrowing is what lets `mypy --strict` check the body at all off
    # Windows. Dropping it is how CI's Code Quality job went red.
    if sys.platform != "win32":
        raise OSError("Windows only")
    import ctypes

    from ama_cryptography._owner_only import _BOOL, _PVOID, _win

    descriptor = _PVOID()
    if not _win("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW")(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise OSError(ctypes.get_last_error(), "building the wide descriptor failed")
    try:
        present = _BOOL()
        dacl = _PVOID()
        defaulted = _BOOL()
        if not _win("advapi32", "GetSecurityDescriptorDacl")(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl failed")
        # 0x4 = DACL_SECURITY_INFORMATION, deliberately NOT protected, so the
        # result differs from the owner-only form in the P flag as well.
        status = _win("advapi32", "SetNamedSecurityInfoW")(
            str(path), 1, 0x4, None, None, dacl, None
        )
        if status != 0:
            raise OSError(status, "SetNamedSecurityInfoW failed")
    finally:
        _win("kernel32", "LocalFree")(descriptor)


class TestTheDaclComparisonToleratesWindowsBookkeepingOnly:
    """Windows does not hand back the SDDL it was given.

    ``SetNamedSecurityInfoW`` records its own control bits, so a DACL written
    as ``D:P(...)`` reads back as ``D:PAI(...)``; the ACE order is
    canonicalised; and an access mask comes back as a hex literal when the
    converter declines the abbreviation. A raw string comparison would fail on
    a DACL that is exactly correct — and, worse, could be "fixed" by loosening
    it until it stopped failing.

    So the comparison normalises first, and these cases pin what that
    normalisation may and may not forgive. They run on Linux: the function is
    string handling, and the whole point is that its behaviour is checkable
    without the platform that produces the strings.
    """

    SID = "S-1-5-21-1-2-3-1001"

    @property
    def owner_only(self) -> str:
        return _owner_only._normalise_dacl_sddl(f"D:P(A;;FA;;;{self.SID})")

    @pytest.mark.parametrize(
        ("equivalent", "why"),
        [
            pytest.param("D:PAI(A;;FA;;;{sid})", "the AI control bit", id="auto-inherited-flag"),
            pytest.param(
                "D:P(A;;0x1f01ff;;;{sid})", "FILE_ALL_ACCESS as hex", id="hex-access-mask"
            ),
            pytest.param("D:PAI(A;;0x1f01ff;;;{sid})", "both at once", id="both"),
        ],
    )
    def test_windows_bookkeeping_is_forgiven(self, equivalent: str, why: str) -> None:
        assert _owner_only._normalise_dacl_sddl(equivalent.format(sid=self.SID)) == (
            self.owner_only
        ), f"{why} must not make a correct DACL compare unequal"

    @pytest.mark.parametrize(
        ("different", "why"),
        [
            pytest.param("D:(A;;FA;;;WD)", "grants Everyone, and is not protected", id="widened"),
            pytest.param(
                "D:AI(A;;FA;;;{sid})",
                "the P flag is gone, so the parent's ACEs are inherited",
                id="lost-protection",
            ),
            pytest.param(
                "D:PAI(A;;FA;;;{sid})(A;;FR;;;WD)",
                "a second ACE grants Everyone read",
                id="extra-ace",
            ),
            pytest.param(
                "D:P(A;OICI;FA;;;{sid})",
                "container/object inheritance is the directory form",
                id="directory-form",
            ),
            pytest.param(
                "D:P(A;;FA;;;S-1-5-32-544)", "a different principal entirely", id="other-sid"
            ),
        ],
    )
    def test_a_real_difference_is_never_normalised_away(self, different: str, why: str) -> None:
        assert _owner_only._normalise_dacl_sddl(different.format(sid=self.SID)) != (
            self.owner_only
        ), f"normalisation hid a real difference: {why}"

    def test_ace_order_is_not_significant(self) -> None:
        """Windows canonicalises ACE order; the DACL still grants the same set."""
        a = f"D:P(A;;FA;;;{self.SID})(A;;FR;;;WD)"
        b = f"D:P(A;;FR;;;WD)(A;;FA;;;{self.SID})"
        assert _owner_only._normalise_dacl_sddl(a) == _owner_only._normalise_dacl_sddl(b)


class TestEveryWindowsCallHasADeclaredPrototype:
    """ctypes' defaults are 32-bit, and that silently broke every Windows lane.

    ctypes does not know a foreign function's signature. Absent ``restype`` it
    assumes ``c_int``; absent ``argtypes`` it passes Python ints as 32-bit. On
    Win64 a ``HANDLE`` is pointer-width, so ``GetCurrentProcess()``'s
    ``(HANDLE)-1`` came back truncated and ``OpenProcessToken`` answered
    ``ERROR_INVALID_HANDLE`` (6) — 11 failures across all five Windows Python
    versions, none of them reproducible on this host.

    These checks run on Linux. They read the source rather than the platform,
    so the defect class cannot come back on a runner nobody is watching.
    """

    @staticmethod
    def _module_source() -> str:
        return pathlib.Path(_owner_only.__file__).read_text(encoding="utf-8")

    @staticmethod
    def _declared_calls() -> set[tuple[str, str]]:
        """Every ``_win("lib", "func")`` the module makes, read from its AST."""
        import ast

        tree = ast.parse(TestEveryWindowsCallHasADeclaredPrototype._module_source())
        found: set[tuple[str, str]] = set()
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_win"
            ):
                continue
            # Bound to a list comprehension rather than tested with `all(...)`
            # so the element type narrows for real; `all()` narrows nothing,
            # which is what a `# type: ignore` on the unpack would have been
            # papering over.
            literals = [arg for arg in node.args if isinstance(arg, ast.Constant)]
            if len(literals) != 2 or len(node.args) != 2:
                continue
            found.add((str(literals[0].value), str(literals[1].value)))
        return found

    def test_every_call_site_resolves_to_a_declared_prototype(self) -> None:
        undeclared = sorted(self._declared_calls() - set(_owner_only._WINDOWS_PROTOTYPES))
        assert not undeclared, (
            f"these Windows calls have no prototype, so ctypes would use its "
            f"32-bit defaults for them: {undeclared}"
        )

    def test_there_are_calls_to_check(self) -> None:
        # Non-vacuity: an AST walk that matched nothing would pass the check
        # above forever.
        assert len(self._declared_calls()) >= 8

    def test_no_windows_entry_point_is_reached_outside_the_table(self) -> None:
        """``_win`` must be the only way in.

        A call written as ``advapi32.Something(...)`` would take the defaults
        again, and every prototype in the table would still be correct — so
        checking the table alone is not enough. This checks the call sites.
        """
        source = self._module_source()
        for library in ("advapi32", "kernel32"):
            # The only mentions permitted are the table keys and _win's own
            # lookup; an attribute call like `advapi32.OpenProcessToken(` is not.
            assert f"{library}." not in source, (
                f"{library} is reached by attribute access somewhere in "
                f"_owner_only.py; every call must go through _win() so its "
                f"prototype is applied"
            )

    def test_handles_and_pointers_are_pointer_width(self) -> None:
        """The exact defect: a pointer typed as ``c_int`` truncates on Win64."""
        import ctypes

        prototypes = _owner_only._WINDOWS_PROTOTYPES
        argtypes, restype = prototypes[("kernel32", "GetCurrentProcess")]
        assert restype is ctypes.c_void_p, (
            "GetCurrentProcess returns a HANDLE; typed as c_int its (HANDLE)-1 "
            "pseudo-handle truncates to 32 bits and OpenProcessToken fails with "
            "ERROR_INVALID_HANDLE"
        )
        assert argtypes == ()
        for (library, function), (args, result) in prototypes.items():
            assert result is not None, f"{library}.{function} has no restype"
            for index, arg in enumerate(args):
                assert arg is not None, f"{library}.{function} arg {index} is untyped"

    def test_every_prototype_is_actually_used(self) -> None:
        """No dead entries: a stale prototype is a claim nothing checks."""
        unused = sorted(set(_owner_only._WINDOWS_PROTOTYPES) - self._declared_calls())
        assert not unused, f"prototypes declared but never called: {unused}"


if __name__ == "__main__":  # pragma: no cover - convenience
    raise SystemExit(pytest.main([__file__]))
