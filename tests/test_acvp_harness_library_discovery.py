#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``nist_vectors/run_vectors.py`` must find the library at any SONAME.

The harness named its versioned fallback literally::

    lib_names = ["libama_cryptography.so", "libama_cryptography.so.2"]

``CMakeLists.txt`` sets ``SOVERSION ${PROJECT_VERSION_MAJOR}``, so that string
went stale the moment 3.0.0 shipped and had been wrong for three majors by
5.0.0.  It never bit because CI builds in-tree, where the unversioned symlink
exists and is tried first — but on any layout carrying only the versioned
object (an installed prefix, a packaged sysroot, a wheel's bundled library)
the harness would report that it could not find the library while the library
sat beside it under its current name.

A validation harness that cannot find the library reports a *build* failure,
not a vector failure, which is the misdiagnosis worth removing.  Re-pinning
the constant to ``.so.5`` would only restart the same clock, so discovery is
derived from what is present.

These tests deliberately do not name a major.  A test asserting ``.so.5``
would itself need editing at 6.0.0 — the defect it is meant to prevent.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "nist_vectors"))

run_vectors = pytest.importorskip("run_vectors", reason="nist_vectors harness not importable")


class _FakeCDLL:
    """Records the path it was asked to load instead of dlopen-ing it."""

    def __init__(self, path: str) -> None:
        self.path = path


@pytest.fixture
def loader(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """`load_library` pointed at a temp dir, with dlopen and setup stubbed."""
    monkeypatch.setattr(run_vectors, "LIB_DIR", tmp_path)
    monkeypatch.setattr(run_vectors.ctypes, "CDLL", _FakeCDLL)
    monkeypatch.setattr(run_vectors, "_setup_ctypes", lambda lib: None)
    return tmp_path


def _write(directory: Path, name: str) -> Path:
    path = directory / name
    path.write_bytes(b"\x7fELF not really")
    return path


class TestVersionedDiscovery:
    def test_the_unversioned_symlink_is_preferred(self, loader: Path) -> None:
        """The build tree's own name wins — it is the developer's intent."""
        _write(loader, "libama_cryptography.so")
        _write(loader, "libama_cryptography.so.9")
        assert run_vectors.load_library().path.endswith("libama_cryptography.so")

    @pytest.mark.parametrize("major", [3, 4, 5, 6, 17])
    def test_any_single_major_is_found(self, loader: Path, major: int) -> None:
        """The regression: only ``.so.2`` used to be found."""
        _write(loader, f"libama_cryptography.so.{major}")
        assert run_vectors.load_library().path.endswith(f".so.{major}")

    def test_the_highest_major_wins_when_several_are_present(self, loader: Path) -> None:
        for major in (2, 4, 10):
            _write(loader, f"libama_cryptography.so.{major}")
        assert run_vectors.load_library().path.endswith(".so.10")

    def test_full_version_suffixes_are_ordered_numerically(self, loader: Path) -> None:
        """``.so.5.0.0`` must outrank ``.so.4.10.0`` — not string ordering."""
        _write(loader, "libama_cryptography.so.4.10.0")
        _write(loader, "libama_cryptography.so.5.0.0")
        assert run_vectors.load_library().path.endswith(".so.5.0.0")

    def test_an_unparseable_suffix_is_not_loaded(self, loader: Path) -> None:
        """A stray ``.so.bak`` beside the real object must not be dlopen-ed."""
        _write(loader, "libama_cryptography.so.bak")
        _write(loader, "libama_cryptography.so.5")
        assert run_vectors.load_library().path.endswith(".so.5")

    def test_only_an_unparseable_candidate_is_a_clean_failure(self, loader: Path) -> None:
        _write(loader, "libama_cryptography.so.bak")
        with pytest.raises(RuntimeError, match="Cannot find"):
            run_vectors.load_library()

    def test_nothing_present_names_the_remedy(self, loader: Path) -> None:
        """The message must say how to fix it, since this is a build failure."""
        with pytest.raises(RuntimeError, match="cmake"):
            run_vectors.load_library()


class TestNoHardcodedMajorRemains:
    def test_the_harness_does_not_pin_a_soname_major(self) -> None:
        """A literal ``libama_cryptography.so.<N>`` is the defect itself."""
        import re

        source = (REPO_ROOT / "nist_vectors" / "run_vectors.py").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        # Strip the docstring, which discusses the old constant by name.
        body = code.split('"""', 2)[-1] if code.count('"""') >= 2 else code
        pinned = re.findall(r'["\']libama_cryptography\.so\.\d', body)
        assert not pinned, f"a SONAME major is hard-coded again: {pinned}"
