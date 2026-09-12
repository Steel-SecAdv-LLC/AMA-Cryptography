#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/verify_wheel_reproducible.py``.

The gate this file covers exists because reproducibility was verified on a
build that was then thrown away: ``static-analysis.yml``'s
``reproducible-build`` job is gated ``schedule || workflow_dispatch ||
pull_request``, and ``release.yml`` never called it, so the wheels that get
signed and published were never compared against anything.

A gate added to close that hole is itself worth nothing until it is shown to
fail on the thing it claims to catch, so every failure mode below is driven
with a synthesised wheel pair rather than asserted in prose.
"""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "verify_wheel_reproducible.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_wheel_reproducible", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


WHEEL = "ama_cryptography-5.0.0-cp312-cp312-manylinux_2_28_x86_64.whl"

#: The members every synthesised wheel carries.  `_integrity_signature.py` is
#: present deliberately: it is the one member excluded from the byte
#: comparison, so its presence is what the gate checks instead.
BASE_MEMBERS = {
    "ama_cryptography/__init__.py": b"# package\n",
    "ama_cryptography/crypto_api.py": b"# api\n",
    "ama_cryptography/_integrity_signature.py": b"PUBKEY = 'aaaa'\n",
    "ama_cryptography/libama_cryptography.so": b"\x7fELF fake native object",
    "ama_cryptography-5.0.0.dist-info/METADATA": b"Name: ama-cryptography\n",
    "ama_cryptography-5.0.0.dist-info/RECORD": b"ama_cryptography/__init__.py,sha256=x,9\n",
}


def _write_wheel(path: Path, members: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)


def _pair(tmp_path: Path, shipped: dict[str, bytes], rebuilt: dict[str, bytes]) -> tuple[Path, Path]:
    a, b = tmp_path / "shipped", tmp_path / "rebuilt"
    _write_wheel(a / WHEEL, shipped)
    _write_wheel(b / WHEEL, rebuilt)
    return a, b


def _run(gate: ModuleType, a: Path, b: Path) -> int:
    return int(gate.main(["--shipped", str(a), "--rebuilt", str(b)]))


# --------------------------------------------------------------------------
# The passing shape
# --------------------------------------------------------------------------


def test_identical_wheels_pass(gate: ModuleType, tmp_path: Path) -> None:
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), dict(BASE_MEMBERS))
    assert _run(gate, a, b) == 0


def test_the_per_build_signature_may_differ(gate: ModuleType, tmp_path: Path) -> None:
    """INVARIANT-17 gives each build its own keypair; that is not a failure."""
    rebuilt = dict(BASE_MEMBERS)
    rebuilt["ama_cryptography/_integrity_signature.py"] = b"PUBKEY = 'bbbb'\n"
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 0


def test_record_may_differ(gate: ModuleType, tmp_path: Path) -> None:
    """RECORD hashes the other members, so its equality is transitive."""
    rebuilt = dict(BASE_MEMBERS)
    rebuilt["ama_cryptography-5.0.0.dist-info/RECORD"] = b"different,sha256=y,9\n"
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 0


# --------------------------------------------------------------------------
# What it must catch
# --------------------------------------------------------------------------


def test_a_changed_native_object_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case the gate exists for: shipped .so != rebuilt .so."""
    rebuilt = dict(BASE_MEMBERS)
    rebuilt["ama_cryptography/libama_cryptography.so"] = b"\x7fELF DIFFERENT native object"
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 1
    assert "libama_cryptography.so differs" in capsys.readouterr().err


def test_a_changed_py_file_fails(gate: ModuleType, tmp_path: Path) -> None:
    rebuilt = dict(BASE_MEMBERS)
    rebuilt["ama_cryptography/crypto_api.py"] = b"# api, tampered\n"
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 1


def test_an_added_member_fails(gate: ModuleType, tmp_path: Path) -> None:
    rebuilt = dict(BASE_MEMBERS)
    rebuilt["ama_cryptography/extra.py"] = b"# surprise\n"
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 1


def test_a_dropped_member_fails(gate: ModuleType, tmp_path: Path) -> None:
    rebuilt = dict(BASE_MEMBERS)
    del rebuilt["ama_cryptography/crypto_api.py"]
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 1


def test_a_missing_integrity_signature_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exclusion must not become a way to remove the file entirely."""
    rebuilt = dict(BASE_MEMBERS)
    del rebuilt["ama_cryptography/_integrity_signature.py"]
    a, b = _pair(tmp_path, dict(BASE_MEMBERS), rebuilt)
    assert _run(gate, a, b) == 1
    assert "_integrity_signature.py is missing" in capsys.readouterr().err


def test_a_wheel_the_rebuild_did_not_produce_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = tmp_path / "shipped", tmp_path / "rebuilt"
    _write_wheel(a / WHEEL, dict(BASE_MEMBERS))
    _write_wheel(b / "ama_cryptography-5.0.0-cp313-cp313-manylinux_2_28_x86_64.whl", dict(BASE_MEMBERS))
    assert _run(gate, a, b) == 1
    assert "the rebuild produced no wheel of this name" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Fail-closed: a comparison that did not happen is not a pass
# --------------------------------------------------------------------------


def test_no_shipped_wheels_fails_closed(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = tmp_path / "shipped", tmp_path / "rebuilt"
    a.mkdir()
    _write_wheel(b / WHEEL, dict(BASE_MEMBERS))
    assert _run(gate, a, b) == 2
    assert "no wheels" in capsys.readouterr().err


def test_no_rebuilt_wheels_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    a, b = tmp_path / "shipped", tmp_path / "rebuilt"
    _write_wheel(a / WHEEL, dict(BASE_MEMBERS))
    b.mkdir()
    assert _run(gate, a, b) == 2


def test_a_missing_directory_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    a = tmp_path / "shipped"
    _write_wheel(a / WHEEL, dict(BASE_MEMBERS))
    assert _run(gate, a, tmp_path / "does-not-exist") == 2


# --------------------------------------------------------------------------
# The gate has to be wired into the release, or it protects nothing
# --------------------------------------------------------------------------


def test_the_release_workflow_actually_runs_this_gate() -> None:
    """A verifier release.yml does not call is the hole it was written to close."""
    release = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "verify_wheel_reproducible.py" in release, (
        "release.yml does not invoke tools/verify_wheel_reproducible.py. The whole "
        "point of this gate is that the PR-time reproducibility job never ran on "
        "the released artefacts; adding a verifier nothing calls repeats that."
    )


def test_publishing_depends_on_the_verification() -> None:
    """Running it but not gating on it would be the same hole with more steps."""
    release = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for job in ("publish-pypi:", "github-release:"):
        assert job in release, f"{job} vanished from release.yml"
    # Both publishing jobs must list the verification among their needs.
    for job_name in ("publish-pypi", "github-release"):
        start = release.index(f"  {job_name}:")
        block = release[start : start + 1200]
        assert "verify-reproducible-wheel" in block, (
            f"{job_name} does not depend on verify-reproducible-wheel, so a wheel "
            f"that failed the comparison could still be published."
        )
