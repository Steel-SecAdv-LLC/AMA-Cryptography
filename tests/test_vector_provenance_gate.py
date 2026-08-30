# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_vector_provenance.py``.

The incident: this repository's own pre-commit hooks rewrote its test
vectors.  The KAT format spells an empty field as a key followed by a
trailing space, so ``trailing-whitespace`` turned ``PT = `` into ``PT =``
across ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and Ascon —
19 files no longer matching what NIST published.

What made it worth a gate: **nothing detected it**.  On the rewritten tree
the corpus generators' ``--check``, ``check_corpus_originality.py``,
``check_vendor_isolation.py`` and all 135 KAT tests still passed.

The gate was verified against that exact corruption rather than a mock: the
whitespace strip was reapplied to ``tests/kat/ascon/ascon_aead128.kat``, and
the gate failed naming the file and the 260,253 -> 260,220 byte delta.  The
mutation was reverted.

ANCHOR_DIGESTS below is the part that does not live in the manifest.  A
manifest committed alongside the files it pins can be regenerated to match
corrupted files; these assertions sit in the test source, so regenerating the
manifest alone leaves them failing.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_vector_provenance.py"

#: Digests recorded independently of the manifest, so that rewriting the
#: manifest is not sufficient to make a corrupted vector look correct.  One
#: file per published family.
ANCHOR_DIGESTS: dict[str, tuple[str, int]] = {
    "tests/kat/ascon/ascon_aead128.kat": (
        "bbbc34692fe05e5fda0a3b025585622ab3e3747495e5e3655b29aae8c2a4bd33",
        260253,
    ),
    "tests/kat/fips203/ml_kem_1024.kat": (
        "12eb413b3aaf8fc4b972f71a98e30906a21c77b13ac0ca0d972bc524d8f0b27b",
        1290400,
    ),
    "tests/kat/fips204/ml_dsa_65.kat": (
        "34286eb745b5f1d5844370f543f6e51a92bd47fcb964cdebbf075c615eb1cbb0",
        2238625,
    ),
    "ama_cryptography/_post_kats/slh_dsa_shake_128s_sigver.json": (
        "d07f443b7dab059e6f61e5b862ccd46b1fb8595cdb9e3dabff2b899a3d296b3a",
        30763,
    ),
}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_vector_provenance", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


# --------------------------------------------------------------------------
# The tree as it stands
# --------------------------------------------------------------------------


def test_the_tree_matches_its_manifest(gate: ModuleType) -> None:
    assert gate.main([]) == 0


def test_the_manifest_exists_and_covers_every_protected_root(gate: ModuleType) -> None:
    recorded = json.loads(gate.MANIFEST_PATH.read_text(encoding="utf-8"))
    for root in gate.PROTECTED:
        assert any(
            k.startswith(root + "/") for k in recorded["files"]
        ), f"{root} is declared protected but has no pinned file"


def test_every_protected_root_is_real_and_populated(gate: ModuleType) -> None:
    """A root that has moved would silently protect nothing."""
    for root, reason in gate.PROTECTED.items():
        directory = REPO_ROOT / root
        assert directory.is_dir(), f"{root} has moved; it is pinned as: {reason}"
        assert any(p.is_file() for p in directory.rglob("*")), f"{root} is empty"


def test_wycheproof_is_deliberately_not_double_pinned(gate: ModuleType) -> None:
    """It has its own manifest and its own upstream re-fetch.

    Two pins over one tree is two things to keep in step, and the second one
    to drift is the one nobody reads.
    """
    assert "wycheproof_vectors" not in gate.PROTECTED
    assert (REPO_ROOT / "wycheproof_vectors" / "manifest.json").is_file()


# --------------------------------------------------------------------------
# The anchors — deliberately not read from the manifest
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("relative", "expected"), sorted(ANCHOR_DIGESTS.items()))
def test_anchor_files_still_hash_to_their_recorded_digest(
    relative: str, expected: tuple[str, int]
) -> None:
    """Regenerating the manifest does not satisfy these.

    The digest and the size are both asserted: the corruption this gate
    exists for changed the size too (260,253 -> 260,220 on the Ascon AEAD
    vectors), and a size mismatch is the more legible half of the report.
    """
    path = REPO_ROOT / relative
    assert path.is_file(), f"{relative} is gone; it is an anchor for this gate"
    digest, size = expected
    assert path.stat().st_size == size, f"{relative} changed size"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, (
        f"{relative} no longer hashes to its recorded digest. These bytes are "
        f"published elsewhere; a change here is a corrupted vector unless it was "
        f"deliberate, and a deliberate one must update this test as well as the "
        f"manifest."
    )


def test_the_anchors_span_every_published_family(gate: ModuleType) -> None:
    """One anchor in a single directory would leave the rest unguarded."""
    roots = {r for r in gate.PROTECTED for k in ANCHOR_DIGESTS if k.startswith(r + "/")}
    assert len(roots) >= 2, f"anchors only cover {roots}"
    families = {Path(k).parent.name for k in ANCHOR_DIGESTS}
    assert len(families) >= 4, f"anchors only cover {families}"


# --------------------------------------------------------------------------
# Mutations the gate must reject
# --------------------------------------------------------------------------


def test_an_edited_vector_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The historical corruption, in miniature: one byte of trailing whitespace."""
    root = tmp_path / "vectors"
    root.mkdir()
    for i in range(gate.MIN_FILES):
        (root / f"v{i}.kat").write_text(f"PT = \nCT = {i}\n", encoding="utf-8")
    manifest = tmp_path / "PROVENANCE.json"
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", manifest)
    monkeypatch.setattr(gate, "PROTECTED", {"vectors": "synthetic"})
    assert gate.main(["--update"]) == 0
    assert gate.main([]) == 0

    victim = root / "v0.kat"
    victim.write_text(
        victim.read_text(encoding="utf-8").replace("PT = \n", "PT =\n"), encoding="utf-8"
    )
    assert gate.main([]) == 1
    assert "CHANGED" in capsys.readouterr().err


def test_an_unpinned_new_vector_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A tree that can grow past its manifest drifts out from under the gate."""
    root = tmp_path / "vectors"
    root.mkdir()
    for i in range(gate.MIN_FILES):
        (root / f"v{i}.kat").write_text(f"x{i}\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", tmp_path / "PROVENANCE.json")
    monkeypatch.setattr(gate, "PROTECTED", {"vectors": "synthetic"})
    assert gate.main(["--update"]) == 0
    (root / "brand_new.kat").write_text("unpinned\n", encoding="utf-8")
    assert gate.main([]) == 1
    assert "not pinned" in capsys.readouterr().err


def test_a_deleted_vector_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A pinned file that is gone must be named, not absorbed.

    The fixture holds MIN_FILES + 5 so that removing one still clears the
    vacuity floor. That ordering is deliberate in the gate: a tree that has
    shrunk below the floor is reported as unreadable (exit 2) before any
    per-file comparison, because a comparison over a tree that was not really
    read is the failure this gate's floor exists to prevent. The real tree
    holds 30 files against a floor of 20 (tests/kat/PROVENANCE.json vs
    MIN_FILES), so an ordinary deletion lands here, at exit 1, with the path
    named.
    """
    root = tmp_path / "vectors"
    root.mkdir()
    for i in range(gate.MIN_FILES + 5):
        (root / f"v{i}.kat").write_text(f"x{i}\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", tmp_path / "PROVENANCE.json")
    monkeypatch.setattr(gate, "PROTECTED", {"vectors": "synthetic"})
    assert gate.main(["--update"]) == 0
    (root / "v0.kat").unlink()
    assert gate.main([]) == 1
    assert "missing from the tree" in capsys.readouterr().err


def test_a_tree_it_could_not_read_fails_closed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Too few files is not a clean tree; it is a tree that was not read."""
    root = tmp_path / "vectors"
    root.mkdir()
    (root / "only.kat").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", tmp_path / "PROVENANCE.json")
    monkeypatch.setattr(gate, "PROTECTED", {"vectors": "synthetic"})
    assert gate.main([]) == 2


def test_a_missing_root_fails_closed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", tmp_path / "PROVENANCE.json")
    monkeypatch.setattr(gate, "PROTECTED", {"absent": "synthetic"})
    assert gate.main([]) == 2


def test_a_missing_manifest_fails_closed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "vectors"
    root.mkdir()
    for i in range(gate.MIN_FILES):
        (root / f"v{i}.kat").write_text(f"x{i}\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "MANIFEST_PATH", tmp_path / "absent.json")
    monkeypatch.setattr(gate, "PROTECTED", {"vectors": "synthetic"})
    assert gate.main([]) == 2
