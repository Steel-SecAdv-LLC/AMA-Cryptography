# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The C-library SBOM records every adapted third-party source NOTICE names.

``NOTICE`` lists ``src/c/internal/ama_fe25519_safegcd.h`` as "Adapted source
(compiled in, attributed under its licence)" — the Bernstein-Yang inversion,
whose structure follows libsecp256k1's MIT-licensed ``modinv64``.  The SBOM
rendered ``ama_ed25519`` as a plain in-house component with no licence and no
pedigree, and the README's third-party section and the INVARIANT-1 addendum
said there was no third-party code in the library at all.  A licence review
reading either would have redistributed binaries without the MIT notice.

``tools/generate_sbom.py`` now carries an ``ADAPTED_SOURCES`` registry, renders
it as CycloneDX ``pedigree`` + ``licenses`` on the component that compiles the
file in, and fails closed when the registry, the source tree and ``NOTICE``
disagree.  These tests pin each direction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import generate_sbom

REPO_ROOT = Path(__file__).resolve().parent.parent
SAFEGCD = "src/c/internal/ama_fe25519_safegcd.h"


def _fixture(tmp_path: Path, *, notice: str, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for name, body in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    (repo / "NOTICE").write_text(notice, encoding="utf-8")
    return repo


_CITING = "/* structure follows libsecp256k1 (MIT licence -- see\n * NOTICE) */\n"
_GOOD_NOTICE = f"Adapted source:\n  {SAFEGCD}\n  Distributed under the MIT software licence.\n"


def test_the_real_tree_is_consistent() -> None:
    assert generate_sbom.check_adapted_sources(REPO_ROOT) == []


def test_the_committed_sbom_carries_the_pedigree() -> None:
    """The artefact a reviewer receives, not just the renderer, says MIT."""
    sbom = json.loads(
        (REPO_ROOT / "docs" / "compliance" / "sbom-c-library.json").read_text(encoding="utf-8")
    )
    ed25519 = next(c for c in sbom["components"] if c["name"] == "ama_ed25519")
    assert ed25519["licenses"] == [{"expression": "Apache-2.0 AND MIT"}]
    (ancestor,) = ed25519["pedigree"]["ancestors"]
    assert ancestor["name"] == "secp256k1"
    assert ancestor["licenses"] == [{"license": {"id": "MIT"}}]
    assert SAFEGCD in ed25519["pedigree"]["notes"]
    # Components with no adapted source stay plain: the pedigree is not noise
    # sprayed across the whole document.
    assert all("pedigree" not in c for c in sbom["components"] if c["name"] != "ama_ed25519")


def test_the_committed_sbom_is_what_the_generator_renders() -> None:
    rendered = generate_sbom.serialize(
        generate_sbom.render_sbom(generate_sbom.read_package_version())
    )
    committed = (REPO_ROOT / "docs" / "compliance" / "sbom-c-library.json").read_text(
        encoding="utf-8"
    )
    assert committed == rendered


def test_a_consistent_fixture_passes(tmp_path: Path) -> None:
    repo = _fixture(tmp_path, notice=_GOOD_NOTICE, files={SAFEGCD: _CITING})
    assert generate_sbom.check_adapted_sources(repo) == []


def test_an_unregistered_file_that_cites_notice_fails(tmp_path: Path) -> None:
    """A new adaptation cannot land without an SBOM pedigree."""
    repo = _fixture(
        tmp_path,
        notice=_GOOD_NOTICE,
        files={SAFEGCD: _CITING, "src/c/ama_new_thing.c": "/* MIT -- see NOTICE */\n"},
    )
    problems = generate_sbom.check_adapted_sources(repo)
    assert len(problems) == 1 and "src/c/ama_new_thing.c" in problems[0]


def test_a_registered_file_that_stops_citing_notice_fails(tmp_path: Path) -> None:
    repo = _fixture(tmp_path, notice=_GOOD_NOTICE, files={SAFEGCD: "/* in-house */\n"})
    problems = generate_sbom.check_adapted_sources(repo)
    assert any(SAFEGCD in p and "no longer cites" in p for p in problems)


def test_notice_must_name_the_file(tmp_path: Path) -> None:
    repo = _fixture(
        tmp_path, notice="Distributed under the MIT software licence.\n", files={SAFEGCD: _CITING}
    )
    problems = generate_sbom.check_adapted_sources(repo)
    assert problems == [f"NOTICE does not name {SAFEGCD}"]


def test_notice_must_state_the_licence(tmp_path: Path) -> None:
    repo = _fixture(tmp_path, notice=f"Adapted source:\n  {SAFEGCD}\n", files={SAFEGCD: _CITING})
    problems = generate_sbom.check_adapted_sources(repo)
    assert problems == [f"NOTICE does not state the MIT licence for {SAFEGCD}"]


def test_render_refuses_an_inconsistent_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check runs inside render_sbom, so --check and a regeneration both
    fail closed rather than writing an SBOM without the pedigree."""
    monkeypatch.setattr(
        generate_sbom, "check_adapted_sources", lambda repo=REPO_ROOT: ["planted problem"]
    )
    with pytest.raises(SystemExit, match="planted problem"):
        generate_sbom.render_sbom("5.0.0")
