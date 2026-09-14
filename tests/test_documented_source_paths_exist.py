# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A document that names a source file must name one that exists.

WHY THIS TEST EXISTS

This repository treats a false documented claim as a defect, and a path is the
most mechanically checkable claim a document makes.  Nothing checked them.
``tools/check_documented_counts.py`` verifies the NUMBERS in the documentation
and says nothing about the file names beside them, so a renamed or imagined
source file could sit in a document indefinitely — and did.

Measured across the 56 tracked ``.md`` files (``CHANGELOG.md`` excluded, see
below): **215** distinct cited source paths, **12** of which did not exist.
Five of those twelve are the run-produced outputs and the one placeholder that
:data:`RUN_PRODUCED` records.  The other seven were genuine:

* ``wiki/Performance-Benchmarks.md`` cited four AVX2 kernels by names no file
  has had — ``ama_sha3_x4_avx2.c``, ``ama_aes_gcm_vaes.c``,
  ``ama_chacha20_x8_avx2.c``, ``ama_argon2_g_avx2.c`` — as the "Reference"
  column of the table a reader consults to find the kernel behind a number.
* The same file promised results in ``benchmarks/regression_results.json``,
  which nothing writes: ``benchmark_runner.py``'s ``--output`` has no default.
* ``src/c/PROVENANCE.md`` stated that the dudect regression tests "are run
  under ``tests/test_constant_time.py``" — a file that does not exist, in the
  document that records the provenance and side-channel posture of the
  vendored C sources.
* ``INVARIANTS.md`` cited ``tests/c/test_ed25519_canonical_y.c`` rhetorically
  ("-style coverage lives in ...") while naming a file that never existed.

A path only counts if it is spelled with its directory, and two of the
findings above were not.  ``ENHANCED_FEATURES.md``'s AVX2 table credited
Ed25519 with a kernel file — ``ama_ed25519_avx2.c`` — that has never existed
(the AVX2 curve kernel is ``ama_x25519_avx2.c``, and it is X25519), and its
CI section documented a ``docker.yml`` workflow that does not exist either;
the Docker build is a job inside ``ci-build-test.yml``.  Both were invisible
to a directory-anchored pattern, so bare filenames are checked too, by
basename against the tracked file list.

WHAT IT ENFORCES

Every backtick-quoted path under a real source directory, in every tracked
``.md`` file, resolves on disk — unless it is in :data:`RUN_PRODUCED`, which is
for paths a document correctly describes as the OUTPUT of a command rather than
a file in the tree.  Each entry there names the command that writes it, so the
allowlist is a statement about the tree rather than a place to hide a typo.

Every backtick-quoted bare filename with a source-ish extension must match the
basename of a tracked file, unless it is in :data:`NOT_IN_TREE` — for the
runtime artefacts, run-produced outputs, external SDK headers and one
deliberate historical reference that legitimately are not in this repository.
Each entry there says which of those it is.

``CHANGELOG.md`` is excluded, and deliberately: it is a historical record, and
an entry describing a file that a later release renamed or deleted is accurate
about the past.  Rewriting it to satisfy a gate would falsify the history the
document exists to keep.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Directories that hold real, tracked source. A path under one of these is a
#: claim about the tree; a path anywhere else may be a user's own file, a
#: temporary, or an example, and is not this test's business.
SOURCE_DIRS = (
    "src",
    "include",
    "tests",
    "tools",
    "benchmarks",
    "cmake",
    "fuzz",
    "docker",
    "schemas",
    "examples",
    "wycheproof_vectors",
    "nist_vectors",
)

_PATH_RE = re.compile(r"`((?:" + "|".join(SOURCE_DIRS) + r")/[A-Za-z0-9_./+-]+\.[A-Za-z0-9_+]+)`")

#: Paths a document names as the OUTPUT of a command, not as a tracked file.
#: Each value is the command that produces it — the justification, not a label.
RUN_PRODUCED = {
    "benchmarks/performance_results.json": "written by benchmarks/performance_suite.py",
    "benchmarks/benchmark_c_raw_results.json": (
        "written by the raw-C harness; benchmarks/generate_charts.py reads it "
        "'when present' and falls back to checked-in anchors"
    ),
    "nist_vectors/results.json": "written by nist_vectors/run_vectors.py",
    "nist_vectors/validation_summary.json": (
        "written by .github/workflows/acvp_validation.yml after run_vectors.py"
    ),
    # A placeholder inside a quoted description of check_documented_counts.py's
    # own claim pattern (``  `tests/x.py` - N tests ``), not a file reference.
    "tests/x.py": "placeholder in a quoted description of the gate's claim pattern",
}

#: Extensions worth checking when a document names a file without its
#: directory.  Prose names plenty of other things in backticks; these are the
#: ones that are a claim about a file in this tree.
_BARE_EXTENSIONS = (
    "c",
    "h",
    "py",
    "pyx",
    "pxd",
    "yml",
    "yaml",
    "cmake",
    "json",
    "toml",
    "cfg",
    "txt",
    "sh",
    "ps1",
    "md",
    "map",
    "in",
)

_BARE_RE = re.compile(r"`([A-Za-z0-9_.+-]+\.(?:" + "|".join(_BARE_EXTENSIONS) + r"))`")

#: Bare filenames a document names that are deliberately not files in this
#: repository.  The value says which kind, so the entry is reviewable.
NOT_IN_TREE = {
    ".kdf_metadata.json": (
        "runtime artefact: written under the caller's storage_path by "
        "ama_cryptography/key_management.py"
    ),
    "CRYPTO_PACKAGE.json": "runtime artefact: written by the CLI run IMPLEMENTATION_GUIDE.md shows",
    "seed.txt": (
        "runtime artefact: written, then explicitly deleted, by the operator "
        "procedure in SECURITY.md"
    ),
    "BENCHMARKS.md": "run-produced: benchmarks/benchmark_suite.py --markdown default",
    "benchmark_results.json": "run-produced: benchmarks/benchmark_suite.py --json default",
    "results.json": "run-produced: nist_vectors/run_vectors.py",
    "validation_summary.json": "run-produced: .github/workflows/acvp_validation.yml",
    "internalProjection.json": "external: pulled from the upstream ACVP repository",
    "synchapi.h": "external: Windows SDK header, named for InitOnceExecuteOnce",
    "ama_sphincs.c": (
        "historical: CSRC_ALIGN_REPORT.md says in the same sentence that it "
        "existed at the audit date and was deleted in v3.3.0 (#362)"
    ),
}


#: Historical record; see the module docstring.
EXCLUDED_FILES = {"CHANGELOG.md"}


def _tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    return [REPO_ROOT / f for f in out if Path(f).name not in EXCLUDED_FILES]


DOCS = _tracked_markdown()


def test_there_are_documents_to_check() -> None:
    """Non-vacuity: an empty file list would make every assertion below pass."""
    assert len(DOCS) > 20, f"only {len(DOCS)} markdown files found — the glob is wrong"


def test_the_corpus_of_cited_paths_is_substantial() -> None:
    """Non-vacuity again: if the regex stopped matching, nothing would be checked."""
    cited = {
        m for d in DOCS for m in _PATH_RE.findall(d.read_text(encoding="utf-8", errors="replace"))
    }
    assert len(cited) > 200, (
        f"only {len(cited)} distinct source paths matched across {len(DOCS)} documents; "
        f"the pattern has stopped seeing the citations it is meant to check"
    )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_source_path_a_document_cites_exists(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8", errors="replace")
    missing = sorted(
        {
            m
            for m in _PATH_RE.findall(text)
            if m not in RUN_PRODUCED and not (REPO_ROOT / m).exists()
        }
    )
    assert not missing, (
        f"{doc.relative_to(REPO_ROOT)} cites {missing}, which do not exist. A document "
        f"that names a source file must name one that exists — a reader following the "
        f"citation finds nothing, and a reviewer cannot check the claim beside it. "
        f"Correct the path, or add it to RUN_PRODUCED with the command that writes it "
        f"if the document is describing an output rather than a tracked file."
    )


def test_the_allowlist_has_no_stale_entry() -> None:
    """An entry for a path that now exists, or that no document cites, is dead."""
    cited = {
        m for d in DOCS for m in _PATH_RE.findall(d.read_text(encoding="utf-8", errors="replace"))
    }
    for path, why in RUN_PRODUCED.items():
        assert path in cited, f"RUN_PRODUCED lists {path!r} but no document cites it ({why})"
        assert not (REPO_ROOT / path).exists(), (
            f"RUN_PRODUCED lists {path!r} as run-produced, but it exists in the tree; "
            f"remove the entry so the path is checked like any other"
        )


def _tracked_basenames() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    return {Path(f).name for f in out}


TRACKED_BASENAMES = _tracked_basenames()


def test_the_tracked_basename_set_is_substantial() -> None:
    """Non-vacuity: an empty set would make the bare-filename check pass on anything."""
    assert len(TRACKED_BASENAMES) > 400, (
        f"only {len(TRACKED_BASENAMES)} tracked basenames; git ls-files is not "
        f"returning the tree"
    )


def test_the_corpus_of_bare_filenames_is_substantial() -> None:
    """Non-vacuity: if the pattern stopped matching, nothing below would be checked."""
    cited = {
        m
        for d in DOCS
        for m in _BARE_RE.findall(d.read_text(encoding="utf-8", errors="replace"))
        if "/" not in m
    }
    assert len(cited) > 100, (
        f"only {len(cited)} distinct bare filenames matched across {len(DOCS)} "
        f"documents; the pattern has stopped seeing the citations it must check"
    )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_bare_filename_a_document_cites_exists(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8", errors="replace")
    missing = sorted(
        {
            m
            for m in _BARE_RE.findall(text)
            if "/" not in m and m not in NOT_IN_TREE and m not in TRACKED_BASENAMES
        }
    )
    assert not missing, (
        f"{doc.relative_to(REPO_ROOT)} cites {missing}; no tracked file has that "
        f"name. A document that names a source file must name one that exists — "
        f"ENHANCED_FEATURES.md credited Ed25519 with an `ama_ed25519_avx2.c` that "
        f"never existed, and documented a `docker.yml` workflow that is a job in "
        f"ci-build-test.yml. Correct the name, or add it to NOT_IN_TREE with "
        f"which kind of non-file it is."
    )


def test_the_not_in_tree_allowlist_has_no_stale_entry() -> None:
    """An entry for a name that now exists, or that no document cites, is dead."""
    cited = {
        m
        for d in DOCS
        for m in _BARE_RE.findall(d.read_text(encoding="utf-8", errors="replace"))
        if "/" not in m
    }
    for name, why in NOT_IN_TREE.items():
        assert name in cited, f"NOT_IN_TREE lists {name!r} but no document cites it ({why})"
        assert name not in TRACKED_BASENAMES, (
            f"NOT_IN_TREE lists {name!r} as absent from the tree, but a tracked file "
            f"has that name; remove the entry so it is checked like any other"
        )
