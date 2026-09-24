# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every page that restates a published figure is pinned, not only the README.

Until 2026-09-24 ``tools/check_published_benchmarks.py`` read one region of one
file.  The wiki's per-algorithm pages printed their own throughput figures —
``wiki/Cryptography-Algorithms.md`` gave ML-DSA-65 signing as 3,639 ops/sec and
SHA3-256 as ~1,046,450, ``wiki/Post-Quantum-Cryptography.md`` gave ML-DSA-65
signing as 981 — 4.x-era numbers that no record held and no gate read.  They
now restate rows of the README's CI table, inside the same markers, and the
record names every page it pins.

Each test below drives the gate with a deliberately broken copy of the real
tree and requires the specific non-zero exit.  Each was mutation-checked
(AGENTS.md section 6.2): with the mechanism its docstring names removed from the
gate, the test fails.  Where a property is enforced twice, the docstring says
so (section 6.3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools import check_published_benchmarks as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

CRYPTO_ALGORITHMS = "wiki/Cryptography-Algorithms.md"
PQC = "wiki/Post-Quantum-Cryptography.md"

#: One line of each newly pinned region, as the page prints it.
MLDSA_SIGN_BULLET = "- Signing (`dilithium_sign`): 3,135 / 3,604"
MLDSA_VERIFY_BULLET = "- Verification (`dilithium_verify`): 10,381 / 11,675"
ED25519_SIGN_FIGURES = "38,811 / 32,846"
SHA3_SENTENCE = "363,574 on `ubuntu-latest` x86_64, 436,428 on"
PQC_VERIFY_ROW = "| Verification (`dilithium_verify`) | 10,381 | 11,675 |"
README_SHA3_ROW = "| 363,574 (362,192–484,921) | 436,428 (433,513–436,658) |"


def _record(root: Path) -> dict[str, Any]:
    loaded = json.loads((root / gate.RECORD).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_record(root: Path, record: dict[str, Any]) -> None:
    (root / gate.RECORD).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A copy of the record and every page it pins; the copy passes before it is broken."""
    for relative in [*_record(REPO_ROOT)["documents"], gate.RECORD]:
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_text(
            (REPO_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8"
        )
    assert _run(tmp_path) == 0
    return tmp_path


def _run(root: Path) -> int:
    return gate.main(["--repo", str(root)])


def _edit(root: Path, document: str, old: str, new: str) -> None:
    path = root / document
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, (document, old)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


class TestTheNewPagesAreListed:
    """The coverage this change adds is in the committed record, not only in a test tree."""

    def test_the_record_pins_the_wiki_pages(self) -> None:
        documents = _record(REPO_ROOT)["documents"]
        assert documents[0] == gate.README
        assert CRYPTO_ALGORITHMS in documents
        assert PQC in documents

    def test_the_retired_wiki_figures_are_gone(self) -> None:
        """The 4.x-era copies this change replaced must not come back unpinned."""
        crypto = (REPO_ROOT / CRYPTO_ALGORITHMS).read_text(encoding="utf-8")
        pqc = (REPO_ROOT / PQC).read_text(encoding="utf-8")
        for retired in ("5,536", "3,639", "6,490", "10,600", "1,046,450"):
            assert retired not in crypto, retired
        for retired in ("4,554", "| 981 |", "4,809"):
            assert retired not in pqc, retired


class TestAnEditOnAnyPinnedPageFails:
    """Mechanism: the gate reads every listed document, and every region in each."""

    @pytest.mark.parametrize(
        ("document", "old", "new"),
        [
            # The first region of the page.
            (CRYPTO_ALGORITHMS, MLDSA_SIGN_BULLET, "- Signing (`dilithium_sign`): 4,135 / 3,604"),
            # The second and third regions of the same page: a gate that read
            # only the first region of a document passes both.
            (CRYPTO_ALGORITHMS, ED25519_SIGN_FIGURES, "38,811 / 42,846"),
            (CRYPTO_ALGORITHMS, SHA3_SENTENCE, "463,574 on `ubuntu-latest` x86_64, 436,428 on"),
            # A table on the other page.
            (PQC, PQC_VERIFY_ROW, "| Verification (`dilithium_verify`) | 10,381 | 12,675 |"),
        ],
    )
    def test_an_edited_figure_fails(self, tree: Path, document: str, old: str, new: str) -> None:
        _edit(tree, document, old, new)
        assert _run(tree) == 1

    @pytest.mark.parametrize(
        ("document", "line"),
        [(CRYPTO_ALGORITHMS, MLDSA_VERIFY_BULLET), (PQC, PQC_VERIFY_ROW)],
    )
    def test_a_deleted_figure_fails(self, tree: Path, document: str, line: str) -> None:
        _edit(tree, document, line + "\n", "")
        assert _run(tree) == 1

    @pytest.mark.parametrize(
        "added",
        [
            "- Batch verification (`ed25519_batch_verify`): 99,999 / 99,999",
            "- Signing is 2.5× faster than the 4.x release",
        ],
    )
    def test_an_invented_figure_fails(self, tree: Path, added: str) -> None:
        _edit(tree, CRYPTO_ALGORITHMS, MLDSA_VERIFY_BULLET, f"{MLDSA_VERIFY_BULLET}\n{added}")
        assert _run(tree) == 1


class TestFiguresCannotTradePlaces:
    """An edit that keeps the multiset of figures is still an edit."""

    def test_swapping_the_two_columns_of_a_readme_row_fails(self, tree: Path) -> None:
        """Mechanism: ``position``.  The x86_64 and aarch64 medians of one row."""
        _edit(
            tree,
            gate.README,
            README_SHA3_ROW,
            "| 436,428 (362,192–484,921) | 363,574 (433,513–436,658) |",
        )
        assert _run(tree) == 1

    def test_swapping_the_two_figures_of_a_bullet_fails(self, tree: Path) -> None:
        """Mechanism: ``position``.  x86_64 and aarch64 in one list item."""
        _edit(
            tree,
            CRYPTO_ALGORITHMS,
            MLDSA_SIGN_BULLET,
            "- Signing (`dilithium_sign`): 3,604 / 3,135",
        )
        assert _run(tree) == 1

    def test_swapping_the_figures_of_two_bullets_fails(self, tree: Path) -> None:
        """Mechanism: a list item is labelled by its text up to the colon.

        Labelled ``(prose)``, signing's figures and verification's could trade
        lines and leave every (label, position, value) key in place.
        """
        _edit(
            tree,
            CRYPTO_ALGORITHMS,
            f"{MLDSA_SIGN_BULLET}\n{MLDSA_VERIFY_BULLET}",
            "- Signing (`dilithium_sign`): 10,381 / 11,675\n"
            "- Verification (`dilithium_verify`): 3,135 / 3,604",
        )
        assert _run(tree) == 1


class TestTheDocumentIsPartOfTheIdentity:
    def test_a_record_entry_moved_to_another_page_fails(self, tree: Path) -> None:
        """Mechanism: ``document`` in the key.

        One README figure re-filed under a wiki page: the README now prints a
        figure its record no longer holds, and the record holds one the wiki
        does not print.  Without ``document`` in the key both still match.
        """
        record = _record(tree)
        entry = next(e for e in record["measurements"] if e["document"] == gate.README)
        entry["document"] = PQC
        _write_record(tree, record)
        assert _run(tree) == 1

    def test_a_restated_figure_moves_with_the_readme(self, tree: Path) -> None:
        """Mechanism: ``check_restatements``.

        The README's dilithium_sign median re-based consistently — page and
        record together — while the wiki copies keep the old value.  Every page
        agrees with its own entries; the wiki no longer agrees with the table
        it restates.
        """
        _edit(tree, gate.README, "| 3,135 (3,106–3,905) |", "| 3,136 (3,106–3,905) |")
        record = _record(tree)
        moved = [
            e
            for e in record["measurements"]
            if e["document"] == gate.README and e["value"] == "3,135"
        ]
        assert len(moved) == 1
        moved[0]["value"] = "3,136"
        _write_record(tree, record)
        assert _run(tree) == 1


class TestCoverageCannotLapseQuietly:
    def test_markers_on_an_unlisted_page_fail(self, tree: Path) -> None:
        """Mechanism: the stray-marker search.  Read as pinned, pinned by nothing."""
        page = tree / "docs" / "NEW_PAGE.md"
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text(
            f"# New\n\n{gate.BEGIN_MARKER}\nSigning: 9,999 ops/sec\n{gate.END_MARKER}\n",
            encoding="utf-8",
        )
        assert _run(tree) == 1

    def test_an_entry_naming_an_unlisted_page_fails(self, tree: Path) -> None:
        """Redundant (section 6.3): the record-to-published direction also rejects it."""
        record = _record(tree)
        record["measurements"].append(
            {**record["measurements"][0], "document": "wiki/Home.md", "position": 0}
        )
        _write_record(tree, record)
        assert _run(tree) == 1

    @pytest.mark.parametrize("document", [CRYPTO_ALGORITHMS, PQC])
    def test_a_listed_page_that_loses_its_markers_exits_two(
        self, tree: Path, document: str
    ) -> None:
        """Enforced twice (section 6.3), measured by removing each check and then both.

        A page with no markers is refused as malformed, and a page whose
        regions hold no figure is refused as empty; either alone keeps this
        test passing, and removing both fails it.
        """
        path = tree / document
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(gate.BEGIN_MARKER, "").replace(gate.END_MARKER, ""), encoding="utf-8"
        )
        assert _run(tree) == 2

    def test_a_listed_page_that_is_missing_exits_two(self, tree: Path) -> None:
        (tree / PQC).unlink()
        assert _run(tree) == 2

    @pytest.mark.parametrize(
        "mutate",
        [
            # A second begin with no end after it.
            lambda text: text + f"\n{gate.BEGIN_MARKER}\n",
            # An end with no begin before it, at the top of the page ...
            lambda text: f"{gate.END_MARKER}\n" + text,
            # ... and after the last region closed.
            lambda text: text + f"\n{gate.END_MARKER}\n",
            # A region opened inside another.
            lambda text: text.replace(
                gate.BEGIN_MARKER, f"{gate.BEGIN_MARKER}\n{gate.BEGIN_MARKER}", 1
            ),
        ],
        ids=["unclosed", "stray-end-first", "stray-end-last", "nested"],
    )
    def test_malformed_markers_exit_two(self, tree: Path, mutate: Any) -> None:
        """Unbalanced markers would leave part of the page outside the check."""
        path = tree / CRYPTO_ALGORITHMS
        path.write_text(mutate(path.read_text(encoding="utf-8")), encoding="utf-8")
        assert _run(tree) == 2

    @pytest.mark.parametrize(
        "documents",
        [None, [], [CRYPTO_ALGORITHMS, PQC], [gate.README, PQC, PQC]],
        ids=["absent", "empty", "no-readme", "duplicate"],
    )
    def test_a_malformed_documents_list_exits_two(self, tree: Path, documents: Any) -> None:
        """README.md is always pinned; the list cannot be emptied or dropped."""
        record = _record(tree)
        if documents is None:
            del record["documents"]
        else:
            record["documents"] = documents
        _write_record(tree, record)
        assert _run(tree) == 2

    def test_an_entry_without_a_document_fails(self, tree: Path) -> None:
        record = _record(tree)
        del record["measurements"][0]["document"]
        _write_record(tree, record)
        assert _run(tree) == 1
