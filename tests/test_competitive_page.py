# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed competitive page must be what its generator produces.

``benchmarks/competitive.html`` is rendered by
``benchmarks/generate_competitive.py`` from two checked-in JSON records, but
nothing regenerated it on change and nothing compared it to a fresh render —
which is how commit ``4c3dcfa`` corrected the generator's footer (the page
claimed "nothing is hand-entered" on the line where eight of nine peer-library
versions are string literals) while the committed page kept the falsehood for
two further days. A page that is a pure function of data beside it must be
gated as one.

The second class of defect this file pins: the hand-written ``NOTES`` prose
carried ranks that contradicted the generated badges in the same table row —
"Last of six" beside a row whose own badge read "fastest of 6". Prose is not
generated, so it needs its own reconciliation against the data.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE = REPO_ROOT / "benchmarks" / "competitive.html"
RESULTS = REPO_ROOT / "benchmarks" / "multi_library_results.json"

#: The one render-time value that legitimately differs between two renders of
#: identical inputs: the "Generated <date> <time> UTC" stamp.
_GEN_STAMP_RE = re.compile(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")

#: Rank phrases the NOTES prose uses.  Word ordinals cover the forms in use;
#: a numeric "3rd of 8" is matched separately.  "fastest"/"last" map to the
#: first and final rank.
_WORD_ORDINALS = {
    "first": 1,
    "second": 2,
    "third": 3,
    "fourth": 4,
    "fifth": 5,
    "sixth": 6,
    "seventh": 7,
    "eighth": 8,
    "fastest": 1,
}
_WORD_COUNTS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
}
_RANK_PHRASE_RE = re.compile(
    r"\b(?P<ord>first|second|third|fourth|fifth|sixth|seventh|eighth|fastest|last"
    r"|(?P<num>\d+)(?:st|nd|rd|th))"
    r"\s+of\s+"
    r"(?P<count>\d+|one|two|three|four|five|six|seven|eight|nine)\b",
    re.IGNORECASE,
)


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_competitive", REPO_ROOT / "benchmarks" / "generate_competitive.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_generator()


def _ranks() -> dict[str, tuple[int, int]]:
    """``{primitive: (AMA rank by ops/sec desc, row size)}`` from the record."""
    by: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for row in json.loads(RESULTS.read_text(encoding="utf-8"))["results"]:
        by[row["primitive"]].append((row["library"], row["ops_per_sec"]))
    out: dict[str, tuple[int, int]] = {}
    for primitive, rows in by.items():
        ordered = sorted(rows, key=lambda r: -r[1])
        for position, (library, _) in enumerate(ordered, start=1):
            if library == "AMA":
                out[primitive] = (position, len(ordered))
                break
    return out


class TestThePageIsAFreshRender:
    def test_the_committed_page_matches_the_generator_modulo_timestamp(
        self, generator: ModuleType
    ) -> None:
        """One substitution — the render stamp — and the bytes must agree.

        A mismatch means someone changed the generator or the JSON without
        re-rendering (the ``4c3dcfa`` failure mode), or edited the HTML by
        hand (which the page's own footer says must not happen).  The fix in
        either direction is one command:
        ``python benchmarks/generate_competitive.py``.
        """
        c, q = generator.load()
        fresh = _GEN_STAMP_RE.sub("Generated <render-time> UTC", generator.render(c, q))
        committed = _GEN_STAMP_RE.sub(
            "Generated <render-time> UTC", PAGE.read_text(encoding="utf-8")
        )
        assert committed == fresh, (
            "benchmarks/competitive.html is not a fresh render of its inputs; "
            "run: python benchmarks/generate_competitive.py"
        )

    def test_the_stamp_normalisation_actually_matched_something(self) -> None:
        """A regex that matches nothing would make the comparison above
        vacuously strict in the wrong place (two live timestamps would fail
        equality for a reason the assertion message does not name)."""
        assert _GEN_STAMP_RE.search(PAGE.read_text(encoding="utf-8"))


class TestNotesAgreeWithTheData:
    def test_every_rank_phrase_in_notes_matches_the_measured_rank(
        self, generator: ModuleType
    ) -> None:
        """Prose ranks are reconciled against the same JSON the badges use.

        Verified to fail on the defect it pins: with ``SHA3-256``'s note
        reverted to "Last of six", this test reports rank 6 claimed against
        rank 1 measured.
        """
        ranks = _ranks()
        problems: list[str] = []
        for primitive, note in generator.NOTES.items():
            if primitive not in ranks:
                continue
            measured_rank, row_size = ranks[primitive]
            for match in _RANK_PHRASE_RE.finditer(note):
                count_text = match.group("count").lower()
                claimed_count = (
                    int(count_text) if count_text.isdigit() else _WORD_COUNTS[count_text]
                )
                ordinal = match.group("ord").lower()
                if match.group("num"):
                    claimed_rank = int(match.group("num"))
                elif ordinal == "last":
                    claimed_rank = claimed_count
                else:
                    claimed_rank = _WORD_ORDINALS[ordinal]
                if claimed_count != row_size or claimed_rank != measured_rank:
                    problems.append(
                        f"{primitive}: note says {claimed_rank} of {claimed_count}, "
                        f"measured {measured_rank} of {row_size}"
                    )
        assert not problems, "\n".join(problems)

    def test_the_rank_reconciliation_is_not_vacuous(self, generator: ModuleType) -> None:
        """At least some notes must carry a rank phrase AND be reconcilable.

        Counting phrase-bearing notes alone was not enough: the test above
        does ``if primitive not in ranks: continue``, so a primitive renamed
        in benchmarks/multi_library_results.json detached every one of its
        notes from the measured ranks — the reconciliation then checked zero
        rows while this floor, satisfied by the phrases alone, stayed green.
        The floor now counts notes that actually intersect the measured set,
        and any phrase-bearing note that does NOT is itself a failure: a
        rank claim about a primitive the results no longer name is exactly
        the unreconciled prose this class exists to forbid.
        """
        ranks = _ranks()
        with_phrase = {
            primitive for primitive, note in generator.NOTES.items() if _RANK_PHRASE_RE.search(note)
        }
        reconcilable = sorted(with_phrase & set(ranks))
        orphaned = sorted(with_phrase - set(ranks))
        assert not orphaned, (
            f"these NOTES carry rank phrases but their primitives are absent from "
            f"multi_library_results.json, so the reconciliation cannot check them: "
            f"{orphaned}"
        )
        assert len(reconcilable) >= 3, reconcilable
