# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Run the code blocks the documentation prints.

Why
---
``docs/KEY_FORMATS.md``'s "Using it" block — the first thing a new user copies —
called ``jwk_thumbprint(jwk)`` without importing it, and imported ``load_spki``
without using it. Both are the same symptom: nothing executed the example, so
it drifted the moment the API around it moved.

``tools/check_documented_counts.py`` already re-derives every *count* the
documentation pins, on the argument that "a documented number that has quietly
gone wrong is worse than no number, because a reader takes it as evidence".
A documented *example* is a stronger claim than a number — it asserts that this
exact sequence of calls works — and it had no check at all.

How
---
The fenced ``python`` blocks are extracted from the markdown and executed, in a
temporary working directory so the examples' file writes do not touch the tree.
Extracting rather than duplicating is the point: a copy in a test file is a
second thing to keep true, which is the defect this module exists to close.

Blocks that are deliberately illustrative rather than runnable — a shell
transcript, a fragment with an ellipsis, an intentional failure — are skipped by
an explicit marker so the skip is visible in the document rather than implied by
this file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Documents whose python blocks must run. Deliberately a short, curated list:
#: the value is in the examples a user copies first, and sweeping every markdown
#: file in the tree would drown that in prose fragments.
DOCUMENTS = ("docs/KEY_FORMATS.md",)

#: A block opening with this comment is prose, not a program.
SKIP_MARKER = "# doc-example: not runnable"

_BLOCK_RE = re.compile(r"^```python\n(.*?)^```", re.M | re.S)


def _blocks(relative: str) -> list[tuple[int, str]]:
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    out: list[tuple[int, str]] = []
    for match in _BLOCK_RE.finditer(text):
        body = match.group(1)
        if SKIP_MARKER in body:
            continue
        line = text.count("\n", 0, match.start()) + 1
        out.append((line, body))
    return out


def _cases() -> list[tuple[str, int, str]]:
    return [(doc, line, body) for doc in DOCUMENTS for line, body in _blocks(doc)]


CASES = _cases()


def test_there_are_examples_to_run() -> None:
    """Non-vacuity: an extractor that finds nothing would pass silently."""
    assert CASES, f"no runnable python blocks found in {DOCUMENTS}"


@pytest.mark.parametrize(
    ("document", "line", "source"),
    CASES,
    ids=[f"{doc}:{line}" for doc, line, _ in CASES],
)
def test_the_documented_example_runs(
    document: str, line: int, source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Executed verbatim, in a scratch directory.

    A failure here means the document is wrong, not that the test is: the
    document is the thing a user runs.
    """
    monkeypatch.chdir(tmp_path)
    namespace: dict[str, object] = {"__name__": "__doc_example__"}
    # `exec` is the point of this module: the documentation's own code is what
    # has to run, and any indirection would be running something else. The
    # source is a reviewed file in this repository, not input.
    try:
        exec(  # noqa: S102 -- running the documentation verbatim is the test (DOC-001)
            compile(source, f"{document}:{line}", "exec"), namespace
        )
    except Exception as exc:  # pragma: no cover - the assertion carries the message
        raise AssertionError(
            f"the python block at {document}:{line} does not run: " f"{type(exc).__name__}: {exc}"
        ) from exc
