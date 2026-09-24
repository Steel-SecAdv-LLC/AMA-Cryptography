#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Refuse a release whose own shipped documents still call it unreleased.

Why this gate exists
--------------------
The tree deliberately carries pre-release prose while a version is in
preparation: ``## [5.0.0] - Unreleased`` and entries under the version-less
``## [Unreleased]`` heading in the CHANGELOG, "``v5.0.0`` is not
tagged yet" in the README, "not yet tagged or published" in SECURITY.md, and
the same in the Sphinx landing page.  Every one of those statements is TRUE
during development and becomes FALSE the instant the tag is pushed — but
``release.yml``'s preflight checked only the tag shape, the tag↔version
equality, cross-file version consistency and the SBOM.  Nothing stopped a real
tag going out while shipped documents still told the reader the release had not
happened (audit M12).

Two lifecycle events, not one
-----------------------------
"Tagged" and "published to PyPI" are *separate* events in this project, and the
gate keeps them separate so it never forces a shipped falsehood in the other
direction:

* **Tag state** — "``v5.0.0`` is not tagged yet", the ``Unreleased`` CHANGELOG
  heading, entries still filed under ``## [Unreleased]``, the absence of a dated
  ``## [5.0.0] - YYYY-MM-DD`` section — becomes false the instant the annotated
  tag exists.  ``release.yml`` is triggered *by* that tag push, so at release
  time these are always false and are enforced unconditionally.

* **PyPI publish state** — "not published yet", "not yet published" (the README
  availability rows) — is decoupled.  ``release.yml``'s ``publish-pypi`` job is
  opt-in, gated on ``vars.AMA_PUBLISH_TO_PYPI == 'true'``; the project also
  ships via git tags, GitHub Release assets and a private index, so a tag can be
  cut with PyPI deliberately *not* published.  Flipping the PyPI rows on such a
  release would make the docs claim an availability that does not exist.  These
  markers are therefore enforced ONLY when ``--require-published`` is passed —
  which ``release.yml`` does exactly when ``AMA_PUBLISH_TO_PYPI`` is true.

This gate is meant to run in preflight ONLY on a tag push
(``github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')``): on a
development branch the markers are correct and must not be flagged, so the
workflow — not this tool — decides *when* to run it.  Its job here is simply to
answer "do the release-state docs still describe an unreleased version?";
clearing the markers (dating the CHANGELOG heading, flipping the availability
rows) is what a release engineer does before the tag, and this is what makes
forgetting it a failed release rather than a shipped falsehood.

Exit status
-----------
0  no enforced unreleased-state marker remains in any release-state document,
   and the CHANGELOG has a dated section for the version and an empty
   ``## [Unreleased]`` placeholder
1  at least one document still says the version is unreleased (each printed
   with its file:line and the marker matched), OR the CHANGELOG has no dated
   ``## [<version>] - YYYY-MM-DD`` heading or still holds entries under
   ``## [Unreleased]``, OR a listed document is missing (a release-state doc
   that vanished cannot be confirmed cleared)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The documents whose prose asserts release state.  Kept explicit rather than
#: swept: these are the ones a reader consults for "is it released?", and an
#: over-broad sweep of every doc would flag historical CHANGELOG entries and
#: design notes that legitimately discuss past unreleased states.
RELEASE_STATE_FILES = (
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
    "docs/index.rst",
)


def tag_state_markers(version: str) -> list[tuple[re.Pattern[str], str]]:
    """Markers that become false the instant the tag exists — always enforced.

    Tight phrasings, matched case-insensitively, so ordinary prose in these
    files is not swept up: only the specific tag-state claims the pre-tag tree
    carries.  EVERY marker is version-scoped, the CHANGELOG heading by its
    bracket and the two "not (yet) tagged" forms by requiring the current
    version on the same line as the phrase — which is how every shipped
    document writes them ("`v5.0.0` is not tagged yet", "5.0.0 is prepared
    but **not yet tagged or published**").  The two phrase markers used to
    carry no version anchor at all while ``scan()`` pointed them at the whole
    of CHANGELOG.md, so a 5.0.0 release note recording "v4.0.0 was not yet
    tagged when this landed" would have failed the release-day preflight —
    the over-broad sweep the RELEASE_STATE_FILES docstring says the curated
    list exists to avoid.  A compound assertion like SECURITY.md's "not yet
    tagged or published" is caught on its "not yet tagged" half — correct,
    because *that half* is false at tag time.
    """
    v = re.escape(version)
    tagged_yet = r"not[ \t]+tagged[ \t]+yet"
    yet_tagged = r"not[ \t]+yet[ \t]+tagged"

    def scoped(phrase: str) -> re.Pattern[str]:
        # The version may sit before or after the phrase, but on its line:
        # a marker about ANOTHER version (historical prose) must not match.
        return re.compile(rf"(?:v?{v}[^\n]*?(?:{phrase})|(?:{phrase})[^\n]*?v?{v})", re.IGNORECASE)

    return [
        (
            # The dated heading (## [x.y.z] - 2026-08-24) drops "Unreleased"; match
            # the version heading line while it still carries that word, whatever the
            # separator, rather than pinning one dash glyph.
            re.compile(rf"##\s*\[{v}\][^\n]*Unreleased", re.IGNORECASE),
            f"CHANGELOG heading still reads '## [{version}] - Unreleased'",
        ),
        (scoped(tagged_yet), f"'not tagged yet' about {version}"),
        (scoped(yet_tagged), f"'not yet tagged' about {version}"),
    ]


#: Keep a Changelog's standing placeholder heading, however it is spaced.
_UNRELEASED_HEADING_RE = re.compile(r"^##[ \t]*\[[ \t]*unreleased[ \t]*\][^\n]*$", re.IGNORECASE)

#: Any level-2 heading: where a CHANGELOG section ends.
_LEVEL_2_HEADING_RE = re.compile(r"^##(?!#)")

#: A line that records no change: blank, a Markdown thematic break, or a
#: sub-heading (an empty ``### Fixed`` is scaffolding, not an entry).
_NOT_AN_ENTRY_RE = re.compile(r"^[ \t]*(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|#.*)?$")


def changelog_problems(text: str, version: str) -> list[str]:
    """What the CHANGELOG must say at tag time, beyond the absence of a marker.

    The markers above can only refuse a statement that is PRESENT.  They could
    not see the form this CHANGELOG actually takes before a release: its notes
    sit under Keep a Changelog's version-less ``## [Unreleased]`` heading, and
    no ``## [X.Y.Z]`` heading exists at all until a release engineer writes
    one.  Tagging ``v5.0.1`` without renaming that heading matched nothing —
    ``## [5.0.1] … Unreleased`` needs the version inside the brackets — so the
    preflight passed and the tag shipped a CHANGELOG that still filed its own
    contents as unreleased (audit M12, the defect this gate exists for).

    Two requirements close that, both stated positively:

    * a dated ``## [<version>] - YYYY-MM-DD`` heading exists — the release has
      a section, and the section says when it happened;
    * the ``## [Unreleased]`` section, if present, is EMPTY.  The placeholder
      itself is the convention and stays; but everything in the tree at tag
      time is in the tag, so an entry still under it describes a change this
      release ships as one it does not.
    """
    problems: list[str] = []
    v = re.escape(version)
    dated = re.compile(rf"^##[ \t]*\[{v}\][ \t]*-[ \t]*\d{{4}}-\d{{2}}-\d{{2}}\b", re.MULTILINE)
    if not dated.search(text):
        problems.append(
            f"  - CHANGELOG.md: no dated '## [{version}] - YYYY-MM-DD' heading; the "
            f"release being tagged has no section that says it happened."
        )
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not _UNRELEASED_HEADING_RE.match(line):
            continue
        for offset, body in enumerate(lines[index + 1 :], start=index + 2):
            if _LEVEL_2_HEADING_RE.match(body):
                break
            if not _NOT_AN_ENTRY_RE.match(body):
                problems.append(
                    f"  - CHANGELOG.md:{offset}: the '## [Unreleased]' section still "
                    f"holds entries ({body.strip()[:60]!r}); everything in the tree "
                    f"ships in {version}, so move them under its dated heading."
                )
                break
    return problems


def publish_state_markers() -> list[tuple[re.Pattern[str], str]]:
    """PyPI-publish-state markers — enforced ONLY under ``--require-published``.

    PyPI publication is opt-in (``vars.AMA_PUBLISH_TO_PYPI``) and separate from
    the tag, so on a release that does not publish to PyPI these statements stay
    TRUE and must not be flipped.  The workflow passes ``--require-published``
    exactly when the run does publish, at which point leaving these in the
    shipped docs would be the same class of falsehood the tag-state markers guard
    against.
    """
    return [
        (re.compile(r"not[ \t]+published[ \t]+yet", re.IGNORECASE), "'not published yet'"),
        (re.compile(r"not[ \t]+yet[ \t]+published", re.IGNORECASE), "'not yet published'"),
    ]


def scan(repo: Path, version: str, require_published: bool) -> tuple[list[str], int]:
    """`(problems, documents scanned)` over the release-state files."""
    markers = tag_state_markers(version)
    if require_published:
        markers = markers + publish_state_markers()
    problems: list[str] = []
    scanned = 0
    for rel in RELEASE_STATE_FILES:
        path = repo / rel
        if not path.is_file():
            problems.append(
                f"  - {rel}: listed as a release-state document but not found; a "
                f"release cannot confirm it no longer says '{version} unreleased'."
            )
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        if rel == "CHANGELOG.md":
            problems.extend(changelog_problems(text, version))
        for pattern, desc in markers:
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                problems.append(f"  - {rel}:{line}: still says {desc} ({m.group(0)!r})")
    return problems, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", required=True, help="the canonical release version, e.g. 5.0.0"
    )
    parser.add_argument(
        "--require-published",
        action="store_true",
        help=(
            "also enforce PyPI-publish-state markers ('not published yet'); pass this "
            "when the run publishes to PyPI (vars.AMA_PUBLISH_TO_PYPI == 'true')."
        ),
    )
    parser.add_argument(
        "--repo", type=Path, default=REPO, help="repository root (default: this tree)"
    )
    args = parser.parse_args(argv)

    problems, scanned = scan(args.repo, args.version, args.require_published)

    if problems:
        print(
            f"RELEASE STATE CHECK FAILED — {args.version} is being tagged, but its own "
            f"shipped documents still call it unreleased:",
            file=sys.stderr,
        )
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            "\nUpdate these before pushing the tag: move the CHANGELOG heading to a "
            "dated release, file every '## [Unreleased]' entry under it, and flip the "
            "availability rows and the Sphinx landing page to 'released'. A tag that "
            "ships while the docs say it has not happened is the defect this gate "
            "exists to stop.",
            file=sys.stderr,
        )
        return 1

    scope = "tag-state and PyPI-publish-state" if args.require_published else "tag-state"
    print(
        f"OK: none of the {scanned} release-state document(s) still carries a "
        f"{scope} 'unreleased' marker for {args.version}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
