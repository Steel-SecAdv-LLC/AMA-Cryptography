#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AMA Cryptography — pin the performance figures README.md publishes.

Why this exists
---------------
``tools/check_benchmark_claims.py`` pins the numbers that are *re-derivable*:
the generated tables recomputed from ``benchmarks/benchmark-results.json``, the
regression floors quoted in prose, the provenance fields, the units. It does
not see a table of measured medians written into ``README.md`` by hand,
because nothing it reads carries those figures as data.

That gap was measured, not assumed, twice. With the ML-DSA-65 KeyGen row of
the old canonical-host table edited from ``3,626 ops/sec`` to
``9,626 ops/sec``, that gate reported ``OK    86 benchmark claim(s)
consistent with their records``. And with the ``ama_sha3_256_hash`` x86_64
median of the CI four-run table edited from ``363,574`` to ``963,574``, it
reported ``OK    91 benchmark claim(s) consistent with their records`` — as
did the canonical-host gate this file replaces, whose region did not include
that table.

What this pins
--------------
``README.md`` delimits its measured-performance section with::

    <!-- published-bench: begin -->
    ...
    <!-- published-bench: end -->

Every number inside that region must appear in
``benchmarks/published-benchmarks.json``, and every number in the record must
still appear in the region, as many times as the region prints it. "Every
number", not "every number followed by a unit this gate recognises": an
earlier version read only the latter, so a figure whose unit was not adjacent
("~10,834 Decaps ops/sec") or was in an unlisted unit could be edited freely
inside the pinned region. The only digits not pinned are those inside a name —
``ML-DSA-65``, ``Ed25519``, ``64-byte`` — which cannot change without the name
changing. The comparison runs in both directions on purpose: one direction
catches an edited or invented figure, the other a figure quietly dropped to
make an inconvenient claim go away.

Provenance is a property of the source, and is checked
------------------------------------------------------
Each record entry names the source it came from. A source is one of a closed
set of kinds, and each kind must carry the fields that make its figures
checkable:

* ``measurement`` — a figure some machine produced. AGENTS.md section 8 item 7
  prohibits publishing one without its host, build flags and run identifier,
  and INVARIANT-53 requires the command, host, units, sampling and aggregation
  behind it. So a measurement source must state ``host``, ``build``,
  ``command``, ``sampling``, ``aggregation``, the date ``measured``, and a
  non-empty list of ``runs``. A figure from hardware whose run cannot be named
  cannot be recorded, which is the mechanism behind the policy that
  ``benchmarks/README.md`` states.
* ``ledger`` — a number read from a committed file (a regression floor, its
  tolerance, a derivation recorded in a baseline change log).
* ``specification`` — a number a cited standard defines.
* ``source-constant`` — a number fixed by this repository's code.

The three non-measurement kinds need a ``description`` and a ``reference``
naming where the number can be read. An unknown kind fails: a source that is
not one of these has no provenance rule, and a gate that accepts it has none
either.

There is no exemption list. Per AGENTS.md section 10 a gate that carries one
is not a gate, and this one does not need one: the region is explicit, so a
number that should not be pinned belongs outside the markers rather than on a
waiver.

More than one document
----------------------
The README is not the only page that restates a throughput figure. The wiki's
per-algorithm pages printed their own copies, and those copies had been
4.x-era numbers for two majors while the README's table was pinned — nothing
compared them to anything. So the record names the ``documents`` it pins, and
every one of them carries the same markers, possibly several pairs of them.
Each recorded figure names the document it is published in, and that document
is part of its identity: a figure moved from one page to another is a figure
deleted from one and invented on the other, and fails as both.

The other documents restate the README's rows; they are not a second place a
measurement can enter. So a figure outside ``README.md`` that cites a
``measurement`` source must also be published in ``README.md`` from that same
source: re-basing the table then fails every copy that was not moved with it.

``README.md`` must always be listed. A listed document without well-formed
markers, or whose regions hold no figure, exits 2 like the README always did,
so a page cannot fall out of coverage by losing its markers. The converse is
checked too: a document that carries the markers but is not listed would look
pinned to a reader and be pinned by nothing, so it fails.

Exit codes:
    0  every published figure matches its record
    1  a figure drifted, was added without a record, or was dropped; a source
       lacks the provenance its kind requires; or a document carries the
       markers without being listed in the record
    2  the region markers or the record file are missing or malformed
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

README = "README.md"
RECORD = "benchmarks/published-benchmarks.json"

BEGIN_MARKER = "<!-- published-bench: begin -->"
END_MARKER = "<!-- published-bench: end -->"

#: The kinds of file a published figure can be written in, searched for stray
#: markers. A document carrying the markers outside the record's list would
#: read as pinned and be pinned by nothing.
_DOCUMENT_SUFFIXES = (".md", ".rst", ".html")

#: Directories that hold build products, caches or tooling rather than
#: documents this repository publishes; the stray-marker search does not
#: descend into them. Hidden directories (``.git``, ``.venv``) are skipped too.
_NOT_DOCUMENT_DIRS = frozenset({"build", "node_modules", "venv", "__pycache__", "dist"})

#: The provenance each kind of source must state. ``description`` is common to
#: all of them; a measurement adds everything AGENTS.md section 8 item 7 and
#: INVARIANT-53 require of a published performance figure.
REQUIRED_BY_KIND: dict[str, tuple[str, ...]] = {
    "measurement": (
        "description",
        "measured",
        "host",
        "build",
        "command",
        "sampling",
        "aggregation",
    ),
    "ledger": ("description", "reference"),
    "specification": ("description", "reference"),
    "source-constant": ("description", "reference"),
}

#: A number as this README writes them: thousands-separated, decimal, or plain.
_NUMBER = r"\d{1,3}(?:,\d{3})+|\d+\.\d+|\d+"

#: The units this README publishes, and the ones a figure could be republished
#: in. MICRO SIGN and MULTIPLICATION SIGN are written as escapes rather than as
#: literals: ruff's RUF001 flags them as confusable with "u" and "x", and it is
#: right to — a gate whose pattern can be read two ways is a gate that can
#: silently stop matching. The escape is the same character to `re`, and
#: unambiguous to a reader. Longest first, so ``MB/s`` is not read as ``MB``.
_UNITS = (
    "ops/sec",
    "MB/s",
    "GB/s",
    "cycles",
    "\u00b5s",
    "us",
    "ms",
    "ns",
    "\u00d7",
    "%",
    "KB",
    "MB",
    "GB",
)

#: A measurement is a number followed by a unit. ``~`` marks an approximate
#: figure and is part of the claim: "~276us" and "276us" say different things
#: about how the number was arrived at, so the gate keeps them distinct.
_MEASUREMENT = re.compile(rf"(~?)\s*({_NUMBER})\s*({'|'.join(map(re.escape, _UNITS))})(?![A-Za-z])")

#: Every number token the region prints: a date, a dotted version, a
#: thousands-separated or decimal figure, or a bare digit run.
_ANY_NUMBER = re.compile(
    r"(~?)\s*(\d{4}-\d{2}-\d{2}|\d+(?:\.\d+){2,}|\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"
)

#: The characters that glue a digit run into a word: ``ML-DSA-65``, ``x86-64``,
#: ``radix-2^51``, ``64-byte``. A digit run whose word carries a letter is part
#: of a NAME, not a figure: it cannot drift without the name changing.
_WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_^-")

#: A Markdown link target is an address, not a published figure.
_LINK_TARGET = re.compile(r"\]\([^)]*\)")

#: The prefixes of a Markdown list item, whose text up to its first colon
#: names the figures that follow it.
_LIST_MARKERS = ("- ", "* ", "+ ")


def _is_name_part(line: str, start: int, end: int) -> bool:
    """True when the digits at ``line[start:end]`` sit inside a word with a letter."""
    left = start
    while left > 0 and line[left - 1] in _WORD_CHARS:
        left -= 1
    right = end
    while right < len(line) and line[right] in _WORD_CHARS:
        right += 1
    return any(character.isalpha() for character in line[left:start] + line[end:right])


class Report:
    """Collects failures so one run names every problem, not just the first."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def ok(self) -> bool:
        return not self.failures


Key = tuple[str, str, str, int, bool, str, str]


def _key(entry: dict[str, Any]) -> Key:
    """The identity of a measurement: which page says it, where, and what it says."""
    return (
        str(entry["document"]),
        str(entry["heading"]),
        str(entry["label"]),
        int(entry["position"]),
        bool(entry["approx"]),
        str(entry["value"]),
        str(entry["unit"]),
    )


def extract_regions(text: str) -> Optional[list[str]]:
    """Every marked region of ``text``, in order, or None if the markers are malformed.

    Malformed means: no begin marker at all, an end before its begin, a begin
    before the previous region ended (nesting), or a begin with no end. Each of
    those would otherwise leave part of the page silently outside the check.
    """
    regions: list[str] = []
    position = 0
    while True:
        start = text.find(BEGIN_MARKER, position)
        stray_end = text.find(END_MARKER, position)
        if start < 0:
            if stray_end >= 0:
                return None
            break
        if 0 <= stray_end < start:
            return None
        body_start = start + len(BEGIN_MARKER)
        end = text.find(END_MARKER, body_start)
        if end < 0:
            return None
        nested = text.find(BEGIN_MARKER, body_start)
        if 0 <= nested < end:
            return None
        regions.append(text[body_start:end])
        position = end + len(END_MARKER)
    return regions or None


def extract_region(text: str) -> Optional[str]:
    """The first marked region of ``text``, or None if the markers are malformed."""
    regions = extract_regions(text)
    return regions[0] if regions else None


def find_marked_documents(repo: Path) -> set[str]:
    """Every document under ``repo`` that carries a region marker, repo-relative."""
    found: set[str] = set()
    for directory, subdirectories, files in os.walk(repo):
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if not name.startswith(".") and name not in _NOT_DOCUMENT_DIRS
        )
        for name in files:
            if not name.endswith(_DOCUMENT_SUFFIXES):
                continue
            path = Path(directory) / name
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if BEGIN_MARKER in text or END_MARKER in text:
                found.add(path.relative_to(repo).as_posix())
    return found


def _label(stripped: str) -> str:
    """What a line of a region names: a table row, a list item, a heading or prose."""
    if stripped.startswith("#"):
        return "(heading)"
    if stripped.startswith("|") and stripped.count("|") > 2:
        return stripped.split("|")[1].strip()
    if stripped[:2] in _LIST_MARKERS and ":" in stripped:
        return stripped[2 : stripped.index(":")].strip()
    return "(prose)"


def extract_measurements(region: str, document: str = README) -> list[dict[str, Any]]:
    """Every number in the region, tagged with the row and section it is in.

    Not only the figures followed by a recognised unit: a throughput claim
    whose unit is not adjacent to the number, or a figure in a unit this gate
    did not list, would otherwise escape. So every number token is pinned —
    carrying its unit when one follows it, and an empty unit when none does —
    unless its digits are part of a name (``ML-DSA-65``, ``Ed25519``,
    ``64-byte``), which cannot change without the name changing. A heading's
    numbers are pinned under the label ``(heading)``.

    The label is the first cell of a markdown table row, or the text of a list
    item up to its first colon, which is how these pages name the thing being
    measured. Other prose is labelled ``(prose)`` so a failure still says where
    to look. Every entry is tagged with ``document``, the page it was read
    from, and with ``position``, its ordinal among the figures of its line:
    without it, two figures of one row or one sentence could trade places — an
    x86_64 median for its aarch64 neighbour — and leave the multiset of keys,
    and so the comparison, unchanged.
    """
    found: list[dict[str, Any]] = []
    heading = ""
    for raw in region.splitlines():
        line = _LINK_TARGET.sub("]()", raw)
        stripped = line.strip()
        label = _label(stripped)
        if label == "(heading)":
            heading = stripped.lstrip("# ").strip()
        on_line: list[tuple[int, bool, str, str]] = []
        claimed: list[tuple[int, int]] = []
        for match in _MEASUREMENT.finditer(line):
            claimed.append(match.span(2))
            on_line.append((match.start(2), bool(match.group(1)), match.group(2), match.group(3)))
        for match in _ANY_NUMBER.finditer(line):
            start, end = match.span(2)
            if any(start < taken_end and taken_start < end for taken_start, taken_end in claimed):
                continue
            if _is_name_part(line, start, end):
                continue
            on_line.append((start, bool(match.group(1)), match.group(2), ""))
        for position, (_, approx, value, unit) in enumerate(sorted(on_line)):
            found.append(
                {
                    "document": document,
                    "heading": heading,
                    "label": label,
                    "position": position,
                    "approx": approx,
                    "value": value,
                    "unit": unit,
                }
            )
    return found


def check_sources(report: Report, record: dict[str, Any]) -> set[str]:
    """Every source must be a known kind and state the provenance that kind requires.

    A measurement additionally names the runs that produced it: a figure from a
    machine whose run cannot be cited is exactly the kind of number
    AGENTS.md section 8 item 7 prohibits publishing, so it cannot be recorded
    here either.
    """
    sources = record.get("sources")
    if not isinstance(sources, dict) or not sources:
        report.fail(f"{RECORD}: 'sources' is missing or empty; no figure can cite one")
        return set()

    named: set[str] = set()
    for name, provenance in sources.items():
        if not isinstance(provenance, dict):
            report.fail(f"{RECORD}: source '{name}' is not an object")
            continue
        named.add(str(name))
        kind = provenance.get("kind")
        required = REQUIRED_BY_KIND.get(kind) if isinstance(kind, str) else None
        if required is None:
            report.fail(
                f"{RECORD}: source '{name}' has kind {kind!r}; it must be one of "
                f"{', '.join(sorted(REQUIRED_BY_KIND))}, each of which carries its "
                f"own provenance rule."
            )
            continue
        for field in required:
            value = provenance.get(field)
            if not isinstance(value, str) or not value.strip():
                report.fail(
                    f"{RECORD}: {kind} source '{name}' is missing '{field}'. A "
                    f"published figure names where it came from and how it was "
                    f"produced (INVARIANT-53; AGENTS.md section 8 item 7)."
                )
        if kind == "measurement":
            runs = provenance.get("runs")
            if (
                not isinstance(runs, list)
                or not runs
                or not all(isinstance(run, str) and run.strip() for run in runs)
            ):
                report.fail(
                    f"{RECORD}: measurement source '{name}' names no run. A "
                    f"performance figure is not published without the run "
                    f"identifier that produced it (AGENTS.md section 8 item 7)."
                )
    return named


def check_measurements(
    report: Report,
    published: list[dict[str, Any]],
    record: dict[str, Any],
    sources: set[str],
    documents: list[str],
) -> None:
    """Compare the published figures against the record, in both directions."""
    entries = record.get("measurements")
    if not isinstance(entries, list) or not entries:
        report.fail(f"{RECORD}: 'measurements' is missing or empty")
        return

    # Counted, not collected into a set: a figure printed twice is two
    # figures, and deleting one of them must not pass because the other still
    # carries the same key.
    recorded: Counter[Key] = Counter()
    for entry in entries:
        if not isinstance(entry, dict):
            report.fail(f"{RECORD}: a measurement entry is not an object")
            continue
        try:
            key = _key(entry)
        except KeyError as exc:
            report.fail(f"{RECORD}: a measurement entry is missing {exc}")
            continue
        if key[0] not in documents:
            report.fail(
                f"{RECORD}: {key[2]} {key[5]}{key[6]} names document '{key[0]}', "
                f"which is not in 'documents'; nothing would compare it to anything"
            )
        source = entry.get("source")
        if not isinstance(source, str) or source not in sources:
            report.fail(
                f"{RECORD}: {key[2]} {key[5]}{key[6]} cites source "
                f"'{source}', which is not described under 'sources'"
            )
        recorded[key] += 1

    published_keys: Counter[Key] = Counter(_key(entry) for entry in published)

    for key, count in sorted((published_keys - recorded).items()):
        approx = "~" if key[4] else ""
        report.fail(
            f"{key[0]}: '{key[2]}' publishes {approx}{key[5]} {key[6]}".rstrip()
            + f" under '{key[1]}' (figure {key[3] + 1} of its line)"
            + (f" {count} more time(s) than" if key in recorded else ", which is not in")
            + f" {RECORD}. Either it drifted from the recorded figure, or it is a "
            "new claim with no source behind it."
        )

    for key, count in sorted((recorded - published_keys).items()):
        approx = "~" if key[4] else ""
        report.fail(
            f"{RECORD} carries '{key[2]}' at {approx}{key[5]} {key[6]}".rstrip()
            + f" under '{key[1]}' (figure {key[3] + 1} of its line)"
            + (
                f" {count} more time(s) than {key[0]} publishes it"
                if key in published_keys
                else f", but {key[0]} no longer publishes it"
            )
            + ". A recorded figure is not retired by deleting the line that quotes it."
        )


def check_restatements(report: Report, record: dict[str, Any]) -> None:
    """A measured figure on another page must still be one the README publishes.

    The other documents restate rows of the README's table; they are not a
    second source of measurements. Without this, re-basing the README's table
    (and its record entries) would leave every copy elsewhere pinned to the
    superseded value, each consistent with its own entry and none with the
    measurement it claims to repeat.
    """
    sources = record.get("sources")
    entries = record.get("measurements")
    if not isinstance(sources, dict) or not isinstance(entries, list):
        return
    measured = {
        name
        for name, provenance in sources.items()
        if isinstance(provenance, dict) and provenance.get("kind") == "measurement"
    }
    in_readme = {
        (entry.get("source"), entry.get("value"), entry.get("unit"))
        for entry in entries
        if isinstance(entry, dict) and entry.get("document") == README
    }
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("document") in (None, README):
            continue
        if entry.get("source") not in measured:
            continue
        if (entry.get("source"), entry.get("value"), entry.get("unit")) not in in_readme:
            report.fail(
                f"{entry.get('document')}: '{entry.get('label')}' restates "
                f"{entry.get('value')} {entry.get('unit')}".rstrip()
                + f" from measurement source '{entry.get('source')}', but {README} "
                f"publishes no such figure from that source. A restated figure "
                f"moves with the table it restates."
            )


def _documents(record: dict[str, Any]) -> Optional[list[str]]:
    """The record's ``documents`` list, or None if it is absent or malformed."""
    documents = record.get("documents")
    if (
        not isinstance(documents, list)
        or not documents
        or not all(isinstance(name, str) and name.strip() for name in documents)
        or len(set(documents)) != len(documents)
    ):
        return None
    return [str(name) for name in documents]


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    repo: Path = args.repo.resolve()

    readme_path = repo / README
    record_path = repo / RECORD
    for path in (readme_path, record_path):
        if not path.is_file():
            print(f"FAIL: {path} does not exist", file=sys.stderr)
            return 2

    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL: {RECORD} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(record, dict):
        print(f"FAIL: {RECORD} is not a JSON object", file=sys.stderr)
        return 2

    documents = _documents(record)
    if documents is None or README not in documents:
        print(
            f"FAIL: {RECORD} must carry 'documents', a non-empty list of distinct "
            f"repo-relative paths that includes {README}. Without it the gate "
            f"would not know which pages to read, and a page left off it would "
            f"be checked by nothing.",
            file=sys.stderr,
        )
        return 2

    published: list[dict[str, Any]] = []
    for document in documents:
        path = repo / document
        if not path.is_file():
            print(f"FAIL: {document}, listed in {RECORD}, does not exist", file=sys.stderr)
            return 2
        regions = extract_regions(path.read_text(encoding="utf-8"))
        if regions is None:
            print(
                f"FAIL: {document} does not carry well-formed {BEGIN_MARKER} / "
                f"{END_MARKER} pairs (missing, unbalanced or nested). Without "
                f"the markers this gate checks nothing on that page, so it fails "
                f"rather than reporting a vacuous pass.",
                file=sys.stderr,
            )
            return 2
        found = [
            measurement
            for region in regions
            for measurement in extract_measurements(region, document)
        ]
        if not found:
            print(
                f"FAIL: no measurement was found between the markers in {document}. "
                f"An empty region would let every recorded figure be deleted at once.",
                file=sys.stderr,
            )
            return 2
        published.extend(found)

    report = Report()
    for stray in sorted(find_marked_documents(repo) - set(documents)):
        report.fail(
            f"{stray} carries published-bench markers but is not in {RECORD} "
            f"'documents'. Its figures would read as pinned and be pinned by "
            f"nothing: list it and record its figures, or remove the markers."
        )
    sources = check_sources(report, record)
    check_measurements(report, published, record, sources, documents)
    check_restatements(report, record)

    if not report.ok():
        for failure in report.failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(report.failures)} published benchmark problem(s)", file=sys.stderr)
        return 1

    print(
        f"OK    {len(published)} published figure(s) in {len(documents)} document(s) "
        f"match {RECORD} across {len(sources)} source(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
