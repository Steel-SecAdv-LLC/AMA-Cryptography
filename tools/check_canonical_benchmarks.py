#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AMA Cryptography — pin the published canonical-host benchmark figures.

Why this exists
---------------
``tools/check_benchmark_claims.py`` pins the numbers that are *re-derivable*:
the CI-runner tables recomputed from ``benchmarks/benchmark-results.json``, the
regression floors quoted in prose, the provenance fields, the units. It does
not see the canonical-host tables in ``README.md``, because nothing in the tree
carries those figures as data — they existed only as prose.

That gap was measured, not assumed. With the ML-DSA-65 KeyGen row edited from
``3,626 ops/sec`` to ``9,626 ops/sec``, the existing gate reported::

    OK    86 benchmark claim(s) consistent with their records

A fabricated throughput figure survived the full documentation gate set. These
are the most quotable numbers this repository publishes — they are what a
reader takes away as "how fast is it" — and they were the only published
figures with no mechanism behind them at all.

What this pins, and what it deliberately does not
-------------------------------------------------
Re-measuring the canonical host needs the canonical host: a Linux x86-64 part
with AVX-512F/VL/BW/DQ/VBMI plus VAES and VPCLMULQDQ. This repository's CI does
not have one, and that prerequisite is unchanged by this gate.

Drift detection needs no such thing. A number that was measured once and then
published forever has two distinct failure modes, and only one of them is about
hardware:

* the figure stops describing the code (needs a re-measurement — blocked), and
* the figure stops describing the measurement (needs a record — this gate).

The second is the one that has actually bitten this tree: a
``wiki/Performance-Benchmarks.md`` floor sat two majors stale, and the macOS
export list drifted from the ELF version script until the dylib published every
internal helper. An unpinned number does not stay honest on its own.

How it works
------------
``README.md`` delimits its host-measured benchmark section with::

    <!-- canonical-bench: begin -->
    ...
    <!-- canonical-bench: end -->

Every measurement inside that region must appear in
``benchmarks/canonical-host.json``, and every measurement in the record must
still appear in the region. The comparison runs in both directions on purpose:
one direction catches an edited or invented figure, the other catches a figure
quietly dropped to make an inconvenient claim go away.

Each record entry names the source it came from, and each source carries its
provenance — what it is, the date, and the command that produced the number.
A figure cannot be added to the region without stating where it came from,
which is what INVARIANT-36 and AGENTS.md section 3.5 require of any published
performance claim.

There is no exemption list. Per AGENTS.md section 10 a gate that carries one is
not a gate, and this one does not need one: the region is explicit, so a number
that should not be pinned belongs outside the markers rather than on a waiver.

Exit codes:
    0  every published figure matches its record
    1  a figure drifted, was added without a record, or was dropped
    2  the region markers or the record file are missing or malformed
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

README = "README.md"
RECORD = "benchmarks/canonical-host.json"

BEGIN_MARKER = "<!-- canonical-bench: begin -->"
END_MARKER = "<!-- canonical-bench: end -->"

#: A number as this README writes them: thousands-separated, decimal, or plain.
_NUMBER = r"\d{1,3}(?:,\d{3})+|\d+\.\d+|\d+"

#: The units this README publishes. MICRO SIGN and MULTIPLICATION SIGN are
#: written as escapes rather than as literals: ruff's RUF001 flags them as
#: confusable with "u" and "x", and it is right to — a gate whose pattern can be
#: read two ways is a gate that can silently stop matching. The escape is the
#: same character to `re`, and unambiguous to a reader.
_UNITS = ("ops/sec", "\u00b5s", "\u00d7", "%", "KB")

#: A measurement is a number followed by a unit. ``~`` marks an approximate
#: figure and is part of the claim: "~276us" and "276us" say different things
#: about how the number was arrived at, so the gate keeps them distinct.
_MEASUREMENT = re.compile(rf"(~?)\s*({_NUMBER})\s*({'|'.join(_UNITS)})")


class Report:
    """Collects failures so one run names every problem, not just the first."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def ok(self) -> bool:
        return not self.failures


def _key(entry: dict[str, Any]) -> tuple[str, str, bool, str, str]:
    """The identity of a measurement: where it is said, and what it says."""
    return (
        str(entry["heading"]),
        str(entry["label"]),
        bool(entry["approx"]),
        str(entry["value"]),
        str(entry["unit"]),
    )


def extract_region(text: str) -> Optional[str]:
    """Return the text between the markers, or None if they are not both there."""
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    if start < 0 or end < 0 or end < start:
        return None
    return text[start + len(BEGIN_MARKER) : end]


def extract_measurements(region: str) -> list[dict[str, Any]]:
    """Every measurement in the region, tagged with the row and section it is in.

    The label is the first cell of a markdown table row, which is how this
    README names the thing being measured. Prose measurements outside a table
    are labelled by their line so a failure still says where to look.
    """
    found: list[dict[str, Any]] = []
    heading = ""
    for line in region.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped.lstrip("# ").strip()
            continue
        if stripped.startswith("|") and stripped.count("|") > 2:
            label = stripped.split("|")[1].strip()
        else:
            label = "(prose)"
        for match in _MEASUREMENT.finditer(line):
            found.append(
                {
                    "heading": heading,
                    "label": label,
                    "approx": bool(match.group(1)),
                    "value": match.group(2),
                    "unit": match.group(3),
                }
            )
    return found


def check_sources(report: Report, record: dict[str, Any]) -> set[str]:
    """Every source in the record must state how its figures were produced.

    Most sources are hosts. Two are not: the comb table size is a property of
    the code rather than of any machine, and the 1.8-2.2x range is reported by
    OpenSSL and BoringSSL, not measured here. Calling either a "host" would be
    false provenance, so the record names sources and each one says what it is.
    """
    sources = record.get("sources")
    if not isinstance(sources, dict) or not sources:
        report.fail(f"{RECORD}: 'sources' is missing or empty; no figure can cite one")
        return set()

    required = ("description", "measured", "command")
    named: set[str] = set()
    for name, provenance in sources.items():
        if not isinstance(provenance, dict):
            report.fail(f"{RECORD}: source '{name}' is not an object")
            continue
        for field in required:
            value = provenance.get(field)
            if not isinstance(value, str) or not value.strip():
                report.fail(
                    f"{RECORD}: source '{name}' is missing '{field}'. A published "
                    f"performance figure names where it came from, when, and the "
                    f"command that produced it (INVARIANT-36)."
                )
        named.add(str(name))
    return named


def check_measurements(
    report: Report,
    published: list[dict[str, Any]],
    record: dict[str, Any],
    sources: set[str],
) -> None:
    """Compare the published figures against the record, in both directions."""
    entries = record.get("measurements")
    if not isinstance(entries, list) or not entries:
        report.fail(f"{RECORD}: 'measurements' is missing or empty")
        return

    recorded: dict[tuple[str, str, bool, str, str], dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            report.fail(f"{RECORD}: a measurement entry is not an object")
            continue
        try:
            key = _key(entry)
        except KeyError as exc:
            report.fail(f"{RECORD}: a measurement entry is missing {exc}")
            continue
        source = entry.get("source")
        if not isinstance(source, str) or source not in sources:
            report.fail(
                f"{RECORD}: {key[1]} {key[3]}{key[4]} cites source "
                f"'{source}', which is not described under 'sources'"
            )
        recorded[key] = entry

    published_keys = {_key(entry) for entry in published}

    for entry in published:
        key = _key(entry)
        if key not in recorded:
            approx = "~" if key[2] else ""
            report.fail(
                f"{README}: '{key[1]}' publishes {approx}{key[3]} {key[4]} under "
                f"'{key[0]}', which is not in {RECORD}. Either it drifted from the "
                f"recorded figure, or it is a new claim with no host behind it."
            )

    for key in recorded:
        if key not in published_keys:
            approx = "~" if key[2] else ""
            report.fail(
                f"{RECORD} carries '{key[1]}' at {approx}{key[3]} {key[4]} under "
                f"'{key[0]}', but {README} no longer publishes it. A recorded "
                f"figure is not retired by deleting the line that quotes it."
            )


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

    region = extract_region(readme_path.read_text(encoding="utf-8"))
    if region is None:
        print(
            f"FAIL: {README} does not carry both {BEGIN_MARKER} and {END_MARKER}. "
            f"Without the markers this gate checks nothing, so it fails rather "
            f"than reporting a vacuous pass.",
            file=sys.stderr,
        )
        return 2

    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL: {RECORD} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(record, dict):
        print(f"FAIL: {RECORD} is not a JSON object", file=sys.stderr)
        return 2

    published = extract_measurements(region)
    if not published:
        print(
            f"FAIL: no measurement was found between the markers in {README}. "
            f"An empty region would let every recorded figure be deleted at once.",
            file=sys.stderr,
        )
        return 2

    report = Report()
    sources = check_sources(report, record)
    check_measurements(report, published, record, sources)

    if not report.ok():
        for failure in report.failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(report.failures)} canonical benchmark problem(s)", file=sys.stderr)
        return 1

    print(
        f"OK    {len(published)} published canonical figure(s) match {RECORD} "
        f"across {len(sources)} source(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
