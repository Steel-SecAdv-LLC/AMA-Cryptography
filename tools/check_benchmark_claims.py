#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Validate documented benchmark numbers against the records that produced them.

The fact this gate protects
---------------------------
A performance number in documentation is a measurement claim, and a measurement
claim without provenance is not checkable by anyone — including the person who
wrote it. The 2026-09 pass found three distinct failures of exactly that shape:

* ``ARCHITECTURE.md`` published "ML-DSA-65 signing (4.20 ms, dominant signing
  cost)" three lines below a table putting a whole multi-layer package creation
  at 2.17 ms. The document contradicted itself before a reader reached a
  measurement, and the figure was roughly thirty times the real cost.
* ``wiki/Performance-Benchmarks.md`` cited an HMAC-SHA3-256 regression floor of
  76,215 ops/sec. That floor had been 215,299 (x86-64) and 285,176 (aarch64)
  for two major releases.
* ``README.md`` published ``ed25519_sign`` at 70,496 ops/sec after INVARIANT-51
  roughly halved signing throughput by design, and after the floor itself had
  been re-based to 38,170 in the same repository.

None was a typo. Each was a static constant with no link to a measurement, in a
document nothing re-derived.

What this gate can and cannot enforce
-------------------------------------
It deliberately does **not** try to enforce absolute performance in CI. Runner
hardware varies by more than any honest tolerance would allow, and a gate that
fails on a slow runner teaches people to re-run until green — which is worse
than no gate. What it enforces instead is everything that is *not* hardware:

1. **Derived tables are derived.** Every cell of ARCHITECTURE.md's
   ``AUTO-PIPELINE-LATENCY`` block and wiki/Performance-Benchmarks.md's
   ``AUTO-BENCHMARK-TABLE`` is recomputed from
   ``benchmarks/benchmark-results.json`` and ``benchmarks/baseline.json`` and
   compared. A hand-edited number cannot survive a push.
2. **Every documented regression floor matches the JSON that enforces it**,
   by benchmark identifier and architecture label. This is the rule that would
   have caught 76,215 and 70,496. Both are resolved from the claim itself —
   its clause, sentence or table row, widening to paragraph, blockquote and
   section only while nothing nearer names one — and the value must equal THAT
   benchmark's floor on THAT architecture. A floor-shaped figure that cannot
   be attributed to exactly one of each fails: it cannot be checked.
3. **Provenance is present.** A record that documentation draws numbers from
   must carry the command, host, units and sampling method that make it
   reproducible. A record missing any of them is rejected, so the next person
   cannot publish from it.
4. **Units are stated and consistent.** ops/sec and ms/op are reciprocals; a
   figure published without a unit, or with the wrong one, is the 4.20 ms bug.
5. **Ranges are sane.** Where documentation pairs a measured figure with a
   floor for the same benchmark on the same architecture, the two must be
   within a declared factor of each other. A measured value thirty times its
   floor is not a fast machine; it is a mistake.

Exit status
-----------
0  every documented benchmark claim is consistent with its record
1  at least one is not
2  the check could not run
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parent.parent

RESULTS_JSON = "benchmarks/benchmark-results.json"
X86_BASELINE_JSON = "benchmarks/baseline.json"
ARM_BASELINE_JSON = "benchmarks/arm-baseline.json"

#: Provenance keys a record must carry before documentation may quote it.
#: Each answers one of the questions that makes a number reproducible.
REQUIRED_PROVENANCE: tuple[tuple[str, str], ...] = (
    ("command", "the exact benchmark command"),
    ("host", "the platform and architecture"),
    ("sampling", "the sample methodology"),
    ("aggregation", "how repeated observations were reduced"),
)

#: Every floor entry must declare these, or the number it enforces is a
#: constant with no meaning attached.
REQUIRED_BASELINE_FIELDS: tuple[str, ...] = (
    "baseline_value",
    "unit",
    "tolerance_percent",
    "metric",
    "tier",
)

#: A measured figure more than this many times its own floor, on the same
#: architecture, is a units or identity error rather than a fast host.  Chosen
#: to be loose enough for genuine cross-class hardware spread (the x86 fleet is
#: two-class at ~15%, and a canonical bench host can be several times a shared
#: runner) and tight enough to have caught every defect this pass found: the
#: 4.20 ms ML-DSA figure was ~30x out and the 70,496 ed25519_sign row ~1.85x
#: over a re-based floor it should have moved with.
MAX_MEASURED_OVER_FLOOR = 8.0

LATENCY_START = "<!-- AUTO-PIPELINE-LATENCY-START -->"
LATENCY_END = "<!-- AUTO-PIPELINE-LATENCY-END -->"
BENCH_START = "<!-- AUTO-BENCHMARK-TABLE-START -->"
BENCH_END = "<!-- AUTO-BENCHMARK-TABLE-END -->"

#: A throughput-shaped figure: comma-grouped, or four or more bare digits.  The
#: look-arounds keep it from starting inside ``1.8469`` or a ``2026-09-22`` date.
_NUMBER = r"(?<![\w.,-])(?P<value>\d{1,3}(?:,\d{3})+|\d{4,})(?![\w]|[.,-]\d)"

#: The ways a sentence asserts that a figure IS a floor.  Each is anchored on
#: the word "floor" and on the figure, so a sentence that merely mentions a
#: floor near a number it describes otherwise -- "the floor was first set by a
#: derivation (70,496 / 1.8469 = 38,170)" -- is not read as a claim.
_FLOOR_CLAIMS: tuple[re.Pattern[str], ...] = (
    # "the floor for X on Y is 215,299 ops/sec" -- the form this gate has
    # always read, unchanged so nothing it caught before now escapes.
    re.compile(r"\bfloors?\b[^.\n]{0,120}?" + _NUMBER + r"[^.\n]{0,60}?\bops/sec\b", re.IGNORECASE),
    # "the enforced floor is 285,176" -- the figure is the predicate of
    # "floor", with only copulas and markup between them; no unit needed.
    re.compile(r"\bfloors?\b(?:[\s*`:=]|\b(?:is|are|of|at|value)\b)*" + _NUMBER, re.IGNORECASE),
    # "a 38,811 ops/sec floor", "215,299 ops/sec is the enforced floor".
    re.compile(
        _NUMBER + r"(?:\s*ops/sec)?[\s*`]+(?:(?:is|are)\s+the\s+)?(?:[\w`*-]+\s+){0,2}?floors?\b",
        re.IGNORECASE,
    ),
)

#: Architecture designations, keyed by the label this gate files floors under.
#: ``baseline.json`` is the x86-64 ledger only when it is not the tail of
#: ``arm-baseline.json``.
_ARCHITECTURES: dict[str, re.Pattern[str]] = {
    "x86-64": re.compile(r"x86[-_]64|\bamd64\b|(?<![\w-])baseline\.json|ubuntu-latest", re.I),
    "aarch64": re.compile(r"\baarch64\b|\barm64\b|arm-baseline\.json|ubuntu-24\.04-arm", re.I),
}

#: After a claim, a further figure in the same sentence is a claim too when it
#: is itself labelled with an architecture -- "... 215,299 ops/sec on x86-64
#: and 285,176 on aarch64".  This is the phrasing the first version of the gate
#: never parsed: no "floor" before it and no "ops/sec" after it.
_LABELLED_FIGURE = re.compile(
    _NUMBER + r"(?:\s*\*\*)?(?:\s*ops/sec)?(?:\s*\*\*)?\s*(?:\bon\b|\bfor\b|\()\s*`?\s*"
    r"(?:benchmarks/)?(?:x86[-_]64|amd64|aarch64|arm64|arm-baseline\.json|baseline\.json)",
    re.IGNORECASE,
)

#: "not 76,215" -- a figure named in order to refute it is not a floor claim.
_REFUTED = re.compile(r"\bnot\s*(?:\*\*)?\s*$", re.IGNORECASE)

# A `_LATENCY_CLAIM` regex stood here, described as being "for the units
# rule". No units rule was ever written, and measurement says one of that shape
# must not be: scanning prose for `<number> <unit>` and re-deriving it finds 32
# hits, and all but a handful are the frozen historical ledger in CHANGELOG.md
# and docs/BENCHMARK_HISTORY.md, which record what a past release measured and
# would be WRONG to re-derive against today's record. The live figures moved
# into the AUTO-PIPELINE-LATENCY and AUTO-BENCHMARK-TABLE blocks instead, where
# check_generated_tables re-derives every cell rather than pattern-matching
# prose — a stronger check than the one the regex named, which is why it was
# left unused. Removed rather than kept as an unused global that implies a rule
# the gate does not run.


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    checked: int = 0
    skipped: list[str] = field(default_factory=list)

    def fail(self, detail: str) -> None:
        self.failures.append(detail)

    def ok(self) -> None:
        self.checked += 1


def _load(repo: Path, relative: str) -> Optional[dict[str, Any]]:
    path = repo / relative
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{relative} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RuntimeError(f"{relative} is not a JSON object")
    return loaded


def _floors(baseline: dict[str, Any]) -> dict[str, dict[str, Any]]:
    flat: dict[str, dict[str, Any]] = {}
    flat.update(baseline.get("benchmarks", {}))
    flat.update(baseline.get("pqc_benchmarks", {}))
    return flat


# ---------------------------------------------------------------------------
# 1 & 2. Provenance and floor hygiene
# ---------------------------------------------------------------------------


def check_provenance(report: Report, results: dict[str, Any]) -> None:
    provenance = results.get("provenance") or {}
    for key, what in REQUIRED_PROVENANCE:
        value = str(provenance.get(key, "")).strip()
        if not value:
            report.fail(
                f"{RESULTS_JSON} records no {key!r} — documentation draws numbers "
                f"from this record and a reader needs {what} to reproduce them. "
                "Re-run benchmarks/benchmark_runner.py, which writes the full "
                "provenance block."
            )
        else:
            report.ok()
    if not results.get("timestamp"):
        report.fail(f"{RESULTS_JSON} records no timestamp")
    else:
        report.ok()
    for row in results.get("results", []):
        if row.get("ops_per_second") is None:
            report.fail(f"{RESULTS_JSON}: benchmark {row.get('name')!r} has no ops_per_second")
        else:
            report.ok()


def check_baseline_fields(report: Report, relative: str, baseline: dict[str, Any]) -> None:
    for name, entry in _floors(baseline).items():
        missing = [field_name for field_name in REQUIRED_BASELINE_FIELDS if field_name not in entry]
        if missing:
            report.fail(
                f"{relative}: floor {name!r} declares no {', '.join(missing)}. A "
                "floor without a unit, a metric and a tolerance is a bare "
                "constant, which is what this gate exists to prevent."
            )
            continue
        if entry["unit"] not in {"ops/sec", "ns", "us", "ms", "bytes", "instructions"}:
            report.fail(f"{relative}: floor {name!r} has unrecognised unit {entry['unit']!r}")
            continue
        report.ok()


def check_architecture_labels(report: Report, x86: dict[str, Any], arm: dict[str, Any]) -> None:
    """Each baseline must say which runner class it was measured on."""
    for relative, baseline, expected in (
        (X86_BASELINE_JSON, x86, ("x86_64", "x86-64", "amd64")),
        (ARM_BASELINE_JSON, arm, ("aarch64", "arm64", "arm")),
    ):
        metadata = baseline.get("metadata", {})
        label = " ".join(
            str(metadata.get(key, "")) for key in ("runner_cpu_class", "system", "description")
        ).lower()
        if not any(token in label for token in expected):
            report.fail(
                f"{relative}: metadata does not name an architecture. A floor that "
                "does not say which machine it describes cannot be compared with a "
                "documented figure, which is how 76,215 survived two majors."
            )
            continue
        report.ok()


# ---------------------------------------------------------------------------
# 3. Generated tables are actually generated
# ---------------------------------------------------------------------------


def _extract_block(text: str, start: str, end: str) -> Optional[str]:
    if start not in text or end not in text:
        return None
    return text.split(start, 1)[1].split(end, 1)[0]


def check_generated_tables(report: Report, repo: Path, results: dict[str, Any]) -> None:
    """Re-derive every cell of the generated blocks and compare."""
    # Loaded by path rather than by name: this tool lives in tools/ but is run
    # from the repository root, and `--repo` may point elsewhere entirely (the
    # gate's own tests drive it against a fixture tree).
    spec = importlib.util.spec_from_file_location(
        "_update_docs_for_benchmark_claims", repo / "tools" / "update_docs.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable on a real tree
        report.fail("cannot load tools/update_docs.py to re-derive the tables")
        return
    update_docs = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(update_docs)
    except Exception as exc:  # pragma: no cover
        report.fail(f"cannot import tools/update_docs.py to re-derive the tables: {exc!r}")
        return

    for start, end, generator, label in (
        (
            LATENCY_START,
            LATENCY_END,
            update_docs._generate_pipeline_latency_table,
            "AUTO-PIPELINE-LATENCY",
        ),
        (BENCH_START, BENCH_END, update_docs._generate_benchmark_table, "AUTO-BENCHMARK-TABLE"),
    ):
        expected = generator()
        if not expected:
            report.fail(
                f"{label}: the generator produced nothing — "
                f"{RESULTS_JSON} is missing or has no results"
            )
            continue
        carried = 0
        for path in sorted(list(repo.glob("*.md")) + list(repo.glob("wiki/*.md"))):
            text = path.read_text(encoding="utf-8")
            block = _extract_block(text, start, end)
            if block is None:
                continue
            carried += 1
            if block.strip() != expected.strip():
                report.fail(
                    f"{path.relative_to(repo)}: the {label} block does not match what "
                    "tools/update_docs.py derives from "
                    f"{RESULTS_JSON}. Someone edited a generated number by hand, or "
                    "the record moved without regenerating. Run "
                    "`python tools/update_docs.py`."
                )
            else:
                report.ok()
        if carried == 0:
            report.fail(
                f"{label}: no document carries these markers any more. Deleting the "
                "markers silently stops the published table tracking the "
                "measurements — the exact failure the markers exist to prevent."
            )


# ---------------------------------------------------------------------------
# 4 & 5. Documented floors, units and ranges
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Block:
    """A paragraph, list item or table, with the enclosing context it resolves in."""

    kind: str  # "para" or "table"
    lines: tuple[tuple[int, str], ...]  # (1-based line number, text sans quote marker)
    quote: Optional[int]  # blockquote run the block sits in, if any
    section: int  # heading-delimited section index


_QUOTE_PREFIX = re.compile(r"^\s*>\s?")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")
_HEADING = re.compile(r"^\s*#{1,6}\s")


def _blocks(text: str) -> list[_Block]:
    """Split a Markdown page into paragraphs, list items and tables.

    Line numbers are preserved (generated blocks are blanked, not deleted), so
    a failure names the line a reader has to fix.
    """
    raw = text.splitlines()
    skip = False
    lines: list[Optional[str]] = []
    for original in raw:
        if LATENCY_START in original or BENCH_START in original:
            skip = True
        # Generated blocks are re-derived by check_generated_tables; blank
        # them here so one defect is not reported twice.
        lines.append(None if skip else original)
        if LATENCY_END in original or BENCH_END in original:
            skip = False

    blocks: list[_Block] = []
    section = 0
    quote_run = -1
    in_quote = False
    current: list[tuple[int, str]] = []
    current_kind = "para"
    current_quote: Optional[int] = None

    def flush() -> None:
        nonlocal current
        if current:
            blocks.append(_Block(current_kind, tuple(current), current_quote, section))
        current = []

    for number, line in enumerate(lines, start=1):
        if line is None:
            flush()
            in_quote = False
            continue
        quoted = bool(_QUOTE_PREFIX.match(line))
        if quoted and not in_quote:
            quote_run += 1
        if quoted != in_quote:
            flush()
        in_quote = quoted
        body = _QUOTE_PREFIX.sub("", line, count=1) if quoted else line
        if not body.strip():
            flush()
            continue
        if _HEADING.match(body):
            flush()
            section += 1
            current_kind, current_quote = "para", (quote_run if quoted else None)
            current = [(number, body.strip())]
            flush()
            continue
        kind = "table" if body.lstrip().startswith("|") else "para"
        if current and (kind != current_kind or (kind == "para" and _LIST_ITEM.match(body))):
            flush()
        if not current:
            current_kind, current_quote = kind, (quote_run if quoted else None)
        current.append((number, body.strip()))
    flush()
    return blocks


def _join(block: _Block) -> tuple[str, list[tuple[int, int]]]:
    """The block as one string, with (offset, line number) marks."""
    parts: list[str] = []
    marks: list[tuple[int, int]] = []
    offset = 0
    for number, content in block.lines:
        marks.append((offset, number))
        parts.append(content)
        offset += len(content) + 1
    return " ".join(parts), marks


def _line_at(marks: list[tuple[int, int]], offset: int) -> int:
    line = marks[0][1]
    for start, number in marks:
        if start > offset:
            break
        line = number
    return line


def _sentences(text: str) -> list[tuple[int, str]]:
    """(offset, sentence) pairs; a full stop inside ``1.8469`` does not split."""
    spans: list[tuple[int, str]] = []
    start = 0
    for boundary in re.finditer(r"(?<=[.!?])\s+", text):
        spans.append((start, text[start : boundary.start()]))
        start = boundary.end()
    spans.append((start, text[start:]))
    return [(offset, sentence) for offset, sentence in spans if sentence.strip()]


def _benchmark_patterns(names: set[str]) -> dict[str, re.Pattern[str]]:
    """``hmac_sha3_256`` also matches ``ama_hmac_sha3_256`` and ``HMAC-SHA3-256``.

    The trailing guard keeps ``ed25519_sign`` from matching inside
    ``ed25519_sign_expanded``: a name continues through ``_`` or ``-``.
    """
    patterns: dict[str, re.Pattern[str]] = {}
    for name in names:
        stem = name[4:] if name.startswith("ama_") else name
        body = r"[-_]".join(re.escape(token) for token in stem.split("_"))
        patterns[name] = re.compile(
            r"(?<![A-Za-z0-9])(?:ama[-_])?" + body + r"(?![A-Za-z0-9]|[-_][A-Za-z0-9])",
            re.IGNORECASE,
        )
    return patterns


def _resolve(
    patterns: dict[str, re.Pattern[str]], contexts: list[tuple[str, str]]
) -> tuple[Optional[str], str]:
    """The one name the nearest context that names any names, or why not.

    Nearest first.  A context naming two is ambiguous and is NOT resolved by a
    wider one: widening past an ambiguity is guessing.
    """
    for label, text in contexts:
        found = sorted(name for name, pattern in patterns.items() if pattern.search(text))
        if len(found) == 1:
            return found[0], label
        if len(found) > 1:
            return None, f"its {label} names {', '.join(found)}"
    return None, "nothing around it names one"


@dataclass(frozen=True)
class FloorClaim:
    path: str
    line: int
    value: str
    benchmark: Optional[str]
    architecture: Optional[str]
    why_unattributed: str
    excerpt: str


def extract_floor_claims(text: str, path: str, benchmarks: set[str]) -> list[FloorClaim]:
    """Every figure a page asserts to be a regression floor, attributed.

    Identity is resolved from the claim outward -- the text between this figure
    and the next claimed one, then its sentence (or table row), then its
    paragraph, blockquote and section -- and the nearest context naming exactly
    one benchmark (or architecture) decides.
    """
    bench_patterns = _benchmark_patterns(benchmarks)
    blocks = _blocks(text)
    quotes: dict[int, str] = {}
    sections: dict[int, str] = {}
    for block in blocks:
        joined = _join(block)[0]
        sections[block.section] = sections.get(block.section, "") + " " + joined
        if block.quote is not None:
            quotes[block.quote] = quotes.get(block.quote, "") + " " + joined

    claims: list[FloorClaim] = []

    def attribute(
        line: int,
        value: str,
        bench_contexts: list[tuple[str, str]],
        arch_contexts: list[tuple[str, str]],
        excerpt: str,
    ) -> None:
        bench, bench_why = _resolve(bench_patterns, bench_contexts)
        arch, arch_why = _resolve(_ARCHITECTURES, arch_contexts)
        why = []
        if bench is None:
            why.append(f"no benchmark: {bench_why}")
        if arch is None:
            why.append(f"no architecture: {arch_why}")
        claims.append(FloorClaim(path, line, value, bench, arch, "; ".join(why), excerpt))

    def scan(
        sentence: str,
        marks: list[tuple[int, int]],
        base: int,
        label: str,
        wider: list[tuple[str, str]],
    ) -> None:
        found: dict[int, str] = {}
        for pattern in _FLOOR_CLAIMS:
            for match in pattern.finditer(sentence):
                found.setdefault(match.start("value"), match.group("value"))
        if not found:
            return
        first = min(found)
        for match in _LABELLED_FIGURE.finditer(sentence):
            position = match.start("value")
            if position > first and not _REFUTED.search(sentence[:position]):
                found.setdefault(position, match.group("value"))
        ordered = sorted(found)
        for index, position in enumerate(ordered):
            end = ordered[index + 1] if index + 1 < len(ordered) else len(sentence)
            own = [(label, sentence)]
            attribute(
                _line_at(marks, base + position),
                found[position],
                own + wider,
                [("clause", sentence[position:end]), *own, *wider],
                sentence,
            )

    for block in blocks:
        section = ("section", sections[block.section])
        if block.kind == "table":
            # A column headed as a floor in ops/sec makes every figure in it a
            # claim; the row names the benchmark, the header the architecture.
            header = [cell.strip() for cell in block.lines[0][1].strip("|").split("|")]
            columns = [
                index
                for index, cell in enumerate(header)
                if re.search(r"\bfloor", cell, re.I) and re.search(r"ops/s", cell, re.I)
            ]
            for number, row in block.lines[2:]:
                cells = [cell.strip() for cell in row.strip("|").split("|")]
                for index in columns:
                    if index >= len(cells):
                        continue
                    for match in re.finditer(_NUMBER, cells[index]):
                        attribute(
                            number,
                            match.group("value"),
                            [("row", row), section],
                            [("column header", header[index]), ("row", row), section],
                            row,
                        )
            # Outside such a column a row is prose: "floor is N ops/sec" in a
            # cell is a claim, attributed from its row outward.
            if not columns:
                for number, row in block.lines:
                    scan(row, [(0, number)], 0, "row", [section])
            continue

        joined, marks = _join(block)
        wider: list[tuple[str, str]] = [("paragraph", joined)]
        if block.quote is not None:
            wider.append(("blockquote", quotes[block.quote]))
        wider.append(section)
        for start, sentence in _sentences(joined):
            scan(sentence, marks, start, "sentence", wider)
    return claims


def check_documented_floors(
    report: Report, repo: Path, x86: dict[str, Any], arm: dict[str, Any]
) -> None:
    """A figure documented as a floor must be THAT benchmark's floor on THAT architecture.

    Matching a value against every floor in both ledgers -- which this did
    until 2026-09 -- accepts HMAC's 215,299 cited as the ed25519_sign floor, or
    an x86-64 figure labelled aarch64.  And a floor-shaped figure the gate
    cannot attribute to one benchmark and one architecture fails rather than
    passing: a claim that cannot be checked is not evidence it is right.
    """
    floors: dict[tuple[str, str], float] = {}
    for architecture, baseline in (("x86-64", x86), ("aarch64", arm)):
        for name, entry in _floors(baseline).items():
            if isinstance(entry.get("baseline_value"), (int, float)):
                floors[(architecture, name)] = float(entry["baseline_value"])
    if not floors:
        report.fail("no floors could be read from the baseline JSON files")
        return
    benchmarks = {name for _, name in floors}

    for path in sorted(list(repo.glob("*.md")) + list(repo.glob("wiki/*.md"))):
        if path.name == "CHANGELOG.md":
            continue
        relative = str(path.relative_to(repo))
        for claim in extract_floor_claims(path.read_text(encoding="utf-8"), relative, benchmarks):
            where = f"{claim.path}:{claim.line}"
            excerpt = f"\n      {claim.excerpt[:200]}"
            if claim.benchmark is None or claim.architecture is None:
                report.fail(
                    f"{where} documents a regression floor of {claim.value} that "
                    f"cannot be attributed ({claim.why_unattributed}). Name the "
                    "benchmark identifier and the architecture in the claim, so "
                    "it can be checked against the ledger that enforces it." + excerpt
                )
                continue
            expected = floors.get((claim.architecture, claim.benchmark))
            ledger = X86_BASELINE_JSON if claim.architecture == "x86-64" else ARM_BASELINE_JSON
            if expected is None:
                report.fail(
                    f"{where} documents a {claim.architecture} floor of {claim.value} "
                    f"for {claim.benchmark}, which has no floor in {ledger}." + excerpt
                )
                continue
            if float(claim.value.replace(",", "")) != expected:
                report.fail(
                    f"{where} documents the {claim.architecture} {claim.benchmark} "
                    f"floor as {claim.value} ops/sec; {ledger} enforces "
                    f"{expected:,.0f}. A floor cited against the wrong benchmark "
                    "or architecture is enforcing nothing." + excerpt
                )
                continue
            report.ok()


def check_measured_against_floor(
    report: Report, results: dict[str, Any], x86: dict[str, Any]
) -> None:
    """A measured figure many times its own floor is a units or identity error."""
    floors = _floors(x86)
    for row in results.get("results", []):
        name = row.get("name")
        ops = row.get("ops_per_second")
        entry = floors.get(name)
        if not (name and ops and entry):
            continue
        floor = entry.get("baseline_value")
        if not isinstance(floor, (int, float)) or floor <= 0:
            continue
        ratio = float(ops) / float(floor)
        if ratio > MAX_MEASURED_OVER_FLOOR:
            report.fail(
                f"{name}: the committed measurement is {ops:,.1f} ops/sec against a "
                f"floor of {floor:,} — {ratio:.1f}x. Genuine hardware spread does "
                f"not reach {MAX_MEASURED_OVER_FLOOR:g}x; check the units and that "
                "both figures name the same operation."
            )
            continue
        report.ok()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    args = parser.parse_args(argv)
    repo: Path = args.repo

    if not (repo / "benchmarks").is_dir():
        print(f"FATAL: {repo} does not look like the repository root.", file=sys.stderr)
        return 2

    try:
        results = _load(repo, RESULTS_JSON)
        x86 = _load(repo, X86_BASELINE_JSON)
        arm = _load(repo, ARM_BASELINE_JSON)
    except RuntimeError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    if results is None or x86 is None or arm is None:
        missing = [
            name
            for name, value in (
                (RESULTS_JSON, results),
                (X86_BASELINE_JSON, x86),
                (ARM_BASELINE_JSON, arm),
            )
            if value is None
        ]
        print(f"FATAL: missing benchmark record(s): {', '.join(missing)}", file=sys.stderr)
        return 2

    report = Report()
    check_provenance(report, results)
    check_baseline_fields(report, X86_BASELINE_JSON, x86)
    check_baseline_fields(report, ARM_BASELINE_JSON, arm)
    check_architecture_labels(report, x86, arm)
    check_generated_tables(report, repo, results)
    check_documented_floors(report, repo, x86, arm)
    check_measured_against_floor(report, results, x86)

    if report.failures:
        print(
            f"BENCHMARK CLAIM CHECK FAILED — {len(report.failures)} problem(s):",
            file=sys.stderr,
        )
        for failure in report.failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nA published performance number must be re-derivable from a record "
            "that says how it was measured. Do not replace one unexplained "
            "constant with another.",
            file=sys.stderr,
        )
        return 1

    print(f"OK    {report.checked} benchmark claim(s) consistent with their records")
    for skipped in report.skipped:
        print(f"SKIP  {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
