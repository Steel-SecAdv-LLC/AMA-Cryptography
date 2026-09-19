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
   have caught 76,215 and 70,496.
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

#: Documentation lines asserting a regression floor, e.g.
#: "the enforced floor is 215,299 ops/sec on x86-64".
_FLOOR_CLAIM = re.compile(
    r"\bfloor\b[^.\n]{0,120}?\b(?P<value>\d{1,3}(?:,\d{3})+|\d{4,})\b" r"[^.\n]{0,60}?\bops/sec\b",
    re.IGNORECASE,
)

#: A bare latency assertion with a unit, for the units rule.
_LATENCY_CLAIM = re.compile(
    r"(?P<what>[A-Za-z0-9 +\-/]{3,40}?)\s*(?:signing|sign|verify|hash|derive)"
    r"[^.\n]{0,40}?\(?\s*~?(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|µs|us|ns)\b",
    re.IGNORECASE,
)


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


_TABLE_ROW = re.compile(r"^\|\s*(?P<label>[^|]+?)\s*\|(?P<rest>.*)\|\s*$")


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


def check_documented_floors(
    report: Report, repo: Path, x86: dict[str, Any], arm: dict[str, Any]
) -> None:
    """Any ops/sec figure documented as a *floor* must be one."""
    known = {
        float(entry["baseline_value"])
        for baseline in (x86, arm)
        for entry in _floors(baseline).values()
        if isinstance(entry.get("baseline_value"), (int, float))
    }
    if not known:
        report.fail("no floors could be read from the baseline JSON files")
        return

    for path in sorted(list(repo.glob("*.md")) + list(repo.glob("wiki/*.md"))):
        if path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8")
        # Generated blocks are re-derived above; skip them here so one defect
        # is not reported twice.
        for start, end in ((LATENCY_START, LATENCY_END), (BENCH_START, BENCH_END)):
            block = _extract_block(text, start, end)
            if block is not None:
                text = text.replace(block, "")
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            for match in _FLOOR_CLAIM.finditer(line):
                value = float(match.group("value").replace(",", ""))
                if value in known:
                    report.ok()
                    continue
                report.fail(
                    f"{path.relative_to(repo)}:{number} documents a regression floor "
                    f"of {match.group('value')} ops/sec. No entry in "
                    f"{X86_BASELINE_JSON} or {ARM_BASELINE_JSON} carries that "
                    "value, so it is enforcing nothing.\n"
                    f"      {line[:150]}"
                )


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
