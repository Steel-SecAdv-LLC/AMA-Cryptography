#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Aggregate the per-target mutation runs into docs/audit/PR394_MUTATION.tsv.

One row per measured target: mutant count, killed, survived, timed out, the
kill rate over decided mutants, and the surviving mutants broken down by
operator so the disposition can be read (a surviving string constant in a
diagnostic message is a different thing from a surviving comparison flip).

Usage::

    python docs/audit/sweeps/mutation_summary.py
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
#: Where measurements live.  Phase D is the first pass; phase R is the
#: re-measurement made after the survivors were read one by one (FINDING-0011).
#: A target measured in both is reported from its LATEST round, with the
#: earlier logs named in their own column so the improvement stays auditable
#: and no measurement is quietly replaced.
RUN_DIRS = (
    REPO / "docs" / "audit" / "logs" / "phaseD" / "mutation",
    REPO / "docs" / "audit" / "logs" / "phaseR" / "mutation",
)
OUT = REPO / "docs" / "audit" / "PR394_MUTATION.tsv"


def _order(path: Path) -> tuple[int, float]:
    """Sort key: which pass, then which round within it.

    The convention, in both directories: a ``.roundN.tsv`` file is an EARLIER
    round and the unsuffixed file is that pass's final measurement.  Sorting
    the unsuffixed file first — as an earlier revision of this function did —
    reported `check_keygen_pct.py` at its round-1 rate of 47/55 rather than
    its final 51/55, and `check_dudect_class_staging.py` at 60/95 rather than
    80/95: a summary that silently replaced two measurements with worse,
    superseded ones.
    """
    phase = 1 if "phaseR" in path.parts else 0
    match = re.search(r"\.round(\d+)\.tsv$", path.name)
    return (phase, float(match.group(1)) if match else float("inf"))


def _target_of(path: Path) -> str:
    """The target a measurement file is about, from its own summary line."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# target="):
            return line.split("target=", 1)[1].split()[0]
    return path.stem.split(".")[0]


def _latest_per_target() -> dict[str, list[Path]]:
    """Every measurement of each target, oldest first."""
    seen: dict[str, list[Path]] = {}
    for directory in RUN_DIRS:
        for tsv in sorted(directory.glob("*.tsv")) if directory.is_dir() else []:
            seen.setdefault(_target_of(tsv), []).append(tsv)
    for paths in seen.values():
        paths.sort(key=_order)
    return seen


def main() -> int:
    rows = [
        "target\ttests\tmutants\tkilled\tsurvived\ttimeout\tkill_rate\tsurvivors_by_operator\tsurviving_logic_mutants\trun_log\tearlier_rounds"
    ]
    for _target, history in sorted(_latest_per_target().items()):
        tsv = history[-1]
        earlier = ";".join(str(q.relative_to(REPO)) for q in history[:-1]) or "-"
        lines = tsv.read_text(encoding="utf-8").splitlines()
        summary = next((line for line in lines if line.startswith("# target=")), "")
        m = re.search(
            r"target=(\S+) tests=(.*?) self_run=\S+ mutants=(\d+) killed=(\d+) survived=(\d+) timeout=(\d+) kill_rate=([0-9.]+)",
            summary,
        )
        if not m:
            print(f"no summary in {tsv}", file=sys.stderr)
            continue
        target, tests, mutants, killed, survived, timeout, rate = m.groups()
        by_op: collections.Counter[str] = collections.Counter()
        logic: list[str] = []
        for line in lines[1:]:
            if line.startswith("#") or not line.strip():
                continue
            f = line.split("\t")
            if len(f) < 9 or f[8] != "survived":
                continue
            by_op[f[3]] += 1
            if f[3] != "str-const":
                logic.append(f"L{f[1]}:{f[4]}->{f[5]}")
        ops = ",".join(f"{k}={v}" for k, v in sorted(by_op.items()))
        rows.append(
            "\t".join(
                [
                    target,
                    tests,
                    mutants,
                    killed,
                    survived,
                    timeout,
                    rate,
                    ops or "-",
                    ";".join(logic) or "-",
                    str(tsv.relative_to(REPO)),
                    earlier,
                ]
            )
        )
    OUT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("\n".join(r.split("\t")[0] + "\t" + "\t".join(r.split("\t")[2:7]) for r in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
