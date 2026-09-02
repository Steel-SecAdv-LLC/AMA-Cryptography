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
RUNS = REPO / "docs" / "audit" / "logs" / "phaseD" / "mutation"
OUT = REPO / "docs" / "audit" / "PR394_MUTATION.tsv"


def main() -> int:
    rows = [
        "target\ttests\tmutants\tkilled\tsurvived\ttimeout\tkill_rate\tsurvivors_by_operator\tsurviving_logic_mutants\trun_log"
    ]
    for tsv in sorted(RUNS.glob("*.tsv")):
        if ".round" in tsv.name:
            continue
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
                    f"docs/audit/logs/phaseD/mutation/{tsv.name}",
                ]
            )
        )
    OUT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("\n".join(r.split("\t")[0] + "\t" + "\t".join(r.split("\t")[2:7]) for r in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
