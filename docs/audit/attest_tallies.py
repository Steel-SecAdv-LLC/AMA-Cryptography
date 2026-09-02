#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tallies for docs/audit/PR394_ATTESTATION.md, computed from the artefacts.

Every number the attestation states is read from the committed tables so it
cannot drift from them: claims by verdict, coverage rows by depth,
negative-control verdicts, mutation kill rates, findings by severity and
status, and the validation rows of the ledger.  Prints a Markdown fragment.

Usage::

    python docs/audit/attest_tallies.py
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
AUDIT = REPO / "docs" / "audit"


def _tsv(path: Path) -> list[dict[str, str]]:
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    head = lines[0].split("\t")
    return [dict(zip(head, line.split("\t"))) for line in lines[1:]]


def claims() -> str:
    path = AUDIT / "PR394_CLAIMS.yaml"
    if not path.is_file():
        return "- claims: PR394_CLAIMS.yaml absent\n"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = data.get("claims", data) if isinstance(data, dict) else data
    by = collections.Counter(str(e.get("verdict", "?")) for e in entries)
    refuted = [e for e in entries if e.get("verdict") == "refuted"]
    mapped = sum(1 for e in refuted if e.get("finding") or e.get("action"))
    return (
        f"- claims: {len(entries)} executed reproductions — confirmed {by.get('confirmed', 0)}, "
        f"refuted {by.get('refuted', 0)}, unverifiable {by.get('unverifiable', 0)}"
        f" (ratio {by.get('confirmed', 0)}:{by.get('refuted', 0)}:{by.get('unverifiable', 0)}); "
        f"refuted claims carrying a finding or disposition: {mapped}/{len(refuted)}\n"
    )


def coverage() -> str:
    rows = _tsv(AUDIT / "PR394_COVERAGE.tsv")
    executed = sum(1 for r in rows if r["ledger_ids"] != "none")
    read = sum(1 for r in rows if r["read_by_auditor"] != "no")
    none = [r["path"] for r in rows if r["ledger_ids"] == "none" and r["read_by_auditor"] == "no"]
    changed = sum(1 for r in rows if r["changed_in_pr"] == "yes")
    return (
        f"- coverage: {len(rows)} files in scope ({changed} changed in the PR); executed-against by at least one ledger row: {executed}; "
        f"read by the auditor: {read}; with neither: {len(none)}\n"
        + ("".join(f"    - not-reviewed: {p}\n" for p in none[:200]))
    )


def controls() -> str:
    rows = _tsv(AUDIT / "PR394_NEGATIVE_CONTROLS.tsv")
    by = collections.Counter(r["verdict"] for r in rows)
    bad = [f"{r['id']} ({r['verdict']})" for r in rows if r["verdict"] != "OK"]
    return (
        f"- negative controls: {len(rows)} controls; made to fail and pass clean: {by.get('OK', 0)}; "
        f"could not be made to fail or not clean: {len(bad)}"
        + (f" — {', '.join(bad)}" if bad else "")
        + "\n"
    )


def mutation() -> str:
    rows = _tsv(AUDIT / "PR394_MUTATION.tsv")
    out = "- mutation kill rate, per measured target (killed / decided):\n"
    for r in rows:
        out += (
            f"    - {r['target']}: {r['killed']}/{int(r['killed']) + int(r['survived'])} = {float(r['kill_rate']):.1%} "
            f"({r['survived']} survived: {r['survivors_by_operator']}; timeouts {r['timeout']})\n"
        )
    return out


def findings() -> str:
    data = yaml.safe_load((AUDIT / "PR394_FINDINGS.yaml").read_text(encoding="utf-8"))
    by = collections.Counter((f["severity"], f["status"]) for f in data)
    lines = [
        f"- findings: {len(data)} — "
        + ", ".join(f"{s} {st}: {n}" for (s, st), n in sorted(by.items()))
    ]
    for f in data:
        lines.append(f"    - {f['id']} [{f['severity']}, {f['status']}]: {f['title']}")
    return "\n".join(lines) + "\n"


def validation() -> str:
    rows = [
        line.split("\t")
        for line in (AUDIT / "ledger.tsv").read_text(encoding="utf-8").splitlines()[1:]
        if line.startswith("V-")
    ]
    latest: dict[str, list[str]] = {}
    for r in rows:
        latest[r[0]] = r
    bad = [f"{k} exit {v[3]}" for k, v in latest.items() if v[3] != "0"]
    return (
        f"- validation rows (latest per id): {len(latest)}; non-zero exits: {len(bad)}"
        + (f" — {', '.join(bad)}" if bad else "")
        + "\n"
    )


ATTESTATION = AUDIT / "PR394_ATTESTATION.md"
BEGIN = "<!-- TALLIES:BEGIN -->"
END = "<!-- TALLIES:END -->"


def render() -> str:
    out = []
    for fn in (claims, coverage, controls, mutation, findings, validation):
        try:
            out.append(fn())
        except FileNotFoundError as exc:
            out.append(f"- {fn.__name__}: missing input ({exc.filename})\n")
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--write",
        action="store_true",
        help="replace the TALLIES block in PR394_ATTESTATION.md instead of printing",
    )
    args = ap.parse_args()
    block = render()
    if not args.write:
        sys.stdout.write(block)
        return 0
    text = ATTESTATION.read_text(encoding="utf-8")
    head, _, rest = text.partition(BEGIN)
    _, _, tail = rest.partition(END)
    ATTESTATION.write_text(
        f"{head}{BEGIN}\n\n## Tallies (generated by docs/audit/attest_tallies.py)\n\n{block}\n{END}{tail}",
        encoding="utf-8",
    )
    print(f"wrote {len(block.splitlines())} tally line(s) into {ATTESTATION.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
