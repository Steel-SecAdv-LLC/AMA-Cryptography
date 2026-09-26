#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Fail-closed gate on Semgrep findings, read from the JSON report.

Why this exists
---------------
The CI step ran::

    semgrep --config .semgrep.yml ama_cryptography/ --json -o semgrep-report.json

``semgrep scan`` exits 0 whether or not it finds anything unless ``--error`` is
passed, and nothing ever read ``semgrep-report.json``.  The "Semgrep security
scan" step in the merge-blocking job therefore could not fail: with the pinned
``semgrep==1.74.0`` the repository's own tree produces findings and a file that
trips the config's own ERROR-severity rules still exits 0.  A gate that cannot
fail is not a gate; it is a green light wired to nothing.

This mirrors ``tools/check_bandit_severity.py``: apply the policy to the JSON
data rather than to an exit code the scanner never sets.  The policy blocks on
any finding at or above ERROR severity — the config's Python ERROR rules
``insecure-random-usage``, ``weak-hash-algorithm``, ``deprecated-cryptography-api``,
``private-key-logging`` and ``unsafe-pickle-usage`` — so a genuinely dangerous
pattern fails CI while the existing WARNING-level constant-time advisories do
not (they are tracked, not merge-blocking).

.. note::
   ``.semgrep.yml`` also declares ``bare-memset-zero-secret-named-buffer`` at
   ERROR, but that C rule does NOT run under this gate and cannot: semgrep's C
   parser chokes on the AMA_API export macro, and the rule is scoped to
   ``src/c/`` which this scan never targets (see the rule's ENFORCEMENT NOTE in
   ``.semgrep.yml``).  The property it states is enforced by
   ``tools/check_c_secret_zeroization.py`` instead.  It is listed here as a
   control that is live in the repo, just not via this gate.

Fail-closed conditions — anything meaning "the scan did not actually run over
the tree" is a failure, not a pass:

* the report is missing, unreadable, or not JSON;
* it has no ``results`` list, or that list holds something other than
  result objects;
* a result carries no severity, or one this gate does not rank — a finding it
  cannot rank is a finding it cannot clear, so it blocks;
* Semgrep recorded scan ``errors`` (a rule or file that failed to evaluate was
  not actually checked);
* ``paths.scanned`` is empty (nothing was examined).

Usage::

    python tools/check_semgrep_severity.py [semgrep-report.json]

Exit status: 0 when the scan ran and produced no finding at or above the
severity floor; 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_REPORT = "semgrep-report.json"

#: Semgrep severities, weakest to strongest.  The gate blocks at or above FLOOR.
_ORDER = {"INFO": 0, "WARNING": 1, "ERROR": 2}
FLOOR = "ERROR"


def _fail(message: str) -> int:
    print(f"SEMGREP GATE FAILED — {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    report_path = Path(args[0] if args else DEFAULT_REPORT)

    if not report_path.is_file():
        return _fail(
            f"report {report_path} not found. The scan did not run, so the tree "
            "is unverified — fail closed."
        )
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return _fail(f"report {report_path} is not readable JSON ({exc}).")

    if not isinstance(data, dict) or "results" not in data:
        return _fail(f"report {report_path} has no 'results' key — not a semgrep report.")

    errors = data.get("errors") or []
    if errors:
        # A rule that failed to compile or a file that failed to parse was not
        # actually evaluated; an unevaluated tree is not a clean tree.
        summaries = "; ".join(str(e.get("message") or e.get("type") or e)[:160] for e in errors[:5])
        return _fail(f"semgrep reported {len(errors)} scan error(s): {summaries}")

    scanned = (data.get("paths") or {}).get("scanned") or []
    if not scanned:
        return _fail("semgrep scanned zero files — the config or target path is wrong.")

    results = data["results"]
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        return _fail(
            f"report {report_path} has a 'results' value that is not a list of "
            "result objects — not a semgrep report."
        )

    floor = _ORDER[FLOOR]
    blocking = []
    for result in results:
        extra = result.get("extra")
        raw = extra.get("severity") if isinstance(extra, dict) else None
        # Fail closed on an unrecognised severity.  Mapping an unknown label to
        # INFO (the old `.get(severity, 0)`) means a future Semgrep level above
        # ERROR — or a custom label from a config — would sink to INFO and slip a
        # real finding through a merge-blocking gate.  Unknown severity blocks.
        #
        # So does an ABSENT one.  The read used to be
        # `extra.get("severity", "INFO")`: a result carrying no severity (or no
        # `extra` at all) was labelled INFO by this gate — a label Semgrep never
        # gave it — and passed as an advisory.  A result the gate cannot rank
        # is a result it cannot clear.
        rank = _ORDER.get(raw.upper()) if isinstance(raw, str) else None
        if rank is None or rank >= floor:
            blocking.append(result)

    if blocking:
        print(
            f"SEMGREP GATE FAILED — {len(blocking)} finding(s) at or above {FLOOR} "
            "severity (a missing or unrecognised severity counts as at or above):\n",
            file=sys.stderr,
        )
        for r in blocking:
            path = r.get("path", "?")
            line = (r.get("start") or {}).get("line", "?")
            check = r.get("check_id", "?")
            extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
            severity = extra.get("severity") or "NO SEVERITY"
            msg = str(extra.get("message", "")).strip().splitlines()
            first = msg[0] if msg else ""
            print(f"  {path}:{line}: [{check}] ({severity}) {first}", file=sys.stderr)
        return 1

    print(
        f"OK: semgrep scanned {len(scanned)} file(s); no finding at or above "
        f"{FLOOR} severity ({len(results)} lower-severity advisory finding(s))."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
