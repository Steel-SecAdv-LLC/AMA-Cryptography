#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Fuzz Target Registration Verifier (INVARIANT-33)
===================================================================

Verifies that every fuzz harness in ``fuzz/`` is registered in all three
places that must know about it, and that none of those places names a target
that does not exist.

Why this exists
---------------
A fuzz target is registered in three independent lists:

* ``fuzz/CMakeLists.txt`` — ``FUZZ_CORE_TARGETS`` / ``FUZZ_PQC_TARGETS``,
  which decide what the local and CI builds compile;
* ``.github/workflows/fuzzing.yml`` — the job matrix, which decides what the
  per-PR fuzz lane actually runs;
* ``oss-fuzz/build.sh`` — ``FUZZ_TARGETS``, which decides what Google's
  OSS-Fuzz infrastructure builds and runs continuously.

Nothing tied them together.  ``oss-fuzz/build.sh`` even carries the comment
"Keep in sync with fuzz/CMakeLists.txt" — and had drifted anyway:
``fuzz_agent_binding`` was added to the CMake lists and to the workflow matrix
when the agent-binding layer landed, and never to ``build.sh``.  OSS-Fuzz
therefore never built it, and the omission was invisible because
``build.sh`` skips a missing target with a warning and exits 0.

That is the worst shape a coverage gap can take: the target exists, it is
tested in CI, and the continuous fuzzing that is supposed to run it for
months on end silently does not.  A harness nobody runs is indistinguishable
from a harness that finds nothing.

What is checked
---------------
The set of ``fuzz/fuzz_*.c`` files must equal the union of the two CMake
lists, must equal the workflow matrix, and must equal the ``build.sh`` array.
Any target present in one list and absent from another is reported with the
direction of the drift, as is a list entry with no corresponding source file.

Both directions are pinned by ``tests/test_fuzz_target_registration.py``.

Usage
-----
::

    python tools/check_fuzz_target_registration.py

Exits 0 when all four sets agree, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FUZZ_DIR = Path("fuzz")
CMAKE_PATH = Path("fuzz/CMakeLists.txt")
WORKFLOW_PATH = Path(".github/workflows/fuzzing.yml")
OSSFUZZ_PATH = Path("oss-fuzz/build.sh")

_TARGET_RE = re.compile(r"\bfuzz_[a-z0-9_]+\b")

#: A libFuzzer entry-point *definition* at the start of a line — not a mention
#: of the symbol in prose, and not a declaration inside a comment block.
_ENTRY_POINT_RE = re.compile(
    r"^\s*(?:extern\s+\"C\"\s+)?int\s+LLVMFuzzerTestOneInput\s*\(",
    re.M,
)


def _sources(root: Path) -> set[str]:
    """Every fuzz harness that actually exists as a source file.

    A harness is identified by *defining* ``LLVMFuzzerTestOneInput``, not by
    its filename and not by mentioning the symbol.  Both distinctions are
    load-bearing:

    * ``fuzz/`` contains support translation units linked *into* a harness
      rather than being one — ``fuzz_rng.c`` supplies
      ``__wrap_ama_randombytes`` to ``fuzz_frost`` — so a filename glob
      reports those as unregistered targets forever.
    * ``fuzz_rng.c`` also *names* ``LLVMFuzzerTestOneInput`` in a comment, so
      a substring test misclassifies it as a harness for the same reason.
    """
    harnesses: set[str] = set()
    for path in sorted((root / FUZZ_DIR).glob("fuzz_*.c")):
        text = path.read_text(encoding="utf-8")
        if _ENTRY_POINT_RE.search(text):
            harnesses.add(path.stem)
    return harnesses


def _strip_comments(text: str, marker: str) -> str:
    """Drop comment lines so a target named in prose is not counted.

    This must run BEFORE the block is delimited, not after: these lists carry
    explanatory comments containing parentheses — "(INVARIANT-30)" — and a
    naive scan for the closing ")" truncates the block at the first one,
    silently reporting the targets below it as unregistered.
    """
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith(marker))


def _block(text: str, start_pattern: str) -> str:
    """Return the parenthesised block introduced by a pattern.

    Callers pass comment-stripped text; see :func:`_strip_comments`.
    """
    match = re.search(start_pattern, text)
    if not match:
        return ""
    tail = text[match.end() :]
    end = tail.find(")")
    return tail[:end] if end >= 0 else ""


def _cmake_targets(root: Path) -> set[str]:
    text = _strip_comments((root / CMAKE_PATH).read_text(encoding="utf-8"), "#")
    found: set[str] = set()
    for pattern in (r"set\(FUZZ_CORE_TARGETS", r"set\(FUZZ_PQC_TARGETS"):
        found |= set(_TARGET_RE.findall(_block(text, pattern)))
    return found


def _workflow_targets(root: Path) -> set[str]:
    """Matrix entries that actively run: `          - fuzz_sha3`."""
    text = (root / WORKFLOW_PATH).read_text(encoding="utf-8")
    return {match.group(1) for match in re.finditer(r"^\s*-\s+(fuzz_[a-z0-9_]+)\s*$", text, re.M)}


def _workflow_documented_exclusions(root: Path) -> set[str]:
    """Matrix entries commented out on purpose: `        # - fuzz_sphincs`.

    Not every harness belongs in the per-PR lane.  ``fuzz_sphincs`` is
    excluded because SPHINCS+ is too slow for CI, and that decision is
    recorded in the workflow next to the entry.  A commented-out entry is a
    *documented* exclusion and is accepted here; a harness that appears
    nowhere at all is silent drift and is not.  Such a target must still be
    registered in the two build lanes, so OSS-Fuzz keeps running it.
    """
    text = (root / WORKFLOW_PATH).read_text(encoding="utf-8")
    return {
        match.group(1) for match in re.finditer(r"^\s*#\s*-\s+(fuzz_[a-z0-9_]+)\s*$", text, re.M)
    }


def _ossfuzz_targets(root: Path) -> set[str]:
    text = _strip_comments((root / OSSFUZZ_PATH).read_text(encoding="utf-8"), "#")
    return set(_TARGET_RE.findall(_block(text, r"FUZZ_TARGETS=\(")))


def audit(root: Path = Path(".")) -> list[str]:
    """Compare all four sets and describe every disagreement."""
    sources = _sources(root)
    registries: dict[str, set[str]] = {
        "fuzz/CMakeLists.txt": _cmake_targets(root),
        # A documented (commented-out) matrix entry counts as registered here;
        # see _workflow_documented_exclusions for why.
        ".github/workflows/fuzzing.yml": (
            _workflow_targets(root) | _workflow_documented_exclusions(root)
        ),
        "oss-fuzz/build.sh": _ossfuzz_targets(root),
    }

    failures: list[str] = []
    if not sources:
        failures.append("no fuzz_*.c sources found — is the path correct?")
        return failures

    for name, registered in registries.items():
        missing = sorted(sources - registered)
        if missing:
            failures.append(
                f"{name}: {len(missing)} harness(es) exist in fuzz/ but are not "
                f"registered — {', '.join(missing)}. A harness absent here is "
                f"never built or run by that lane, which is indistinguishable "
                f"from a harness that finds nothing."
            )
        unknown = sorted(registered - sources)
        if unknown:
            failures.append(
                f"{name}: names target(s) with no fuzz/<name>.c source — " f"{', '.join(unknown)}."
            )

    return failures


def main() -> int:
    root = Path.cwd()
    for required in (FUZZ_DIR, CMAKE_PATH, WORKFLOW_PATH, OSSFUZZ_PATH):
        if not (root / required).exists():
            print(f"ERROR: {required} not found — run from the repository root.")
            return 1

    failures = audit(root)
    sources = _sources(root)

    print("INVARIANT-33: fuzz target registration")
    print(f"  harnesses in fuzz/: {len(sources)}")

    if failures:
        print(f"  FAIL — {len(failures)} finding(s):\n")
        for failure in failures:
            print(f"    ::error::{failure}\n")
        return 1

    print("  PASS — every harness is registered in CMake, CI and OSS-Fuzz.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
