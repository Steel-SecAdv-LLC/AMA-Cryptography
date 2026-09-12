#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Log Message Encodability Verifier (INVARIANT-43)
===================================================================

Verifies that every literal string this library hands to ``logging`` or to
``warnings.warn`` can be encoded in ``cp1252`` — the code page a default
Windows install gives ``locale.getpreferredencoding()``.

Why this exists
---------------
A library does not own the process's logging handlers; the application does.
``logging.FileHandler`` opens its file with ``encoding=None``, which resolves
to the platform's preferred encoding, and with strict error handling.  On a
Western-European Windows host that is ``cp1252``.

When a record's text contains a character ``cp1252`` cannot represent, the
encode raises inside ``Handler.emit``.  ``logging`` does not propagate that:
it routes the exception to ``Handler.handleError``, which prints a traceback
to ``stderr`` and **discards the record**.  The call site sees nothing.  The
log file simply never receives the line:

.. code-block:: text

    >>> h = logging.FileHandler("app.log", encoding="cp1252")
    >>> log.info("Posture-triggered key rotation: %s -> %s", old, new)   # U+2192
    --- Logging error ---
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'
    >>> open("app.log", "rb").read()
    b''

That shipped.  ``adaptive_posture.py`` logged both the key-rotation and the
algorithm-switch events with a ``→`` between the old and new identifiers, so
on Windows the two records that say a signing key changed were the exact two
records a cp1252 ``FileHandler`` dropped.  An audit trail that silently loses
precisely the key-rotation entries is worse than one that was never claimed,
because the absence is indistinguishable from "no rotation happened".

``sys.stderr`` masks this in casual testing: CPython gives it
``errors="backslashreplace"``, so a bare ``StreamHandler`` degrades to a
visible ``\\u2192`` escape rather than a loss.  Only a handler that opens its
own stream — which is every handler that writes a file — fails closed into
``handleError``.  So "it looked fine in my terminal" is not evidence.

Scope and the choice of cp1252
------------------------------
The rule is *cp1252-encodable*, not *ASCII*.  ASCII would be simpler but it
is the wrong boundary: ``—`` (U+2014) and ``§`` (U+00A7) both encode in
cp1252 and appear in over a thousand of this library's POST and diagnostic
strings, where they are correct and readable.  cp1252 is exactly the line at
which a record stops being written, so it is exactly the line this gate
draws.

Only *literal* text is checked.  Interpolated values are runtime data and
cannot be decided statically; keeping the library's own wording encodable is
the part that is decidable here, and it is the part that was wrong.

Both directions are pinned by ``tests/test_log_message_encodability_gate.py``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

#: Logging methods whose first positional argument is the record's format string.
LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)

#: The encoding a default Windows ``FileHandler`` uses.  See the module docstring
#: for why this, and not ``ascii``, is the correct boundary.
TARGET_ENCODING = "cp1252"

PACKAGE_DIR = "ama_cryptography"


def unencodable_characters(text: str, encoding: str = TARGET_ENCODING) -> list[str]:
    """Return the distinct characters in ``text`` that ``encoding`` cannot represent."""
    found: list[str] = []
    for char in text:
        if ord(char) < 128 or char in found:
            continue
        try:
            char.encode(encoding)
        except UnicodeEncodeError:
            found.append(char)
    return found


def _receiver_name(node: ast.expr) -> str:
    """Best-effort dotted name of a call's receiver (``self.logger`` -> ``self.logger``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_receiver_name(node.value)}.{node.attr}"
    return ""


def _emission_kind(call: ast.Call) -> str | None:
    """Return a label if ``call`` emits text to logging/warnings, else ``None``."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    # The inline idiom: ``logging.getLogger(__name__).critical(...)``.  The
    # receiver of ``.critical`` is a Call node, which the dotted-name walk
    # below renders as "" — so the first version of this gate was blind to
    # every such site while reporting PASS over the files that contained
    # them.  The shipped package uses this exact shape for some of its most
    # consequential records (the POST-failure criticals in ``__init__``),
    # which is the audience this gate exists for.  Any call spelled
    # ``<...>.getLogger(...).<level>(...)`` is a logger emission by
    # construction, whatever the module alias in front of it.
    if isinstance(func.value, ast.Call):
        callee = func.value.func
        if isinstance(callee, (ast.Name, ast.Attribute)):
            callee_name = _receiver_name(callee)
            if callee_name.rsplit(".", 1)[-1] == "getLogger" and func.attr in LOG_METHODS:
                return f"{callee_name}(...).{func.attr}"
        return None
    receiver = _receiver_name(func.value)
    if func.attr == "warn" and receiver.split(".")[-1] == "warnings":
        return "warnings.warn"
    if func.attr in LOG_METHODS and "log" in receiver.rsplit(".", 1)[-1].lower():
        return f"{receiver}.{func.attr}"
    return None


def audit(root: Path) -> tuple[list[str], int, int]:
    """Scan the shipped package.  Returns (failures, files_scanned, sites_scanned)."""
    failures: list[str] = []
    files_scanned = 0
    sites_scanned = 0

    for path in sorted((root / PACKAGE_DIR).rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError) as exc:  # pragma: no cover - defensive
            failures.append(f"{path}: could not be parsed ({exc})")
            continue
        files_scanned += 1

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kind = _emission_kind(node)
            if kind is None:
                continue
            sites_scanned += 1

            for argument in node.args:
                for part in ast.walk(argument):
                    if not isinstance(part, ast.Constant) or not isinstance(part.value, str):
                        continue
                    bad = unencodable_characters(part.value)
                    if not bad:
                        continue
                    rel = path.relative_to(root)
                    glyphs = ", ".join(f"{c!r} (U+{ord(c):04X})" for c in bad)
                    snippet = part.value.strip().replace("\n", "\\n")[:60]
                    failures.append(
                        f"{rel}:{part.lineno}: {kind}() text is not {TARGET_ENCODING}-encodable "
                        f"— {glyphs} in {snippet!r}. A cp1252 FileHandler drops this record "
                        f"entirely. Use an ASCII equivalent (-> for U+2192, [OK] for U+2713)."
                    )

    return failures, files_scanned, sites_scanned


def main() -> int:
    root = Path.cwd()
    if not (root / PACKAGE_DIR).is_dir():
        print(f"ERROR: {PACKAGE_DIR}/ not found — run from the repository root.")
        return 1

    failures, files_scanned, sites_scanned = audit(root)

    print(f"INVARIANT-43: log message encodability ({TARGET_ENCODING})")
    print(f"  files scanned: {files_scanned}; emission sites: {sites_scanned}")

    if failures:
        print(f"  FAIL — {len(failures)} finding(s):\n")
        for failure in failures:
            print(f"    ::error::{failure}\n")
        return 1

    print(f"  PASS — every logged literal survives a {TARGET_ENCODING} handler.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
