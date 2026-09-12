# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No branch-free predicate may write and read the same object unsequenced.

Removing a secret-dependent branch usually means turning

    if (!load(&v, src) || is_zero(&v))

into the branch-free

    bad = (1 ^ load(&v, src)) | is_zero(&v);

That transformation silently drops a sequence point.  ``||`` sequences its
left operand before its right; ``|`` and ``&`` do not, and the two function
calls are only *indeterminately sequenced* with respect to each other
(C11 6.5.2.2p10).  A conforming compiler may run ``is_zero(&v)`` before
``load()`` has written ``v``.

Measured, not theorised: gcc and clang evaluate left to right, MSVC right to
left.  On ``windows-latest`` ``ama_secp256k1_ecdsa_sign`` therefore read ``d``
before the private key was loaded into it, and

* rejected valid private keys with ``AMA_ERROR_INVALID_PARAM``; and
* **signed successfully under an all-zero private key**, because the zero
  test had inspected either indeterminate stack bytes or the zeroed slot the
  function's own exit scrub left from an earlier call.

Nothing on a Linux or macOS runner can reproduce that, so the property is
pinned at the source level instead: a call that *writes* an object through a
non-const pointer may not share an operand of ``|`` or ``&`` with another
call that names the same object.  Hoisting the write into its own statement
restores the sequence point and keeps the predicate branch-free.
"""

from __future__ import annotations

import itertools
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
C_ROOT = REPO_ROOT / "src" / "c"

_CALLEE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
#: ``|`` and ``&`` as *binary* operators: not ``||``, ``&&``, ``|=`` or ``&=``.
_BINARY = {
    "|": re.compile(r"(?<![|&])\|(?![|=])"),
    "&": re.compile(r"(?<![|&])&(?![&=])"),
}
_KEYWORDS = frozenset({"if", "for", "while", "switch", "return", "sizeof", "defined", "do", "else"})


def _strip_comments(text: str) -> str:
    """Blank out comments, preserving line numbers and column positions."""
    out: list[str] = []
    i, n, in_block = 0, len(text), False
    while i < n:
        if in_block:
            if text.startswith("*/", i):
                in_block, i = False, i + 2
                out.append("  ")
            else:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
        elif text.startswith("/*", i):
            in_block, i = True, i + 2
            out.append("  ")
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _split_params(params: str) -> list[str]:
    """Split a parameter list on top-level commas."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in params:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _writes_through_pointer(param: str) -> bool:
    """True when ``param`` is a pointer (or array) to non-const."""
    if "*" not in param and "[" not in param:
        return False
    return not re.search(r"\bconst\b\s*[A-Za-z_0-9\s]*[*\[]", param) and "const" not in param


def _declared_parameters(sources: dict[pathlib.Path, str]) -> dict[str, list[str]]:
    """Map every function defined or declared under ``src/c`` to its parameters.

    Callees this cannot resolve — function-like macros, compiler builtins,
    intrinsics — are treated as non-writers, which is the safe direction for a
    gate whose finding is "this call writes what the other one reads".
    """
    table: dict[str, list[str]] = {}
    for text in sources.values():
        for match in _CALLEE.finditer(text):
            name = match.group(1)
            if name in _KEYWORDS:
                continue
            depth, i, n = 0, match.end() - 1, len(text)
            while i < n:
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif text[i] == ";":
                    break
                i += 1
            if i >= n or text[i] != ")":
                continue
            tail = text[i + 1 :].lstrip()
            if tail[:1] not in ("{", ";"):
                continue
            params = _split_params(text[match.end() : i])
            if params and params != ["void"]:
                table.setdefault(name, params)
    return table


def _arguments(call_text: str, open_paren: int) -> list[str]:
    depth, i, n = 0, open_paren, len(call_text)
    while i < n:
        if call_text[i] == "(":
            depth += 1
        elif call_text[i] == ")":
            depth -= 1
            if depth == 0:
                return _split_params(call_text[open_paren + 1 : i])
        i += 1
    return []


def _written_names(operand: str, params: dict[str, list[str]]) -> set[str]:
    """Objects this operand passes to a call that can write them."""
    written: set[str] = set()
    for match in _CALLEE.finditer(operand):
        name = match.group(1)
        signature = params.get(name)
        if signature is None or name in _KEYWORDS:
            continue
        for index, argument in enumerate(_arguments(operand, match.end() - 1)):
            if index >= len(signature):
                break
            if _writes_through_pointer(signature[index]):
                written.update(_IDENT.findall(argument))
    return written


def _read_names(operand: str) -> set[str]:
    callees = {m.group(1) for m in _CALLEE.finditer(operand)}
    return {name for name in _IDENT.findall(operand) if name not in callees}


def _sources() -> dict[pathlib.Path, str]:
    return {
        path: _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for path in sorted(C_ROOT.rglob("*.[ch]"))
    }


def find_unsequenced(sources: dict[pathlib.Path, str]) -> list[str]:
    """Every ``|``/``&`` expression whose operands write and read one object."""
    params = _declared_parameters(sources)
    findings: list[str] = []
    for path, text in sources.items():
        for number, line in enumerate(text.splitlines(), 1):
            if "=" not in line:
                continue
            rhs = line.split("=", 1)[1]
            for pattern in _BINARY.values():
                operands = pattern.split(rhs)
                for left, right in itertools.pairwise(operands):
                    if not (_CALLEE.search(left) and _CALLEE.search(right)):
                        continue
                    shared = (_written_names(left, params) & _read_names(right)) | (
                        _written_names(right, params) & _read_names(left)
                    )
                    if shared:
                        try:
                            where = path.relative_to(REPO_ROOT)
                        except ValueError:  # pragma: no cover - scratch trees
                            where = path
                        findings.append(f"{where}:{number}: {sorted(shared)}: {line.strip()}")
    return findings


class TestNoPredicateWritesAndReadsOneObjectUnsequenced:
    def test_the_shipped_c_sources_are_clean(self) -> None:
        findings = find_unsequenced(_sources())
        assert not findings, (
            "a call that writes an object shares a `|`/`&` expression with a call "
            "that reads it; the two are only indeterminately sequenced, so MSVC "
            "reads before the write. Hoist the write into its own statement:\n  "
            + "\n  ".join(findings)
        )

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            pytest.param(
                "static int load(int *r, const int *b);\n"
                "static int is_zero(const int *a);\n"
                "void f(void) { int bad = (1 ^ load(&d, src)) | is_zero(&d); }\n",
                True,
                id="the-defect-as-it-shipped",
            ),
            pytest.param(
                "static int load(int *r, const int *b);\n"
                "static int is_zero(const int *a);\n"
                "void f(void) { const int ok = load(&d, src);\n"
                "               int bad = (1 ^ ok) | is_zero(&d); }\n",
                False,
                id="the-fix-hoists-the-write",
            ),
            pytest.param(
                "static int lt(const int *a, const int *b);\n"
                "static int is_zero(const int *a);\n"
                "void f(void) { int ok = lt(k, n) & (1 ^ is_zero(k)); }\n",
                False,
                id="two-readers-are-fine",
            ),
            pytest.param(
                "static unsigned load32(const unsigned char *p);\n"
                "void f(void) { unsigned t = load32(m) | (load32(m + 4) << 16); }\n",
                False,
                id="pure-loads-of-one-buffer-are-fine",
            ),
        ],
    )
    def test_the_detector_separates_the_defect_from_its_neighbours(
        self, tmp_path: pathlib.Path, source: str, expected: bool
    ) -> None:
        """Non-vacuity, both ways.

        A gate that flagged nothing would pass the first test forever, and one
        that flagged every shared name would have to be suppressed across the
        field arithmetic.  These four cases pin both edges.
        """
        path = tmp_path / "probe.c"
        path.write_text(source)
        assert bool(find_unsequenced({path: _strip_comments(source)})) is expected
