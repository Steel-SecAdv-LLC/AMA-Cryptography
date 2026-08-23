#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-6 gate: no bare ``memset(SECRET, 0, LEN)`` in the C sources.

Why this exists as a tool rather than a semgrep rule
----------------------------------------------------
``.semgrep.yml`` carries ``bare-memset-zero-secret-named-buffer`` at ERROR
severity, scoped to ``src/c/**``, and both ``tools/check_semgrep_severity.py``
and the CI step name it as one of the blocking rules.  It never ran.  Every
semgrep invocation in this repository scans ``ama_cryptography/`` only, so a
rule restricted to ``src/c/**`` matched nothing and could not fail the gate —
an ERROR-severity control that was, in practice, decorative.

Adding ``src/c/`` to the scan target does not fix it either: semgrep's C parser
does not know this codebase's ``AMA_API`` export macro and reports a syntax
error on every function declared with it (15 files on the current tree).  The
severity gate fails closed on scan errors — correctly — so widening the scope
turns a silent no-op into a permanently red gate.

So the check is implemented here instead, against the same rule, in a parser
that understands the codebase.  The semgrep rule is retained for the Python
tree's benefit and annotated to point here.

What is flagged
---------------
``memset(DST, 0, ...)`` — and the ``0x00`` / ``'\\0'`` spellings — where DST
names secret state.  The name test is deliberately the narrow one the semgrep
rule established: unambiguous prefixes (``secret_``, ``private_``, ``master_``,
``seed_``, ``key_``, ``sk_``, ``priv_``, ``kp_``), unambiguous suffixes
(``_key``, ``_secret``, ``_seed``, ``_state``, ``_priv``, ``_kp``, ``_sk``,
``_ks``), and a short list of known-secret spellings (``round_keys``,
``tag_mask``, ``ipad``/``opad``, ``h_table``, …).  Generic names (``block``,
``buf``, ``out``) are NOT flagged: they often hold AAD or ciphertext, and
mass-flagging them trains people to silence the gate, which is worse than not
having it.

``ama_secure_memzero()`` is the required replacement: its volatile writes plus
memory barrier defeat the dead-store elimination the as-if rule permits on a
plain ``memset`` whose result is never read (CWE-226).

Scope: ``src/c/**`` and ``tests/c/**`` (``*.c`` and ``*.h``), excluding any
``vendor/`` subtree (third-party code this project does not rewrite).  Tests
are deliberately in scope — a test that bare-memsets a secret exercises the
same anti-pattern.  That sentence predates the second root by some months: the
scan walked ``src/c`` only, so the stated scope was an intention rather than a
behaviour, and two matches in ``tests/c`` went unreported for as long as it
said so.  ``tests/test_c_secret_zeroization_gate.py`` now pins both roots.

Exit status: 0 when clean, 1 on any finding, 2 on a usage error.  A tree with
no C sources is an error, not a pass: that means the scan pointed nowhere.
"""

from __future__ import annotations

import re
import sys
from bisect import bisect_right
from pathlib import Path
from typing import NamedTuple, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
C_ROOT = REPO_ROOT / "src" / "c"
#: The C test tree.  The module docstring has always said tests are in scope —
#: "a test that bare-memsets a secret exercises the same anti-pattern" — but
#: the scan only ever walked C_ROOT, so the sentence described an intention
#: rather than the gate's behaviour.  Two real matches were sitting in
#: tests/c/ the whole time.  A second root, walked with the same exclusions
#: and the same fail-closed empty check, makes the stated scope the real one.
TEST_C_ROOT = REPO_ROOT / "tests" / "c"
EXCLUDED_DIRS = ("vendor",)

# The destination-name test, character-for-character the semgrep rule's regex.
_SECRET_NAME_RE = re.compile(
    r"^(secret_[A-Za-z0-9_]+|private_[A-Za-z0-9_]+|master_[A-Za-z0-9_]+"
    r"|seed_[A-Za-z0-9_]+|key_[A-Za-z0-9_]+|sk_[A-Za-z0-9_]+|priv_[A-Za-z0-9_]+"
    r"|kp_[A-Za-z0-9_]+|round_keys?|tag_mask|k_prime|scalar_reduced|wnaf|hram"
    r"|inner_hash|opad|ipad|h_table|ghash_key|poly_key|chaining_state|nu_state)$"
    r"|^[A-Za-z0-9_]+_(key|secret|seed|state|priv|kp|sk|ks)$"
)

# memset(DST, 0, ...) with the zero written as 0, 0x00, 0x0, or '\0'.
#
# DST may be a bare identifier (`secret_key`), a member access
# (`ctx->hmac_key`, `st.master_seed`), or either with an index or a leading `&`.
# The name that carries the convention is the LAST identifier in the chain —
# `ctx->hmac_key` is a key because of `hmac_key`, not because of `ctx` — so the
# whole destination expression is captured here and the trailing identifier is
# extracted in _destination_name().
#
# Written to backtrack linearly.  Two shapes in the first draft made it
# polynomial, and CodeQL flagged it (correctly) as a ReDoS:
#
#   `\(\s*&?\s*`  — two nullable quantifiers separated by an optional atom, so
#                   a run of N spaces that ultimately fails to match can be
#                   split between them N ways.
#   `(?:\s*…|\s*\[…\])*` — a starred group whose every alternative begins with
#                   `\s*`, which multiplies the same ambiguity.
#
# Measured on the original: 2,000 spaces 37 ms, 4,000 128 ms, 8,000 516 ms,
# 16,000 2,077 ms — a clean 4x per doubling.  Both are rewritten so each
# quantifier is followed by something that cannot itself match whitespace
# (`&` and the identifier start), which makes the match deterministic:
# 16,000 spaces now costs microseconds.  A .c file with a long run of spaces
# after `memset(` is a strange input, but this tool runs over whatever is in
# the tree, and a gate must not be the thing that hangs CI.
#
# ``\s`` matches newlines, so every quantifier below spans line breaks and the
# pattern matches the multi-line spelling of the call as readily as the
# one-line one — see scan_text(), which applies it to the whole (comment- and
# literal-blanked) file text rather than to each line in isolation.
#
# The optional address-of is written ``(?:(?P<amp>&)\s*)?`` rather than
# ``&?\s*``: every ``\s*`` here is followed by something that cannot itself be
# whitespace (``&`` or an identifier start), which is what keeps the match
# deterministic.  It is captured, not discarded, because the remediation hint
# has to reproduce a destination expression that compiles.
# A leading cast is admitted (``memset((void *)ctx->hmac_key, 0, n)`` is an
# ordinary C spelling, and requiring the destination to START with an
# identifier let it through), and the zero accepts an integer suffix
# (``0U``/``0u``/``0L``).  Both were silent bypasses of an ERROR-severity
# control whose semgrep counterpart is documented as unrunnable, so this regex
# is the only enforcement of INVARIANT-6.
#
# The cast group must also not reintroduce the ReDoS this file was hardened
# against.  Its first form did: ``[A-Za-z0-9_ \t]*`` matched whitespace and was
# followed by ``\**\s*\)``, so on a failing match a whitespace run could be
# split between two quantifiers in O(N) ways and the engine tried all of them
# — measured cleanly quadratic (32k whitespace chars after ``memset((void``
# took 7.7 s, 4x per doubling).  The form below keeps the character classes
# DISJOINT so no position is claimable by two quantifiers: identifier words are
# separated by ``[ \t]+`` that must be followed by an identifier character,
# each pointer ``*`` anchors its own optional whitespace run, and exactly one
# trailing ``[ \t]*`` reaches the closing paren.  Every input therefore has a
# single parse, which is what makes the scan linear rather than usually-fast.
#
# THREE further spellings were reaching past it, each verified as a silent
# bypass on the tree as it stood and each pinned in both directions by
# tests/test_c_secret_zeroization_gate.py:
#
#   * `memset(secret_key, 00, 32)` -- octal zero.  `0[uUlL]*` consumed one
#     `0` and then required a comma, so a second `0` failed the match.  `0+`
#     fixes it and cannot be ambiguous: it is followed by a suffix class that
#     excludes digits.
#   * `memset(secret_key, (0), 32)` -- a parenthesized zero, which C
#     programmers write constantly inside macro bodies.
#   * `memset(secret_key + 4, 0, 28)` -- pointer arithmetic on the
#     destination.  Zeroing the tail of a secret buffer is still zeroing
#     secret state, and _destination_name already resolves the leading
#     identifier, so admitting the offset costs nothing but the match.
#
# The ReDoS constraint from the cast group governs each addition, and this
# file has acquired that defect twice already:
#   * `0+` sits alone before `[uUlL]*` (digits and suffix letters are
#     disjoint), so a digit run has exactly one parse.
#   * The optional parens around the value are a fixed pair with one `\s*`
#     each, and the value alternation cannot match `(` or `)`, so no position
#     is claimable by two quantifiers.
#   * The offset tail is `(?:[ \t]*[-+][ \t]*<term>)*` where <term> starts
#     with a character class disjoint from `[ \t]` and from `[-+]`, so a
#     whitespace run again has one parse.
# tests/test_c_secret_zeroization_gate.py pins the growth ratio at ~2.0x per
# doubling (linear), which is what caught both earlier regressions.
_MEMSET_RE = re.compile(
    r"\bmemset\s*\(\s*"
    r"(?:\(\s*[A-Za-z_][A-Za-z0-9_]*(?:[ \t]+[A-Za-z_][A-Za-z0-9_]*)*"
    r"(?:[ \t]*\*)*[ \t]*\)\s*)?"
    r"(?:(?P<lparen>\()\s*)?"
    r"(?:(?P<amp>&)\s*)?"
    r"(?P<dst>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*"
    r"(?:[ \t]*[-+][ \t]*[A-Za-z0-9_]+"
    r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*)*)"
    r"(?:\s*\))?\s*,\s*"
    r"(?:\(\s*)?"
    r"(?P<val>0[xX]0+[uUlL]*|0+[uUlL]*|'\\0')"
    r"(?:\s*\))?"
    r"\s*,"
)

#: `#define NAME(p1, p2, ...) ... memset(pN, 0, ...) ...` -- a function-like
#: macro whose body bare-memsets one of its OWN parameters.  Matched
#: separately because the CALL SITE carries no `memset` token at all, so
#: _MEMSET_RE is structurally blind to it.  Verified: scan_text returned 0
#: findings for
#:
#:     #define CLR(x) memset((x),0,sizeof(x))
#:     CLR(secret_key);
#:
#: The definition is not a finding on its own -- a parameter has no name to
#: test -- and the call site is where the secret appears, so the call site is
#: what gets reported.  This tool is the SOLE enforcement of INVARIANT-6 (the
#: semgrep counterpart is documented in this module's docstring as unrunnable
#: and cannot be made to run), so a one-line wrapper macro was a complete
#: bypass of an ERROR-severity control.
#:
#: Deliberately NOT a preprocessor.  Nested expansion, token pasting and
#: conditional definitions are out of scope; the one shape in scope is a bare
#: memset hidden behind a name in a single expansion step.  A tool that covers
#: one shape and says which one beats a tool that claims to cover C.
_MACRO_DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\((?P<params>[^)\n]*)\)(?P<body>(?:\\\n|[^\n])*)",
    re.MULTILINE,
)

#: `#define NAME memset` -- an object-like alias.  The same blindness one
#: token earlier: the call site spells the alias, not `memset`.
_MEMSET_ALIAS_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]+memset[ \t]*$",
    re.MULTILINE,
)


def _destination_name(expression: str) -> str:
    """The identifier a naming convention attaches to, for a memset target.

    ``ctx->hmac_key`` -> ``hmac_key``; ``round_keys[i]`` -> ``round_keys``;
    ``secret_key`` -> itself.  Subscript contents are skipped so an index
    variable is never mistaken for the destination.

    A single left-to-right scan tracking bracket depth, not
    ``re.sub(r"\\[[^\\]]*\\]", …)`` + findall.  That form is linear on the
    balanced input _MEMSET_RE actually produces, but quadratic on unbalanced
    brackets (100k ``[`` took 5.5 s), and this helper is module-level: a test
    or a later caller can hand it anything.  Linearity here is free.

    Tracking depth also fixes two things deleting bracket pairs got wrong on
    input _MEMSET_RE cannot produce but a direct caller can: an unterminated
    subscript used to return the INDEX (``a[b`` -> ``b``, exactly the mistake
    this function exists to avoid), and deleting a pair spliced its neighbours
    into an identifier that was never in the source (``a[b]c`` -> ``ac``).
    They now yield ``a`` and ``c``.
    """
    # An additive offset is not part of the name.  `_MEMSET_RE` now admits
    # `memset(secret_key + 4, 0, 28)` — zeroing the tail of a secret buffer is
    # still zeroing secret state — and the left-to-right "last identifier at
    # depth 0" rule below resolved that expression to `4`, the offset, which
    # names nothing and matches no secret pattern.  Two independent halves of
    # the same bypass: the regex could not see the call, and the resolver
    # would have named the wrong thing if it had.  Truncating at the first
    # top-level `+`/`-` leaves the base object, which is what the destination
    # is; the member-access rule (`ctx->hmac_key` -> `hmac_key`) then applies
    # to that base unchanged.
    depth = 0
    for index, ch in enumerate(expression):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch in "+-" and depth == 0:
            # `->` is a member access, not a subtraction.  Without this the
            # truncation resolved `ctx->hmac_key + 8` to `ctx` — a base name
            # the secret-name test does not match, which is the same class of
            # miss the truncation was added to fix.
            if ch == "-" and expression[index + 1 : index + 2] == ">":
                continue
            expression = expression[:index]
            break

    depth = 0
    last = ""
    current: list[str] = []

    def flush() -> None:
        nonlocal last, current
        if current and depth == 0:
            last = "".join(current)
        current = []

    for ch in expression:
        if ch == "[":
            flush()
            depth += 1
        elif ch == "]":
            current = []
            if depth > 0:
                depth -= 1
        elif ch.isalnum() or ch == "_":
            if depth == 0:
                current.append(ch)
        else:
            flush()
    flush()
    return last


class Finding(NamedTuple):
    path: Path
    line_no: int
    dst: str
    text: str
    expression: str = ""

    @property
    def target(self) -> str:
        """The destination as written in the source, for the remediation hint.

        ``dst`` is only the trailing identifier — the one the naming convention
        attaches to (``hmac_key`` out of ``ctx->hmac_key``, ``signing_key`` out
        of ``keys[i].signing_key``).  That is the right thing to *test* and the
        wrong thing to *suggest*: ``ama_secure_memzero(hmac_key, LEN)`` does not
        compile at the site being reported.  The hint uses the full destination
        expression the regex captured, falling back to ``dst`` only for a
        Finding constructed without one.
        """
        return self.expression or self.dst

    def render(self) -> str:
        # Paths outside the repository (an explicit file argument, a test's
        # temporary tree) have no repo-relative form; show them as given rather
        # than raising out of the reporting path.
        try:
            rel: Path | str = self.path.relative_to(REPO_ROOT)
        except ValueError:
            rel = self.path
        return (
            f"{rel}:{self.line_no}: bare memset() zeroing secret-named "
            f"buffer {self.dst!r}\n"
            f"    {self.text.strip()}\n"
            f"    Use ama_secure_memzero({self.target}, LEN) — a plain memset may be "
            f"elided by the optimizer (INVARIANT-6, CWE-226)."
        )


def scan_roots() -> list[Path]:
    """The directory trees this gate walks, read at CALL time.

    Read at call time rather than bound as defaults so a test can rebind
    :data:`C_ROOT` or :data:`TEST_C_ROOT` and have :func:`main`'s fail-closed
    empty-scan guard actually see the rebinding.
    """
    return [C_ROOT, TEST_C_ROOT]


def c_sources(root: Path | None = None) -> list[Path]:
    """Every first-party C source and header, vendored code excluded.

    With no argument this walks BOTH scan roots — the library sources and the
    C test tree — because a test that bare-memsets a secret exercises exactly
    the anti-pattern INVARIANT-6 exists to prevent, and because a gate whose
    documented scope is wider than its actual scope is a gate that reports
    "clean" over code it never opened.

    ``root`` selects a single tree, which is what the scope tests use.
    """
    roots = scan_roots() if root is None else [root]
    out: list[Path] = []
    for scan_root in roots:
        if not scan_root.is_dir():
            continue
        for path in sorted(scan_root.rglob("*")):
            if path.suffix not in (".c", ".h") or not path.is_file():
                continue
            if any(part in EXCLUDED_DIRS for part in path.relative_to(scan_root).parts):
                continue
            out.append(path)
    return sorted(set(out))


def blank_comments_and_literals(text: str) -> str:
    """``text`` with comment and string/char-literal bodies replaced by spaces.

    Length and line structure are preserved exactly — every replaced character
    becomes a space and every newline is kept — so an offset into the result
    indexes the same character of the original.  That is what lets scan_text()
    match against the blanked text and still report the source line.

    Comments are blanked because this repo documents the anti-pattern in prose,
    including inside this rule's own sources, and a gate that reports its own
    documentation is a gate people turn off.  String and character literals are
    blanked for two reasons in opposite directions: a literal containing
    ``memset(secret_key, 0,`` is not code and must not be reported, and — the
    sharper one — a literal containing ``//`` or ``/*`` used to swallow the rest
    of a real line.  ``puts("a//b"); memset(secret_key, 0, 32);`` was a silent
    MISS under the previous per-line ``re.sub(r"//.*$", ...)``: an ERROR-severity
    gate failing open on a legal C line.

    A single left-to-right pass, so this is linear in the length of the input.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            # Line comment. A backslash-newline splices the next line into it
            # (C11 5.1.1.2 phase 2 runs before comments are recognised), so the
            # comment does not end there.
            out.append("  ")
            i += 2
            while i < n and text[i] != "\n":
                if text[i] == "\\" and text.startswith("\n", i + 1):
                    out.append(" \n")
                    i += 2
                    continue
                if text[i] == "\\" and text.startswith("\r\n", i + 1):
                    out.append(" \r\n")
                    i += 3
                    continue
                out.append(" ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and text.startswith("/", i + 1)):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue

        if ch in ('"', "'"):
            # A character literal is passed through VERBATIM, a string literal
            # is blanked.  The asymmetry is deliberate: `'\0'` is one of the
            # three spellings of the zero this rule looks for, so blanking it
            # would make `memset(secret_key, '\0', 32)` invisible — and a char
            # literal is one character wide, so it cannot hide a call.  A string
            # literal can, so its body goes.
            quote = ch
            keep = quote == "'"
            out.append(quote if keep else " ")
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    # An escaped character never terminates the literal, and an
                    # escaped newline continues it.
                    pair = text[i : i + 2]
                    out.append(pair if keep else ("  " if pair[1] != "\n" else " \n"))
                    i += 2
                    continue
                if text[i] == "\n":
                    # Unterminated literal: C forbids it, but this tool reads
                    # whatever is in the tree.  End it at the newline rather
                    # than blanking the rest of the file.
                    break
                out.append(text[i] if keep else " ")
                i += 1
            if i < n and text[i] == quote:
                out.append(quote if keep else " ")
                i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _split_top_level(argument_text: str) -> list[str]:
    """Split a C argument list on top-level commas.

    Depth-tracking over `()`, `[]` and `{}` so `CLR(a[i, j])` and
    `CLR(f(x, y))` stay single arguments.  A plain `.split(",")` would
    mis-map every argument after a nested comma onto the wrong parameter,
    which on this gate means testing the wrong identifier for secrecy.
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in argument_text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return [part.strip() for part in parts]


def _match_call_arguments(text: str, open_paren: int) -> tuple[str, int] | None:
    """The text between `text[open_paren] == '('` and its matching `)`.

    Returns `(arguments, index_after_close)`, or None when the parenthesis is
    never closed.  Depth-tracked rather than regex-matched: a `[^)]*` form
    would stop at the first `)` inside a nested call and hand the caller a
    truncated argument list.
    """
    depth = 0
    i = open_paren
    n = len(text)
    while i < n:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i], i + 1
        i += 1
    return None


class _ZeroingMacro(NamedTuple):
    """A function-like macro that bare-memsets one of its own parameters."""

    name: str
    #: Index of the parameter the memset writes to.
    parameter_index: int


def _zeroing_macros(blanked: str) -> list[_ZeroingMacro]:
    """Function-like macros whose body bare-memsets a parameter of their own.

    See _MACRO_DEFINE_RE for why this exists and what it deliberately does not
    attempt.  A macro whose memset targets a fixed symbol rather than a
    parameter needs nothing here: the body carries both the `memset` token and
    the symbol's name, so _MEMSET_RE already reports it at the definition.
    """
    macros: list[_ZeroingMacro] = []
    for define in _MACRO_DEFINE_RE.finditer(blanked):
        parameters = [token.strip() for token in define.group("params").split(",") if token.strip()]
        if not parameters:
            continue
        body = define.group("body")
        for call in _MEMSET_RE.finditer(body):
            target = _destination_name(call.group("dst"))
            if target in parameters:
                macros.append(_ZeroingMacro(define.group("name"), parameters.index(target)))
                break
    return macros


def _memset_aliases(blanked: str) -> list[_ZeroingMacro]:
    """`#define NAME memset` aliases, mapped to memset's own dst parameter."""
    return [_ZeroingMacro(define.group("name"), 0) for define in _MEMSET_ALIAS_RE.finditer(blanked)]


def _macro_call_findings(
    blanked: str,
    text: str,
    path: Path,
    lines: list[str],
    line_starts: list[int],
) -> list[Finding]:
    """Call sites of zeroing macros whose mapped argument names a secret.

    An alias (`#define CLR memset`) is only a finding when the call also
    passes a zero value, because `CLR(buf, 0xff, n)` is not a zeroing call;
    the alias's mapped index is memset's dst, so the zero test is re-applied
    to the second argument.  A wrapper macro (`#define CLR(x) memset((x),0,…)`)
    has already been proven to zero, so its call sites need no such test.
    """
    findings: list[Finding] = []
    aliases = {macro.name for macro in _memset_aliases(blanked)}
    macros = _zeroing_macros(blanked) + _memset_aliases(blanked)
    if not macros:
        return findings

    by_name = {macro.name: macro for macro in macros}
    name_pattern = re.compile(
        r"\b(" + "|".join(re.escape(macro.name) for macro in macros) + r")\s*\("
    )
    for call in name_pattern.finditer(blanked):
        macro = by_name[call.group(1)]
        # The macro's own #define line is not a call site.
        line_no = bisect_right(line_starts, call.start())
        raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        if raw.lstrip().startswith("#"):
            continue
        matched = _match_call_arguments(blanked, call.end() - 1)
        if matched is None:
            continue
        arguments = _split_top_level(matched[0])
        if macro.parameter_index >= len(arguments):
            continue
        if macro.name in aliases:
            if len(arguments) < 2 or not re.fullmatch(
                r"\(?\s*(?:0[xX]0+[uUlL]*|0+[uUlL]*|'\\0')\s*\)?", arguments[1]
            ):
                continue
        expression = arguments[macro.parameter_index]
        dst = _destination_name(expression)
        if not dst or not _SECRET_NAME_RE.match(dst):
            continue
        findings.append(Finding(path, line_no, dst, raw, expression))
    return findings


def scan_text(text: str, path: Path) -> list[Finding]:
    """Findings in one file's text.

    The scan runs over the WHOLE file at once, not line by line.  ``memset``
    calls are routinely written across several lines:

        memset(secret_key,
               0,
               sizeof(secret_key));

    and a per-line regex cannot see them — a shape common enough in formatted C
    that missing it made this ERROR-severity gate under-enforce exactly where a
    long destination expression (the ones most likely to be secret state) forces
    the wrap.  ``\\s`` matches newlines, so _MEMSET_RE spans the wrap unchanged;
    what had to change is the unit of text it is applied to.

    Comment and literal bodies are blanked first, in place, so match offsets
    still index the original text and the reported line is the source line.
    """
    blanked = blank_comments_and_literals(text)
    lines = text.splitlines()
    # Offset of the first character of each line, for offset -> line lookup.
    line_starts: list[int] = [0]
    for match in re.finditer(r"\n", text):
        line_starts.append(match.end())

    findings: list[Finding] = []
    for match in _MEMSET_RE.finditer(blanked):
        dst = _destination_name(match.group("dst"))
        if not dst or not _SECRET_NAME_RE.match(dst):
            continue
        line_no = bisect_right(line_starts, match.start())
        raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        expression = ("&" if match.group("amp") else "") + match.group("dst")
        findings.append(Finding(path, line_no, dst, raw, expression))

    # Call sites of macros that wrap a bare memset — invisible to the regex
    # above because they carry no `memset` token.  See _MACRO_DEFINE_RE.
    findings.extend(_macro_call_findings(blanked, text, path, lines, line_starts))
    findings.sort(key=lambda finding: (finding.line_no, finding.dst))
    return findings


def audit(paths: Sequence[Path] | None = None) -> list[Finding]:
    """Scan the C tree (or an explicit file list) and return every finding."""
    targets = list(paths) if paths is not None else c_sources()
    findings: list[Finding] = []
    for path in targets:
        findings.extend(scan_text(path.read_text(encoding="utf-8", errors="replace"), path))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        targets = [Path(a).resolve() for a in args]
        missing = [t for t in targets if not t.is_file()]
        if missing:
            for path in missing:
                print(f"ERROR: not a file: {path}", file=sys.stderr)
            return 2
    else:
        missing_roots = [r for r in scan_roots() if not r.is_dir()]
        if missing_roots:
            for root in missing_roots:
                print(f"ERROR: C source root not found: {root}", file=sys.stderr)
            return 2
        # Fail closed PER ROOT, not on the union.  Checking only the total
        # would let a walk that silently stopped covering one whole tree pass
        # on the strength of the other — which is the failure this gate is
        # being widened to fix, one level up.
        for root in scan_roots():
            if not c_sources(root):
                print(f"ERROR: no C sources found under {root}", file=sys.stderr)
                return 2
        targets = c_sources()
        if not targets:
            # Fail closed: an empty scan is a broken scan, not a clean tree.
            print("ERROR: no C sources found under any scan root", file=sys.stderr)
            return 2

    findings = audit(targets)
    if findings:
        print(f"FAIL  bare memset() on secret-named buffers ({len(findings)} finding(s)):\n")
        for finding in findings:
            print(finding.render())
            print()
        print(
            "Replace each with ama_secure_memzero() from src/c/ama_consttime.c.\n"
            "INVARIANT-6: secret material must be scrubbed with a write the "
            "compiler is not free to remove."
        )
        return 1

    print(f"OK    no bare memset() on secret-named buffers ({len(targets)} C file(s) checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
