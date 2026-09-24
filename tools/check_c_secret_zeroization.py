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

The bare secret names themselves — ``sk``, ``key``/``keys``, ``seed``,
``secret``, ``priv``/``private``/``privkey`` — were not in that list, so
``memset(sk, 0, n)`` and ``memset(ctx->key, 0, n)`` passed anywhere a
``PUBLIC-DATA`` comment sat beside them, and everywhere in ``tests/c`` (where
the annotation rule does not apply).  They are now known-secret spellings: a
destination so named is a finding even when annotated ``PUBLIC-DATA``, because
the annotation asserts a buffer is not secret and the name asserts it is.

``memset`` is not the only plain zeroing call.  ``bzero``, the compiler
builtins ``__builtin_memset`` / ``__builtin_bzero``, and Windows'
``ZeroMemory`` / ``RtlZeroMemory`` (macros over ``memset``) are exactly as
elidable, and none contains the token ``memset`` at a word boundary, so each
was a complete bypass.  They are held to the same two rules.  The
NON-elidable interfaces — ``explicit_bzero``, ``memset_s``,
``memset_explicit``, ``SecureZeroMemory`` — are not the anti-pattern this gate
exists for and are not matched (``\bbzero`` does not match inside
``explicit_bzero``, nor ``\bZeroMemory`` inside ``SecureZeroMemory``);
``ama_secure_memzero`` remains the project's portable spelling.

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
from dataclasses import dataclass, field
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
    r"|sk|keys?|seed|secret|priv|private|privkey"
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
#
# A PARENTHESIZED offset term was still a miss, and the one it hid was the
# tree's only SCRUB-BARRIER site: `memset(frame + (sizeof frame - bytes), 0,
# bytes)` in ama_consttime.c did not match at all, so the gate never looked
# at its annotation or its barrier -- deleting both left the gate green --
# and `memset(secret_key + (n - k), 0, k)` passed the secret-name rule the
# same way.  <term> now also admits `( ... )` with one level of nested
# parentheses.  It opens with `(`, which the identifier alternative cannot,
# and inside it `[^()]` and `\(` are disjoint, so it keeps one parse per
# input.  Widening it added exactly that one match on the tree.
# tests/test_c_secret_zeroization_gate.py pins the growth ratio at ~2.0x per
# doubling (linear), which is what caught both earlier regressions.
#: The destination-argument grammar, shared by the memset and bzero forms so a
#: fix to one (and its ReDoS discipline, above) cannot miss the other.  Ends
#: at the comma that closes the destination argument.
_DST_ARGUMENT = (
    r"(?:\(\s*[A-Za-z_][A-Za-z0-9_]*(?:[ \t]+[A-Za-z_][A-Za-z0-9_]*)*"
    r"(?:[ \t]*\*)*[ \t]*\)\s*)?"
    r"(?:(?P<lparen>\()\s*)?"
    r"(?:(?P<amp>&)\s*)?"
    r"(?P<dst>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*"
    r"(?:[ \t]*[-+][ \t]*(?:[A-Za-z0-9_]+"
    r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*"
    r"|\((?:[^()]|\([^()]*\))*\)))*)"
    r"(?:\s*\))?\s*,"
)

#: ``__builtin_memset`` is the same elidable store; ``\bmemset`` cannot match
#: it (``_`` is a word character), so it is spelled out.
_MEMSET_RE = re.compile(
    r"\b(?P<fn>(?:__builtin_)?memset)\s*\(\s*" + _DST_ARGUMENT + r"\s*"
    r"(?:\(\s*)?"
    r"(?P<val>0[xX]0+[uUlL]*|0+[uUlL]*|'\\0')"
    r"(?:\s*\))?"
    r"\s*,"
)

#: The zero-by-construction calls: ``bzero(dst, len)`` and its builtin and
#: Windows spellings.  No value argument — every call zeroes.  The word
#: boundary keeps the non-elidable ``explicit_bzero`` and
#: ``SecureZeroMemory`` / ``RtlSecureZeroMemory`` out.
_BZERO_RE = re.compile(
    r"\b(?P<fn>__builtin_bzero|bzero|RtlZeroMemory|ZeroMemory)\s*\(\s*" + _DST_ARGUMENT
)

#: Every plain-zeroing call form, for the scans that treat them alike.
_ZEROING_CALL_RES = (_MEMSET_RE, _BZERO_RE)

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

#: `#undef NAME`.  Without it the macro table had no notion of preprocessor
#: scope: a name #undef'd (or redefined to something that does NOT zero) kept
#: its zeroing definition in force for the whole file, so this ERROR-severity
#: gate reported findings on already-remediated code.
_MACRO_UNDEF_RE = re.compile(
    r"^[ \t]*#[ \t]*undef[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)

#: `#define NAME memset` -- an object-like alias.  The same blindness one
#: token earlier: the call site spells the alias, not `memset`.
_MEMSET_ALIAS_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]+"
    r"(?:__builtin_)?memset[ \t]*$",
    re.MULTILINE,
)

#: `#define NAME bzero` -- the same alias for a call that always zeroes, so
#: its call sites need no value test.
_BZERO_ALIAS_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]+"
    r"(?:__builtin_bzero|bzero|RtlZeroMemory|ZeroMemory)[ \t]*$",
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
    #: ``"secret-named"`` — the destination matches the secret naming
    #: convention (the original rule).  ``"unannotated"`` — a shipped-tree
    #: memset-zero whose destination the convention does not recognise and
    #: that carries no ``PUBLIC-DATA`` annotation (see
    #: :func:`_is_annotated`).
    kind: str = "secret-named"
    #: The zeroing call as spelled (``memset``, ``bzero``, ``__builtin_memset``…).
    call: str = "memset"

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
        if self.kind == "unannotated":
            return (
                f"{rel}:{self.line_no}: bare {self.call}() zeroing {self.dst!r} with no "
                f"PUBLIC-DATA annotation\n"
                f"    {self.text.strip()}\n"
                f"    If {self.target} never holds secret material, say so on the call: "
                f"`// PUBLIC-DATA: {self.dst} — <why>`.  Otherwise use "
                f"ama_secure_memzero({self.target}, LEN) — a plain {self.call} may be "
                f"elided by the optimizer (INVARIANT-6, CWE-226)."
            )
        return (
            f"{rel}:{self.line_no}: bare {self.call}() zeroing secret-named "
            f"buffer {self.dst!r}\n"
            f"    {self.text.strip()}\n"
            f"    Use ama_secure_memzero({self.target}, LEN) — a plain {self.call} may be "
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


def blank_comments_and_literals(text: str, *, keep_strings: bool = False) -> str:
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

    ``keep_strings=True`` blanks comments only and passes string literals
    through, still offset-for-offset.  The SCRUB-BARRIER check needs it: part
    of an inline-asm barrier's meaning is in a string literal (the
    ``"memory"`` clobber), and reading it from the raw text instead let a
    comment that merely quoted a barrier count as one.

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
            keep = quote == "'" or keep_strings
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


def _paren_index(text: str) -> dict[int, int]:
    """Offset of every `(` mapped to the offset of its matching `)`.

    ONE left-to-right pass with a stack, so the whole file costs O(n) and each
    lookup is O(1).  The obvious alternative — scanning forward from each `(`
    until the depth returns to zero — is what this replaces: with N unclosed
    occurrences of a macro name it costs O(N * filesize), and this module's
    linearity is an explicit, tested discipline (see `_destination_name`, which
    was rewritten for the same reason).  A `(` that is never closed simply has
    no entry, which is exactly the None the caller needs.
    """
    index: dict[int, int] = {}
    stack: list[int] = []
    for position, character in enumerate(text):
        if character == "(":
            stack.append(position)
        elif character == ")" and stack:
            index[stack.pop()] = position
    return index


def _match_call_arguments(
    text: str, open_paren: int, index: dict[int, int] | None = None
) -> tuple[str, int] | None:
    """The text between `text[open_paren] == '('` and its matching `)`.

    Returns `(arguments, index_after_close)`, or None when the parenthesis is
    never closed.  Depth-tracked rather than regex-matched: a `[^)]*` form
    would stop at the first `)` inside a nested call and hand the caller a
    truncated argument list.

    `index` is an optional precomputed `_paren_index(text)`; callers in a loop
    pass it so the whole scan stays linear.  Without it this falls back to the
    forward walk, which is correct but O(filesize) per unclosed paren — kept
    only so the helper remains usable standalone.
    """
    if index is not None:
        close = index.get(open_paren)
        if close is None:
            return None
        return text[open_paren + 1 : close], close + 1
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
    """A definition (or un-definition) of a name that may zero its arguments.

    `parameter_indices` holds EVERY parameter the body bare-memsets, not just
    the first.  A macro that wipes two of its own parameters used to be
    recorded as wiping one: the collector `break`ed on the first match and the
    call-site lookup was a `{name: macro}` dict, so every other argument at
    every call site went untested — a complete bypass of an ERROR-severity
    gate for exactly the macros that do the most zeroing.

    `offset` and `undef` give the table preprocessor scope.  Without them a
    `#undef NAME`, or a redefinition that does NOT zero, left the original
    definition in force for the rest of the file and the gate reported
    findings on already-remediated code.  A call site resolves against the
    LAST event for its name that precedes it.
    """

    name: str
    #: Indices of every parameter the body memsets.  Empty for `undef`, and
    #: for a redefinition that zeroes nothing.
    parameter_indices: tuple[int, ...]
    #: Byte offset of the `#define` / `#undef` in the blanked text.
    offset: int
    #: True for `#undef NAME`.
    undef: bool = False
    #: True for an object-like `#define NAME memset` alias, whose call sites
    #: additionally have to pass a zero value.
    alias: bool = False


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
        indices: list[int] = []
        for pattern in _ZEROING_CALL_RES:
            for call in pattern.finditer(body):
                target = _destination_name(call.group("dst"))
                if target in parameters:
                    position = parameters.index(target)
                    if position not in indices:
                        indices.append(position)
        # Recorded even when `indices` is empty: a redefinition that zeroes
        # nothing must SUPERSEDE an earlier zeroing one, not be invisible to
        # the call-site lookup.
        macros.append(
            _ZeroingMacro(
                define.group("name"),
                tuple(sorted(indices)),
                define.start(),
            )
        )
    return macros


def _memset_aliases(blanked: str) -> list[_ZeroingMacro]:
    """`#define NAME memset` / `#define NAME bzero` aliases, mapped to the dst.

    A memset alias is marked ``alias`` so its call sites must also pass a zero
    value; a bzero alias zeroes unconditionally and is recorded as a plain
    zeroing macro.
    """
    return [
        _ZeroingMacro(define.group("name"), (0,), define.start(), alias=True)
        for define in _MEMSET_ALIAS_RE.finditer(blanked)
    ] + [
        _ZeroingMacro(define.group("name"), (0,), define.start())
        for define in _BZERO_ALIAS_RE.finditer(blanked)
    ]


def _macro_undefs(blanked: str) -> list[_ZeroingMacro]:
    """`#undef NAME` events, which cancel whatever definition preceded them."""
    return [
        _ZeroingMacro(undef.group("name"), (), undef.start(), undef=True)
        for undef in _MACRO_UNDEF_RE.finditer(blanked)
    ]


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
    events = sorted(
        _zeroing_macros(blanked) + _memset_aliases(blanked) + _macro_undefs(blanked),
        key=lambda macro: macro.offset,
    )
    zeroing_names = {macro.name for macro in events if macro.parameter_indices}
    if not zeroing_names:
        return findings

    # name -> its events, in source order.  A call site resolves against the
    # LAST event for its name that precedes it, so an #undef or a
    # non-zeroing redefinition cancels the earlier definition instead of
    # leaving it in force for the whole file.
    timeline: dict[str, list[_ZeroingMacro]] = {}
    for event in events:
        timeline.setdefault(event.name, []).append(event)

    parens = _paren_index(blanked)
    name_pattern = re.compile(
        r"\b(" + "|".join(re.escape(name) for name in sorted(zeroing_names)) + r")\s*\("
    )
    for call in name_pattern.finditer(blanked):
        history = timeline.get(call.group(1), [])
        macro: _ZeroingMacro | None = None
        for event in history:
            if event.offset >= call.start():
                break
            macro = event
        if macro is None or macro.undef or not macro.parameter_indices:
            continue
        # The macro's own #define line is not a call site.
        line_no = bisect_right(line_starts, call.start())
        raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        if raw.lstrip().startswith("#"):
            continue
        matched = _match_call_arguments(blanked, call.end() - 1, parens)
        if matched is None:
            continue
        arguments = _split_top_level(matched[0])
        if macro.alias:
            if len(arguments) < 2 or not re.fullmatch(
                r"\(?\s*(?:0[xX]0+[uUlL]*|0+[uUlL]*|'\\0')\s*\)?", arguments[1]
            ):
                continue
        # EVERY mapped parameter, not only the first.
        for parameter_index in macro.parameter_indices:
            if parameter_index >= len(arguments):
                continue
            expression = arguments[parameter_index]
            dst = _destination_name(expression)
            if not dst or not _SECRET_NAME_RE.match(dst):
                continue
            findings.append(Finding(path, line_no, dst, raw, expression))
    return findings


#: The annotation that marks a bare memset-zero as deliberately NOT a secret
#: scrub.  The shipped C tree already carried it on most of its memsets
#: (``memset(&tmp, 0, sizeof(tmp));  // PUBLIC-DATA: tmp — ...``); what it
#: lacked was a rule that REQUIRED it.
_PUBLIC_DATA_TOKEN = "PUBLIC-DATA"  # noqa: S105 -- a C-comment annotation token the gate greps for, not a credential (ZERO-011)

#: The second sanctioned form for a shipped zeroing memset: the destination
#: DOES hold secret material, and the write is made non-elidable by an
#: explicit compiler barrier on the following lines rather than by
#: ``ama_secure_memzero``'s volatile stores.
#:
#: One site needs it and it is not an exemption: ``ama_secure_stack_wipe()``
#: zeroes several kilobytes of dead stack after every AEAD call, and the
#: volatile word loop ``ama_secure_memzero`` uses costs 90-127 ns there
#: against 29 ns for ``memset`` plus a barrier — on a 16-byte AEAD call the
#: difference between +50% and +17%.  ``memset`` keeps the wide-store path
#: while the barrier supplies exactly the property the volatile stores exist
#: for.
#:
#: The annotation is not taken on trust: :func:`_has_scrub_barrier` requires
#: a real barrier within :data:`_BARRIER_WINDOW_LINES` after the call, on
#: every build, so deleting the barrier and keeping the comment fails the
#: gate.  That sentence was not true of the one real site until the offset
#: grammar in :data:`_DST_ARGUMENT` admitted its parenthesized offset: the
#: call was never matched, so neither its annotation nor its barrier was read.
_SCRUB_BARRIER_TOKEN = "SCRUB-BARRIER"  # noqa: S105 -- a C-comment annotation token the gate greps for, not a credential (ZERO-012)

#: The opening of a GNU inline-asm statement.  What makes one a BARRIER is
#: decided by :func:`_is_barrier_asm`, not by this pattern.
#:
#: The pattern this replaces accepted ``__asm__`` with its operand and clobber
#: lists optional, and matched it against RAW source lines.  Three things
#: therefore vouched for a ``SCRUB-BARRIER`` memset that the compiler was
#: still free to delete — and because the SCRUB-BARRIER waiver is checked
#: before the secret-name rule, each one also waived a secret-named finding:
#:
#: * ``__asm__ volatile("")``.  Measured with gcc 13.3.0 -O2 on
#:   ``memset(secret_key, 0, 64)`` after the key was used: the stores are gone.
#:   ``"" : : "r"(secret_key)`` without ``"memory"`` is also elided by gcc, and
#:   ``"" ::: "memory"`` without the operand is elided by clang 18.1.3 -O2 for
#:   a buffer whose address never escapes (``ama_stack_wipe_below``'s frame is
#:   exactly that).  Only ``"" : : "r"(buf) : "memory"`` kept the stores under
#:   both compilers, which is the form ``ama_consttime.c`` uses.
#: * ``#if defined(_MSC_VER) _ReadWriteBarrier(); #endif`` — no barrier at all
#:   in the gcc/clang builds.
#: * a COMMENT quoting a barrier, since raw lines include comments.
_ASM_RE = re.compile(r"\b(?:__asm__|__asm|asm)\s*(?:(?:__volatile__|__volatile|volatile)\s*)?\(")

#: MSVC's compiler barrier.  Accepted as the MSVC arm of a barrier, never as
#: the only one: see :func:`_has_scrub_barrier`.
_MSVC_BARRIER_RE = re.compile(r"\b_ReadWriteBarrier\s*\(\s*\)")

#: A preprocessor conditional directive, in comment- and literal-blanked text.
_CONDITIONAL_RE = re.compile(
    r"^[ \t]*#[ \t]*(?P<kind>ifdef|ifndef|if|elifdef|elifndef|elif|else|endif)\b",
    re.MULTILINE,
)

#: How far after the memset the barrier may sit.  Small on purpose: the
#: barrier belongs beside the write it protects, and a wide window would let
#: an unrelated barrier elsewhere in a long function vouch for it.
_BARRIER_WINDOW_LINES = 12


class _Source(NamedTuple):
    """One file's text in the three views the annotation checks need.

    All three have the same length and the same newlines, so one offset or
    one line number indexes the same character in each.
    """

    #: The file as written.
    text: str
    #: Comments and string/char literal bodies blanked (``blank_comments_and_literals``).
    blanked: str
    #: Comments blanked, string literals kept (``keep_strings=True``).
    code: str
    #: Offset of the first character of each line.
    line_starts: list[int]

    def line(self, view: str, line_no: int) -> str:
        """Line ``line_no`` (1-based) of ``view``, without its newline."""
        begin = self.line_starts[line_no - 1]
        end = self.line_starts[line_no] - 1 if line_no < len(self.line_starts) else len(view)
        return view[begin:end]


def _in_shipped_tree(path: Path) -> bool:
    """Whether ``path`` is under ``src/c`` — the tree whose bytes ship."""
    try:
        path.resolve().relative_to(C_ROOT.resolve())
    except ValueError:
        return False
    return True


def _call_end_offset(blanked: str, start: int) -> int:
    """Offset of the ``)`` that closes the call beginning at ``start``.

    ``_MEMSET_RE`` stops after the zero argument, so the call's LAST line (the
    one that most naturally carries a trailing annotation on a wrapped call)
    is found by matching parentheses forward from the ``memset(`` instead.
    """
    opening = blanked.find("(", start)
    if opening < 0:
        return start
    depth = 0
    for index in range(opening, len(blanked)):
        char = blanked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(blanked) - 1


def _comment_text(source: _Source, line_no: int) -> str:
    """The characters of line ``line_no`` that sit inside a comment."""
    raw = source.line(source.text, line_no)
    code = source.line(source.code, line_no)
    return "".join(r if r != c else " " for r, c in zip(raw, code))


def _is_annotated(source: _Source, token: str, first_line: int, last_line: int) -> bool:
    """Whether the call spanning ``first_line..last_line`` (1-based) carries ``token``.

    The token must be written in a comment, on a line the call occupies or on
    the line immediately above it — the two places the existing sites put it.

    The line above counts ONLY when it holds no code.  It used to count
    unconditionally, so in::

        memset(&input_block, 0, n);  // PUBLIC-DATA: input_block — ...
        memset(kr, 0, sizeof kr);

    the second call borrowed the first one's annotation and a bare,
    elidable memset shipped unreported: deleting the comment from
    ``ama_argon2.c``'s second consecutive annotated memset left the gate
    green.  A comment-only line above is still an annotation of the call
    below it; a statement above is annotating itself.
    """
    candidates = list(range(first_line, last_line + 1))
    if first_line > 1 and not source.line(source.blanked, first_line - 1).strip():
        candidates.insert(0, first_line - 1)
    return any(token in _comment_text(source, number) for number in candidates)


def _is_barrier_asm(source: _Source, open_paren: int, close_paren: int, names: set[str]) -> bool:
    """Whether the asm statement whose operands span the parentheses is a barrier.

    A barrier here is an INPUT operand naming the scrubbed object and
    ``"memory"`` among the clobbers — e.g.
    ``__asm__ __volatile__("" : : "r"(frame) : "memory")``.  Both are
    load-bearing, measured (see :data:`_ASM_RE`): without the operand clang
    deletes the memset of a buffer whose address never escapes; without the
    clobber (``: "cc"`` in its place included) gcc does.  The template and the
    ``volatile`` qualifier are deliberately not examined: a ``"nop"`` template
    and a non-volatile asm with an unused output both kept the stores under
    gcc 13.3.0 and clang 18.1.3 at -O2, so requiring either would be a rule
    with no measured property behind it.

    The sections are split at top-level colons in the blanked text (so a colon
    inside a string or comment cannot split them); the clobbers are read from
    the comment-blanked text with strings kept, and the operand names from the
    fully blanked one, so a comment can supply neither.

    That exclusion of comments is REDUNDANT with :func:`_barriers_in`, which
    already locates the asm in the blanked text, and it is kept deliberately:
    measured by mutation, either layer alone keeps a commented-out barrier from
    counting, and only removing both lets it through.  The tests therefore pin
    the property (a quoted barrier is refused), not either layer.
    """
    cuts = [open_paren]
    depth = 0
    for index in range(open_paren + 1, close_paren):
        char = source.blanked[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == ":" and depth == 0:
            cuts.append(index)
    cuts.append(close_paren)
    sections = [(cuts[k] + 1, cuts[k + 1]) for k in range(len(cuts) - 1)]
    if len(sections) < 4:
        return False
    inputs, clobbers = sections[2], sections[3]
    operand_text = source.blanked[inputs[0] : inputs[1]]
    if not any(re.search(r"\b" + re.escape(name) + r"\b", operand_text) for name in names):
        return False
    return '"memory"' in source.code[clobbers[0] : clobbers[1]]


def _barriers_in(source: _Source, start: int, end: int, names: set[str]) -> tuple[bool, bool]:
    """``(any barrier, a gcc/clang barrier)`` in ``[start, end)``, no directives inside."""
    for asm in _ASM_RE.finditer(source.blanked, start, end):
        matched = _match_call_arguments(source.blanked, asm.end() - 1)
        if matched is not None and _is_barrier_asm(source, asm.end() - 1, matched[1] - 1, names):
            return True, True
    return _MSVC_BARRIER_RE.search(source.blanked, start, end) is not None, False


@dataclass
class _Group:
    """A preprocessor conditional group: its arms, and whether they are exhaustive."""

    #: An ``#else`` arm exists, so some arm is compiled on every build.
    exhaustive: bool = False
    #: The ``#endif`` was reached inside the window.
    closed: bool = False
    #: Each arm's items: ``(begin, end)`` text spans and nested groups.
    arms: list[list[tuple[int, int] | _Group]] = field(default_factory=list)


def _parse_conditionals(
    directives: list[re.Match[str]], index: int, start: int, end: int
) -> tuple[list[tuple[int, int] | _Group], int, re.Match[str] | None]:
    """Parse ``[start, end)`` into text spans and conditional groups.

    Returns ``(items, index, terminator)``: ``terminator`` is the
    ``#elif``/``#else``/``#endif`` that ended this sequence (``index`` is its
    position in ``directives``), or None when ``end`` was reached.
    """
    items: list[tuple[int, int] | _Group] = []
    position = start
    while index < len(directives):
        directive = directives[index]
        items.append((position, directive.start()))
        if directive.group("kind") not in ("if", "ifdef", "ifndef"):
            return items, index, directive
        group = _Group()
        items.append(group)
        index += 1
        position = directive.end()
        while True:
            arm, index, terminator = _parse_conditionals(directives, index, position, end)
            group.arms.append(arm)
            if terminator is None:
                return items, index, None
            index += 1
            position = terminator.end()
            if terminator.group("kind") == "else":
                group.exhaustive = True
            if terminator.group("kind") == "endif":
                group.closed = True
                break
    items.append((position, end))
    return items, index, None


def _covers(
    source: _Source, items: list[tuple[int, int] | _Group], names: set[str]
) -> tuple[bool, bool]:
    """``(every preprocessor path reaches a barrier, some path reaches a gcc/clang one)``.

    A conditional group covers only if it is closed, has an ``#else``, and
    every arm covers — so ``#if defined(_MSC_VER) _ReadWriteBarrier(); #endif``
    leaves the other builds bare and does not count.
    """
    covered = False
    native = False
    for item in items:
        if isinstance(item, _Group):
            arms = [_covers(source, arm, names) for arm in item.arms]
            native = native or any(arm_native for _, arm_native in arms)
            if item.exhaustive and item.closed and all(arm_covered for arm_covered, _ in arms):
                covered = True
            continue
        any_barrier, gnu_barrier = _barriers_in(source, item[0], item[1], names)
        covered = covered or any_barrier
        native = native or gnu_barrier
    return covered, native


def _has_scrub_barrier(source: _Source, call_close: int, last_line: int, names: set[str]) -> bool:
    """Whether a real compiler barrier follows the call on every build.

    What makes ``SCRUB-BARRIER`` a claim the gate checks rather than a comment
    it believes.  The window opens just after the call's closing parenthesis
    (not at the start of its line, whose trailing comment is not code) and
    runs :data:`_BARRIER_WINDOW_LINES` lines past the call, or to the end of
    the enclosing block if that comes first — a barrier in the next function
    does not protect this one's write.

    Every preprocessor path through the window must reach a barrier (a
    gcc/clang one per :func:`_is_barrier_asm`, or ``_ReadWriteBarrier()`` for
    an MSVC arm), and at least one path must reach the gcc/clang one.  A
    ``#else``/``#elif`` of a group the call itself sits in starts a sibling
    arm the call is never compiled with, so that arm is skipped to its
    ``#endif``.
    """
    last = min(last_line + _BARRIER_WINDOW_LINES, len(source.line_starts))
    end = source.line_starts[last] if last < len(source.line_starts) else len(source.text)
    depth = 0
    for index in range(call_close + 1, end):
        char = source.blanked[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                end = index
                break
    directives = list(_CONDITIONAL_RE.finditer(source.blanked, call_close + 1, end))
    items: list[tuple[int, int] | _Group] = []
    index = 0
    position = call_close + 1
    while True:
        parsed, index, terminator = _parse_conditionals(directives, index, position, end)
        items.extend(parsed)
        if terminator is None:
            break
        index += 1
        position = terminator.end()
        if terminator.group("kind") == "endif":
            # The call's own group closed; what follows runs after it.
            continue
        # `#else`/`#elif` of the call's own group: the arms up to its `#endif`
        # are never compiled with the call, so they cannot protect it.
        nesting = 0
        while index < len(directives) and (
            directives[index].group("kind") != "endif" or nesting > 0
        ):
            kind = directives[index].group("kind")
            if kind in ("if", "ifdef", "ifndef"):
                nesting += 1
            elif kind == "endif":
                nesting -= 1
            index += 1
        if index == len(directives):
            break
        position = directives[index].end()
        index += 1
    covered, native = _covers(source, items, names)
    return covered and native


def scan_text(text: str, path: Path) -> list[Finding]:
    """Findings in one file's text.

    Two rules, one regex:

    1. A memset-zero whose destination is SECRET-NAMED (``_SECRET_NAME_RE``)
       is a finding wherever it appears.
    2. In the shipped tree (``src/c``), a memset-zero whose destination is
       NOT secret-named is a finding unless it carries a ``PUBLIC-DATA``
       annotation.  Rule 1 alone recognised about 7 % of the identifiers this
       codebase scrubs as secrets — measured against the tree's own
       ``ama_secure_memzero`` call sites, 17 of 244 distinct scrub targets
       matched the convention — so ``memset(sk, 0, ...)``, ``memset(seed,
       ...)``, ``memset(key, ...)`` and ``memset(kr, ...)`` all passed.  Naming
       cannot be made exhaustive; the burden is inverted instead: every
       remaining bare zeroing memset in shipped code must state, at the site,
       that its destination is not a secret, and the reviewer of that line
       decides whether the statement is true.  The test tree keeps rule 1 only
       (a test's memsets are not shipped).

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

    # The annotation checks index lines through `line_starts`, so they read
    # the same line in all three views whatever line breaks the file uses.
    source = _Source(
        text, blanked, blank_comments_and_literals(text, keep_strings=True), line_starts
    )

    findings: list[Finding] = []
    shipped = _in_shipped_tree(path)
    matches = [match for pattern in _ZEROING_CALL_RES for match in pattern.finditer(blanked)]
    for match in matches:
        dst = _destination_name(match.group("dst"))
        if not dst:
            continue
        call = match.group("fn")
        line_no = bisect_right(line_starts, match.start())
        raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        expression = ("&" if match.group("amp") else "") + match.group("dst")
        call_close = _call_end_offset(blanked, match.start())
        end_line = bisect_right(line_starts, call_close)
        # The barrier's operand may name the object (`frame`) or the member
        # the naming convention resolves to (`ctx->key` -> `key`).
        base = re.match(r"[A-Za-z_][A-Za-z0-9_]*", match.group("dst"))
        names = {dst} | ({base.group(0)} if base else set())
        if _is_annotated(source, _SCRUB_BARRIER_TOKEN, line_no, end_line) and _has_scrub_barrier(
            source, call_close, end_line, names
        ):
            # Secret destination, non-elidable by an explicit barrier that
            # _has_scrub_barrier() has just confirmed is there.
            continue
        if _SECRET_NAME_RE.match(dst):
            findings.append(Finding(path, line_no, dst, raw, expression, call=call))
            continue
        if shipped:
            if not _is_annotated(source, _PUBLIC_DATA_TOKEN, line_no, end_line):
                findings.append(
                    Finding(path, line_no, dst, raw, expression, "unannotated", call=call)
                )

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
        print(
            f"FAIL  bare memset()/bzero() on secret-named or unannotated buffers "
            f"({len(findings)} finding(s)):\n"
        )
        for finding in findings:
            print(finding.render())
            print()
        print(
            "Scrub secret material with ama_secure_memzero() from src/c/ama_consttime.c;\n"
            "annotate a shipped memset-zero of non-secret data with `// PUBLIC-DATA: <name> — <why>`.\n"
            "INVARIANT-6: secret material must be scrubbed with a write the "
            "compiler is not free to remove."
        )
        return 1

    print(
        f"OK    no bare memset()/bzero() on secret-named buffers, and every shipped memset-zero "
        f"is annotated ({len(targets)} C file(s) checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
