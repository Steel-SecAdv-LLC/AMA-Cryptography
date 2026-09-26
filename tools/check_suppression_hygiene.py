#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-13 enforcement: scan for unjustified static-analysis suppressions.

Exit codes:
    0  — all suppressions are justified
    1  — one or more violations found

Usage (CI):
    python tools/check_suppression_hygiene.py
"""

from __future__ import annotations

import ast
import io
import os
import re
import sys
import tokenize
from pathlib import Path
from typing import Optional

# Suppression tokens to scan for.
#
# ``nosemgrep`` is included here because INVARIANT-13 is worded "any
# equivalent suppression marker"; semgrep is part of the same defence-in-
# depth stack as bandit/ruff/mypy and the same tracking-ID + justification
# requirements apply.  Devin reviews #19/#20/#21/#22 (PR #277) caught four
# ``nosemgrep`` markers that lacked tracking IDs; extending the scanner is
# the regression check that would have caught those at PR-review time.
#
# Two-stage matching:
#   1. ``_SUPPRESSION_RE`` matches *any* suppression marker — including a
#      bare ``# nosemgrep`` with no rule id — so the line is always
#      flagged for the tracking-ID + justification pass.
#   2. For the ``nosemgrep`` family specifically, ``_NOSEMGREP_STRICT_RE``
#      then asserts the line-targeted form ``# nosemgrep: <rule_id>``
#      (Copilot review @ tools/check_suppression_hygiene.py:34).  Bare
#      ``# nosemgrep`` blanket-suppresses every rule on the line, which
#      is exactly the kind of catch-all the INVARIANT-13 audit trail is
#      meant to prevent.  Semgrep itself accepts both forms; this repo
#      requires the colon + rule id form so reviewers can verify *which*
#      rule each suppression silences.
_SUPPRESSION_RE = re.compile(
    r"#\s*(noqa|nosec|nosemgrep|pylint:\s*disable|type:\s*ignore|mypy:\s*\S+)"
)

#: FILE-SCOPED linter directives.  INVARIANT-13's FIRST condition is that a
#: suppression be line-scoped, not file-scoped — and that condition had no
#: enforcement anywhere.  Every one of these forms is a STANDALONE comment, and
#: `effective_suppressions` discards standalone comments before
#: `_SUPPRESSION_RE` ever sees them: the mechanism that stops the gate firing
#: on its own prose is exactly what guaranteed the file-scoped forms were never
#: examined.  `mypy:` was not in the marker set at all, so
#: `# mypy: ignore-errors` was unrecognised even as a marker.
#:
#: These are refused UNCONDITIONALLY, justification or not: the invariant
#: forbids the scope, not the absence of a reason.  Two more file-scoped forms
#: are found by position rather than by spelling, and so are not in this
#: pattern: mypy's whole-module `# type: ignore` (see
#: :func:`module_level_type_ignore_lines`) and mypy's inline configuration
#: (see :func:`mypy_inline_config_lines`).
_FILE_SCOPED_RE = re.compile(
    r"^#\s*(?:"
    r"ruff\s*:\s*noqa"
    r"|flake8\s*:\s*noqa"
    r"|mypy\s*:\s*(?:ignore-errors|disable-error-code)"
    r"|pylint\s*:\s*(?:skip-file|disable-all)"
    r")\b"
)

#: mypy's inline-configuration prefix, spelled exactly as mypy matches it
#: (``mypy.util.get_mypy_comments``: ``line.startswith("# mypy: ")`` over the
#: RAW source lines, verified against mypy 2.3.1).
_MYPY_INLINE_CONFIG_PREFIX = "# mypy: "


def module_level_type_ignore_lines(source: str) -> list[int]:
    """Lines of every ``# type: ignore`` that makes mypy skip the whole module.

    mypy's rule (``ASTConverter.translate_stmt_list``, mypy 2.3.1): a
    ``type: ignore`` comment whose line is BEFORE the module's first statement
    — a decorated definition starts at its first decorator — ignores the
    entire module.  Not "on line 1": anywhere before the first statement.

    The gate used to test ``lineno == 1`` only, and every tracked ``.py`` file
    opens with the shebang and/or the copyright and SPDX lines that
    ``check_headers.py`` requires, so line 1 can never hold the marker in a
    compliant file.  ``# type: ignore`` on line 4 — after the SPDX line,
    before the docstring — made ``mypy --strict`` skip the module while this
    gate reported every suppression justified.

    Found the way mypy finds it: the parser's own ``type_ignores`` (Python's
    tokenizer emits them only for genuine comments), compared against the
    first statement's line.  A file that does not parse yields nothing here,
    and mypy refuses it outright anyway.
    """
    try:
        tree = ast.parse(source, type_comments=True)
    except (SyntaxError, ValueError):
        return []
    if not tree.body:
        return []
    first = tree.body[0]
    first_line = first.lineno
    if (
        isinstance(first, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and first.decorator_list
    ):
        first_line = first.decorator_list[0].lineno
    return sorted(ti.lineno for ti in tree.type_ignores if ti.lineno < first_line)


def mypy_inline_config_lines(source: str) -> list[tuple[int, str]]:
    """``(lineno, line)`` for every line mypy reads as inline configuration.

    mypy's inline configuration is file-scoped by construction: it sets
    per-module options for the whole file.  ``# mypy: allow-untyped-defs``
    or ``# mypy: no-warn-unused-ignores`` relaxes ``--strict`` for every line
    of the module just as ``# mypy: ignore-errors`` does, and
    ``_FILE_SCOPED_RE`` named only the last two options.

    Matched on RAW lines, the way mypy matches it, not on comment tokens: mypy
    does not tokenize, so a line beginning ``# mypy: ignore-errors`` inside a
    triple-quoted string silences the module exactly as a real comment does,
    and a token-based scan never sees it.

    Every option is refused, not just the relaxations.  An allow-list of
    "strictness-increasing" options would have to track mypy's option set and
    its ``flag=False`` spellings; a per-module setting belongs in the
    reviewed ``[tool.mypy]`` configuration instead.  The tree carries none.
    """
    return [
        (lineno, line.rstrip("\r"))
        for lineno, line in enumerate(source.split("\n"), start=1)
        if line.startswith(_MYPY_INLINE_CONFIG_PREFIX)
    ]


#: A comment that could be a ``type: ignore`` — the loose pre-filter that
#: decides whether :func:`module_level_type_ignore_lines` needs to parse.
_MAYBE_TYPE_IGNORE_RE = re.compile(r"type\s*:\s*ignore")

#: Tokens that are not a statement's first token.
_NOT_A_STATEMENT = frozenset(
    {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.ENCODING, tokenize.ENDMARKER}
)


def scan_comments(source: str) -> tuple[list[tuple[int, str, bool]], Optional[int]]:
    """One tokenize pass: ``(lineno, text, trailing)`` per comment, and the
    line of the first statement's first token (``None`` for no statement).

    The first significant token is where mypy's rule places the first
    statement — a decorator's ``@``, a docstring's opening quote — so this
    pass also tells :func:`file_scoped_lines` whether a ``type: ignore``
    comment is even a candidate before anything is parsed.  An unparseable
    file yields what was seen before the error.
    """
    comments: list[tuple[int, str, bool]] = []
    first: Optional[int] = None
    lines = source.splitlines()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                lineno, col = tok.start
                physical = lines[lineno - 1] if lineno - 1 < len(lines) else ""
                comments.append((lineno, tok.string, bool(physical[:col].strip())))
            elif first is None and tok.type not in _NOT_A_STATEMENT:
                first = tok.start[0]
    except (tokenize.TokenError, SyntaxError, IndentationError):
        # Keep what was seen before the error: file_scoped_lines and the
        # candidate listing want every comment they can get.  This is NOT
        # where an unparseable file is judged -- check_source refuses one
        # outright, because a suppression written after the error point is
        # invisible to this pass and would otherwise go unreported.
        return comments, first
    return comments, first


def file_scoped_lines(
    source: str,
    scanned: Optional[tuple[list[tuple[int, str, bool]], Optional[int]]] = None,
) -> dict[int, str]:
    """Every line of ``source`` that holds a file-scoped suppression.

    The union of the three ways a suppression can reach the whole file: a
    standalone linter directive ``_FILE_SCOPED_RE`` names, mypy's
    whole-module ``# type: ignore``, and mypy's inline configuration.
    ``scanned`` is :func:`scan_comments`' result, when the caller has it.
    """
    comments, first = scanned if scanned is not None else scan_comments(source)
    found: dict[int, str] = {}
    candidate = False
    for lineno, text, trailing in comments:
        if trailing:
            continue  # line-scoped by position
        if _FILE_SCOPED_RE.match(text.strip()):
            found[lineno] = text.strip()
        if (first is None or lineno < first) and _MAYBE_TYPE_IGNORE_RE.search(text):
            candidate = True
    if candidate:
        # Exact, and rare: only a file with a type-ignore-shaped comment ahead
        # of its first statement pays for a parse.
        lines = source.splitlines()
        for lineno in module_level_type_ignore_lines(source):
            found[lineno] = lines[lineno - 1].strip() if lineno - 1 < len(lines) else ""
    if _MYPY_INLINE_CONFIG_PREFIX in source:
        for lineno, line in mypy_inline_config_lines(source):
            found[lineno] = line.strip()
    return found


_NOSEMGREP_STRICT_RE = re.compile(r"^:\s*\S+")

# The same requirement, for the two other markers that blanket-suppress a whole
# scanner when written bare.  Adding them is not symmetry for its own sake:
#
# ``nosec``  bandit resolves ``# nosec <text>`` by parsing <text> as test ids
#            (``NOSEC_COMMENT`` / ``NOSEC_COMMENT_TESTS`` in bandit's manager),
#            warns "Test in comment: X is not a test name or id, ignoring" for
#            every word it cannot resolve, and — this is the part that matters —
#            treats an EMPTY resolved set as "no specific tests", i.e. blanket.
#            So this repository's house style, ``# nosec -- reason (TAG-NNN)``,
#            would read to a reviewer as a targeted suppression carrying its
#            justification while silencing every bandit test on the line.  A
#            ``B``-code makes the resolved set non-empty and the marker means
#            what it looks like.  Verified against bandit 1.9.2.
#
# ``noqa``   ruff (and flake8) treat a bare ``noqa`` comment as "all rules on
#            this line"; only the ``noqa: <CODE>`` form targets one.  Same
#            catch-all, same audit-trail problem.  (The marker is spelled here
#            without its leading hash: ruff scans comment PROSE for the
#            hash-prefixed form too, and reports the examples themselves as
#            malformed directives — three warnings in every CI lint log.)
#
# ``type: ignore`` and ``pylint: disable`` are deliberately NOT held to this,
# and the reason is stated rather than left as an omission: mypy --strict's
# ``warn_unused_ignores`` already reports an ignore that suppresses nothing.
# (mypy's bare whole-module ``# type: ignore`` is not an exception to that:
# it is file-scoped, and :func:`file_scoped_lines` refuses it outright.)
# Neither family has a bare occurrence in the tree today.
_NOSEC_STRICT_RE = re.compile(r"^:?\s*B\d+", re.IGNORECASE)
_NOQA_STRICT_RE = re.compile(r"^:\s*[A-Z]+\d+", re.IGNORECASE)

#: Marker -> (pattern its targeted form must match, the form to write instead).
_STRICT_FORMS: dict[str, tuple[re.Pattern[str], str]] = {
    "nosemgrep": (_NOSEMGREP_STRICT_RE, "# nosemgrep: <rule_id> -- justification (TAG-NNN)"),
    "nosec": (_NOSEC_STRICT_RE, "# nosec B105 -- justification (TAG-NNN)"),
    "noqa": (_NOQA_STRICT_RE, "# noqa: S310 -- justification (TAG-NNN)"),
}

# Tracking ID pattern: parenthesised alphanumeric tag, e.g. (KM-001), (FIN-002)
_TRACKING_ID_RE = re.compile(r"\([A-Z]+-\d+\)")

# Justification: an em-dash, double-hyphen, or inline comment (# ...) followed by text.
# The inline-comment form is required for ``type: ignore`` because mypy >=1.20
# rejects em-dashes inside the ``# type: ignore[code]`` directive.
_JUSTIFICATION_RE = re.compile(r"[\u2014\u2013]|--|#\s*\S")

# Forbidden directories: suppressions are absolutely prohibited here
_FORBIDDEN_DIRS: tuple[str, ...] = (
    "src/c/",
    "include/",
)


def _is_forbidden(filepath: str) -> bool:
    """Return True if the file lives under a forbidden directory."""
    for d in _FORBIDDEN_DIRS:
        if filepath.startswith(d) or f"/{d}" in filepath:
            return True
    return False


def effective_suppressions(source: str) -> list[tuple[int, str]]:
    """Return ``(lineno, comment_text)`` for comments that actually suppress.

    Two filters, both of which the previous line-oriented scan lacked.

    **Comment text, not the whole line.** The scan used to collect the line
    *numbers* carrying a comment and then run the marker regex over the entire
    raw line, which put every string literal on such a line back in scope — the
    exact thing tokenizing was supposed to rule out. The comment token's own
    text is used here instead.

    **Trailing comments only.** ``bandit``, ``ruff`` and ``mypy`` all anchor a
    suppression to the line of the finding, so a full-line comment suppresses
    nothing; it is prose. That distinction never mattered while the scan
    covered only ``ama_cryptography/`` and ``tests/``, where nothing discusses
    markers in a comment. It matters immediately in ``tools/``, where the
    checkers *document their own subject matter*: eight comments explaining
    what a ``# nosec`` is were reported as unjustified suppressions the moment
    that tree was included. A gate that fires on its own documentation is one
    people learn to route around.

    The standalone forms that are REAL — the file-scoped suppressions
    :func:`file_scoped_lines` finds — are kept in scope explicitly rather than
    lost to the rule.  That set used to be just mypy's ``# type: ignore`` on
    line 1, which meant ``# ruff: noqa``, ``# flake8: noqa`` and
    ``# mypy: ignore-errors`` were structurally invisible: the gate could not
    have reported them however they were written, and INVARIANT-13's first
    condition — line-scoped, not file-scoped — had no enforcement at all.
    Line 1 was itself the wrong test: see
    :func:`module_level_type_ignore_lines`.
    """
    scanned = scan_comments(source)
    scoped = file_scoped_lines(source, scanned)
    return [(lineno, text) for lineno, text, trailing in scanned[0] if trailing or lineno in scoped]


def check_source(filepath: str, source: str) -> list[str]:
    """Return violation messages for already-loaded Python ``source``."""
    violations: list[str] = []
    try:
        ast.parse(source, filename=filepath)
    except SyntaxError as exc:  # IndentationError and TabError are subclasses
        # Fail closed: tokenizing stops at the error, so every comment after
        # it -- and every suppression those comments carry -- is unseen.
        return [
            f"{filepath}:{exc.lineno or 0}: cannot be parsed ({exc.msg}); no "
            f"suppression after this line can be verified, so the file is refused"
        ]
    # File-scoped first, and unconditionally: INVARIANT-13 forbids the SCOPE.
    # A justification and a tracking id do not make a file-scoped `ruff: noqa`
    # comment line-scoped, so there is no form of it to accept.
    #
    # Reported from `file_scoped_lines` directly, not from the comment tokens:
    # a mypy inline-config line inside a string literal is not a comment token
    # at all, and mypy honours it anyway.  A trailing
    # `# type: ignore[arg-type]` — the ordinary line-scoped form — is never in
    # this set.
    scanned = scan_comments(source)
    scoped = file_scoped_lines(source, scanned)
    for lineno, stripped in sorted(scoped.items()):
        violations.append(
            f"{filepath}:{lineno}: FILE-SCOPED suppression '{stripped[:60]}' — "
            f"INVARIANT-13 requires line-scoped suppressions; move it to the "
            f"lines it applies to and justify each one"
        )
    for lineno, comment, trailing in scanned[0]:
        if not trailing or lineno in scoped:
            continue  # prose, or already reported as file-scoped
        for m in _SUPPRESSION_RE.finditer(comment):
            tag = f"{filepath}:{lineno}"
            if _is_forbidden(filepath):
                violations.append(f"{tag}: suppression in forbidden directory")
                break
            rest = comment[m.end() :]
            # Strict form: the marker must name the rule it silences, so a
            # reviewer can verify WHICH check each suppression turns off.  A
            # bare marker blanket-suppresses its whole scanner on that line,
            # which is the catch-all the INVARIANT-13 audit trail exists to
            # prevent.  See _STRICT_FORMS for why each family is or is not
            # held to this.
            marker = m.group(1)
            strict = _STRICT_FORMS.get(marker)
            if marker == "nosec" and rest[:1].isalpha() and not _NOSEC_STRICT_RE.match(rest):
                # A longer word that merely STARTS with the marker — the secret
                # scanner's nosecret opt-out is the one this tree defines.
                # bandit's NOSEC_COMMENT matches the prefix all the same, finds
                # no test id in the remainder, and skips every test on the line
                # (bandit 1.9.2), so this is a real blanket suppression.
                violations.append(
                    f"{tag}: '{comment.strip()[:40]}' is read by bandit as a bare "
                    f"'nosec' (its pattern matches the prefix) and silences every "
                    f"bandit test on the line; the secret-scan opt-out cannot be "
                    f"used in a Python file"
                )
                continue
            if strict is not None and not strict[0].match(rest):
                violations.append(
                    f"{tag}: suppression '{marker}' missing rule id "
                    f"(expected '{strict[1]}'); written bare it suppresses "
                    f"every rule on the line"
                )
                continue
            if not _JUSTIFICATION_RE.search(rest):
                violations.append(
                    f"{tag}: suppression '{m.group()}' missing justification "
                    f"(expected em-dash, --, or # followed by reason and tracking ID)"
                )
            elif not _TRACKING_ID_RE.search(rest):
                violations.append(
                    f"{tag}: suppression '{m.group()}' missing tracking ID "
                    f"(expected e.g. (KM-001))"
                )
    return violations


def _scan_file(filepath: str) -> list[str]:
    """Return a list of violation messages for the given file."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return []  # skip unreadable files
    return check_source(filepath, source)


#: Trees where INVARIANT-13 states suppressions are "**absolutely forbidden**
#: ... regardless of justification".  Scanned by :func:`scan_c_tree` below.
#:
#: They had never been scanned.  ``_FORBIDDEN_DIRS`` above listed them and
#: ``_is_forbidden()`` reported on them, but ``main()`` only ever collected
#: ``ama_cryptography/**/*.py``, ``tests/**/*.py`` and ``tools/**/*.py`` — no
#: path under ``src/c/`` or ``include/`` could reach that branch, so it was
#: dead code for every entry, and INVARIANTS.md's "CI scans the repository for
#: suppression tokens and **must** fail if a suppression appears in a forbidden
#: directory" was false.  A live suppression sat in ``src/c/`` while the gate
#: printed "all suppressions are properly justified" and exited 0.
_C_FORBIDDEN_ROOTS: tuple[str, ...] = ("src/c", "include")

#: Vendored trees are excluded.  They are third-party code carried verbatim;
#: INVARIANT-13 governs what THIS project writes, and rewriting a vendor
#: comment would defeat the "no project-side modifications" property the
#: vendor-isolation gate enforces separately.
_C_VENDOR_MARKER = "vendor"

#: Suppression markers recognised by the C/C++ analysers this project runs.
#: ``NOLINT`` covers ``NOLINT``, ``NOLINTNEXTLINE`` and ``NOLINTBEGIN`` in one
#: pattern because clang-tidy matches the token anywhere inside a comment —
#: which is also why it is spelled here as a regex and never as prose in a C
#: comment: writing it in a source comment ARMS it.
_C_SUPPRESSION_RE = re.compile(
    r"NOLINT(?:NEXTLINE|BEGIN|END)?\b|cppcheck-suppress|nosemgrep|coverity\s*\[|/\*\s*LINTED"
    # Compiler- and sanitizer-level suppressions.  The scan used to recognise
    # analyser comment markers only, so a `#pragma GCC diagnostic ignored`, an
    # MSVC `#pragma warning(disable)`, a `no_sanitize` attribute or `optnone`
    # silenced a diagnostic in the crypto core while the gate reported the C
    # tree "carries none at all".  The tree carried three.
    r"|#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+ignored"
    r"|#\s*pragma\s+warning\s*\(\s*(?:disable|suppress)"
    # The operator form of the same pragma, which the directive pattern above
    # never sees: `_Pragma("GCC diagnostic ignored \"-W...\"")`.
    r"|_Pragma\s*\(\s*\"\s*(?:GCC|clang)\s+diagnostic\s+ignored"
    # Optimisation switches that change what the analysers and the
    # constant-time lanes see for one function or one region.
    r"|#\s*pragma\s+(?:GCC\s+optimize|clang\s+optimize\s+off)"
    r"|\bno_sanitize(?:_address|_memory|_thread|_undefined)?\b"
    r"|\bdisable_sanitizer_instrumentation\b"
    # `optnone` in any position of an attribute list, and the C23 spelling.
    r"|__attribute__\s*\(\s*\([^)]*\boptnone\b"
    r"|\[\[\s*clang\s*::\s*optnone\s*\]\]"
)


def c_tree_files(repo_root: Path) -> list[Path]:
    """Every non-vendored ``.c``/``.h`` under the forbidden roots.

    The same enumeration the clang-tidy CI job performs, so "the gate scans
    what the analyser scans" is true by construction rather than by hope.
    """
    out: list[Path] = []
    for root in _C_FORBIDDEN_ROOTS:
        base = repo_root / root
        if not base.is_dir():
            continue
        for pattern in ("**/*.c", "**/*.h"):
            for path in base.glob(pattern):
                if _C_VENDOR_MARKER in path.relative_to(repo_root).parts:
                    continue
                out.append(path)
    return sorted(set(out))


def scan_c_tree(repo_root: Path) -> list[str]:
    """Violations in the trees where suppressions are absolutely forbidden.

    No justification pass here, deliberately.  For the Python trees the rule
    is "justified and tracked"; for these it is "none, regardless of
    justification", so a well-argued suppression is still a violation and the
    only correct outcomes are fixing the code or dropping the check category
    in ``.clang-tidy`` — which is what that file's own header says.
    """
    violations: list[str] = []
    files = c_tree_files(repo_root)
    if not files:
        # Fail closed: an empty scope means the layout moved or the glob broke,
        # and reporting "clean" over nothing is how this gate was wrong before.
        return [
            "src/c and include contain no non-vendored .c/.h files — the scan "
            "scope is empty, which is a checker fault, not a clean tree"
        ]
    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable file
            violations.append(f"{rel}: cannot be read ({exc})")
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _C_SUPPRESSION_RE.search(line)
            if match:
                violations.append(
                    f"{rel}:{lineno}: suppression marker {match.group(0)!r} in a "
                    "tree where INVARIANT-13 forbids suppressions regardless of "
                    "justification — fix the code or drop the check category"
                )
    return violations


# ---------------------------------------------------------------------------
# Third pass: environment-dependent `type: ignore` in optional-import blocks
# ---------------------------------------------------------------------------
#
# A `# type: ignore` inside an `except ImportError:` handler cannot be correct
# in both of the environments this project type-checks in.  Where the optional
# package IS installed, the name bound by the `try` has the imported module's
# type and `name = None` needs the ignore.  Where it is NOT — the CI
# type-check image carries the pinned tools and nothing else — the import
# resolves to `Any` through `ignore_missing_imports`, `name = None` is fine,
# and the same ignore is an ERROR under `warn_unused_ignores`.
#
# So the marker makes the file green in one place and red in the other, which
# is the "green local mypy --strict reached a red CI" failure the type-check
# step already warns about.  It appeared four times in this tree
# (`setup.py` twice, `benchmarks/benchmark_suite.py`,
# `examples/python/complete_demo.py`), each a latent CI break.
#
# The fix is never another suppression: DECLARE the name before the `try`
# (`np: Any`) and import under an alias, which makes the verdict the same in
# both environments.

#: Files this pass reads.  Wider than the justification pass above, because
#: the hazard is about where mypy runs, not about which tree the file is in.
_OPTIONAL_IMPORT_SCAN_DIRS = (
    "ama_cryptography",
    "tests",
    "tools",
    "benchmarks",
    "examples",
    "fuzz",
    "nist_vectors",
    "schemas",
    "wycheproof_vectors",
)

_TYPE_IGNORE_RE = re.compile(r"#\s*type:\s*ignore")


#: Import prefixes that resolve identically in every environment this project
#: type-checks in, because they live in this repository.  A fallback for one of
#: these is not the hazard below: mypy finds the module either way, so an
#: ignore that is needed is needed everywhere.
_FIRST_PARTY_PREFIXES = ("ama_cryptography", "ama_cryptography_monitor", "tools", "tests")


def _may_hold_a_guarded_import(source: str) -> bool:
    """Cheap pre-filter: could this file possibly hold a guarded optional import?

    It must name at least one of the two spellings the AST pass accepts, and
    carry a suppression at all.  The filter used to test
    ``"ImportError" not in source``, and
    ``"ModuleNotFoundError"`` does not contain that substring — so a module
    whose optional import is guarded by the ``ModuleNotFoundError`` spelling
    was dropped here and never reached
    :func:`_third_party_import_fallback_lines`, which handles both.  The hazard
    this pass exists for — a ``# type: ignore`` that is required where the
    package is installed and an error under ``warn_unused_ignores`` where it is
    not — is identical for either spelling.
    """
    if "type:" not in source:
        return False
    return "ImportError" in source or "ModuleNotFoundError" in source


def _third_party_import_fallback_lines(source: str) -> set[int]:
    """1-based line numbers inside an ``except ImportError`` whose ``try``
    imports a module that is NOT first-party.

    The first-party restriction is what makes this precise.
    ``crypto_api.py`` guards ``from ama_cryptography.rfc3161_timestamp import
    …`` — an in-tree module that mypy resolves in every environment — so the
    three ignores in that handler are needed unconditionally and are not a
    portability problem.  Flagging them would be a gate crying wolf on correct
    code, which is how a gate stops being read.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    covered: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue

        third_party = False
        for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(stmt, ast.Import):
                modules = [alias.name for alias in stmt.names]
            elif isinstance(stmt, ast.ImportFrom):
                # A relative import (level > 0) is first-party by construction.
                modules = [] if stmt.level else [stmt.module or ""]
            else:
                continue
            for module in modules:
                head = module.split(".", 1)[0]
                if head and head not in _FIRST_PARTY_PREFIXES:
                    third_party = True
        if not third_party:
            continue

        for handler in node.handlers:
            names: list[str] = []
            exc = handler.type
            if isinstance(exc, ast.Name):
                names = [exc.id]
            elif isinstance(exc, ast.Tuple):
                names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
            if not any(n in ("ImportError", "ModuleNotFoundError") for n in names):
                continue
            for stmt in handler.body:
                end = getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno
                covered.update(range(stmt.lineno, end + 1))
    return covered


def scan_optional_imports(repo_root: Path) -> list[str]:
    """Every ``type: ignore`` sitting inside an optional-import fallback."""
    violations: list[str] = []
    for directory in _OPTIONAL_IMPORT_SCAN_DIRS:
        root = repo_root / directory
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if not _may_hold_a_guarded_import(source):
                continue
            covered = _third_party_import_fallback_lines(source)
            if not covered:
                continue
            for lineno, line in enumerate(source.splitlines(), start=1):
                if lineno in covered and _TYPE_IGNORE_RE.search(line):
                    violations.append(
                        f"{path.relative_to(repo_root).as_posix()}:{lineno}: "
                        f"`type: ignore` inside an except ImportError block — this "
                        f"marker is REQUIRED where the optional package is installed "
                        f"and an ERROR where it is not, so the file cannot be green "
                        f"in both. Declare the name before the `try` "
                        f"(e.g. `np: Any`) and import under an alias instead."
                    )
    for path in (repo_root / "setup.py", repo_root / "ama_cryptography_monitor.py"):
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        if not _may_hold_a_guarded_import(source):
            continue
        covered = _third_party_import_fallback_lines(source)
        for lineno, line in enumerate(source.splitlines(), start=1):
            if lineno in covered and _TYPE_IGNORE_RE.search(line):
                violations.append(
                    f"{path.name}:{lineno}: `type: ignore` inside an except "
                    f"ImportError block — see the note in this gate."
                )
    return violations


def tracked_python_files(root: Path) -> list[Path]:
    """Every ``*.py`` file git tracks, relative to ``root``.

    git rather than a filesystem walk or hard-coded roots: a walk needs a
    hand-maintained list of directories to skip (``build/``, ``.venv/``,
    ``*.egg-info/``, whichever ``build-*`` a local run left behind), and that
    list is exactly the kind of thing that drifts and quietly narrows the check.
    Same discovery ``check_type_check_scope.py`` uses, for the same reason.

    Enumerated through ``tools/_repo.py``, which lists with ``-z``: the bare
    ``git ls-files`` this used to run C-quoted a non-ASCII name
    (``"zz_\\303\\251.py"``), the quoted path matched no file, and a bare
    ``# noqa`` in ``zz_é.py`` was never read.  The helper raises
    ``TrackedFilesError`` (a ``RuntimeError``) if git fails or a tracked path is
    not a regular file on disk.
    """
    repo = str(Path(__file__).resolve().parent.parent)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    from tools._repo import tracked_names

    return [Path(name) for name in tracked_names(root, "*.py")]


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    # Every tracked *.py file, via git rather than three hard-coded rglob roots.
    #
    # The scan was ama_cryptography/ + tests/ + tools/ -- 276 of the 303 tracked
    # Python files. setup.py (shipped in the sdist and executed on every source
    # install), the fuzz harnesses, the benchmark scripts and the wycheproof
    # vector runner sat OUTSIDE it, carrying real suppressions the enforcement
    # layer never saw (audit H8). The comment here used to justify adding tools/
    # on the grounds it "was the only tree where they went unpoliced"; it was
    # not.  git ls-files closes the gap and cannot silently narrow.
    targets = tracked_python_files(repo_root)

    all_violations: list[str] = []
    for path in sorted(targets):
        filepath = str(path)
        all_violations.extend(_scan_file(filepath))

    # The trees INVARIANT-13 calls absolute.  Separate pass, separate rule:
    # presence alone is the violation there.
    all_violations.extend(scan_c_tree(repo_root))

    # Suppressions that cannot be right in both type-check environments.
    all_violations.extend(scan_optional_imports(repo_root))

    if all_violations:
        print(f"INVARIANT-13 violations ({len(all_violations)}):\n")
        for v in all_violations:
            print(f"  {v}")
        print(
            f"\n{len(all_violations)} suppression violation(s). Python-tree markers "
            "need a justification and a tracking ID; markers under src/c or "
            "include must be removed outright."
        )
        return 1

    print(
        "INVARIANT-13: all suppressions are properly justified "
        f"({len(targets)} Python files), and the {len(c_tree_files(repo_root))} "
        "non-vendored C/H files under src/c and include carry none."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
