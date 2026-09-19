#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Hold every security-relevant documented construction to the code that implements it.

The fact this gate protects
---------------------------
A cryptographic document is not prose about software; for anyone integrating
this library it *is* the specification they build against. When it disagrees
with the implementation, one of two things is true, and both are defects:

* the reader builds against a construction that does not exist, or
* the reader trusts a property the code does not provide.

The 2026-09 documentation-integrity pass found both shapes, repeatedly:

``CRYPTOGRAPHY.md`` said ``secure_wipe()`` "uses memory barriers to prevent
compiler optimization" and "verifies the wipe completed". It was three plain
Python ``for`` loops with no barrier of any kind.

``ARCHITECTURE.md`` and ``ENHANCED_FEATURES.md`` each advertised a "pure Python
SHA3-256 fallback" for the hybrid KEM combiner. ``HybridCombiner.combine()``
*raises* when the native HKDF is unavailable, by design, because a
non-constant-time HKDF silently substituted into secret-dependent key
combination is exactly what INVARIANT-7 forbids. The documentation was
advertising the forbidden behaviour as a feature.

``ENHANCED_FEATURES.md`` and ``CRYPTOGRAPHY.md`` published threat thresholds of
0.3 / 0.6 / 0.8 against an implementation using 0.15 / 0.45 / 0.80 — and a
three-signal 0.50/0.30/0.20 weighting against a four-signal
0.45/0.25/0.15/0.15 one. The threshold error ran in the dangerous direction:
the code escalates *earlier* than the table promised, so an operator
calibrating alerts against 0.3 was under-reading their own monitor.

``tests/kat/keyformats/README.md`` said "AMA does not implement HSS/LMS" while
``ama_lms_verify`` and ``ama_hss_verify`` were implemented and exported.

``IMPLEMENTATION_GUIDE.md`` used ``MASTER_OMNI_CODES`` thirteen times. No such
name has ever existed.

Why a gate and not just a correction
------------------------------------
INVARIANT-16's BIP32 case is the precedent: that claim was corrected once
(CHANGELOG KM-HD-001), shipped with no gate, and came back in six places.
``tools/check_hd_interop_honesty.py`` exists because of it. This gate is the
same instrument for the rest of the claim surface — and it is deliberately
built the same way ``check_verification_claim_honesty.py`` is: the authority is
**derived from the source tree**, not written into the gate. Implement a
fallback and the fallback rule stops firing on its own; change a weight and the
weight the gate demands changes with it. A denylist would freeze today's
implementation into CI and start rejecting documentation once it became true.

What is checked
---------------
1. **Forbidden-fallback claims.** For each construction whose implementation
   raises rather than substituting, any documentation asserting a fallback
   fails. Whether it raises is read out of the source with ``ast``.
2. **Weights, thresholds and signal counts.** The posture evaluator's composite
   weights and its three default thresholds are parsed from
   ``adaptive_posture.py``; any documented tuple that disagrees fails, and so
   does a documented signal *count* that disagrees with the number of weights.
3. **Construction descriptions.** The native memory-zeroing kernel writes once
   and issues a barrier; "multi-pass" descriptions of the *native* path fail.
   ``ETHICAL_VECTOR``'s length is read from ``equations.py``.
4. **Removed or nonexistent symbols.** Every ``ama_cryptography``-namespaced
   identifier a document names in a code context must exist in the package or
   in the public C header.
5. **Contradictions with INVARIANTS.** A document may not assert a behaviour
   an invariant forbids where the implementation agrees with the invariant.
6. **Reintroduction elsewhere.** Every rule runs over the whole tracked
   documentation set, so moving a corrected claim into another file does not
   escape it. The retired-claim registry additionally pins the exact wording
   that was removed.

The scan covers **source comments and docstrings as well as prose**, because
they drift identically and are read by the same people. Extending it found two
more: ``crypto_api.py`` carried "Import HMAC and HKDF from pqc_backends
(native C) with pure-Python fallback" four lines above the module's own
INVARIANT-7 guard, and ``secure_memory.py``'s module docstring described
``secure_memzero`` as a "Multi-pass byte-level overwrite" while the function's
own docstring, in the same file, correctly said the native kernel writes once
and issues a barrier. Only the symbol-existence rule is prose-only — in Python
source ``from ama_cryptography import adaptive_posture`` is a valid submodule
import that a prose-shaped rule would misread.

``CHANGELOG.md`` is exempt throughout: it is a historical record and must be
able to quote the wording it retired.

Exit status
-----------
0  documentation agrees with the implementation
1  at least one claim contradicts it
2  the check could not run
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent

#: Prose files. The symbol-existence rule runs only on these: in Python source
#: ``from ama_cryptography import adaptive_posture`` is a valid submodule
#: import, and a prose-shaped rule would report ~150 of them as missing names.
PROSE_SUFFIXES: frozenset[str] = frozenset({".md", ".rst", ".txt"})

#: Everything scanned. Source comments and docstrings are documentation too,
#: and they drift the same way: ``crypto_api.py`` carried
#: "Import HMAC and HKDF from pqc_backends (native C) with pure-Python
#: fallback" four lines above the module's own INVARIANT-7 guard, and
#: ``secure_memory.py``'s module docstring described ``secure_memzero`` as a
#: "Multi-pass byte-level overwrite" while its function docstring — in the same
#: file — correctly said the native kernel writes once and issues a barrier.
SCAN_SUFFIXES: frozenset[str] = PROSE_SUFFIXES | frozenset({".py", ".pyx"})

#: CHANGELOG.md records history, including retired wording. Excluding it is
#: what lets the gate be strict everywhere else.
EXEMPT_FILES: frozenset[str] = frozenset({"CHANGELOG.md"})

EXCLUDED_DIRS: frozenset[str] = frozenset(
    {".git", "build", "build-consumer", "dist", "node_modules", "__pycache__", ".venv", "venv"}
)

#: Files that hold the claims and therefore have to quote them: this gate, its
#: three siblings, and the test module whose negative controls ARE the retired
#: wording. Exempting them is not a loophole — a gate cannot be written without
#: naming what it rejects — but the list is checked at startup, so an entry
#: that outlives its file fails rather than silently widening the exemption.
SELF_REFERENTIAL: tuple[str, ...] = (
    "tools/check_crypto_construction_docs.py",
    "tools/check_doc_examples.py",
    "tools/check_public_api_docs.py",
    "tools/check_benchmark_claims.py",
    "tests/test_documentation_integrity_gates.py",
)

#: A correction note has to quote the wording it retires, or the reader cannot
#: tell what changed.  The marker below opens such a note and waives the rest
#: of its PARAGRAPH — from the marker to the next blank line — which is the
#: natural unit for a correction narrative and the smallest scope that does not
#: force one marker per sentence.
#:
#: It is deliberately explicit and greppable rather than inferred: a waiver
#: that can be inferred is a waiver that arrives by accident, and the whole
#: point of this gate is that a claim cannot come back quietly.  Grepping for
#: this string lists every place the tree still quotes a retired claim, which
#: is a short list a reviewer can read.
WAIVER = "<!-- claim-check: quoting-retired-wording -->"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    text: str
    why: str


# ---------------------------------------------------------------------------
# Authority: facts read out of the implementation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Authority:
    """What the code actually does, derived rather than asserted."""

    combine_raises_on_missing_native: bool
    posture_weights: tuple[float, ...]
    #: ELEVATED, HIGH, CRITICAL — in that order, and short if the source stopped
    #: declaring one.  Deliberately ``tuple[float, ...]`` rather than a
    #: three-tuple: a shorter result means the derivation broke, and ``main``
    #: fails closed on it rather than the type system hiding it behind a cast.
    posture_thresholds: tuple[float, ...]
    ethical_vector_length: int
    native_memzero_has_barrier: bool
    lms_verify_implemented: bool
    hss_verify_implemented: bool
    secure_wipe_delegates_to_memzero: bool
    package_symbols: frozenset[str]
    c_symbols: frozenset[str]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _function(tree: ast.AST, name: str) -> Optional[ast.FunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _raises_invariant7(node: ast.AST) -> bool:
    """True when the body raises with INVARIANT-7 named in the message."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Raise) or child.exc is None:
            continue
        for literal in ast.walk(child.exc):
            if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                if "INVARIANT-7" in literal.value:
                    return True
    return False


def _composite_weights(tree: ast.AST) -> tuple[float, ...]:
    """The literal weights of the posture evaluator's composite score.

    Read from the ``x * W + y * W + ...`` expression rather than from a table
    here, so the number the gate demands moves when the code moves.
    """
    evaluate = _function(tree, "evaluate")
    if evaluate is None:
        return ()
    for node in ast.walk(evaluate):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t for t in node.targets if isinstance(t, ast.Name) and t.id == "score"]
        if not targets:
            continue
        weights = _weights_in_source_order(node.value)
        if weights:
            return weights
    return ()


def _weights_in_source_order(expr: ast.AST) -> tuple[float, ...]:
    """Flatten ``a*W1 + b*W2 + ...`` left-to-right.

    ``ast.walk`` will not do: an Add chain is left-nested, so a walk yields the
    terms in an order that depends on the tree shape rather than the source.
    Getting this wrong would make the gate demand a permutation of the real
    weights and reject the correct documentation.
    """
    terms: list[ast.AST] = []

    def flatten(node: ast.AST) -> None:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            flatten(node.left)
            flatten(node.right)
        else:
            terms.append(node)

    flatten(expr)
    weights: list[float] = []
    for term in terms:
        if isinstance(term, ast.BinOp) and isinstance(term.op, ast.Mult):
            for side in (term.left, term.right):
                if isinstance(side, ast.Constant) and isinstance(side.value, (int, float)):
                    weights.append(float(side.value))
    return tuple(weights)


def _named_floats(tree: ast.AST, names: Sequence[str]) -> tuple[float, ...]:
    found: dict[str, float] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id in names
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, (int, float))
            ):
                found[target.id] = float(node.value.value)
    return tuple(found[name] for name in names if name in found)


def _dict_literal_length(tree: ast.AST, name: str) -> int:
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name and isinstance(node.value, ast.Dict):
                return len(node.value.keys)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return len(node.value.keys)
    return 0


def _module_level_names(path: Path) -> set[str]:
    """Every name a module binds at module level, plus its ``__all__``."""
    names: set[str] = set()
    try:
        tree = _parse(path)
    except (SyntaxError, OSError):
        return names
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    for walked in ast.walk(tree):
        if isinstance(walked, ast.Assign):
            for target in walked.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    for element in ast.walk(walked.value):
                        if isinstance(element, ast.Constant) and isinstance(element.value, str):
                            names.add(element.value)
    return names


_C_SYMBOL = re.compile(r"\b(ama_[a-z0-9_]+)\s*\(")


def build_authority(repo: Path = REPO) -> Authority:
    package = repo / "ama_cryptography"

    combiner = _parse(package / "hybrid_combiner.py")
    combine = _function(combiner, "combine")

    posture = _parse(package / "adaptive_posture.py")
    equations = _parse(package / "equations.py")
    legacy = _parse(package / "legacy_compat.py")
    wipe = _function(legacy, "secure_wipe")

    consttime = (repo / "src" / "c" / "ama_consttime.c").read_text(encoding="utf-8")
    memzero_body = consttime.split("void ama_secure_memzero(", 1)[-1].split("\n}", 1)[0]

    lms = ""
    lms_path = repo / "src" / "c" / "ama_lms.c"
    if lms_path.is_file():
        lms = lms_path.read_text(encoding="utf-8")

    package_symbols: set[str] = set()
    for module in sorted(package.glob("*.py")):
        package_symbols |= _module_level_names(module)

    header = (repo / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    c_symbols = frozenset(_C_SYMBOL.findall(header))

    return Authority(
        combine_raises_on_missing_native=bool(combine and _raises_invariant7(combine)),
        posture_weights=_composite_weights(posture),
        posture_thresholds=_named_floats(
            posture,
            (
                "DEFAULT_ELEVATED_THRESHOLD",
                "DEFAULT_HIGH_THRESHOLD",
                "DEFAULT_CRITICAL_THRESHOLD",
            ),
        ),
        ethical_vector_length=_dict_literal_length(equations, "ETHICAL_VECTOR"),
        native_memzero_has_barrier=("__asm__" in memzero_body and "memory" in memzero_body)
        or "_ReadWriteBarrier" in memzero_body,
        lms_verify_implemented="ama_lms_verify(" in lms,
        hss_verify_implemented="ama_hss_verify(" in lms,
        secure_wipe_delegates_to_memzero=bool(
            wipe
            and any(
                isinstance(call.func, ast.Name) and call.func.id == "secure_memzero"
                for call in ast.walk(wipe)
                if isinstance(call, ast.Call)
            )
        ),
        package_symbols=frozenset(package_symbols),
        c_symbols=c_symbols,
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

#: A line that *denies* a claim is the corrected wording and must keep passing
#: even though it quotes the phrase in order to deny it.
NEGATION_CUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(no|never|not|without|refus\w*|rais\w*|forbid\w*|absent)\b", re.IGNORECASE),
    re.compile(
        r"\b(an earlier|previously|used to|no longer|was documented|stale)\b", re.IGNORECASE
    ),
    re.compile(r"\bINVARIANT-7\b"),
)


def _is_negated(line: str) -> bool:
    return any(cue.search(line) for cue in NEGATION_CUES)


_FALLBACK_NEAR_HKDF = re.compile(
    r"(pure[- ]?python|python)\s+(sha3-?256\s+)?fallback|fallback[^.]{0,40}\bpython\b",
    re.IGNORECASE,
)
_HKDF_CONTEXT = re.compile(r"hkdf|combiner|hybrid|ama_hkdf", re.IGNORECASE)

_MULTIPASS = re.compile(
    r"multi[- ]?pass|multiple overwrite passes|three (?:overwrite )?passes|"
    r"0x00\s*/\s*0xFF\s*/\s*0x00|zeros?,?\s+then\s+ones,?\s+then\s+zeros?",
    re.IGNORECASE,
)
_MEMZERO_CONTEXT = re.compile(
    r"secure_memzero|secure_wipe|ama_secure_memzero|zeroi[sz]ation|zeroing", re.IGNORECASE
)

_WEIGHT_TRIPLE = re.compile(
    r"timing\s*\(?\s*(\d{1,3})\s*%\)?\s*[,;/]\s*pattern\s*\(?\s*(\d{1,3})\s*%\)?\s*"
    r"[,;/]\s*(?:and\s+)?resonance\s*\(?\s*(\d{1,3})\s*%\)?",
    re.IGNORECASE,
)
_WEIGHT_DECIMALS = re.compile(r"\b0\.\d\d(?:\s*/\s*0\.\d\d){2,3}\b")

_THRESHOLD_ROW = re.compile(
    # U+2013 EN DASH is written as an escape rather than as a literal: the
    # corrected threshold tables render their ranges with one, and a literal
    # en dash is indistinguishable from a hyphen when this file is read.
    "\\|\\s*(NOMINAL|ELEVATED|HIGH|CRITICAL)\\s*\\|\\s*([0-9.]+)"
    "\\s*[-\u2013]\\s*([0-9.]+)\\s*\\|",
    re.IGNORECASE,
)

_ETHICAL_LEN = re.compile(r"len\(\s*[\w.]*ethical_vector\s*\)\s*==\s*(\d+)")

_NO_LMS = re.compile(
    r"(does not|do not|doesn'?t|no)\s+implement(?:ation)?s?\s+(?:of\s+)?(HSS/?LMS|LMS/?HSS|LMS)",
    re.IGNORECASE,
)

#: Claims corrected in the 2026-09 pass. Each is pinned by its exact retired
#: wording so it cannot reappear in another document — the failure mode
#: INVARIANT-16's BIP32 case demonstrated six times over.
RETIRED_CLAIMS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bMASTER_OMNI_CODES\b"),
        "MASTER_OMNI_CODES does not exist. The exported name is MASTER_CODES "
        "(ama_cryptography/equations.py, re-exported by legacy_compat).",
    ),
    (
        re.compile(r"secure_mlock[^.\n]{0,60}(returns?\s+(True|a\s+bool|bool))", re.IGNORECASE),
        "secure_mlock() returns None and raises on failure. Branching on its "
        "return value takes the failure path on every successful lock.",
    ),
    (
        re.compile(r"GCC\s*7\b|Clang\s*6\b", re.IGNORECASE),
        "The build refuses GCC below 12 and Clang below 15 "
        "(CMakeLists.txt:89-107, message(FATAL_ERROR)).",
    ),
    (
        re.compile(r"ama_randombytes[^.\n]{0,80}\bexport(ed|s)?\b", re.IGNORECASE),
        "ama_randombytes is named in the `local:` list of cmake/ama_exports.map "
        "and has zero exported symbols. It cannot be linked out-of-tree.",
    ),
    (
        re.compile(r"buf\.data\s*(?::|\[)", re.IGNORECASE),
        "SecureBuffer.__enter__ yields the bytearray, so the name bound by "
        "`with SecureBuffer(...) as buf` has no `.data` attribute.",
    ),
    (
        re.compile(r"ML-DSA-65 signing \(4\.2\d*\s*ms|~4\.2\s*ms", re.IGNORECASE),
        "ML-DSA-65 signing is sub-millisecond. ARCHITECTURE.md's latency table "
        "is generated from benchmarks/benchmark-results.json by "
        "tools/update_docs.py; do not type the figure.",
    ),
)


def _rule_fallback(line: str, authority: Authority) -> Optional[str]:
    if not authority.combine_raises_on_missing_native:
        return None  # a fallback exists; the claim would be true
    if not (_FALLBACK_NEAR_HKDF.search(line) and _HKDF_CONTEXT.search(line)):
        return None
    return (
        "claims a Python HKDF fallback. HybridCombiner.combine() raises "
        "RuntimeError when ama_hkdf is unavailable (hybrid_combiner.py) — "
        "INVARIANT-7 forbids substituting a non-constant-time HKDF into "
        "secret-dependent key combination, and documenting the substitution "
        "as a feature is how an integrator comes to rely on it."
    )


def _rule_memzero_passes(line: str, authority: Authority) -> Optional[str]:
    if not authority.native_memzero_has_barrier:
        return None
    if not (_MULTIPASS.search(line) and _MEMZERO_CONTEXT.search(line)):
        return None
    if re.search(r"fallback|AMA_ALLOW_PYTHON_MEMZERO|opt-in", line, re.IGNORECASE):
        return None  # the opt-in Python fallback genuinely does loop
    return (
        "describes the native zeroing kernel as multi-pass. "
        "ama_secure_memzero (src/c/ama_consttime.c) writes zeros ONCE through "
        "volatile stores and then issues a compiler barrier; the barrier is "
        "what defeats dead-store elimination, not a repeat count. Only the "
        "opt-in AMA_ALLOW_PYTHON_MEMZERO fallback loops."
    )


def _rule_posture_weights(line: str, authority: Authority) -> Optional[str]:
    if not authority.posture_weights:
        return None
    actual_percent = tuple(round(w * 100) for w in authority.posture_weights)
    match = _WEIGHT_TRIPLE.search(line)
    if match:
        documented = tuple(int(g) for g in match.groups())
        if documented != actual_percent[: len(documented)] or len(authority.posture_weights) != len(
            documented
        ):
            return (
                f"documents {len(documented)} posture signals weighted "
                f"{'/'.join(str(d) + '%' for d in documented)}; the composite is "
                f"{len(authority.posture_weights)} signals weighted "
                f"{'/'.join(format(w, '.2f') for w in authority.posture_weights)} "
                "(adaptive_posture.py, the `score = ...` expression in evaluate())."
            )
        return None
    decimals = _WEIGHT_DECIMALS.search(line)
    if decimals and re.search(r"weight|posture|signal|scor", line, re.IGNORECASE):
        documented_decimals = tuple(float(v) for v in re.findall(r"0\.\d\d", decimals.group(0)))
        if documented_decimals != authority.posture_weights:
            return (
                f"documents posture weights {documented_decimals}; the composite "
                f"uses {authority.posture_weights} (adaptive_posture.py)."
            )
    return None


def _rule_posture_thresholds(line: str, authority: Authority) -> Optional[str]:
    if len(authority.posture_thresholds) != 3:
        return None
    elevated, high, critical = authority.posture_thresholds
    match = _THRESHOLD_ROW.search(line)
    if not match:
        return None
    level = match.group(1).upper()
    low, upper = float(match.group(2)), float(match.group(3))
    expected = {
        "NOMINAL": (0.0, elevated),
        "ELEVATED": (elevated, high),
        "HIGH": (high, critical),
        "CRITICAL": (critical, 1.0),
    }[level]
    if (low, upper) != expected:
        return (
            f"a {level} row spanning {low} to {upper}; the implemented boundaries "
            f"are {expected[0]} to {expected[1]} "
            "(DEFAULT_ELEVATED/HIGH/CRITICAL_THRESHOLD = "
            f"{elevated} / {high} / {critical}, adaptive_posture.py). Publishing a "
            "higher boundary than the code uses means the module escalates before "
            "the documented level, so an operator calibrating to the table "
            "under-reads their own monitor."
        )
    return None


def _rule_ethical_vector(line: str, authority: Authority) -> Optional[str]:
    if not authority.ethical_vector_length:
        return None
    match = _ETHICAL_LEN.search(line)
    if not match:
        return None
    documented = int(match.group(1))
    if documented != authority.ethical_vector_length:
        return (
            f"asserts len(ethical_vector) == {documented}; ETHICAL_VECTOR has "
            f"{authority.ethical_vector_length} keys (equations.py). The SUM of "
            "its weights is 12.0 — that is the 12 this assertion confused for a "
            "length."
        )
    return None


def _rule_lms(line: str, authority: Authority) -> Optional[str]:
    if not (authority.lms_verify_implemented and authority.hss_verify_implemented):
        return None
    if not _NO_LMS.search(line):
        return None
    if re.search(r"\bsign\w*\b|XMSS|SP 800-208|stateful", line, re.IGNORECASE):
        return None  # signing genuinely is not implemented; that claim is true
    return (
        "says AMA does not implement HSS/LMS. ama_lms_verify and ama_hss_verify "
        "are implemented in src/c/ama_lms.c and exported by the shared library; "
        "tests/test_rfc8554_vectors.py runs RFC 8554 Appendix F through them. "
        "Only SIGNING is withheld, and ama_lms_signing_available() reports that."
    )


def _rule_retired(line: str, authority: Authority) -> Optional[str]:
    for pattern, why in RETIRED_CLAIMS:
        if pattern.search(line):
            return f"reintroduces a corrected claim — {why}"
    return None


#: Most rules look for an ASSERTION, so a line that denies the claim is the
#: corrected wording and must keep passing.  Two rules invert that: the LMS
#: rule is looking for a denial ("AMA does not implement HSS/LMS"), and the
#: retired-claim registry pins wording that teaches a dead name whether or not
#: the sentence around it is a denial.  Applying the negation waiver to those
#: two would make them permanently vacuous — which is exactly what happened on
#: the first run of this gate, where the HSS/LMS claim it was written for
#: passed because "does not" tripped the waiver.
NEGATION_SENSITIVE_RULES: frozenset[str] = frozenset({"_rule_lms", "_rule_retired"})

RULES: tuple[Callable[[str, Authority], Optional[str]], ...] = (
    _rule_fallback,
    _rule_memzero_passes,
    _rule_posture_weights,
    _rule_posture_thresholds,
    _rule_ethical_vector,
    _rule_lms,
    _rule_retired,
)


# ---------------------------------------------------------------------------
# Symbol existence
# ---------------------------------------------------------------------------

#: ``ama_cryptography`` itself or one of its submodules — NOT
#: ``ama_cryptography_monitor``, which is a separate top-level module at the
#: repository root and a legitimate import.
_PY_IMPORT = re.compile(r"from\s+(ama_cryptography(?:\.[\w.]+)?)\s+import\s+\(?([^)\n]*)\)?")

#: Compiled Cython submodules have no ``.py`` on disk; they are declared in
#: ``src/cython/`` and built into the package.  Treating them as absent would
#: make the gate reject correct documentation on a source checkout.
_CYTHON_SUBMODULES: frozenset[str] = frozenset(
    {
        "math_engine",
        "sha3_binding",
        "hmac_binding",
        "hkdf_binding",
        "ed25519_binding",
        "dilithium_binding",
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


def _rule_symbols(line: str, authority: Authority, repo: Path) -> Optional[str]:
    # Markdown prose quotes imports inline with backticks, ellipses and
    # trailing commentary; only the code itself is a claim about the API.
    cleaned = re.sub(r"\s+#.*$", "", line).replace("`", " ")
    match = _PY_IMPORT.search(cleaned)
    if not match:
        return None
    module = match.group(1)
    leaf = module.split(".")[-1]
    if (
        leaf != "ama_cryptography"
        and leaf not in _CYTHON_SUBMODULES
        and not (repo / "ama_cryptography" / f"{leaf}.py").is_file()
    ):
        return f"imports from {module}, which is not a module of the package"
    for piece in match.group(2).split(","):
        name = piece.strip().split(" as ")[0].strip().strip("*")
        if not name or not _IDENTIFIER.match(name):
            continue  # an ellipsis, a fragment of prose, a wildcard
        if name not in authority.package_symbols:
            return (
                f"imports {name!r} from {module}; no module of "
                "ama_cryptography/ binds that name at module level"
            )
    return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def scanned_files(repo: Path = REPO) -> list[Path]:
    seen: list[Path] = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        relative = path.relative_to(repo)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if relative.as_posix() in EXEMPT_FILES or relative.as_posix() in SELF_REFERENTIAL:
            continue
        seen.append(path)
    return seen


def find_claims(
    authority: Authority, repo: Path = REPO, files: Optional[Iterable[Path]] = None
) -> list[Finding]:
    findings: list[Finding] = []
    for path in files if files is not None else scanned_files(repo):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        relative = path.relative_to(repo).as_posix()
        source_lines = text.splitlines()
        waived = False
        for number, raw in enumerate(source_lines, start=1):
            line = raw.strip()
            if not line:
                waived = False  # a blank line closes the paragraph, and the waiver with it
                continue
            # The marker must be the WHOLE line: prose that merely mentions it
            # (this invariant's own text does) must not silently waive the
            # paragraph it appears in.
            if line == WAIVER:
                waived = True
                continue
            if waived:
                continue
            negated = _is_negated(line)
            for rule in RULES:
                if negated and rule.__name__ not in NEGATION_SENSITIVE_RULES:
                    continue
                why = rule(line, authority)
                if why:
                    findings.append(Finding(relative, number, line[:160], why))
                    break
            else:
                if path.suffix.lower() not in PROSE_SUFFIXES:
                    continue
                why = _rule_symbols(line, authority, repo)
                if why:
                    findings.append(Finding(relative, number, line[:160], why))
    return findings


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--file", action="append", dest="files", default=None)
    args = parser.parse_args(argv)
    repo: Path = args.repo

    if not (repo / "ama_cryptography" / "hybrid_combiner.py").is_file():
        print(f"FATAL: {repo} does not look like the repository root.", file=sys.stderr)
        return 2

    try:
        authority = build_authority(repo)
    except (OSError, SyntaxError) as exc:
        print(f"FATAL: cannot derive the implementation's behaviour: {exc}", file=sys.stderr)
        return 2

    # Fail closed on a collapsed derivation: a gate that silently learns
    # nothing from the source reports green on everything.
    missing = [
        name
        for name, value in (
            ("posture weights", authority.posture_weights),
            ("posture thresholds", authority.posture_thresholds),
            (
                "all three posture thresholds",
                authority.posture_thresholds if len(authority.posture_thresholds) == 3 else (),
            ),
            ("ETHICAL_VECTOR length", authority.ethical_vector_length),
            ("package symbols", authority.package_symbols),
            ("C header symbols", authority.c_symbols),
        )
        if not value
    ]
    if missing:
        print(
            "FATAL: could not derive " + ", ".join(missing) + " from the source tree. "
            "The gate refuses to run with a partial authority.",
            file=sys.stderr,
        )
        return 2

    stale_exemptions = [name for name in SELF_REFERENTIAL if not (repo / name).is_file()]
    if stale_exemptions:
        print(
            "FATAL: these files are exempt from this gate but no longer exist: "
            + ", ".join(stale_exemptions)
            + ". Remove the entry rather than leaving a widened exemption behind.",
            file=sys.stderr,
        )
        return 2

    files = [repo / name for name in args.files] if args.files else None
    findings = find_claims(authority, repo, files)

    if findings:
        print(
            f"CRYPTOGRAPHIC CONSTRUCTION DOC CHECK FAILED — {len(findings)} claim(s) "
            "contradict the implementation:",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  {finding.path}:{finding.line}", file=sys.stderr)
            print(f"      {finding.text}", file=sys.stderr)
            print(f"      -> {finding.why}", file=sys.stderr)
        print(
            "\nThe implementation and the invariants are authoritative. Correct the "
            "document — do not weaken the code, add a fallback, or relax an "
            "invariant to make a sentence true.",
            file=sys.stderr,
        )
        return 1

    scanned = files if files is not None else scanned_files(repo)
    print(
        f"OK    {len(scanned)} document(s); constructions agree with the implementation "
        f"(posture {authority.posture_weights} / thresholds {authority.posture_thresholds}, "
        f"ETHICAL_VECTOR len {authority.ethical_vector_length}, "
        f"combiner fails closed: {authority.combine_raises_on_missing_native}, "
        f"LMS/HSS verify: {authority.lms_verify_implemented and authority.hss_verify_implemented})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
