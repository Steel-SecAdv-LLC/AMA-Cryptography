#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
INVARIANT-37 — a verification API must not claim a check it does not perform.

Why this exists
---------------
AMA implements the RFC 3161 wire format and the §2.4.2 message-imprint binding.
It does not verify the TSA's CMS ``SignerInfo`` signature and does not validate
the TSA's certificate chain. Neither is implemented anywhere in the library.

By the time anyone checked, the repository asserted the opposite in more than
fifty places. ``ARCHITECTURE.md``'s verification flow listed "Verify TSA
signature and time bounds" as a step. ``THREAT_MODEL.md`` recorded "RFC 3161
TSA with independent verification" as **IMPLEMENTED** — the row an auditor
reads to conclude the threat is mitigated. ``AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md``
carried a "Mathematical Proof" whose security statement was exactly inverted:
"Requires TSA private key compromise to forge", when forging a token AMA
accepts requires no key at all. A comparison table scored AMA ✓ and OpenSSL ✗
on RFC 3161, on the one axis where OpenSSL does the work and AMA does not. The
module's own docstring opened with "Third-party attestation: Independent
verification by TSA".

None of that was written dishonestly. It was written by people who knew what a
timestamp is *for*, describing a feature named after the thing it does not do.
That is the failure mode this invariant addresses: not lying, but the absence
of anything that would notice.

Why the checker is driven by a capability table
-----------------------------------------------
The obvious implementation is a denylist of forbidden phrases. It would be
wrong in a specific and expensive way: it freezes today's limitation into CI.
The day somebody implements CMS ``SignerInfo`` verification, a phrase denylist
starts rejecting claims that have become *true*, and the fix is to remember to
edit a gate — which is the same class of memory this invariant exists because
nobody had.

So the forbidden claims are derived, not listed.
``ama_cryptography.rfc3161_timestamp.RFC3161_CAPABILITIES`` states which checks
the library performs. This checker reads that table and forbids a claim
**because its capability is ``False``**. Implementing a check and flipping its
entry to ``True`` permits the corresponding claims in the same commit, with no
gate edit and no stale prohibition left behind. The table is also what
:class:`~ama_cryptography.rfc3161_timestamp.TokenVerification` reports and what
``tests/test_rfc3161_api_honesty.py`` drives behaviourally, so the code, the
runtime record, the tests and the documentation cannot disagree in any
direction.

The table is read from the source with ``ast`` rather than by importing the
module, so the gate runs in a lint job with nothing built and no native backend
present. ``tests/test_verification_claim_honesty_gate.py`` asserts the parsed
table equals the imported one, so the two readings cannot drift.

What is checked
---------------
1. **No claim of an unperformed check.** For every capability that is ``False``,
   the claim patterns bound to it must not appear in shipped code or
   documentation *unless negated on the same line*. Same line, deliberately: a
   disclaimer three paragraphs from the claim is how this repository came to
   assert attestation in fifty places while the module docstring disclaimed it.
2. **The misnamed result key is not taught.** No document or docstring may show
   ``results["rfc3161"]``. That key is retained in code for compatibility and
   now warns when read, but a copy-pasteable example teaching it defeats the
   rename that made it honest.
3. **A refusing argument is documented as refusing.** Any parameter named
   ``certificate_file`` or ``tsa_cert_path`` — arguments that request checks AMA
   does not implement, and therefore raise — must be described as refused in its
   function's docstring. The behavioural half (that it really does raise) is
   asserted by the test suite, which can call the functions.
4. **No instruction to install a removed third-party cryptographic library.**
   ``rfc3161ng`` was removed under INVARIANT-1. Documentation telling an
   operator to install it re-creates the dependency the invariant forbids.
5. **The table cannot outgrow its enforcement.** Every ``False`` capability must
   have claim patterns bound to it, and every pattern must name a real
   capability. Adding a capability without teaching the gate what claims it
   governs is a failure, not a silent no-op.

What is deliberately *not* checked
----------------------------------
* Claims about anything other than RFC 3161. Ed25519, ML-DSA, ML-KEM, HMAC,
  SPHINCS+, Argon2id, HKDF and the C primitives are implemented as described.
* This file, and ``tests/test_verification_claim_honesty_gate.py``. Both must
  state the forbidden claims — one to forbid them, the other to require that
  they are rejected. That reason cannot be extended to a third file, and check
  5 fails if the exemption list ever grows.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence

REPO = Path(__file__).resolve().parent.parent

#: The module that declares the capability table.
CAPABILITY_SOURCE = Path("ama_cryptography") / "rfc3161_timestamp.py"

#: The name of the table inside it.
CAPABILITY_SYMBOL = "RFC3161_CAPABILITIES"

#: Trees scanned for claims. ``tests/`` is included: a test docstring is read by
#: the next person to touch the code, and two of the stale ``rfc3161ng`` claims
#: this invariant was written for lived in one.
SCAN_ROOTS: tuple[str, ...] = (
    "ama_cryptography",
    "tools",
    "tests",
    "examples",
    "docs",
    "wiki",
    "benchmarks",
    "fuzz",
)

#: Markdown at the repository root is scanned too — it is the most-read
#: documentation in the project and held the largest number of false claims.
SCAN_ROOT_GLOBS: tuple[str, ...] = ("*.md",)

SCAN_SUFFIXES: frozenset[str] = frozenset({".py", ".md", ".rst", ".txt"})

#: Directories never scanned: vendored corpora, build output, caches.
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "kat",
        "nist_vectors",
        "node_modules",
        "wycheproof_vectors",
    }
)

#: The only two files exempt from the claim scan, each for a reason that cannot
#: apply to a third: this checker states the forbidden claims in order to forbid
#: them, and its test states them in order to require rejection. Check 5 asserts
#: the list stays exactly this long, because every further exemption is a place
#: the invariant silently stops applying.
CLAIM_SCAN_EXEMPT: frozenset[str] = frozenset(
    {
        "tools/check_verification_claim_honesty.py",
        "tests/test_verification_claim_honesty_gate.py",
    }
)

#: Cues that a line is talking about RFC 3161 at all.
#:
#: Without this, generic assurance vocabulary is caught wherever it appears:
#: "requires independent verification" about side-channel review of the C code,
#: or "# Round trip and independent verification" in an ECDSA test, are true
#: statements about other things. A pattern marked ``requires_context`` is only
#: a violation on a line that is about timestamping.
CONTEXT_CUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"rfc\s*-?\s*3161", re.I),
    re.compile(r"\bTSA\b"),
    re.compile(r"\btime\s*-?\s*stamp", re.I),
    re.compile(r"\bTST\b|\bTSTInfo\b"),
    re.compile(r"\bgenTime\b", re.I),
)

# ---------------------------------------------------------------------------
# Claim patterns, bound to the capability that would make them true
# ---------------------------------------------------------------------------
# Each entry is (compiled pattern, human description, requires_context). A
# pattern is enforced only while its capability is False in
# RFC3161_CAPABILITIES. ``requires_context`` marks generic assurance vocabulary
# that is only a violation on a line already talking about timestamping; a
# pattern that names the TSA or the timestamp itself is self-scoping and needs
# no such gate.
_P = re.compile

CLAIM_PATTERNS: Mapping[str, tuple[tuple[re.Pattern[str], str, bool], ...]] = {
    "tsa_signature": (
        (
            _P(r"verif\w*\s+(?:the\s+)?(?:TSA(?:'s|\u2019s)?|timestamp)\s+signature", re.I),
            "claims the TSA's signature is verified",
            False,
        ),
        (
            _P(r"\bthird[- ]party\s+(?:attestation|verification)", re.I),
            "claims third-party attestation",
            True,
        ),
        (
            _P(r"\bindependent\s+verification\b", re.I),
            "claims independent verification by the TSA",
            True,
        ),
        (
            # The optional tail must be able to swallow a plural or a gerund
            # *before* the word boundary. An earlier form ended
            # ``(?:stamp|-stamp|stamping)?\b``, which failed on "trusted
            # timestamps": the group matched "stamp", the \b then demanded a
            # boundary before the "s", and every backtrack failed the same way.
            # The gate silently missed the most common phrasing of the most
            # common false claim in the tree, and read as passing. Its own
            # negative controls are what found that.
            _P(r"\btrusted\s+time(?:\s*-?\s*stamp\w*)?\b", re.I),
            "calls the timestamp or the time trusted",
            False,
        ),
        (
            _P(r"\bverified\s+by\s+(?:the\s+)?TSA\b", re.I),
            "claims the TSA verified something",
            False,
        ),
        (
            _P(r"requires?\s+TSA\s+private\s+key\s+compromise", re.I),
            "claims forgery requires a TSA key compromise (it requires no key)",
            False,
        ),
    ),
    "tsa_certificate_chain": (
        (
            _P(r"(?:validat|verif)\w*\s+(?:the\s+)?(?:TSA\s+)?certificate\s+chain", re.I),
            "claims certificate-chain validation",
            True,
        ),
        (
            _P(r"\bcertificate\s+chain\s+validation\b", re.I),
            "claims certificate-chain validation",
            True,
        ),
        (
            _P(r"\bchain\s+of\s+trust\b.{0,40}\bTSA\b", re.I),
            "claims a TSA chain of trust",
            False,
        ),
    ),
    "gen_time": (
        (_P(r"\bproof[- ]of[- ]existence\b", re.I), "claims proof of existence", True),
        (_P(r"\btemporal\s+proof\b", re.I), "claims temporal proof", True),
        (
            _P(r"\bprov(?:es|ing|e)\s+(?:when|that)\b.{0,60}\bexist", re.I),
            "claims to prove when data existed",
            True,
        ),
        (
            _P(r"\bnon[- ]repudiation\s+of\s+time\b", re.I),
            "claims non-repudiation of time",
            True,
        ),
        (
            _P(r"\btemporal\s+integrity\b", re.I),
            "claims temporal integrity",
            True,
        ),
        (
            _P(r"\bproof\s+of\s+existence\s+time\b", re.I),
            "claims proof of existence time",
            True,
        ),
    ),
}

#: Cues that a claim on the same line is being denied rather than made. A claim
#: pattern that matches a line carrying one of these is not a violation.
NEGATION_CUES: tuple[re.Pattern[str], ...] = (
    _P(r"\bnot\b", re.I),
    _P(r"\bno\b", re.I),
    _P(r"\bnone\b", re.I),
    _P(r"\bnothing\b", re.I),
    _P(r"\bnever\b", re.I),
    _P(r"\bneither\b", re.I),
    _P(r"\bnor\b", re.I),
    _P(r"\bwithout\b", re.I),
    _P(r"\bcannot\b|\bcan't\b|\bdoes ?n[o']t\b|\bisn[o']?t\b", re.I),
    _P(r"\brefus\w+", re.I),
    _P(r"\bexclud\w+", re.I),
    _P(r"\bunauthenticated\b", re.I),
    _P(r"\bunverified\b", re.I),
    _P(r"\bdeprecat\w+", re.I),
    _P(r"\bpartial\b", re.I),
    _P(r"\bwould\s+(?:be|have|require)\b", re.I),
    _P(r"\bused\s+to\b", re.I),
    _P(r"\bstopped\b", re.I),
    _P(r"\bmisread\w*", re.I),
    _P(r"\bfals\w+", re.I),
    _P(r"\binverted\b", re.I),
    # Cues that the line is *citing* a claim rather than making one. Quoting a
    # retired claim in order to retire it is a legitimate documentation act —
    # INVARIANT-37's own text, this checker and the CHANGELOG all have to do it
    # — and the same-line rule then requires the citation to say so on the line
    # where the quote appears. That is a stricter demand than a suppression
    # comment and a better one: the reader gets the disclaimer at the same
    # moment they get the quote, which is exactly the property whose absence
    # let fifty false claims stand.
    _P(r"\bretired\b", re.I),
    _P(r"\berrat(?:um|a)\b", re.I),
    _P(r"\bopposite\b", re.I),
    _P(r"\bwrongly\b", re.I),
    _P(r"\bincorrect\w*", re.I),
    _P(r"\bclaimed\b", re.I),
)

#: The retained-but-misnamed result key, in the form a copy-paste teaches.
LEGACY_RESULT_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    _P(r"""results\s*\[\s*['"]rfc3161['"]\s*\]"""),
    _P(r"""\bresults\.get\(\s*['"]rfc3161['"]"""),
)

#: The third-party client removed under INVARIANT-1.
REMOVED_DEPENDENCY_PATTERNS: tuple[re.Pattern[str], ...] = (
    _P(r"pip\s+install\s+rfc3161ng", re.I),
    _P(r"requires?\s+(?:the\s+)?(?:optional\s+)?[`'\"]?rfc3161ng", re.I),
)

#: Parameters that request checks AMA does not implement, and therefore raise.
REFUSING_PARAMETERS: frozenset[str] = frozenset({"certificate_file", "tsa_cert_path"})

#: A docstring documenting one of those must contain one of these.
REFUSAL_MARKERS: tuple[re.Pattern[str], ...] = (
    _P(r"\brefus\w+", re.I),
    _P(r"\brais\w+", re.I),
    _P(r"\bnot\s+honoured\b|\bnot\s+honored\b", re.I),
)


def _rel(path: Path, repo: Path = REPO) -> str:
    """Repo-relative POSIX path.

    ``repo`` is a parameter rather than the module constant so the whole
    checker can be pointed at a synthetic tree. Its own tests need that: a gate
    that can only be run against a repository which passes it has no
    demonstrated rejection direction, and INVARIANT-2 calls that not-a-gate.
    """
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------------------
# The capability table, read from source without importing it
# ---------------------------------------------------------------------------
def load_capabilities(source: Path | None = None) -> dict[str, bool]:
    """Parse ``RFC3161_CAPABILITIES`` out of the module source.

    ``ast`` rather than ``import`` so the gate runs in a lint job with nothing
    built. ``tests/test_verification_claim_honesty_gate.py`` asserts this agrees
    with the imported object, so the two readings cannot drift apart.
    """
    path = source if source is not None else REPO / CAPABILITY_SOURCE
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        targets: Sequence[ast.expr]
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        else:
            continue
        if value is None:
            continue
        if not any(isinstance(t, ast.Name) and t.id == CAPABILITY_SYMBOL for t in targets):
            continue
        # MappingProxyType({...}) or a bare {...}
        literal = value
        if isinstance(value, ast.Call) and value.args:
            literal = value.args[0]
        table = ast.literal_eval(literal)
        if not isinstance(table, dict):
            raise ValueError(f"{CAPABILITY_SYMBOL} is not a dict literal")
        out: dict[str, bool] = {}
        for key, val in table.items():
            if not isinstance(key, str) or not isinstance(val, bool):
                raise ValueError(f"{CAPABILITY_SYMBOL} entries must be str -> bool")
            out[key] = val
        return out
    raise ValueError(f"{CAPABILITY_SYMBOL} not found in {path}")


def _scanned_files(repo: Path) -> list[Path]:
    seen: list[Path] = []
    for glob in SCAN_ROOT_GLOBS:
        seen.extend(sorted(repo.glob(glob)))
    for root in SCAN_ROOTS:
        base = repo / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
                continue
            if any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
                continue
            seen.append(path)
    return [p for p in seen if _rel(p, repo) not in CLAIM_SCAN_EXEMPT]


def _is_negated(line: str) -> bool:
    return any(cue.search(line) for cue in NEGATION_CUES)


def _has_rfc3161_context(line: str) -> bool:
    return any(cue.search(line) for cue in CONTEXT_CUES)


def _iter_lines(paths: Iterable[Path]) -> Iterable[tuple[Path, int, str]]:
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            yield path, number, line


# ---------------------------------------------------------------------------
# Check 1 — no claim of a check the capability table says is not performed
# ---------------------------------------------------------------------------
def scan_for_unperformed_claims(
    repo: Path = REPO, capabilities: Mapping[str, bool] | None = None
) -> list[str]:
    caps = dict(capabilities) if capabilities is not None else load_capabilities()
    active: list[tuple[str, re.Pattern[str], str, bool]] = [
        (capability, pattern, description, needs_context)
        for capability, patterns in CLAIM_PATTERNS.items()
        if not caps.get(capability, False)
        for pattern, description, needs_context in patterns
    ]
    if not active:
        return []
    problems: list[str] = []
    for path, number, line in _iter_lines(_scanned_files(repo)):
        if _is_negated(line):
            continue
        in_context = _has_rfc3161_context(line)
        for capability, pattern, description, needs_context in active:
            if needs_context and not in_context:
                continue
            match = pattern.search(line)
            if match is None:
                continue
            problems.append(
                f"{_rel(path, repo)}:{number} {description} — {match.group(0)!r} — while "
                f"RFC3161_CAPABILITIES[{capability!r}] is False. Either negate the "
                "claim on this line, or implement the check and flip the capability."
            )
    return problems


# ---------------------------------------------------------------------------
# Check 2 — the misnamed result key is not taught
# ---------------------------------------------------------------------------
def scan_for_legacy_result_key(repo: Path = REPO) -> list[str]:
    problems: list[str] = []
    for path, number, line in _iter_lines(_scanned_files(repo)):
        # A line that names the key *while calling it deprecated* is documenting
        # the retirement, not teaching the key. That is the same same-line rule
        # check 1 uses, and for the same reason: the qualification has to be
        # where the reader's eye already is.
        if _is_negated(line):
            continue
        for pattern in LEGACY_RESULT_KEY_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            problems.append(
                f"{_rel(path, repo)}:{number} teaches the deprecated result key "
                f"{match.group(0)!r}. Its value is the RFC 3161 §2.4.2 message-imprint "
                'binding, not TSA attestation; use results["rfc3161_binding"]. The key '
                "is retained in code for compatibility and warns when read, which a "
                "copy-pasteable example here would defeat."
            )
    return problems


# ---------------------------------------------------------------------------
# Check 3 — a refusing argument is documented as refusing
# ---------------------------------------------------------------------------
def check_refusing_parameters(repo: Path = REPO) -> list[str]:
    problems: list[str] = []
    package = repo / "ama_cryptography"
    if not package.is_dir():
        return problems
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
            offending = names & REFUSING_PARAMETERS
            if not offending:
                continue
            doc = ast.get_docstring(node) or ""
            for name in sorted(offending):
                if name not in doc:
                    problems.append(
                        f"{_rel(path, repo)}:{node.lineno} {node.name}() takes {name!r} but "
                        "its docstring never mentions it. That argument requests a "
                        "check AMA does not implement and must be documented as "
                        "refused."
                    )
                    continue
                if not any(marker.search(doc) for marker in REFUSAL_MARKERS):
                    problems.append(
                        f"{_rel(path, repo)}:{node.lineno} {node.name}() documents {name!r} "
                        "without saying it is refused. It requests CMS SignerInfo or "
                        "X.509 path validation, which AMA does not implement, so the "
                        "call raises — the docstring must say so."
                    )
    return problems


# ---------------------------------------------------------------------------
# Check 4 — no instruction to install the removed third-party client
# ---------------------------------------------------------------------------
def scan_for_removed_dependency(repo: Path = REPO) -> list[str]:
    problems: list[str] = []
    for path, number, line in _iter_lines(_scanned_files(repo)):
        if _is_negated(line):
            continue
        for pattern in REMOVED_DEPENDENCY_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            problems.append(
                f"{_rel(path, repo)}:{number} instructs installing 'rfc3161ng' "
                f"({match.group(0)!r}). It was removed under INVARIANT-1 — RFC 3161 is "
                "implemented in-tree on AMA's own DER codec and RFC3161_AVAILABLE is "
                "unconditionally True, so this re-creates the third-party dependency "
                "the invariant forbids."
            )
    return problems


# ---------------------------------------------------------------------------
# Check 5 — the table cannot outgrow its enforcement
# ---------------------------------------------------------------------------
def check_pattern_coverage(capabilities: Mapping[str, bool] | None = None) -> list[str]:
    caps = dict(capabilities) if capabilities is not None else load_capabilities()
    problems: list[str] = []
    for capability, performed in sorted(caps.items()):
        if performed:
            continue
        if not CLAIM_PATTERNS.get(capability):
            problems.append(
                f"RFC3161_CAPABILITIES[{capability!r}] is False but CLAIM_PATTERNS "
                "binds no claim to it, so nothing stops the documentation asserting "
                "it. Add the patterns that would make this capability true."
            )
    for capability in sorted(CLAIM_PATTERNS):
        if capability not in caps:
            problems.append(
                f"CLAIM_PATTERNS names {capability!r}, which is not a key of "
                "RFC3161_CAPABILITIES. A pattern bound to nothing is never enforced."
            )
    if len(CLAIM_SCAN_EXEMPT) != 2:
        problems.append(
            "CLAIM_SCAN_EXEMPT must hold exactly two paths — this checker, which "
            "states the forbidden claims in order to forbid them, and its test, which "
            f"states them in order to require rejection. It holds "
            f"{len(CLAIM_SCAN_EXEMPT)}: {sorted(CLAIM_SCAN_EXEMPT)}. Every further "
            "exemption is a place this invariant silently stops applying."
        )
    # A pattern may only be marked self-scoping if its own source spells out
    # what it is about. Checked with a plain substring test rather than by
    # running CONTEXT_CUES over the regex source: a cue like ``\bTSA\b`` does
    # not match the text ``\bTSA\b``, because the preceding backslash-b makes
    # the 'b' a word character and kills the boundary. Introspecting a regex
    # with another regex is how that kind of near-miss gets shipped.
    self_scoping_tokens = ("tsa", "time", "3161", "tst", "gentime")
    for capability, patterns in CLAIM_PATTERNS.items():
        for pattern, _description, needs_context in patterns:
            if needs_context:
                continue
            if any(token in pattern.pattern.lower() for token in self_scoping_tokens):
                continue
            problems.append(
                f"CLAIM_PATTERNS[{capability!r}] pattern {pattern.pattern!r} is marked "
                "self-scoping but does not itself name RFC 3161, a TSA or a timestamp, "
                "so it would fire on unrelated prose. Mark it requires_context=True."
            )
    return problems


def main() -> int:
    try:
        capabilities = load_capabilities()
    except (OSError, ValueError) as exc:
        print(f"FAIL: cannot read {CAPABILITY_SYMBOL}: {exc}", file=sys.stderr)
        return 1

    performed = sorted(k for k, v in capabilities.items() if v)
    withheld = sorted(k for k, v in capabilities.items() if not v)
    print(f"RFC3161_CAPABILITIES performed: {', '.join(performed) or '(none)'}")
    print(f"RFC3161_CAPABILITIES withheld : {', '.join(withheld) or '(none)'}")

    sections = (
        ("claims of unperformed checks", scan_for_unperformed_claims(REPO, capabilities)),
        ("deprecated result key in documentation", scan_for_legacy_result_key()),
        ("refusing arguments documented as refusing", check_refusing_parameters()),
        ("removed third-party dependency", scan_for_removed_dependency()),
        ("capability/pattern coverage", check_pattern_coverage(capabilities)),
    )
    failures = [(title, problems) for title, problems in sections if problems]
    for title, problems in sections:
        if not problems:
            print(f"OK    {title}")
    if failures:
        print(
            "\nFAIL: INVARIANT-37 — something claims a verification check AMA does " "not perform.",
            file=sys.stderr,
        )
        for title, problems in failures:
            print(f"  {title}:", file=sys.stderr)
            for problem in problems:
                print(f"    - {problem}", file=sys.stderr)
        return 1
    print(
        "\nINVARIANT-37 holds: every documented verification claim is one "
        "RFC3161_CAPABILITIES says AMA performs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
