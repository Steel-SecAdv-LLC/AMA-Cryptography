#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — every constant-time claim in the public headers is measured.

What it checks
--------------
A public function whose header documentation says it runs in constant time is
making a security claim, and INVARIANT-16 forbids a claim the project cannot
back.  This gate reads every documentation comment in ``include/*.h`` and
holds each such claim to a measurement:

1. Every claim is attributable to a public (``AMA_API``) function -- the one
   the comment documents, or one the comment names -- and every such function
   is in :data:`REGISTRY`.  A new claim without a registry entry fails.
2. Every registry entry still has a claim behind it.  A claim that is removed
   moves to :data:`WITHDRAWN`; it is not left as a stale entry.
3. Every withdrawn function's documentation makes no claim and says, in a
   sentence, that the claim was withdrawn.  Re-adding the claim fails.
4. Every function in the registry has at least one dudect lane in
   ``tests/c/test_dudect.c`` -- the wall-clock harness, under its calibrated
   threshold (``DUDECT_T_THRESHOLD``, the majority and direction rules and
   the effect-size floor) -- and the lane's code calls the function (or a
   forwarder it names in ``via``).  A lane registered info-only cannot fail a
   build, so an entry whose every lane is info-only must also name a blocking
   deterministic target.
5. Every deterministic target it names exists in
   ``tools/check_ghash_constant_time.py`` (``_DRIVERS`` for an instruction
   count, ``_TAINT_DRIVERS`` for secret-taint) and its driver calls the
   function or its forwarder.
6. Every ``via`` forwarder is a public function in ``src/c`` whose body is one
   ``return`` of the claimed function, so measuring it measures the claim.

What counts as a claim
----------------------
A sentence containing "constant time" or "constant-time" in which the phrase
is not negated (a "not", "non-", "no", "never", "nor" or "without" within the
few words before it, or "withdrawn" anywhere in the sentence) and does not
name an instrument ("constant-time gate", "... harness", "... path", and so
on, :data:`_META_AFTER`).  Section banners -- comments drawn with a row of
``=`` -- are headings over many declarations and claim nothing on their own.
The rule is mechanical on purpose: a reworded claim either still reads as one
and needs a measurement, or reads as a negation, which states the opposite.

What it does not establish
--------------------------
That the measurements pass.  The lanes and targets run in
``.github/workflows/dudect.yml``, fail-closed; this gate proves that each
claim has them, not what they read.  Nor does it read prose outside the
public headers: CONSTANT_TIME_VERIFICATION.md records the methodology and
each lane's history, and its claims are about the functions registered here.

Exit status: 0 consistent, 1 a claim without a measurement (or a stale,
dangling or unpinned entry), 2 a file it needs is missing.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Evidence:
    """The measurements that stand behind one constant-time claim."""

    #: Lane names as registered in tests/c/test_dudect.c.
    lanes: tuple[str, ...]
    #: Instruction-count targets of tools/check_ghash_constant_time.py.
    counts: tuple[str, ...] = ()
    #: Secret-taint targets of the same tool.
    taints: tuple[str, ...] = ()
    #: Public one-statement forwarders a lane or driver may call instead.
    via: tuple[str, ...] = ()


#: Every public function whose header claims constant time, and what
#: measures it.  Lane names are the strings tests/c/test_dudect.c registers;
#: target names are tools/check_ghash_constant_time.py's.
REGISTRY: dict[str, Evidence] = {
    "ama_consttime_memcmp": Evidence(("ama_consttime_memcmp",), ("consttime",), ("consttime",)),
    "ama_consttime_swap": Evidence(("ama_consttime_swap",), ("consttime-swap",)),
    "ama_consttime_lookup": Evidence(("ama_consttime_lookup",), ("consttime-lookup",)),
    "ama_consttime_copy": Evidence(("ama_consttime_copy",), ("consttime-copy",)),
    "ama_base64_encode": Evidence(("ama_base64_encode",), ("base64",), ("base64",)),
    "ama_base64_decode": Evidence(("ama_base64_decode",), ("base64",), ("base64",)),
    "ama_hmac_sha3_256": Evidence(("HMAC-SHA3-256 verify",), ("hkdf",), ("hkdf",)),
    "ama_agent_binding_check": Evidence(
        ("Agent binding check",), ("agent-binding",), ("agent-binding",)
    ),
    "ama_secp256k1_point_mul": Evidence(
        ("secp256k1 scalar multiplication",),
        ("secp256k1-scalarmult",),
        ("secp256k1-scalarmult",),
    ),
    "ama_secp256k1_pubkey_from_privkey": Evidence(
        ("ama_secp256k1_pubkey_from_privkey",), ("ecdsa",), ("api-surface",)
    ),
    "ama_secp256k1_seckey_verify": Evidence(
        ("ama_secp256k1_seckey_verify",), ("secp256k1-seckey",), ("secp256k1-seckey",)
    ),
    "ama_secp256k1_seckey_tweak_add": Evidence(
        ("ama_secp256k1_seckey_tweak_add",), ("secp256k1-seckey",), ("secp256k1-seckey",)
    ),
    "ama_secp256k1_ecdsa_sign": Evidence(
        ("secp256k1 ECDSA sign (RFC 6979)",), (), ("api-surface",)
    ),
    "ama_x25519_key_exchange": Evidence(("X25519 scalarmult",), ("x25519",), ("x25519",)),
    "ama_argon2id_legacy_verify": Evidence(
        ("Argon2id legacy verify",), ("argon2id-verify",), ("argon2id-verify",)
    ),
    "ama_ml_kem_decapsulate": Evidence(
        ("Kyber-1024 decaps",),
        ("kyber-decaps",),
        ("kyber-decaps", "api-surface"),
        via=("ama_kyber_decapsulate",),
    ),
    "ama_aes_sbox_consttime": Evidence(("ama_aes_sbox_consttime",), (), ("api-surface",)),
    "ama_aes256_key_expansion_consttime": Evidence(
        ("ama_aes256_key_expansion_consttime",), (), ("api-surface",)
    ),
    "ama_aes256_encrypt_block_consttime": Evidence(
        ("ama_aes256_encrypt_block_consttime",), (), ("api-surface",)
    ),
}

#: Functions whose constant-time claim was withdrawn, and when.  Each was
#: headed "(constant-time)" through 5.0.0 and the heading did not describe
#: the code: ML-DSA-65 signing is INVARIANT-12's rejection-loop carve-out,
#: ML-DSA and ML-KEM key generation rejection-sample seed-derived output, and
#: verification has no secret input to be constant-time with respect to.
WITHDRAWN: dict[str, str] = {
    "ama_keypair_generate": "2026-11-22",
    "ama_sign": "2026-11-22",
    "ama_verify": "2026-11-22",
}

_PHRASE = re.compile(r"constant[- ]time", re.IGNORECASE)
_NEG_BEFORE = re.compile(
    r"(?:\b(?:not|non|no|never|nor|without)\b[^.;:]{0,40}|\bnon-)$", re.IGNORECASE
)
_WITHDRAWN = re.compile(r"\bwithdrawn\b", re.IGNORECASE)
_META_AFTER = re.compile(
    r"^[- ]?(?:gates?|harness(?:es)?|paths?|testing|verification|lanes?|targets?|"
    r"instruments?|obligation)\b",
    re.IGNORECASE,
)
_BANNER = re.compile(r"={10,}")
_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_DECL_AFTER = re.compile(r"\s*AMA_API\s+[^;{]*?\b(\w+)\s*\(", re.DOTALL)
_DECL_ANY = re.compile(r"\bAMA_API\s+[^;{]*?\b(ama_\w+)\s*\(", re.DOTALL)
_NAMED = re.compile(r"\b(ama_[a-z0-9_]+)\(")
_LANE = re.compile(
    r'DUDECT_REGISTER_LANE\(\s*results\s*,\s*idx\s*,\s*"([^"]+)"\s*,\s*(\w+)\s*\(\s*iterations\s*\)'
    r"\s*,\s*([01])\s*\)"
)
_CALL = r"\b{}\s*\("


@dataclass(frozen=True)
class Claim:
    """One sentence that claims constant time, and where it is."""

    function: Optional[str]
    path: str
    line: int
    sentence: str


def _clean(comment: str) -> str:
    body = comment[2:-2]
    return "\n".join(re.sub(r"^\s*\*+ ?", "", ln) for ln in body.splitlines())


def _sentences(text: str) -> list[str]:
    flat = re.sub(r"\s+", " ", text).strip()
    return [s for s in re.split(r"(?<=[.!?])\s+(?=[A-Z*`(@])", flat) if s]


def sentence_claims(sentence: str) -> bool:
    """True when ``sentence`` claims constant time (see the module docstring)."""
    if _WITHDRAWN.search(sentence):
        return False
    for match in _PHRASE.finditer(sentence):
        if _META_AFTER.match(sentence[match.end() :]):
            continue
        if _NEG_BEFORE.search(sentence[: match.start()]):
            continue
        return True
    return False


def public_functions(headers: Sequence[Path]) -> set[str]:
    """Every function declared ``AMA_API`` in ``headers``."""
    names: set[str] = set()
    for path in headers:
        text = _COMMENT.sub(" ", path.read_text(encoding="utf-8"))
        names.update(_DECL_ANY.findall(text))
    return names


def scan_headers(headers: Sequence[Path], root: Path) -> list[Claim]:
    """Every claiming sentence in the documentation comments of ``headers``.

    A claim in the comment immediately before an ``AMA_API`` declaration is
    that function's.  A claim elsewhere belongs to every public function the
    comment names; if it names none it is returned with ``function=None``,
    which the gate reports as unattributable.
    """
    public = public_functions(headers)
    claims: list[Claim] = []
    for path in headers:
        text = path.read_text(encoding="utf-8")
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        for match in _COMMENT.finditer(text):
            comment = match.group(0)
            if _BANNER.search(comment) or not _PHRASE.search(comment):
                continue
            body = _clean(comment)
            claiming = [s for s in _sentences(body) if sentence_claims(s)]
            if not claiming:
                continue
            line = text.count("\n", 0, match.start()) + 1
            attached = _DECL_AFTER.match(text, match.end())
            if attached:
                owners: list[Optional[str]] = [attached.group(1)]
            else:
                named = sorted(set(_NAMED.findall(body)) & public)
                owners = list(named) if named else [None]
            for owner in owners:
                for sentence in claiming:
                    claims.append(Claim(owner, rel, line, sentence))
    return claims


def documentation_of(headers: Sequence[Path], function: str) -> Optional[str]:
    """The documentation comment immediately before ``function``'s declaration."""
    for path in headers:
        text = path.read_text(encoding="utf-8")
        for match in _COMMENT.finditer(text):
            attached = _DECL_AFTER.match(text, match.end())
            if attached and attached.group(1) == function:
                return _clean(match.group(0))
    return None


def dudect_lanes(source: str) -> dict[str, tuple[str, bool]]:
    """Lane name -> (test function, info-only) as registered in ``source``."""
    return {m.group(1): (m.group(2), m.group(3) == "1") for m in _LANE.finditer(source)}


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*", "", _COMMENT.sub(" ", source))


def _function_bodies(source: str) -> dict[str, str]:
    """Top-level function definitions in ``source``: name -> body text."""
    bodies: dict[str, str] = {}
    code = _strip_c_comments(source)
    for match in re.finditer(r"^[A-Za-z_][\w \t\*]*?\b(\w+)\s*\([^;{)]*\)\s*\{", code, re.M):
        depth, i = 1, match.end()
        while depth and i < len(code):
            depth += {"{": 1, "}": -1}.get(code[i], 0)
            i += 1
        bodies.setdefault(match.group(1), code[match.end() : i])
    return bodies


def calls_reachable(bodies: dict[str, str], start: str, depth: int = 3) -> str:
    """``start``'s body and the bodies of the file's functions it reaches."""
    seen: set[str] = set()
    frontier = [start]
    text: list[str] = []
    for _ in range(depth + 1):
        nxt: list[str] = []
        for name in frontier:
            if name in seen or name not in bodies:
                continue
            seen.add(name)
            text.append(bodies[name])
            nxt.extend(re.findall(r"\b(\w+)\b", bodies[name]))
        frontier = nxt
    return "\n".join(text)


def _calls(text: str, names: Sequence[str]) -> bool:
    return any(re.search(_CALL.format(re.escape(n)), text) for n in names)


def forwarder_ok(c_sources: Sequence[Path], alias: str, target: str) -> bool:
    """True when ``alias`` is defined in ``c_sources`` as one ``return target(...)``."""
    pattern = re.compile(
        rf"\b{re.escape(alias)}\s*\([^;{{)]*\)\s*\{{\s*return\s+{re.escape(target)}\s*\([^;]*\);\s*\}}",
        re.DOTALL,
    )
    return any(
        pattern.search(_strip_c_comments(p.read_text(encoding="utf-8", errors="replace")))
        for p in c_sources
    )


def _load_ct_tool(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ct_claims_ghash_tool", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(
    root: Path,
    registry: dict[str, Evidence],
    withdrawn: dict[str, str],
    ct_tool: Optional[ModuleType] = None,
) -> list[str]:
    """Return every inconsistency between the headers, the registry and the
    instruments; an empty list is a pass."""
    headers = sorted((root / "include").glob("*.h"))
    c_sources = sorted((root / "src" / "c").rglob("*.c"))
    dudect_path = root / "tests" / "c" / "test_dudect.c"
    errors: list[str] = []

    claims = scan_headers(headers, root)
    claimed: dict[str, list[Claim]] = {}
    for claim in claims:
        if claim.function is None:
            errors.append(
                f"{claim.path}:{claim.line}: a constant-time claim that names no public "
                f"function: {claim.sentence!r}. Attach it to the function it describes."
            )
            continue
        claimed.setdefault(claim.function, []).append(claim)

    for function, where in sorted(claimed.items()):
        if function in withdrawn:
            errors.append(
                f"{where[0].path}:{where[0].line}: {function} claims constant time again, "
                f"but its claim was withdrawn on {withdrawn[function]}: {where[0].sentence!r}"
            )
        elif function not in registry:
            errors.append(
                f"{where[0].path}:{where[0].line}: {function} claims constant time and has "
                f"no entry in tools/check_ct_claims.py REGISTRY, so nothing measures the "
                f"claim: {where[0].sentence!r}"
            )
    for function in sorted(set(registry) - set(claimed)):
        errors.append(
            f"REGISTRY: {function} no longer claims constant time in include/. Move it "
            f"to WITHDRAWN with the date, or restore the claim."
        )
    for function, date in sorted(withdrawn.items()):
        doc = documentation_of(headers, function)
        if doc is None:
            errors.append(f"WITHDRAWN: {function} is not declared AMA_API in include/.")
        elif not _WITHDRAWN.search(doc):
            errors.append(
                f"WITHDRAWN: {function}'s documentation does not say its constant-time "
                f"claim was withdrawn ({date}); a reader of the header cannot tell."
            )

    if not dudect_path.is_file():
        errors.append(f"{dudect_path.relative_to(root)} is missing")
        return errors
    dudect_source = dudect_path.read_text(encoding="utf-8")
    lanes = dudect_lanes(dudect_source)
    bodies = _function_bodies(dudect_source)
    if ct_tool is None:
        tool_path = root / "tools" / "check_ghash_constant_time.py"
        ct_tool = _load_ct_tool(tool_path) if tool_path.is_file() else None

    for function, evidence in sorted(registry.items()):
        names = (function, *evidence.via)
        for alias in evidence.via:
            if not forwarder_ok(c_sources, alias, function):
                errors.append(
                    f"{function}: via {alias}, but src/c does not define {alias} as a "
                    f"single `return {function}(...)`."
                )
        if not evidence.lanes:
            errors.append(f"{function}: no dudect lane measures it.")
        strict = False
        for lane in evidence.lanes:
            if lane not in lanes:
                errors.append(f"{function}: lane {lane!r} is not registered in {dudect_path.name}.")
                continue
            test_fn, info_only = lanes[lane]
            strict = strict or not info_only
            if not _calls(calls_reachable(bodies, test_fn), names):
                errors.append(
                    f"{function}: lane {lane!r} ({test_fn}) never calls {' or '.join(names)}."
                )
        if not strict and not (evidence.counts or evidence.taints):
            errors.append(
                f"{function}: every lane is info-only and no deterministic target is named, "
                f"so nothing that measures it can fail a build."
            )
        if ct_tool is None:
            errors.append("tools/check_ghash_constant_time.py is missing")
            continue
        for kind, table, targets in (
            ("count", getattr(ct_tool, "_DRIVERS", {}), evidence.counts),
            ("taint", getattr(ct_tool, "_TAINT_DRIVERS", {}), evidence.taints),
        ):
            for target in targets:
                if target not in table:
                    errors.append(f"{function}: {kind} target {target!r} does not exist.")
                elif not _calls(_strip_c_comments(table[target]), names):
                    errors.append(
                        f"{function}: the {kind} driver {target!r} never calls "
                        f"{' or '.join(names)}."
                    )
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--list", action="store_true", help="print the registry and exit")
    args = parser.parse_args(argv)
    if not (args.root / "include").is_dir():
        print(f"include/ not found under {args.root}", file=sys.stderr)
        return 2
    if args.list:
        for function, ev in sorted(REGISTRY.items()):
            print(
                f"{function}: lanes={list(ev.lanes)} counts={list(ev.counts)} "
                f"taints={list(ev.taints)} via={list(ev.via)}"
            )
        for function, date in sorted(WITHDRAWN.items()):
            print(f"{function}: WITHDRAWN {date}")
        return 0
    errors = check(args.root, REGISTRY, WITHDRAWN)
    if errors:
        print("CONSTANT-TIME CLAIM CHECK FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        f"constant-time claims: {len(REGISTRY)} registered and measured, "
        f"{len(WITHDRAWN)} withdrawn and stated so in the header."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
