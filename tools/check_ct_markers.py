#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — declassification points and optimizer barriers cannot
move or vanish unreviewed.

Two markers in ``src/c`` carry constant-time arguments the compiler cannot
check:

``AMA_CT_DECLASSIFY(ptr, len)`` (``src/c/internal/ama_ct_declassify.h``)
    asserts that a value is public -- a verdict the function returns, or bytes
    it emits.  Under ``AMA_TESTING_MODE`` it tells Memcheck the bytes are
    defined, so the secret-taint gate does not report the branch that follows;
    in production it expands to nothing.  A point placed BEFORE the value's
    last secret-dependent write declassifies an intermediate secret rather
    than the public result, and the taint gate cannot see that: Memcheck
    re-taints bytes a later secret write touches, so the gate can stay green
    while the argument at the site has become false.

``ama_ct_value_barrier_u64`` / ``_u32`` (``src/c/internal/ama_ct_barrier.h``)
    launder a mask through an empty ``asm`` so the optimizer cannot turn a
    masked select back into a branch on the secret.  Removing one changes no
    functional result and, on today's compilers, often no instruction either
    -- which is exactly why its removal would pass every other test.

This gate enforces, over the comment-stripped sources:

1. **Inventory.**  The number of declassification points and of barrier uses
   in each file equals :data:`DECLASSIFY_SITES` / :data:`BARRIER_SITES`.  A new
   point is a review item (the header says so); a removed barrier is a
   weakening.  Either changes a count here, in the same diff, where a reviewer
   sees it.  This is an inventory pin, like the per-file reference counts of
   ``tools/check_stdlib_hash_boundary.py``, not an exemption list: nothing in
   it excuses a site from rule 2.
2. **Order.**  After a declassification point, nothing writes the declassified
   object before the end of the block that contains the point: no
   assignment, increment or compound assignment, and no call that receives
   the object (bare, by address or at an offset) in a parameter the callee
   may write.  The callee's own declarations decide that: a parameter
   declared ``const T *``, ``const T x[]`` or by value is a read; anything
   else, and any callee with no declaration in ``src/c`` or ``include``, is a
   write unless it is in :data:`READ_ONLY_CALLS`.  ``memcpy``, ``memmove``
   and ``memset`` write their first argument only.  A write followed, in the
   same block, by a fresh declassification of the same object is the next
   published value (SLH-DSA reuses one buffer for each layer's root) and is
   not a violation.  So a point moved above the computation of its value --
   or a variable reused for a later secret after being declassified -- fails
   here.
3. **Argument.**  Every point has, within the sixteen lines above it, a
   comment that says why the value is public: it names ``public``,
   ``publish``, a ``verdict``, the signature or the declassify header.

What the barrier's opacity rests on -- that the compilers CI uses cannot see
through the ``asm`` -- is not a source property; ``tests/test_ct_barrier_opacity.py``
compiles a probe under each of them and checks it.

Exit status: 0 consistent, 1 a violation, 2 the source tree is missing.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Declassification points per file (comment-stripped), reviewed 2026-11-22.
DECLASSIFY_SITES: dict[str, int] = {
    "src/c/ama_aes_gcm.c": 1,
    "src/c/ama_agent_binding.c": 2,
    "src/c/ama_argon2.c": 1,
    "src/c/ama_ascon.c": 1,
    "src/c/ama_base64.c": 2,
    "src/c/ama_chacha20poly1305.c": 1,
    "src/c/ama_dilithium.c": 8,
    "src/c/ama_frost.c": 6,
    "src/c/ama_kyber.c": 2,
    "src/c/ama_nistp.c": 11,
    "src/c/ama_secp256k1.c": 12,
    "src/c/ama_slhdsa.c": 4,
    "src/c/avx2/ama_aes_gcm_avx2.c": 1,
    "src/c/avx2/ama_aes_gcm_vaes_avx2.c": 1,
    "src/c/neon/ama_aes_gcm_neon.c": 1,
}

#: Optimizer-barrier uses per file (helper calls plus the two raw register
#: barriers in the AVX2 ChaCha20 and VAES kernels), reviewed 2026-11-22.
BARRIER_SITES: dict[str, int] = {
    "src/c/ama_aes_gcm.c": 2,
    "src/c/ama_ascon.c": 4,
    "src/c/ama_base64.c": 2,
    "src/c/ama_chacha20poly1305.c": 1,
    "src/c/ama_consttime.c": 1,
    "src/c/ama_dilithium.c": 1,
    "src/c/ama_ed25519.c": 1,
    "src/c/ama_kyber.c": 3,
    "src/c/ama_nistp.c": 1,
    "src/c/ama_secp256k1.c": 14,
    "src/c/ama_sha3.c": 1,
    "src/c/ama_x25519.c": 5,
    "src/c/avx2/ama_aes_gcm_avx2.c": 1,
    "src/c/avx2/ama_aes_gcm_vaes_avx2.c": 2,
    "src/c/avx2/ama_argon2_avx2.c": 2,
    "src/c/avx2/ama_chacha20poly1305_avx2.c": 2,
    "src/c/avx2/ama_dilithium_avx2.c": 3,
    "src/c/avx2/ama_kyber_avx2.c": 2,
    "src/c/avx2/ama_sha3_avx2.c": 8,
    "src/c/avx512/ama_sha3_x4_avx512.c": 8,
    "src/c/fe51.h": 3,
    "src/c/fe64.h": 3,
    "src/c/internal/ama_ed25519_ge.h": 1,
    "src/c/neon/ama_argon2_neon.c": 1,
}

#: Callees that only read (or scrub) an argument.
READ_ONLY_CALLS = frozenset(
    {
        "AMA_CT_DECLASSIFY",
        "ama_consttime_memcmp",
        "memcmp",
        "ama_secure_memzero",
        "nistp_der_encode",
        "der_encode_signature",
        # Reads `hbits` only.  Its parameter is `uint8_t hbits[K][N]` because
        # C11 does not convert `uint8_t (*)[N]` to `const uint8_t (*)[N]`
        # without a diagnostic under -Wpedantic, so the prototype cannot say
        # so itself.
        "dil_polyveck_pack_hint",
        "sizeof",
        "if",
        "while",
        "for",
        "switch",
        "return",
    }
)
_FIRST_ARG_WRITERS = frozenset({"memcpy", "memmove", "memset"})

_DECLASSIFY = re.compile(r"\bAMA_CT_DECLASSIFY\s*\(")
_BARRIER = re.compile(
    r"\bama_ct_value_barrier_u(?:64|32)\s*\(|__asm__\s+volatile\s*\(\s*\"\"\s*:\s*\"\+r\""
)
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_DEFINITION = "ama_ct_declassify.h"
_BARRIER_DEFINITION = "ama_ct_barrier.h"


@dataclass(frozen=True)
class Site:
    path: str
    line: int
    obj: str
    text: str


def blank_comments(source: str) -> str:
    """``source`` with every comment replaced by spaces, offsets preserved."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


def _split_args(text: str, open_paren: int) -> tuple[list[str], int]:
    """Top-level arguments of the call whose ``(`` is at ``open_paren``."""
    depth, i, start, args = 0, open_paren, open_paren + 1, []
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:i])
                return [a.strip() for a in args], i
        elif ch == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
        i += 1
    return [a.strip() for a in args], len(text)


def base_object(expr: str) -> Optional[str]:
    """The variable an argument expression names: ``&x``, ``x``, ``x + 32``."""
    expr = re.sub(r"^\(\s*[\w\s]+\*?\s*\)", "", expr.strip()).strip().lstrip("&").strip()
    match = re.match(r"([A-Za-z_]\w*)", expr)
    return match.group(1) if match else None


def _block_end(code: str, pos: int) -> int:
    depth = 0
    for i in range(pos, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            if depth == 0:
                return i
            depth -= 1
    return len(code)


def declassify_sites(path: Path, root: Path) -> list[Site]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    code = blank_comments(raw)
    rel = path.relative_to(root).as_posix()
    sites = []
    for match in _DECLASSIFY.finditer(code):
        args, _ = _split_args(code, match.end() - 1)
        obj = base_object(args[0]) if args else None
        sites.append(Site(rel, code.count("\n", 0, match.start()) + 1, obj or "", raw))
    return sites


_MEMBER_POINTER = re.compile(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(([^;{}()]*)\)\s*;")
#: A declaration or definition: a type token, whitespace or `*`, the name and
#: a parameter list.  Every quantified piece is separated from its neighbour
#: by a disjoint character class, so a match is linear in the input (the
#: first spelling of this pattern nested quantifiers, which CodeQL's
#: py/redos rightly reported as exponential).
_PROTOTYPE = re.compile(r"\b([A-Za-z_]\w*)[\s*]+([A-Za-z_]\w*)\s*\(([^;{}()]*)\)\s*[;{]")
#: Tokens that may precede a CALL in the shape above (`return f(x);`).
_NOT_A_TYPE = frozenset(
    {"return", "else", "case", "goto", "do", "sizeof", "if", "while", "for", "switch"}
)
_DECL_PARAM = re.compile(r"[A-Za-z_][\w\s\*\[\]]*")


def _is_declared_parameter(param: str) -> bool:
    """A type and a name (`const uint8_t *out`, `uint8_t k[32]`), or `void`.

    A call's argument (`buf`, `&x`, `a + b`) is not one, so a call that
    happens to follow an identifier is never read as a declaration -- which
    would record its parameters as read-only, the unsafe direction.
    """
    return param in ("void", "...") or (
        _DECL_PARAM.fullmatch(param) is not None and len(re.findall(r"[A-Za-z_]\w*", param)) >= 2
    )


def param_writability(sources: Sequence[Path]) -> dict[str, list[bool]]:
    """Function name -> per-parameter "may write through it", from every
    declaration and definition in ``sources``.  Where declarations disagree
    a parameter is writable if any says so."""
    table: dict[str, list[bool]] = {}
    for path in sources:
        code = blank_comments(path.read_text(encoding="utf-8", errors="replace"))
        hits = [
            (m.group(2), m.group(3))
            for m in _PROTOTYPE.finditer(code)
            if m.group(1) not in _NOT_A_TYPE
        ] + [(m.group(1), m.group(2)) for m in _MEMBER_POINTER.finditer(code)]
        for name, raw_params in hits:
            params = raw_params.strip()
            if name in _NOT_A_TYPE:
                continue
            parts = [p.strip() for p in params.split(",")] if params else []
            if parts and not all(_is_declared_parameter(p) for p in parts):
                continue
            if not params or params == "void":
                flags: list[bool] = []
            else:
                flags = []
                for param in parts:
                    indirect = "*" in param or "[" in param
                    const_pointee = bool(re.match(r"(?:const\s+\w+|\w+\s+const)\b", param))
                    flags.append(indirect and not const_pointee)
            old = table.get(name)
            if old is None or len(old) != len(flags):
                table[name] = flags if old is None else [True] * max(len(old), len(flags))
            else:
                table[name] = [a or b for a, b in zip(old, flags)]
    return table


def writes_after(
    code: str, start: int, obj: str, writable: Optional[dict[str, list[bool]]] = None
) -> list[str]:
    """Writes to ``obj`` from ``start`` to the end of the enclosing block that
    no later declassification of ``obj`` in the same block re-publishes."""
    tail = code[start : _block_end(code, start)]
    redeclassified = [
        m.start()
        for m in _DECLASSIFY.finditer(tail)
        if base_object(_split_args(tail, m.end() - 1)[0][0]) == obj
    ]

    def republished(pos: int) -> bool:
        return any(r > pos for r in redeclassified)

    name = re.escape(obj)
    found = []
    assign = re.compile(
        rf"(?<![\w.>]){name}\s*(?:\[[^\]]*\]\s*)*(?:[-+*/%&|^]|<<|>>)?=(?!=)"
        rf"|(?:\+\+|--)\s*{name}\b|(?<![\w.>]){name}\s*(?:\+\+|--)"
    )
    for m in assign.finditer(tail):
        if not republished(m.start()):
            found.append(" ".join(tail[m.start() : m.start() + 48].split()))
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", tail):
        callee = m.group(1)
        if callee in READ_ONLY_CALLS or republished(m.start()):
            continue
        args, _ = _split_args(tail, m.end() - 1)
        if callee in _FIRST_ARG_WRITERS:
            flags = [True] + [False] * max(0, len(args) - 1)
        elif writable is not None and callee in writable:
            flags = writable[callee]
        else:
            flags = [True] * len(args)
        if any(
            i < len(args) and (flags[i] if i < len(flags) else True) and base_object(args[i]) == obj
            for i in range(len(args))
        ):
            found.append(" ".join(tail[m.start() : m.start() + 48].split()))
    return found


_ARGUMENT = re.compile(r"public|publish|verdict|signature|declassif", re.IGNORECASE)


def has_argument_comment(raw: str, line: int) -> bool:
    """A comment overlapping the sixteen lines up to ``line`` that argues the
    value is public."""
    for m in _COMMENT.finditer(raw):
        first = raw.count("\n", 0, m.start()) + 1
        last = first + m.group(0).count("\n")
        if last >= line - 16 and first <= line and _ARGUMENT.search(m.group(0)):
            return True
    return False


def _sources(root: Path) -> list[Path]:
    src = root / "src" / "c"
    return sorted(p for p in src.rglob("*") if p.suffix in (".c", ".h"))


def check(
    root: Path,
    declassify: dict[str, int],
    barriers: dict[str, int],
) -> list[str]:
    errors: list[str] = []
    seen_decl: dict[str, int] = {}
    seen_barrier: dict[str, int] = {}
    writable = param_writability(_sources(root) + sorted((root / "include").glob("*.h")))
    for path in _sources(root):
        rel = path.relative_to(root).as_posix()
        raw = path.read_text(encoding="utf-8", errors="replace")
        code = blank_comments(raw)
        if path.name != _BARRIER_DEFINITION:
            n = len(_BARRIER.findall(code))
            if n:
                seen_barrier[rel] = n
        if path.name == _DEFINITION:
            continue
        for match in _DECLASSIFY.finditer(code):
            seen_decl[rel] = seen_decl.get(rel, 0) + 1
            line = code.count("\n", 0, match.start()) + 1
            args, close = _split_args(code, match.end() - 1)
            obj = base_object(args[0]) if args else None
            if obj is None:
                errors.append(f"{rel}:{line}: AMA_CT_DECLASSIFY argument names no object.")
                continue
            semi = code.find(";", close)
            for write in writes_after(code, semi + 1, obj, writable):
                errors.append(
                    f"{rel}:{line}: `{obj}` is declassified and then written "
                    f"(`{write}`) in the same block. Declassify the final value, "
                    f"after its last secret-dependent write."
                )
            if not has_argument_comment(raw, line):
                errors.append(
                    f"{rel}:{line}: AMA_CT_DECLASSIFY with no comment stating why "
                    f"`{obj}` is public (internal/ama_ct_declassify.h requires one)."
                )
    for kind, seen, pinned in (
        ("declassification point", seen_decl, declassify),
        ("optimizer barrier", seen_barrier, barriers),
    ):
        for rel in sorted(set(seen) | set(pinned)):
            have, want = seen.get(rel, 0), pinned.get(rel, 0)
            if have != want:
                errors.append(
                    f"{rel}: {have} {kind}(s), the inventory in "
                    f"tools/check_ct_markers.py pins {want}. Review the change "
                    f"and update the pin in the same commit."
                )
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    if not (args.root / "src" / "c").is_dir():
        print(f"src/c not found under {args.root}", file=sys.stderr)
        return 2
    errors = check(args.root, DECLASSIFY_SITES, BARRIER_SITES)
    if errors:
        print("CONSTANT-TIME MARKER CHECK FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        f"constant-time markers: {sum(DECLASSIFY_SITES.values())} declassification "
        f"points in {len(DECLASSIFY_SITES)} files, each after its value's last write "
        f"and argued; {sum(BARRIER_SITES.values())} optimizer barriers in "
        f"{len(BARRIER_SITES)} files."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
