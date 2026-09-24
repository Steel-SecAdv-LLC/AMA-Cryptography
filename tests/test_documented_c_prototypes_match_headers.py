# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every C prototype the documentation prints must be the one the header declares.

WHY THIS TEST EXISTS

``wiki/C-API-Reference.md`` is the page a C consumer reads before writing a line
against this library, and nothing checked it against ``include/ama_cryptography.h``.
It had drifted until **33 of its 38 declarations were wrong**.  Four named
functions that do not exist (``ama_random_bytes``, ``ama_kyber_enc``,
``ama_kyber_dec``, ``ama_shake256_inc_ctx_release``) and ten macros that do not
exist (the ``AMA_DILITHIUM_*``, ``AMA_KYBER_*`` and ``AMA_SPHINCS_*`` size
families), so the examples could not compile at all.  Those fail loudly.

The dangerous ones compiled:

* ``ama_ed25519_keypair(uint8_t pk[32], uint8_t sk[32])`` — the secret key is
  **64** bytes (RFC 8032 expanded form, ``AMA_ED25519_SECRET_KEY_BYTES``).  A
  reader who sized that buffer from the wiki overflowed it by 32 bytes on every
  keypair and every sign.
* Both AEADs were documented as ``(plaintext, pt_len, aad, aad_len, key, nonce,
  ...)``.  The real order is ``(key, nonce, plaintext, pt_len, aad, aad_len,
  ...)``.  Every one of those parameters is a ``const uint8_t *``, so a caller
  following the wiki passes the plaintext where the key belongs and the compiler
  says nothing.
* ``ama_dilithium_verify`` and ``ama_sphincs_verify`` were documented as
  ``(signature, signature_len, message, message_len, public_key)``.  The real
  order is message first.  Also silent.
* ``ama_consttime_swap`` and ``ama_consttime_copy`` were documented with
  ``condition`` last; it is first.

WHAT IT ENFORCES

Every prototype-shaped declaration inside a ```c fence, in every tracked ``.md``
file, must match a declaration in a real header verbatim after whitespace and
pointer-spacing normalisation.  Parameter names are compared too: these are
reference pages, and a reader who copies ``uint8_t sk[32]`` out of one is
copying a claim about size, not a stylistic choice.

The C API page is not the only one that makes the promise:
``wiki/Cryptography-Algorithms.md`` prints the Argon2id legacy shim's two
prototypes and had drifted from the header the same way, calling ``parallelism``
``p_cost`` and ``output`` ``out``.

A declaration whose header is not under ``include/`` must be listed in
:data:`INTERNAL_HEADER_DOCUMENTED`, whose value names the header it comes from.
There is exactly one, and the page says out loud that the public header does not
declare it.

The header's own doc comments are held to the C bodies they describe as well
(the section at the end of this file): a "delegates to X()" claim must name a
function the body calls, and an entry point whose body signs or verifies under
the empty FIPS 204/205 context must say so and cite INVARIANT-50.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_INCLUDE = REPO_ROOT / "include"

#: Functions the wiki documents that are declared in an internal header rather
#: than in ``include/``.  The value is the header, so the entry is a statement
#: about the tree and not a place to hide a typo.
INTERNAL_HEADER_DOCUMENTED: dict[str, str] = {
    # ``ama_randombytes`` used to be here: wiki/C-API-Reference.md documented
    # its prototype and offered an ``extern`` declaration as a recipe for
    # out-of-tree callers.  That recipe never linked — cmake/ama_exports.map
    # names the symbol in its ``local:`` list, so ``nm --dynamic`` finds
    # nothing — and the page now says so instead of declaring it.  The entry is
    # removed rather than kept, because this map is a statement about what the
    # page documents.
}

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_FENCE = re.compile(r"```c\n(.*?)```", re.S)
_CONTINUATION = re.compile(r"\\\n")
_PREPROCESSOR = re.compile(r"^[ \t]*#.*$", re.M)
_HEADER_DECL = re.compile(
    r"\A\s*(?:AMA_API\s+)?"
    r"((?:const\s+|unsigned\s+|struct\s+)*[A-Za-z_][\w\s\*]*?\bama_\w+\s*\([^()]*\))\s*\Z",
    re.S,
)
_DOC_DECL = re.compile(
    r"(?:^|\n)[ \t]*"
    r"((?:const\s+|static\s+|extern\s+)*[A-Za-z_]\w*(?:\s*\*+)?\s*\**\s*ama_\w+\s*\([^;{]*?\))\s*;",
    re.S,
)
_NAME = re.compile(r"(ama_\w+)\s*\(")


def _name_of(declaration: str) -> str:
    """The function name in a declaration this module produced.

    Every declaration in :data:`DECLARATIONS` and :data:`PROTOTYPES` was matched by
    a pattern that requires ``ama_\\w+(``, so the search cannot miss; raising rather
    than returning ``None`` keeps that guarantee visible to the type checker and
    turns a future parser change into a loud failure instead of a skipped check.
    """
    match = _NAME.search(declaration)
    if match is None:  # pragma: no cover - unreachable while the patterns agree
        raise AssertionError(f"no ama_* function name in {declaration!r}")
    return match.group(1)


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub(" ", _BLOCK_COMMENT.sub(" ", text))


def _normalise(decl: str) -> str:
    """Collapse whitespace and pointer spacing so `T *x` and `T* x` compare equal."""
    s = " ".join(_strip_comments(decl).split())
    s = re.sub(r"^extern\s+", "", s)
    s = re.sub(r"\s*\*\s*", "* ", s)
    s = re.sub(r"\s*,\s*", ", ", s)
    s = re.sub(r"\s*\[\s*", "[", s)
    s = re.sub(r"\s*\]\s*", "] ", s).strip()
    s = re.sub(r"\s+([,)])", r"\1", s)
    s = re.sub(r"\(\s+", "(", s)
    return s


def _prototypes(paths: list[Path]) -> dict[str, tuple[str, Path]]:
    """Map every ``ama_*`` function a header declares to its normalised prototype.

    Statement-based rather than regex-over-the-whole-file: preprocessor lines are
    removed first (a ``#define`` right above a prototype otherwise gets swept into
    it), the text is split on ``;``, and only the tail after the last ``}`` of each
    statement is considered, so struct and enum bodies cannot leak in.
    """
    out: dict[str, tuple[str, Path]] = {}
    for path in paths:
        text = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        text = _CONTINUATION.sub(" ", text)
        text = _PREPROCESSOR.sub(" ", text)
        for statement in text.split(";"):
            statement = statement.rsplit("}", 1)[-1]
            m = _HEADER_DECL.match(statement)
            if m is None:
                continue
            decl = _normalise(m.group(1))
            out.setdefault(_name_of(decl), (decl, path))
    return out


def _header_files() -> list[Path]:
    public = sorted(PUBLIC_INCLUDE.rglob("*.h"))
    internal = sorted((REPO_ROOT / "src" / "c").rglob("*.h"))
    # Public first, so a name declared in both resolves to the public header.
    return public + internal


PROTOTYPES = _prototypes(_header_files())


def _tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [REPO_ROOT / f for f in out]


def _doc_declarations() -> list[tuple[Path, str]]:
    """Every prototype-shaped declaration in a ```c fence, across all tracked docs.

    Not just the C API page: `wiki/Cryptography-Algorithms.md` prints the
    Argon2id legacy shim's prototypes too, and had drifted from the header the
    same way (`p_cost` for `parallelism`, `out` for `output`).  Any document that
    prints a prototype is making the same promise, so all of them are checked.
    """
    found: list[tuple[Path, str]] = []
    for doc in _tracked_markdown():
        text = doc.read_text(encoding="utf-8", errors="replace")
        for block in _FENCE.findall(text):
            for m in _DOC_DECL.finditer(_strip_comments(block)):
                found.append((doc, _normalise(m.group(1))))
    return found


DECLARATIONS = _doc_declarations()


def test_the_header_corpus_is_substantial() -> None:
    """Non-vacuity: an empty prototype map would make every comparison below pass."""
    assert len(PROTOTYPES) > 120, (
        f"only {len(PROTOTYPES)} prototypes parsed from the headers; the parser has "
        f"stopped seeing declarations it is meant to compare against"
    )


def test_the_page_declares_a_substantial_api() -> None:
    """Non-vacuity: if the fence/declaration pattern broke, nothing would be checked."""
    assert len(DECLARATIONS) > 30, (
        f"only {len(DECLARATIONS)} declarations parsed from the tracked documents; "
        f"the pattern has stopped seeing the prototypes it is meant to check"
    )


def _case_id(case: tuple[Path, str]) -> str:
    doc, declaration = case
    return f"{doc.relative_to(REPO_ROOT)}::{_name_of(declaration)}"


@pytest.mark.parametrize("case", DECLARATIONS, ids=_case_id)
def test_every_documented_prototype_matches_the_header(case: tuple[Path, str]) -> None:
    doc, declaration = case
    name = _name_of(declaration)
    where = doc.relative_to(REPO_ROOT)
    assert name in PROTOTYPES, (
        f"{where} documents {name}(), which no header declares. A reader following "
        f"this page gets a link error at best. Correct the name, or remove the entry."
    )
    expected, header = PROTOTYPES[name]
    assert declaration == expected, (
        f"{where} disagrees with {header.relative_to(REPO_ROOT)} about {name}():\n"
        f"    doc:    {declaration}\n"
        f"    header: {expected}\n"
        f"A reader copies buffer sizes and argument order out of this page. Where the "
        f"types are compatible the compiler will not catch the difference."
    )


@pytest.mark.parametrize("case", DECLARATIONS, ids=_case_id)
def test_a_documented_internal_entry_point_is_declared_as_such(
    case: tuple[Path, str],
) -> None:
    """Anything not in ``include/`` must be listed, with the header it comes from."""
    doc, declaration = case
    name = _name_of(declaration)
    if name not in PROTOTYPES:
        pytest.skip("absence is the other test's failure")
    _, header = PROTOTYPES[name]
    # as_posix(), not str(): on Windows str() spells this "src\\c\\ama_platform_rand.h"
    # and the allowlist is written with forward slashes, so the comparison failed
    # on three Windows lanes while passing everywhere else.
    rel = header.relative_to(REPO_ROOT).as_posix()
    if header.is_relative_to(PUBLIC_INCLUDE):
        assert name not in INTERNAL_HEADER_DOCUMENTED, (
            f"INTERNAL_HEADER_DOCUMENTED lists {name}, but {rel} is a public header; "
            f"remove the entry"
        )
        return
    assert INTERNAL_HEADER_DOCUMENTED.get(name) == rel, (
        f"{doc.relative_to(REPO_ROOT)} documents {name}(), which is declared in {rel} "
        f"— not in include/, so it is not part of the installed public header set. "
        f"Either stop documenting it, or add {{{name!r}: {rel!r}}} to "
        f"INTERNAL_HEADER_DOCUMENTED and say so on the page."
    )


def test_the_internal_allowlist_has_no_stale_entry() -> None:
    documented = {_name_of(d) for _, d in DECLARATIONS}
    for name, header in INTERNAL_HEADER_DOCUMENTED.items():
        assert name in documented, (
            f"INTERNAL_HEADER_DOCUMENTED lists {name}, but the page no longer "
            f"documents it; remove the entry"
        )
        assert (REPO_ROOT / header).exists(), f"{header} does not exist"


def test_the_documented_prototypes_compile_against_the_real_header() -> None:
    """Second opinion: a C compiler agrees, for the public entry points.

    The text comparison above is the strict check — it sees parameter-name and
    buffer-size drift a compiler is entitled to ignore.  This one is the
    independent one: it feeds the page's own declarations to the compiler after
    the real header, so a conflicting redeclaration is a hard error rather than
    a diff this test's parser has to notice.
    """
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler on PATH")

    public = [
        d
        for _, d in DECLARATIONS
        if _name_of(d) in PROTOTYPES and PROTOTYPES[_name_of(d)][1].is_relative_to(PUBLIC_INCLUDE)
    ]
    assert len(public) > 30, f"only {len(public)} public declarations to compile"

    # AMA_BUILDING_STATIC, because on Windows AMA_API expands to
    # __declspec(dllimport) for an external consumer of the DLL, and a
    # redeclaration without that attribute is -Wattributes ("redeclared without
    # dllimport attribute").  The documentation prints the prototype without the
    # AMA_API decoration -- correctly, since it is a linkage macro and not part
    # of the signature a reader types -- so the probe must compile in the mode
    # where the macro is empty.  The header's own static-library arm does that
    # (include/ama_cryptography.h: "#elif defined(AMA_BUILDING_STATIC)").
    source = (
        "#define AMA_BUILDING_STATIC 1\n"
        "#include <stddef.h>\n#include <stdint.h>\n"
        '#include "ama_cryptography.h"\n' + "".join(f"{d};\n" for d in public)
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "wiki_prototypes.c"
        src.write_text(source, encoding="utf-8")
        # -Wall -Wextra -Werror stays.  Dropping it was tried and reverted: a
        # conflicting return type is not always an error (ama_error_t carries a
        # negative enumerator, so gcc makes it compatible with int), and the
        # diagnostic that actually catches the dangerous class here --
        # -Warray-parameter on "uint8_t[32]" against a declared "uint8_t[64]",
        # which is exactly the Ed25519 secret-key defect -- is a warning.  The
        # Windows failure came from the dllimport attribute, and the
        # AMA_BUILDING_STATIC define above removes it at the source rather than
        # by silencing a whole warning class.
        proc = subprocess.run(
            [
                cc,
                "-std=c11",
                "-fsyntax-only",
                "-Wall",
                "-Wextra",
                "-Werror",
                # -isystem, not -I: it suppresses warnings that originate inside
                # the header while still reporting the ones attributed to this
                # probe's own redeclarations -- verified in both directions, the
                # mutated ama_ed25519_keypair is rejected either way.  -Werror
                # then covers exactly what this test checks, and a warning the
                # header happens to emit under some compiler this repository
                # does not otherwise build with cannot fail it.
                "-isystem",
                str(PUBLIC_INCLUDE),
                str(src),
            ],
            capture_output=True,
            text=True,
        )
    assert proc.returncode == 0, (
        "the prototypes printed in the documentation do not agree with "
        "include/ama_cryptography.h:\n" + proc.stderr
    )


def test_the_internal_allowlist_is_spelled_with_forward_slashes() -> None:
    """The comparison is against ``Path.as_posix()``; the allowlist must match.

    This failed on three Windows lanes and nowhere else, because ``str(Path)``
    there spells the header ``src\\c\\ama_platform_rand.h``.  Pinning the
    spelling keeps the next entry from reintroducing a platform-only failure.
    """
    for name, header in INTERNAL_HEADER_DOCUMENTED.items():
        assert "\\" not in header, (
            f"INTERNAL_HEADER_DOCUMENTED[{name!r}] is spelled {header!r}; use forward "
            f"slashes, which is what Path.as_posix() produces on every platform"
        )
        assert not header.startswith("/"), f"{header!r} must be repo-relative"


# ---------------------------------------------------------------------------
# The header's own prose must describe the body it documents.
#
# include/ama_cryptography.h is the page a C consumer reads most, and its doc
# comments make claims about the code the prototypes above cannot see.  Two of
# them outlived the 5.0.0 context-separation change (INVARIANT-50):
#
# * ama_dilithium_sign_ctx / ama_dilithium_verify_ctx / ama_sphincs_verify_ctx
#   were documented as applying 0x00 || len(ctx) || ctx || M "before
#   delegating to" ama_dilithium_sign() / _verify() / ama_sphincs_verify().
#   Those functions now apply the empty-context wrapper themselves, so the
#   sentence describes a double wrapper no FIPS 204/205 verifier accepts; the
#   bodies call ama_ml_dsa_sign_ctx / ama_ml_dsa_verify_ctx / ama_slhdsa_verify
#   directly and wrap once.
# * ama_dilithium_sign / ama_dilithium_verify changed wire format -- raw-M
#   Algorithm 7/8 to empty-context Algorithm 2/3 -- and their header entries
#   still said only "Sign message with ML-DSA-65", so a consumer whose 4.x
#   signatures stopped verifying had nothing to read.  ama_sphincs_sign, the
#   same change on the SLH-DSA side, did carry the note.
#
# Both checks take their expectation from the C body, not from a list here.
# ---------------------------------------------------------------------------

_DOC_THEN_DECL = re.compile(
    r"/\*\*((?:(?!\*/).)*)\*/\s*AMA_API\s+[A-Za-z_][\w \*]*?\b(ama_[A-Za-z0-9_]+)\s*\(",
    re.S,
)
_DELEGATION = re.compile(r"\bdelegat\w*\s+to\s+`?(ama_[A-Za-z0-9_]+)\(\)")
#: A body that signs or verifies under the EMPTY FIPS 204 / 205 context: the
#: external wrapper called with `NULL, 0` for (ctx, ctx_len), or the two-byte
#: 0x00 || 0x00 prefix the SLH-DSA legacy entry points pass to the internal core.
_EMPTY_CONTEXT = re.compile(
    r"\b(?:ama_ml_dsa_(?:sign|verify)_ctx|ama_slhdsa_(?:sign|verify))\s*\([^;]*?"
    r"\bNULL\s*,\s*0\s*,"
    r"|\bempty_ctx_prefix\b"
)


def _header_docs() -> dict[str, str]:
    """Each AMA_API function in the public header -> its doc comment, one line."""
    text = (PUBLIC_INCLUDE / "ama_cryptography.h").read_text(encoding="utf-8")
    return {
        m.group(2): " ".join(re.sub(r"(?m)^\s*\*", " ", m.group(1)).split())
        for m in _DOC_THEN_DECL.finditer(text)
    }


def _definition_body(name: str) -> Optional[tuple[Path, str]]:
    """The body of ``name``'s definition under ``src/c``, comments removed."""
    head = re.compile(
        r"(?m)^(?:[A-Za-z_][\w \t\*]*[ \t\*])?" + re.escape(name) + r"[ \t]*\([^;{}]*\)\s*\{"
    )
    for source in sorted((REPO_ROOT / "src" / "c").rglob("*.c")):
        text = _strip_comments(source.read_text(encoding="utf-8", errors="replace"))
        m = head.search(text)
        if m is None:
            continue
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        assert depth == 0, f"unbalanced braces after {name} in {source}"
        return source, text[m.end() : i - 1]
    return None


HEADER_DOCS = _header_docs()
DELEGATION_CLAIMS = sorted(
    (name, callee) for name, doc in HEADER_DOCS.items() for callee in _DELEGATION.findall(doc)
)
EMPTY_CONTEXT_ENTRY_POINTS = sorted(
    name
    for name in HEADER_DOCS
    if (found := _definition_body(name)) is not None and _EMPTY_CONTEXT.search(found[1])
)


def test_the_header_claims_are_actually_being_read() -> None:
    """Non-vacuity for the two checks below, on both signature families."""
    assert len(HEADER_DOCS) > 120, f"only {len(HEADER_DOCS)} documented AMA_API functions parsed"
    assert DELEGATION_CLAIMS, "no 'delegates to X()' claim parsed from the header"
    families = {name.split("_")[1] for name in EMPTY_CONTEXT_ENTRY_POINTS}
    assert {"dilithium", "sphincs"} <= families, EMPTY_CONTEXT_ENTRY_POINTS


@pytest.mark.parametrize("claim", DELEGATION_CLAIMS, ids=lambda c: f"{c[0]}->{c[1]}")
def test_a_delegation_claim_names_the_function_the_body_calls(claim: tuple[str, str]) -> None:
    name, callee = claim
    found = _definition_body(name)
    assert found is not None, f"{name} is documented but no definition was found under src/c"
    source, body = found
    assert re.search(r"\b" + re.escape(callee) + r"\s*\(", body), (
        f"include/ama_cryptography.h says {name}() delegates to {callee}(), but its "
        f"body in {source.relative_to(REPO_ROOT).as_posix()} never calls it. A reader "
        f"who re-implements the documented composition gets a different construction."
    )


@pytest.mark.parametrize("name", EMPTY_CONTEXT_ENTRY_POINTS)
def test_an_empty_context_entry_point_says_so_in_the_header(name: str) -> None:
    doc = HEADER_DOCS[name]
    assert "empty context" in doc, (
        f"{name}() signs or verifies under the empty FIPS 204/205 context, and its "
        f"header entry does not say so."
    )
    assert "INVARIANT-50" in doc, (
        f"{name}() changed wire format in 5.0.0 (raw message -> empty context); its "
        f"header entry must say so and cite INVARIANT-50, or a consumer whose 4.x "
        f"signatures stop verifying has nothing to read."
    )
