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
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_INCLUDE = REPO_ROOT / "include"

#: Functions the wiki documents that are declared in an internal header rather
#: than in ``include/``.  The value is the header, so the entry is a statement
#: about the tree and not a place to hide a typo.
INTERNAL_HEADER_DOCUMENTED = {
    "ama_randombytes": "src/c/ama_platform_rand.h",
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
    rel = str(header.relative_to(REPO_ROOT))
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

    source = (
        "#include <stddef.h>\n#include <stdint.h>\n"
        '#include "ama_cryptography.h"\n' + "".join(f"{d};\n" for d in public)
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "wiki_prototypes.c"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                cc,
                "-std=c11",
                "-fsyntax-only",
                "-Wall",
                "-Wextra",
                "-Werror",
                f"-I{PUBLIC_INCLUDE}",
                str(src),
            ],
            capture_output=True,
            text=True,
        )
    assert proc.returncode == 0, (
        "the prototypes printed in the documentation do not agree with "
        "include/ama_cryptography.h:\n" + proc.stderr
    )
