# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""An SLH-DSA parameter row that overruns a stack buffer of ama_slhdsa.c must not compile.

WHY THIS TEST EXISTS

``src/c/ama_slhdsa.c`` runs every parameter set through one core whose stack
buffers have fixed sizes: n-octet values at 32, the FORS treehash stack at
a <= 12, the XMSS treehash stack at h' <= 9, the FORS indices and roots at
k <= 35, the WOTS+ digits and public key at len <= 80, the H_msg digest at
m <= 64.  Until 2026-09-30 each parameter row was a hand-written struct beside
its own ``_Static_assert`` of n against ``SLH_MAX_N``, and nothing else.  A
new row that left the assertion out compiled: one with n = 40 did, and at run
time ``sha2_PRF`` copied 40 octets out of its 32-octet SHA-256 digest.  A row
that kept it compiled as well: SLH-DSA-SHAKE-256s (FIPS 205 Table 2; a = 14, as
in every 192s and 256s set) passed its n assertion and overflowed the FORS
treehash stack.  Both were measured under AddressSanitizer.

The table is now one X-macro list, ``SLH_PARAM_ROWS``.  The row objects,
``slh_lookup()`` and the column maxima that a single ``_Static_assert``
compares with the bounds are all expanded from it, and each of those buffers
is declared through the bound it is checked against.  Two of the maxima are
not columns but read extents no single column gives: the octets of an n-octet
value that ``slh_base_w`` reads as the len1 WOTS+ message digits, and the
octets of the H_msg digest that ``slh_split_digest`` reads.  A row inside
every column bound but past one of those compiled until they were added and
overran under AddressSanitizer (len1 = 72 at lg(w) = 4; fors_msg_bytes = 60).
``SLH_MAX_N`` is itself held to the SHA-256 digest that ``sha2_F`` and
``sha2_PRF`` truncate to n.

WHAT IT ENFORCES

* PIN -- an over-bound row does not compile: the real translation unit, with
  one row added to ``SLH_PARAM_ROWS``, fails in that assertion.  One probe per
  bounded entry, each exceeding that bound alone, plus SLH-DSA-SHAKE-256s,
  the FIPS 205 set the old per-row assertion let through.  Mutation (each
  entry's comparison deleted from the assertion in turn): exactly the probe
  for that entry compiles and this test fails; with the ``a`` comparison
  deleted, the SHAKE-256s probe also compiles.
* RANGE -- non-vacuity: the same harness compiles the same translation unit
  with FIPS 205's SLH-DSA-SHAKE-192f added, so a rejection above is the bound
  and not a harness that cannot compile the file.  Mutation (``SLH_MAX_N``
  lowered to 16): this test fails.
* PIN -- the n bound cannot outgrow the digest: with ``SLH_MAX_N`` raised to
  33, the translation unit fails in the assertion that holds it to
  ``AMA_SHA256_DIGEST_SIZE``.  The table's assertion cannot catch this, since
  every row is still inside the raised bound.  Mutation (that assertion
  deleted): the probe compiles and this test fails, and it is the only one.
* PIN -- a member no row initializes does not compile: with a member added to
  the end of ``slhdsa_params_t``, the translation unit fails under
  ``-Werror=missing-field-initializers``, a diagnostic ``-Wextra`` enables.
  ``SLH_ROW_OBJECT``'s initializer is positional, as the hand-written rows
  were, for this.  Mutation (that initializer made designated, which leaves
  the member zero in every row without a diagnostic): the probe compiles and
  this test fails, and it is the only one.
* PIN -- no row is defined outside the list: outside the ``SLH_ROW_OBJECT``
  macro, every mention of the type in the source (``slhdsa_params_t`` or
  ``struct slhdsa_params``, comments aside) is a pointer type, the struct's
  definition, a declaration of its tag alone, or the typedef's own name.
  Nothing there declares a parameter object, a by-value parameter or a
  compound literal, or renames the type.  Mutation (a SHA2-256f row written
  out by hand as 1ef0c93 wrote them; a row declared through
  ``struct slhdsa_params``, as a compound literal, through a typedef alias or
  a ``#define`` of the type, with a parenthesised declarator or with an
  attribute before its name; a by-value parameter; a local copy): this test
  fails.  For a row under a preprocessor branch the compilers here do not
  take, it is the only test that fails.
* PIN -- ``slh_lookup()`` is the list's: its body is exactly the switch that
  ``SLH_PARAM_ROWS(SLH_ROW_CASE)`` fills, ending in INVARIANT-35's
  ``default: return NULL``.  Mutation (a hand-written ``case``; an ``if``
  before the switch; the default returning a row): this test fails, and for
  an ``if`` or a default that returns a listed row it is the only one.
* PIN -- every compiled row is a listed row: in the preprocessed translation
  unit, shipped and ``AMA_TESTING_MODE``, the same holds of every mention of
  the type but the rows', and the rows are single-declarator declarations of
  exactly ``SLHDSA_PARAMS_<name>`` for each name in ``SLH_PARAM_ROWS``.
  Mutation (``SLH_ROW_OBJECT`` invoked by hand outside the list; a second
  declarator added to ``SLH_ROW_OBJECT``): this test fails, and it is the
  only one.  It also fails, with the source check, on each route listed there
  except the untaken preprocessor branch.  Neither detects an object declared
  through ``__typeof__`` of a listed row, which never names the type.

Not pinned here: that each buffer is declared through its bound.  With the
FORS treehash stack written back as ``(12 + 1) * 32``, the value of that bound
today, every case passes.  Nor are a row's columns checked against each other
(FIPS 205's h = d * h', its len1, len2 and m, the signature length):
SHAKE-128s with d = 8 and its own sig_bytes is inside every bound, and under
AddressSanitizer its signing wrote past the caller's 7856-octet signature
buffer.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SLHDSA_C = REPO_ROOT / "src" / "c" / "ama_slhdsa.c"

#: The first string literal of the table assertion's message.  A rejection
#: must be attributable to it, not to some other error in the probe.
CHECK_MESSAGE = "a row of SLH_PARAM_ROWS exceeds a stack-buffer bound"

#: The first string literal of the message of the assertion that holds
#: SLH_MAX_N to the SHA-256 digest.
DIGEST_MESSAGE = "SLH_MAX_N exceeds the SHA-256 digest"

#: The line that opens the list; each probe row is inserted directly after it.
ROWS_HEADER = re.compile(r"^#define SLH_PARAM_ROWS\(X\)[ \t]*\\\n", re.MULTILINE)

#: The list's continuation lines, after ROWS_HEADER, through its last row.
ROWS_BODY = re.compile(r"(?:[^\n]*\\\n)*[^\n]*")

#: The name each row gives X().
ROW_NAME = re.compile(r"\bX\(\s*(\w+)\s*,")

#: SLH_MAX_N's definition, whose value the digest probe replaces.
MAX_N_DEFINE = re.compile(r"^(#define[ \t]+SLH_MAX_N[ \t]+)\S+", re.MULTILINE)

#: The line that closes slhdsa_params_t; the member probe adds one before it.
STRUCT_END = re.compile(r"^\}[ \t]*slhdsa_params_t;", re.MULTILINE)

#: Either spelling of the parameter type.
TYPE_MENTION = re.compile(r"\bslhdsa_params_t\b|\bstruct\s+slhdsa_params\b")

#: A mention that declares no parameter object: a pointer type (qualifiers,
#: then '*'), or, after the struct tag, its definition or a declaration of the
#: tag alone.
POINTER = re.compile(r"\s*(?:(?:const|volatile)\b\s*)*\*")
TAG_ONLY = re.compile(r"\s*[{;]")

#: What SLH_ROW_OBJECT expands to after the type, through the initializer's
#: opening brace.
ROW_DECLARATION = re.compile(r"\s+(SLHDSA_PARAMS_\w+)\s*=\s*\{")

#: slh_lookup()'s body with its whitespace removed: the rows' cases and
#: INVARIANT-35's default, nothing else.
LOOKUP_BODY = "switch(ps){SLH_PARAM_ROWS(SLH_ROW_CASE)default:returnNULL;}"

#: The defines the library itself compiles this translation unit with.
#: AMA_BUILDING_STATIC makes AMA_API empty on Windows, where the header would
#: otherwise fall through to __declspec(dllimport) on functions this file
#: defines (see tests/test_kyber_compress_width_contract.py).
PRODUCTION_DEFINES = ("-DAMA_USE_NATIVE_PQC", "-DAMA_BUILDING_STATIC")

#: SLH_PARAM_ROWS columns after the name and id, in order.
_COLUMNS = "n h d hp a k w lgw len1 len2 len m pk sk sig fors_msg fors wots_sig adrsc".split()


def _columns(values: str) -> dict[str, int]:
    """A row as SLH_PARAM_ROWS writes it, from n to use_compressed_adrs."""
    return dict(zip(_COLUMNS, (int(v) for v in values.split(",")), strict=True))


#: FIPS 205 Table 2 rows.  Every probe below that is not a FIPS 205 set is
#: SHAKE-128s with one or more columns moved.
SHAKE_128S = _columns("16, 63, 7, 9, 12, 14, 16, 4, 32, 3, 35, 30, 32, 64, 7856, 21, 2912, 560, 0")
#: Inside every bound.
SHAKE_192F = _columns(
    "24, 66, 22, 3, 8, 33, 16, 4, 48, 3, 51, 42, 48, 96, 35664, 33, 7128, 1224, 0"
)
#: a = 14 against a FORS treehash stack sized for a <= 12; every other entry
#: inside its bound.
SHAKE_256S = _columns(
    "32, 64, 8, 8, 14, 22, 16, 4, 64, 3, 67, 47, 64, 128, 29792, 39, 10560, 2144, 0"
)

#: One probe per bounded entry, each exceeding that bound and no other.  The
#: WOTS+ digits are bounded twice, as len (read) and len1 + len2 (written), so
#: each of those probes keeps the other inside 80; len1 + len2 is exceeded at
#: lg(w) = 1, since at lg(w) = 4 a len1 that large also reads more than 32
#: octets of the message.  len2 alone needs lg(w) = 1, since len2 = 9 at
#: lg(w) = 4 would also exceed the two-octet checksum.  The last two are read
#: extents: len1 = 72 at lg(w) = 4 reads 36 octets of an n-octet value, and
#: fors_msg_bytes = 60 reads 60 + 7 + 2 = 69 octets of the 64-octet digest.
OVER_BOUND_ROWS: dict[str, dict[str, int]] = {
    "n": {**SHAKE_128S, "n": 40},
    "h'": {**SHAKE_128S, "hp": 10},
    "a": {**SHAKE_128S, "a": 13},
    "k": {**SHAKE_128S, "k": 36},
    "len": {**SHAKE_128S, "len": 81},
    "len2": {**SHAKE_128S, "w": 2, "lgw": 1, "len1": 26, "len2": 9},
    "m": {**SHAKE_128S, "m": 65},
    "len1 + len2": {**SHAKE_128S, "w": 2, "lgw": 1, "len1": 75, "len2": 8},
    "len2 * lg(w)": {**SHAKE_128S, "w": 256, "lgw": 8},
    "SLH-DSA-SHAKE-256s": SHAKE_256S,
    "WOTS+ message octets": {**SHAKE_128S, "len1": 72},
    "digest octets": {**SHAKE_128S, "fors_msg": 60},
}


def _compilers() -> list[str]:
    """Every distinct C compiler on PATH; both GCC and Clang where present."""
    found: list[str] = []
    seen: set[str] = set()
    for name in ("cc", "gcc", "clang"):
        path = shutil.which(name)
        if path is None:
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        found.append(path)
    return found


COMPILERS = _compilers()


def _needs_compiler(cc: str | None) -> str:
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


def _base_command(cc: str) -> list[str]:
    return [
        cc,
        "-std=c11",
        "-I",
        str(REPO_ROOT / "include"),
        "-I",
        str(REPO_ROOT / "src" / "c"),
        *PRODUCTION_DEFINES,
    ]


def _compile(cc: str, source: str, *flags: str) -> subprocess.CompletedProcess[str]:
    """Compile ``source`` in place of src/c/ama_slhdsa.c."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "ama_slhdsa_row_probe.c"
        probe.write_text(source, encoding="utf-8")
        return subprocess.run(
            [*_base_command(cc), *flags, "-fsyntax-only", str(probe)],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )


def _row(columns: dict[str, int]) -> str:
    values = ", ".join(str(columns[name]) for name in _COLUMNS)
    return f"    X(PROBE, (ama_slhdsa_param_set_t)99, {values}, shake) \\\n"


def _compile_with_row(cc: str, columns: dict[str, int]) -> subprocess.CompletedProcess[str]:
    """Compile ama_slhdsa.c with one row added to the head of SLH_PARAM_ROWS."""
    source = SLHDSA_C.read_text(encoding="utf-8")
    header = ROWS_HEADER.search(source)
    assert header is not None, "SLH_PARAM_ROWS is no longer defined in src/c/ama_slhdsa.c"
    return _compile(cc, source[: header.end()] + _row(columns) + source[header.end() :])


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_a_row_inside_every_bound_compiles(cc: str | None) -> None:
    """Non-vacuity: the harness compiles the real TU with a FIPS 205 row added."""
    compiler = _needs_compiler(cc)
    proc = _compile_with_row(compiler, SHAKE_192F)
    assert proc.returncode == 0, (
        f"{compiler}: src/c/ama_slhdsa.c with SLH-DSA-SHAKE-192f added to "
        f"SLH_PARAM_ROWS does not compile, so the rejections below would prove "
        f"nothing:\n{proc.stderr}"
    )


@pytest.mark.parametrize("cc", COMPILERS or [None])
@pytest.mark.parametrize("bound", sorted(OVER_BOUND_ROWS))
def test_a_row_over_a_bound_does_not_compile(cc: str | None, bound: str) -> None:
    compiler = _needs_compiler(cc)
    proc = _compile_with_row(compiler, OVER_BOUND_ROWS[bound])
    assert proc.returncode != 0, (
        f"{compiler}: a row exceeding {bound} compiled.  Every stack buffer in "
        f"src/c/ama_slhdsa.c that a row sizes or reads into is bounded, and each "
        f"row is checked against the bounds; a row past one must be a build "
        f"error, because at run time it is an overrun."
    )
    assert CHECK_MESSAGE in proc.stderr, (
        f"{compiler}: a row exceeding {bound} failed to compile, but not in the "
        f"table's bound check:\n{proc.stderr}"
    )


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_the_n_bound_cannot_outgrow_the_sha256_digest(cc: str | None) -> None:
    compiler = _needs_compiler(cc)
    source, count = MAX_N_DEFINE.subn(r"\g<1>33u", SLHDSA_C.read_text(encoding="utf-8"))
    assert count == 1, "SLH_MAX_N is no longer defined once in src/c/ama_slhdsa.c"
    proc = _compile(compiler, source)
    assert proc.returncode != 0, (
        f"{compiler}: src/c/ama_slhdsa.c compiled with SLH_MAX_N = 33.  sha2_F "
        f"and sha2_PRF copy n octets out of a 32-octet SHA-256 digest, and the "
        f"table's assertion holds a row's n only to SLH_MAX_N, so a raised bound "
        f"would admit a SHA-2 row that reads past the digest."
    )
    assert DIGEST_MESSAGE in proc.stderr, (
        f"{compiler}: SLH_MAX_N = 33 failed to compile, but not in the "
        f"assertion that holds it to the SHA-256 digest:\n{proc.stderr}"
    )


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_a_member_no_row_initializes_does_not_compile(cc: str | None) -> None:
    compiler = _needs_compiler(cc)
    source, count = STRUCT_END.subn(
        "    size_t probe_member;\n} slhdsa_params_t;", SLHDSA_C.read_text(encoding="utf-8")
    )
    assert count == 1, "slhdsa_params_t is no longer closed once in src/c/ama_slhdsa.c"
    proc = _compile(compiler, source, "-Werror=missing-field-initializers")
    assert proc.returncode != 0, (
        f"{compiler}: src/c/ama_slhdsa.c compiled with a slhdsa_params_t member "
        f"that no row initializes.  SLH_ROW_OBJECT's initializer must stay "
        f"positional: a designated one leaves the new member zero in every row, "
        f"and -Wextra says nothing."
    )
    assert "probe_member" in proc.stderr and "missing-field-initializers" in proc.stderr, (
        f"{compiler}: the member probe failed to compile, but not on the "
        f"uninitialized member:\n{proc.stderr}"
    )


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _closing_brace(text: str, opening: int) -> int:
    """The index just past the brace that closes the one at ``text[opening]``."""
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise AssertionError(f"the brace at offset {opening} is never closed")


def _mentions(text: str) -> tuple[list[str], list[str]]:
    """The rows ``text`` declares, and every other mention of the type in it.

    A mention of ``slhdsa_params_t`` or ``struct slhdsa_params`` declares no
    parameter object when it is a pointer type, the struct's definition or a
    declaration of its tag, or the typedef's own name.  One that begins a
    single-declarator declaration of ``SLHDSA_PARAMS_<name>`` is a row.  Any
    other -- an object, a by-value parameter, a compound literal, a typedef or
    ``#define`` renaming the type, ``sizeof`` of it -- is returned in context.
    """
    rows: list[str] = []
    others: list[str] = []
    for mention in TYPE_MENTION.finditer(text):
        after = mention.end()
        if POINTER.match(text, after):
            continue
        if mention.group(0).startswith("struct") and TAG_ONLY.match(text, after):
            continue
        before = text[max(0, mention.start() - 64) : mention.start()].rstrip()
        if before.endswith("}") and text[after : after + 64].lstrip().startswith(";"):
            continue
        row = ROW_DECLARATION.match(text, after)
        if row is not None:
            end = _closing_brace(text, row.end() - 1)
            if text[end : end + 64].lstrip().startswith(";"):
                rows.append(row.group(1))
                continue
        others.append(" ".join(text[mention.start() : mention.start() + 96].split()))
    return rows, others


def test_no_row_is_defined_outside_the_list() -> None:
    """Every slhdsa_params_t object in the source is SLH_ROW_OBJECT's."""
    source = _strip_comments(SLHDSA_C.read_text(encoding="utf-8"))
    row_object = re.search(r"^#define SLH_ROW_OBJECT\(.*?[^\\]\n", source, re.DOTALL | re.MULTILINE)
    assert row_object is not None, "SLH_ROW_OBJECT is no longer defined in src/c/ama_slhdsa.c"
    rows, others = _mentions(source[: row_object.start()] + source[row_object.end() :])
    assert not rows and not others, (
        f"src/c/ama_slhdsa.c uses slhdsa_params_t outside SLH_ROW_OBJECT as other "
        f"than a pointer: {rows + others}.  A parameter row belongs in "
        f"SLH_PARAM_ROWS, where the bound check reads it."
    )


def test_slh_lookup_returns_only_the_listed_rows() -> None:
    source = _strip_comments(SLHDSA_C.read_text(encoding="utf-8"))
    lookup = re.search(r"\bslh_lookup\s*\([^)]*\)\s*\{(.*?)\n\}", source, re.DOTALL)
    assert lookup is not None, "slh_lookup() is no longer defined in src/c/ama_slhdsa.c"
    body = re.sub(r"\s+", "", lookup.group(1))
    assert body == LOOKUP_BODY, (
        f"slh_lookup()'s body is {body!r}, not {LOOKUP_BODY!r}.  Its cases must "
        f"be expanded from SLH_PARAM_ROWS, so that every row it returns passed "
        f"the bound check, and anything else must reach default: return NULL."
    )


@pytest.mark.parametrize("cc", COMPILERS or [None])
@pytest.mark.parametrize("testing", [False, True], ids=["shipped", "testing"])
def test_every_compiled_row_is_a_listed_row(cc: str | None, testing: bool) -> None:
    compiler = _needs_compiler(cc)
    source = _strip_comments(SLHDSA_C.read_text(encoding="utf-8"))
    header = ROWS_HEADER.search(source)
    assert header is not None, "SLH_PARAM_ROWS is no longer defined in src/c/ama_slhdsa.c"
    body = ROWS_BODY.match(source, header.end())
    assert body is not None
    listed = sorted(f"SLHDSA_PARAMS_{name}" for name in ROW_NAME.findall(body.group(0)))
    # The two shipped rows, SHA2-256f and SHAKE-128s.
    assert len(listed) >= 2, f"only {listed} read off SLH_PARAM_ROWS; the pattern has stopped"
    command = [*_base_command(compiler), "-E", "-P", str(SLHDSA_C)]
    if testing:
        command.insert(1, "-DAMA_TESTING_MODE")
    proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
    assert proc.returncode == 0, f"{compiler}: could not preprocess ama_slhdsa.c:\n{proc.stderr}"
    rows, others = _mentions(proc.stdout)
    assert not others, (
        f"{compiler}: the preprocessed ama_slhdsa.c uses slhdsa_params_t as other "
        f"than a pointer or a listed row: {others}.  An object the list does not "
        f"hold is one the bound check never read; add it to SLH_PARAM_ROWS."
    )
    assert sorted(rows) == listed, (
        f"{compiler}: the preprocessed ama_slhdsa.c declares the rows "
        f"{sorted(rows)}, but SLH_PARAM_ROWS lists {listed}.  A row the list does "
        f"not hold is one the bound check never read; add it to the list."
    )
