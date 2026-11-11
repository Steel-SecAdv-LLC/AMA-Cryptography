# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every exported function is accounted for by the stack-scrub structure.

``tests/c/test_stack_scrub.c`` measures what a call leaves on the stack, one
row per entry point.  A measurement says nothing about an entry point that has
no row, and nothing at all on a host where the harness does not run.  This
file reads the same structure from the sources, where it can be read on every
host:

* **Classified.**  An export is a scrubbed entry point (its exit clears the
  stack below it), or it has a row of its own in the harness (the leaf
  helpers, and the forwarders: four generic entry points, named, and every
  export that is one call of a scrubbed one), or it is on the inventory below
  of functions that take no secret, with the reason.  Nothing is on two
  lists and the inventory names nothing that is not exported, so a new export
  is a failure here until it has been put somewhere.
* **Shaped.**  A scrubbed entry point is the two functions
  ``src/c/internal/ama_stack_wipe.h`` describes and nothing more: it calls an
  implementation that is never inlined, clears the stack, and returns what the
  implementation returned.  A statement added to the exported half is a value
  in the one frame nothing clears.
* **Held to its family.**  Each scrubbed entry point has a row in the harness
  that calls it and names the depth family its exit clears.
* **Cleared once.**  Code under ``src/c`` does not name a scrubbed entry
  point: it calls the inner function ``src/c/internal/ama_scrubbed_inner.h``
  declares, which is the same work with nothing cleared, because the entry
  point it runs under clears the whole depth.  The forwarders are the
  exception, and hybrid signing, which is built from two entry points.  Each
  inner function is declared there, kept out of the export table, and reached
  from its entry point through an implementation half that does nothing else.
* **Coherent.**  Both columns of the depth table give every family a depth,
  the unoptimised one never the shallower; every depth has exactly one frame
  function, declared, defined, kept out of the export table and measured by
  ``tests/c/test_stack_wipe_coverage.c``.

The inventory is a classification, not an exemption: the functions on it are
outside the rule because of what they are given, and each group says what
that is.  It was written by reading each prototype's documentation in
``include/ama_cryptography.h`` (2026-11-10).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
C_ROOT = REPO_ROOT / "src" / "c"
WIPE_HEADER = C_ROOT / "internal" / "ama_stack_wipe.h"
CONSTTIME = C_ROOT / "ama_consttime.c"
PUBLIC_HEADER = REPO_ROOT / "include" / "ama_cryptography.h"
EXPORT_MAP = REPO_ROOT / "cmake" / "ama_exports.map"
INNER_HEADER = C_ROOT / "internal" / "ama_scrubbed_inner.h"
HARNESS = REPO_ROOT / "tests" / "c" / "test_stack_scrub.c"
HARNESS_BUILD = REPO_ROOT / "tests" / "c" / "stack_scrub_build.h"
COVERAGE = REPO_ROOT / "tests" / "c" / "test_stack_wipe_coverage.c"

#: The depth of the exported ``ama_secure_stack_wipe()``; not a family.
EXPORTED_WIPE = "EXPORTED_WIPE"

#: The generic entry points of ``src/c/ama_core.c``.  They have rows that name
#: a family's depth and no wipe of their own, because they keep nothing of
#: their own: each hands its caller's pointers to an entry point that clears
#: (``ama_sign``'s hybrid branch through a pair inside it).  Named, so that an
#: entry point that loses its wipe is not taken for one of them.  The other
#: kind of forwarder needs no name: an export whose whole body is one call of
#: a scrubbed entry point (:func:`plain_forwards`), which is what the
#: ``ama_kyber_*`` and ``ama_dilithium_*`` names are to ``ama_ml_kem_*`` and
#: ``ama_ml_dsa_*``.  Those cleared their stack too until the instruction
#: counts showed each call zeroing its depth twice.
GENERIC_FORWARDERS = frozenset(
    {"ama_keypair_generate", "ama_sign", "ama_kem_encapsulate", "ama_kem_decapsulate"}
)

#: The one function that is no export and still calls scrubbed entry points.
#: Hybrid signing is an Ed25519 signature and an ML-DSA one; each of those
#: entry points clears its own depth, and the pair around them clears only
#: what it wrote outside them (the ``HYBRID`` depth, 2 KiB, where an inner
#: call of ML-DSA signing would make it 172).
NESTS_BY_DESIGN = frozenset({"hybrid_sign_body"})

#: Exports that take no secret and leave none, by what they are given.
NO_SECRET: dict[str, tuple[str, ...]] = {
    "verification: a public key, a message and a signature or share": (
        "ama_dilithium_verify",
        "ama_dilithium_verify_ctx",
        "ama_ed25519_batch_verify",
        "ama_ed25519_verify",
        "ama_frost_aggregate",
        "ama_frost_verify_share",
        "ama_hss_verify",
        "ama_lms_verify",
        "ama_ml_dsa_verify_ctx",
        "ama_ml_kem_pubkey_check",
        "ama_nistp_ecdsa_verify",
        "ama_nistp_ecdsa_verify_ex",
        "ama_nistp_ecdsa_verify_raw",
        "ama_nistp_ecdsa_verify_raw_ex",
        "ama_nistp_pubkey_validate",
        "ama_secp256k1_ecdsa_verify",
        "ama_secp256k1_ecdsa_verify_ex",
        "ama_slhdsa_verify",
        "ama_sphincs_verify",
        "ama_sphincs_verify_ctx",
        "ama_verify",
    ),
    "arithmetic documented as public-only, and the NTT benchmark surface": (
        "ama_dilithium_invntt_bench",
        "ama_dilithium_ntt_bench",
        "ama_ed25519_double_scalarmult_public",
        "ama_ed25519_point_add",
        "ama_ed25519_scalarmult_public",
    ),
    "encodings, sizes and names of public values": (
        "ama_agent_binding_encode",
        "ama_agent_binding_init",
        "ama_base64_encoded_len",
        "ama_hss_pubkey_levels",
        "ama_lms_pubkey_params",
        "ama_lms_signature_length",
        "ama_ml_dsa_param_set_name",
        "ama_ml_dsa_public_key_bytes",
        "ama_ml_dsa_secret_key_bytes",
        "ama_ml_dsa_signature_bytes",
        "ama_ml_kem_ciphertext_bytes",
        "ama_ml_kem_param_set_name",
        "ama_ml_kem_public_key_bytes",
        "ama_ml_kem_secret_key_bytes",
        "ama_nistp_curve_name",
        "ama_nistp_field_bytes",
        "ama_nistp_point_decode",
        "ama_nistp_point_encode",
        "ama_nistp_pubkey_bytes",
        "ama_nistp_sig_der_max_len",
        "ama_nistp_sig_der_to_raw",
        "ama_nistp_sig_raw_to_der",
        "ama_secp256k1_pubkey_decompress",
    ),
    "dispatch, build facts and diagnostics": (
        "ama_aes_gcm_active_backend",
        "ama_ct_hw_mode_control",
        "ama_ct_hw_mode_enable",
        "ama_ct_hw_mode_status",
        "ama_dilithium_invntt_bench_last_dispatch_get",
        "ama_dilithium_invntt_dispatch_slot_wired",
        "ama_dilithium_ntt_bench_last_dispatch_get",
        "ama_dilithium_ntt_dispatch_slot_wired",
        "ama_dispatch_active_slot",
        "ama_dispatch_init",
        "ama_dispatch_table_is_sealed",
        "ama_ed25519_active_backend",
        "ama_ed25519_active_fold",
        "ama_ed25519_set_avx2_fold_override",
        "ama_ed25519_set_mulx_override",
        "ama_get_dispatch_info",
        "ama_get_dispatch_table",
        "ama_impl_level_name",
        "ama_integrity_trust_anchor_pubkey_hex",
        "ama_lms_signing_available",
        "ama_print_dispatch_info",
        "ama_version_number",
        "ama_version_string",
        "ama_x25519_field_path",
        "ama_x25519_get_mulx_override",
        "ama_x25519_set_mulx_override",
    ),
    "state set up or released, given no input to absorb": (
        "ama_context_free",
        "ama_context_init",
        "ama_sha3_512_init",
        "ama_sha3_init",
        "ama_shake128_inc_init",
        "ama_shake256_inc_init",
    ),
    "memory utilities: they are given an address, not its contents": (
        "ama_secure_alloc",
        "ama_secure_free",
        "ama_secure_mlock",
        "ama_secure_munlock",
    ),
    "the operating system writes the output into the caller's buffer": ("ama_random_bytes",),
}


def _load_tool(name: str) -> ModuleType:
    """A gate script under ``tools/``, loaded by path (``tools`` is no package)."""
    path = REPO_ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_stack_scrub_surface_{name}", path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def exports() -> frozenset[str]:
    """The declared ABI: ``AMA_API`` in an installed header, not localised."""
    declared: frozenset[str] = _load_tool("check_export_allowlist").declared_abi(REPO_ROOT)
    return declared


def depth_columns() -> tuple[dict[str, int], dict[str, int]]:
    """The header's two depth tables: (optimised, unoptimised)."""
    text = WIPE_HEADER.read_text(encoding="utf-8")
    table = text.split("#if AMA_SCRUB_OPTIMISED_BUILD\n", 1)[1]
    optimised, rest = table.split("#else\n", 1)
    unoptimised = rest.split("#endif\n", 1)[0]
    row = re.compile(r"^#define AMA_SCRUB_([A-Z0-9_]+)_BYTES (\S+)$", re.MULTILINE)
    columns = []
    for block in (optimised, unoptimised):
        lines = [line for line in block.splitlines() if line.strip()]
        found = row.findall(block)
        assert len(found) == len(lines), "a line of the depth table is not a depth"
        assert all(value.isdigit() for _, value in found), found
        columns.append({family: int(value) for family, value in found})
    return columns[0], columns[1]


def _enclosing_function(lines: list[str], index: int) -> str:
    """The function a line belongs to: the nearest definition header above it."""
    for line in reversed(lines[:index]):
        if line and not line[0].isspace() and not line.startswith(("/", "*", "#", "{", "}")):
            match = re.search(r"\b(\w+)\s*\(", line)
            if match:
                return match.group(1)
    raise AssertionError(f"no function above line {index + 1}")


def wipe_sites() -> dict[str, list[tuple[str, str]]]:
    """function -> [(file, depth name)] for every AMA_STACK_WIPE_BELOW use."""
    use = re.compile(r"AMA_STACK_WIPE_BELOW\(AMA_SCRUB_([A-Z0-9_]+)_BYTES\)")
    sites: dict[str, list[tuple[str, str]]] = {}
    total = 0
    for source in sorted(C_ROOT.rglob("*.c")):
        text = source.read_text(encoding="utf-8")
        lines = text.splitlines()
        for index, line in enumerate(lines):
            match = use.search(line)
            if match:
                sites.setdefault(_enclosing_function(lines, index), []).append(
                    (source.name, match.group(1))
                )
        # "AMA_STACK_WIPE_BELOW()" is how the comments name the macro.
        total += len(re.findall(r"AMA_STACK_WIPE_BELOW\((?!\))", text))
    assert total == sum(
        len(found) for found in sites.values()
    ), "an AMA_STACK_WIPE_BELOW use does not name an AMA_SCRUB_*_BYTES depth"
    return sites


def plain_forwards() -> dict[str, str]:
    """export -> the one function it calls, for exports that do nothing else."""
    shape = re.compile(
        r"^AMA_API [\w \*]+?\b(ama_\w+)\([^;{}]*\)\s*\{\n"
        r"\s+return (ama_\w+)\([^;{}]*\);\n"
        r"\}\n",
        re.MULTILINE,
    )
    forwards: dict[str, str] = {}
    for source in sorted(C_ROOT.rglob("*.c")):
        for name, callee in shape.findall(source.read_text(encoding="utf-8")):
            forwards[name] = callee
    return forwards


def _code(text: str) -> str:
    """C source with comments and string literals blanked, positions kept."""

    def spaces(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", spaces, text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", spaces, text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', spaces, text)


def mentions_of_scrubbed_entry_points(exports: frozenset[str]) -> list[tuple[str, int, str, str]]:
    """(file, line, entry point, where) for each use of one in ``src/c`` code.

    A use is the name anywhere but at the start of its own declaration or
    definition: a call, a function pointer, or a macro that expands to either
    (``where`` is then ``#define``).
    """
    scrubbed = sorted(n for n in wipe_sites() if n in exports and n != "ama_secure_stack_wipe")
    name = re.compile(
        r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, scrubbed)) + r")(?![A-Za-z0-9_])"
    )
    found = []
    for source in sorted([*C_ROOT.rglob("*.c"), *C_ROOT.rglob("*.h")]):
        lines = _code(source.read_text(encoding="utf-8")).splitlines()
        for index, line in enumerate(lines):
            if not line[:1].isspace() and not line.startswith("#"):
                continue  # a declaration, or a definition's first line
            for match in name.finditer(line):
                where = "#define" if line.startswith("#") else _enclosing_function(lines, index)
                found.append((source.name, index + 1, match.group(1), where))
    return found


def inner_functions() -> dict[str, tuple[str, bool]]:
    """inner function -> (file, is static), for every definition in ``src/c``."""
    # At column 0: an indented line that ends a condition looks the same.
    definition = re.compile(
        r"^(static )?\w[\w \*]*?\b(ama_\w+_inner)\([^;{}]*\)\s*\{", re.MULTILINE
    )
    found: dict[str, tuple[str, bool]] = {}
    for source in sorted(C_ROOT.rglob("*.c")):
        for static, name in definition.findall(_code(source.read_text(encoding="utf-8"))):
            assert name not in found, f"{name} is defined twice"
            found[name] = (source.name, bool(static))
    return found


def _arguments(text: str, start: int) -> list[str]:
    """The top-level arguments of the parenthesis opening at ``text[start]``."""
    assert text[start] == "("
    depth, current, found = 0, "", []
    for char in text[start:]:
        if char == "(":
            depth += 1
            if depth == 1:
                continue
        elif char == ")":
            depth -= 1
            if depth == 0:
                found.append(current)
                return found
        if char == "," and depth == 1:
            found.append(current)
            current = ""
        else:
            current += char
    raise AssertionError("unbalanced parenthesis")


def harness_rows() -> dict[str, set[str]]:
    """entry point -> the depths its rows name ("0" for a leaf helper)."""
    text = HARNESS.read_text(encoding="utf-8")
    rows: dict[str, set[str]] = {}
    for match in re.finditer(r"^\s*V?ROW(\()", text, re.MULTILINE):
        arguments = _arguments(text, match.start(1))
        assert len(arguments) >= 4, arguments
        name, depth = arguments[0].strip(), arguments[1].strip()
        called = re.search(r"\b(ama_\w+)\s*\(", ",".join(arguments[3:]))
        assert called, f"row {name} calls no ama_* function"
        family = re.fullmatch(r"scrub_depth_([A-Z0-9_]+)|0", depth)
        assert family, f"row {name} names no depth: {depth!r}"
        assert name.startswith(called.group(1)), f"row {name} calls {called.group(1)}"
        rows.setdefault(called.group(1), set()).add(family.group(1) or "0")
    return rows


def test_both_columns_give_every_family_a_depth() -> None:
    optimised, unoptimised = depth_columns()
    assert optimised and list(optimised) == list(unoptimised)
    shallower = {f for f in optimised if unoptimised[f] < optimised[f]}
    assert not shallower, f"the unoptimised column is shallower for {sorted(shallower)}"
    families = re.search(
        r"#define SCRUB_FAMILIES\(X\)(.*?)\n\n", HARNESS_BUILD.read_text(encoding="utf-8"), re.S
    )
    assert families
    assert sorted(re.findall(r"X\((\w+)\)", families.group(1))) == sorted(optimised)


def test_every_depth_has_exactly_one_frame_function() -> None:
    optimised, unoptimised = depth_columns()
    header = WIPE_HEADER.read_text(encoding="utf-8")
    exported = re.search(r"^#define AMA_SCRUB_EXPORTED_WIPE_BYTES (\d+)$", header, re.MULTILINE)
    public = re.search(
        r"^#define AMA_STACK_WIPE_BYTES (\d+)u$",
        PUBLIC_HEADER.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert exported and public and exported.group(1) == public.group(1)
    depths = sorted({*optimised.values(), *unoptimised.values(), int(exported.group(1))})
    declared = [
        int(d) for d in re.findall(r"^void ama_stack_wipe_frame_(\d+)\(void\);$", header, re.M)
    ]
    defined = [
        int(d)
        for d in re.findall(
            r"^AMA_STACK_WIPE_FRAME\((\d+)\)$", CONSTTIME.read_text(encoding="utf-8"), re.M
        )
    ]
    localised = [
        int(d)
        for d in re.findall(
            r"^\s*ama_stack_wipe_frame_(\d+);$", EXPORT_MAP.read_text(encoding="utf-8"), re.M
        )
    ]
    measured = re.search(
        r"#define WIPE_DEPTHS\(X\)(.*?)\n\n", COVERAGE.read_text(encoding="utf-8"), re.S
    )
    assert measured
    assert declared == defined == localised == depths
    assert [int(d) for d in re.findall(r"X\((\d+)\)", measured.group(1))] == depths
    assert all(depth % 64 == 0 for depth in depths)


def test_every_export_is_classified_once(exports: frozenset[str]) -> None:
    sites = wipe_sites()
    rows = harness_rows()
    scrubbed = {name for name in sites if name in exports}
    inventory = [name for names in NO_SECRET.values() for name in names]
    assert len(inventory) == len(set(inventory)), "a name is on the inventory twice"
    assert all(list(names) == sorted(names) for names in NO_SECRET.values())
    stale = set(inventory) - exports
    assert not stale, f"on the inventory and not exported: {sorted(stale)}"
    both = set(inventory) & (scrubbed | set(rows))
    assert not both, f"on the inventory and also scrubbed or measured: {sorted(both)}"
    unclassified = exports - scrubbed - set(rows) - set(inventory)
    assert not unclassified, (
        "exported, and neither a scrubbed entry point, nor measured by a row of "
        f"tests/c/test_stack_scrub.c, nor on the no-secret inventory: {sorted(unclassified)}"
    )
    unknown = set(rows) - exports
    assert not unknown, f"a row calls something that is not exported: {sorted(unknown)}"


def test_a_scrubbed_entry_point_has_a_row_that_names_its_family(exports: frozenset[str]) -> None:
    optimised, _ = depth_columns()
    sites = wipe_sites()
    rows = harness_rows()
    for name in sorted(n for n in sites if n in exports):
        families = {family for _, family in sites[name]}
        if name == "ama_secure_stack_wipe":
            assert families == {EXPORTED_WIPE}
            assert "ama_secure_stack_wipe()" in COVERAGE.read_text(encoding="utf-8")
            continue
        assert len(sites[name]) == 1, f"{name} clears its stack {len(sites[name])} times"
        assert families <= set(optimised), f"{name} clears a depth that is no family: {families}"
        assert (
            rows.get(name) == families
        ), f"{name} clears {sorted(families)}; its rows name {sorted(rows.get(name, ()))}"
    # A row for a function with no wipe of its own is a leaf helper's, which
    # names no depth, or a forwarder's, which names the depth of what it
    # reaches: a generic entry point, or an export that is one call of a
    # scrubbed one and so clears exactly what that one clears.  Anything else
    # is an entry point whose wipe has gone.
    forwards = plain_forwards()
    plain = 0
    for name, named in rows.items():
        assert named <= set(optimised) | {"0"}, (name, named)
        if name in sites:
            continue
        assert len(named) == 1, (name, named)
        if forwards.get(name) in sites:
            assert named == {family for _, family in sites[forwards[name]]}, (name, named)
            plain += 1
            continue
        generic = name in GENERIC_FORWARDERS
        assert (
            named == {"0"}
        ) != generic, f"{name} has a row naming {sorted(named)} and does not clear its stack"
    assert GENERIC_FORWARDERS <= set(rows), sorted(GENERIC_FORWARDERS - set(rows))
    assert plain >= 11, plain


def test_a_wipe_that_is_not_an_exports_exit_is_accounted_for(exports: frozenset[str]) -> None:
    """A family depth is cleared at the exit of a pair.  Where the pair is not
    itself exported (hybrid signing, inside ``ama_sign``), a row still names
    that family, so the harness measures it.  A wipe issued from anywhere else
    (SLH-DSA's two error exits) uses the exported depth, which promises
    nothing about a family."""
    named = {family for families in harness_rows().values() for family in families}
    for name, found in wipe_sites().items():
        if name in exports:
            continue
        families = {family for _, family in found}
        assert families == {EXPORTED_WIPE} or (len(found) == 1 and families <= named), (
            name,
            found,
        )


def test_a_scrubbed_entry_point_is_two_functions_and_nothing_more() -> None:
    """The exported half calls the implementation, clears, and returns.

    Anything else in it is a value in the one frame nothing clears.  The
    implementation is declared ``AMA_SCRUBBED_BODY``: inlined, its frame would
    be the exported function's own.
    """
    exit_shape = re.compile(
        r"\) \{\n"
        r"    (?:(?:const )?\w[\w ]*?\**\s*rc = )?(?P<body>\w+)\((?P<args>[^;{}]*)\);\n"
        r"    AMA_STACK_WIPE_BELOW\(AMA_SCRUB_(?P<family>[A-Z0-9_]+)_BYTES\);\n"
        r"(?:    return rc;\n)?"
        r"\}\n"
    )
    family_use = re.compile(r"AMA_STACK_WIPE_BELOW\(AMA_SCRUB_(?!EXPORTED_WIPE_)[A-Z0-9_]+_BYTES\)")
    checked = 0
    for source in sorted(C_ROOT.rglob("*.c")):
        text = source.read_text(encoding="utf-8")
        shaped = [m for m in exit_shape.finditer(text) if m.group("family") != EXPORTED_WIPE]
        assert len(shaped) == len(
            family_use.findall(text)
        ), f"{source.name}: a family depth is cleared outside the two-function shape"
        for match in shaped:
            body = match.group("body")
            assert re.search(
                rf"^static AMA_SCRUBBED_BODY [\w \*]+?\b{body}\(", text, re.MULTILINE
            ), f"{source.name}: {body} is not declared AMA_SCRUBBED_BODY"
            assert "&" not in match.group("args"), f"{source.name}: {body} is handed a local"
            checked += 1
    assert checked >= 90, checked


def test_library_code_does_not_call_a_scrubbed_entry_point(exports: frozenset[str]) -> None:
    """One call of the public function clears the stack once.

    A scrubbed entry point named from inside the library clears its depth
    under a caller that will clear it again, or under verification, which has
    nothing to clear.  Measured 2026-11-10 while the public names were still
    what the library called: 24% more instructions for SLH-DSA-SHAKE-128s key
    generation and for its verification, and thirteen wipes for one
    HKDF-SHA3-256 derivation (``src/c/internal/ama_scrubbed_inner.h``).
    """
    forwarders = GENERIC_FORWARDERS | set(plain_forwards()) | NESTS_BY_DESIGN
    nested = [
        f"{file}:{line}: {name} in {where}"
        for file, line, name, where in mentions_of_scrubbed_entry_points(exports)
        if where not in forwarders
    ]
    assert not nested, (
        "library code names a scrubbed entry point; call its inner function "
        "(src/c/internal/ama_scrubbed_inner.h):\n  " + "\n  ".join(nested)
    )
    # The exceptions are in use, or the list above has outlived them.
    used = {where for *_, where in mentions_of_scrubbed_entry_points(exports)}
    assert NESTS_BY_DESIGN <= used and GENERIC_FORWARDERS & used, sorted(used)


def test_an_inner_function_is_the_work_of_one_entry_point(exports: frozenset[str]) -> None:
    """Declared, kept off the ABI, and reached through a half that is only a call.

    The implementation half an entry point calls is never inlined, so that its
    frame is dead when the entry point clears the stack.  An inner function
    carries no such attribute: the half is ``return x_inner(...)`` and nothing
    else, and anything more in it would be work the library's own callers of
    ``x_inner`` do not get.
    """
    inner = inner_functions()
    sites = wipe_sites()
    declared = set(
        re.findall(
            r"^[\w \*]+?\b(ama_\w+_inner)\(", _code(INNER_HEADER.read_text(encoding="utf-8")), re.M
        )
    )
    shared = {name for name, (_, static) in inner.items() if not static}
    assert declared == shared, (
        f"declared in {INNER_HEADER.name} and not defined, or defined for other "
        f"files and not declared: {sorted(declared ^ shared)}"
    )
    localised: frozenset[str] = _load_tool("check_public_api_docs").localised_symbols(REPO_ROOT)
    assert shared <= localised, f"would be exported: {sorted(shared - localised)}"
    assert not shared & exports
    for name, (file, _) in sorted(inner.items()):
        entry = name.removesuffix("_inner")
        assert entry in exports and entry in sites, f"{name}: {entry} is no scrubbed entry point"
        text = (C_ROOT / file).read_text(encoding="utf-8")
        half = re.search(
            rf"^static AMA_SCRUBBED_BODY [\w \*]+?\b{entry}_body\([^;{{}}]*\) \{{\n"
            rf"    (?:return )?{name}\([^;{{}}]*\);\n\}}\n",
            text,
            re.MULTILINE,
        )
        assert half, f"{file}: {entry}_body is not one call of {name}"
        assert not re.search(
            rf"AMA_SCRUBBED_BODY[^;{{}}]*\b{name}\(", text
        ), f"{name} must be free to be inlined into the library's own callers"
    assert len(inner) >= 25, len(inner)
