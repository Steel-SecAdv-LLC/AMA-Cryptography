# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The native repeated-output check says what it does, and does it (INVARIANT-53).

Each property ``include/ama_cryptography.h`` documents for
``ama_random_bytes_repeat_checked`` and ``ama_rng_repeat_check`` (the limits the
check does not provide, the window, the return codes, thread and fork safety,
constant time) is resolved two ways: the sentence must be in the header and,
for the C API page, the wiki, and the SHIPPED shared object, driven in a child
process so the baseline is fresh, must behave as the sentence says. The
AMA_TESTING_MODE seams must be absent from that object, and no exported name
says "health" (INVARIANT-16, INVARIANT-37).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import native_library_path

REPO_ROOT = Path(__file__).resolve().parent.parent
HEADER = REPO_ROOT / "include" / "ama_cryptography.h"
WIKI = REPO_ROOT / "wiki" / "C-API-Reference.md"
EXPORT_MAP = REPO_ROOT / "cmake" / "ama_exports.map"
ROOT_CMAKE = REPO_ROOT / "CMakeLists.txt"
CT_GATE = REPO_ROOT / "tools" / "check_ghash_constant_time.py"
DUDECT = REPO_ROOT / ".github" / "workflows" / "dudect.yml"
STATIC_ANALYSIS = REPO_ROOT / ".github" / "workflows" / "static-analysis.yml"
TESTS_CMAKE = REPO_ROOT / "tests" / "c" / "CMakeLists.txt"

#: Test-only symbols: compiled under AMA_TESTING_MODE, absent from the shipped
#: object, localised by the version script anyway.
TEST_ONLY_FUNCTIONS = (
    "ama_rng_repeat_baseline_for_test",
    "ama_rng_repeat_reset_for_test",
    "ama_rng_repeat_lock_busy_for_test",
    "ama_rng_repeat_compare_for_test",
    "ama_rng_repeat_instrument_probe_for_test",
)
TEST_ONLY_VARIABLES = (
    "ama_rng_repeat_randombytes_hook",
    "ama_rng_repeat_lock_hook",
    "ama_rng_repeat_compare_hook",
    "ama_rng_repeat_critical_hook",
    "ama_rng_repeat_atfork_gate",
    "ama_rng_repeat_lock_acquisitions",
    "ama_rng_repeat_lock_releases",
    "ama_rng_repeat_lock_violations",
)

#: NIST CAVP SHA256ShortMsg.rsp, "Len = 256" (shabytetestvectors.zip on
#: csrc.nist.gov): the message and its digest.  They are held here and in
#: tests/c/test_rng_repeat.c, which this test reads back, so an edit to either
#: copy fails a test (INVARIANT-44: a vector is pinned by its bytes).
CAVP_SHA256_LEN256_MSG = "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95"
CAVP_SHA256_LEN256_MD = "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"

#: Run in a child process against the shipped library.  Prints one JSON object
#: of observations.  Windows are built from a tag so they never collide.
_CHILD = r"""
import ctypes, json, sys

lib = ctypes.CDLL(sys.argv[1])
check = lib.ama_rng_repeat_check
check.argtypes = [ctypes.c_char_p]
check.restype = ctypes.c_int
fused = lib.ama_random_bytes_repeat_checked
fused.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
fused.restype = ctypes.c_int

def window(tag):
    return bytes((tag * 37 + i * 11 + 5) & 0xFF for i in range(32))

A, B, C = window(1), window(2), window(3)
obs = {}
# Fresh process: the very first call has no baseline.
obs["first_call_rc"] = check(A)
obs["repeat_rc"] = check(A)
obs["repeat_again_rc"] = check(A)          # baseline unchanged by the refusal
obs["after_repeat_new_window_rc"] = check(B)   # nothing latched
obs["consecutive_only_rc"] = check(A)      # A, B, A: the old window passes
obs["null_window_rc"] = lib.ama_rng_repeat_check(None)
# Another caller replaces the baseline: C, then A is no longer "the previous".
check(C)
obs["overwritten_baseline_rc"] = check(A)
obs["fused_null_rc"] = fused(None, 4)
buf = ctypes.create_string_buffer(48)
obs["fused_len48_rc"] = fused(buf, 48)
first = bytes(buf.raw)
obs["fused_len48_second_rc"] = fused(buf, 48)
obs["fused_windows_differ"] = first[:32] != bytes(buf.raw)[:32]
# Which bytes of a draw are the window: for len >= 32 the FIRST 32.  Drawn
# 48 bytes, the first 32 are the previous window (a repeat, baseline kept);
# the last 32 are not.  Order matters: the refusal leaves the baseline alone.
buf3 = ctypes.create_string_buffer(48)
fused(buf3, 48)
w3 = bytes(buf3.raw)
obs["fused_window_is_first32_rc"] = check(w3[:32])
obs["fused_window_not_last32_rc"] = check(w3[16:48])
obs["fused_len0_rc"] = fused(None, 0)
obs["fused_len5_rc"] = fused(buf, 5)
missing = []
for name in sys.argv[2].split(","):
    try:
        getattr(lib, name)
    except AttributeError:
        missing.append(name)
obs["absent_functions"] = missing
absent_vars = []
for name in sys.argv[3].split(","):
    try:
        ctypes.c_void_p.in_dll(lib, name)
    except ValueError:
        absent_vars.append(name)
obs["absent_variables"] = absent_vars
print(json.dumps(obs))
"""


def _flat(text: str) -> str:
    """Comment framing and line breaks collapsed to single spaces."""
    return re.sub(r"\s*\n\s*(?:\*\s*)?", " ", text)


def _header_block() -> str:
    """The doc comments and declarations of the two functions, flattened."""
    text = HEADER.read_text(encoding="utf-8")
    start = text.index("@brief ama_random_bytes() with a repeated-output check")
    start = text.rindex("/**", 0, start)
    end_marker = "AMA_API ama_error_t ama_rng_repeat_check(const uint8_t window[32]);"
    end = text.index(end_marker) + len(end_marker)
    return _flat(text[start:end])


def _wiki_section() -> str:
    text = WIKI.read_text(encoding="utf-8")
    start = text.index("## Random Number Generation")
    end = text.index("## Hash Functions")
    return _flat(text[start:end])


@pytest.fixture(scope="module")
def shipped() -> dict[str, Any]:
    lib = native_library_path(REPO_ROOT / "ama_cryptography")
    if lib is None:
        pytest.skip("native library not built in this tree")
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _CHILD,
            str(lib),
            ",".join(TEST_ONLY_FUNCTIONS),
            ",".join(TEST_ONLY_VARIABLES),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"the child could not drive {lib}: {proc.stderr[-2000:]}\n"
        "(a library built before ama_rng_repeat.c joined the tree lacks the symbols; rebuild it)"
    )
    observed: dict[str, Any] = json.loads(proc.stdout.strip().splitlines()[-1])
    return observed


#: Documented claim -> (a pattern the header must contain, the observation that
#: resolves it against the shipped object, the value the claim requires).
#: A claim that has a sentence and no observation, or the other way round, is
#: the drift this test exists for.
CLAIMS: list[tuple[str, str, str, int]] = [
    (
        "the first call of a process passes unchecked",
        r"first call in a process has no previous window",
        "first_call_rc",
        0,
    ),
    (
        "a repeated window is refused with AMA_ERROR_RNG_REPEAT (-10)",
        r"AMA_ERROR_RNG_REPEAT",
        "repeat_rc",
        -10,
    ),
    (
        "the refusal leaves the baseline unchanged",
        r"baseline is unchanged",
        "repeat_again_rc",
        -10,
    ),
    (
        "nothing latches after a repeat",
        r"Nothing latches",
        "after_repeat_new_window_rc",
        0,
    ),
    (
        "only consecutive windows are compared (A, B, A passes)",
        r"Only consecutive windows are compared",
        "consecutive_only_rc",
        0,
    ),
    (
        "any caller of ama_rng_repeat_check replaces the process-wide baseline",
        r"any code in the process can replace it by calling ama_rng_repeat_check",
        "overwritten_baseline_rc",
        0,
    ),
    (
        "a NULL window is refused",
        r"AMA_ERROR_INVALID_PARAM if @p window is NULL",
        "null_window_rc",
        -1,
    ),
    (
        "a NULL buffer with len > 0 is refused",
        r"AMA_ERROR_INVALID_PARAM for NULL with len > 0",
        "fused_null_rc",
        -1,
    ),
    (
        "for len >= 32 the first 32 bytes of the draw are the window",
        r"its first 32 bytes are the window",
        "fused_window_is_first32_rc",
        -10,
    ),
    (
        "... and the last 32 bytes of a longer draw are not",
        r"its first 32 bytes are the window",
        "fused_window_not_last32_rc",
        0,
    ),
    (
        "len == 0 still draws and checks a window",
        r"0 still draws and checks a window",
        "fused_len0_rc",
        0,
    ),
]


@pytest.mark.parametrize(("claim", "header_pattern", "key", "expected"), CLAIMS)
def test_each_documented_claim_is_in_the_header_and_true_of_the_shipped_object(
    shipped: dict[str, Any], claim: str, header_pattern: str, key: str, expected: int
) -> None:
    """Each documented claim is in the header and true of the shipped object (INVARIANT-53)."""
    assert re.search(
        header_pattern, _header_block()
    ), f"the header no longer says: {claim} (pattern {header_pattern!r})"
    assert (
        shipped[key] == expected
    ), f"the header says '{claim}'; the shipped object returned {shipped[key]!r} for {key}"


def test_the_real_source_issues_distinct_windows_and_refuses_none(
    shipped: dict[str, Any],
) -> None:
    """[SMOKE] Real OS draws through the shipped fused entry point."""
    assert shipped["fused_len48_rc"] == 0
    assert shipped["fused_len48_second_rc"] == 0
    assert shipped["fused_windows_differ"] is True
    assert shipped["fused_len5_rc"] == 0


def test_no_test_seam_is_in_the_shipped_object(shipped: dict[str, Any]) -> None:
    """A baseline observer, a reset or a hook in the shipped ABI would read or
    blind process-wide RNG state; they exist under AMA_TESTING_MODE only."""
    assert sorted(shipped["absent_functions"]) == sorted(TEST_ONLY_FUNCTIONS)
    assert sorted(shipped["absent_variables"]) == sorted(TEST_ONLY_VARIABLES)


def test_the_test_only_functions_are_localised_by_the_version_script() -> None:
    text = EXPORT_MAP.read_text(encoding="utf-8")
    local = text[text.index("local:") :]
    for name in TEST_ONLY_FUNCTIONS:
        assert re.search(rf"^\s*{name};", local, re.MULTILINE), name


class TestWording:
    """The wording the maintainers fixed before the ABI froze."""

    def test_no_public_name_says_health(self) -> None:
        text = HEADER.read_text(encoding="utf-8")
        names = re.findall(r"AMA_API\s+[\w\s\*]*?\b(ama_\w+)\s*\(", text)
        assert "ama_random_bytes_repeat_checked" in names
        assert "ama_rng_repeat_check" in names
        assert [n for n in names if "health" in n.lower()] == []
        assert "AMA_ERROR_RNG_REPEAT" in text
        assert not re.search(r"AMA_ERROR_\w*HEALTH", text, re.IGNORECASE)

    def test_the_header_uses_the_word_only_to_deny_it(self) -> None:
        block = _header_block()
        uses = [m.start() for m in re.finditer(r"health", block, re.IGNORECASE)]
        assert len(uses) == 1, "the block uses the word more than once"
        context = block[max(0, uses[0] - 40) : uses[0] + 20]
        assert re.search(r"not a FIPS 140-3 health test", context), context

    def test_the_wiki_states_the_same_limits_and_the_stale_sentence_is_gone(self) -> None:
        wiki = _wiki_section()
        assert "There is no public RNG entry point" not in wiki
        for fragment in (
            "ama_random_bytes_repeat_checked",
            "ama_rng_repeat_check",
            "not** a FIPS 140-3 RNG health test",
            "one value for the whole process",
            "any code in the process can replace it",
            "first call in a process passes unchecked",
            "Nothing latches",
            "consecutive",
            "dlclose",
        ):
            assert fragment in wiki, fragment
        assert "AMA_ERROR_RNG_REPEAT" in WIKI.read_text(encoding="utf-8")

    def test_the_header_states_the_fork_and_dlclose_contract(self) -> None:
        """The header states the fork and dlclose contract in the direction it is true."""
        block = _header_block()
        assert "fork()" in block
        assert "pthread_atfork" in block
        assert "a library that has been used must not be dlclose()d" in block
        assert "may be dlclose()d" not in block
        assert "Windows has no fork()" in block

    def test_the_wiki_states_the_dlclose_contract_in_the_same_direction(self) -> None:
        wiki = _wiki_section()
        assert "do not `dlclose()` the library once it has been used" in wiki
        assert "may `dlclose()`" not in wiki

    def test_the_null_contract_is_stated_exactly(self) -> None:
        """NULL is acceptable only for len == 0, worded as a sentence."""
        block = _header_block()
        assert "@param buf Output buffer (may be NULL only when len is 0)" in block
        assert "AMA_ERROR_INVALID_PARAM for NULL with len > 0" in block
        assert "NULL with len > 0" in block
        assert "may be NULL when len is" not in block

    #: The @return of each function as the header words it, whole.  The set of
    #: codes and the condition each is returned under are the contract; a
    #: sentence that drifts from the object (an enumeration that says a code is
    #: never returned, a condition dropped) fails here.
    FUSED_RETURN = (
        "@return AMA_SUCCESS; AMA_ERROR_INVALID_PARAM for NULL with len > 0; "
        "AMA_ERROR_RNG_REPEAT if the window repeated the previous one; "
        "AMA_ERROR_CRYPTO if the OS source failed, the lock that makes the check "
        "atomic could not be taken, or (POSIX) the fork handlers could not be "
        "registered (the draw is refused, not issued unchecked)."
    )
    CHECK_RETURN = (
        "@return AMA_SUCCESS; AMA_ERROR_INVALID_PARAM if @p window is NULL; "
        "AMA_ERROR_RNG_REPEAT if its digest equals the baseline (which is then left "
        "unchanged); AMA_ERROR_CRYPTO if the lock could not be taken or (POSIX) the "
        "fork handlers could not be registered (the window is refused, not accepted "
        "unchecked)."
    )

    def test_the_return_enumerations_are_exact(self) -> None:
        block = _header_block()
        assert self.FUSED_RETURN in block
        assert self.CHECK_RETURN in block
        # Every code a function returns is one the header lists for it.
        for ret in (self.FUSED_RETURN, self.CHECK_RETURN):
            assert set(re.findall(r"\bAMA_(?:SUCCESS|ERROR_\w+)", ret)) == {
                "AMA_SUCCESS",
                "AMA_ERROR_INVALID_PARAM",
                "AMA_ERROR_RNG_REPEAT",
                "AMA_ERROR_CRYPTO",
            }

    def test_the_wiki_lists_the_failure_that_a_registration_failure_returns(self) -> None:
        wiki = _wiki_section()
        assert "(POSIX) when the `fork()` handlers could not be registered" in wiki
        assert "a failed registration stays failed for the life of the process" in wiki

    def test_the_cavp_vector_in_the_c_test_is_the_one_fetched(self) -> None:
        """INVARIANT-44: the C test's CAVP arrays are the published message and digest."""
        src = (TESTS_CMAKE.parent / "test_rng_repeat.c").read_text(encoding="utf-8")

        def array(name: str) -> str:
            m = re.search(rf"{name}\[32\] = \{{([^}}]*)\}}", src)
            assert m is not None, name
            return "".join(
                f"{int(b, 16):02x}" for b in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
            )

        assert array("cavp_msg") == CAVP_SHA256_LEN256_MSG
        assert array("cavp_md") == CAVP_SHA256_LEN256_MD

    def test_the_window_is_the_first_32_bytes_in_the_header_and_the_wiki(self) -> None:
        """The window is the FIRST 32 bytes of a draw, in the header and the wiki."""
        block = _header_block()
        assert (
            "For len >= 32 the draw is made straight into @p buf and its first 32 "
            "bytes are the window." in block
        )
        assert "last 32 bytes are the window" not in block
        assert "For len < 32, including len == 0, a separate 32-byte draw is the window" in block
        wiki = _wiki_section()
        assert "For `len >= 32` the window is the first 32 bytes of `buf`" in wiki
        assert "the window is the last 32 bytes" not in wiki

    def test_the_atomicity_claim_is_a_sentence_in_both_places_and_has_its_c_pins(self) -> None:
        """The "one atomic step" claim is a sentence here; the C suites pin the property."""
        block = _header_block()
        assert (
            "The comparison and the update are one atomic step, the call is safe from any" in block
        )
        assert "number of threads" in block
        assert "two steps" not in block and "not atomic" not in block
        wiki = _wiki_section()
        assert "It is thread-safe, and on POSIX a `fork()`" in wiki
        assert "not thread-safe" not in wiki
        assert "the lock that makes the check atomic" in wiki
        cmake = TESTS_CMAKE.read_text(encoding="utf-8")
        for target in ("test_rng_repeat", "test_rng_repeat_concurrent"):
            assert re.search(rf"^\s*add_ama_test\({target}\s", cmake, re.MULTILINE), target
        conc = (TESTS_CMAKE.parent / "test_rng_repeat_concurrent.c").read_text(encoding="utf-8")
        assert "ama_rng_repeat_lock_acquisitions" in conc
        assert "ama_rng_repeat_lock_violations" in conc

    def test_the_constant_time_claim_is_a_sentence_and_has_its_gate(self) -> None:
        """The constant-time claims have a sentence, a constant-time compare and a gate."""
        block = _header_block()
        assert (
            "SHA-256 of the window is compared in constant time with the digest of the window "
            "of the previous draw" in block
        )
        assert "compares the digest in constant time with the process-wide baseline" in block
        unit = (REPO_ROOT / "src" / "c" / "ama_rng_repeat.c").read_text(encoding="utf-8")
        assert re.search(r"return ama_consttime_memcmp;", unit)
        gate = CT_GATE.read_text(encoding="utf-8")
        assert re.search(r'^\s+"rng-repeat": 0,$', gate, re.MULTILINE)
        assert re.search(r'^\s+"rng-repeat": _RNG_REPEAT_DRIVER,$', gate, re.MULTILINE)
        workflow = DUDECT.read_text(encoding="utf-8")
        assert re.search(r"--target rng-repeat\s*$", workflow, re.MULTILINE), "count lane"
        assert re.search(r"\brng-repeat\b[^\n]*;\s*do", workflow), "taint lane"

    def test_the_enum_value_is_appended_after_the_last_one(self) -> None:
        text = HEADER.read_text(encoding="utf-8")
        values = dict(re.findall(r"\b(AMA_(?:SUCCESS|ERROR_\w+))\s*=\s*(-?\d+)", text))
        assert values["AMA_ERROR_ETHICAL_BINDING"] == "-9"
        assert values["AMA_ERROR_RNG_REPEAT"] == "-10"


class TestWiring:
    """The new translation unit and its tests are in the lists that build them."""

    def test_the_unit_is_in_the_native_source_list(self) -> None:
        text = ROOT_CMAKE.read_text(encoding="utf-8")
        native = text[text.index("if(AMA_USE_NATIVE_PQC)\n    list(APPEND AMA_SOURCES") :]
        native = native[: native.index("endif()")]
        assert "src/c/ama_rng_repeat.c" in native
        assert "src/c/ama_platform_rand.c" in native

    @pytest.mark.parametrize(
        ("target", "source"),
        [
            ("test_rng_repeat", "test_rng_repeat.c"),
            ("test_rng_repeat_concurrent", "test_rng_repeat_concurrent.c"),
            ("test_rng_repeat_fork", "test_rng_repeat_fork.c"),
            ("test_rng_repeat_atfork_fail", "test_rng_repeat_atfork_fail.c"),
            ("test_rng_repeat_atfork_fail_real", "test_rng_repeat_atfork_fail.c"),
            ("test_rng_repeat_fork_shipped", "test_rng_repeat_fork_shipped.c"),
            ("test_rng_repeat_residue", "test_rng_repeat_residue.c"),
            ("test_rng_repeat_residue_shipped", "test_rng_repeat_residue.c"),
            ("test_rng_repeat_shipped", "test_rng_repeat_shipped.c"),
        ],
    )
    def test_each_c_suite_is_registered(self, target: str, source: str) -> None:
        text = TESTS_CMAKE.read_text(encoding="utf-8")
        defined = (
            rf"^\s*(?:add_ama_test|add_ama_residue_probe|add_executable)\({target}\s+{source}\b"
        )
        assert re.search(defined, text, re.MULTILINE), target
        assert (REPO_ROOT / "tests" / "c" / source).is_file(), source

    def test_the_registration_failure_is_driven_through_the_real_pthread_atfork(self) -> None:
        """The failing build defines pthread_atfork(), so the production call's result is tested."""
        text = TESTS_CMAKE.read_text(encoding="utf-8")
        for needle in (
            "add_ama_test(test_rng_repeat_atfork_fail_real test_rng_repeat_atfork_fail.c)",
            "target_compile_definitions(test_rng_repeat_atfork_fail_real PRIVATE "
            "AMA_ATFORK_FAIL_REAL=1)",
            "set_tests_properties(test_rng_repeat_atfork_fail_real PROPERTIES SKIP_RETURN_CODE 77)",
        ):
            assert needle in text, needle
        src = (TESTS_CMAKE.parent / "test_rng_repeat_atfork_fail.c").read_text(encoding="utf-8")
        assert re.search(r"^int pthread_atfork\(", src, re.MULTILINE)
        assert "atfork_calls == 1" in src

    @pytest.mark.parametrize("target", ["test_rng_repeat_shipped", "test_rng_repeat_fork_shipped"])
    def test_the_shipped_object_suites_are_run_and_skip_only_by_exit_77(self, target: str) -> None:
        """A built executable that is not handed to CTest runs nowhere; it may skip only by 77."""
        text = TESTS_CMAKE.read_text(encoding="utf-8")
        assert re.search(rf"add_test\(NAME {target} COMMAND {target}\)", text), target
        assert re.search(
            rf"set_tests_properties\({target} PROPERTIES SKIP_RETURN_CODE 77\)", text
        ), target

    def test_the_tsan_lane_runs_the_concurrent_suite_and_fails_without_it(self) -> None:
        """The TSan lane lists the concurrent suite as non-vacuity and runs every suite."""
        text = STATIC_ANALYSIS.read_text(encoding="utf-8")
        start = text.index("\n  thread-sanitizer:\n")
        end = text.index("\n  valgrind-memcheck:\n", start)
        lane = text[start:end]
        assert re.search(r"for name in [^\n]*\btest_rng_repeat_concurrent\b[^\n]*; do", lane)
        assert "ctest -N" in lane
        assert re.search(r"run: cd build-tsan && ctest --output-on-failure\s*$", lane, re.MULTILINE)
