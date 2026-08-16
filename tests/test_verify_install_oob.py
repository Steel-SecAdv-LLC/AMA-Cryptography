# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/verify_install_oob.py`` — the out-of-band installed-tree
verifier.

The tool exists because the in-process integrity checks share a trusted
computing base with the tree they verify (the checker-poisoning boundary,
SECURITY.md "Execution integrity"): its hand-written SHA3-256 / Ed25519 must
therefore be correct on their own.  These tests pin them against the
specifications' vectors and against ``hashlib`` as an independent oracle,
then drive the CLI end to end against this repository's signed tree and
against tampered copies of it.

NOTE on the oracle: ``hashlib.sha3_256`` is OpenSSL-backed on CPython and is
forbidden as a *runtime stand-in* for AMA crypto (INVARIANT-1; the
INVARIANT-36 benchmark finding) — which is exactly why the tool hand-writes
its digests.  Using it here as a TEST oracle is the established pattern
(``_self_test._kat_sha3_256`` cross-checks native against hashlib the same
way): a disagreement between two independent implementations of a fixed
function localises the fault immediately.
"""

import hashlib
import importlib.util
import marshal
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import verify_install_oob as oob

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "verify_install_oob.py"
PKG_DIR = REPO_ROOT / "ama_cryptography"


def _resolve_native_lib() -> "Path | None":
    """Locate the built native library the way the package itself does.

    Hard-coding ``build/lib/libama_cryptography.so`` was wrong twice over: the
    library is ``.dylib`` on macOS and ``.dll``/``.pyd`` on Windows, so that
    path could never exist there *even when the library was built*, and the
    output directory varies by generator (MSVC uses ``build/bin/Release``).
    The result was four CI errors on every macOS and Windows test job — the
    conftest promotes a backend skip to a failure, correctly, because the
    backend was in fact present and only this lookup could not see it.

    ``_find_native_library_path`` is the package's own discovery — the same
    function the build-time signer uses to decide which bytes to bind — so
    this test now asks the question the rest of the tree already answers, and
    inherits every search dir and platform suffix it knows about.
    """
    try:
        from ama_cryptography.pqc_backends import _find_native_library_path

        return _find_native_library_path()
    except Exception:
        # No importable package / no candidate: report "not discoverable" and
        # let the skip marker (and, in CI, the conftest promotion) decide.
        return None


NATIVE_LIB = _resolve_native_lib()

requires_signed_tree = pytest.mark.skipif(
    not (PKG_DIR / "_integrity_signature.py").is_file(),
    reason="working tree carries no signed integrity artefact",
)
requires_native_lib = pytest.mark.skipif(
    NATIVE_LIB is None,
    reason="native library backend not discoverable by the package loader",
)


def _run_tool(*args: str) -> "subprocess.CompletedProcess[str]":
    """Run the verifier CLI in a FRESH interpreter (that is its contract)."""
    return subprocess.run(
        [sys.executable, str(TOOL_PATH), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=600,
        check=False,
    )


# ---------------------------------------------------------------------------
# (a) startup self-KATs
# ---------------------------------------------------------------------------


class TestSelfKATs:
    def test_self_kats_pass(self) -> None:
        assert oob.run_self_kats() is None

    def test_self_kat_failure_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A wrong expected vector must surface as a KAT failure, proving the
        KAT loop actually compares (a run_self_kats that always returns None
        would pass the test above)."""
        bad = ((b"", "00" * 32), *oob._SHA3_KATS[1:])
        monkeypatch.setattr(oob, "_SHA3_KATS", bad)
        error = oob.run_self_kats()
        assert error is not None and "SHA3-256 KAT failed" in error

    def test_cli_fails_closed_on_kat_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """main() must exit 3 and verify nothing when a self-KAT fails."""
        monkeypatch.setattr(oob, "run_self_kats", lambda: "forced failure")
        assert oob.main([str(tmp_path)]) == 3


# ---------------------------------------------------------------------------
# (b) hand-written SHA3-256 vs hashlib (test oracle only — see module note)
# ---------------------------------------------------------------------------


class TestSha3Parity:
    def test_agrees_with_hashlib_over_random_inputs(self) -> None:
        rng = random.Random(0xA3A3_2026)  # noqa: S311 -- test data, not keys (OOB-002)
        # Deterministic boundary lengths around the 136-byte rate (padding
        # edge: 135 leaves one byte for 0x86, 136 forces a full pad block),
        # then random lengths up to several blocks — 200 inputs total.
        lengths: list[int] = [0, 1, 2, 7, 8, 9, 135, 136, 137, 271, 272, 273]
        lengths += [rng.randrange(0, 1200) for _ in range(200 - len(lengths))]
        assert len(lengths) == 200
        for i, length in enumerate(lengths):
            data = rng.randbytes(length)
            assert (
                oob.sha3_256(data) == hashlib.sha3_256(data).digest()
            ), f"disagreement at case {i} (length {length})"

    def test_sha512_agrees_with_hashlib(self) -> None:
        """The Ed25519-internal SHA-512 gets the same oracle treatment."""
        rng = random.Random(0x512_2026)  # noqa: S311 -- test data, not keys (OOB-003)
        for length in [0, 1, 111, 112, 113, 127, 128, 129, 500]:
            data = rng.randbytes(length)
            assert oob.sha512(data) == hashlib.sha512(data).digest()


# ---------------------------------------------------------------------------
# (c) Ed25519 verify: RFC 8032 §7.1 TEST 1-3, plus bit-flip rejection
# ---------------------------------------------------------------------------

# Verify-side halves of the RFC 8032 §7.1 vectors — byte-identical to the
# repo's canonical copies in tests/test_ed25519_native.py (RFC8032_VECTORS).
RFC8032_VERIFY_VECTORS: list[dict[str, bytes]] = [
    {
        "public_key": bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a" "0ee172f3daa62325af021a68f707511a"
        ),
        "message": b"",
        "signature": bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        "public_key": bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc" "9c982ccf2ec4968cc0cd55f12af4660c"
        ),
        "message": bytes.fromhex("72"),
        "signature": bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
    {
        "public_key": bytes.fromhex(
            "fc51cd8e6218a1a38da47ed00230f058" "0816ed13ba3303ac5deb911548908025"
        ),
        "message": bytes.fromhex("af82"),
        "signature": bytes.fromhex(
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
]

_VECTOR_IDS = ["TEST 1 (empty)", "TEST 2 (0x72)", "TEST 3 (0xaf82)"]


def _flip_bit(data: bytes, bit: int = 0) -> bytes:
    flipped = bytearray(data)
    flipped[bit // 8] ^= 1 << (bit % 8)
    return bytes(flipped)


class TestEd25519Verify:
    @pytest.mark.parametrize("vector", RFC8032_VERIFY_VECTORS, ids=_VECTOR_IDS)
    def test_accepts_rfc8032_vector(self, vector: dict[str, bytes]) -> None:
        assert oob.ed25519_verify(vector["signature"], vector["message"], vector["public_key"])

    @pytest.mark.parametrize("vector", RFC8032_VERIFY_VECTORS, ids=_VECTOR_IDS)
    def test_rejects_flipped_signature_bit(self, vector: dict[str, bytes]) -> None:
        # Flip a bit in each half: R (point) and S (scalar) are rejected
        # through different code paths.
        for bit in (0, 64 * 8 - 9):
            assert not oob.ed25519_verify(
                _flip_bit(vector["signature"], bit), vector["message"], vector["public_key"]
            )

    @pytest.mark.parametrize("vector", RFC8032_VERIFY_VECTORS, ids=_VECTOR_IDS)
    def test_rejects_flipped_pubkey_bit(self, vector: dict[str, bytes]) -> None:
        assert not oob.ed25519_verify(
            vector["signature"], vector["message"], _flip_bit(vector["public_key"])
        )

    @pytest.mark.parametrize(
        "vector",
        # TEST 1's message is empty (nothing to flip); the message-tamper
        # direction is exercised on TEST 2 and TEST 3.
        RFC8032_VERIFY_VECTORS[1:],
        ids=_VECTOR_IDS[1:],
    )
    def test_rejects_flipped_message_bit(self, vector: dict[str, bytes]) -> None:
        assert not oob.ed25519_verify(
            vector["signature"], _flip_bit(vector["message"]), vector["public_key"]
        )

    def test_rejects_noncanonical_scalar(self) -> None:
        """S >= L must be rejected outright (malleability guard)."""
        vector = RFC8032_VERIFY_VECTORS[0]
        s = int.from_bytes(vector["signature"][32:], "little") + oob._ED_L
        forged = vector["signature"][:32] + s.to_bytes(32, "little")
        assert not oob.ed25519_verify(forged, vector["message"], vector["public_key"])


# ---------------------------------------------------------------------------
# (d) end-to-end: the CLI verifies THIS repo's signed tree
# ---------------------------------------------------------------------------


def _covered_binding_names() -> "set[str]":
    """Names the working tree's artefact actually binds, via the tool's own
    parser (never a re-implementation of the schema)."""
    fields, error = oob.parse_artefact_fields(PKG_DIR / "_integrity_signature.py")
    if fields is None or error is not None:
        return set()
    binding, _ = oob._parse_binding_digest_field(fields)
    return set(binding or ())


@pytest.fixture()
def installed_tree(tmp_path: Path) -> Path:
    """A copy of the signed package tree in the state the tool is designed to
    PASS: no compiled extension the artefact does not cover.

    The *working* tree is deliberately not such a state.  ``pip install -e .``
    builds the six Cython bindings into the package directory, while the
    repair flow (``integrity --update --sign``) deliberately binds an EMPTY
    map — only the wheel pipeline's ``--bind-extensions`` binds them.
    ``_verify_binding_extensions`` refuses that combination on purpose: an
    out-of-band verifier cannot tell a developer rebuild from an implant.

    So asserting ``RESULT: PASS`` against the working tree asserted the
    opposite of the tool's documented contract, and did so in a test that
    could not run in CI (its skip guard looked for a library path that never
    exists on macOS or Windows).  With the guard fixed the assertion would
    have failed on every job.  Copying the tree and dropping the *uncovered*
    extensions reproduces a real installed tree, so the PASS path is exercised
    for real; ``test_uncovered_binding_extension_is_refused`` below pins the
    refusal that the working tree's own state demonstrates.
    """
    pkg_copy = tmp_path / "ama_cryptography"
    shutil.copytree(PKG_DIR, pkg_copy)
    covered = _covered_binding_names()
    for path in pkg_copy.iterdir():
        if not path.is_file() or path.suffix not in oob._EXTENSION_SUFFIXES:
            continue
        if path.name.startswith(oob._NATIVE_LIB_PREFIXES):
            continue
        if path.name not in covered:
            path.unlink()
    return pkg_copy


@requires_signed_tree
@requires_native_lib
class TestCliAgainstRepoTree:
    def test_clean_tree_passes(self, installed_tree: Path) -> None:
        assert NATIVE_LIB is not None  # guaranteed by @requires_native_lib
        result = _run_tool(str(installed_tree), "--native-lib", str(NATIVE_LIB))
        assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        # The working tree's artefact is a repair-flow signing: v3 schema with
        # the binding map EMPTY — the tool must handle that state, not choke.
        assert "schema v3" in result.stdout
        assert "[signature] verified" in result.stdout
        assert "[native] verified" in result.stdout
        assert "RESULT: PASS" in result.stdout

    def test_uncovered_binding_extension_is_refused(self, installed_tree: Path) -> None:
        """A compiled extension the artefact does not cover must fail closed.

        This is the state a developer tree lands in after ``pip install -e .``
        re-builds the bindings, and the state an implant would also produce;
        the tool cannot distinguish them out of band, so it refuses both.
        """
        assert NATIVE_LIB is not None  # guaranteed by @requires_native_lib
        planted = installed_tree / f"implant_binding{oob._EXTENSION_SUFFIXES[0]}"
        planted.write_bytes(b"not a real extension, but it is compiled code")
        result = _run_tool(str(installed_tree), "--native-lib", str(NATIVE_LIB))
        assert result.returncode != 0, f"stdout:\n{result.stdout}"
        assert "not covered by" in result.stdout
        assert planted.name in result.stdout
        assert "RESULT: FAIL" in result.stdout


# ---------------------------------------------------------------------------
# (e) tamper detection on a copied tree
# ---------------------------------------------------------------------------


def _ensure_cache(py_path: Path) -> Path:
    """Compile ``py_path`` into its standard ``__pycache__`` slot (the copied
    tree may or may not have carried one for this interpreter), returning the
    cache path.  Uses a plain header + marshal so the fixture does not depend
    on py_compile internals."""
    return _write_pyc(py_path, py_path.read_text(encoding="utf-8"))


def _write_pyc(py_path: Path, source: str) -> Path:
    """Write bytecode compiled from ``source`` into ``py_path``'s cache slot.

    The 16-byte header (magic + flags/mtime/size zeroed) is enough for the
    tool, which deliberately ignores the timestamp fields exactly as
    ``_self_test._cached_code_for`` does — an attacker sets those freely.
    """
    code = compile(source, str(py_path), "exec", dont_inherit=True, optimize=-1)
    cache_path = Path(importlib.util.cache_from_source(str(py_path)))
    cache_path.parent.mkdir(exist_ok=True)
    cache_path.write_bytes(importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code))
    return cache_path


@pytest.fixture()
def tree_copy(tmp_path: Path) -> tuple[Path, Path]:
    """A byte-identical copy of the signed package tree plus the native
    library, isolated in tmp so tampering never touches the working tree."""
    assert NATIVE_LIB is not None, "fixture used without @requires_native_lib"
    pkg_copy = tmp_path / "ama_cryptography"
    shutil.copytree(PKG_DIR, pkg_copy)
    # Keep the real suffix (.so / .dylib / .dll): the copy stands in for the
    # shipped object, and a platform-wrong name would misrepresent it.
    native_copy = tmp_path / NATIVE_LIB.name
    native_copy.write_bytes(NATIVE_LIB.resolve().read_bytes())
    return pkg_copy, native_copy


@requires_signed_tree
@requires_native_lib
class TestTamperDetection:
    def test_flipped_byte_in_py_fails_naming_the_file(self, tree_copy: tuple[Path, Path]) -> None:
        pkg_copy, native_copy = tree_copy
        target = pkg_copy / "exceptions.py"
        _ensure_cache(target)  # guarantee a cache exists for attribution
        original = target.read_bytes()
        tampered = original.replace(b"class ", b"klass ", 1)
        assert tampered != original, "fixture assumption broken: no 'class ' in exceptions.py"
        target.write_bytes(tampered)

        result = _run_tool(str(pkg_copy), "--native-lib", str(native_copy))
        assert result.returncode != 0
        assert "py digest MISMATCH" in result.stdout
        # Attribution: the cached bytecode no longer matches the tampered
        # source, so the report names the file.
        assert "exceptions.py" in result.stdout
        assert "RESULT: FAIL" in result.stdout

    def test_poisoned_pyc_fails_while_source_digest_holds(
        self, tree_copy: tuple[Path, Path]
    ) -> None:
        """The signature-evading attack the tool exists for: every .py is
        pristine (digest and signature verify) but the cached bytecode the
        interpreter would EXECUTE was compiled from different source."""
        pkg_copy, native_copy = tree_copy
        target = pkg_copy / "equations.py"
        poisoned_source = target.read_text(encoding="utf-8") + "\n_OOB_POISON_MARKER = 1\n"
        _write_pyc(target, poisoned_source)

        result = _run_tool(str(pkg_copy), "--native-lib", str(native_copy))
        assert result.returncode != 0
        # Source tree still authentic...
        assert "[py-digest] verified" in result.stdout
        assert "[signature] verified" in result.stdout
        # ...but the executed surface is not, and the file is named.
        assert "equations.py" in result.stdout
        assert "cached bytecode does not match" in result.stdout
        assert "RESULT: FAIL" in result.stdout

    def test_flipped_byte_in_native_lib_fails(self, tree_copy: tuple[Path, Path]) -> None:
        pkg_copy, native_copy = tree_copy
        blob = bytearray(native_copy.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        native_copy.write_bytes(bytes(blob))

        result = _run_tool(str(pkg_copy), "--native-lib", str(native_copy))
        assert result.returncode != 0
        assert "native library digest MISMATCH" in result.stdout
        assert "RESULT: FAIL" in result.stdout
