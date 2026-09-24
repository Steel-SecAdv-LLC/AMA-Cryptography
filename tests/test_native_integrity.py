#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Native-library integrity binding and FIPS POST stage ordering
=============================================================

Before this coverage existed, the signed-integrity artefact covered the
package's ``.py`` files and nothing else.  ``libama_cryptography`` — the shared
object that performs every cryptographic operation — was signed by nothing and
verified at load by nothing.  An attacker who replaced it with a back-doored
build left the ``.py`` digest, the Ed25519 signature and the trust anchor all
intact and verifying, while the actual cryptography ran from bytes no check had
ever looked at.  The wrapper was tamper-evident; the implementation was not.

These tests pin the v2 binding:

* the signature covers ``SHA3-256(domain || py_digest || native_digest)``, so
  the two digests are inseparable;
* the loaded shared object is re-hashed at import and must match the signed
  native digest;
* a tampered ``.so`` fails POST (and therefore the import);
* rewriting the embedded native digest to match a tampered ``.so`` breaks the
  signature, which cannot be forged;
* the two modules that must agree on the signed-message construction
  (``_self_test`` at runtime, ``_build_sign`` at build time) are pinned equal.

They also pin the FIPS 140-3 stage ordering (NIST IG 10.3.A): the SHA3-256 and
Ed25519 CASTs run before the integrity stage that relies on them.

Run with:  pytest tests/test_native_integrity.py -v
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import native_library_path, native_library_present

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

pytestmark = pytest.mark.fips


def _run_python(
    code: str, cwd: Path, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = str(cwd)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def signed_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package that carries a valid v2 signed artefact.

    Skips when the source tree has no native library or no signed artefact —
    the binding cannot be exercised without both.
    """
    if not (PKG_DIR / "_integrity_signature.py").is_file():
        pytest.skip("no signed-integrity artefact in the source tree")
    if not native_library_present(PKG_DIR):
        pytest.skip("native library not built in this tree")
    sig_src = (PKG_DIR / "_integrity_signature.py").read_text(encoding="utf-8")
    if "INTEGRITY_NATIVE_DIGEST_HEX" not in sig_src:
        pytest.skip("source artefact is legacy v1 (no native digest); re-sign to run these")

    root = tmp_path_factory.mktemp("signed")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    _drop_unbound_extensions(root / "ama_cryptography")
    return root


def _drop_unbound_extensions(pkg_root: Path) -> None:
    """Remove compiled binding extensions the signed artefact does not cover.

    A source-tree artefact deliberately binds NO extensions: they are
    per-interpreter and not reproducible, so binding one tree's would read as
    a digest MISMATCH — a tampering verdict — on every other machine (see
    ``_build_sign``'s ``--bind-extensions`` help).  The documented consequence
    is that a tree carrying built-but-uncovered extensions is *correctly*
    reported at below-full integrity strength.

    ``pip install -e .`` builds six such extensions into the package
    directory, so a fixture that copies the package wholesale inherits them
    and can never be "fully verified" — which is what turned five tests red
    across ubuntu, macOS and arm once the strength downgrade stopped being
    dead code.  Dropping the uncovered ones makes the copied tree internally
    consistent, which is the state these tests mean by "healthy".
    """
    try:
        from ama_cryptography import _integrity_signature as _sig

        covered = set(getattr(_sig, "INTEGRITY_BINDING_DIGESTS_HEX", {}) or {})
    except Exception:
        covered = set()
    for suffix in (".so", ".pyd", ".dylib"):
        for path in pkg_root.glob(f"*{suffix}"):
            if path.name.startswith(("libama_cryptography", "ama_cryptography.dll")):
                continue  # the native library, bound separately
            if path.name not in covered:
                path.unlink()


def _real_so(tree_root: Path) -> Path:
    """The resolved (symlink-followed) native library inside a package tree.

    Delegates to the shared probe rather than carrying its own candidate list.
    It used to hold ``("libama_cryptography.so", "libama_cryptography.dylib")``
    with a ``libama_cryptography.so*`` fallback — no Windows spelling in either
    — so once the fixtures stopped skipping on Windows this asserted "no native
    library in the copied tree" against a tree that contained
    ``ama_cryptography.dll``. Two hardcoded lists for one question is how the
    first one drifted; there is now only the one in ``conftest``.
    """
    found = native_library_path(tree_root / "ama_cryptography")
    assert found is not None, "no native library in the copied tree"
    return found


# ---------------------------------------------------------------------------
# 1. The signer and the verifier must agree on the signed message
# ---------------------------------------------------------------------------


class TestSignerVerifierAgreement:
    """A drift between the two modules silently invalidates every signature."""

    def test_domain_constants_are_identical(self) -> None:
        from ama_cryptography import _build_sign, _self_test

        assert _self_test._INTEGRITY_SIG_DOMAIN == _build_sign._INTEGRITY_SIG_DOMAIN

    def test_composite_message_is_identical(self) -> None:
        from ama_cryptography import _build_sign, _self_test

        py = bytes(range(32))
        native = bytes(range(32, 64))
        assert _self_test._composite_integrity_message(
            py, native
        ) == _build_sign._composite_integrity_message(py, native)

    def test_composite_binds_both_digests(self) -> None:
        """Changing either digest changes the signed message."""
        from ama_cryptography import _self_test as st

        base = st._composite_integrity_message(b"\x00" * 32, b"\x11" * 32)
        assert base != st._composite_integrity_message(b"\x01" + b"\x00" * 31, b"\x11" * 32)
        assert base != st._composite_integrity_message(b"\x00" * 32, b"\x12" + b"\x11" * 31)

    def test_package_digest_format_tag_is_identical(self) -> None:
        from ama_cryptography import _build_sign, _self_test

        assert _self_test._PACKAGE_DIGEST_FORMAT == _build_sign._PACKAGE_DIGEST_FORMAT

    def test_entry_framing_is_identical(self) -> None:
        """The two mirrors must absorb an entry into the same bytes."""
        import hashlib

        from ama_cryptography import _build_sign, _self_test

        one, two = hashlib.sha3_256(), hashlib.sha3_256()
        _self_test._absorb_entry(one, b"py", "a.py", b"body\r\nhere")
        _build_sign._absorb_entry(two, b"py", "a.py", b"body\r\nhere")
        assert one.digest() == two.digest()


class TestAllThreeDigestMirrorsAgree:
    """There is a THIRD copy of the package-digest construction.

    ``tools/verify_install_oob.py`` is the out-of-band verifier an operator
    runs against an installed tree.  It deliberately imports nothing from the
    tree it is checking — that is the point of it — so it carries its own copy
    of the digest, and the two tests above, which compare only ``_self_test``
    and ``_build_sign``, could not see it.

    When the construction was framed in 5.0.0 that third copy was left on the
    old unframed encoding.  It did not merely go stale: computed and stored
    digests could never agree again, so the verifier reported
    ``py digest MISMATCH`` on every correctly signed tree — a verifier that
    fails closed on the truth is as useless as one that passes on a lie, and
    the whole-suite run is what caught it.

    These tests compare all three on the same input, so the next change to one
    of them fails here.
    """

    @staticmethod
    def _oob() -> Any:
        import importlib.util

        repo_root = Path(__file__).resolve().parent.parent
        path = repo_root / "tools" / "verify_install_oob.py"
        spec = importlib.util.spec_from_file_location("_oob_verifier", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_format_tag_is_identical_in_all_three(self) -> None:
        from ama_cryptography import _build_sign, _self_test

        oob = self._oob()
        assert oob._PACKAGE_DIGEST_FORMAT == _self_test._PACKAGE_DIGEST_FORMAT
        assert oob._PACKAGE_DIGEST_FORMAT == _build_sign._PACKAGE_DIGEST_FORMAT

    def test_entry_framing_is_identical_in_all_three(self) -> None:
        """All three, as the name says.

        This compared the out-of-band copy against ``_build_sign`` only, so
        the ``_self_test`` mirror — the one the RUNTIME verifier uses — was
        named in the test title and absent from its body.  ``_self_test`` and
        ``_build_sign`` are pinned equal by ``TestSignerVerifierAgreement``
        above, so the three did agree transitively, but a test that says
        "all three" must fail when any one of them drifts, not two of them.
        """
        import hashlib

        from ama_cryptography import _build_sign, _self_test

        oob = self._oob()
        entry = (b"post_kats", "v.json", b"x\r\ny")

        signer = hashlib.sha3_256()
        _build_sign._absorb_entry(signer, *entry)
        runtime = hashlib.sha3_256()
        _self_test._absorb_entry(runtime, *entry)
        chunks: list[bytes] = []
        oob._absorb_entry(chunks, *entry)
        out_of_band = hashlib.sha3_256(b"".join(chunks))

        assert signer.digest() == runtime.digest(), "signer and runtime mirrors differ"
        assert signer.digest() == out_of_band.digest(), "signer and out-of-band mirrors differ"

    def test_the_whole_digest_is_identical_on_a_staged_tree(self, tmp_path: Path) -> None:
        """The assertion that would have caught the drift: same tree, same digest."""
        from ama_cryptography import _build_sign

        pkg = tmp_path / "ama_cryptography"
        (pkg / "_post_kats").mkdir(parents=True)
        (pkg / "a.py").write_text("alpha = 1\r\n", encoding="utf-8")
        (pkg / "b.py").write_text("beta = 2\n", encoding="utf-8")
        # Excluded from the digest by both implementations; present so the
        # exclusion is exercised rather than assumed.
        (pkg / "_integrity_signature.py").write_text("SIGNATURE = 'x'\n", encoding="utf-8")
        (pkg / "_post_kats" / "one.json").write_text('{"v": 1}\n', encoding="utf-8")

        oob = self._oob()
        signer = _build_sign._compute_package_digest(pkg)
        assert oob.compute_package_digest(pkg) == signer, "out-of-band digest differs from signer"

        # ...and the runtime mirror over the same staged tree.  It derives its
        # package directory from ``Path(__file__).resolve().parent``, so it is
        # pointed at the staged tree the same way tests/test_build_sign.py does
        # rather than being re-implemented here — a fourth transcription would
        # be one more copy to keep in step by hand.
        from unittest.mock import patch

        from ama_cryptography import _self_test as st

        class _FakeParent:
            @property
            def parent(self) -> Any:
                return pkg

        class _FakeFile:
            def resolve(self) -> _FakeParent:
                return _FakeParent()

        with patch.object(st, "Path", lambda _p: _FakeFile()):
            runtime_hex = st._compute_module_digest()
        assert runtime_hex == signer.hex(), "runtime digest differs from signer over the same tree"

    def test_the_shipped_tree_verifies_out_of_band(self) -> None:
        """End to end, against the real signed artefact.

        The unit comparisons above would pass on two implementations that are
        identically wrong.  This one is the ground truth: the digest the
        out-of-band tool computes over the shipped package must be the digest
        the artefact was signed over.
        """
        repo_root = Path(__file__).resolve().parent.parent
        pkg = repo_root / "ama_cryptography"
        if not (pkg / "_integrity_signature.py").exists():
            pytest.skip("unsigned tree: nothing to verify against")

        # Read through _artefact_source, not by importing the generated
        # module: the artefact is parsed from SOURCE TEXT everywhere else in
        # the tree precisely so a poisoned __pycache__ cannot supply the
        # values, and a test that imports it would be checking a different
        # thing from what the product checks.
        from ama_cryptography._artefact_source import load_artefact_fields

        fields = load_artefact_fields()
        # None means no artefact on disk, which the guard above already ruled
        # out — asserted rather than assumed so the failure names the cause.
        assert fields is not None, "signed artefact present but not parseable"
        oob = self._oob()
        assert oob.compute_package_digest(pkg).hex() == fields.INTEGRITY_DIGEST_HEX


class TestThePackageDigestIsAnInjectiveCommitment:
    """A hash of a concatenation commits to the concatenation, not to the map.

    Until 5.0.0 each entry contributed ``name || content`` with no length
    prefix and no delimiter, and consecutive entries were simply concatenated —
    so a filename could be smuggled into a neighbouring file's body and the
    digest could not tell the two trees apart.  This digest is exactly what the
    Ed25519 artefact signs, so one signature covered both.

    Measured against the shipped signer at the previous commit::

        A/  a.py = b"X"          b.py = b"Y"
        B/  a.py = b"Xb.pyY"     (b.py absent)

        digest(A) == digest(B) == 98aaca986290313a24078bb7c79f8ee8...

    The same module got it right one function away: ``_serialize_binding_digests``
    frames each entry as ``name || 0x00 || digest`` for precisely this reason.
    """

    @staticmethod
    def _tree(root: Path, files: dict[str, bytes], kats: dict[str, bytes] | None = None) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (root / name).write_bytes(body)
        if kats:
            kat_dir = root / "_post_kats"
            kat_dir.mkdir()
            for name, body in kats.items():
                (kat_dir / name).write_bytes(body)
        return root

    def _digest(self, root: Path) -> str:
        from ama_cryptography import _build_sign

        return _build_sign._compute_package_digest(root).hex()

    def test_the_demonstrated_collision_no_longer_holds(self, tmp_path: Path) -> None:
        a = self._tree(tmp_path / "A", {"a.py": b"X", "b.py": b"Y"})
        b = self._tree(tmp_path / "B", {"a.py": b"Xb.pyY"})
        assert self._digest(a) != self._digest(b)

    def test_a_same_count_collision_no_longer_holds(self, tmp_path: Path) -> None:
        """The strongest form: one file each, so no entry count separates them.

        Under the unframed construction both absorb the bytes ``b"a.pyb.py"`` —
        the second tree's filename is a prefix of the first's and the remainder
        is its content.  Verified to collide under the pre-5.0.0 encoding, and
        it survives the entry-count prefixes, so it pins the FRAMING rather
        than the counts.
        """
        a = self._tree(tmp_path / "A", {"a.pyb.py": b""})
        b = self._tree(tmp_path / "B", {"a.py": b"b.py"})
        assert self._digest(a) != self._digest(b)

    def test_a_crafted_body_cannot_forge_the_post_kats_section(self, tmp_path: Path) -> None:
        """``b"_post_kats/"`` was an unframed literal a body could reproduce.

        Both trees hold exactly one ``.py`` file; the second writes the section
        marker, the KAT's name and its content into that file's body.  Verified
        to collide under the pre-5.0.0 encoding.
        """
        a = self._tree(tmp_path / "A", {"z.py": b""}, kats={"v.json": b"{}"})
        b = self._tree(tmp_path / "B", {"z.py": b"_post_kats/v.json{}"})
        assert self._digest(a) != self._digest(b)

    def test_the_digest_is_stable_for_one_tree(self, tmp_path: Path) -> None:
        """Non-vacuity: the construction must still be deterministic."""
        a = self._tree(tmp_path / "A", {"a.py": b"X", "b.py": b"Y"}, kats={"k": b"Z"})
        assert self._digest(a) == self._digest(a)

    def test_content_still_changes_the_digest(self, tmp_path: Path) -> None:
        a = self._tree(tmp_path / "A", {"a.py": b"X"})
        b = self._tree(tmp_path / "B", {"a.py": b"Y"})
        assert self._digest(a) != self._digest(b)

    def test_crlf_is_still_normalised(self, tmp_path: Path) -> None:
        """The Windows-checkout property the framing must not have broken."""
        a = self._tree(tmp_path / "A", {"a.py": b"one\r\ntwo\r\n"})
        b = self._tree(tmp_path / "B", {"a.py": b"one\ntwo\n"})
        assert self._digest(a) == self._digest(b)

    def test_the_generated_artefact_is_still_excluded(self, tmp_path: Path) -> None:
        a = self._tree(tmp_path / "A", {"a.py": b"X"})
        b = self._tree(tmp_path / "B", {"a.py": b"X", "_integrity_signature.py": b"anything"})
        assert self._digest(a) == self._digest(b)


# ---------------------------------------------------------------------------
# 2. Native-library digest helper
# ---------------------------------------------------------------------------


class TestNativeDigestHelper:
    def test_hashes_file_contents(self, tmp_path: Path) -> None:
        from ama_cryptography._self_test import _compute_native_library_digest

        f = tmp_path / "lib.so"
        f.write_bytes(b"abc123")
        assert _compute_native_library_digest(str(f)) == hashlib.sha3_256(b"abc123").digest()

    def test_follows_symlinks(self, tmp_path: Path) -> None:
        from ama_cryptography._self_test import _compute_native_library_digest

        real = tmp_path / "lib.so.4.0.0"
        real.write_bytes(b"real-object-bytes")
        link = tmp_path / "lib.so"
        link.symlink_to(real)
        via_link = _compute_native_library_digest(str(link))
        assert via_link == _compute_native_library_digest(str(real))

    def test_none_on_missing_or_empty_path(self, tmp_path: Path) -> None:
        from ama_cryptography._self_test import _compute_native_library_digest

        assert _compute_native_library_digest(None) is None
        assert _compute_native_library_digest("") is None
        assert _compute_native_library_digest(str(tmp_path / "nope.so")) is None


# ---------------------------------------------------------------------------
# 3. Healthy binding
# ---------------------------------------------------------------------------


class TestHealthyBinding:
    def test_native_library_is_verified(self, signed_tree: Path) -> None:
        result = _run_python(
            """
            import sys; sys.path.insert(0, ".")
            import ama_cryptography as a
            att = a.module_attestation()
            assert att["state"] == "OPERATIONAL", att
            assert att["fully_verified"] is True, att
            detail = dict((n, d) for n, _p, d in a.module_self_test_results())["integrity"]
            assert "native library verified" in detail, detail
            print("OK")
            """,
            cwd=signed_tree,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# 4. Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_flipped_byte_in_so_fails_import(self, signed_tree: Path, tmp_path: Path) -> None:
        """A tampered shipped library is now refused BEFORE it is mapped.

        Previously the tampered object loaded — running its constructors —
        and the POST integrity stage then reported "native library digest
        MISMATCH".  The pre-load check in ``_try_load_library`` closes that
        window: the digest is compared before ``dlopen``, so the refusal
        message is the pre-load one and no constructor from the tampered
        object ever executes.
        """
        root = tmp_path / "tampered"
        shutil.copytree(signed_tree / "ama_cryptography", root / "ama_cryptography")
        so = _real_so(root)
        blob = bytearray(so.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        so.write_bytes(bytes(blob))

        result = _run_python("import ama_cryptography", cwd=root)
        assert result.returncode != 0, "a tampered native library imported cleanly"
        combined = result.stdout + result.stderr
        assert "refused before mapping" in combined, combined
        # And NOT the post-load message: the object must never have been
        # mapped for a post-load comparison to run against.
        assert "native library digest MISMATCH" not in combined, combined

    def test_rewriting_embedded_digest_breaks_the_signature(
        self, signed_tree: Path, tmp_path: Path
    ) -> None:
        """The composite bind: an attacker who edits the .so must also edit the
        embedded native digest to pass the digest check — which changes the
        signed message and so breaks a signature they cannot forge."""
        import re

        root = tmp_path / "resigned"
        shutil.copytree(signed_tree / "ama_cryptography", root / "ama_cryptography")
        so = _real_so(root)
        blob = bytearray(so.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        so.write_bytes(bytes(blob))
        new_digest = hashlib.sha3_256(bytes(blob)).hexdigest()

        sig = root / "ama_cryptography" / "_integrity_signature.py"
        text = sig.read_text(encoding="utf-8")
        text = re.sub(
            r'INTEGRITY_NATIVE_DIGEST_HEX = "\w+"',
            f'INTEGRITY_NATIVE_DIGEST_HEX = "{new_digest}"',
            text,
        )
        sig.write_text(text, encoding="utf-8")

        result = _run_python("import ama_cryptography", cwd=root)
        assert result.returncode != 0, "rewriting the embedded digest defeated the binding"
        combined = result.stdout + result.stderr
        assert "signature did NOT verify" in combined, combined
        # And crucially NOT a mere digest mismatch — the signature is the gate.
        assert "native library digest MISMATCH" not in combined


# ---------------------------------------------------------------------------
# 5. AMA_CRYPTO_LIB_PATH override — signed, but native not the shipped object
# ---------------------------------------------------------------------------


class TestOverrideVerification:
    def test_byte_identical_override_is_verified(self, signed_tree: Path, tmp_path: Path) -> None:
        """An override whose bytes EQUAL the signed bytes is the signed library.

        The pre-4.0 rule marked every override UNVERIFIED unconditionally.
        Since the POST stage now compares the digest of the bytes actually
        mapped, verification is a property of the bytes, not the path: a
        byte-identical copy loaded from elsewhere carries the full signed
        assurance, and the override's presence remains visible in the
        diagnostics record.
        """
        so = _real_so(signed_tree)
        external = tmp_path / "elsewhere"
        external.mkdir()
        ext_so = external / "libama_cryptography.so"
        ext_so.write_bytes(so.read_bytes())

        result = _run_python(
            """
            import sys; sys.path.insert(0, ".")
            import ama_cryptography as a
            att = a.module_attestation()
            assert att["state"] == "OPERATIONAL", att
            assert att["fully_verified"] is True, att
            detail = dict((n, d) for n, _p, d in a.module_self_test_results())["integrity"]
            assert "native library verified" in detail, detail
            from ama_cryptography.pqc_backends import native_backend_diagnostics
            assert native_backend_diagnostics()["override"], "override not recorded"
            print("OK")
            """,
            cwd=signed_tree,
            env_extra={"AMA_CRYPTO_LIB_PATH": str(ext_so)},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout

    def test_modified_override_loads_but_is_recorded_unverified(
        self, signed_tree: Path, tmp_path: Path
    ) -> None:
        """A *modified* override is the operator's own substitution: honoured,
        never digest-blocked, and reported UNVERIFIED rather than tampered."""
        so = _real_so(signed_tree)
        external = tmp_path / "elsewhere-modified"
        external.mkdir()
        ext_so = external / "libama_cryptography.so"
        blob = bytearray(so.read_bytes())
        # Append a byte: changes the digest without perturbing any mapped
        # segment, so the object still loads and functions.
        blob.append(0x00)
        ext_so.write_bytes(bytes(blob))

        result = _run_python(
            """
            import sys; sys.path.insert(0, ".")
            import ama_cryptography as a
            att = a.module_attestation()
            # The override backend is functional, so the module is OPERATIONAL...
            assert att["state"] == "OPERATIONAL", att
            # ...but the loaded bytes are not the signed ones, so NOT full.
            assert att["fully_verified"] is False, att
            detail = dict((n, d) for n, _p, d in a.module_self_test_results())["integrity"]
            assert "UNVERIFIED" in detail and "override" in detail, detail
            print("OK")
            """,
            cwd=signed_tree,
            env_extra={"AMA_CRYPTO_LIB_PATH": str(ext_so)},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# 6. FIPS stage ordering (NIST IG 10.3.A)
# ---------------------------------------------------------------------------


class TestPostKatVectors:
    """The POST KAT vectors are authentic NIST records and are tamper-covered."""

    def test_provenance_gate_passes_and_is_not_vacuous(self) -> None:
        """`build_post_kats.py --check` re-derives from the vendored sources."""
        import subprocess

        tool = REPO_ROOT / "tools" / "build_post_kats.py"
        assert tool.is_file()
        ok = subprocess.run(
            [sys.executable, str(tool), "--check"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert ok.returncode == 0, ok.stdout + ok.stderr

        # Non-vacuity: a corrupted pinned vector must serialise differently from
        # what the builder re-derives, so `--check` (which compares the two)
        # cannot pass over a drift.
        import json

        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import build_post_kats as bpk  # type: ignore[import-not-found]  # loaded from tools/ via runtime sys.path insert; mypy cannot see it (NI-001)
        finally:
            sys.path.pop(0)

        expected = bpk._serialise(bpk._build_ml_kem_1024())
        corrupted = json.loads(expected)
        ss = corrupted["ss_hex"]
        corrupted["ss_hex"] = ("0" if ss[0] != "0" else "1") + ss[1:]
        assert bpk._serialise(corrupted) != expected, "check() could not detect a corrupted vector"

    def test_module_digest_covers_post_kats(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Editing a POST KAT vector changes the module digest.

        Without this, an attacker could swap a known-answer vector for one a
        broken implementation passes and defeat the KAT on a build whose .py
        digest and signature still verified.

        Runs against a COPY of the package.  The earlier version tampered with
        the repository's own tracked vector and restored it in a ``finally``:
        a Ctrl-C, a SIGKILL or a crash inside that window left the checkout
        with a corrupted vector, and — as the sibling test
        ``test_swapped_vector_fails_import`` demonstrates — every subsequent
        ``import ama_cryptography`` in that checkout then failed POST, with
        nothing pointing at this test as the cause.  ``_compute_module_digest``
        resolves the package directory from the module's ``__file__`` at call
        time, so pointing that at the copy is enough.
        """
        from ama_cryptography import _self_test as st

        kat_name = "ml_kem_1024_kat.json"
        if not (PKG_DIR / "_post_kats" / kat_name).is_file():
            pytest.skip("pinned vector not present")

        pkg_copy = tmp_path / "ama_cryptography"
        shutil.copytree(PKG_DIR, pkg_copy)
        _drop_unbound_extensions(pkg_copy)
        monkeypatch.setattr(st, "__file__", str(pkg_copy / "_self_test.py"))

        kat = pkg_copy / "_post_kats" / kat_name
        before = st._compute_module_digest()
        kat.write_bytes(kat.read_bytes()[:-2] + b"X\n")
        after = st._compute_module_digest()

        assert before != after, "the module digest does not cover _post_kats/ vectors"
        assert (
            PKG_DIR / "_post_kats" / kat_name
        ).read_bytes() != kat.read_bytes(), "the working tree's own vector was modified"

    def test_swapped_vector_fails_import(self, signed_tree: Path, tmp_path: Path) -> None:
        """End to end: a modified POST KAT vector fails POST and the import."""
        import json

        root = tmp_path / "swapped"
        shutil.copytree(signed_tree / "ama_cryptography", root / "ama_cryptography")
        vec = root / "ama_cryptography" / "_post_kats" / "ml_dsa_65_kat.json"
        payload = json.loads(vec.read_text(encoding="utf-8"))
        payload["pk_hex"] = ("0" if payload["pk_hex"][0] != "0" else "1") + payload["pk_hex"][1:]
        vec.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = _run_python("import ama_cryptography", cwd=root)
        assert result.returncode != 0, "a swapped POST KAT vector imported cleanly"
        assert "digest mismatch" in (result.stdout + result.stderr)

    def test_kats_are_known_answer_not_roundtrip(self) -> None:
        """The PQC KATs must consume the pinned vectors, not self-generate.

        A roundtrip KAT calls keygen with no fixed input; a known-answer KAT
        reads the vector.  Pinning the source guards against a silent regression
        back to a self-consistency roundtrip.
        """
        import inspect

        from ama_cryptography import _self_test as st

        for fn, token in (
            (st._kat_ml_kem_1024, "ml_kem_1024_kat.json"),
            (st._kat_ml_dsa_65, "ml_dsa_65_kat.json"),
            (st._kat_slh_dsa, "slh_dsa_sha2_256f_kat.json"),
        ):
            src = inspect.getsource(fn)
            assert token in src, f"{fn.__name__} no longer loads its pinned vector"
            assert "_load_post_kat" in src, f"{fn.__name__} does not use the pinned-vector loader"


class TestStageOrdering:
    def test_integrity_relevant_casts_run_before_integrity(self, signed_tree: Path) -> None:
        result = _run_python(
            """
            import sys; sys.path.insert(0, ".")
            import ama_cryptography as a
            names = [n for n, _p, _d in a.module_self_test_results()]
            i = names.index("integrity")
            assert names.index("SHA3-256") < i, names
            assert names.index("Ed25519") < i, names
            # native-backend presence precedes everything.
            assert names.index("native-backend") < names.index("SHA3-256"), names
            print("ORDER-OK")
            """,
            cwd=signed_tree,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ORDER-OK" in result.stdout

    def test_ed25519_kat_precedes_integrity_in_source_ordering(self) -> None:
        """The runner must schedule the pre-integrity CASTs before integrity."""
        from ama_cryptography import _self_test as st

        pre = [name for name, _fn in st._pre_integrity_kats()]
        assert "SHA3-256" in pre and "Ed25519" in pre
        post = [name for name, _fn in st._post_integrity_kats()]
        assert "SHA3-256" not in post and "Ed25519" not in post
        # No overlap, no loss.
        allnames = [name for name, _fn in st._all_kat_tests()]
        assert sorted(pre + post) == sorted(allnames)
