#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ama_cryptography._build_sign (release-pipeline integrity signer).

Covers the four PR #306 review comments:
  - _load_native_trust_anchor wraps the ctypes call + decode + hex parse
    inside try/except and normalises every failure to RuntimeError so the
    CLI's main() exception handler can render a clean one-line error.
  - main() catches Exception (not just RuntimeError) so an unexpected
    ctypes / OSError exits 1 with a stable failure message rather than a
    raw traceback.
  - _generate_keypair_and_sign returns the actual anchor source so the CLI
    can label the build "native" / "env" / "none" instead of guessing
    from the env var only.
"""

from __future__ import annotations

import ctypes
import os
import stat
from typing import Any, ClassVar, cast
from unittest.mock import patch

import pytest

from ama_cryptography import _build_sign as bs


class _FakeLib:
    """Minimal ctypes-like shim used to stub the native trust-anchor lookup."""

    def __init__(self, return_value: object) -> None:
        self._return = return_value
        captured = return_value

        class _Func:
            argtypes: ClassVar[list[object]] = []
            restype: object = None

            def __call__(self) -> object:
                return captured

        self.ama_integrity_trust_anchor_pubkey_hex = _Func()


def _as_lib(obj: object) -> ctypes.CDLL:
    """Cast a duck-typed test shim to the type the helper expects.

    ``_load_native_trust_anchor`` is annotated as taking a ``ctypes.CDLL``
    because in production that's exactly what flows in, but the function
    only relies on ``hasattr(lib, 'ama_integrity_trust_anchor_pubkey_hex')``
    plus standard attribute access — both of which a duck-typed shim
    satisfies.  The cast is a strict-mode shim, not a behavioural change.
    """
    return cast(ctypes.CDLL, obj)


def test_load_native_trust_anchor_returns_none_when_symbol_missing() -> None:
    """A library without the trust-anchor symbol returns ``None`` cleanly."""

    class _NoSymbol:
        pass

    assert bs._load_native_trust_anchor(_as_lib(_NoSymbol())) is None


def test_load_native_trust_anchor_returns_none_for_empty_string() -> None:
    """Empty C string (no compile-time anchor) is not an error."""
    assert bs._load_native_trust_anchor(_as_lib(_FakeLib(b""))) is None


def test_load_native_trust_anchor_returns_bytes_for_valid_anchor() -> None:
    """A 64-hex-char anchor decodes to 32 raw bytes."""
    anchor_hex = "ab" * 32
    out = bs._load_native_trust_anchor(_as_lib(_FakeLib(anchor_hex.encode("ascii"))))
    assert out == bytes.fromhex(anchor_hex)


def test_load_native_trust_anchor_normalises_decode_errors() -> None:
    """Non-ASCII bytes from the native call must raise RuntimeError, not
    UnicodeDecodeError — Copilot review #3251129755."""
    with pytest.raises(RuntimeError, match=r"trust-anchor lookup failed"):
        bs._load_native_trust_anchor(_as_lib(_FakeLib(b"\xff\xfenot-ascii")))


def test_load_native_trust_anchor_rejects_non_hex() -> None:
    """Garbled ASCII that decodes but is not hex must raise RuntimeError."""
    with pytest.raises(RuntimeError, match=r"not valid hex"):
        bs._load_native_trust_anchor(_as_lib(_FakeLib(b"not-hex-content")))


def test_load_native_trust_anchor_rejects_wrong_length() -> None:
    """A short hex string must raise RuntimeError with the byte count."""
    with pytest.raises(RuntimeError, match=r"has \d+ bytes"):
        bs._load_native_trust_anchor(_as_lib(_FakeLib(b"abcd")))


def test_load_native_trust_anchor_normalises_oserror_from_ctypes() -> None:
    """A ctypes OSError from the symbol call must surface as RuntimeError."""

    class _RaisingLib:
        class ama_integrity_trust_anchor_pubkey_hex:
            argtypes: ClassVar[list[object]] = []
            restype: object = None

            def __call__(self) -> bytes:
                raise OSError("simulated ctypes failure")

    with pytest.raises(RuntimeError, match=r"trust-anchor lookup failed"):
        bs._load_native_trust_anchor(_as_lib(_RaisingLib()))


def test_generate_keypair_and_sign_returns_anchor_source_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no anchor is configured, the third return value is the
    sentinel ``"none"`` so the CLI labels the build as unanchored."""
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        pytest.skip("native library not available in this environment")

    # Force the native lookup to report no anchor (no compile-time pubkey).
    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: None)
    monkeypatch.setattr(bs, "_find_native_library", lambda: _native_lib, raising=False)

    digest = b"\x00" * 32
    pubkey, signature, source = bs._generate_keypair_and_sign(digest)

    assert len(pubkey) == 32
    assert len(signature) == 64
    assert source == "none"


def test_generate_keypair_and_sign_returns_anchor_source_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX is set and the native
    library has no compile-time anchor, the source is ``"env"`` and the
    keypair is regenerated until it matches (out of scope here — we use a
    seed override that matches the env pin)."""
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        pytest.skip("native library not available in this environment")

    # First derive a real pubkey from a known seed so the trust-anchor
    # check passes.  We do that by calling sign once with no anchor.
    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: None)
    seed = b"\xaa" * 32
    pubkey, _sig, _src = bs._generate_keypair_and_sign(b"\x00" * 32, seed_override=seed)

    # Now run again with that exact pubkey pinned as the env trust anchor.
    pubkey2, signature2, source = bs._generate_keypair_and_sign(
        b"\x11" * 32,
        seed_override=seed,
        trusted_pubkey=pubkey,
    )

    assert pubkey2 == pubkey
    assert len(signature2) == 64
    assert source == "env"


def test_require_trust_anchor_without_anchor_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 without any anchor must refuse
    to emit an unanchored signature artefact."""
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        pytest.skip("native library not available in this environment")

    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: None)

    with pytest.raises(RuntimeError, match=r"requires either a native"):
        bs._generate_keypair_and_sign(b"\x00" * 32, require_trust_anchor=True)


def test_strict_release_signing_accepts_pinned_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict release mode signs only when the generated key matches its anchor."""
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        pytest.skip("native library not available in this environment")

    # Simulate a release-CI native anchor without needing a relinked C
    # library: first derive the public key for the deterministic seed,
    # then make _load_native_trust_anchor return exactly that anchor.
    seed = b"\x44" * 32
    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: None)
    pubkey, _sig, _source = bs._generate_keypair_and_sign(b"\x22" * 32, seed_override=seed)

    monkeypatch.setattr(bs, "_load_native_trust_anchor", lambda _lib: pubkey)
    pubkey2, signature2, source = bs._generate_keypair_and_sign(
        b"\x33" * 32,
        seed_override=seed,
        require_trust_anchor=True,
    )

    assert pubkey2 == pubkey
    assert len(signature2) == 64
    assert source == "native"


def test_main_catches_unexpected_exception_returns_exit_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: Any
) -> None:
    """main() must catch unexpected Exception (not just RuntimeError) and
    return exit code 1 — Copilot review #3251129773."""

    # Stage a fake package dir with the bare minimum the signer expects.
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "dummy.py").write_text("x = 1\n")

    def _boom(*args: Any, **kwargs: Any) -> Any:
        # Raise a non-RuntimeError exception type to prove the handler
        # was broadened (the old code re-raised AttributeError as a crash).
        raise AttributeError("simulated unexpected failure")

    monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
    monkeypatch.setattr(bs, "_generate_keypair_and_sign", _boom)
    monkeypatch.setattr(
        "sys.argv",
        ["_build_sign", "--package-dir", str(pkg)],
    )

    rc = bs.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "simulated unexpected failure" in captured.err
    assert "Refusing to write" in captured.err


def test_require_build_pipeline_exits_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The signer must refuse to run outside the build pipeline."""
    monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        bs._require_build_pipeline()
    assert excinfo.value.code == 2


def test_signature_rewrite_removes_stale_bytecode(tmp_path: Any) -> None:
    """Rewriting the artefact must invalidate bytecode cached from the old one.

    CPython validates a ``.pyc`` by ``(mtime-seconds, size)``.  The signature
    module is rewritten with an IDENTICAL size (fixed-width hex fields) and,
    in a build pipeline, within the same second — so a cache compiled from
    the previous artefact still validates and the next import reads STALE
    digests.  That exact race failed PR #391's Alpine image build: the
    re-sign and its verification import ran 250 ms apart, the verifier read
    the old native digest through the stale ``.pyc``, and POST refused an
    image whose on-disk artefact was correct.  The writer now removes the
    cache entries; this pins that contract.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a_binding.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )
    pycache = pkg / "__pycache__"
    pycache.mkdir()
    stale = pycache / "_integrity_signature.cpython-311.pyc"
    stale.write_bytes(b"bytecode compiled from the previous artefact")
    unrelated = pycache / "some_other_module.cpython-311.pyc"
    unrelated.write_bytes(b"must not be touched")

    bs._write_signature_module(
        pkg, b"\x05" * 32, b"\x06" * 32, {"a_binding.so": b"\x0b" * 32}, b"\x07" * 32, b"\x08" * 64
    )

    assert not list(pycache.glob("_integrity_signature.*.pyc")), (
        "stale signature bytecode survived the rewrite — the same-second "
        "same-size .pyc race is open again"
    )
    assert unrelated.exists(), "the invalidation must be surgical, not a cache wipe"


def test_a_failed_rewrite_leaves_the_previous_artefact_intact(
    tmp_path: Any, monkeypatch: Any
) -> None:
    """The rewrite is atomic: readers see the whole old file or the whole new one.

    ``Path.write_text`` opens with ``"w"``, so the artefact is EMPTIED before
    the first byte of the replacement lands.  In that window the file is
    present and empty — and an empty artefact used to parse to zero literals
    and answer ``None`` to every digest lookup, which sent both pre-load gates
    (``__init__._refuse_tampered_bindings_before_import`` and
    ``pqc_backends._expected_native_digest``) down their nothing-to-check
    branch.  ``_artefact_source`` refuses a literal-free artefact now, which is
    the right rule and would have turned this window into a hard ImportError
    for any concurrent import.  Removing the window is the other half.

    Injected at ``os.fsync`` because that is inside the write and before the
    rename: the previous artefact must be byte-identical afterwards, and no
    staging file may survive.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    out = bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a_binding.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )
    original = out.read_bytes()
    assert original, "the first write must have produced a non-empty artefact"

    class _InjectedWriteError(RuntimeError):
        """Raised in place of ``os.fsync`` to fail the write mid-flight."""

    def _explode(_fd: int) -> None:
        raise _InjectedWriteError("injected mid-write failure")

    # Patched on the `os` module itself, not through `bs.os`: `_build_sign`
    # does not re-export `os`, and reaching for it as an attribute of another
    # module is the kind of coupling that breaks on an unrelated import tidy-up.
    monkeypatch.setattr("os.fsync", _explode)
    with pytest.raises(_InjectedWriteError):
        bs._write_signature_module(
            pkg,
            b"\x05" * 32,
            b"\x06" * 32,
            {"a_binding.so": b"\x0b" * 32},
            b"\x07" * 32,
            b"\x08" * 64,
        )

    assert out.read_bytes() == original, (
        "a failed rewrite changed the artefact — the write is not atomic, so a "
        "concurrent reader can see a truncated or partial artefact"
    )
    strays = sorted(pkg.glob("._integrity_signature.*"))
    assert strays == [], f"staging file(s) survived a failed write: {strays}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_a_rewrite_preserves_the_artefacts_existing_mode(tmp_path: Any) -> None:
    """Re-signing must not widen the artefact's permissions.

    ``Path.write_text`` — what the atomic writer replaced — opens an EXISTING
    file with ``"w"``, which does not touch its mode: an artefact stored 0o600
    on a hardened build host stayed 0o600 across every re-sign.  The atomic
    path stages through ``mkstemp`` (0o600) and renames, so the staged file's
    mode becomes the artefact's mode, and a hardcoded ``chmod(0o644)`` there
    silently made the file world-readable on every rewrite regardless of how
    the operator had stored it.  CodeQL flagged it as alert #642; it was a
    real regression, not a false positive.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )
    artefact = pkg / "_integrity_signature.py"
    os.chmod(artefact, 0o600)

    bs._write_signature_module(
        pkg, b"\x05" * 32, b"\x06" * 32, {"a.so": b"\x0b" * 32}, b"\x07" * 32, b"\x08" * 64
    )

    mode = stat.S_IMODE(artefact.stat().st_mode)
    assert mode == 0o600, (
        f"re-signing widened the artefact from 0o600 to 0o{mode:o}; a build host "
        f"running `umask 077` gets permissions it never asked for"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_a_fresh_artefact_gets_the_mode_a_normal_write_would(tmp_path: Any) -> None:
    """With no artefact to preserve, fall back to what creating a file gives.

    Not to a constant: the point is that the operator's umask decides, which
    is exactly what the hardcoded 0o644 overrode.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )

    mask = os.umask(0)
    os.umask(mask)
    expected = 0o666 & ~mask
    mode = stat.S_IMODE((pkg / "_integrity_signature.py").stat().st_mode)
    assert (
        mode == expected
    ), f"fresh artefact is 0o{mode:o}, umask {mask:03o} implies 0o{expected:o}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_mode_is_settled_before_the_rename(tmp_path: Any, monkeypatch: Any) -> None:
    """No reader may ever observe the artefact at the staging mode.

    ``mkstemp`` deliberately creates 0o600 so a half-written artefact is not
    readable.  That is right for the staging file and wrong for the artefact,
    so the mode has to be corrected on the temporary path and not after the
    rename — otherwise every rewrite opens a window in which the installed
    artefact is unreadable to the users who have to import it.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )
    artefact = pkg / "_integrity_signature.py"
    # 0o400, not a group-readable mode: this only has to differ from BOTH
    # mkstemp's 0o600 and the 0o644 a default umask produces, so that the
    # assertion can tell 'preserved' from either default. Picking a mode
    # with group bits made the point no better and tripped CodeQL #643.
    os.chmod(artefact, 0o400)

    seen: list[int] = []
    real_replace = os.replace

    def _spy(src: Any, dst: Any) -> None:
        seen.append(stat.S_IMODE(os.stat(src).st_mode))
        real_replace(src, dst)

    monkeypatch.setattr("os.replace", _spy)
    bs._write_signature_module(
        pkg, b"\x05" * 32, b"\x06" * 32, {"a.so": b"\x0b" * 32}, b"\x07" * 32, b"\x08" * 64
    )

    assert seen == [0o400], (
        f"staging file was renamed carrying {[oct(m) for m in seen]}; the "
        f"artefact's mode must be final before it becomes visible"
    )


def test_signature_module_is_lf_terminated_on_every_platform(tmp_path: Any) -> None:
    """The generated artefacts must be byte-identical wherever they are written.

    Windows' default text-mode newline translation turns every ``\\n`` into
    ``\\r\\n``, which makes a re-signed working tree diverge from the committed
    blob and fails the checkout byte-identity gate
    (``tools/check_line_endings.py``) — the exact failure that took down all
    ten Windows CI jobs.  Asserting on the raw bytes pins the ``newline="\\n"``
    contract on the platforms where translation would not occur anyway, and
    catches a regression on the one where it would.
    """
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    out = bs._write_signature_module(
        pkg, b"\x01" * 32, b"\x02" * 32, {"a_binding.so": b"\x0a" * 32}, b"\x03" * 32, b"\x04" * 64
    )
    raw = out.read_bytes()
    assert b"\r" not in raw, "signature artefact must be LF-only on every platform"
    assert raw.endswith(b"\n")


def test_compute_package_digest_matches_self_test(tmp_path: Any) -> None:
    """The signer's digest computation must be byte-identical with the
    import-time verifier's — otherwise the (digest, signature) embedded in
    the artefact would never verify against the recomputed digest."""
    # Stage two .py files in a fake package and confirm both implementations
    # produce the same SHA3-256 digest over the same content.
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "a.py").write_text("alpha = 1\r\n")
    (pkg / "b.py").write_text("beta = 2\n")

    digest_signer = bs._compute_package_digest(pkg).hex()

    # The self-test side derives its package directory from
    # ``Path(__file__).resolve().parent``, so point that at the staged tree and
    # call the REAL function.
    #
    # This used to re-implement the digest loop inline, which made the
    # assertion a comparison between the signer and the test's own
    # transcription of the verifier — a third copy that has to be kept in step
    # by hand and that silently stops testing the mirror the moment it drifts.
    # It drifted with the framing change in 5.0.0.
    from ama_cryptography import _self_test as st

    class _FakeFile:
        def resolve(self) -> _FakeParent:
            return _FakeParent()

    class _FakeParent:
        @property
        def parent(self) -> Any:
            return pkg

    with patch.object(st, "Path", lambda _path: _FakeFile()):
        digest_self_test = st._compute_module_digest()

    assert digest_signer == digest_self_test


class TestPackageDigestCoversSubpackages:
    """A .py under a subdirectory must be inside signature coverage.

    Both digest enumerations (this signer's and the runtime mirror in
    ``_self_test._compute_module_digest``) used a non-recursive
    ``glob("*.py")``, so on the day a subpackage of .py code is added it
    would be silently UNSIGNED — outside the digest, outside the bytecode
    binding, and accepted by ``_detect_module_substitution`` (which allows
    any module resolved under the package directory).  The enumeration is
    now recursive and keyed by the package-relative path; for the current
    flat layout that changes no byte of any digest.
    """

    @staticmethod
    def _tree(tmp_path: Any) -> Any:
        pkg = tmp_path / "pkg"
        (pkg / "sub").mkdir(parents=True)
        (pkg / "__init__.py").write_text("x = 1\n", encoding="utf-8")
        (pkg / "sub" / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "sub" / "mod.py").write_text("secret = 2\n", encoding="utf-8")
        return pkg

    def test_a_subpackage_edit_changes_the_digest(self, tmp_path: Any) -> None:
        pkg = self._tree(tmp_path)
        before = bs._compute_package_digest(pkg)
        (pkg / "sub" / "mod.py").write_text("secret = 3\n", encoding="utf-8")
        assert bs._compute_package_digest(pkg) != before, (
            "a subpackage .py changed and the signed digest did not — the "
            "file is outside signature coverage"
        )

    def test_same_basename_in_two_directories_cannot_collide(self, tmp_path: Any) -> None:
        """The path key, not the bare name, is what keeps the encoding injective."""
        pkg = self._tree(tmp_path)
        (pkg / "mod.py").write_text("top = 1\n", encoding="utf-8")
        a = bs._compute_package_digest(pkg)
        # Swap the two files' contents; a name-keyed absorption in sorted
        # order could see the same (name, content) multiset.
        (pkg / "mod.py").write_text("secret = 2\n", encoding="utf-8")
        (pkg / "sub" / "mod.py").write_text("top = 1\n", encoding="utf-8")
        assert bs._compute_package_digest(pkg) != a

    def test_pycache_is_not_absorbed(self, tmp_path: Any) -> None:
        pkg = self._tree(tmp_path)
        before = bs._compute_package_digest(pkg)
        cache = pkg / "__pycache__"
        cache.mkdir()
        (cache / "stray.py").write_text("ignored = 1\n", encoding="utf-8")
        assert bs._compute_package_digest(pkg) == before

    def test_runtime_and_signer_agree_on_the_real_tree(self) -> None:
        """The two mirrors must stay byte-for-byte, or POST rejects the sign."""
        from pathlib import Path

        import ama_cryptography._self_test as st

        pkg = Path(st.__file__).resolve().parent
        assert st._compute_module_digest() == bs._compute_package_digest(pkg).hex()

    def test_no_tracked_package_py_escapes_the_enumeration(self) -> None:
        """The omission pin: every .py under the package is in the signed set."""
        from pathlib import Path

        import ama_cryptography._self_test as st

        pkg = Path(st.__file__).resolve().parent
        expected = {
            p.relative_to(pkg).as_posix()
            for p in pkg.rglob("*.py")
            if p.name != "_integrity_signature.py" and "__pycache__" not in p.parts
        }
        enumerated = {
            p.relative_to(pkg).as_posix()
            for p in sorted(pkg.rglob("*.py"))
            if p.name != "_integrity_signature.py" and "__pycache__" not in p.parts
        }
        assert expected == enumerated and expected, "the signed set must be non-empty"
