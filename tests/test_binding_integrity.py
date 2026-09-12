#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for the v3 integrity artefact: binding extensions bound into the signature.

The six Cython binding extensions contain compiled kernels and execute at
import, before POST can examine them, and until v3 nothing covered their
bytes — SECURITY.md carried the gap as "the fix requires a release-pipeline
change" on the claim that ``auditwheel repair`` rewrites the binding ELFs
after signing.  Measured, that claim is false: the published v4.0.0 wheels
ship the bindings byte-identical to the build on every platform (no
``.libs``/``.dylibs`` graft, unmangled ``DT_NEEDED``, the native library
resolving in-package via ``$ORIGIN``/``@loader_path``; Windows repair is
disabled outright), and a local ``auditwheel repair`` of a freshly built
wheel changes only ``RECORD``/``WHEEL`` metadata.  So the digests survive
the pipeline and the artefact now binds them: SHA3-256 per binding file,
serialized into the v3 composite message under its own domain string.

Signer (``_build_sign``) and verifier (``_self_test``) deliberately do not
import each other (INVARIANT-1 build/runtime separation), so their mirrored
constructions are pinned equal here — same pattern as
``tests/test_native_integrity.py::TestSignerVerifierAgreement`` for v2.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from ama_cryptography import _build_sign, _self_test

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"


class TestSignerVerifierAgreement:
    """The mirrored v3 constructions must be byte-identical."""

    def test_v3_domain_constants_are_identical(self) -> None:
        assert _self_test._INTEGRITY_SIG_DOMAIN_V3 == _build_sign._INTEGRITY_SIG_DOMAIN_V3
        # ...and distinct from v2, or the format versioning is decorative.
        assert _self_test._INTEGRITY_SIG_DOMAIN_V3 != _self_test._INTEGRITY_SIG_DOMAIN

    def test_enumeration_criteria_are_identical(self) -> None:
        assert _self_test._EXTENSION_SUFFIXES == _build_sign._EXTENSION_SUFFIXES
        assert _self_test._NATIVE_LIB_PREFIXES == _build_sign._NATIVE_LIB_PREFIXES

    def test_serializers_are_identical(self) -> None:
        sample = {
            "b_binding.so": b"\x02" * 32,
            "a_binding.so": b"\x01" * 32,
            "math_engine.pyd": b"\x03" * 32,
        }
        assert _self_test._serialize_binding_digests(sample) == (
            _build_sign._serialize_binding_digests(sample)
        )

    def test_composite_v3_is_identical(self) -> None:
        py, native = b"\x11" * 32, b"\x22" * 32
        sample = {"a_binding.so": b"\x01" * 32}
        assert _self_test._composite_integrity_message_v3(py, native, sample) == (
            _build_sign._composite_integrity_message_v3(py, native, sample)
        )

    def test_composite_v3_binds_every_component(self) -> None:
        py, native = b"\x11" * 32, b"\x22" * 32
        sample = {"a_binding.so": b"\x01" * 32}
        base = _self_test._composite_integrity_message_v3(py, native, sample)
        assert _self_test._composite_integrity_message_v3(b"\x00" * 32, native, sample) != base
        assert _self_test._composite_integrity_message_v3(py, b"\x00" * 32, sample) != base
        assert (
            _self_test._composite_integrity_message_v3(py, native, {"a_binding.so": b"\x02" * 32})
            != base
        )
        assert _self_test._composite_integrity_message_v3(py, native, {}) != base

    def test_serialization_is_order_independent_and_length_framed(self) -> None:
        a = {"x.so": b"\x01" * 32, "y.so": b"\x02" * 32}
        b = dict(reversed(list(a.items())))
        assert _self_test._serialize_binding_digests(a) == (
            _self_test._serialize_binding_digests(b)
        )
        # Count prefix binds the map size, not just the entries.
        assert _self_test._serialize_binding_digests({}) == (0).to_bytes(4, "big")
        assert _self_test._serialize_binding_digests(a)[:4] == (2).to_bytes(4, "big")
        # Length framing is unconditionally injective: two maps that share every
        # digest but partition the name bytes differently serialize distinctly.
        assert _self_test._serialize_binding_digests(
            {"a": b"\x01" * 32, "bb": b"\x02" * 32}
        ) != _self_test._serialize_binding_digests({"aa": b"\x01" * 32, "b": b"\x02" * 32})
        # ...and it does not depend on filenames lacking NUL — a name that
        # embeds NUL (which the old delimiter form could not have framed) still
        # serializes distinctly from a shifted read.
        assert _self_test._serialize_binding_digests(
            {"a\x00b": b"\x03" * 32}
        ) != _self_test._serialize_binding_digests({"a": b"\x00b" + b"\x03" * 30})


def _setup_py_class_constant(name: str) -> tuple[str, ...]:
    """Read a class-level tuple constant out of ``setup.py`` without running it.

    ``setup.py`` calls ``setup()`` at import, so it cannot be imported here;
    and it cannot import the package either, because at build time the
    package's ``__init__`` would try to load a native library that does not
    exist yet.  Its copy of the enumeration criteria is therefore genuinely
    separate code, and parsing is how it gets pinned.
    """
    tree = ast.parse((REPO_ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            targets: list[ast.expr] = []
            expression: ast.expr | None = None
            if isinstance(statement, ast.Assign):
                targets, expression = list(statement.targets), statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets, expression = [statement.target], statement.value
            if expression is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id == name:
                    value = ast.literal_eval(expression)
                    assert isinstance(value, tuple)
                    return tuple(str(item) for item in value)
    raise AssertionError(f"no class-level {name} found in setup.py")


class TestEveryCopyOfTheEnumerationCriteriaAgrees:
    """Four modules decide "is this file a binding extension?" independently.

    ``_build_sign`` (what the signature covers), ``_self_test`` (what the
    verifier expects to be covered), ``setup.py`` (what the wheel pipeline
    syncs into the directory the signer enumerates) and
    ``tools/verify_install_oob.py`` (what an out-of-band audit of an
    installed tree treats as a binding).  Only the first two were pinned
    together, and drift in the other two is silent in both directions:

    * if ``setup.py`` stops recognising a suffix the signer recognises, the
      wheel ships a binding the artefact never bound, and POST fails every
      install with "present but not covered" — the exact failure the sync
      step was written to prevent, reintroduced by drift;
    * if ``verify_install_oob`` stops recognising one, an implanted
      extension carrying that suffix is never examined by the tool whose
      whole purpose is to find it.

    ``verify_install_oob`` must keep its own copy rather than import one:
    it audits a possibly-tampered installation, and taking its definition of
    "binding extension" from the tree under audit would put the target
    inside the verifier's trust base.  Independence is the design; agreement
    is what needs a test.
    """

    def test_setup_py_matches_the_signer(self) -> None:
        assert _setup_py_class_constant("_EXTENSION_SUFFIXES") == _build_sign._EXTENSION_SUFFIXES
        assert _setup_py_class_constant("_NATIVE_LIB_PREFIXES") == _build_sign._NATIVE_LIB_PREFIXES

    def test_the_out_of_band_verifier_matches_the_signer(self) -> None:
        from tools import verify_install_oob as oob

        assert oob._EXTENSION_SUFFIXES == _build_sign._EXTENSION_SUFFIXES
        assert oob._NATIVE_LIB_PREFIXES == _build_sign._NATIVE_LIB_PREFIXES

    def test_the_parser_would_notice_a_changed_value(self) -> None:
        """The pin is only worth having if reading it can fail.

        A parser that silently returned the first tuple it found, or an
        empty one, would agree with anything.
        """
        with pytest.raises(AssertionError, match="no class-level"):
            _setup_py_class_constant("_NO_SUCH_CONSTANT_IN_SETUP_PY")


class TestTreeArtefactSelfCheck:
    """The artefact in this tree must be one of the two legitimate states.

    A repair-flow artefact (``integrity --update --sign``, the state a source
    tree and this repository's commits carry) binds NO extensions — binding
    extensions are per-interpreter and not reproducible across environments,
    so a committed artefact that bound one machine's extensions would report
    tampering on every other machine's legitimate rebuild.  A wheel-pipeline
    artefact (``--bind-extensions``) binds exactly the extensions shipped
    beside it.  Anything in between is drift.
    """

    def test_artefact_is_v3(self) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        assert getattr(sig_mod, "BUILD_PIPELINE_VERSION", None) == "3"
        assert isinstance(getattr(sig_mod, "INTEGRITY_BINDING_DIGESTS_HEX", None), dict)

    def test_artefact_is_a_legitimate_state_for_this_tree(self) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        on_disk = {p.name: p for p in _self_test._iter_extension_files(PKG_DIR)}
        signed = sig_mod.INTEGRITY_BINDING_DIGESTS_HEX
        if not signed:
            return  # repair-flow artefact: binds none, by design
        assert set(signed) == set(on_disk), (
            "artefact binds extensions but disagrees with the package "
            "directory — a partially-drifted artefact is neither the "
            "repair-flow state (binds none) nor the wheel state (binds "
            "exactly what ships); re-sign: AMA_BUILD_PIPELINE=1 python -m "
            "ama_cryptography.integrity --update --sign"
        )
        for name, path in on_disk.items():
            assert hashlib.sha3_256(path.read_bytes()).hexdigest() == signed[name], name

    def test_signer_and_verifier_enumerate_the_tree_identically(self) -> None:
        assert [p.name for p in _build_sign._iter_binding_files(PKG_DIR)] == [
            p.name for p in _self_test._iter_extension_files(PKG_DIR)
        ]


class TestParseEmbeddedBindingDigests:
    class _Artefact:
        def __init__(self, field: object) -> None:
            if field is not _ABSENT:
                self.INTEGRITY_BINDING_DIGESTS_HEX = field

    def test_absent_field_is_pre_v3_not_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(self._Artefact(_ABSENT))
        assert parsed is None and error is None

    def test_non_dict_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(self._Artefact(["x"]))
        assert parsed is None and error is not None

    def test_bad_hex_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "not-hex"})
        )
        assert parsed is None and error is not None and "a.so" in error

    def test_wrong_length_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "ab" * 16})
        )
        assert parsed is None and error is not None

    def test_valid_dict_parses(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "ab" * 32})
        )
        assert error is None and parsed == {"a.so": bytes.fromhex("ab" * 32)}


_ABSENT = object()


class TestCheckBindingExtensions:
    """Each failure direction, driven on a scratch tree."""

    @pytest.fixture()
    def scratch(self, tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
        files: dict[str, bytes] = {}
        for name in ("ed25519_binding.cpython-311-x86_64-linux-gnu.so", "math_engine.pyd"):
            body = f"compiled {name}".encode()
            (tmp_path / name).write_bytes(body)
            files[name] = hashlib.sha3_256(body).digest()
        # The native library must be ignored by enumeration, not reported.
        (tmp_path / "libama_cryptography.so.4").write_bytes(b"native")
        return tmp_path, files

    def test_matching_tree_verifies(self, scratch: tuple[Path, dict[str, bytes]]) -> None:
        tree, files = scratch
        for anchored in (False, True):
            ok, note, exact = _self_test._check_binding_extensions(files, anchored, pkg_dir=tree)
            assert ok and exact
            assert "2 binding extension(s) verified" in note

    def test_empty_map_with_no_extensions_is_exact(self, tmp_path: Path) -> None:
        """The repair-flow artefact on a tree without built extensions."""
        (tmp_path / "libama_cryptography.so.4").write_bytes(b"native")
        for anchored in (False, True):
            ok, _note, exact = _self_test._check_binding_extensions({}, anchored, pkg_dir=tmp_path)
            assert ok and exact

    def test_tampered_file_fails_on_every_build(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        """MISMATCH is tampering — fatal on anchored AND developer builds."""
        tree, files = scratch
        (tree / "math_engine.pyd").write_bytes(b"different bytes")
        for anchored in (False, True):
            ok, note, _exact = _self_test._check_binding_extensions(files, anchored, pkg_dir=tree)
            assert not ok and "math_engine.pyd" in note and "MISMATCH" in note

    def test_missing_file_fails_anchored_warns_developer(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        tree, files = scratch
        (tree / "math_engine.pyd").unlink()
        ok, note, _e = _self_test._check_binding_extensions(files, True, pkg_dir=tree)
        assert not ok and "missing on disk" in note
        ok, note, exact = _self_test._check_binding_extensions(files, False, pkg_dir=tree)
        assert ok and not exact
        assert "PARTIALLY covered" in note and "missing on disk" in note

    def test_uncovered_file_fails_anchored_warns_developer(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        tree, files = scratch
        (tree / "planted.cpython-311-x86_64-linux-gnu.so").write_bytes(b"rogue")
        ok, note, _e = _self_test._check_binding_extensions(files, True, pkg_dir=tree)
        assert not ok and "planted" in note and "not covered" in note
        ok, note, exact = _self_test._check_binding_extensions(files, False, pkg_dir=tree)
        # Developer build: warned and named, not fatal — a source tree
        # legitimately builds extensions after its artefact was signed, and
        # source trees sit inside the checker-poisoning boundary where
        # in-process attestation of locally built artifacts adds nothing.
        assert ok and not exact
        assert "PARTIALLY covered" in note and "planted" in note

    def test_source_tree_state_uncovered_bindings_with_empty_map(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        """The natural dev state: repair-flow artefact ({}) + built bindings."""
        tree, _files = scratch
        ok, note, exact = _self_test._check_binding_extensions({}, False, pkg_dir=tree)
        assert ok and not exact
        assert "PARTIALLY covered" in note
        ok, _note, _e = _self_test._check_binding_extensions({}, True, pkg_dir=tree)
        assert not ok  # anchored builds never carry drift legitimately

    def test_failure_note_carries_the_resign_hint(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        tree, files = scratch
        (tree / "math_engine.pyd").write_bytes(b"different bytes")
        _ok, note, _e = _self_test._check_binding_extensions(files, False, pkg_dir=tree)
        assert "integrity --update --sign" in note


class TestSignerInventoryFailClosed:
    def test_unknown_extension_refuses_to_sign(self, tmp_path: Path) -> None:
        (tmp_path / "mystery_module.cpython-311-x86_64-linux-gnu.so").write_bytes(b"?")
        with pytest.raises(RuntimeError, match="unknown compiled extension"):
            _build_sign._iter_binding_files(tmp_path)

    def test_native_library_files_are_not_bindings(self, tmp_path: Path) -> None:
        for name in (
            "libama_cryptography.so.4.0.0",
            "libama_cryptography.4.dylib",
            "ama_cryptography.dll",  # .dll is not an enumerated suffix, doubly ignored
            "ed25519_binding.cpython-311-darwin.so",
        ):
            (tmp_path / name).write_bytes(b"x")
        names = [p.name for p in _build_sign._iter_binding_files(tmp_path)]
        assert names == ["ed25519_binding.cpython-311-darwin.so"]
