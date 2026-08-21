# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ``tools/check_vendor_isolation.py`` (INVARIANT-1).

The gate exists because "no third-party cryptographic implementation is linked,
imported or called" was, before it, enforced against *subprocess invocations*
only (``tools/check_corpus_originality.py``) and otherwise asserted by comments
and intent.  A control that has never been shown to fail is indistinguishable
from one that cannot, so every check here is exercised in both directions:

* the **source** check must flag a vendor import, a ``ctypes`` load naming a
  vendor library, and an import of the comparator package;
* the **library** check must flag a genuinely OpenSSL-linked object — the
  interpreter's own ``_ssl`` extension is used as the positive control, so the
  ELF/Mach-O/PE parsing is validated against a real binary rather than a
  fixture;
* the parsers must agree with the platform's own tools where those exist;
* and a check whose evidence is absent (missing library, unparseable file, a
  package directory with no sources) must be a failure, not a silent pass.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from tests.conftest import native_library_path
from tools import check_vendor_isolation as gate

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_vendor_isolation.py"

#: Where CMake leaves the built shared library, across generators.
#:
#: ``CMakeLists.txt`` sets LIBRARY_OUTPUT_DIRECTORY to ``build/lib`` and
#: RUNTIME_OUTPUT_DIRECTORY to ``build/bin`` (Windows puts a DLL in the
#: latter), and multi-config generators add a per-configuration subdirectory.
_LIBRARY_DIRS = (
    Path("build") / "lib",
    Path("build") / "lib" / "Release",
    Path("build") / "bin",
    Path("build") / "bin" / "Release",
    Path("ama_cryptography"),
)


def built_library() -> Path | None:
    """The shared library this tree built, whatever the platform names it.

    Three tests here looked for ``build/lib/libama_cryptography.so`` by exact
    name.  That name exists only on Linux, so on macOS and Windows — where
    the same CI job builds ``.dylib`` and ``.dll`` and sets
    ``AMA_CI_REQUIRE_BACKENDS=1`` — they skipped, and ``conftest`` correctly
    escalated the skip into a failure because its reason claimed a build that
    had in fact happened.  Ten jobs went red on a test-side naming
    assumption, and until they did, the shipped macOS and Windows artefacts
    were never examined by these tests at all.
    """
    for relative in _LIBRARY_DIRS:
        directory = REPO_ROOT / relative
        if directory.is_dir():
            found = native_library_path(directory)
            if found is not None:
                return found
    return None


def write_package(tmp_path: Path, body: str, name: str = "mod.py") -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / name).write_text(body, encoding="utf-8")
    return pkg


class TestSourceCheck:
    def test_clean_package_passes(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "import hashlib\nimport os\n")
        assert gate.check_source(pkg) == []

    @pytest.mark.parametrize(
        ("statement", "vendor"),
        [
            ("import nacl", "libsodium"),
            ("import nacl.signing", "libsodium"),
            ("from cryptography.hazmat.primitives import hashes", "OpenSSL"),
            ("import OpenSSL", "OpenSSL"),
            ("from Crypto.Cipher import AES", "PyCryptodome"),
            ("import wolfcrypt", "wolfSSL"),
            ("import botan3", "Botan"),
            ("import nettle", "Nettle"),
            ("import gcrypt", "libgcrypt"),
            ("import mbedtls", "mbedTLS"),
        ],
    )
    def test_vendor_import_is_flagged(self, tmp_path: Path, statement: str, vendor: str) -> None:
        pkg = write_package(tmp_path, statement + "\n")
        violations = gate.check_source(pkg)
        assert len(violations) == 1
        assert vendor in violations[0].detail

    def test_comparator_package_import_is_flagged(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "from benchmarks import benchmark_runner\n")
        violations = gate.check_source(pkg)
        assert len(violations) == 1
        assert "comparator package" in violations[0].detail

    @pytest.mark.parametrize(
        "call",
        [
            'ctypes.CDLL("libcrypto.so.3")',
            'ctypes.cdll.LoadLibrary("/usr/lib/libsodium.so.23")',
            'ctypes.util.find_library("libmbedcrypto")',
        ],
    )
    def test_ctypes_load_of_a_vendor_library_is_flagged(self, tmp_path: Path, call: str) -> None:
        """No import statement names these, which is the point."""
        pkg = write_package(tmp_path, f"import ctypes\nlib = {call}\n")
        violations = gate.check_source(pkg)
        assert violations, "a ctypes load naming a vendor library must be flagged"

    def test_ctypes_load_of_our_own_library_passes(self, tmp_path: Path) -> None:
        pkg = write_package(
            tmp_path, 'import ctypes\nlib = ctypes.CDLL("libama_cryptography.so.5")\n'
        )
        assert gate.check_source(pkg) == []

    def test_naming_a_vendor_in_prose_is_not_a_violation(self, tmp_path: Path) -> None:
        """Scholarship and wire-format spellings are not invocations."""
        pkg = write_package(
            tmp_path,
            '"""Accepts the SEC 1 / OpenSSL alias prime256v1."""\n'
            "# Approach follows libsodium's ed25519 clamping.\n"
            'CURVE_ALIASES = {"prime256v1": "P-256"}\n',
        )
        assert gate.check_source(pkg) == []

    def test_relative_imports_are_not_vendor_imports(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "from . import sibling\nfrom .sub import thing\n")
        assert gate.check_source(pkg) == []

    def test_empty_directory_is_a_failure_not_a_clean_scan(self, tmp_path: Path) -> None:
        empty = tmp_path / "nothing"
        empty.mkdir()
        violations = gate.check_source(empty)
        assert violations
        assert "refusing to report a clean scan of nothing" in violations[0].detail


class TestCSourceCheck:
    """The C tree is where the only vendor includes in this repository are.

    ``src/c/vendor/ed25519-donna`` carries an OpenSSL SHA-512 and an OpenSSL
    ``RAND_bytes`` as the ``#else`` arm of its hash and RNG selection.  They
    are not compiled because ``src/c/ed25519_donna_shim.c`` defines
    ``ED25519_REFHASH`` and ``ED25519_CUSTOMRANDOM`` first — two lines in one
    file, previously verified by nothing, since the Python source scan has
    never read ``src/c``.
    """

    @staticmethod
    def _tree(tmp_path: Path, *, shim: str, vendor_header: str) -> Path:
        root = tmp_path / "src" / "c"
        (root / "vendor" / "donna").mkdir(parents=True)
        (root / "vendor" / "donna" / "ed25519-hash.h").write_text(vendor_header)
        (root / "shim.c").write_text(shim)
        return tmp_path

    def test_the_real_tree_is_clean(self) -> None:
        assert gate.check_c_source(REPO_ROOT / "src" / "c", REPO_ROOT) == []

    def test_a_vendor_include_outside_the_vendored_tree_is_flagged(self, tmp_path: Path) -> None:
        root = tmp_path / "src" / "c"
        root.mkdir(parents=True)
        (root / "ama_thing.c").write_text("#include <openssl/evp.h>\n")
        violations = gate.check_c_source(root, tmp_path)
        assert any("OpenSSL" in v.detail for v in violations)

    @pytest.mark.parametrize(
        ("include", "vendor"),
        [
            ("<sodium.h>", "libsodium"),
            ("<wolfssl/ssl.h>", "wolfSSL"),
            ("<botan/ffi.h>", "Botan"),
            ("<nettle/sha2.h>", "Nettle"),
            ("<gcrypt.h>", "libgcrypt"),
            ("<mbedtls/sha512.h>", "mbedTLS"),
            ("<psa/crypto.h>", "mbedTLS"),
        ],
    )
    def test_every_forbidden_vendor_is_recognised_in_c(
        self, tmp_path: Path, include: str, vendor: str
    ) -> None:
        """A vendor with no C include root would be invisible to this check."""
        root = tmp_path / "src" / "c"
        root.mkdir(parents=True)
        (root / "ama_thing.c").write_text(f"#include {include}\n")
        violations = gate.check_c_source(root, tmp_path)
        assert any(vendor in v.detail for v in violations)

    def test_a_missing_disabling_macro_is_flagged(self, tmp_path: Path) -> None:
        """The mutation that matters: the shim stops disabling the arm.

        Verified against the real gate on the real tree by removing
        ``#define ED25519_REFHASH`` from ``ed25519_donna_shim.c``, which the
        gate rejects.
        """
        root = REPO_ROOT / "src" / "c"
        shim = (root / "ed25519_donna_shim.c").read_text()
        mutated = shim.replace("#define ED25519_REFHASH", "/* removed */")
        assert mutated != shim, "the shim no longer defines the macro this test mutates"

        staged = tmp_path / "src" / "c"
        staged.mkdir(parents=True)
        (staged / "ed25519_donna_shim.c").write_text(mutated)
        for rel in gate.VENDORED_FALLBACK_INCLUDES:
            src = REPO_ROOT / rel
            dst = tmp_path / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text())
        violations = gate.check_c_source(staged, tmp_path)
        assert any("ED25519_REFHASH" in v.detail for v in violations)

    def test_a_stale_inventory_entry_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A declared fallback that no longer exists weakens the check."""
        monkeypatch.setitem(
            gate.VENDORED_FALLBACK_INCLUDES,
            "src/c/vendor/absent/file.h",
            ("OpenSSL", "SOME_MACRO"),
        )
        violations = gate.check_c_source(REPO_ROOT / "src" / "c", REPO_ROOT)
        assert any("no such include was found" in v.detail for v in violations)

    def test_an_empty_c_tree_is_not_a_clean_scan(self, tmp_path: Path) -> None:
        root = tmp_path / "src" / "c"
        root.mkdir(parents=True)
        violations = gate.check_c_source(root, tmp_path)
        assert violations
        assert "refusing to report a clean scan of nothing" in violations[0].detail

    def test_the_shim_still_defines_both_macros(self) -> None:
        """Stated directly, because it is the whole boundary."""
        shim = (REPO_ROOT / "src" / "c" / "ed25519_donna_shim.c").read_text()
        assert "#define ED25519_REFHASH" in shim
        assert "#define ED25519_CUSTOMRANDOM" in shim


class TestShippedPackageIsClean:
    """The property itself, on the tree as committed."""

    def test_package_source_is_clean(self) -> None:
        assert gate.check_source(REPO_ROOT / "ama_cryptography") == []


class TestLibraryCheck:
    def test_missing_library_is_a_failure(self, tmp_path: Path) -> None:
        violations = gate.check_library(tmp_path / "absent.so")
        assert violations
        assert "refusing to report clean" in violations[0].detail

    def test_unparseable_file_is_a_failure(self, tmp_path: Path) -> None:
        junk = tmp_path / "not-a-binary.so"
        junk.write_bytes(b"this is not an object file at all\n")
        violations = gate.check_library(junk)
        assert violations
        assert "could not parse" in violations[0].detail

    def test_the_interpreters_ssl_extension_is_read_correctly(self) -> None:
        """Positive control: the interpreter's own ``_ssl`` extension.

        This validates the parser against a real, vendor-linked binary on
        whatever platform the suite runs on, rather than against a fixture
        that could agree with a wrong parser.

        The assertion is on the *evidence*, not on the platform.  Parsing
        must succeed everywhere — a refusal to parse was the actual macOS
        defect, where ``_ssl`` is a universal binary and the parser knew only
        thin Mach-O.  If the object names a vendor library dynamically, the
        gate must flag it.  If it does not, that absence is itself checked
        against the platform's own tool, so "no vendor found" can never be a
        parser miss dressed up as a clean result.
        """
        ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
        candidates = [
            Path(sysconfig.get_config_var("DESTSHARED") or "") / f"_ssl{ext_suffix}",
        ]
        try:
            import _ssl

            if getattr(_ssl, "__file__", None):
                candidates.insert(0, Path(_ssl.__file__))
        except ImportError:  # pragma: no cover - _ssl is present on CI
            pass

        target = next((p for p in candidates if p.is_file()), None)
        if target is None:  # pragma: no cover - statically linked interpreter
            pytest.skip("this interpreter ships no _ssl extension module")

        # Must parse.  Not "must parse on Linux".
        info = gate.parse_binary(target)
        assert info.fmt

        violations = gate.check_library(target)
        if violations:
            assert any(
                "OpenSSL" in violation.detail for violation in violations
            ), f"{target}: {violations}"
            return

        # No vendor found.  Prove that is a property of the binary and not of
        # the parser, by asking the platform what it depends on.
        reported = _platform_dependencies(target)
        if reported is None:  # pragma: no cover - depends on runner tooling
            pytest.skip("no dependency-listing tool available to confirm the absence")
        assert not [
            dependency
            for dependency in reported
            if any(name in dependency.lower() for name in ("libssl", "libcrypto"))
        ], (
            f"{target} names an OpenSSL library according to the platform "
            f"({reported}) but the gate reported it clean — the parser missed it"
        )

    def test_ama_library_is_clean_when_built(self) -> None:
        built = built_library()
        if built is None:
            pytest.skip("native library not built in this tree")
        assert gate.check_library(built) == []


class TestTheLibraryIsFoundWhereverCMakePutsIt:
    """Regression protection for the naming assumption that reddened CI.

    A test that cannot find a library which *was* built does not merely skip:
    ``conftest`` escalates a skip whose reason names the backend into a hard
    CI failure, because a job that builds the library and then reports it
    missing is reporting something untrue.  So the locator being wrong shows
    up as ten red jobs, and — until they went red — as the macOS and Windows
    artefacts never being examined at all.
    """

    def test_the_candidate_directories_match_what_cmake_configures(self) -> None:
        """``_LIBRARY_DIRS`` must track ``CMakeLists.txt``, not a memory of it."""
        cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        configured = set(
            re.findall(
                r"set\(CMAKE_(?:LIBRARY|RUNTIME)_OUTPUT_DIRECTORY\s+"
                r"\$\{CMAKE_BINARY_DIR\}/(\w+)\)",
                cmake,
            )
        )
        assert configured, "CMakeLists.txt no longer sets the output directories by that name"
        searched = {part.parts[-1] for part in _LIBRARY_DIRS if part.parts[0] == "build"}
        missing = configured - searched
        assert not missing, f"CMake writes the library to build/{missing} and nothing looks there"

    def test_ci_that_promises_a_build_must_find_one(self) -> None:
        """The exact invariant the escalation in ``conftest`` encodes.

        ``AMA_CI_REQUIRE_BACKENDS=1`` is set by the jobs that have just built
        the library.  If it is set and this locator finds nothing, the
        locator is wrong — which is a defect to surface here, in the test
        that owns the locator, rather than as an escalated skip in whichever
        unrelated test happened to call it first.
        """
        if os.environ.get("AMA_CI_REQUIRE_BACKENDS", "").lower() not in ("true", "1", "yes"):
            pytest.skip("not a CI job that promises a built library")
        found = built_library()
        assert found is not None, (
            "AMA_CI_REQUIRE_BACKENDS=1 promises the C library was built, but "
            f"none of {[str(d) for d in _LIBRARY_DIRS]} holds one"
        )
        assert found.is_file()


def _platform_dependencies(path: Path) -> list[str] | None:
    """What the platform's own tool says ``path`` depends on, or ``None``.

    ``None`` means no tool was available — never "no dependencies", which is
    the confusion that lets a gate report clean having examined nothing.
    """
    readelf = shutil.which("readelf")
    if readelf is not None:
        result = subprocess.run(
            [readelf, "-d", str(path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and "Dynamic section" in result.stdout:
            return [
                line.split("[", 1)[1].rstrip("]").strip()
                for line in result.stdout.splitlines()
                if "(NEEDED)" in line and "[" in line
            ]

    otool = shutil.which("otool")
    if otool is not None:
        result = subprocess.run(
            [otool, "-L", str(path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            # First line is the file name; each remaining line is indented and
            # carries "(compatibility version ...)".
            listed = [
                line.strip().split(" (", 1)[0]
                for line in result.stdout.splitlines()[1:]
                if line.startswith(("\t", " ")) and "(" in line
            ]
            # ...but for a DYLIB the first of those is the image's own install
            # name (LC_ID_DYLIB), not something it depends on.  `otool -L`
            # does not distinguish them; `otool -D` prints exactly the install
            # name, so subtracting it is precise rather than positional.  The
            # gate parses LC_LOAD_DYLIB and correctly never reported the
            # install name — this helper did, and called the gate wrong for it.
            identity = subprocess.run(
                [otool, "-D", str(path)], capture_output=True, text=True, check=False
            )
            if identity.returncode == 0:
                own = [
                    line.strip()
                    for line in identity.stdout.splitlines()[1:]
                    if line.strip() and not line.strip().endswith(":")
                ]
                for name in own:
                    if name in listed:
                        listed.remove(name)
            return listed

    dumpbin = shutil.which("dumpbin")
    if dumpbin is not None:  # pragma: no cover - Windows-only path
        result = subprocess.run(
            [dumpbin, "/DEPENDENTS", str(path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip().lower().endswith(".dll")
            ]
    return None


class TestBinaryParsers:
    """The parsers must agree with the platform's own tools."""

    def test_dependencies_match_the_platforms_own_tool(self) -> None:
        built = built_library()
        if built is None:
            pytest.skip("native library not built in this tree")
        reported = _platform_dependencies(built)
        if reported is None:  # pragma: no cover - depends on runner tooling
            pytest.skip("no dependency-listing tool available on this runner")

        info = gate.parse_binary(built)
        assert reported, (
            f"{built} must depend on at least the platform C library; "
            "an empty result means the tool's output was not parsed"
        )
        if info.fmt.startswith("Mach-O universal"):
            # `otool -L` reports the host slice; the gate unions every slice,
            # so the gate's set is a superset by construction.  That relation
            # is the correct one, not a relaxed one: a dependency present in
            # only a non-host slice still ships.
            assert set(reported) <= set(info.dependencies)
        else:
            assert set(info.dependencies) == set(reported)

    def test_elf_undefined_symbols_match_nm(self) -> None:
        built = built_library()
        if built is None:
            pytest.skip("native library not built in this tree")
        info = gate.parse_binary(built)
        if info.fmt != "ELF":
            pytest.skip(
                f"built library is {info.fmt}; this cross-check is ELF-only "
                "(the Mach-O symbol parsing is covered deterministically on every "
                "runner by TestMachOParsing's constructed images, not left unchecked)"
            )
        nm = shutil.which("nm")
        if nm is None:
            pytest.skip("nm is not installed on this runner")

        out = subprocess.run(
            [nm, "-D", "--undefined-only", str(built)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        expected = {line.split()[-1] for line in out.splitlines() if line.strip()}
        # nm strips the @GLIBC_x.y version suffix from some spellings and not
        # others, so compare on the bare symbol name.
        got = {sym.split("@", 1)[0] for sym in info.undefined_symbols}
        assert got == {sym.split("@", 1)[0] for sym in expected}

    def test_elf_defined_symbols_match_nm(self) -> None:
        """The static-link screen reads the same set the platform reports."""
        built = built_library()
        if built is None:
            pytest.skip("native library not built in this tree")
        info = gate.parse_binary(built)
        if info.fmt != "ELF":
            pytest.skip(
                f"built library is {info.fmt}; this cross-check is ELF-only "
                "(the Mach-O symbol parsing is covered deterministically on every "
                "runner by TestMachOParsing's constructed images, not left unchecked)"
            )
        nm = shutil.which("nm")
        if nm is None:
            pytest.skip("nm is not installed on this runner")

        out = subprocess.run(
            [nm, "-D", "--defined-only", str(built)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        expected = {line.split()[-1].split("@", 1)[0] for line in out.splitlines() if line.strip()}
        got = {sym.split("@", 1)[0] for sym in info.defined_symbols}
        assert expected, "the library must export symbols; an empty set means a parse failure"
        assert got == expected

    def test_truncated_elf_raises_rather_than_reporting_clean(self, tmp_path: Path) -> None:
        truncated = tmp_path / "truncated.so"
        truncated.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 32)
        with pytest.raises((ValueError, struct.error, IndexError)):
            gate.parse_binary(truncated)

    def test_32_bit_elf_is_rejected_rather_than_misparsed(self, tmp_path: Path) -> None:
        elf32 = tmp_path / "elf32.so"
        elf32.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 128)
        with pytest.raises(ValueError, match="64-bit"):
            gate.parse_binary(elf32)


# ---------------------------------------------------------------------------
# Mach-O, built here rather than borrowed from the host
# ---------------------------------------------------------------------------
#
# The macOS branch of the parser cannot be exercised by a Linux or Windows
# runner against a real file, and the branch that was wrong — universal
# binaries — is the one the shipped ``universal2`` wheel actually is.  These
# builders produce genuine Mach-O images from the format's own field layout,
# so every runner tests the macOS path, and a fixture cannot silently agree
# with a wrong parser because the parser plays no part in producing it.

_LC_SYMTAB = 0x02
_LC_LOAD_DYLIB = 0x0C
_N_EXT = 0x01
_N_SECT = 0x0E


def thin_macho(
    dylibs: tuple[str, ...] = (),
    undefined: tuple[str, ...] = (),
    defined: tuple[str, ...] = (),
    *,
    big_endian: bool = False,
) -> bytes:
    """A 64-bit Mach-O image carrying the given load commands and symbols."""
    end = ">" if big_endian else "<"
    header_size = 32

    commands = b""
    for name in dylibs:
        raw = name.encode() + b"\0"
        raw += b"\0" * (-(24 + len(raw)) % 8)
        commands += struct.pack(end + "IIIIII", _LC_LOAD_DYLIB, 24 + len(raw), 24, 0, 0, 0) + raw

    strings = b"\0"
    entries: list[tuple[int, int]] = []
    for name in tuple(undefined) + tuple(defined):
        offset = len(strings)
        strings += name.encode() + b"\0"
        entries.append((offset, _N_EXT if name in undefined else _N_EXT | _N_SECT))

    symbol_offset = header_size + len(commands) + 24
    string_offset = symbol_offset + len(entries) * 16
    commands += struct.pack(
        end + "IIIIII",
        _LC_SYMTAB,
        24,
        symbol_offset,
        len(entries),
        string_offset,
        len(strings),
    )

    header = struct.pack(
        end + "IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, len(dylibs) + 1, len(commands), 0, 0
    )
    symbols = b"".join(
        struct.pack(end + "IBBHQ", offset, kind, 1 if kind & _N_SECT else 0, 0, 0)
        for offset, kind in entries
    )
    return header + commands + symbols + strings


def fat_macho(slices: tuple[bytes, ...], *, wide: bool = False) -> bytes:
    """A universal wrapper around the given thin images."""
    arch_size = 32 if wide else 20
    table_end = 8 + arch_size * len(slices)
    body_start = (table_end + 0x3FFF) & ~0x3FFF

    table = b""
    cursor = body_start
    for index, image in enumerate(slices):
        if wide:
            table += struct.pack(">iiQQII", 0x0100000C, index, cursor, len(image), 14, 0)
        else:
            table += struct.pack(">iiIII", 0x0100000C, index, cursor, len(image), 14)
        cursor += len(image)

    head = struct.pack(">II", 0xCAFEBABF if wide else 0xCAFEBABE, len(slices))
    return head + table + b"\0" * (body_start - table_end) + b"".join(slices)


class TestMachOParsing:
    def _write(self, tmp_path: Path, data: bytes, name: str = "image.dylib") -> Path:
        path = tmp_path / name
        path.write_bytes(data)
        return path

    def test_thin_image_yields_dependencies_and_both_symbol_sets(self, tmp_path: Path) -> None:
        path = self._write(
            tmp_path,
            thin_macho(
                dylibs=("/usr/lib/libSystem.B.dylib",),
                undefined=("_memcpy",),
                defined=("_ama_kem_keypair",),
            ),
        )
        info = gate.parse_binary(path)
        assert info.fmt == "Mach-O"
        assert info.dependencies == ("/usr/lib/libSystem.B.dylib",)
        assert info.undefined_symbols == ("_memcpy",)
        assert info.defined_symbols == ("_ama_kem_keypair",)
        assert gate.check_library(path) == []

    def test_a_dynamically_linked_vendor_is_flagged(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, thin_macho(dylibs=("/opt/homebrew/lib/libcrypto.3.dylib",)))
        assert any("OpenSSL" in v.detail for v in gate.check_library(path))

    def test_an_imported_vendor_symbol_is_flagged(self, tmp_path: Path) -> None:
        """The underscore Mach-O prepends must not hide the prefix."""
        path = self._write(tmp_path, thin_macho(undefined=("_EVP_DigestInit_ex",)))
        violations = gate.check_library(path)
        assert any("OpenSSL" in v.detail for v in violations), violations

    def test_a_statically_linked_vendor_is_flagged(self, tmp_path: Path) -> None:
        """No dependency record, nothing imported — only its own symbols.

        This is the case the dependency and undefined-symbol screens cannot
        see, and it is the one a vendor would take if it wanted to run inside
        the library unnoticed.
        """
        path = self._write(tmp_path, thin_macho(defined=("_sodium_init",)))
        violations = gate.check_library(path)
        assert any("libsodium" in v.detail for v in violations), violations
        assert any("statically" in v.detail for v in violations)

    def test_local_symbols_are_not_screened(self, tmp_path: Path) -> None:
        """A non-external symbol is not evidence of a vendor.

        Screening locals would make the gate fire on any private name that
        happens to share a prefix, which is a false positive that would
        eventually be silenced by loosening the prefix list.
        """
        image = bytearray(thin_macho(defined=("_sodium_init",)))
        # Clear N_EXT on the single symbol: find the nlist and strip the bit.
        marker = image.index(b"_sodium_init")
        for offset in range(32, marker - 16):
            n_strx, n_type = struct.unpack_from("<IB", image, offset)
            if n_type == _N_EXT | _N_SECT and n_strx == 1:
                image[offset + 4] = _N_SECT
                break
        else:  # pragma: no cover - the builder's layout changed
            pytest.fail("could not locate the symbol table entry to de-externalise")
        path = self._write(tmp_path, bytes(image))
        assert gate.parse_binary(path).defined_symbols == ()
        assert gate.check_library(path) == []

    @pytest.mark.parametrize("wide", [False, True], ids=["fat32", "fat64"])
    def test_a_vendor_in_a_non_first_slice_is_still_found(self, tmp_path: Path, wide: bool) -> None:
        """Reading only one slice would be an evasion path.

        A universal binary ships every slice.  A vendor linked into the arm64
        image alone runs on every Apple-silicon machine, and a gate that read
        the x86-64 slice — or the host's — would report it clean.
        """
        clean = thin_macho(dylibs=("/usr/lib/libSystem.B.dylib",))
        dirty = thin_macho(dylibs=("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.dylib"))
        path = self._write(tmp_path, fat_macho((clean, dirty), wide=wide))

        info = gate.parse_binary(path)
        assert info.fmt.startswith("Mach-O universal")
        assert "/usr/lib/libcrypto.dylib" in info.dependencies
        assert any("OpenSSL" in v.detail for v in gate.check_library(path))

    def test_a_universal_binary_of_clean_slices_is_clean(self, tmp_path: Path) -> None:
        clean = thin_macho(dylibs=("/usr/lib/libSystem.B.dylib",), defined=("_ama_init",))
        path = self._write(tmp_path, fat_macho((clean, clean)))
        assert gate.check_library(path) == []
        # Unioned, not concatenated: the same dependency in both slices is
        # one dependency.
        assert gate.parse_binary(path).dependencies == ("/usr/lib/libSystem.B.dylib",)

    def test_big_endian_image_is_decoded_with_the_right_byte_order(self, tmp_path: Path) -> None:
        """The swapped magic means big-endian fields, not little-endian ones.

        Both swapped spellings were mapped to little-endian when this parser
        was written; decoding a big-endian image that way reads ``ncmds`` in
        the millions and walks load commands from nonsense offsets.
        """
        path = self._write(
            tmp_path, thin_macho(dylibs=("/usr/lib/libcrypto.dylib",), big_endian=True)
        )
        assert gate.parse_binary(path).dependencies == ("/usr/lib/libcrypto.dylib",)
        assert any("OpenSSL" in v.detail for v in gate.check_library(path))

    def test_a_java_class_file_is_not_read_as_a_universal_binary(self, tmp_path: Path) -> None:
        """``0xCAFEBABE`` is also Java's magic; a wrong reading must raise."""
        path = self._write(tmp_path, b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 128)
        with pytest.raises(ValueError):
            gate.parse_binary(path)

    def test_a_slice_pointing_outside_the_file_raises(self, tmp_path: Path) -> None:
        image = bytearray(fat_macho((thin_macho(dylibs=("/usr/lib/libSystem.B.dylib",)),)))
        struct.pack_into(">I", image, 8 + 8, 0xFFFF0000)  # slice offset
        path = self._write(tmp_path, bytes(image))
        with pytest.raises(ValueError, match="outside"):
            gate.parse_binary(path)

    def test_a_symtab_pointing_outside_the_file_raises(self, tmp_path: Path) -> None:
        """A truncated image must raise, never report an empty symbol set."""
        image = thin_macho(defined=("_sodium_init",))
        path = self._write(tmp_path, image[: len(image) - 8])
        with pytest.raises(ValueError, match="outside"):
            gate.parse_binary(path)


class TestBuildConfigCheck:
    """A vendor linked by the build files leaves no trace to find later.

    ``check_library`` reads a built artefact.  A static link with hidden
    visibility produces an artefact with no dependency record, no imported
    symbol and no exported one — clean by every linkage measure while running
    vendor code.  The decision is visible in exactly one place: the build
    files.
    """

    def _cmake(self, tmp_path: Path, body: str) -> Path:
        (tmp_path / "CMakeLists.txt").write_text(body, encoding="utf-8")
        return tmp_path

    def test_the_repository_itself_is_clean(self) -> None:
        assert gate.check_build_config(REPO_ROOT) == []

    def test_the_repository_check_actually_examined_files(self) -> None:
        """A clean result must come from having looked, not from an empty list."""
        assert gate.check_build_config(REPO_ROOT / "tools") == [
            gate.Violation(
                "build-config",
                str(REPO_ROOT / "tools"),
                "no build files found — refusing to report clean having examined nothing",
            )
        ]

    @pytest.mark.parametrize(
        ("body", "vendor"),
        [
            ("find_package(OpenSSL REQUIRED)\n", "OpenSSL"),
            ("target_link_libraries(ama PRIVATE OpenSSL::Crypto)\n", "OpenSSL"),
            ("target_link_libraries(ama PRIVATE sodium)\n", "libsodium"),
            ("target_link_libraries(ama PRIVATE /usr/lib/libcrypto.so.3)\n", "OpenSSL"),
            ('set(CMAKE_EXE_LINKER_FLAGS "-lgcrypt")\n', "libgcrypt"),
            ("pkg_check_modules(MBED REQUIRED mbedtls)\n", "mbedTLS"),
            ("target_link_libraries(ama PRIVATE $<$<BOOL:${X}>:wolfssl>)\n", "wolfSSL"),
            ("find_library(NETTLE_LIB nettle)\n", "Nettle"),
            ("target_link_libraries(ama PRIVATE botan-3)\n", "Botan"),
        ],
    )
    def test_each_way_a_vendor_reaches_the_link_line_is_flagged(
        self, tmp_path: Path, body: str, vendor: str
    ) -> None:
        violations = gate.check_build_config(self._cmake(tmp_path, body))
        assert violations, body
        assert any(vendor in v.detail for v in violations), violations

    @pytest.mark.parametrize(
        "body",
        [
            "# OpenSSL: deliberately NOT probed. No find_package(OpenSSL) here.\n",
            'message(STATUS "Native PQC enabled (zero OpenSSL dependency)")\n',
            "target_link_libraries(ama_cryptography PRIVATE m Threads::Threads)\n",
            "find_package(Python3 COMPONENTS Development REQUIRED)\n",
        ],
    )
    def test_a_mention_is_not_a_link(self, tmp_path: Path, body: str) -> None:
        """The tree documents why OpenSSL is not used, in prose that names it.

        A word-level scan would fire on the documentation of the boundary it
        exists to enforce, and the fix for that false positive would be to
        weaken the scan.  Matching commands instead of words avoids needing
        the exemption at all.
        """
        assert gate.check_build_config(self._cmake(tmp_path, body)) == []

    def test_a_hash_inside_a_quoted_string_does_not_hide_the_rest_of_the_line(
        self, tmp_path: Path
    ) -> None:
        body = 'set(BANNER "release #1")\nfind_package(OpenSSL REQUIRED)\n'
        assert gate.check_build_config(self._cmake(tmp_path, body))

    def test_the_comparator_package_may_link_its_comparators(self, tmp_path: Path) -> None:
        """A comparative benchmark that cannot link its comparators measures nothing."""
        benchmarks = tmp_path / "benchmarks"
        benchmarks.mkdir()
        (benchmarks / "CMakeLists.txt").write_text(
            "find_package(OpenSSL REQUIRED)\n"
            "target_link_libraries(bench PRIVATE OpenSSL::Crypto)\n",
            encoding="utf-8",
        )
        (tmp_path / "CMakeLists.txt").write_text("add_subdirectory(benchmarks)\n", encoding="utf-8")
        assert gate.check_build_config(tmp_path) == []

    def test_generated_build_output_is_not_scanned(self, tmp_path: Path) -> None:
        """``build/`` holds CMake's own generated files, not AMA's choices."""
        generated = tmp_path / "build" / "CMakeFiles"
        generated.mkdir(parents=True)
        (generated / "CMakeLists.txt").write_text("find_package(OpenSSL)\n", encoding="utf-8")
        (tmp_path / "CMakeLists.txt").write_text("project(ama)\n", encoding="utf-8")
        assert gate.check_build_config(tmp_path) == []

    def test_every_screened_vendor_has_at_least_one_link_token(self) -> None:
        tokens = gate._vendor_link_tokens()
        for vendor in gate.VENDORS:
            assert vendor.name.lower() in tokens, vendor.name

    def test_openssl_owns_the_crypto_token(self) -> None:
        """``-lcrypto`` is OpenSSL, not PyCryptodome's ``Crypto`` module.

        Both spell a token ``crypto``; attributing a linker flag to a Python
        package would send a reader looking in the wrong place.
        """
        assert gate._vendor_link_tokens()["crypto"] == "OpenSSL"


class TestRuntimeCheck:
    def test_runtime_check_is_clean_on_this_tree(self) -> None:
        violations = gate.check_runtime(REPO_ROOT)
        # A tree without a built library cannot import the package at all;
        # that is reported as a violation (fail-closed), not as clean.
        if violations and "could not be imported" in violations[0].detail:
            pytest.skip("native library not built in this tree")
        assert violations == []

    def test_a_resident_vendor_binding_is_flagged(self, tmp_path: Path) -> None:
        """Inject an OpenSSL binding into every interpreter via sitecustomize.

        This is the transitive-import case the source scan cannot see: no
        `import` statement in this repository names the module, and it is
        nonetheless resident in the process that runs AMA's code.
        """
        pytest.importorskip("cryptography")
        inject = tmp_path / "inject"
        inject.mkdir()
        (inject / "sitecustomize.py").write_text("import cryptography\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(GATE_PATH), "--runtime"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**_clean_env(), "PYTHONPATH": str(inject)},
        )
        if "could not be imported" in proc.stderr:
            pytest.skip("native library not built in this tree")
        assert proc.returncode == 1
        assert "'cryptography' is resident" in proc.stderr


def _clean_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


class TestWiredIntoCI:
    def test_ci_workflow_invokes_the_gate(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "tools/check_vendor_isolation.py" in workflow

    def test_ci_invocation_passes_a_library(self) -> None:
        """The source and runtime checks run by default; the library check
        only runs when a path is given, so the CI call must give one."""
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        idx = workflow.index("tools/check_vendor_isolation.py")
        assert "--library" in workflow[idx : idx + 400]

    def test_ci_invocation_does_not_narrow_to_one_check(self) -> None:
        """Selecting any single check switches the others off.

        ``--source``, ``--build-config`` and ``--runtime`` are selectors: the
        default runs all of them, and naming one runs only that one.  A CI
        line that grew a selector would keep exiting 0 while silently
        checking a quarter of what its name implies.
        """
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        idx = workflow.index("tools/check_vendor_isolation.py")
        invocation = workflow[idx : idx + 400].split("\n", 1)[0]
        for selector in ("--source", "--build-config", "--runtime"):
            assert (
                selector not in invocation
            ), f"{selector} in the CI invocation disables every other check: {invocation!r}"

    def test_the_default_run_selects_every_check(self) -> None:
        """What the CI line relies on, asserted rather than assumed."""
        result = subprocess.run(
            [sys.executable, str(GATE_PATH), "--no-runtime"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
        assert "source (" in result.stdout
        assert "build config" in result.stdout


class TestVendorTableIsComplete:
    def test_every_owner_forbidden_vendor_is_screened(self) -> None:
        """The seven implementations named in the repository's policy."""
        screened = {v.name for v in gate.VENDORS}
        required = {
            "OpenSSL",
            "libsodium",
            "wolfSSL",
            "Botan",
            "Nettle",
            "libgcrypt",
            "mbedTLS",
        }
        assert required <= screened

    def test_every_vendor_is_identifiable_somehow(self) -> None:
        for vendor in gate.VENDORS:
            assert (
                vendor.modules or vendor.library_names or vendor.symbol_prefixes
            ), f"{vendor.name} has no identifying marker and can never be detected"

    def test_stdlib_openssl_accelerators_are_not_screened(self) -> None:
        """`hashlib`/`_hashlib`/`_ssl` are CPython's own stdlib.

        INVARIANT-1 admits `hashlib` for hashing; screening the interpreter's
        accelerator modules would make this gate fail on a stock CPython
        rather than on an AMA defect.
        """
        screened_modules = {m for v in gate.VENDORS for m in v.modules}
        assert screened_modules.isdisjoint({"hashlib", "_hashlib", "_ssl", "ssl"})


class TestContainerRecipes:
    """Dockerfiles are build inputs, and nothing read them.

    ``docker/Dockerfile`` and ``docker/Dockerfile.alpine`` each carried an
    explicit INVARIANT-1 paragraph — "libssl-dev is NOT installed",
    "openssl-dev is deliberately absent" — while ``docker/Dockerfile.c-api``
    installed ``libssl-dev`` in its builder stage and ``libssl3`` in its output
    stage, and ``Dockerfile.alpine``'s own runtime stage installed ``libssl3``:
    the runtime half of the thing its builder stage says is absent.

    ``_BUILD_CONFIG_GLOBS`` covered ``CMakeLists.txt``, ``**/CMakeLists.txt``,
    ``cmake/**/*.cmake`` and ``setup.py``.  No Dockerfile could reach it, so
    the gate reported clean over all three, and the rule lived only in prose in
    the files that broke it.

    Installing OpenSSL does not link it — nothing in this tree does — but it
    puts a CVE-prone library on disk in an image whose own comments say it is
    not there, and a runtime image is exactly where a future ``dlopen`` would
    find one.
    """

    @staticmethod
    def _recipe(tmp_path: Path, body: str, name: str = "Dockerfile") -> Path:
        directory = tmp_path / "docker"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(body, encoding="utf-8")
        return tmp_path

    @pytest.mark.parametrize(
        "body,package",
        [
            (
                "RUN apt-get update && apt-get install -y \\\n    libssl-dev \\\n    cmake\n",
                "libssl-dev",
            ),
            (
                "RUN apt-get update && apt-get install -y \\\n    libssl3 \\\n && rm -rf /x\n",
                "libssl3",
            ),
            ("RUN apk add --no-cache \\\n    libsodium-dev \\\n    python3\n", "libsodium-dev"),
            ("RUN apk add --no-cache openssl-dev musl-dev\n", "openssl-dev"),
            ("RUN dnf install -y libgcrypt-devel\n", "libgcrypt-devel"),
        ],
    )
    def test_a_vendor_package_install_is_reported(
        self, tmp_path: Path, body: str, package: str
    ) -> None:
        root = self._recipe(tmp_path, body)
        violations = gate.check_container_recipes(root)
        assert violations, f"accepted an install of {package}"
        assert package in violations[0].detail

    @pytest.mark.parametrize(
        "body",
        [
            "RUN apt-get update && apt-get install -y \\\n    cmake \\\n    python3\n",
            "RUN apk add --no-cache python3 py3-pip musl-dev\n",
            "# libssl-dev is NOT installed (INVARIANT-1)\nRUN apk add --no-cache python3\n",
            "RUN apt-cache policy libssl-dev\n",
        ],
    )
    def test_a_clean_recipe_passes(self, tmp_path: Path, body: str) -> None:
        assert gate.check_container_recipes(self._recipe(tmp_path, body)) == []

    def test_a_package_after_a_line_continuation_is_still_seen(self, tmp_path: Path) -> None:
        """Every package name in these files is on a continued line.

        With the continuation alternative ordered after ``[^\\n]`` the scan
        stops at the end of the first physical line, so ``RUN apk add
        --no-cache \\`` reads as installing nothing — the shape of every
        install in this repository.
        """
        body = "RUN apk add --no-cache \\\n    python3 \\\n    libssl3 \\\n    py3-pip\n"
        assert gate.check_container_recipes(self._recipe(tmp_path, body))

    def test_options_are_not_mistaken_for_packages(self, tmp_path: Path) -> None:
        body = "RUN apt-get install -y --no-install-recommends cmake\n"
        assert gate.check_container_recipes(self._recipe(tmp_path, body)) == []

    def test_an_empty_scope_fails_closed(self, tmp_path: Path) -> None:
        violations = gate.check_container_recipes(tmp_path)
        assert violations and "examined nothing" in violations[0].detail

    def test_the_shipped_recipes_are_clean(self) -> None:
        assert gate.check_container_recipes(REPO_ROOT) == []

    def test_the_scan_is_not_vacuous_on_the_real_tree(self) -> None:
        """Being "clean" must mean recipes were found and read."""
        found = sorted(p.name for pattern in gate._CONTAINER_GLOBS for p in REPO_ROOT.glob(pattern))
        assert len(found) >= 3, found
