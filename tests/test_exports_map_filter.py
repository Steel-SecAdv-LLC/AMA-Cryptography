# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The ELF version script each link sees names only what that link defines.

``cmake/ama_exports.map`` is the single declaration of what is internal, and
its ``local:`` block names the kernels of every architecture and
configuration.  lld >= 16 defaults to ``--no-undefined-version`` and refuses a
version-script name that matches nothing; measured with ld.lld 18.1.3 on this
tree, ``libama_cryptography.so`` did not link at all (``version script
assignment of 'local' to symbol 'ama_ascon_permutation_for_test' failed:
symbol not defined``, and one line per absent name).

``cmake/filter_exports_map.cmake`` runs as a PRE_LINK step and writes the map
with every ``local:`` name the objects do not define removed, deciding
"defines" from the symbol index of an archive of those objects.  These tests
pin the filter on synthetic objects, the lld behaviour it exists for, and the
CMake wiring that makes the shared library link with its output.

ELF-only by construction (the macOS and PE links read the same source map
through their own generated lists), so the behavioural tests run where ELF
objects, ``ar`` and ``cmake`` are available.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FILTER = REPO_ROOT / "cmake" / "filter_exports_map.cmake"
SOURCE_MAP = REPO_ROOT / "cmake" / "ama_exports.map"

CMAKE = shutil.which("cmake")
CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
AR = shutil.which("ar")
LLD = shutil.which("ld.lld")

needs_elf_toolchain = pytest.mark.skipif(
    not sys.platform.startswith("linux") or not (CMAKE and CC and AR),
    reason="the filter serves the ELF link; needs Linux with cmake, cc and ar",
)

#: The line shape every consumer of the map parses (CMakeLists.txt for macOS,
#: cmake/generate_pe_def.cmake, tools/check_public_api_docs.py).
_LOCAL_ENTRY = re.compile(r"^\s*(ama_[A-Za-z0-9_]+)\s*;", re.MULTILINE)

SYNTHETIC_MAP = """\
# comment naming ama_absent; which must survive untouched
{
    global:
        ama_*;
    local:
        ama_kept_one;
        ama_absent;
        # an indented comment
        ama_kept_two;
        ama_referenced_only;
        *;
};
"""


def _compile(tmp: Path, name: str, source: str) -> Path:
    src = tmp / f"{name}.c"
    src.write_text(source, encoding="utf-8")
    obj = tmp / f"{name}.o"
    subprocess.run([str(CC), "-c", "-fPIC", "-O1", str(src), "-o", str(obj)], check=True)
    return obj


def _filter(
    tmp: Path, map_in: Path, objects: list[Path]
) -> tuple[subprocess.CompletedProcess[str], Path]:
    out = tmp / "out.map"
    completed = subprocess.run(
        [
            str(CMAKE),
            f"-DAMA_MAP_IN={map_in}",
            f"-DAMA_MAP_OUT={out}",
            f"-DAMA_AR={AR}",
            "-DAMA_OBJECTS=" + ";".join(str(o) for o in objects),
            "-P",
            str(FILTER),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed, out


def _synthetic_objects(tmp: Path) -> list[Path]:
    return [
        _compile(tmp, "a", "int ama_kept_one(void) { return 1; }\n"),
        # A REFERENCE to ama_referenced_only is in this object's symbol table
        # as undefined; only a definition may keep a local: entry.
        _compile(
            tmp,
            "b",
            "int ama_referenced_only(void);\n"
            "int ama_kept_two(void) { return ama_referenced_only(); }\n",
        ),
    ]


@needs_elf_toolchain
class TestTheFilter:
    def test_keeps_exactly_the_defined_local_names(self, tmp_path: Path) -> None:
        map_in = tmp_path / "in.map"
        map_in.write_text(SYNTHETIC_MAP, encoding="utf-8")
        completed, out = _filter(tmp_path, map_in, _synthetic_objects(tmp_path))
        assert completed.returncode == 0, completed.stderr
        body = out.read_text(encoding="utf-8")
        assert _LOCAL_ENTRY.findall(body.split("local:", 1)[1]) == [
            "ama_kept_one",
            "ama_kept_two",
        ]
        # Everything else survives byte for byte: the leading comment that
        # merely mentions a dropped name, the global wildcard, the indented
        # comment and the catch-all.
        assert "# comment naming ama_absent; which must survive untouched" in body
        assert "global:\n        ama_*;" in body
        assert "# an indented comment" in body
        assert "        *;\n};" in body
        assert "2 local: name(s) kept; 2 dropped" in body

    def test_the_real_map_passes_through_unchanged_when_everything_is_defined(
        self, tmp_path: Path
    ) -> None:
        """Every name the real map localises, defined: the output body must BE
        the source map.  Pins that the filter parses the same names the gates
        do and mangles no line of the real file."""
        names = _LOCAL_ENTRY.findall(SOURCE_MAP.read_text(encoding="utf-8").split("local:", 1)[1])
        assert len(names) >= 30, "the real map's local: block no longer parses"
        obj = _compile(
            tmp_path, "all", "".join(f"int {name}(void) {{ return 0; }}\n" for name in names)
        )
        completed, out = _filter(tmp_path, SOURCE_MAP, [obj])
        assert completed.returncode == 0, completed.stderr
        body = out.read_text(encoding="utf-8").split("\n", 3)
        assert body[2] == f"# {len(names)} local: name(s) kept; 0 dropped as not defined here."
        assert body[3] == SOURCE_MAP.read_text(encoding="utf-8")

    def test_an_index_without_ama_symbols_fails_closed(self, tmp_path: Path) -> None:
        map_in = tmp_path / "in.map"
        map_in.write_text(SYNTHETIC_MAP, encoding="utf-8")
        obj = _compile(tmp_path, "none", "int unrelated(void) { return 0; }\n")
        completed, out = _filter(tmp_path, map_in, [obj])
        assert completed.returncode != 0
        assert "names no ama_* symbol" in completed.stderr
        assert not out.exists()


@needs_elf_toolchain
@pytest.mark.skipif(LLD is None, reason="ld.lld is not on PATH")
class TestLldLinksTheFilteredMap:
    """The defect and the fix, on the linker that exposed it."""

    def _link(self, tmp: Path, objects: list[Path], version_script: Path, linker: str) -> str:
        completed = subprocess.run(
            [
                str(CC),
                "-shared",
                f"-fuse-ld={linker}",
                *map(str, objects),
                f"-Wl,--version-script={version_script}",
                "-o",
                str(tmp / f"lib-{linker}.so"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stderr if completed.returncode else ""

    def test_the_source_map_is_refused_and_the_filtered_map_links(self, tmp_path: Path) -> None:
        map_in = tmp_path / "in.map"
        map_in.write_text(SYNTHETIC_MAP, encoding="utf-8")
        objects = [
            _compile(tmp_path, "a", "int ama_kept_one(void) { return 1; }\n"),
            _compile(tmp_path, "b", "int ama_kept_two(void) { return 2; }\n"),
        ]
        # Non-vacuity: lld refuses the unfiltered map exactly as it refused the
        # library's.
        refused = self._link(tmp_path, objects, map_in, "lld")
        assert "symbol not defined" in refused, refused or "lld accepted the source map"

        completed, out = _filter(tmp_path, map_in, objects)
        assert completed.returncode == 0, completed.stderr
        assert self._link(tmp_path, objects, out, "lld") == ""
        assert self._link(tmp_path, objects, out, "bfd") == ""


class TestTheSharedLibraryLinksTheGeneratedMap:
    """Structural: the ELF link must use the generated map, not the source map.

    Reverting the wiring to ``--version-script=.../cmake/ama_exports.map`` puts
    the lld failure back; this is what notices.
    """

    CMAKELISTS = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

    def test_the_version_script_is_the_generated_one(self) -> None:
        scripts = re.findall(r"--version-script=([^\"\s]+)", self.CMAKELISTS)
        assert scripts == ["${_ama_elf_map}"], scripts

    def test_the_filter_runs_before_the_link_over_the_librarys_own_objects(self) -> None:
        block = self.CMAKELISTS.split(
            "add_custom_command(TARGET ama_cryptography_shared PRE_LINK", 1
        )
        assert len(block) == 2, "the PRE_LINK filter step is gone"
        step = block[1].split("VERBATIM)", 1)[0]
        assert "cmake/filter_exports_map.cmake" in step
        assert "$<TARGET_OBJECTS:ama_cryptography_shared>" in step
        assert '"-DAMA_MAP_OUT=${_ama_elf_map}"' in step
