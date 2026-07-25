# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for tools/check_headers.py.

Two jobs, mirroring tests/test_version_consistency.py:

  * the real tree must be clean, so the CI gate has a durable
    steady state to defend; and
  * a synthetic tree carrying each of the *wrong* header shapes the
    repository used to contain must be flagged, and must normalize to
    the canonical two-line form — so the scanner is known to be able
    to fail, not merely known to pass.

The stale shapes exercised below are the ones that were actually in
the tree before normalization: the two-line "Licensed under the Apache
License, Version 2.0" note, the thirteen-line Apache boilerplate block,
the C block-comment variants of both, the one-off "Apache License 2.0"
spelling, and a file with no header at all.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_headers.py"

FULL_APACHE_BLOCK = """\
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""

# The same boilerplate in the C block-comment form the tree carried, with the
# copyright inline on the opener — the shape that leaves an orphan `*/` behind
# if the remover works on a flat line window instead of per comment block.
# src/c/internal/ama_ed25519_canonical.h carried exactly this.
C_FULL_APACHE_BLOCK = """\
/* Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""


@pytest.fixture(scope="module")
def tool_module() -> ModuleType:
    """Load tools/check_headers.py as a module so its functions can be
    called directly. The script lives in a non-package directory and
    isn't on sys.path, so importlib.util is the cleanest handle that
    doesn't require modifying the tool layout."""
    spec = importlib.util.spec_from_file_location("check_headers", TOOL_PATH)
    assert spec is not None, f"could not build a ModuleSpec for {TOOL_PATH}"
    assert spec.loader is not None, f"ModuleSpec for {TOOL_PATH} has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git_tree(root: Path, files: dict[str, str]) -> Path:
    """Materialize ``files`` into a real git repo so the tool's
    ``git ls-files`` enumeration has something to enumerate."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


# ---------------------------------------------------------------------------
# Steady state: the shipped tree is clean.
# ---------------------------------------------------------------------------


def test_real_tree_is_clean(tool_module: ModuleType) -> None:
    """Every headed file in the checked-in tree carries the canonical
    header. This is the invariant the CI gate defends; if it fires, a
    file drifted and `python tools/check_headers.py --apply` fixes it."""
    assert tool_module.main(["--check", "--root", str(REPO_ROOT)]) == 0


def test_real_tree_selects_a_substantial_file_set(tool_module: ModuleType) -> None:
    """Guard against the scanner silently selecting nothing — an empty
    selection would make the gate pass vacuously. The tree carries
    several hundred headed sources; the floor below is deliberately
    loose so ordinary additions and deletions don't trip it."""
    selected = tool_module.selected_files(REPO_ROOT)
    assert len(selected) > 250, f"only {len(selected)} files selected"
    styles = {style for _, style in selected}
    assert styles == {"hash", "c"}


def test_exemptions_are_documented(tool_module: ModuleType) -> None:
    """Every exemption carries a reason. A bare skip list is how a gate
    quietly stops covering things."""
    assert tool_module.EXEMPTIONS
    for entry, reason in tool_module.EXEMPTIONS.items():
        assert reason.strip(), f"exemption {entry!r} has no stated reason"
        assert len(reason) > 20, f"exemption {entry!r} reason is too thin: {reason!r}"


def test_spdx_identifier_is_the_registered_one(tool_module: ModuleType) -> None:
    """`Apache-2.0` is the SPDX license-list identifier. `Apache 2.0`
    is not one and does not parse, so a header carrying it is worse
    than an untagged file."""
    assert tool_module.SPDX_LINE == "SPDX-License-Identifier: Apache-2.0"
    assert "Apache 2.0" not in tool_module.SPDX_LINE


def test_copyright_term_is_preserved(tool_module: ModuleType) -> None:
    """The tree asserts a 2025-2026 copyright term. Narrowing it to a
    single year would misstate the term, so it is pinned here."""
    assert tool_module.COPYRIGHT_LINE == ("Copyright (C) 2025-2026 Steel Security Advisors LLC")


# ---------------------------------------------------------------------------
# Failure detection: each stale shape must be flagged.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [
        (
            "two_line_note.py",
            "# Copyright 2025-2026 Steel Security Advisors LLC\n"
            "# Licensed under the Apache License, Version 2.0\n"
            '"""Module."""\n',
            "non-canonical license header",
        ),
        (
            "full_block.py",
            FULL_APACHE_BLOCK + '\n"""Module."""\n',
            "non-canonical license header",
        ),
        (
            "one_off_spelling.py",
            "# Copyright 2025-2026 Steel Security Advisors LLC\n"
            "# Licensed under the Apache License 2.0\n",
            "non-canonical license header",
        ),
        (
            "unregistered_spdx.py",
            "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
            "# SPDX-License-Identifier: Apache 2.0\n",
            "non-canonical license header",
        ),
        (
            "no_header.py",
            "import os\n",
            "missing license header",
        ),
        (
            "c_two_line.c",
            "/**\n"
            " * Copyright 2025-2026 Steel Security Advisors LLC\n"
            " * Licensed under the Apache License, Version 2.0\n"
            " *\n"
            " * @file c_two_line.c\n"
            " */\n"
            "int main(void) { return 0; }\n",
            "non-canonical license header",
        ),
        (
            "c_inline_opener.h",
            "/* Copyright 2025-2026 Steel Security Advisors LLC\n"
            " *\n"
            ' * Licensed under the Apache License, Version 2.0 (the "License");\n'
            " * limitations under the License.\n"
            " */\n"
            "#define X 1\n",
            "non-canonical license header",
        ),
    ],
)
def test_stale_shape_is_flagged(
    tool_module: ModuleType, name: str, body: str, expected: str
) -> None:
    """Each header shape the repository used to carry must be reported
    as non-compliant, with a reason naming what is wrong."""
    style = "c" if name.endswith((".c", ".h")) else "hash"
    assert tool_module.diagnose(body, style) == expected


def test_synthetic_tree_is_flagged_then_fixed(tool_module: ModuleType, tmp_path: Path) -> None:
    """End-to-end: build a git tree carrying wrong headers, assert
    --check fails and names every offender, then assert --apply makes
    --check pass. This is the whole contract of the tool in one test."""
    root = _git_tree(
        tmp_path / "synthetic",
        {
            "a.py": "#!/usr/bin/env python3\n"
            "# Copyright 2025-2026 Steel Security Advisors LLC\n"
            "# Licensed under the Apache License, Version 2.0\n"
            '"""Docstring survives."""\n'
            "VALUE = 1\n",
            "b.c": "/**\n"
            " * Copyright 2025-2026 Steel Security Advisors LLC\n"
            " * Licensed under the Apache License, Version 2.0\n"
            " *\n"
            " * @file b.c\n"
            " */\n"
            "int main(void) { return 0; }\n",
            "c.h": C_FULL_APACHE_BLOCK + "#define C_H 1\n",
            "d.py": "import os\n",
            "data.json": '{"not": "headed"}\n',
        },
    )

    assert tool_module.main(["--check", "--root", str(root)]) == 1
    assert tool_module.main(["--apply", "--root", str(root)]) == 0
    assert tool_module.main(["--check", "--root", str(root)]) == 0

    a = (root / "a.py").read_text(encoding="utf-8")
    assert a.startswith(
        "#!/usr/bin/env python3\n"
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
    ), a
    assert '"""Docstring survives."""' in a, "module docstring was dropped"
    assert "VALUE = 1" in a
    assert "Licensed under the Apache License, Version 2.0" not in a

    b = (root / "b.c").read_text(encoding="utf-8")
    assert b.startswith(
        "/* Copyright (C) 2025-2026 Steel Security Advisors LLC */\n"
        "/* SPDX-License-Identifier: Apache-2.0 */\n"
    ), b
    assert "@file b.c" in b, "surrounding doc block content was dropped"
    assert "int main(void) { return 0; }" in b

    # A file that had no header at all gains one.
    d = (root / "d.py").read_text(encoding="utf-8")
    assert d == (
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "import os\n"
    )

    # A data file with no comment syntax is left strictly alone.
    assert (root / "data.json").read_text(encoding="utf-8") == '{"not": "headed"}\n'


def test_apply_is_idempotent(tool_module: ModuleType, tmp_path: Path) -> None:
    """Running --apply twice must not keep changing the file; a
    normalizer that drifts on every run cannot be a CI gate."""
    root = _git_tree(
        tmp_path / "idem",
        {"m.py": "# Copyright 2025-2026 Steel Security Advisors LLC\n" "x = 1\n"},
    )
    assert tool_module.main(["--apply", "--root", str(root)]) == 0
    once = (root / "m.py").read_text(encoding="utf-8")
    assert tool_module.main(["--apply", "--root", str(root)]) == 0
    assert (root / "m.py").read_text(encoding="utf-8") == once


def test_shebang_stays_first(tool_module: ModuleType) -> None:
    """A shebang must remain line 1 or the script stops being
    executable; the header goes immediately below it."""
    out = tool_module.render("#!/bin/sh\necho hi\n", "hash")
    assert out.splitlines()[0] == "#!/bin/sh"
    assert out.splitlines()[1:3] == list(tool_module.HASH_HEADER)


def test_residual_license_text_is_flagged(tool_module: ModuleType) -> None:
    """A file that carries the canonical header *and* leftover
    boilerplate further down is still wrong — that is the shape a
    half-finished manual edit leaves behind."""
    text = (
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        '"""Doc."""\n'
        "\n"
        "# Licensed under the Apache License, Version 2.0\n"
    )
    reason = tool_module.diagnose(text, "hash")
    assert reason is not None and reason.startswith("residual license text")


def test_header_text_inside_a_string_literal_is_not_residue(tool_module: ModuleType) -> None:
    """ama_cryptography/_build_sign.py holds the *template* for the
    generated _integrity_signature.py, and that template contains a
    literal SPDX line. It is data inside a string, not a second header,
    and must not be reported as residue — otherwise the generator could
    not emit a compliant file."""
    text = (
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        '"""Real module docstring."""\n'
        "\n"
        "TEMPLATE = '''# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        '"""Generated."""\n'
        "'''\n"
    )
    assert tool_module.diagnose(text, "hash") is None


def test_license_in_a_module_docstring_is_still_residue(tool_module: ModuleType) -> None:
    """The module docstring is deliberately *not* excluded from the
    residue scan: the Cython bindings carried their license as the
    docstring's opening paragraph, and that shape must still be
    caught."""
    text = (
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        '"""\n'
        "Copyright 2025-2026 Steel Security Advisors LLC\n"
        "Licensed under the Apache License, Version 2.0\n"
        '"""\n'
    )
    reason = tool_module.diagnose(text, "hash")
    assert reason is not None and reason.startswith("residual license text")


def test_generated_signature_module_carries_the_header() -> None:
    """ama_cryptography/_integrity_signature.py is regenerated on every
    wheel build. If the generator's template lost the header, the next
    build would silently reintroduce a non-compliant file, so the
    template is pinned here rather than only the current output."""
    build_sign = (REPO_ROOT / "ama_cryptography" / "_build_sign.py").read_text(encoding="utf-8")
    marker = "_SIGNATURE_TEMPLATE = '''"
    assert marker in build_sign
    template = build_sign.split(marker, 1)[1]
    assert template.startswith(
        "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
    ), "the generated integrity-signature module would not carry the canonical header"


def test_vendored_tree_is_exempt(tool_module: ModuleType) -> None:
    """Vendored third-party sources must keep upstream provenance
    byte-identical, so they are never rewritten."""
    assert tool_module.is_exempt("src/c/vendor/ed25519-donna/ed25519-donna.h")
    assert tool_module.is_exempt("tests/c/dudect/dudect.h")
    assert not tool_module.is_exempt("src/c/ama_ed25519.c")


def test_license_and_notice_are_exempt(tool_module: ModuleType) -> None:
    """The root LICENSE stays the authoritative text and NOTICE is
    required verbatim by Apache-2.0 section 4(d)."""
    assert tool_module.is_exempt("LICENSE")
    assert tool_module.is_exempt("NOTICE")


def test_data_files_are_not_selected(tool_module: ModuleType) -> None:
    """Formats with no comment syntax must not be selected at all —
    a header would corrupt them."""
    for rel in (
        "tests/kat/vectors.json",
        "fuzz/dictionaries/x25519.dict",
        "nist_vectors/SHA-256-FIPS180-4.json",
        "assets/logo.png",
        "docs/index.rst",
        "README.md",
        ".gitignore",
    ):
        assert tool_module.style_for(rel) is None, rel
