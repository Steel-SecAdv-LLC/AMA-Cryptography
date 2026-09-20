#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Execute, compile and type-check the examples in the user-facing documentation.

The fact this gate protects
---------------------------
A copy-pasteable example is API surface.  A reader cannot verify one without
running it, and a reader who runs one and gets a traceback concludes the
library is broken — not the page.  Before this gate the four pages new users
are pointed at carried, among others:

* ``create_crypto_package(codes, helix_params, kms)`` — ``author`` has been a
  required fourth positional argument for as long as the function has existed,
  so the line raises ``TypeError`` on the first run.
* ``print(f"Package created: {package['package_id']}")`` — the result is a
  ``CryptoPackage`` dataclass.  Not subscriptable, and no such field.
* ``with SecureBuffer(32) as buf: buf.data[:] = ...`` — ``__enter__`` yields the
  ``bytearray``, so ``buf.data`` is an ``AttributeError`` inside the block.
* ``locked: bool = secure_mlock(buffer)`` — ``secure_mlock`` returns ``None``
  and raises on failure.  A reader who branches on the return value takes the
  failure path on every successful lock.
* ``MASTER_OMNI_CODES`` — a name that appears nowhere in the package.
* ``print(get_pqc_status())`` followed by a JSON object — it returns a
  ``PQCStatus`` enum.
* and, worst, a C example that passed **uninitialised stack memory** as an
  Ed25519 seed (``uint8_t sk[64]; ama_ed25519_keypair(pk, sk);``).  It compiles
  without a warning, prints ``valid=1``, and mints a private key from whatever
  the stack happened to hold.

Every one of those was in a document whose whole purpose is to be copied.

How it works
------------
Each fenced ``python`` or ``c`` block in a COVERED file must carry a directive
in an HTML comment on the line before its opening fence::

    <!-- example: python-run -->
    <!-- example: python-signature module=ama_cryptography.secure_memory -->
    <!-- example: c-run -->
    <!-- example: c-decl -->
    <!-- example: pseudocode: why this block is not executable -->

An unmarked block is a failure.  That is the point: the directive is how an
author states what the block claims, and "this one is illustrative" has to be
written down rather than assumed.

The modes
~~~~~~~~~
``python-run``
    Executed in a fresh interpreter.  Non-zero exit, any traceback, fails.
    Catches invalid imports, missing required arguments, invalid attribute
    access and incorrect context-manager behaviour, because all four raise.

``python-signature``
    The block is an API listing.  Every declaration of the shape
    ``name(params) -> Return`` (optionally ``var: T = name(params) -> Return``,
    and optionally spanning several lines) is parsed as a DECLARED signature
    and compared against ``inspect.signature`` of the real object in
    ``module=``: parameter names, order, which are required, and the return
    annotation.  This is what a prose listing cannot self-check —
    ``secure_mlock(...) -> bool`` looks exactly as authoritative as the truth.

``python-names``
    The block is a listing of names — an enum's members, a dataclass's fields,
    a constant table, an import list.  Every name it declares must exist on
    ``module=`` (or, inside a ``class X:`` line, on ``module.X``).  A listing
    is a promise that the names are there; this is the cheapest way to hold it
    to that and nothing more.

``c-run``
    Compiled against ``include/`` and linked against the built library with
    ``-Wall -Wextra -Werror``, then run.  When ``valgrind`` is present the run
    happens under ``memcheck --track-origins=yes --error-exitcode``, which is
    what turns "passes uninitialised stack memory as a seed" from an invisible
    defect into a red build: the uninitialised bytes reach a conditional inside
    the library and memcheck reports the stack allocation in ``main``.

``c-decl``
    The block declares public prototypes.  Each must appear in
    ``include/ama_cryptography.h`` with the same parameter list (whitespace
    normalised), and — when a built library is available — each named symbol
    must actually be exported by it.  This is the mode that catches a
    documented entry point which the version script localises.

``c-const``
    The block lists ``#define NAME value`` macros or ``ENUMERATOR = value``
    rows.  Each must carry the value the public header gives it.  A documented
    key size that has drifted from the header is a buffer overflow in every
    program written from this page, so the numbers are checked, not trusted.

``pseudocode: <reason>``
    Skipped.  The reason is mandatory and must be more than a word, so the
    escape hatch costs something to use.

Exit status
-----------
0  every covered example ran, compiled, linked or matched
1  at least one example failed, or a block carries no directive
2  the check could not run
"""

from __future__ import annotations

import argparse
import ast
import builtins
import importlib
import importlib.util
import inspect
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent

#: The user-facing pages whose examples are promised to work.  Priority 1 of
#: the 2026-09 documentation-integrity pass names the first four explicitly;
#: the rest are the other pages that carry copy-pasteable package code.
COVERED_FILES: tuple[str, ...] = (
    "wiki/Quick-Start.md",
    "wiki/Installation.md",
    "wiki/API-Reference.md",
    "wiki/C-API-Reference.md",
    "wiki/Hybrid-Cryptography.md",
    "wiki/Key-Management.md",
    "wiki/Secure-Memory.md",
)

#: Fence languages this gate is responsible for.  ``bash`` install commands are
#: covered by tools/check_documented_extras.py (INVARIANT-32) and are not
#: re-checked here.
CHECKED_LANGUAGES: frozenset[str] = frozenset({"python", "py", "c"})

_FENCE = re.compile(r"^(?P<indent>\s*)```(?P<info>[^\s`]*)\s*(?P<rest>.*)$")
_DIRECTIVE = re.compile(r"<!--\s*example:\s*(?P<body>.+?)\s*-->\s*$")

#: ``name(params) -> Return`` with an optional ``var: T = `` prefix and an
#: optional trailing comment.  Deliberately strict: anything else in a
#: ``python-signature`` block is prose or a comment and is ignored.
_DECL = re.compile(
    r"^(?:def\s+)?"
    r"(?:(?P<lhs>[A-Za-z_][\w.]*)\s*(?::\s*[^=]+?)?\s*=\s*)?"
    r"(?P<name>[A-Za-z_][\w.]*)\s*"
    r"\((?P<params>.*)\)\s*"
    r"(?:->\s*(?P<ret>.+?))?"
    r"\s*(?::\s*\.\.\.)?\s*$"
)


#: A line is a SIGNATURE declaration (checkable) rather than an ordinary CALL
#: (not checkable — the arguments are values, not parameter names) when it
#: annotates or defaults a parameter, or declares a return type, or is written
#: with ``def``.  ``aead = AESGCMProvider()`` is a call; ``AESGCMProvider(
#: backend: CryptoBackend = ...)`` is a declaration.
def _is_signature_declaration(line: str, match: re.Match[str]) -> bool:
    if line.startswith("def "):
        return True
    if match.group("ret"):
        return True
    params = match.group("params") or ""
    return ":" in params or "=" in params


#: A C prototype in a ``c-decl`` block:  ``ret name(args);``
_C_PROTO = re.compile(
    r"^[ \t]*(?P<ret>[A-Za-z_][\w ]*?[\w*])\s+(?P<name>ama_[A-Za-z0-9_]+)\s*"
    r"\((?P<args>[^;]*?)\)\s*;",
    re.DOTALL | re.MULTILINE,
)

_PSEUDOCODE_MIN_REASON_WORDS = 3


@dataclass(frozen=True)
class Block:
    """One fenced code block, with the directive that classifies it."""

    path: str
    line: int  # 1-based line of the opening fence
    language: str
    directive: Optional[str]  # raw directive body, or None when unmarked
    code: str

    @property
    def mode(self) -> str:
        if self.directive is None:
            return ""
        return self.directive.split()[0].rstrip(":").strip()

    @property
    def options(self) -> dict[str, str]:
        """``key=value`` pairs after the mode word (``module=...``, ``bind=...``).

        Only the ``pseudocode`` mode treats ``:`` as a separator, so an option
        value may itself contain one (``bind=crypto:AmaCryptography``).
        """
        if self.directive is None or self.mode == "pseudocode":
            return {}
        return dict(part.split("=", 1) for part in self.directive.split()[1:] if "=" in part)

    @property
    def reason(self) -> str:
        if self.directive is None or self.mode != "pseudocode":
            return ""
        _, _, rest = self.directive.partition(":")
        return rest.strip()

    def where(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass
class Finding:
    block: Block
    detail: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    ran: int = 0
    skipped: int = 0

    def fail(self, block: Block, detail: str) -> None:
        self.findings.append(Finding(block, detail))


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _display_path(path: Path, repo: Path) -> str:
    """A path for the report: repo-relative when it is inside, absolute when not.

    A fixture handed to ``--file`` may live outside the tree — that is how the
    tests drive these gates without writing into the working copy, which is
    what corrupted ARCHITECTURE.md's line endings on Windows.
    """
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


def extract_blocks(path: Path, repo: Path = REPO) -> list[Block]:
    """Every fenced block in ``path`` whose language this gate checks."""
    relative = _display_path(path, repo)
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[Block] = []
    index = 0
    while index < len(lines):
        match = _FENCE.match(lines[index])
        if not match or not match.group("info"):
            index += 1
            continue
        language = match.group("info").lower()
        fence_indent = match.group("indent")
        opening = index
        index += 1
        body: list[str] = []
        while index < len(lines):
            closing = _FENCE.match(lines[index])
            if closing and not closing.group("info"):
                break
            body.append(lines[index])
            index += 1
        index += 1  # step past the closing fence
        if language not in CHECKED_LANGUAGES:
            continue
        blocks.append(
            Block(
                path=relative,
                line=opening + 1,
                language=language,
                directive=_directive_above(lines, opening),
                code="\n".join(_dedent(body, fence_indent)) + "\n",
            )
        )
    return blocks


def _dedent(body: Sequence[str], indent: str) -> list[str]:
    if not indent:
        return list(body)
    return [line[len(indent) :] if line.startswith(indent) else line for line in body]


def _directive_above(lines: Sequence[str], fence_index: int) -> Optional[str]:
    """The ``<!-- example: ... -->`` directly above the fence, if any."""
    cursor = fence_index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    if cursor < 0:
        return None
    match = _DIRECTIVE.search(lines[cursor].strip())
    return match.group("body") if match else None


# ---------------------------------------------------------------------------
# python-run
# ---------------------------------------------------------------------------


def _load_encodability_predicate() -> Callable[[str], list[str]]:
    """``unencodable_characters`` from the gate that owns INVARIANT-43.

    Loaded by path rather than imported by name: ``tools/`` is not a package,
    so a bare import works only when the caller happens to have that directory
    on ``sys.path`` — which mutating ``sys.path`` at call time would paper over
    while leaving the dependency invisible to the type checker.
    """
    spec = importlib.util.spec_from_file_location(
        "_encodability_for_doc_examples", REPO / "tools" / "check_log_message_encodability.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable on a real tree
        raise RuntimeError("cannot load tools/check_log_message_encodability.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    predicate: Callable[[str], list[str]] = module.unencodable_characters
    return predicate


def _cp1252_offenders(code: str) -> list[tuple[int, str, list[str]]]:
    """Characters a printed literal carries that cp1252 cannot represent.

    INVARIANT-43 already requires this of the library's own log and warning
    text, and ``tools/check_log_message_encodability.py`` owns the rule; this
    imports that module's predicate rather than restating it, so there is one
    definition of "encodable" in the tree.

    It applies to a documented example for the same reason it applies to a log
    record: a Windows console defaults to cp1252, so ``print("\u2713 ALL
    VERIFICATIONS PASSED")`` — which wiki/Quick-Start.md carried — does not
    fail on the check mark, it raises ``UnicodeEncodeError`` and takes the
    whole example down with it. A reader on Windows copies the block, runs it,
    and watches the library appear to crash.

    Only text that reaches ``print`` is checked. Comments and identifiers are
    never encoded to the console, and an em dash in a comment is both correct
    and cp1252-encodable anyway.
    """
    import ast as _ast

    unencodable_characters = _load_encodability_predicate()

    try:
        tree = _ast.parse(code)
    except SyntaxError:
        return []  # not valid Python; run_python reports that on its own

    offenders: list[tuple[int, str, list[str]]] = []
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        func = node.func
        if not (isinstance(func, _ast.Name) and func.id == "print"):
            continue
        for piece in _ast.walk(node):
            text: Optional[str] = None
            if isinstance(piece, _ast.Constant) and isinstance(piece.value, str):
                text = piece.value
            elif isinstance(piece, _ast.JoinedStr):
                text = "".join(
                    part.value
                    for part in piece.values
                    if isinstance(part, _ast.Constant) and isinstance(part.value, str)
                )
            if not text:
                continue
            bad = unencodable_characters(text)
            if bad:
                offenders.append((getattr(piece, "lineno", node.lineno), text, bad))
    return offenders


def check_python_encodability(block: Block, report: Report) -> None:
    """A printed literal must survive a cp1252 console (INVARIANT-43)."""
    for lineno, text, bad in _cp1252_offenders(block.code):
        rendered = ", ".join(f"U+{ord(ch):04X} {ch!r}" for ch in bad)
        report.fail(
            block,
            f"line {lineno} prints {text[:60]!r}, which a cp1252 console cannot "
            f"encode ({rendered}). On Windows this example does not print a tick "
            "— it raises UnicodeEncodeError and dies. INVARIANT-43 requires every "
            "literal the library emits to survive a cp1252 handler; an example a "
            'reader is told to run is held to the same rule. Use ASCII ("OK" / '
            '"FAILED") or a character cp1252 carries.',
        )


def run_python(block: Block, report: Report, repo: Path) -> None:
    with tempfile.TemporaryDirectory() as workdir:
        script = Path(workdir) / "example.py"
        script.write_text(block.code, encoding="utf-8")
        environment = dict(os.environ)
        environment.setdefault("PYTHONPATH", str(repo))
        environment["PYTHONWARNINGS"] = "ignore"
        try:
            completed = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True,
                text=True,
                cwd=workdir,
                env=environment,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            report.fail(block, "example did not finish within 300s")
            return
    if completed.returncode != 0:
        report.fail(block, _tail(completed.stderr or completed.stdout))
        return
    report.ran += 1


def _tail(text: str, limit: int = 12) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return "\n      ".join(lines[-limit:]) if lines else "(no output)"


# ---------------------------------------------------------------------------
# python-signature
# ---------------------------------------------------------------------------


def _declared_parameters(params: str) -> list[tuple[str, bool]]:
    """``(name, required)`` for each parameter in a declared signature."""
    declared: list[tuple[str, bool]] = []
    depth = 0
    current = ""
    for character in params + ",":
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        if character == "," and depth == 0:
            piece = current.strip()
            current = ""
            if not piece or piece in {"*", "/"} or piece.startswith("**"):
                continue
            name = piece.lstrip("*").split(":", 1)[0].split("=", 1)[0].strip()
            if not name:
                continue
            declared.append((name, "=" not in piece))
            continue
        current += character
    return declared


def _logical_lines(code: str) -> list[str]:
    """Join continuation lines so a multi-line declaration reads as one."""
    joined: list[str] = []
    buffer = ""
    depth = 0
    for raw in code.splitlines():
        stripped = re.sub(r"\s*#.*$", "", raw).rstrip()
        if not stripped.strip() and depth == 0:
            continue
        buffer = stripped.strip() if depth == 0 else f"{buffer} {stripped.strip()}"
        depth += stripped.count("(") + stripped.count("[") + stripped.count("{")
        depth -= stripped.count(")") + stripped.count("]") + stripped.count("}")
        if depth <= 0:
            depth = 0
            if buffer:
                joined.append(re.sub(r",\s*\)", ")", buffer))
            buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def _resolve_module(block: Block, report: Report) -> Optional[object]:
    module_name = block.options.get("module")
    if not module_name:
        report.fail(block, f"{block.mode} needs module=<dotted.module>")
        return None
    try:
        return importlib.import_module(module_name)
    except Exception as exc:  # pragma: no cover - a broken module fails loudly
        report.fail(block, f"cannot import {module_name}: {exc!r}")
        return None


_NAME_DECL = re.compile(r"^(?P<name>[A-Z_][A-Za-z0-9_]*|[a-z_][a-z0-9_]*)\s*(?::|=|$)")
_CLASS_DECL = re.compile(r"^class\s+(?P<name>[A-Za-z_]\w*)\s*[(:]")
_IMPORT_FROM = re.compile(r"^from\s+(?P<module>[\w.]+)\s+import\s+\(?(?P<names>[^)]*)\)?")

#: Names a listing may use that are language keywords or obvious placeholders.
_NAME_NOISE: frozenset[str] = frozenset(
    {"class", "def", "import", "from", "return", "with", "for", "if", "else", "pass", "..."}
)


def check_python_names(block: Block, report: Report) -> None:
    """Every name a listing declares must exist on the module (or its class)."""
    module = _resolve_module(block, report)
    if module is None:
        return
    module_name = block.options["module"]
    owner: object = module
    owner_label = module_name
    checked = 0
    # Logical lines, so a parenthesised multi-line import list reads as one.
    for stripped in _logical_lines(block.code):
        if not stripped:
            continue
        import_match = _IMPORT_FROM.match(stripped)
        if import_match:
            try:
                imported = importlib.import_module(import_match.group("module"))
            except Exception as exc:
                report.fail(block, f"cannot import {import_match.group('module')}: {exc!r}")
                continue
            for piece in import_match.group("names").split(","):
                name = piece.strip().split(" as ")[0].strip()
                if not name or name in _NAME_NOISE:
                    continue
                checked += 1
                if not hasattr(imported, name):
                    report.fail(
                        block,
                        f"{import_match.group('module')} has no name {name!r} — the "
                        f"documented import fails",
                    )
            continue
        class_match = _CLASS_DECL.match(stripped)
        if class_match:
            owner_label = f"{module_name}.{class_match.group('name')}"
            owner = getattr(module, class_match.group("name"), None)
            if owner is None:
                report.fail(block, f"{module_name} has no class {class_match.group('name')!r}")
            checked += 1
            continue
        if stripped.startswith(("@", '"', "'")) or stripped in _NAME_NOISE:
            continue
        name_match = _NAME_DECL.match(stripped)
        if not name_match:
            continue
        name = name_match.group("name")
        if name in _NAME_NOISE:
            continue
        checked += 1
        if owner is None:
            continue
        if not _has_member(owner, name):
            report.fail(block, f"{owner_label} has no member {name!r} (line: {stripped})")
    if checked == 0:
        report.fail(block, "python-names block declares no name")
        return
    report.ran += 1


def _has_member(owner: object, name: str) -> bool:
    if hasattr(owner, name):
        return True
    annotations = getattr(owner, "__annotations__", {})
    if name in annotations:
        return True
    fields = getattr(owner, "__dataclass_fields__", {})
    return name in fields


def check_python_signatures(block: Block, report: Report) -> None:
    module = _resolve_module(block, report)
    if module is None:
        return
    module_name = block.options["module"]
    bindings = dict(
        pair.split(":", 1) for pair in block.options.get("bind", "").split(",") if ":" in pair
    )

    checked = 0
    for line in _logical_lines(block.code):
        if not line or line.startswith("#") or line.startswith(("from ", "import ", "class ")):
            continue
        match = _DECL.match(line)
        if not match or not _is_signature_declaration(line, match):
            continue
        name = match.group("name")
        head, *rest = name.split(".")
        # `bind=crypto:AmaCryptography` lets a listing show instance methods on
        # the receiver name the surrounding prose uses.
        owner_label = module_name
        if head in bindings:
            owner_label = f"{module_name}.{bindings[head]}"
            target = getattr(module, bindings[head], None)
        else:
            target = getattr(module, head, None)
            owner_label = module_name
        for attribute in rest:
            target = getattr(target, attribute, None)
        if target is None:
            report.fail(block, f"{owner_label} has no attribute {name!r} (line: {line})")
            continue
        checked += 1
        _compare_signature(block, report, owner_label, name, target, match, line)
    if checked == 0:
        report.fail(block, "python-signature block declares no `name(...) -> Return` line")
        return
    report.ran += 1


def _compare_signature(
    block: Block,
    report: Report,
    module_name: str,
    name: str,
    target: object,
    match: re.Match[str],
    line: str,
) -> None:
    if not callable(target):
        return  # a constant or a module attribute; existence was the claim
    try:
        actual = inspect.signature(target)
    except (TypeError, ValueError):
        return  # a builtin with no introspectable signature

    actual_parameters = [
        parameter
        for parameter in actual.parameters.values()
        if parameter.name != "self"
        and parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    actual_names = [parameter.name for parameter in actual_parameters]
    actual_required = {
        parameter.name
        for parameter in actual_parameters
        if parameter.default is inspect.Parameter.empty
    }

    declared = _declared_parameters(match.group("params") or "")
    declared_names = [entry[0] for entry in declared]

    if declared_names != actual_names:
        report.fail(
            block,
            f"{module_name}.{name} parameters documented as "
            f"({', '.join(declared_names)}) but are ({', '.join(actual_names)})"
            f"\n      line: {line}",
        )
        return

    for parameter_name, required in declared:
        if required != (parameter_name in actual_required):
            expected = "required" if parameter_name in actual_required else "optional"
            report.fail(
                block,
                f"{module_name}.{name}: parameter {parameter_name!r} is {expected}, "
                f"documented otherwise\n      line: {line}",
            )
            return

    declared_return = (match.group("ret") or "").strip()
    if not declared_return:
        return
    actual_return = actual.return_annotation
    if actual_return is inspect.Signature.empty:
        return
    if not _return_matches(declared_return, actual_return, target):
        report.fail(
            block,
            f"{module_name}.{name} documented as returning {declared_return!r} "
            f"but returns {_render(actual_return)!r}\n      line: {line}",
        )


def _render(annotation: object) -> str:
    """The annotation as source text.

    ``__name__`` is wrong for typing constructs — ``Optional[bytes].__name__``
    is ``"Optional"``, which would report every parameterised return type as a
    mismatch against its own correct spelling.  Anything from ``typing`` or
    carrying ``__args__`` is rendered with ``str()`` instead, which round-trips.
    """
    if isinstance(annotation, str):
        return annotation
    if annotation is None or annotation is type(None):
        return "None"
    if getattr(annotation, "__module__", "") == "typing" or hasattr(annotation, "__args__"):
        return str(annotation)
    return getattr(annotation, "__name__", None) or str(annotation)


def _canonical(annotation: object) -> str:
    """A spelling- and interpreter-version-independent key for an annotation.

    The first revision of this comparison rendered both sides with ``str()``
    and compared the text.  That made the gate's verdict depend on the running
    interpreter: CPython 3.14 renders ``Optional[bytes]`` as ``bytes | None``
    and ``Dict[str, Union[bool, str]]`` as ``typing.Dict[str, bool | str]``,
    so two `wiki/API-Reference.md` lines that are correct on every version
    passed under 3.10-3.13 and failed the 3.14 matrix cell.  A documentation
    claim is either true of the implementation or it is not; which Python
    happens to run the check is not part of that question.

    ``typing.get_origin``/``get_args`` decompose the annotation into the same
    structure on every supported version (measured on 3.11 and 3.14), so this
    walks that structure instead of any rendering of it.  ``Union`` members are
    sorted because a union is a set: ``Optional[X]``, ``Union[X, None]`` and
    ``X | None`` are one type written three ways.
    """
    if annotation is None or annotation is type(None):
        return "None"
    if annotation is Ellipsis:
        return "..."
    if isinstance(annotation, list):  # Callable[[int, str], X] parameter lists
        return "[" + ",".join(_canonical(item) for item in annotation) + "]"
    origin = typing.get_origin(annotation)
    if origin is None:
        name = getattr(annotation, "__name__", None)
        return name if isinstance(name, str) else str(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Union or origin is types.UnionType:
        return "Union[" + ",".join(sorted(_canonical(item) for item in args)) + "]"
    # `typing.Dict[...]` and `dict[...]` share the `dict` origin, which is the
    # normalisation the old `typing.` text strip was reaching for.
    origin_name = getattr(origin, "__name__", None) or str(origin)
    if not args:
        return str(origin_name)
    return f"{origin_name}[{','.join(_canonical(item) for item in args)}]"


#: Returned when a documented return type names something this interpreter
#: cannot resolve.  ``None`` cannot serve as that signal: ``-> None`` is a
#: perfectly ordinary annotation that resolves TO ``None``.
_UNRESOLVED = object()


class _NotATypeExpressionError(Exception):
    """A node the annotation grammar below does not accept."""


def _evaluate_type_expression(node: ast.expr, namespace: dict[str, object]) -> object:
    """Resolve one node of a type expression against ``namespace``.

    Deliberately an interpreter for the annotation grammar rather than a call
    to ``eval``.  ``eval`` would work, but it would execute whatever a covered
    page happens to contain and would need a bandit suppression to pass this
    repository's own lint gate; neither is acceptable for a check whose whole
    purpose is that claims are verified rather than asserted.  The grammar
    accepted here is exactly what a return annotation can be: a name, a dotted
    name, a subscript, a tuple or list of those, ``X | Y``, and the constants
    ``None`` / ``...`` / a forward-reference string.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):  # a forward reference, e.g. "SecureBuffer"
            resolved = namespace.get(node.value, _UNRESOLVED)
            if resolved is _UNRESOLVED:
                raise _NotATypeExpressionError(node.value)
            return resolved
        return node.value  # None or Ellipsis
    if isinstance(node, ast.Name):
        if node.id not in namespace:
            raise _NotATypeExpressionError(node.id)
        return namespace[node.id]
    if isinstance(node, ast.Attribute):
        owner = _evaluate_type_expression(node.value, namespace)
        try:
            return getattr(owner, node.attr)
        except AttributeError as exc:
            raise _NotATypeExpressionError(node.attr) from exc
    if isinstance(node, ast.Subscript):
        container = typing.cast(typing.Any, _evaluate_type_expression(node.value, namespace))
        parameter = _evaluate_type_expression(node.slice, namespace)
        try:
            return container[parameter]
        except (TypeError, KeyError, AttributeError) as exc:
            raise _NotATypeExpressionError(ast.unparse(node)) from exc
    if isinstance(node, ast.Tuple):
        return tuple(_evaluate_type_expression(item, namespace) for item in node.elts)
    if isinstance(node, ast.List):  # the parameter list of Callable[[int], X]
        return [_evaluate_type_expression(item, namespace) for item in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = typing.cast(typing.Any, _evaluate_type_expression(node.left, namespace))
        right = _evaluate_type_expression(node.right, namespace)
        try:
            return left | right
        except TypeError as exc:
            raise _NotATypeExpressionError("|") from exc
    raise _NotATypeExpressionError(type(node).__name__)


def _resolve_annotation(declared: str, target: object) -> object:
    """``declared`` as a type object, or ``_UNRESOLVED``.

    Resolved against the namespace of the module that defines ``target`` — the
    same names the annotation was written against — with ``typing`` added so a
    page may write ``Optional[bytes]`` where the module imported it as
    ``t.Optional``.  A page is free to describe a return in prose that names
    nothing importable; that returns ``_UNRESOLVED`` and falls back to the text
    comparison, rather than failing the page.
    """
    try:
        tree = ast.parse(declared.strip(), mode="eval")
    except SyntaxError:
        return _UNRESOLVED
    module = sys.modules.get(str(getattr(target, "__module__", "")))
    # Only the TYPES from builtins: `bytes` and `dict` have to resolve for
    # `Optional[bytes]` to mean anything, and nothing that opens a file has any
    # business in a type expression.
    namespace: dict[str, object] = {
        name: getattr(builtins, name)
        for name in dir(builtins)
        if isinstance(getattr(builtins, name), type)
    }
    namespace.update(vars(typing))
    # So a page may write the fully qualified `typing.Dict[...]` even where the
    # module it documents imported the name directly.
    namespace["typing"] = typing
    if module is not None:
        namespace.update(vars(module))
    namespace.setdefault("NoneType", type(None))
    try:
        return _evaluate_type_expression(tree.body, namespace)
    except _NotATypeExpressionError:
        return _UNRESOLVED


def _return_matches(declared: str, actual: object, target: object = None) -> bool:
    if isinstance(actual, str):
        # A module carrying `from __future__ import annotations` (PEP 563) hands
        # `inspect.signature` the annotation as SOURCE TEXT, so without this the
        # comparison would be a type object against a string and every
        # parameterised return on those ten package modules would report a
        # mismatch that does not exist.  Resolved through the same grammar, so
        # both sides are types.
        resolved_actual = _resolve_annotation(actual, target)
        if resolved_actual is not _UNRESOLVED:
            actual = resolved_actual
    resolved = _resolve_annotation(declared, target)
    if resolved is not _UNRESOLVED:
        return _canonical(resolved) == _canonical(actual)

    # The documented return is prose, not a type expression. Compare the text,
    # which is all either side has.
    def normalise(text: str) -> str:
        # `typing.Generator[bytearray, NoneType, NoneType]` and
        # `Generator[bytearray, None, None]` are the same annotation written two
        # ways; the module prefix and the NoneType spelling are noise here.
        stripped = re.sub(r"\s|typing\.|builtins\.", "", text)
        return re.sub(r"\bNoneType\b", "None", stripped)

    return normalise(declared) == normalise(_render(actual))


# ---------------------------------------------------------------------------
# c-decl
# ---------------------------------------------------------------------------


def _normalise_c(text: str) -> str:
    """Whitespace- and pointer-spelling-insensitive C text.

    ``ama_context_t *ctx`` and ``ama_context_t* ctx`` are the same declaration;
    only a difference the compiler would see should fail this gate.
    """
    flat = re.sub(r"\s+", " ", text.replace("\n", " ")).strip()
    flat = re.sub(r"\s*\*\s*", "*", flat)
    flat = re.sub(r"\s*,\s*", ",", flat)
    return re.sub(r"\s*\(\s*", "(", re.sub(r"\s*\)\s*", ")", flat))


def check_c_declarations(
    block: Block, report: Report, repo: Path, exported: Optional[frozenset[str]]
) -> None:
    header = (repo / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    flat_header = _normalise_c(header)
    code = re.sub(r"//[^\n]*", "", block.code)
    prototypes = list(_C_PROTO.finditer(code))
    if not prototypes:
        report.fail(block, "c-decl block declares no `ama_*` prototype")
        return
    for prototype in prototypes:
        name = prototype.group("name")
        arguments = _normalise_c(prototype.group("args"))
        needle = _normalise_c(f"{name}({arguments})")
        if needle not in flat_header:
            report.fail(
                block,
                f"prototype not found in include/ama_cryptography.h with this "
                f"parameter list: {name}({arguments})",
            )
            continue
        if exported is not None and name not in exported:
            report.fail(
                block,
                f"{name} is declared in the public header but is NOT an exported "
                f"symbol of the built library — cmake/ama_exports.map localises "
                f"it, so an out-of-tree caller cannot link it",
            )
    report.ran += 1


_C_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Z_][A-Z0-9_]*)[ \t]+(?P<value>[^/\n]+?)"
    r"[ \t]*(?://.*)?$",
    re.MULTILINE,
)
_C_ENUMERATOR = re.compile(
    r"^[ \t]*(?P<name>AMA_[A-Z0-9_]+)[ \t]*=[ \t]*(?P<value>-?[ \t]*\d+)[ \t]*,?[ \t]*(?://.*)?$",
    re.MULTILINE,
)


def check_c_constants(block: Block, report: Report, repo: Path) -> None:
    """Every documented macro / enumerator carries the header's value."""
    header = (repo / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    defines = {
        match.group("name"): match.group("value").strip() for match in _C_DEFINE.finditer(header)
    }
    enumerators = {
        match.group("name"): re.sub(r"\s+", "", match.group("value"))
        for match in _C_ENUMERATOR.finditer(header)
    }
    checked = 0
    for raw in block.code.splitlines():
        line = raw.strip()
        if not line:
            continue
        define = _C_DEFINE.match(line)
        if define:
            checked += 1
            name, value = define.group("name"), define.group("value").strip()
            if name not in defines:
                report.fail(block, f"include/ama_cryptography.h defines no {name}")
            elif defines[name] != value:
                report.fail(
                    block,
                    f"{name} documented as {value} but the header defines it as "
                    f"{defines[name]}",
                )
            continue
        enumerator = _C_ENUMERATOR.match(line)
        if enumerator:
            checked += 1
            name = enumerator.group("name")
            value = re.sub(r"\s+", "", enumerator.group("value"))
            if name not in enumerators:
                report.fail(block, f"include/ama_cryptography.h declares no enumerator {name}")
            elif enumerators[name] != value:
                report.fail(
                    block,
                    f"{name} documented as {value} but the header assigns " f"{enumerators[name]}",
                )
    if checked == 0:
        report.fail(block, "c-const block lists no `#define` or `NAME = value` row")
        return
    report.ran += 1


def exported_symbols(library: Path) -> frozenset[str]:
    """Symbols the built library actually exports, whatever format it is in.

    This used to carry its own copy of ``nm --dynamic --defined-only
    --format=posix``, which reads ELF and only ELF.  Both copies then failed
    the same way on the same day: Xcode's nm answers a Mach-O dylib with
    ``File format has no dynamic symbol table`` and exits non-zero, so every
    macOS lane raised out of this function, and ``nm`` on a PE DLL prints
    "no symbols" and exits ZERO, so the windows lanes read an empty export set
    as sixteen missing entry points.

    ``tools/check_public_api_docs.py`` owns the reader and is the gate whose
    subject is the export surface; this borrows it rather than restating it, so
    there is one definition of "exported" in the tree and one place to fix.
    Loaded by path for the reason ``_load_encodability_predicate`` documents:
    ``tools/`` is not a package.
    """
    spec = importlib.util.spec_from_file_location(
        "_exports_for_doc_examples", REPO / "tools" / "check_public_api_docs.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable on a real tree
        raise RuntimeError("cannot load tools/check_public_api_docs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    reader: Callable[[Path], frozenset[str]] = module.dynamic_symbols
    return reader(library)


# ---------------------------------------------------------------------------
# c-run
# ---------------------------------------------------------------------------


_C_WARNING_FLAGS = ("-Wall", "-Wextra", "-Werror", "-Wno-error=unused-parameter")

#: Shared-library basenames by platform.  The gate ran only on Linux while it
#: was being written and globbed ``libama_cryptography.so*`` unconditionally,
#: so on macOS and Windows it found nothing and the C lane silently reported
#: "skipped" — a gate that passes because it looked in the wrong place.
_LIBRARY_PATTERNS: tuple[str, ...] = (
    "libama_cryptography.so*",  # Linux / BSD
    "libama_cryptography.*dylib",  # macOS
    "libama_cryptography.dll*",  # MinGW
    "ama_cryptography.dll",  # MSVC
    "ama_cryptography.lib",  # MSVC import library
    "libama_cryptography.dll.a",  # MinGW import library
)


def find_library(directory: Optional[Path]) -> Optional[Path]:
    """The built shared object in ``directory``, whatever this platform calls it."""
    if directory is None or not directory.is_dir():
        return None
    for pattern in _LIBRARY_PATTERNS:
        matches = sorted(directory.glob(pattern))
        if matches:
            return matches[-1]
    return None


def _link_argv(library_dir: Path) -> list[str]:
    """Link flags for this platform.

    ``-Wl,-rpath`` is a GNU/BSD loader concept; Windows resolves a DLL from
    PATH and the directory of the executable, and passing the flag there makes
    the link fail rather than the run.
    """
    argv = [f"-L{library_dir}", "-lama_cryptography"]
    if sys.platform == "win32":
        return argv
    argv.append(f"-Wl,-rpath,{library_dir}")
    argv += ["-lm", "-lpthread"]
    return argv


def run_c(
    block: Block,
    report: Report,
    repo: Path,
    include_dir: Path,
    library_dir: Path,
    compiler: str,
    use_valgrind: bool,
) -> None:
    with tempfile.TemporaryDirectory() as workdir:
        source = Path(workdir) / "example.c"
        source.write_text(block.code, encoding="utf-8")
        binary = Path(workdir) / "example"
        compile_argv = [
            compiler,
            "-std=c11",
            *_C_WARNING_FLAGS,
            f"-I{include_dir}",
            str(source),
            "-o",
            str(binary),
            *_link_argv(library_dir),
        ]
        compiled = subprocess.run(compile_argv, capture_output=True, text=True, check=False)
        if compiled.returncode != 0:
            report.fail(block, f"{compiler} failed:\n      {_tail(compiled.stderr)}")
            return

        run_argv: list[str] = [str(binary)]
        if use_valgrind:
            run_argv = [
                "valgrind",
                "--quiet",
                "--error-exitcode=97",
                "--track-origins=yes",
                "--leak-check=no",
                *run_argv,
            ]
        try:
            executed = subprocess.run(
                run_argv, capture_output=True, text=True, cwd=workdir, timeout=600, check=False
            )
        except subprocess.TimeoutExpired:
            report.fail(block, "compiled example did not finish within 600s")
            return
        if executed.returncode == 97:
            report.fail(
                block,
                "valgrind memcheck reported an error — the example reads memory "
                "it never initialised (an uninitialised buffer handed to the "
                "library is a key made from stack garbage, and it still "
                f"'succeeds'):\n      {_tail(executed.stderr)}",
            )
            return
        if executed.returncode != 0:
            report.fail(
                block,
                f"compiled example exited {executed.returncode}:"
                f"\n      {_tail(executed.stderr or executed.stdout)}",
            )
            return
    report.ran += 1


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def check_blocks(
    blocks: Iterable[Block],
    *,
    repo: Path = REPO,
    languages: frozenset[str] = frozenset({"python", "c"}),
    include_dir: Optional[Path] = None,
    library_dir: Optional[Path] = None,
    compiler: str = "cc",
    use_valgrind: bool = True,
) -> Report:
    report = Report()
    exported: Optional[frozenset[str]] = None
    if library_dir is not None:
        library = find_library(library_dir)
        if library is not None and sys.platform != "win32":
            # `nm --dynamic` reads ELF and Mach-O; the PE export table needs a
            # different tool, so on Windows the c-decl mode checks the header
            # only and says so rather than pretending it checked the ABI.
            exported = exported_symbols(library)

    for block in blocks:
        family = "c" if block.language == "c" else "python"
        if block.directive is None:
            report.fail(
                block,
                "no `<!-- example: ... -->` directive above the fence. Every "
                "python/c block in a covered page must declare what it claims: "
                "python-run, python-signature, c-run, c-decl, or "
                "pseudocode: <reason>.",
            )
            continue
        mode = block.mode
        if mode == "pseudocode":
            if len(block.reason.split()) < _PSEUDOCODE_MIN_REASON_WORDS:
                report.fail(
                    block,
                    "pseudocode needs a reason of at least "
                    f"{_PSEUDOCODE_MIN_REASON_WORDS} words explaining why the "
                    "block cannot be executed",
                )
                continue
            report.skipped += 1
            continue
        if mode.startswith("python") and family != "python":
            report.fail(block, f"directive {mode!r} on a {block.language} block")
            continue
        if mode.startswith("c-") and family != "c":
            report.fail(block, f"directive {mode!r} on a {block.language} block")
            continue
        if family not in languages:
            report.skipped += 1
            continue

        if mode == "python-run":
            # Checked before execution: the encodability defect is invisible on
            # a UTF-8 runner, so running the block on Linux would report green
            # on the exact example that breaks for a Windows reader.
            check_python_encodability(block, report)
            run_python(block, report, repo)
        elif mode == "python-signature":
            check_python_signatures(block, report)
        elif mode == "python-names":
            check_python_names(block, report)
        elif mode == "c-decl":
            check_c_declarations(block, report, repo, exported)
        elif mode == "c-const":
            check_c_constants(block, report, repo)
        elif mode == "c-run":
            if include_dir is None or library_dir is None:
                report.skipped += 1
                continue
            run_c(
                block,
                report,
                repo,
                include_dir,
                library_dir,
                compiler,
                use_valgrind and shutil.which("valgrind") is not None,
            )
        else:
            report.fail(block, f"unknown example mode {mode!r}")
    return report


def collect(repo: Path = REPO, files: Sequence[str] = COVERED_FILES) -> list[Block]:
    blocks: list[Block] = []
    for relative in files:
        path = repo / relative
        if not path.is_file():
            raise FileNotFoundError(f"covered documentation file is missing: {relative}")
        blocks.extend(extract_blocks(path, repo))
    return blocks


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the documented examples.")
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument(
        "--lang",
        choices=("python", "c", "all"),
        default="all",
        help="which example family to execute (structure is always checked)",
    )
    parser.add_argument("--include-dir", type=Path, default=None)
    parser.add_argument("--library-dir", type=Path, default=None)
    parser.add_argument("--compiler", default=os.environ.get("CC", "cc"))
    parser.add_argument("--no-valgrind", action="store_true")
    parser.add_argument("--file", action="append", dest="files", default=None)
    args = parser.parse_args(argv)

    repo: Path = args.repo
    if not (repo / "ama_cryptography" / "__init__.py").is_file():
        print(f"FATAL: {repo} does not look like the repository root.", file=sys.stderr)
        return 2

    # python-signature / python-names introspect the real objects, so the
    # package must be importable from this process too.
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    files = tuple(args.files) if args.files else COVERED_FILES
    try:
        blocks = collect(repo, files)
    except FileNotFoundError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    if not blocks:
        print("FATAL: no example blocks were found.", file=sys.stderr)
        return 2

    languages = frozenset({"python", "c"}) if args.lang == "all" else frozenset({args.lang})
    # Absolute: the compiled example carries these in -I and -rpath, and it
    # runs from a temporary directory where a relative path means nothing.
    include_dir = (args.include_dir or (repo / "include")).resolve()
    library_dir = args.library_dir.resolve() if args.library_dir else None
    if library_dir is None:
        # Search the places a build actually leaves the library. The CMake tree
        # puts it in build/lib; `pip install -e .` and the wheel builds leave it
        # beside the package, which is where the macOS and Windows test-matrix
        # jobs have it. Looking only in build/lib made the C lane report
        # "skipped" on those runners — a gate passing because it looked in one
        # place and found nothing.
        for candidate in (
            repo / "build" / "lib",
            repo / "ama_cryptography",
            repo / "build",
        ):
            if find_library(candidate) is not None:
                library_dir = candidate.resolve()
                break

    report = check_blocks(
        blocks,
        repo=repo,
        languages=languages,
        include_dir=include_dir,
        library_dir=library_dir,
        compiler=args.compiler,
        use_valgrind=not args.no_valgrind,
    )

    if report.findings:
        print(
            f"DOCUMENTED EXAMPLE CHECK FAILED — {len(report.findings)} "
            f"example(s) do not do what the page says:",
            file=sys.stderr,
        )
        for finding in report.findings:
            print(f"  {finding.block.where()}  [{finding.block.language}]", file=sys.stderr)
            print(f"      {finding.detail}", file=sys.stderr)
        print(
            "\nA copy-pasteable example is API surface. Fix the example, or mark "
            "the block `<!-- example: pseudocode: <reason> -->` if it is not "
            "meant to run.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK    {len(blocks)} example block(s) across {len(files)} page(s): "
        f"{report.ran} executed/checked, {report.skipped} skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
