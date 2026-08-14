#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — ctypes ABI Contract Verifier
===============================================

Cross-checks every ctypes signature the Python package assigns against the
prototype the public C header declares for the same symbol.

Why this exists
---------------
A ctypes symbol probe (``hasattr(lib, "ama_foo")``) proves a *name* is
exported.  It says nothing about arity or ABI: ``lib.ama_foo.argtypes = [...]``
succeeds against a symbol of any actual signature, and the first call through
a wrong declaration corrupts the stack or reads foreign memory — silently on
the happy path, exploitably on a crafted one.  The 2026-08 audit flagged
exactly this (finding #7): "ctypes symbol probes verify only that a name is
exported, not its arity/ABI".

A shared object carries no parameter metadata, so the ABI cannot be read from
the artefact.  What the repository *does* carry is the authoritative contract:
``include/ama_cryptography.h``, the header the library is compiled from.  This
gate parses every ``AMA_API`` prototype out of that header and every
``argtypes``/``restype`` assignment out of the Python sources, and requires
them to agree on

* **arity** — the number of parameters, and
* **shape** — a coarse class per position: pointer-like vs. integer-like, and
  pointer/integer/void for the return.

The coarse classes are deliberate.  ``uint8_t*`` vs ``const char*`` is a
distinction ctypes erases anyway (both marshal as a pointer); ``size_t`` vs
``ama_algorithm_t`` are both integers of register width or narrower.  What the
classes DO catch is every drift that corrupts a call frame: an added or
removed parameter, a pointer where an integer is expected (or vice versa), a
void return read as a value.  Those are the ABI bugs a bare name-probe cannot
see, and each one now fails CI instead of shipping.

The runtime counterpart of this static gate is the load-time version
handshake in ``pqc_backends`` (``ama_version_number`` must report the same
major version as the package), which rejects an artefact compiled from a
DIFFERENT header before any of the signatures checked here are configured
against it.

Scope
-----
Every module under ``ama_cryptography/`` that assigns ``argtypes`` or
``restype`` — discovered by walking the package's ASTs, not from a
hand-maintained list.  In practice that is ``pqc_backends.py`` (the primary
native surface, ~110 symbols) plus ``ascon.py``, ``agent_binding.py``,
``secure_memory.py``, ``hybrid_combiner.py``, ``_build_sign.py`` and
``_self_test.py``.

The list *was* hand-maintained, and had drifted: the last three above were
missing from it, so INVARIANT-42 did not cover them.  That is the predictable
end state for a list of files-that-use-a-feature, because adding the feature
to a new file is not a change to the list, and nothing fails when the two
disagree.  ``REQUIRED_MODULES`` now acts as a floor beneath discovery so an
extractor bug cannot quietly empty the scope and report a pass.

Completeness is enforced in both directions inside that scope: a symbol
*called* on a library handle without a signature assignment is an error, and a
signature assigned for a symbol the header does not declare is an error.

Usage
-----
::

    python tools/check_ctypes_abi.py

Exit status: 0 when every assigned signature matches its header prototype and
every called symbol is covered; 1 otherwise.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
HEADER = REPO_ROOT / "include" / "ama_cryptography.h"

#: Additional headers whose ``AMA_API`` symbols the Python package consumes.
#: The SHA-256 / HMAC-SHA-256 kernels are exported for internal use (the
#: NIST-P RFC 6979 nonce derivation, HKDF-SHA-2) but deliberately kept out of
#: the installed public header; their prototypes live with their translation
#: units.  Listed explicitly so a symbol declared nowhere still fails.
EXTRA_HEADERS = (
    "src/c/ama_sha256.h",
    "src/c/ama_hmac_sha256.h",
)

#: The package whose ctypes assignments are checked.
PACKAGE = "ama_cryptography"

#: Modules that must always be in scope.
#:
#: The scope used to be this list *alone*, and it had drifted: three modules
#: that declare ctypes signatures were absent from it (``hybrid_combiner.py``,
#: ``_build_sign.py``, ``_self_test.py``), so INVARIANT-42 was unenforced for
#: them.  Their transcriptions happened to match the header, but nothing was
#: checking — and a hand-maintained list of files-that-use-a-feature drifts by
#: construction, because adding the feature to a new file is not a change to
#: the list.
#:
#: Scope is now discovered (see :func:`ctypes_modules`) and this tuple is the
#: floor beneath it.  A discovery bug that returned nothing would otherwise
#: turn the gate into a silent pass, which is the failure mode this repository
#: treats as worse than no gate at all.
REQUIRED_MODULES = (
    "ama_cryptography/pqc_backends.py",
    "ama_cryptography/ascon.py",
    "ama_cryptography/agent_binding.py",
    "ama_cryptography/secure_memory.py",
    "ama_cryptography/hybrid_combiner.py",
    "ama_cryptography/_build_sign.py",
    "ama_cryptography/_self_test.py",
)

#: Marks a module as declaring a ctypes signature.
_CTYPES_ATTRS = ("argtypes", "restype")


def ctypes_modules(package_root: Path | None = None) -> tuple[str, ...]:
    """Every module in the package that assigns ``argtypes`` or ``restype``.

    Detection is by AST attribute assignment rather than a text search, so a
    mention inside a docstring or comment does not pull a module into scope.

    ``package_root`` is read at call time rather than bound as a default so a
    test can point the scan somewhere else; see the note on the same pattern in
    ``tools/check_c_secret_zeroization.py``.
    """
    root = (REPO_ROOT / PACKAGE) if package_root is None else package_root
    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if any(
                isinstance(target, ast.Attribute) and target.attr in _CTYPES_ATTRS
                for target in node.targets
            ):
                # A scan pointed outside the repository (a test's temporary
                # tree) has no repo-relative form; report the path as given
                # rather than raising out of discovery.
                try:
                    found.add(path.relative_to(REPO_ROOT).as_posix())
                except ValueError:
                    found.add(path.as_posix())
                break
    return tuple(sorted(found | set(REQUIRED_MODULES)))


#: ctypes type names that marshal as an integer-class argument.
_INT_CTYPES = {
    "c_int",
    "c_uint",
    "c_uint8",
    "c_uint16",
    "c_uint32",
    "c_uint64",
    "c_int8",
    "c_int16",
    "c_int32",
    "c_int64",
    "c_size_t",
    "c_ssize_t",
    "c_long",
    "c_ulong",
    "c_bool",
}

#: ctypes type names that marshal as a pointer-class argument.
_PTR_CTYPES = {"c_char_p", "c_void_p", "c_wchar_p"}

#: C parameter/return tokens that are integer-class.  Everything carrying a
#: ``*`` or ``[`` is pointer-class regardless of these; enum typedefs
#: (``ama_algorithm_t`` …) are integers by C rules and matched by suffix.
_INT_C_TOKENS = {
    "int",
    "unsigned",
    "size_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
}


@dataclass(frozen=True)
class Signature:
    """A coarse ABI signature: per-parameter classes plus a return class."""

    params: tuple[str, ...]  # each entry "ptr" | "int"
    ret: str  # "ptr" | "int" | "void"
    origin: str  # "file:line" for diagnostics


def _strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def _classify_c_param(param: str) -> Optional[str]:
    """Classify one C parameter declaration as ``"ptr"`` or ``"int"``.

    Returns None for ``void`` (a zero-parameter list) and for ``...``
    (varargs, which this API does not use but the parser must not misread).
    """
    param = param.strip()
    if not param or param == "void" or param == "...":
        return None
    if "*" in param or "[" in param:
        return "ptr"
    tokens = param.replace("const", " ").split()
    # Drop the trailing parameter name when present: "size_t pk_len" -> the
    # type tokens are everything that is a known type word or a typedef.
    for token in tokens:
        if token in _INT_C_TOKENS or token.endswith("_t"):
            return "int"
    # A single-token declaration ("int", already covered) or an unknown
    # typedef with no pointer syntax: C passes it by value.  Every by-value
    # type in this API is an integer or enum, so classify as int — a struct
    # passed by value would need a new class here, and the header has none.
    return "int"


def _classify_c_return(ret: str) -> str:
    ret = ret.strip()
    if "*" in ret:
        return "ptr"
    if ret.replace("const", "").strip() == "void":
        return "void"
    return "int"


def parse_header(header_text: str, origin: str = "header") -> dict[str, Signature]:
    """Extract ``{symbol: Signature}`` for every ``AMA_API`` prototype."""
    text = _strip_c_comments(header_text)
    prototypes: dict[str, Signature] = {}
    # The return-type segment must not be able to match whitespace that the
    # neighbouring quantifiers can also match.  The original spelling —
    # ``\s+(?P<ret>[\w\s]+?\**)\s*`` — put three overlapping whitespace
    # matchers in a row (``\s+``, the ``\s`` inside ``[\w\s]``, and ``\s*``)
    # with a nullable ``\**`` between them, so a run of N spaces could be
    # divided among them in O(N^2) ways; with ``finditer`` retrying every start
    # offset that is cubic.  Measured on ``"AMA_API" + " " * N + "!"``:
    # 2.4 ms at N=100, 145 ms at 400, 8.6 s at 1,600 — 7.8x per doubling, and
    # roughly 2.4 hours extrapolated to N=16,000.  Worse than every other
    # pattern this branch has fixed, all of which were merely quadratic.
    #
    # ``[^;{()]`` cannot match the ``(`` that follows the function name, so the
    # segment has exactly one way to end, and the bound keeps a pathological
    # header linear rather than merely slower.  A real prototype's return type
    # is a few dozen characters; 200 is generous.
    pattern = re.compile(
        r"AMA_API(?P<ret>[^;{()]{0,200}?)\b(?P<name>ama_\w+)\s{0,64}"
        r"\((?P<params>[^;{]*)\)\s{0,64};",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        name = match.group("name")
        params_blob = " ".join(match.group("params").split())
        classes = []
        if params_blob:
            for param in params_blob.split(","):
                cls = _classify_c_param(param)
                if cls is not None:
                    classes.append(cls)
        line = text[: match.start()].count("\n") + 1
        prototypes[name] = Signature(
            params=tuple(classes),
            ret=_classify_c_return(match.group("ret")),
            origin=f"{origin}:{line}",
        )
    return prototypes


def _ctypes_name(node: ast.AST) -> Optional[str]:
    """The bare name of a ctypes type expression: ``ctypes.c_int`` -> ``c_int``."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _classify_ctypes_arg(node: ast.AST) -> Optional[str]:
    """Classify one element of an ``argtypes`` list."""
    name = _ctypes_name(node)
    if name is not None:
        if name in _INT_CTYPES:
            return "int"
        if name in _PTR_CTYPES:
            return "ptr"
        return None
    if isinstance(node, ast.Call):
        fn = _ctypes_name(node.func)
        if fn == "POINTER":
            return "ptr"
    return None


def _classify_ctypes_restype(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and node.value is None:
        return "void"
    name = _ctypes_name(node)
    if name is not None:
        if name in _INT_CTYPES:
            return "int"
        if name in _PTR_CTYPES:
            return "ptr"
    return None


def _argtypes_classes(node: ast.AST) -> Optional[list[str]]:
    """Classify a full ``argtypes`` value expression, or None if opaque.

    Handles the three literal shapes the tree uses: a plain list/tuple, a
    list multiplied by an int (``[POINTER(c_int)] * 3``), and concatenation
    of those.  An alias (``lib.a.argtypes = lib.b.argtypes``) is resolved by
    the caller, not here.
    """
    if isinstance(node, (ast.List, ast.Tuple)):
        out = []
        for element in node.elts:
            cls = _classify_ctypes_arg(element)
            if cls is None:
                return None
            out.append(cls)
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        base = _argtypes_classes(node.left)
        if (
            base is not None
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, int)
        ):
            return base * node.right.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _argtypes_classes(node.left)
        right = _argtypes_classes(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _symbol_of_attribute_target(node: ast.AST) -> Optional[tuple[str, str]]:
    """For a target ``<recv>.ama_x.argtypes`` return ``("ama_x", "argtypes")``."""
    if (
        isinstance(node, ast.Attribute)
        and node.attr in ("argtypes", "restype")
        and isinstance(node.value, ast.Attribute)
        and node.value.attr.startswith("ama_")
    ):
        return node.value.attr, node.attr
    return None


def _getattr_loop_symbols(loop: ast.For) -> list[str]:
    """Symbol names a ``for name in (...)`` getattr-loop configures.

    Matches the tree's idiom::

        for name in ("ama_a", "ama_b"):
            fn = getattr(lib, name)
            fn.argtypes = [...]
            fn.restype = ...

    including variants where the iterable is a list and where the loop
    variable feeds ``getattr`` indirectly through one assignment.
    """
    if not isinstance(loop.iter, (ast.Tuple, ast.List)):
        return []
    symbols = [
        element.value
        for element in loop.iter.elts
        if isinstance(element, ast.Constant)
        and isinstance(element.value, str)
        and element.value.startswith("ama_")
    ]
    return symbols if len(symbols) == len(loop.iter.elts) else []


def parse_python_signatures(
    tree: ast.Module, origin: str
) -> tuple[dict[str, dict[str, Any]], set[str], list[str]]:
    """Return ``(signatures, called, problems)`` for one module.

    ``signatures`` maps symbol -> dict with optional "params"/"ret" and the
    assignment line.  ``called`` is the set of ``ama_*`` symbols invoked via
    attribute access or via a getattr-loop signature group.
    """
    signatures: dict[str, dict[str, Any]] = {}
    aliases: list[tuple[str, str, int]] = []
    called: set[str] = set()
    problems: list[str] = []

    def record(symbol: str, field: str, value_node: ast.AST, lineno: int) -> None:
        entry = signatures.setdefault(symbol, {"origin": f"{origin}:{lineno}"})
        if field == "argtypes":
            source = _symbol_of_attribute_target(value_node)
            if source is not None and source[1] == "argtypes":
                aliases.append((symbol, source[0], lineno))
                return
            classes = _argtypes_classes(value_node)
            if classes is None:
                problems.append(
                    f"  - {origin}:{lineno}: cannot classify argtypes for {symbol} "
                    "(unrecognised expression shape — extend the checker, do not skip it)"
                )
                return
            entry["params"] = tuple(classes)
        else:
            cls = _classify_ctypes_restype(value_node)
            if cls is None:
                problems.append(f"  - {origin}:{lineno}: cannot classify restype for {symbol}")
                return
            entry["ret"] = cls

    def _local_binding_symbol(node: ast.Assign) -> Optional[tuple[str, str]]:
        """Match the ``fn = lib.ama_x`` binding idiom: ``(local_name, symbol)``.

        This shape was the extractor's one blind spot (adversarial-review
        finding F1): a symbol bound to a local first was invisible to the
        direct-target match, AND its call site (``fn(...)``) is a bare
        ``ast.Name`` call the completeness check could not see either — so
        the two live uses of the idiom (``ama_secure_memzero``,
        ``ama_version_number``, the exact call the version handshake makes
        against an unvalidated object) escaped the gate in both directions.
        """
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr.startswith("ama_")
        ):
            return node.targets[0].id, node.value.attr
        return None

    def _walk_scope(scope: ast.AST) -> Any:
        """Yield this scope's nodes WITHOUT descending into nested functions.

        ``ast.walk`` + ``continue`` does not do this — ``walk`` has already
        queued the skipped node's children — so a shared bindings map would
        leak an ``fn`` from one function into another's calls.  (The
        rejection-direction test for exactly that leak is what caught it.)
        """
        # Pre-order DFS in SOURCE order (reversed pushes onto a LIFO stack):
        # the one-pass binding tracker below requires seeing ``fn = lib.ama_x``
        # before the ``fn.argtypes = ...`` that follows it in the file.
        stack = list(ast.iter_child_nodes(scope))[::-1]
        while stack:
            node = stack.pop()
            yield node
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                stack.extend(list(ast.iter_child_nodes(node))[::-1])

    def _process_scope(scope: ast.AST, inherited: Optional[dict[str, str]] = None) -> None:
        """Extract from one lexical scope, tracking its local ``fn`` bindings.

        Bindings are scoped per function so an ``fn`` in one function cannot
        contaminate an unrelated ``fn`` in another.  A NESTED function is
        recursed into with a copy of the bindings visible at its definition
        point — closures read their enclosing scope (``secure_memory``'s
        ``_zero_via_native`` calls the outer ``fn`` binding), and a child
        scope's own rebindings must not flow back up.
        """
        local_bindings: dict[str, str] = dict(inherited or {})
        for node in _walk_scope(scope):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _process_scope(node, local_bindings)
                continue
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = _symbol_of_attribute_target(node.targets[0])
                if target is not None:
                    record(target[0], target[1], node.value, node.lineno)
                    continue
                binding = _local_binding_symbol(node)
                if binding is not None:
                    local_bindings[binding[0]] = binding[1]
                    continue
                loop_target = node.targets[0]
                if (
                    isinstance(loop_target, ast.Attribute)
                    and loop_target.attr in ("argtypes", "restype")
                    and isinstance(loop_target.value, ast.Name)
                    and loop_target.value.id in local_bindings
                ):
                    record(
                        local_bindings[loop_target.value.id],
                        loop_target.attr,
                        node.value,
                        node.lineno,
                    )
            if isinstance(node, ast.For):
                symbols = _getattr_loop_symbols(node)
                if symbols:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Assign) and len(sub.targets) == 1:
                            loop_target = sub.targets[0]
                            if (
                                isinstance(loop_target, ast.Attribute)
                                and loop_target.attr in ("argtypes", "restype")
                                and isinstance(loop_target.value, ast.Name)
                            ):
                                for symbol in symbols:
                                    record(symbol, loop_target.attr, sub.value, sub.lineno)
                    # A symbol configured by a loop group is reachable through
                    # getattr dispatch at the call sites; count it as called.
                    called.update(symbols)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr.startswith("ama_"):
                    called.add(node.func.attr)
                elif isinstance(node.func, ast.Name) and node.func.id in local_bindings:
                    called.add(local_bindings[node.func.id])

    _process_scope(tree)

    # Resolve aliases after the pass so order of definition does not matter.
    for symbol, source, lineno in aliases:
        if source in signatures and "params" in signatures[source]:
            signatures[symbol]["params"] = signatures[source]["params"]
        else:
            problems.append(
                f"  - {origin}:{lineno}: {symbol} aliases argtypes of {source}, "
                "which has no classified signature"
            )
    return signatures, called, problems


def check(
    header_protos: dict[str, Signature],
    modules: Sequence[tuple[str, dict[str, dict[str, Any]], set[str]]],
) -> tuple[list[str], int]:
    """Cross-check parsed Python signatures against header prototypes.

    ``modules`` is a sequence of ``(origin, signatures, called)``.
    Returns ``(problems, checked_count)``.
    """
    problems: list[str] = []
    checked = 0
    for origin, signatures, called in modules:
        for symbol in sorted(called - set(signatures)):
            problems.append(
                f"  - {origin}: {symbol} is CALLED but never assigned an "
                "argtypes/restype signature — the call marshals through "
                "ctypes defaults, which is exactly the unchecked-ABI hole "
                "this gate exists to close"
            )
        for symbol, entry in sorted(signatures.items()):
            proto = header_protos.get(symbol)
            if proto is None:
                problems.append(
                    f"  - {entry['origin']}: {symbol} has a ctypes signature but "
                    "no AMA_API prototype in include/ama_cryptography.h — either "
                    "the symbol is dead or the header no longer declares it"
                )
                continue
            checked += 1
            params = entry.get("params")
            if params is not None and params != proto.params:
                problems.append(
                    f"  - {entry['origin']}: {symbol} argtypes {list(params)} != "
                    f"header {list(proto.params)} ({proto.origin})"
                )
            ret = entry.get("ret")
            if ret is not None and ret != proto.ret:
                problems.append(
                    f"  - {entry['origin']}: {symbol} restype {ret!r} != header "
                    f"{proto.ret!r} ({proto.origin})"
                )
    return problems, checked


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv
    if not HEADER.is_file():
        print(f"ERROR: {HEADER} not found — cannot verify the ABI contract", file=sys.stderr)
        return 2
    header_protos = parse_header(HEADER.read_text(encoding="utf-8"), origin=HEADER.name)
    if not header_protos:
        print(
            "ERROR: no AMA_API prototypes parsed out of the header — the gate "
            "would pass vacuously",
            file=sys.stderr,
        )
        return 2
    for rel in EXTRA_HEADERS:
        extra = REPO_ROOT / rel
        if not extra.is_file():
            print(f"ERROR: {rel} not found — cannot verify the ABI contract", file=sys.stderr)
            return 2
        for symbol, proto in parse_header(
            extra.read_text(encoding="utf-8"), origin=extra.name
        ).items():
            # The public header wins on a duplicate declaration; a private
            # header only fills symbols the public one does not carry.
            header_protos.setdefault(symbol, proto)

    modules = ctypes_modules()
    missing = [m for m in REQUIRED_MODULES if m not in modules]
    if missing:
        # Discovery lost a module the gate is known to cover: that is a
        # checker bug or a deleted module, never a clean tree.
        print(
            f"ERROR: required module(s) absent from the discovered scope: " f"{', '.join(missing)}",
            file=sys.stderr,
        )
        return 2

    parsed = []
    parse_problems: list[str] = []
    for rel in modules:
        path = REPO_ROOT / rel
        if not path.is_file():
            print(f"ERROR: {rel} not found", file=sys.stderr)
            return 2
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        signatures, called, problems = parse_python_signatures(tree, rel)
        parse_problems.extend(problems)
        parsed.append((rel, signatures, called))

    problems, checked = check(header_protos, parsed)
    problems = parse_problems + problems

    if checked == 0:
        print(
            "ERROR: zero signatures cross-checked — the extractor found "
            "nothing, which is a checker bug, not a clean tree",
            file=sys.stderr,
        )
        return 2
    if problems:
        print(
            f"ctypes ABI contract check FAILED — {len(problems)} problem(s):\n",
            file=sys.stderr,
        )
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    total_symbols = sum(len(signatures) for _, signatures, _ in parsed)
    print(
        f"OK: {checked} ctypes signature(s) across {len(modules)} module(s) "
        f"match their header prototypes ({total_symbols} symbols covered, "
        f"{len(header_protos)} prototypes in the header)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
