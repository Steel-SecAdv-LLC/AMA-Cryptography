#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
INVARIANT-1 boundary gate: stdlib ``hashlib`` in the shipped package.

CPython's ``hashlib`` is not a neutral helper.  In every build that links
libcrypto — which includes every manylinux wheel and every mainstream distro
Python — its constructors resolve to OpenSSL: ``hashlib.sha3_256`` *is*
``_hashlib.openssl_sha3_256``, the SHA-3 family included.  A production
``hashlib`` call inside ``ama_cryptography`` is therefore OpenSSL performing
an AMA cryptographic primitive in-process, which INVARIANT-1 forbids.  Fifty
such call sites accumulated under documentation claiming zero external crypto
dependencies before the 2026-08 sweep converted them to the library's own
kernels (``native_sha256/384/512``, ``native_sha3_256/384/512``,
``native_pbkdf2_hmac_sha256/512``).

What legitimately remains is the TRUST BOOTSTRAP: code that must hash before
the native library may be used, plus deliberately-independent comparators.
This gate pins that boundary exactly, the same way the vendor-isolation gate
pins linkage: every ``hashlib`` / ``_hashlib`` reference in the package must
sit in an allowlisted file, and each allowlisted file must carry EXACTLY the
number of references its entry records — so a new use inside an allowlisted
file fails just as loudly as a new file.  Docstrings and comments do not
count; the scan is over the AST.

Why the bootstrap cannot be converted:

* ``pqc_backends`` hashes every candidate shared object BEFORE mapping it
  (constructors execute on dlopen).  The library cannot hash itself into
  trust; something outside it must hold the scale.
* ``_self_test`` / ``__init__`` / ``_build_sign`` compute the source/artefact
  digests that decide whether the package may operate at all.  Using the
  native library here would let a tampered library attest tampered sources.
* ``_self_test``'s SHA3-256 KAT also runs ``hashlib`` against the FIPS 202
  vectors as a cross-implementation check — a comparator compared against
  fixed constants, never a producer of trusted values.
* ``hybrid_combiner._hkdf_python`` is the RuntimeError-guarded test-only
  reference whose value is exactly its independence from the native path.

What this gate counts, and why the shape matters
------------------------------------------------

An earlier revision counted only ``import hashlib`` statements and
``hashlib.<attr>`` attribute reads off a name literally spelled ``hashlib``
or ``_hashlib``.  That left four ways to use OpenSSL inside an allowlisted
file without moving its pinned count, i.e. four silent bypasses of the only
enforcement INVARIANT-1 has on the Python side:

1. ``from hashlib import sha256`` — the import counted once, and every
   subsequent bare ``sha256(...)`` call was invisible.
2. ``import hashlib as h`` — the import counted once, and every ``h.sha256``
   was invisible because the attribute root was not spelled ``hashlib``.
   (``__init__.py`` escaped this only by accident: its alias happens to be
   ``_hashlib``, one of the two hard-coded names.)
3. ``importlib.import_module("hashlib")`` / ``__import__("hashlib")`` —
   invisible entirely, module object bound to an arbitrary name.
4. Anything under a subpackage — the scan used a non-recursive ``glob``.

Closing those four still left a fifth and sixth of the same species, closed
since:

5. ``_h = hashlib`` — the module root rebound to a plain name.  The RHS was
   a bare Name load (counted by nothing) and ``_h`` never entered the root
   set, so one aliasing line bought unlimited ``_h.sha3_256(...)`` uses with
   the pinned count unchanged.  Assignments from a root are now followed,
   and a BARE load of a root counts as the reference — which also covers
6. ``getattr(hashlib, "sha3_256")`` and ``f(hashlib)`` — the module handed
   to a callee this gate cannot follow, counted at the load exactly as a
   dynamic import is counted at the call.

The walker below therefore resolves *bindings* rather than matching a
spelling: it tracks which local names refer to a guarded module (through any
alias or re-assignment), which names were imported directly out of one, and
flags dynamic imports by the module string.  ``hmac`` is guarded alongside ``hashlib``
because stdlib ``hmac`` on a libcrypto build is OpenSSL performing an AMA
MAC — the same violation, and one the docstrings in ``crypto_api`` and
``pqc_backends`` already name explicitly.  The scan is recursive so a future
subpackage cannot host an unpinned use.

A seventh and eighth, closed since:

7. ``__import__("hash" + "lib")`` / ``import_module(name)`` — the dynamic
   import was counted only when its argument was a bare string constant.  A
   concatenation, an f-string, or a variable skipped the count.  Arguments
   are now RESOLVED (:class:`StringResolver`: constant folding plus
   single-binding names, literal loop sequences, and the parameters of
   private helpers whose every in-module call passes a resolvable value), and
   an argument that cannot be resolved FAILS the gate outright, whatever the
   file's allowlist entry says: a module chosen at run time is a module this
   gate cannot bound.
8. ``sys.modules["hashlib"]`` — the already-imported module object read out
   of the import cache, which no import statement or call names.  Subscripts
   and ``get``/``pop``/``setdefault`` on ``sys.modules`` are resolved the same
   way; a guarded key counts as a reference, an unresolvable key fails.

:func:`dynamic_imports` is the shared walker for 7 and 8, and
``tools/check_vendor_isolation.py`` imports it (rather than copying it) to
apply the same resolution to the vendor modules it forbids.

A ninth, closed since, with two of the same species found beside it:

9. ``from .pqc_backends import hashlib`` — OpenSSL re-exported by a sibling.
   Four bootstrap files bind ``hashlib`` at module scope, so any other file
   could import it from one of them (or read ``pqc_backends.hashlib``) with
   no ``import hashlib`` of its own.  Only imports whose SOURCE was a guarded
   module counted, so the file's count stayed 0, a count of 0 needs no
   allowlist entry, and the gate printed OK.  Now the guarded object counts
   however it is reached: importing a guarded NAME from any module, reading
   an attribute NAMED ``hashlib``/``_hashlib``/``hmac`` off any object, and —
   through :func:`package_exports`, a fixpoint over the whole package —
   importing or reading any name a sibling binds to a guarded object at
   module scope, under whatever name it was re-exported.  A star import from a
   guarded module or from a sibling with exports, and a ``getattr`` on such a
   sibling by an unprovable name, fail outright like an unresolvable dynamic
   import: the names they bind cannot be enumerated.
10. ``_s = hashlib.sha256`` / ``f = getattr(hashlib, "sha3_256")`` — a MEMBER
    bound to a plain name, then called any number of times.  Bypass 5 followed
    ``_h = hashlib`` only.  Any name assigned from a guarded expression is now
    a root.
11. A function defined ABOVE the ``import hashlib`` it uses.  Counting ran in
    source order, so the root was unknown when the use was visited; a module
    body has finished by the time its functions run, so the order proves
    nothing.  Bindings are now collected over the whole file, to a fixpoint,
    before anything is counted.

What is still not followed: a sibling module object obtained DYNAMICALLY
(``import_module("ama_cryptography.pqc_backends")``, ``sys.modules[...]``) is
not traced to its exports, so only its guarded NAMES (``.hashlib``) are caught
through it, not a renamed export.  Adding a renamed export to a bootstrap file
moves that file's pinned count, so it cannot arrive unreviewed.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Mapping, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "ama_cryptography"

#: file name -> (expected reference count, rationale).  The count includes
#: import statements and every ``hashlib.<attr>`` / ``_hashlib.<attr>``
#: attribute access.  Change a bootstrap file and this gate makes you come
#: here and say why.
ALLOWLIST: dict[str, tuple[int, str]] = {
    "__init__.py": (
        2,
        "pre-import binding gate: hashes each signed compiled binding "
        "extension (.so/.pyd) against INTEGRITY_BINDING_DIGESTS_HEX before "
        "its module-init function can run, ahead of the native library being "
        "trusted (import + 1 use in _refuse_tampered_bindings_before_import). "
        "This entry used to say 'stale-source fast check: hashes .py files "
        "against the recorded digest'; no such check exists here and this "
        "file hashes no .py files",
    ),
    "pqc_backends.py": (
        3,
        "pre-load digest verification: every candidate shared object is "
        "hashed BEFORE dlopen maps it, so the hash cannot come from the "
        "library under test (import + POSIX fd path + Windows read path)",
    ),
    "_self_test.py": (
        7,
        "signed-integrity digest chain over the .py sources and native "
        "library (import + 5 uses), plus the SHA3-256 KAT cross-check that "
        "runs hashlib against fixed FIPS 202 vectors as an independent "
        "comparator (1 use)",
    ),
    "_build_sign.py": (
        6,
        "build-time signer: computes the digests the artefact will bind "
        "before any built library exists to compute them (import + 5 uses)",
    ),
    "hybrid_combiner.py": (
        4,
        "test-only HKDF reference implementation, RuntimeError-guarded "
        "behind _test_only_allow_python; its purpose is independence from "
        "the native path it cross-checks (import + 3 uses)",
    ),
}


#: Modules whose use inside the package is an INVARIANT-1 violation unless
#: allowlisted.  ``hmac`` is here for the same reason as ``hashlib``: on any
#: libcrypto build ``hmac.new`` is OpenSSL computing an AMA MAC.
GUARDED_MODULES = ("hashlib", "_hashlib", "hmac")

#: Callables that materialise a module object from a runtime string.
_DYNAMIC_IMPORTERS = ("import_module", "__import__")


# ---------------------------------------------------------------------------
# Static string resolution (shared with tools/check_vendor_isolation.py)
# ---------------------------------------------------------------------------


#: Bound on resolver recursion; a chain deeper than this is "unresolvable".
_MAX_RESOLVE_DEPTH = 12


def _binding_names(node: ast.AST) -> list[str]:
    """Names a single AST node binds in its scope (excluding nested scopes)."""
    names: list[str] = []
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        names.append(node.id)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.append(node.name)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        for alias in node.names:
            names.append((alias.asname or alias.name).split(".", 1)[0])
    elif isinstance(node, ast.ExceptHandler) and node.name:
        names.append(node.name)
    elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        names.append(node.name)
    elif isinstance(node, ast.MatchMapping) and node.rest:
        names.append(node.rest)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        names.extend(node.names)
    return names


def _scope_nodes(scope: ast.AST) -> list[ast.AST]:
    """Every node in ``scope`` that is not inside a nested function or class.

    The nested definition's own name IS included (it binds in this scope);
    its body is not.
    """
    out: list[ast.AST] = []
    stack: list[ast.AST] = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            # Decorators, defaults and bases are evaluated in THIS scope.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                stack.extend(node.args.defaults)
                stack.extend(d for d in node.args.kw_defaults if d is not None)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                stack.extend(node.decorator_list)
            if isinstance(node, ast.ClassDef):
                stack.extend(node.bases)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return out


class StringResolver:
    """Statically resolve an expression to the set of strings it can evaluate to.

    Returns ``None`` whenever the value is not provable from the module's own
    source.  Resolved values are ``str`` or ``None`` (the constant ``None``,
    which ``ctypes.CDLL(None)`` uses for the process handle).  What resolves:

    * constants; ``+`` concatenation; f-strings; ``str(x)``;
    * ``__name__`` (the module's own dotted name, when supplied);
    * a name with exactly ONE binding in its scope, when that binding is an
      assignment of a resolvable value, or a ``for`` target over a literal
      sequence (a list/tuple/set literal, or a name bound once to one — for a
      mutable list or set, only when every load of it is a ``for`` iterable,
      so nothing can have appended to it);
    * a parameter of a module-level PRIVATE function (``_name``) whose name is
      loaded only as a call target in this module, when every such call
      passes a resolvable value for it (or omits it and the default resolves).

    A ``global``/``nonlocal`` declaration of the name anywhere makes it
    unresolvable: its binding can then change from another scope.
    """

    def __init__(self, tree: ast.Module, module_name: str | None = None) -> None:
        self._tree = tree
        self._module_name = module_name
        self._parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self._parents[id(child)] = parent
        self._globalised: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                self._globalised.update(node.names)
        self._scope_cache: dict[int, list[ast.AST]] = {}

    # -- scope helpers -----------------------------------------------------

    def _nodes(self, scope: ast.AST) -> list[ast.AST]:
        cached = self._scope_cache.get(id(scope))
        if cached is None:
            cached = _scope_nodes(scope)
            self._scope_cache[id(scope)] = cached
        return cached

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        """The innermost function (or the module) whose scope ``node`` is in."""
        current = self._parents.get(id(node))
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return current
            current = self._parents.get(id(current))
        return self._tree

    def _parameter(self, scope: ast.AST, name: str) -> ast.arg | None:
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return None
        args = scope.args
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            if arg.arg == name:
                return arg
        for star in (args.vararg, args.kwarg):
            if star is not None and star.arg == name:
                return star
        return None

    def _bindings(self, scope: ast.AST, name: str) -> list[ast.AST]:
        return [node for node in self._nodes(scope) if name in _binding_names(node)]

    def _loads(self, scope: ast.AST, name: str) -> list[ast.Name]:
        return [
            node
            for node in self._nodes(scope)
            if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
        ]

    # -- resolution --------------------------------------------------------

    def resolve(self, expr: ast.AST, depth: int = 0) -> frozenset[str | None] | None:
        """The values ``expr`` can take, or ``None`` if not provable."""
        if depth > _MAX_RESOLVE_DEPTH:
            return None
        if isinstance(expr, ast.Constant):
            if expr.value is None or isinstance(expr.value, str):
                return frozenset({expr.value})
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self.resolve(expr.left, depth + 1)
            right = self.resolve(expr.right, depth + 1)
            if left is None or right is None or None in left or None in right:
                return None
            return frozenset(f"{a}{b}" for a in left for b in right)
        if isinstance(expr, ast.JoinedStr):
            results: set[str] = {""}
            for part in expr.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    results = {prefix + part.value for prefix in results}
                    continue
                if not isinstance(part, ast.FormattedValue) or part.format_spec is not None:
                    return None
                if part.conversion not in (-1, ord("s")):
                    return None
                inner = self.resolve(part.value, depth + 1)
                if inner is None or None in inner:
                    return None
                results = {prefix + str(value) for prefix in results for value in inner}
            return frozenset(results)
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "str"
            and len(expr.args) == 1
            and not expr.keywords
        ):
            inner = self.resolve(expr.args[0], depth + 1)
            if inner is None or None in inner:
                return None
            return inner
        if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
            return self._resolve_name(expr, depth)
        return None

    def _resolve_sequence(self, expr: ast.AST, depth: int) -> frozenset[str | None] | None:
        """The union of the elements of a literal sequence (for a ``for`` loop)."""
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            values: set[str | None] = set()
            for element in expr.elts:
                resolved = self.resolve(element, depth + 1)
                if resolved is None:
                    return None
                values |= resolved
            return frozenset(values)
        if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
            if expr.id in self._globalised:
                return None
            scope = self.enclosing_scope(expr)
            while True:
                bindings = self._bindings(scope, expr.id)
                if bindings or scope is self._tree:
                    break
                scope = self.enclosing_scope(scope)
            if self._parameter(scope, expr.id) is not None or len(bindings) != 1:
                return None
            binding = bindings[0]
            assign = self._parents.get(id(binding))
            if not (
                isinstance(assign, ast.Assign)
                and len(assign.targets) == 1
                and assign.targets[0] is binding
            ):
                return None
            value = assign.value
            if isinstance(value, (ast.List, ast.Set)):
                # Mutable: prove nothing else can have changed it.
                for load in self._loads(scope, expr.id):
                    parent = self._parents.get(id(load))
                    if not (isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is load):
                        return None
            elif not isinstance(value, ast.Tuple):
                return None
            return self._resolve_sequence(value, depth + 1)
        return None

    def _resolve_name(self, expr: ast.Name, depth: int) -> frozenset[str | None] | None:
        name = expr.id
        if name in self._globalised:
            return None
        scope = self.enclosing_scope(expr)
        # Walk outward to the scope that binds the name (closure / global read).
        while True:
            parameter = self._parameter(scope, name)
            bindings = self._bindings(scope, name)
            if parameter is not None or bindings or scope is self._tree:
                break
            scope = self.enclosing_scope(scope)
        if parameter is not None:
            if bindings:
                return None  # the parameter is rebound in the body
            return self._resolve_parameter(scope, parameter, depth)
        if not bindings:
            if name == "__name__" and self._module_name is not None:
                return frozenset({self._module_name})
            return None
        if len(bindings) != 1:
            return None
        binding = bindings[0]
        parent = self._parents.get(id(binding))
        if (
            isinstance(parent, ast.Assign)
            and len(parent.targets) == 1
            and parent.targets[0] is binding
        ):
            return self.resolve(parent.value, depth + 1)
        if (
            isinstance(parent, ast.AnnAssign)
            and parent.target is binding
            and parent.value is not None
        ):
            return self.resolve(parent.value, depth + 1)
        if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.target is binding:
            return self._resolve_sequence(parent.iter, depth + 1)
        return None

    def _resolve_parameter(
        self, scope: ast.AST, parameter: ast.arg, depth: int
    ) -> frozenset[str | None] | None:
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if not scope.name.startswith("_") or self._parents.get(id(scope)) is not self._tree:
            return None
        args = scope.args
        if parameter is args.vararg or parameter is args.kwarg:
            return None
        positional = [*args.posonlyargs, *args.args]
        index = next((i for i, arg in enumerate(positional) if arg is parameter), None)
        default: ast.expr | None = None
        if index is not None:
            offset = index - (len(positional) - len(args.defaults))
            if offset >= 0:
                default = args.defaults[offset]
        else:
            kw_index = args.kwonlyargs.index(parameter)
            default = args.kw_defaults[kw_index]
        values: set[str | None] = set()
        calls = 0
        for node in ast.walk(self._tree):
            if not (isinstance(node, ast.Name) and node.id == scope.name):
                continue
            if not isinstance(node.ctx, ast.Load):
                return None  # the helper's name is rebound or deleted
            call = self._parents.get(id(node))
            if not (isinstance(call, ast.Call) and call.func is node):
                return None  # the function escapes: callers we cannot see
            if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
                keyword.arg is None for keyword in call.keywords
            ):
                return None
            supplied: ast.expr | None = None
            if index is not None and index < len(call.args):
                supplied = call.args[index]
            else:
                for keyword in call.keywords:
                    if keyword.arg == parameter.arg:
                        supplied = keyword.value
            source = supplied if supplied is not None else default
            if source is None:
                return None
            resolved = self.resolve(source, depth + 1)
            if resolved is None:
                return None
            values |= resolved
            calls += 1
        if calls == 0:
            return None
        return frozenset(values)


class DynamicImport(NamedTuple):
    """A module obtained from a run-time string rather than an import statement."""

    lineno: int
    #: ``import_module`` / ``__import__`` / ``sys.modules``.
    kind: str
    #: The source text of the argument, for diagnostics.
    argument: str
    #: The module names the argument can take, or ``None`` if not provable.
    names: frozenset[str] | None


#: ``sys.modules`` methods that return a cached module by key.
_SYS_MODULES_LOOKUPS = ("get", "pop", "setdefault")


def _sys_modules_roots(tree: ast.Module) -> tuple[set[str], set[str]]:
    """``(names bound to the sys module, names bound to sys.modules)``."""
    sys_names: set[str] = set()
    modules_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_names.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys" and node.level == 0:
            for alias in node.names:
                if alias.name == "modules":
                    modules_names.add(alias.asname or "modules")
    return sys_names, modules_names


def dynamic_imports(tree: ast.Module, module_name: str | None = None) -> list[DynamicImport]:
    """Every ``import_module``/``__import__`` call and ``sys.modules`` lookup.

    Each carries the resolved set of module names (see :class:`StringResolver`),
    or ``None`` when the argument is not provable from the source.  An
    ``import_module`` with a relative name (``".x"``) resolves to the name as
    written; callers that care about relative imports check for a leading dot.
    """
    resolver = StringResolver(tree, module_name)
    sys_names, modules_names = _sys_modules_roots(tree)

    def _is_sys_modules(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in modules_names
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "modules"
            and isinstance(node.value, ast.Name)
            and node.value.id in sys_names
        )

    def _names(expr: ast.AST) -> frozenset[str] | None:
        resolved = resolver.resolve(expr)
        if resolved is None or None in resolved:
            return None
        return frozenset(value for value in resolved if value is not None)

    found: list[DynamicImport] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id if isinstance(func, ast.Name) else None
            )
            if name in _DYNAMIC_IMPORTERS:
                argument: ast.expr | None = node.args[0] if node.args else None
                if argument is None:
                    argument = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
                if argument is None:
                    found.append(DynamicImport(node.lineno, str(name), "", None))
                    continue
                found.append(
                    DynamicImport(node.lineno, str(name), ast.unparse(argument), _names(argument))
                )
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in _SYS_MODULES_LOOKUPS
                and _is_sys_modules(func.value)
                and node.args
            ):
                found.append(
                    DynamicImport(
                        node.lineno,
                        "sys.modules",
                        ast.unparse(node.args[0]),
                        _names(node.args[0]),
                    )
                )
        elif isinstance(node, ast.Subscript) and _is_sys_modules(node.value):
            found.append(
                DynamicImport(
                    node.lineno, "sys.modules", ast.unparse(node.slice), _names(node.slice)
                )
            )
    return sorted(found)


def module_name_for(path: Path, package_dir: Path) -> str:
    """The dotted name ``path`` is imported under, for resolving ``__name__``."""
    relative = path.relative_to(package_dir.parent).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


#: ``{dotted package module: the names it binds, at module scope, to a guarded
#: object}``.  Every module of the scanned package has a key (most with an empty
#: set), so membership also answers "is this dotted name a package module?".
Exports = Mapping[str, frozenset[str]]


def _resolve_from(node: ast.ImportFrom, module_name: str | None, is_package: bool) -> str | None:
    """The absolute dotted module an ``ImportFrom`` reads from, or ``None``."""
    if node.level == 0:
        return node.module
    if module_name is None:
        return None
    parts = module_name.split(".")
    if not is_package:
        parts = parts[:-1]
    keep = len(parts) - (node.level - 1)
    if keep <= 0:
        return None
    base = parts[:keep]
    if node.module:
        base += node.module.split(".")
    return ".".join(base)


def _binding_nodes(tree: ast.Module) -> list[ast.AST]:
    """Every node that can bind a guarded name: imports and assignments."""
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.NamedExpr))
    ]


def _is_getattr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
    )


class _GuardedModuleVisitor(ast.NodeVisitor):
    """Count references to a guarded module, resolving bindings not spellings.

    The binding forms tracked:

    * ``import hashlib`` / ``import hashlib as h`` binds a *module root*.
      Every attribute read off that root counts, whatever the alias.
    * ``from hashlib import sha256 as s`` binds a *direct name*.  Every load
      of that name counts, because the call site no longer mentions the
      module at all.
    * ``from <any module> import hashlib`` (``_hashlib``, ``hmac``) binds a
      module root too: the guarded object is the thing imported, whichever
      module it is read out of.  So does ``from <package module> import x``
      when that module binds ``x`` to a guarded object at module scope (its
      *exports*, see :func:`package_exports`).
    * ``x = <guarded expression>`` binds a module root: ``h = hashlib``,
      ``s = hashlib.sha256``, ``f = getattr(hashlib, "sha3_256")``,
      ``h = pqc_backends.hashlib``.
    * ``import <package module> [as m]`` / ``from . import m`` binds a
      *package module*, so ``m.<export>`` and ``getattr(m, "<export>")`` are
      recognised as reads of a guarded object.
    * ``importlib.import_module("hashlib")`` / ``__import__("hashlib")``
      counts at the call, since the resulting object is bound to a name this
      gate cannot follow.  Flagging the call is what keeps it from being free.

    Bindings are collected over the whole file before anything is counted
    (:meth:`bind`), so a use in a function defined ABOVE the import or alias it
    relies on is still a use: a module body has finished running by the time
    any of its functions is called, so source order proves nothing.  Counting
    in one source-order pass missed exactly that.

    Any attribute read NAMED ``hashlib`` / ``_hashlib`` / ``hmac``, off any
    object, counts: ``pqc_backends.hashlib.sha256(...)`` is OpenSSL whichever
    module object it was reached through.  Two shapes cannot be bounded and are
    reported in :attr:`unbounded` instead of counted: a star import from a
    guarded module or from a package module with exports, and ``getattr`` on a
    package module with exports by a name this gate cannot resolve.
    """

    def __init__(
        self,
        module_name: str | None = None,
        *,
        is_package: bool = False,
        exports: Exports | None = None,
        resolver: StringResolver | None = None,
        binders: list[ast.AST] | None = None,
    ) -> None:
        self.count = 0
        self._binders = binders
        self._module_roots: set[str] = set()
        self._direct_names: set[str] = set()
        self._package_modules: dict[str, str] = {}
        #: Name nodes already counted as part of an enclosing Attribute, so
        #: `hashlib.sha256` is one reference, not two.
        self._consumed: set[int] = set()
        self._module_name = module_name
        self._is_package = is_package
        self._exports: Exports = exports if exports is not None else {}
        self._resolver = resolver
        #: ``(line, source)`` of each reference this gate cannot bound.
        self.unbounded: list[tuple[int, str]] = []

    # -- binding resolution ------------------------------------------------

    def bind(self, tree: ast.Module) -> None:
        """Collect every guarded binding in ``tree``, to a fixpoint."""
        if self._resolver is None:
            self._resolver = StringResolver(tree, self._module_name)
        binders = self._binders if self._binders is not None else _binding_nodes(tree)
        while True:
            before = (
                frozenset(self._module_roots),
                frozenset(self._direct_names),
                frozenset(self._package_modules.items()),
            )
            for node in binders:
                if isinstance(node, ast.Import):
                    self._bind_import(node)
                elif isinstance(node, ast.ImportFrom):
                    self._bind_import_from(node)
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    self._bind_assignment(node)
            after = (
                frozenset(self._module_roots),
                frozenset(self._direct_names),
                frozenset(self._package_modules.items()),
            )
            if after == before:
                return

    def _bind_import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in GUARDED_MODULES:
                self._module_roots.add(alias.asname or alias.name)
            elif alias.name in self._exports:
                if alias.asname:
                    self._package_modules[alias.asname] = alias.name
                else:
                    top = alias.name.split(".", 1)[0]
                    if top in self._exports:
                        self._package_modules[top] = top

    def _bind_import_from(self, node: ast.ImportFrom) -> None:
        if node.module in GUARDED_MODULES:
            for alias in node.names:
                if alias.name != "*":
                    self._direct_names.add(alias.asname or alias.name)
            return
        source = _resolve_from(node, self._module_name, self._is_package)
        exported = self._exports.get(source or "", frozenset())
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            if alias.name in GUARDED_MODULES or alias.name in exported:
                self._module_roots.add(bound)
            elif source is not None and f"{source}.{alias.name}" in self._exports:
                self._package_modules[bound] = f"{source}.{alias.name}"

    def _bind_assignment(self, node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> None:
        if node.value is None:
            return
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if not names:
            return
        if self._is_guarded_expr(node.value):
            self._module_roots.update(names)
            return
        module = self._package_module_of(node.value)
        if module is not None:
            for name in names:
                self._package_modules[name] = module

    def _package_module_of(self, expr: ast.AST) -> str | None:
        """The package module ``expr`` evaluates to, when it is a name chain."""
        if isinstance(expr, ast.Name):
            return self._package_modules.get(expr.id)
        if isinstance(expr, ast.Attribute):
            base = self._package_module_of(expr.value)
            if base is not None and f"{base}.{expr.attr}" in self._exports:
                return f"{base}.{expr.attr}"
        return None

    def _exported_by(self, expr: ast.AST) -> frozenset[str]:
        module = self._package_module_of(expr)
        return self._exports.get(module, frozenset()) if module is not None else frozenset()

    def _getattr_reads_guarded(self, obj: ast.AST, key: ast.AST) -> bool | None:
        """Whether ``getattr(obj, key)`` reads a guarded object.

        ``None`` when ``key`` is not provable and ``obj`` is a package module
        that has something guarded to hand out.
        """
        if self._resolver is None:
            raise RuntimeError("bind() must run before a getattr key can be resolved")
        names = self._resolver.resolve(key)
        exported = self._exported_by(obj)
        if names is None:
            return None if exported else False
        return any(
            name is not None and (name in GUARDED_MODULES or name in exported) for name in names
        )

    def _is_guarded_expr(self, expr: ast.AST) -> bool:
        """Whether ``expr`` evaluates to a guarded module or an object read out of one."""
        if isinstance(expr, ast.Name):
            return expr.id in self._module_roots or expr.id in self._direct_names
        if isinstance(expr, ast.Attribute):
            if expr.attr in GUARDED_MODULES or self._is_guarded_expr(expr.value):
                return True
            return expr.attr in self._exported_by(expr.value)
        if isinstance(expr, ast.Call) and _is_getattr(expr):
            obj, key = expr.args[0], expr.args[1]
            return self._is_guarded_expr(obj) or bool(self._getattr_reads_guarded(obj, key))
        return False

    def exports(self, tree: ast.Module) -> frozenset[str]:
        """Names bound at module scope to a guarded object (call after :meth:`bind`)."""
        at_module_scope = {name for node in _scope_nodes(tree) for name in _binding_names(node)}
        return frozenset(at_module_scope & (self._module_roots | self._direct_names))

    # -- counting ------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in GUARDED_MODULES:
                self.count += 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        spelled = f"from {'.' * node.level}{node.module or ''} import *"
        if node.module in GUARDED_MODULES:
            self.count += 1
            if any(alias.name == "*" for alias in node.names):
                self.unbounded.append((node.lineno, spelled))
        else:
            source = _resolve_from(node, self._module_name, self._is_package)
            exported = self._exports.get(source or "", frozenset())
            for alias in node.names:
                if alias.name == "*":
                    if exported:
                        self.unbounded.append((node.lineno, spelled))
                elif alias.name in GUARDED_MODULES or alias.name in exported:
                    self.count += 1
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in self._module_roots:
            self.count += 1
            self._consumed.add(id(node.value))
        elif node.attr in GUARDED_MODULES or node.attr in self._exported_by(node.value):
            # `<anything>.hashlib`, or `<package module>.<export>`: the guarded
            # object read out of another module object.
            self.count += 1
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_getattr(node) and not self._is_guarded_expr(node.args[0]):
            # A guarded receiver is already counted at its own load.
            verdict = self._getattr_reads_guarded(node.args[0], node.args[1])
            if verdict is None:
                self.unbounded.append((node.lineno, ast.unparse(node)))
            elif verdict:
                self.count += 1
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        # Only loads: rebinding the name locally is not a use of the import.
        # A BARE load of a module root counts too — `h = hashlib`,
        # `getattr(hashlib, "sha3_256")`, `f(hashlib)` all hand the module to
        # a binding or callee this gate cannot follow, so the load itself is
        # the reference (the same reasoning that makes a dynamic import count
        # at the call).  Loads consumed by an enclosing counted Attribute are
        # excluded above.
        if isinstance(node.ctx, ast.Load) and id(node) not in self._consumed:
            if node.id in self._direct_names or node.id in self._module_roots:
                self.count += 1
        self.generic_visit(node)


def _is_guarded(name: str) -> bool:
    return name.split(".", 1)[0] in GUARDED_MODULES


def _analyse(
    tree: ast.Module,
    module_name: str | None = None,
    *,
    is_package: bool = False,
    exports: Exports | None = None,
    resolver: StringResolver | None = None,
    binders: list[ast.AST] | None = None,
) -> _GuardedModuleVisitor:
    visitor = _GuardedModuleVisitor(
        module_name, is_package=is_package, exports=exports, resolver=resolver, binders=binders
    )
    visitor.bind(tree)
    visitor.visit(tree)
    return visitor


def count_hash_references(
    tree: ast.Module,
    module_name: str | None = None,
    *,
    is_package: bool = False,
    exports: Exports | None = None,
) -> int:
    """Guarded-module references: imports, aliased uses, and dynamic imports.

    A dynamic import or ``sys.modules`` lookup counts once when ANY value its
    argument resolves to names a guarded module.  Unresolvable ones are not
    counted here; :func:`unresolved_dynamic_imports` fails them outright.
    ``exports`` (from :func:`package_exports`) lets a re-export from a sibling
    module be recognised; without it only the guarded names themselves are.
    """
    visitor = _analyse(tree, module_name, is_package=is_package, exports=exports)
    return visitor.count + _dynamic_guarded_count(dynamic_imports(tree, module_name))


def _dynamic_guarded_count(sites: list[DynamicImport]) -> int:
    return sum(
        1
        for site in sites
        if site.names is not None and any(_is_guarded(name) for name in site.names)
    )


def unresolved_dynamic_imports(
    tree: ast.Module, module_name: str | None = None
) -> list[DynamicImport]:
    """Dynamic imports / ``sys.modules`` lookups whose module is not provable."""
    return [site for site in dynamic_imports(tree, module_name) if site.names is None]


def package_exports(
    package_dir: Path,
    trees: Mapping[Path, ast.Module],
    resolvers: Mapping[Path, StringResolver] | None = None,
    binders: Mapping[Path, list[ast.AST]] | None = None,
) -> dict[str, frozenset[str]]:
    """Every package module's guarded exports, to a fixpoint across the package.

    ``pqc_backends.py`` binds ``hashlib`` at module scope, so
    ``from .pqc_backends import hashlib`` in any sibling hands that sibling
    OpenSSL without an ``import hashlib`` of its own.  The fixpoint follows a
    re-export through any number of hops (``a`` exports it, ``b`` imports it
    from ``a`` under another name, ``c`` imports that name from ``b``).
    """
    names = {path: module_name_for(path, package_dir) for path in trees}
    exports: dict[str, frozenset[str]] = {name: frozenset() for name in names.values()}
    if resolvers is None:
        resolvers = {path: StringResolver(tree, names[path]) for path, tree in trees.items()}
    if binders is None:
        binders = {path: _binding_nodes(tree) for path, tree in trees.items()}
    changed = True
    while changed:
        changed = False
        for path, tree in trees.items():
            visitor = _GuardedModuleVisitor(
                names[path],
                is_package=path.name == "__init__.py",
                exports=exports,
                resolver=resolvers[path],
                binders=binders[path],
            )
            visitor.bind(tree)
            found = visitor.exports(tree)
            if found != exports[names[path]]:
                exports[names[path]] = found
                changed = True
    return exports


def scan_package(package_dir: Path) -> list[str]:
    """Return failure messages; empty means the boundary holds."""
    failures: list[str] = []
    seen: set[str] = set()
    py_files = sorted(path for path in package_dir.rglob("*.py") if "__pycache__" not in path.parts)
    if not py_files:
        return [f"{package_dir}: no Python files found — refusing to pass an empty scan"]
    trees: dict[Path, ast.Module] = {}
    for path in py_files:
        try:
            trees[path] = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover - a broken tree fails elsewhere
            failures.append(
                f"{path.relative_to(package_dir).as_posix()}: unparseable ({exc}); cannot verify the boundary"
            )
    resolvers = {
        path: StringResolver(tree, module_name_for(path, package_dir))
        for path, tree in trees.items()
    }
    binders = {path: _binding_nodes(tree) for path, tree in trees.items()}
    exports = package_exports(package_dir, trees, resolvers, binders)
    for path, tree in trees.items():
        key = path.relative_to(package_dir).as_posix()
        module_name = module_name_for(path, package_dir)
        visitor = _analyse(
            tree,
            module_name,
            is_package=path.name == "__init__.py",
            exports=exports,
            resolver=resolvers[path],
            binders=binders[path],
        )
        sites = dynamic_imports(tree, module_name)
        count = visitor.count + _dynamic_guarded_count(sites)
        for site in (site for site in sites if site.names is None):
            failures.append(
                f"{key}:{site.lineno}: {site.kind}({site.argument}) — the module is "
                "chosen at run time and cannot be resolved from the source, so this "
                "gate cannot bound it (it could be hashlib/_hashlib/hmac under any "
                "spelling). Name the module with a literal, or iterate a literal "
                "tuple of module names; this is not allowlistable."
            )
        for lineno, source in visitor.unbounded:
            failures.append(
                f"{key}:{lineno}: {source} — this can bind hashlib/_hashlib/hmac, or "
                "an object a sibling module read out of one, under names this gate "
                "cannot enumerate. Import the names you use explicitly; this is not "
                "allowlistable."
            )
        entry = ALLOWLIST.get(key)
        if count and entry is None:
            failures.append(
                f"{key}: {count} guarded-module reference(s), but the file is "
                "not in the trust-bootstrap allowlist. Production hashing belongs on "
                "the native kernels (native_sha256/384/512, native_sha3_256/384/512, "
                "native_pbkdf2_hmac_sha256/512). If this file genuinely joined the "
                "bootstrap, add it to ALLOWLIST in tools/check_stdlib_hash_boundary.py "
                "with the exact count and the reason."
            )
        elif entry is not None:
            seen.add(key)
            expected, rationale = entry
            if count != expected:
                failures.append(
                    f"{key}: {count} guarded-module reference(s), allowlist "
                    f"records {expected} ({rationale}). A new use inside a bootstrap "
                    "file is not covered by the file's rationale — convert it to the "
                    "native kernels, or update the allowlist entry with why the "
                    "bootstrap grew."
                )
    for name in sorted(set(ALLOWLIST) - seen):
        failures.append(
            f"{name}: allowlisted but absent from {PACKAGE_DIR.name}/ — remove the "
            "stale entry so the allowlist cannot quietly cover a future file"
        )
    return failures


def main() -> int:
    failures = scan_package(PACKAGE_DIR)
    if failures:
        print("FAIL  stdlib-hash boundary (INVARIANT-1):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    total = len(ALLOWLIST)
    print(
        f"OK    stdlib hashlib confined to the {total}-file trust bootstrap "
        "(counts pinned; production hashing is native)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
