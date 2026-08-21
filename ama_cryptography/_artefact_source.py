# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Read the signed integrity artefact from its SOURCE TEXT, never through import.

WHY THIS MODULE EXISTS
======================

``_integrity_signature.py`` is generated data: a handful of module-level
literals (digests, an Ed25519 public key, a signature) that every integrity
control in this package consumes.  Three of those controls read it *before* the
package's bytecode has been validated:

* ``ama_cryptography.__init__._refuse_tampered_bindings_before_import()`` — the
  pre-import binding-extension gate, whose whole purpose is to refuse a tampered
  ``.so`` BEFORE its module-init function runs;
* ``ama_cryptography.pqc_backends._expected_native_digest()`` — the pre-load
  check on ``libama_cryptography`` itself, for the same reason (a shared object
  runs its constructors the moment it is mapped);
* the POST ``integrity`` stage, which runs before the ``execution-integrity``
  stage that binds cached bytecode to signed source.

All three obtained the literals with ``from ama_cryptography import
_integrity_signature``.  An ordinary import does not read the ``.py`` — it reads
``__pycache__/_integrity_signature.cpython-3XX.pyc`` whenever a cache exists
whose PEP 552 header matches the source's ``(mtime, size)``.  Nothing had
validated that cache at any of those three points.

THE ATTACK THIS CLOSES, AS MEASURED
-----------------------------------

Against a signed tree with the extensions bound, in a scratch copy:

1. flip one byte of a signed ``hkdf_binding*.so``.  With no bytecode cache
   (``python -B``) the pre-import gate refuses, as designed::

       hkdf_binding…so: digest MISMATCH — bytes differ from the signed build
       Refused BEFORE any binding was imported.

2. write ``__pycache__/_integrity_signature.cpython-311.pyc`` compiled from the
   artefact source with ONE entry of ``INTEGRITY_BINDING_DIGESTS_HEX`` replaced
   by the tampered object's real digest, carrying the untouched source's
   ``(mtime, size)`` in the header so CPython accepts it.  Leave
   ``_integrity_signature.py`` byte-identical — its Ed25519 signature still
   verifies.

3. import the package::

       IMPORT SUCCEEDED — binding modules executed: [… 'ama_cryptography.hkdf_binding' …]

The gate compared the tampered object against the tampered object's own digest.
Writing one file in ``__pycache__/`` — no code poisoning, no re-signing —
converted a pre-execution refusal back into nothing at all.

WHAT THIS DOES AND DOES NOT ESTABLISH
-------------------------------------

Reading the source text removes the artefact-as-DATA poisoning: the literals now
come from bytes the signature covers, so changing them means changing a signed
file, which is exactly the attacker the pre-load checks are documented to stop.

It does not, and cannot, defend against poisoning the CHECKER's own bytecode — a
``__init__.pyc`` or ``pqc_backends.pyc`` written by the same attacker runs
whatever they like.  That is the boundary ``SECURITY.md`` already states ("a
self-check written in Python cannot vouch for the bytecode of its OWN module"),
it is detected after the fact by the POST ``execution-integrity`` stage, and it
requires substituting code rather than data.  The distinction is the point: the
artefact is data this code consumes, not the code itself, and it had no business
being reachable through the import system.

``_build_sign._write_signature_module`` already unlinks this cache after
writing, which kept the honest case working and left the adversarial one open.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, Optional


class ArtefactSourceError(Exception):
    """``_integrity_signature.py`` exists but could not be read as literals.

    Distinct from absence.  A missing artefact means nothing is signed, which
    is the ordinary state of a source checkout; a present-but-unparseable one
    means the file this package trusts for every digest has been altered into
    something it does not recognise, and that is never a fallback.
    """


#: The generated artefact's file name, relative to the package directory.
ARTEFACT_NAME = "_integrity_signature.py"


class ArtefactFields:
    """Attribute view over the artefact's module-level literals.

    Deliberately shaped like the module object the call sites used to import,
    so ``getattr(sig, "INTEGRITY_NATIVE_DIGEST_HEX", None)`` keeps working
    unchanged at every consumer.  It carries only literals: there is no code in
    it to execute, which is the property the import system could not offer.
    """

    __slots__ = ("_values",)

    def __init__(self, values: Dict[str, Any]) -> None:
        self._values = dict(values)

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError as exc:  # pragma: no cover - mirrors module semantics
            raise AttributeError(name) from exc

    def as_dict(self) -> Dict[str, Any]:
        """A copy of the parsed literals, for callers that want the mapping."""
        return dict(self._values)


def artefact_path(package_dir: Optional[Path] = None) -> Path:
    """Where the artefact lives.  ``package_dir`` defaults to this package."""
    base = Path(__file__).resolve().parent if package_dir is None else Path(package_dir)
    return base / ARTEFACT_NAME


def load_artefact_fields(package_dir: Optional[Path] = None) -> Optional[ArtefactFields]:
    """Parse the artefact's literals from source text.

    Returns ``None`` when the file is absent — an unsigned tree, where there is
    nothing to check against and every caller already has a documented
    behaviour for that state.

    Raises :class:`ArtefactSourceError` when the file is present but does not
    parse, when a top-level assignment is not a literal, or when it parses to
    NO literal assignments at all.  A generated file of constants that has
    stopped being a generated file of constants is tampering, and refusing is
    the same fail-closed rule the callers apply to a digest that does not
    match.

    That last case is the one that was silent.  An empty (or literal-free)
    artefact parses cleanly to zero values, and the ``ArtefactFields`` it used
    to produce answered ``None`` to every ``getattr`` a caller makes — so
    ``__init__._refuse_tampered_bindings_before_import`` took its
    ``not signed -> return`` branch and ``pqc_backends._expected_native_digest``
    returned ``None``, and BOTH pre-load gates passed without comparing
    anything.  A signed tree whose artefact has been truncated is not an
    unsigned tree; it is a signed tree with the signatures removed, and the
    difference is exactly the one these gates exist to notice before a shared
    object is mapped.  ``Path.write_text`` truncates in place, so the state was
    reachable without an attacker at all — see ``_build_sign``, where the write
    is now atomic.

    Only module-level ``NAME = <literal>`` and ``NAME: ann = <literal>`` forms
    are collected.  Anything else in the file — imports, functions, conditionals
    — is a shape the generator never emits, and is rejected rather than skipped:
    silently ignoring it would let an attacker hide the real assignment behind a
    construct this reader does not model.
    """
    path = artefact_path(package_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ArtefactSourceError(f"{path}: cannot be read ({exc})") from exc
    except UnicodeDecodeError as exc:
        # NOT an OSError — UnicodeDecodeError derives from ValueError, so the
        # handler above does not catch it and a non-UTF-8 artefact escaped this
        # function raw, past the one exception type every caller of the trust
        # bootstrap is written to expect.  An artefact that is not text is
        # exactly as unusable as one that cannot be opened, and the callers
        # that treat ArtefactSourceError as "no usable artefact, refuse" must
        # see it as such rather than as an unhandled exception.
        raise ArtefactSourceError(f"{path}: is not UTF-8 text ({exc})") from exc

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        raise ArtefactSourceError(f"{path}: is not parseable Python ({exc})") from exc

    values: Dict[str, Any] = {}
    saw_assignment = False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # the module docstring
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue  # a bare annotation binds nothing
            targets = [node.target]
            value = node.value
        else:
            raise ArtefactSourceError(
                f"{path}: unexpected top-level {type(node).__name__} — the "
                "generated artefact contains only literal assignments"
            )

        names = []
        for target in targets:
            if not isinstance(target, ast.Name):
                raise ArtefactSourceError(
                    f"{path}: unexpected assignment target {type(target).__name__}"
                )
            names.append(target.id)

        try:
            literal = ast.literal_eval(value)
        except (ValueError, SyntaxError) as exc:
            raise ArtefactSourceError(f"{path}: {names[0]} is not a literal ({exc})") from exc
        for name in names:
            values[name] = literal
        saw_assignment = True

    if not saw_assignment:
        # Present, readable, parseable — and carrying nothing.  The generator
        # always emits INTEGRITY_DIGEST_HEX and four siblings, so a file of
        # zero literal assignments is not an artefact this reader models; it
        # is the same "shape the generator never emits" the branches above
        # refuse, reached by subtraction instead of by addition.  Returning
        # fields here answered None to every digest lookup and took both
        # pre-load gates down their nothing-to-check branch.
        raise ArtefactSourceError(
            f"{path}: parses to no literal assignments — the generated "
            "artefact always defines INTEGRITY_DIGEST_HEX and its siblings, so "
            "an empty one is a signed tree with its signatures removed, not an "
            "unsigned tree.  Restore it from the wheel, or remove it and "
            "re-sign: rm <package-dir>/_integrity_signature.py && "
            "AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity "
            "--update --sign"
        )

    return ArtefactFields(values)
