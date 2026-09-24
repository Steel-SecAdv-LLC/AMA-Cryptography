#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Aggregating Gate Coverage Verifier (INVARIANT-31)
====================================================================

Verifies that every job which runs on a pull request is actually capable of
blocking that pull request.

Why this exists
---------------
Branch protection on this repository was designed to require the
*aggregating gate* context of each primary workflow (``ci-gate``,
``static-analysis-gate``, ``fuzzing-gate``, …) rather than the individual job
names.  That design is deliberate and documented in each gate's own comment:
it means adding, renaming, or matrix-expanding a job updates a ``needs:`` list
under code review instead of drifting the branch-protection configuration out
of sync (*required-context drift*).

Correction (AGENTS.md section 6.6), measured 2026-09-24 against the public
rules endpoint: the ruleset on ``main`` requires 55 individual job contexts and
none of the gates, so the design above is not what is enforced.  This checker
still proves every job can fail its gate; whether the gate can block a merge
is a ruleset setting, reported on every CI run by
``tools/check_required_contexts.py`` until an administrator adds the gate
contexts.

The design has one failure mode, and it is silent in the worst possible
direction.  A job that is **not** listed in its workflow's gate ``needs:``
still runs, still reports its own red X on the pull request — and still
cannot block a merge, because branch protection never evaluates its context.
The pull request shows a failing check next to a green required gate, and
"all required checks passed" is true.

That is not hypothetical here.  ``c-library-no-native-pqc`` in
``ci-build-test.yml`` guards the ``AMA_USE_NATIVE_PQC=OFF`` configuration —
the build for consumers who take the library without native post-quantum
support.  It was absent from ``ci-gate``'s ``needs:`` while commit ``f3dd0c2``
of this branch had to repair that exact configuration after it broke
undetected.  The guard job existed, ran, and gated nothing.

Each gate's comment states what it requires of its dependencies.  The
wildcard gates require every one to be ``success`` — ``ci-gate`` in both
``ci.yml`` and ``ci-build-test.yml`` says "every job in this workflow runs
unconditionally … so each MUST be ``success``".  ``dudect-gate`` and
``static-analysis-gate`` say the opposite on purpose: several of their jobs are
schedule- or dispatch-only, so each gate re-derives every job's trigger and
requires ``success`` where the job should run and ``skipped`` where it should
not.  (This paragraph used to say every gate comment asserted the first form;
those two never did.)  Either statement is true only of the jobs a gate
actually lists and evaluates, and that is what this checker enforces.

What is checked
---------------
``gate presence``
    A workflow that triggers on ``pull_request`` and defines more than one
    job must define an aggregating gate job.  Single-job workflows are
    exempt: the job *is* its own status context, so there is nothing to
    aggregate.  Workflows that never trigger on ``pull_request`` (``release.yml``
    on a tag push, ``wiki-sync.yml`` on a push to main) are exempt: branch
    protection cannot require a context they never produce.

``gate coverage``
    Every non-gate job in a workflow must appear in the ``needs:`` of some
    gate job in that workflow.  ``needs:`` is workflow-local, so each
    workflow is checked independently.

``gate reachability``
    Every gate job must carry a job-level ``if: always()``.  Without it the
    gate is *skipped* when any dependency fails, and a required context that
    reports ``skipped`` never resolves — the pull request sits on "Expected —
    waiting for status check to be reported" indefinitely rather than going
    red.  A gate that cannot report red is not a gate.

Both directions are pinned by ``tests/test_gate_coverage.py``, so this gate
cannot silently degrade into a no-op.

Usage
-----
::

    python tools/check_gate_coverage.py

Exits 0 when every workflow satisfies the invariant, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

# A job is an aggregating gate iff its job id ends with this suffix.  Every
# gate in the repository follows the convention (`ci-gate`, `dudect-gate`,
# `static-analysis-gate`, …); enforcing the naming keeps detection mechanical
# rather than heuristic.
GATE_SUFFIX = "-gate"

WORKFLOW_DIR = Path(".github/workflows")

#: Non-vacuity floors (H7).  These are pinned so deleting workflows or jobs
#: cannot silently shrink what the aggregating-gate audit inspects down to
#: nothing -- the two ways this meta-gate was proven vacuous (an empty
#: .github/workflows left `examined` 0 and the run PASS; a planted
#: always-failing lane bound into env: passed too).  Matching the MIN_* floors
#: the rest of the gates carry: a real reduction must lower these under review
#: rather than pass silently.
#:
#: Both floors equal the live counts, and tests/test_gate_coverage.py holds
#: them there.  They used to trail the tree (14 files and 40 jobs against 18
#: and 83), so four workflows could disappear without tripping anything --
#: the drift the floor exists to catch.  Adding or removing a workflow or a job
#: now means changing these two numbers in the same change, under review.
#: 15 since the five no-op twin workflows were removed (see
#: check_pr_relevance); each gate they twinned now decides relevance itself.
MIN_WORKFLOWS = 15
MIN_JOBS_INSPECTED = 84


def _load(path: Path) -> dict[Any, Any]:
    """Parse a workflow file, returning ``{}`` for anything unparseable."""
    with path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    return loaded if isinstance(loaded, dict) else {}


def _triggers(workflow: dict[Any, Any]) -> dict[Any, Any]:
    """Return the ``on:`` block.

    PyYAML resolves the bare key ``on`` to the boolean ``True`` under the
    YAML 1.1 rules it implements, so the block has to be looked up under both
    keys — and the mapping is therefore genuinely ``dict[Any, Any]``, not
    ``dict[str, Any]``.  Reading only ``"on"`` silently reports every workflow
    as having no triggers, which would make this entire checker vacuous.
    """
    raw = workflow.get(True, workflow.get("on"))
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return {raw: None}
    if isinstance(raw, list):
        return dict.fromkeys(raw)
    return {}


def _needs(job: dict[str, Any]) -> set[str]:
    """Normalise ``needs:``, which GitHub accepts as a string or a list."""
    raw = job.get("needs") or []
    if isinstance(raw, str):
        return {raw}
    return {entry for entry in raw if isinstance(entry, str)}


#: A gate step that consults ``needs.*.result`` evaluates EVERY dependency by
#: construction — adding a job to ``needs:`` extends the check with no further
#: edit.  Seven of this repository's NINE aggregating gates are written that
#: way — counted rather than recalled: acvp-gate, arm-qemu-gate, ci-gate in
#: both ci.yml and ci-build-test.yml, corpus-provenance-gate, dudect-gate,
#: fuzzing-gate, security-gate and static-analysis-gate, of which seven use
#: the `needs.*.result` wildcard form.
#:
#: MENTIONING the wildcard is not evaluating it.  The exemption used to be
#: granted to any gate whose `if:` text matched this pattern, so
#: ``if: contains(needs.*.result, 'cancelled') && false`` — a step that can
#: never run — switched the per-dependency check off and the gate passed.  The
#: pattern is now only used to say WHY a wildcard gate was rejected; the
#: exemption itself requires :func:`_wildcard_fail_step`.
_WILDCARD_NEEDS_RE = re.compile(r"needs\.\*\.(?:result|outputs|conclusion)")

#: The three non-success results a dependency can end in on a pull request.
#: A wildcard step that fails on only some of them lets the others through:
#: the failure-only form ``contains(needs.*.result, 'failure')`` passes a
#: dependency that was *cancelled* or *skipped* (an upstream `needs:` failure
#: or a mis-scoped `if:` skips it), and the gate goes green over a job that
#: never ran.
WILDCARD_REQUIRED_RESULTS = frozenset({"failure", "cancelled", "skipped"})

#: One disjunct of the accepted wildcard condition, exactly.
_WILDCARD_DISJUNCT_RE = re.compile(r"contains\(\s*needs\.\*\.result\s*,\s*(['\"])([a-z_]+)\1\s*\)")


def _split_top_level_or(expression: str) -> list[str] | None:
    """Split an expression on ``||`` operators that are not inside parentheses.

    Returns ``None`` when the parentheses are unbalanced.  Quoted strings are
    skipped so a ``'||'`` literal is not an operator.
    """
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    quote: str | None = None
    while index < len(expression):
        char = expression[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and expression.startswith("||", index):
            parts.append(expression[start:index])
            index += 2
            start = index
            continue
        index += 1
    if depth != 0 or quote is not None:
        return None
    parts.append(expression[start:])
    return [part.strip() for part in parts]


def _strip_outer_parens(expression: str) -> str:
    """Remove parentheses that enclose the WHOLE expression, repeatedly."""
    text = expression.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        encloses_all = True
        for position, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and position != len(text) - 1:
                    encloses_all = False
                    break
        if not encloses_all:
            break
        text = text[1:-1].strip()
    return text


def _wildcard_condition_results(condition: str) -> set[str] | None:
    """The results a wildcard `if:` fails on, or ``None`` if it is any other shape.

    Accepted: a disjunction (``||``) whose every top-level term is exactly
    ``contains(needs.*.result, '<result>')``, optionally inside ``${{ }}`` and
    parentheses.  Anything else — a conjunction, a negation, a literal
    ``false``, a comparison — is rejected, because each of those can make the
    step unreachable while still mentioning the wildcard.  The accepted shape
    is monotone: adding a disjunct can only make the step fire MORE often.
    """
    text = condition.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    disjuncts = _split_top_level_or(_strip_outer_parens(text))
    if not disjuncts:
        return None
    results: set[str] = set()
    for disjunct in disjuncts:
        match = _WILDCARD_DISJUNCT_RE.fullmatch(_strip_outer_parens(disjunct))
        if match is None:
            return None
        results.add(match.group(2))
    return results


#: A line of a `run:` script that is exactly ``exit <nonzero>`` at column 0,
#: i.e. not nested in a shell `if`/function body the step could branch around.
_TOP_LEVEL_NONZERO_EXIT_RE = re.compile(r"^exit[ \t]+([1-9][0-9]*)[ \t]*(?:#.*)?$", re.MULTILINE)
#: Any `exit` whose status is zero, absent, or computed — each can end the
#: script successfully before the nonzero exit is reached.
_ANY_EXIT_RE = re.compile(r"(?:^|[;&|({]\s*|\s)exit\b(?:[ \t]+(\S+))?", re.MULTILINE)


def _run_exits_nonzero(run: str) -> bool:
    """True when a step's script unconditionally ends in a nonzero exit.

    Requires a column-0 ``exit N`` (N >= 1) and no other ``exit`` whose status
    is not a nonzero literal, so ``exit 0`` / bare ``exit`` / ``exit $rc``
    cannot short-circuit it.
    """
    if not _TOP_LEVEL_NONZERO_EXIT_RE.search(run):
        return False
    for match in _ANY_EXIT_RE.finditer(run):
        status = match.group(1)
        if status is None or not re.fullmatch(r"[1-9][0-9]*", status):
            return False
    return True


def _wildcard_fail_step(job: dict[str, Any]) -> bool:
    """True when some step fails the gate on EVERY non-success wildcard result.

    The step must (1) carry an `if:` of the accepted wildcard shape that covers
    ``failure``, ``cancelled`` and ``skipped``; (2) run a script that exits
    nonzero unconditionally; and (3) not carry ``continue-on-error``, which
    would turn that nonzero exit into a green step.  This is the form every
    wildcard roll-up gate in this repository uses.
    """
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict) or step.get("if") is None:
            continue
        results = _wildcard_condition_results(str(step["if"]))
        if results is None or not WILDCARD_REQUIRED_RESULTS <= results:
            continue
        run = step.get("run")
        if not isinstance(run, str) or not _run_exits_nonzero(run):
            continue
        if step.get("continue-on-error") not in (None, False):
            continue
        return True
    return False


#: Commands whose arguments are output, never a decision.  A dependency's result
#: that appears only as their argument is printed, not evaluated: the command
#: succeeds whatever the value was, so the gate stays green over a failed job.
_OUTPUT_ONLY_COMMANDS = frozenset({"echo", "printf", ":", "true"})

#: Reserved words and grouping tokens that can open a simple command without
#: being its command word (``if [ ... ]``, ``then exit 1``, ``! test ...``).
_COMMAND_PREFIXES = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "(", "time"}
)

#: Commands through which a script turns a value into a failing status.
_FAILING_COMMANDS = frozenset({"test", "[", "[[", "false"})

#: The opener of a heredoc (``<<EOF``, ``<<-'EOF'``), not a here-string (``<<<``).
_HEREDOC_RE = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _shell_segments(run: str) -> list[tuple[str, bool]]:
    """Split a ``run:`` script into simple commands, as ``(text, piped)``.

    Separators are newline, ``;``, ``&&``, ``||`` and ``&`` outside quotes and
    outside ``${{ }}`` expressions.  ``|`` does not separate: a pipeline's
    status is its last stage's, so ``echo "$R" | grep -q success`` is one
    command that CAN fail, and ``piped`` records that it is a pipeline.
    Comments are dropped, and a heredoc's body is dropped as the data it is.

    This is a tokenizer for deciding what a script DOES with a value, not a
    shell parser; it errs toward reporting a real evaluation as missing (the
    gate author then writes the check plainly) rather than toward accepting a
    mention as one.
    """
    segments: list[tuple[str, bool]] = []
    current: list[str] = []
    piped = False
    quote: str | None = None
    heredocs: list[str] = []
    index = 0
    length = len(run)

    def flush() -> None:
        nonlocal piped
        text = "".join(current).strip()
        if text:
            segments.append((text, piped))
            heredocs.extend(match.group(2) for match in _HEREDOC_RE.finditer(text))
        current.clear()
        piped = False

    while index < length:
        char = run[index]
        if run.startswith("${{", index):
            end = run.find("}}", index + 3)
            end = length if end < 0 else end + 2
            current.append(run[index:end])
            index = end
            continue
        if quote is not None:
            current.append(char)
            if char == "\\" and quote == '"' and index + 1 < length:
                current.append(run[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            current.append(" " if run[index + 1] == "\n" else run[index : index + 2])
            index += 2
            continue
        if char == "#" and (index == 0 or run[index - 1] in " \t\n;&|()"):
            newline = run.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if char == "\n":
            flush()
            index += 1
            # A heredoc's body starts on the line after its opener and ends at
            # the line holding only its delimiter; none of it is a command.
            while heredocs:
                delimiter = heredocs.pop(0)
                while index < length:
                    newline = run.find("\n", index)
                    line_end = length if newline < 0 else newline
                    line = run[index:line_end]
                    index = line_end + 1
                    if line.strip() == delimiter:
                        break
            continue
        if run.startswith("&&", index) or run.startswith("||", index):
            flush()
            index += 2
            continue
        if char == ";" or (
            char == "&"
            and run[index - 1 : index] not in (">", "<")
            and run[index + 1 : index + 2] != ">"
        ):
            flush()
            index += 1
            continue
        if char == "|":
            piped = True
        current.append(char)
        index += 1
    flush()
    return segments


def _command_word(segment: str) -> tuple[str, list[str]]:
    """The command a simple-command segment runs, and its tokens from there."""
    tokens = segment.split()
    while tokens and tokens[0] in _COMMAND_PREFIXES:
        tokens.pop(0)
    if not tokens:
        return "", []
    tokens[0] = tokens[0].lstrip("(")
    return tokens[0], tokens


def _decisive_text(run: str) -> str:
    """The parts of a script that can act on a value: every command that is not
    output-only.  A read that survives only here can change the exit status."""
    kept: list[str] = []
    for segment, piped in _shell_segments(run):
        word, _tokens = _command_word(segment)
        if word in _OUTPUT_ONLY_COMMANDS and not piped:
            continue
        kept.append(segment)
    return "\n".join(kept)


def _run_can_fail(run: str) -> bool:
    """Whether a script has any way to turn a value into a failing status.

    A ``test``/``[``/``[[``/``false`` command (a false test fails the step under
    the runner's ``bash -e``), an ``exit``/``return`` with a status other
    than a literal ``0``, or a pipeline whose last stage is not output-only.
    A script with none of these succeeds whatever the
    dependency's result was, so a read inside it evaluates nothing.
    """
    for segment, piped in _shell_segments(run):
        word, tokens = _command_word(segment)
        if word in _FAILING_COMMANDS:
            return True
        if word in ("exit", "return") and len(tokens) > 1 and tokens[1] != "0":
            return True
        if piped:
            # A pipeline's status is its last stage's: `echo "$R" | grep -qx
            # success` fails the step under `bash -e` when grep finds nothing.
            last_word, _ = _command_word(segment.rsplit("|", 1)[1])
            if last_word and last_word not in _OUTPUT_ONLY_COMMANDS:
                return True
    return False


#: ``needs.<dep>.result`` / ``.outcome`` inside a value, dotted or bracketed.
_NEEDS_IN_VALUE_RE = re.compile(
    r"needs\s*(?:\.\s*([A-Za-z0-9_-]+)|\[\s*['\"]([^'\"]+)['\"]\s*\])\s*\.\s*(?:result|outcome)"
)


def _env_aliases(env: Any) -> dict[str, set[str]]:
    """Map each dependency to the ``env:`` key(s) one ``env:`` block binds to it.

    Records the KEY a value referencing ``needs.<dep>.result`` is bound to (the
    shell variable name).  A dependency is only evaluated through such an alias
    when a ``run:`` script that can see it dereferences it; the binding alone
    is not evaluation, which is the vacuity H7 names.  Scoped per block because
    a step sees the job's ``env:`` and its own, never another step's.
    """
    alias_map: dict[str, set[str]] = {}
    if not isinstance(env, dict):
        return alias_map
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        for match in _NEEDS_IN_VALUE_RE.finditer(value):
            dep = match.group(1) or match.group(2)
            if dep:
                alias_map.setdefault(dep, set()).add(key)
    return alias_map


def _gate_condition_text(job: dict[str, Any]) -> str:
    """Only the `if:` expressions of a gate job and of its steps.

    A dependency's outcome is EVALUATED in a condition; everything else in the
    job — `run`, `env`, `with` — can mention it without acting on it.  The
    wildcard exemption is about evaluation, so it reads only the conditions.
    """
    conditions: list[str] = []
    condition = job.get("if")
    if condition is not None:
        conditions.append(str(condition))
    steps = job.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict) and step.get("if") is not None:
                conditions.append(str(step["if"]))
    return "\n".join(conditions)


def _result_reference(need: str) -> str:
    """Pattern matching a real read of ``need``'s outcome.

    ``needs.<name>.result`` and ``needs.<name>.outcome`` are the two spellings
    GitHub offers, in both the dotted and the bracketed context form.  Anything
    else -- the job's name in a comment, in an echo, or as a substring of a
    different job's name -- is a mention, not an evaluation.

    The optional backslash before the bracket quotes dates from when the body
    this was searched against was JSON-serialised, so a double-quoted
    ``needs["job"].outcome`` arrived as ``needs[\\"job\\"].outcome``.  The
    search now reads the raw ``if:`` and ``run:`` text, where the backslash
    never appears; allowing it matches nothing a real read would not.
    """
    name = re.escape(need)
    return (
        r"needs\s*\.\s*" + name + r"\s*\.\s*(?:result|outcome)"
        r"|needs\s*\[\s*(?:\\)?['\"]" + name + r"(?:\\)?['\"]\s*\]\s*\.\s*(?:result|outcome)"
    )


def _unevaluated_needs(job: dict[str, Any]) -> list[str]:
    """Dependencies the gate lists but never looks at.

    ``needs:`` membership alone does not make a job blocking.  It makes the
    gate WAIT for the job; whether the gate goes red when that job fails is
    decided by the gate's own step, and two of this repository's gates —
    ``dudect-gate`` and ``static-analysis-gate`` — hand-enumerate each
    dependency into an ``env:`` block and call a shell ``check`` function once
    per job.  A job added to ``needs:`` but not to that hand-written list
    satisfies INVARIANT-31's coverage rule and is still never evaluated: the
    gate carries ``if: always()``, so it runs anyway, ``rc`` stays 0, and the
    final step prints that every job reached the state the trigger requires.
    """
    # The wildcard exemption applies only where the wildcard is EVALUATED AND
    # ACTED ON: a step whose `if:` fires on failure, cancelled and skipped and
    # whose script then exits nonzero.  Merely naming `needs.*.result` in an
    # `if:` -- `contains(needs.*.result, 'cancelled') && false` -- used to be
    # enough to switch the per-dependency check off.
    if _wildcard_fail_step(job):
        return []

    # Read the EVALUATION, not the binding (H7), and not the mention either.
    # A dependency's env: alias binding -- `R_X: ${{ needs.x.result }}` -- used
    # to satisfy the old whole-body substring test even when the run: script
    # that sets `rc` never consulted `$R_X`.  The fix for that still accepted
    # ANY read in any if: or run:, so `run: echo "x=${{ needs.x.result }}"`
    # counted, while `echo ${{ join(needs.*.result, ', ') }}` did not exempt the
    # wildcard -- the same mention held to two standards.  A named read now
    # counts only where it can turn the gate red, in a step without
    # `continue-on-error` (which turns a failing step green):
    #   (a) the step's `if:` reads it and the step's script exits nonzero
    #       unconditionally -- the wildcard rule, for one dependency; or
    #   (b) the step's script reads it, directly or through an env: alias the
    #       step can see (the job's env: or its own), in a command that is not
    #       output-only (echo/printf/:/true, a heredoc body, a comment), and the
    #       script has a way to fail at all (test/[/[[/false, or exit/return
    #       with a status other than 0).
    job_aliases = _env_aliases(job.get("env"))
    needs = _needs(job)
    evaluated: set[str] = set()
    steps = job.get("steps")
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        if step.get("continue-on-error") not in (None, False):
            continue
        run = step.get("run")
        run = run if isinstance(run, str) else ""
        condition = step.get("if")
        if condition is not None and _run_exits_nonzero(run):
            evaluated.update(
                need for need in needs if re.search(_result_reference(need), str(condition))
            )
        if not run or not _run_can_fail(run):
            continue
        decisive = _decisive_text(run)
        aliases = {dep: set(keys) for dep, keys in job_aliases.items()}
        for dep, keys in _env_aliases(step.get("env")).items():
            aliases.setdefault(dep, set()).update(keys)
        for need in needs:
            if re.search(_result_reference(need), decisive) or any(
                re.search(r"\$\{?" + re.escape(alias) + r"(?![A-Za-z0-9_])", decisive)
                for alias in aliases.get(need, set())
            ):
                evaluated.add(need)
    return sorted(needs - evaluated)


def _is_always(job: dict[str, Any]) -> bool:
    """True when the job carries a job-level condition equivalent to always()."""
    condition = job.get("if")
    if condition is None:
        return False
    # Accept `always()`, `${{ always() }}`, and surrounding whitespace.  Any
    # richer expression is rejected: a gate whose reachability depends on a
    # compound condition is exactly the ambiguity this check exists to remove.
    normalised = str(condition).strip()
    for wrapper in ("${{", "}}"):
        normalised = normalised.replace(wrapper, "")
    return normalised.strip() == "always()"


def check_parsed(name: str, workflow: dict[Any, Any]) -> list[str]:
    """Check an already-parsed workflow document.

    Takes the parsed document so the rules can be exercised against
    synthetic documents without writing files.
    """
    jobs: dict[str, Any] = workflow.get("jobs") or {}
    if not jobs:
        return []

    failures: list[str] = []

    gate_ids = {job_id for job_id in jobs if job_id.endswith(GATE_SUFFIX)}
    other_ids = set(jobs) - gate_ids

    on_pull_request = "pull_request" in _triggers(workflow)

    if not gate_ids:
        # Exempt when there is nothing an aggregating gate could add: a
        # single-job workflow is its own status context, and a workflow that
        # never runs on a pull request produces no context branch protection
        # could require.
        # The `changes` job (see check_pr_relevance) decides relevance for the
        # job beside it and reports no context anyone requires, so a guard plus
        # its `changes` job is still a single-context workflow.
        context_jobs = [job_id for job_id in jobs if job_id != CHANGES_JOB]
        if on_pull_request and len(context_jobs) > 1:
            failures.append(
                f"{name}: {len(context_jobs)} jobs run on pull_request but the workflow "
                f"defines no aggregating gate job (expected a job id ending in "
                f"'{GATE_SUFFIX}'). Branch protection would have to require each "
                f"job by name, which is the required-context drift this "
                f"convention exists to prevent."
            )
        return failures

    covered: set[str] = set()
    for gate_id in sorted(gate_ids):
        gate = jobs[gate_id] or {}
        covered |= _needs(gate)
        if not _is_always(gate):
            failures.append(
                f"{name}: gate job '{gate_id}' has no job-level `if: always()`. "
                f"Without it the gate is skipped when a dependency fails, and a "
                f"required context reporting 'skipped' never resolves — the pull "
                f"request waits for a status that never arrives instead of going "
                f"red."
            )
        unevaluated = _unevaluated_needs(gate)
        if unevaluated:
            failures.append(
                f"{name}: gate job '{gate_id}' lists {len(unevaluated)} "
                f"dependenc(y/ies) it never evaluates — {', '.join(unevaluated)}. "
                f"`needs:` only makes the gate WAIT for a job; whether the gate "
                f"goes red when it fails is decided by the gate's own step. This "
                f"gate hand-enumerates its dependencies, so a job added to "
                f"`needs:` and not to that list runs, fails, and leaves the gate "
                f"green — with `if: always()` the gate runs regardless and its "
                f"exit status never sees the failure. Reference each dependency "
                f"in the gate's steps, or give the gate a step with "
                f"`if: contains(needs.*.result, 'failure') || "
                f"contains(needs.*.result, 'cancelled') || "
                f"contains(needs.*.result, 'skipped')` whose script is "
                f"`exit 1` — the form that cannot go stale. The failure-only "
                f"form is not enough: it passes a dependency that was "
                f"cancelled or skipped."
                + (
                    " (This gate names `needs.*.result` in an `if:`, but no step "
                    "of that shape acts on it.)"
                    if _WILDCARD_NEEDS_RE.search(_gate_condition_text(gate))
                    else ""
                )
            )

    missing = sorted(other_ids - covered)
    if missing:
        gate_label = "/".join(sorted(gate_ids))
        failures.append(
            f"{name}: {len(missing)} job(s) absent from the '{gate_label}' "
            f"needs: list — {', '.join(missing)}. Each still runs and still "
            f"reports its own result, but branch protection evaluates only the "
            f"gate context, so none of them can block a merge."
        )

    # A `needs:` entry naming a job that does not exist is a hard workflow
    # error at run time, but it surfaces as the gate never starting rather
    # than as a red gate — worth catching statically alongside the coverage.
    dangling = sorted(covered - set(jobs))
    if dangling:
        failures.append(
            f"{name}: gate needs: references undefined job(s) "
            f"{', '.join(dangling)}. The gate will fail to start rather than "
            f"report red."
        )

    return failures


#: The job that decides pull-request relevance, and the env key its watched
#: patterns live in (tools/pr_touches_watched_paths.py reads the same key).
CHANGES_JOB = "changes"
WATCHED_PATHS_KEY = "WATCHED_PATHS"


def _watched_paths(changes_job: dict[str, Any]) -> list[str] | None:
    """The WATCHED_PATHS patterns a `changes` job's steps declare, if any."""
    for step in changes_job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        value = (step.get("env") or {}).get(WATCHED_PATHS_KEY)
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
    return None


def check_pr_relevance(parsed: dict[str, dict[Any, Any]]) -> list[str]:
    """No gate is path-filtered on pull_request; relevance is decided in-workflow.

    GitHub creates no check run for a workflow that path filtering skipped, so
    a required context coming from one leaves every non-matching pull request
    on "Expected -- waiting for status".  This tree's first remedy was
    GitHub's documented no-op twin (same names, complementary
    ``paths-ignore:``), which this check used to hold complementary.  A twin is
    not exclusive: ``paths:`` fires when ANY changed file matches and
    ``paths-ignore:`` fires when ANY changed file is not ignored, so a pull
    request touching a watched and an unwatched file ran both, and the twin's
    trivial green arrived minutes before the real lanes reported.  No list
    arithmetic fixes that, so the twins were removed.

    The rule now:

    * no workflow filters ``pull_request`` by ``paths:`` or ``paths-ignore:``;
    * a workflow that decides relevance does it in a ``changes`` job whose
      step env carries ``WATCHED_PATHS`` -- non-empty, including the
      workflow's own file -- and every other job depends on ``changes``;
    * where ``push`` is path-filtered, its list equals ``WATCHED_PATHS``, so a
      change is gated the same however it arrives;
    * a job that is not a gate and depends on relevance must also run when
      ``changes`` did not succeed (its condition names
      ``needs.changes.result``): otherwise a crashed detector skips it, and a
      skipped job reports a passing check.  Gates read ``changes`` like any
      other dependency (see :func:`check_parsed`).
    """
    failures: list[str] = []
    for name, workflow in sorted(parsed.items()):
        triggers = _triggers(workflow)
        pull_request = triggers.get("pull_request")
        if isinstance(pull_request, dict):
            filtered = [key for key in ("paths", "paths-ignore") if pull_request.get(key)]
            if filtered:
                failures.append(
                    f"{name}: `pull_request` is filtered by {filtered}. A path-filtered "
                    f"workflow reports no check on a non-matching pull request, and a "
                    f"no-op twin is not exclusive. Run on every pull request and decide "
                    f"relevance in a `{CHANGES_JOB}` job (tools/pr_touches_watched_paths.py)."
                )
        jobs = workflow.get("jobs") or {}
        changes = jobs.get(CHANGES_JOB)
        if not isinstance(changes, dict):
            continue
        watched = _watched_paths(changes)
        if not watched:
            failures.append(f"{name}: the `{CHANGES_JOB}` job declares no {WATCHED_PATHS_KEY}.")
            continue
        own = f".github/workflows/{name}"
        if own not in watched:
            failures.append(
                f"{name}: {WATCHED_PATHS_KEY} omits the workflow's own file, so a pull "
                f"request editing only this workflow would skip every job it defines."
            )
        push = triggers.get("push")
        if isinstance(push, dict) and push.get("paths") and list(push["paths"]) != watched:
            failures.append(
                f"{name}: `push.paths` and {WATCHED_PATHS_KEY} differ "
                f"({sorted(set(push['paths']) ^ set(watched))}); the same change would "
                f"be gated differently by how it arrived."
            )
        for job_id, job in jobs.items():
            if job_id == CHANGES_JOB or not isinstance(job, dict):
                continue
            if CHANGES_JOB not in _needs(job):
                failures.append(
                    f"{name}: job {job_id!r} does not depend on `{CHANGES_JOB}`, so it "
                    f"ignores the relevance decision the workflow makes."
                )
                continue
            condition = str(job.get("if", ""))
            if (
                not job_id.endswith(GATE_SUFFIX)
                and not any(job_id in _needs(other or {}) for other in jobs.values())
                and "needs.changes.result" not in condition
            ):
                failures.append(
                    f"{name}: job {job_id!r} reports its own context but its condition "
                    f"does not run it when `{CHANGES_JOB}` failed; a crashed detector "
                    f"would skip it, and a skipped job is a passing check."
                )
    return failures


def audit(workflow_dir: Path = WORKFLOW_DIR) -> tuple[list[str], int]:
    """Check every workflow. Returns (failures, number of files examined)."""
    paths = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
    failures: list[str] = []
    total_jobs = 0
    parsed: dict[str, dict[Any, Any]] = {}
    for path in paths:
        workflow = _load(path)
        parsed[path.name] = workflow
        total_jobs += len(workflow.get("jobs") or {})
        failures.extend(check_parsed(path.name, workflow))
    failures.extend(check_pr_relevance(parsed))

    # Non-vacuity floors (H7).  Proven two ways: `rm .github/workflows/*.yml`
    # left `examined` 0 and the run PASS, and a partial deletion would shrink the
    # job set with no complaint.  Pin both so a real reduction lowers the floor
    # under review rather than passing silently.
    if len(paths) < MIN_WORKFLOWS:
        failures.append(
            f"only {len(paths)} workflow file(s) examined (floor {MIN_WORKFLOWS}) — the "
            f"aggregating-gate audit has nothing, or almost nothing, to check. If a "
            f"workflow was intentionally removed, lower MIN_WORKFLOWS under review."
        )
    if total_jobs < MIN_JOBS_INSPECTED:
        failures.append(
            f"only {total_jobs} job(s) inspected across {len(paths)} workflow(s) (floor "
            f"{MIN_JOBS_INSPECTED}) — too few for the coverage audit to mean anything. If "
            f"jobs were intentionally removed, lower MIN_JOBS_INSPECTED under review."
        )
    return failures, len(paths)


def main() -> int:
    if not WORKFLOW_DIR.is_dir():
        print(f"ERROR: {WORKFLOW_DIR} not found — run from the repository root.")
        return 1

    failures, examined = audit()

    print("INVARIANT-31: aggregating gate coverage")
    print(f"  workflows examined: {examined}")

    if failures:
        print(f"  FAIL — {len(failures)} finding(s):\n")
        for failure in failures:
            print(f"    ::error::{failure}\n")
        return 1

    print("  PASS — every pull-request job is reachable from its workflow's gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
