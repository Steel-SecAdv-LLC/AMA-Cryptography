# AMA Cryptography — Architectural Invariants

> **Policy document.** Every PR that touches `ama_cryptography/`, `.github/workflows/`,
> or `tests/` **must** satisfy all four invariants below.
> Reviewers: reject any PR that violates them.

---

## INVARIANT-1 — Zero External Crypto Dependencies

AMA Cryptography owns all cryptographic primitives natively.
**Do NOT introduce, retain, or fall back to any external library** — including
`libsodium`, `pynacl`, `hmac` (stdlib), or any third-party cryptographic package.

If a fix cannot be implemented using AMA's own C library and Python bindings,
**stop and report** — do not work around it with an external dependency.

## INVARIANT-2 — Fail-Closed CI

Security-critical CI steps (pip-audit, bandit, KAT tests when oqs is present,
secret scanning) **must not** use `continue-on-error: true`.
Failures in these steps **must** block the pipeline.

## INVARIANT-3 — Observable Failure States

- No bare `except …: pass` that swallows security-relevant errors.
- No bare `return` that silently skips a test — use `pytest.skip(reason=…)`.
- No `2>/dev/null` or other stderr suppression in workflow scripts.
- Mock assertions must verify **call signatures**, not just call occurrence.

## INVARIANT-4 — Pinned Action References

All third-party GitHub Actions used in security workflows **must** be pinned
to a full commit SHA, not a mutable tag (`@main`, `@v1`, etc.).

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-03-13_
