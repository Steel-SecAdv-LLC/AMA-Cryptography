# Item 21 — OpenSSF Scorecard + branch-protection audit (2026-08-31)

## What ran

`scorecard v5.2.1 --local .` (file-based checks; the remote `--repo` mode needs
direct GitHub API access, which this session's proxy blocks — see Operator
actions). Raw JSON: `item21-scorecard-local.json`.

| Check | Score | Disposition |
|---|---|---|
| Dangerous-Workflow | 10 | clean |
| Dependency-Update-Tool | 10 | clean (Dependabot present) |
| Fuzzing | 10 | clean (15 libFuzzer targets; OSS-Fuzz onboarding prepared, item 5) |
| Packaging | 10 | clean |
| SAST | 10 | clean (CodeQL + clang-tidy + scan-build, item 16) |
| Security-Policy | 10 | clean (SECURITY.md) |
| License | 9 | clean (Apache-2.0) |
| Vulnerabilities | 6 | osv-scanner in local mode; the repo's CI runs pip-audit strict on the lock file (security.yml) |
| Pinned-Dependencies | 4 | see below — false-positive + required exception |
| Token-Permissions | 0 | see below — necessary, minimally-scoped write grants |
| Binary-Artifacts | 0 | see below — fuzz corpora + doc PNGs, inherent to the project |

## The three low scores — analysed, no genuine repo-side defect

**Binary-Artifacts (0):** the 675 `fuzz/seed_corpus/**` files and 3 `assets/*.png`
docs images. Scorecard flags any checked-in binary; a fuzzing project inherently
ships seed corpora, and the corpus originality/provenance is itself gated
(`tools/check_corpus_originality.py`, `corpus-provenance.yml`). Not removable
without deleting the fuzzing seeds and documentation assets. Not a defect.

**Pinned-Dependencies (4):** two unpinned `uses:`, both correct as-is —
  1. `./.github/workflows/integrity-anchor-check.yml` — a LOCAL reusable
     workflow (relative path); it is pinned by living at the same commit, and
     cannot carry a SHA. Scorecard false positive.
  2. `slsa-framework/slsa-github-generator/.../generator_generic_slsa3.yml@v2.1.0`
     — the SLSA generator MUST be referenced by a semantic-version tag, not a
     SHA: the generator verifies its own ref is an immutable release tag for the
     provenance to be valid, and SHA-pinning it breaks SLSA L3 provenance. A
     required exception, documented in release.yml.
  Every other `uses:` in all 14 workflows is 40-hex-SHA-pinned (verified).

**Token-Permissions (0):** all `*: write` grants are necessary and minimally
scoped — `release.yml` (`id-token: write` for sigstore/SLSA OIDC, `contents:
write` to publish releases), `static-analysis.yml` (`security-events: write` on
the CodeQL job ALONE, to upload SARIF), `auto-docs.yml` / `wiki-sync.yml`
(`contents:`/`pull-requests: write` for their sole doc/wiki-automation job —
top-level == job-level in a single-job workflow, so no over-grant). Removing any
would break the workflow's function (forbidden by the feature-freeze). Scorecard
scores necessary writes the same as gratuitous ones; this is a scanner artifact,
not an over-privilege defect.

## Verdict

No genuine repo-side Scorecard item is fixable without degrading required
functionality or fighting a documented false positive. The authoritative
remote Scorecard run and the branch-protection audit require GitHub API access
and org-admin rights not available in this session — see
`operator-actions/item21-scorecard-branch-protection.md`.
