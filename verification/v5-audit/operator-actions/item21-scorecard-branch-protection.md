# Operator action — remote Scorecard + branch-protection audit (item 21, ◆)

Repo-side analysis is complete (`logs/item21-scorecard-analysis.md`): the local
Scorecard run's low scores are all scanner artifacts or required exceptions,
with no fixable repo-side defect. The remaining two pieces need GitHub API
access and org-admin rights that this session does not have.

## 1. Authoritative remote Scorecard run (needs a GitHub token)

    export GITHUB_AUTH_TOKEN=<a PAT with public_repo / repo:read>
    scorecard --repo=github.com/Steel-SecAdv-LLC/AMA-Cryptography --show-details

The remote run adds the API-only checks the local run cannot compute —
Branch-Protection, Code-Review, Maintained, CI-Tests, Contributors, and the
authoritative Token-Permissions/Pinned-Dependencies with per-finding details.
Compare against the local analysis; the file-based scores should match.

Optional but recommended (this is the ◆ "implement everything repo-side"
lever): add `.github/workflows/scorecard.yml` (the standard
`ossf/scorecard-action`) on a weekly schedule + push to `main`, uploading SARIF
to the code-scanning dashboard and publishing the Scorecard badge. It must be
built to pass this repo's own workflow gates (INVARIANT-25 workflow-command
checker, SHA-pinned actions, a top-level `permissions:` block with
`security-events: write` on the upload step only). Not added in this audit to
avoid landing a workflow that has not been through the repo's CI.

## 2. Branch-protection audit (needs org-admin on the repo)

Confirm, under Settings → Branches → `main` (and any release branch):
  - Require a pull request before merging, with >= 1 approving review.
  - Require status checks to pass: at minimum the `Static Analysis Gate`,
    `CI` strict gate, and the CodeQL analysis, before merge.
  - Require branches to be up to date before merging.
  - Require signed commits (the project signs release tags; extend to commits).
  - Dismiss stale approvals on new commits.
  - Restrict force-pushes and deletions on `main`.
  - Require the `release` environment's reviewers (PR #394 body, prerequisite 5)
    for the `github-release` job — a one-time Settings → Environments action.

These are the "public trust signals reviewers check first" the checklist names;
none can be set without repository-admin access.
