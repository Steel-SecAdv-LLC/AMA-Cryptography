# Operator action — OSS-Fuzz onboarding PR (item 5, ◆)

Everything repo-side is done and locally validated. The only remaining step is
the upstream pull request to google/oss-fuzz, which requires a GitHub account
that can open a PR there (an external-account action this audit cannot perform).

## What is already validated (this session)

`oss-fuzz/{project.yaml, Dockerfile, build.sh}` exist in this repo and were run
through OSS-Fuzz's own infrastructure locally:

    python3 infra/helper.py build_fuzzers --sanitizer address   ama-cryptography <local-checkout>
    python3 infra/helper.py check_build    --sanitizer address   ama-cryptography
    python3 infra/helper.py build_fuzzers --sanitizer undefined ama-cryptography <local-checkout>
    python3 infra/helper.py check_build    --sanitizer undefined ama-cryptography

Result: all four commands exit 0; all 15 fuzz targets build and pass
`check_build`'s bad-build checks under both AddressSanitizer and
UndefinedBehaviorSanitizer (30 target-checks). Evidence:
`verification/v5-audit/logs/item5-ossfuzz-localvalidate.log`, ledger row `5`.

Note: the local validation used a one-line divergence in a THROWAWAY copy of
the Dockerfile (the in-container `git clone` was replaced with `mkdir`, because
`helper.py build_fuzzers <local path>` bind-mounts the real checkout over
`/src` and because this sandbox's TLS-inspecting egress proxy breaks the
in-container clone). The COMMITTED `oss-fuzz/Dockerfile` keeps the real
`git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git` that
OSS-Fuzz's own infrastructure needs — do NOT ship the mkdir variant.

## The submission (to perform)

1. Fork `github.com/google/oss-fuzz`.
2. Create `projects/ama-cryptography/` containing the three files from this
   repo's `oss-fuzz/` directory, unmodified:
       cp oss-fuzz/project.yaml oss-fuzz/Dockerfile oss-fuzz/build.sh \
          <oss-fuzz-fork>/projects/ama-cryptography/
3. Set `primary_contact` in `project.yaml` to an address the OSS-Fuzz team can
   reach (it currently reads `security@steelsecadv.com`; confirm it is
   monitored — OSS-Fuzz emails bug reports there).
4. Open a PR to `google/oss-fuzz`. The OSS-Fuzz maintainers run the same
   `build_fuzzers` + `check_build` this session already passed; expect their CI
   to go green without further changes.
5. After merge, ClusterFuzz begins continuous fuzzing; grant the
   `auto_ccs` addresses access to the ClusterFuzz dashboard.

This is the single highest-leverage action on the checklist: free, continuous,
multi-engine (libFuzzer/AFL++/Honggfuzz), multi-sanitizer fuzzing forever, with
automatic regression tracking.
