# OSS-Fuzz Onboarding Guide

## What is OSS-Fuzz?

[OSS-Fuzz](https://github.com/google/oss-fuzz) is Google's continuous fuzzing infrastructure for open-source software. It runs fuzzing engines (libFuzzer, AFL++, Honggfuzz) with sanitizers (ASan, MSan, UBSan) against your code 24/7, automatically reporting crashes, memory errors, and undefined behavior.

AMA Cryptography already has 17 libFuzzer fuzz targets running in CI. Onboarding to OSS-Fuzz provides:

- **Continuous 24/7 fuzzing** with massive compute resources
- **Multiple fuzzing engines** (libFuzzer, AFL++, Honggfuzz) for coverage diversity
- **Multiple sanitizers** (AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer)
- **Automatic regression testing** — previously found bugs are continuously re-tested
- **ClusterFuzz dashboard** — web UI for monitoring coverage and findings
- **Automatic triage** — deduplication, bisection, and severity assessment

## Configuration Files

The `oss-fuzz/` directory contains three files required by OSS-Fuzz:

### `project.yaml`

Project metadata used by the OSS-Fuzz infrastructure:

- **homepage**: Project URL for identification
- **language**: `c` — determines the base build environment
- **primary_contact**: Email for security bug notifications
- **fuzzing_engines**: libFuzzer, AFL, Honggfuzz
- **sanitizers**: address, memory, undefined
- **architectures**: x86_64

### `Dockerfile`

Defines the build environment. Based on `gcr.io/oss-fuzz-base/base-builder`, it installs build dependencies and clones the repository.

### `build.sh`

Executed inside the Docker container to compile all fuzz targets. It:

1. Builds the AMA static library with CMake using OSS-Fuzz-provided compiler flags
2. Compiles each fuzz target against `$LIB_FUZZING_ENGINE`
3. Copies seed corpora and dictionaries to `$OUT/`

## Testing the Build

The build is exercised by CI on every push and pull request: the
`oss-fuzz-build` job in `.github/workflows/fuzzing.yml` runs
`tools/test_oss_fuzz_build.sh`, which is also the command to run locally
before submitting the PR to google/oss-fuzz:

### Quick Test

```bash
./tools/test_oss_fuzz_build.sh            # needs Docker; ~10 minutes
OSS_FUZZ_REF=<commit> ./tools/test_oss_fuzz_build.sh   # a different infra commit
```

This script:
1. Fetches google/oss-fuzz at a pinned commit (`OSS_FUZZ_REF`) into
   `$RUNNER_TEMP/oss-fuzz` or `/tmp/oss-fuzz`, unless a checkout is given
2. Copies the configuration files into `projects/ama-cryptography/`
3. Runs `build_fuzzers` with **this checkout** mounted over the Dockerfile's
   clone (the trailing source-path argument to `infra/helper.py`), so the tree that
   is built is the one you are standing in, not the default branch
4. Runs `check_build`, OSS-Fuzz's bad-build check: every fuzzer must start,
   be linked against the requested engine and sanitizer, and run its seed
   corpus

`oss-fuzz/build.sh` writes its intermediates under `$WORK`, so the mounted
checkout is left untouched.

### Continuous fuzzing before onboarding

`.github/workflows/clusterfuzzlite.yml` runs the same build integration on
OSS-Fuzz's infrastructure inside GitHub Actions
([ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)): nightly
batch fuzzing under ASan, UBSan and MSan, with the corpus kept between runs
as workflow artifacts, a weekly prune and a weekly coverage report.
`.clusterfuzzlite/build.sh` execs `oss-fuzz/build.sh`, so there is one build
integration, not two. The workflow has no pull-request trigger, and GitHub
refuses a `workflow_dispatch` of a workflow file that is not yet on the
default branch, so its first run happens only after the workflow lands on
`main`; the per-push `oss-fuzz-build` job in `fuzzing.yml` is what checks
the build integration before that.

### Manual Test

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git /tmp/oss-fuzz

# Copy project files
mkdir -p /tmp/oss-fuzz/projects/ama-cryptography
cp oss-fuzz/project.yaml /tmp/oss-fuzz/projects/ama-cryptography/
cp oss-fuzz/Dockerfile /tmp/oss-fuzz/projects/ama-cryptography/
cp oss-fuzz/build.sh /tmp/oss-fuzz/projects/ama-cryptography/

# Test the build of THIS checkout (the trailing path is mounted over the clone)
cd /tmp/oss-fuzz
python3 infra/helper.py build_fuzzers ama-cryptography <repo>
python3 infra/helper.py check_build ama-cryptography

# Run a fuzzer locally (optional)
python3 infra/helper.py run_fuzzer ama-cryptography fuzz_sha3 -- -max_total_time=60
```

## Submitting the PR to google/oss-fuzz

1. **Fork** [google/oss-fuzz](https://github.com/google/oss-fuzz) on GitHub

2. **Create the project directory**:
   ```bash
   mkdir -p projects/ama-cryptography
   cp <repo>/oss-fuzz/project.yaml projects/ama-cryptography/
   cp <repo>/oss-fuzz/Dockerfile projects/ama-cryptography/
   cp <repo>/oss-fuzz/build.sh projects/ama-cryptography/
   ```

3. **Test locally** (see above) to ensure the build passes

4. **Submit a PR** to google/oss-fuzz with:
   - Title: "Add ama-cryptography project"
   - Description: Brief project description, link to repository, mention the 17 C fuzz targets

5. **Wait for review** — Google's OSS-Fuzz team will review and merge

## Monitoring Results

Once onboarded:

- **Dashboard**: https://oss-fuzz.com — view coverage, crash reports, and build status
- **Bug reports**: Filed automatically to the project's issue tracker (configurable)
- **ClusterFuzz**: Provides detailed crash analysis, bisection, and minimized test cases

## Adding New Fuzz Targets

When adding a new fuzz target:

1. Create `fuzz/fuzz_<name>.c` with `LLVMFuzzerTestOneInput` entry point
2. Add it to `fuzz/CMakeLists.txt`
3. Add seed corpus files to `fuzz/seed_corpus/fuzz_<name>/`
4. Add a dictionary to `fuzz/dictionaries/fuzz_<name>.dict` (if applicable)
5. Add the target name to the `FUZZ_TARGETS` array in `oss-fuzz/build.sh`
6. Test locally with `./tools/test_oss_fuzz_build.sh`

## Fuzz Target Requirements

OSS-Fuzz requires:

- **Entry point**: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` — must be present
- **No hardcoded paths**: Use only relative paths or `$SRC`/`$OUT` environment variables
- **No environment dependencies**: Don't rely on specific env vars or system state
- **Return 0**: The entry point must return 0 (non-zero causes the fuzzer to abort)
- **No memory leaks**: ASan will flag any leaks — ensure all allocations are freed
