#!/bin/bash -eu
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# One build integration, not two.  ClusterFuzzLite runs exactly the script an
# OSS-Fuzz submission carries, so the harness list, link flags and corpus
# packaging cannot drift between the nightly fuzzing and the onboarding
# files — tools/check_fuzz_target_registration.py holds oss-fuzz/build.sh to
# the harness set, and this shim inherits that.
exec "$SRC/ama-cryptography/oss-fuzz/build.sh"
