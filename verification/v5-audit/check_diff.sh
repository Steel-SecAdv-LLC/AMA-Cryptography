#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Phase 0.1: PR range diff must be 1063 files / 82900 insertions / 7481 deletions (git ground truth).
set -u
line=$(git diff --stat 2dcef5c..32c3e0d | tail -1)
echo "$line"
echo "$line" | grep -q "1063 files changed, 82900 insertions(+), 7481 deletions(-)"
