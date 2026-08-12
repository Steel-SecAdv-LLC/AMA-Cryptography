# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point: python -m ama_cryptography"""

import sys

from ama_cryptography.legacy_compat import main

if __name__ == "__main__":
    # main() returns the demonstration's verdict as an exit code: a real
    # verification failure must exit non-zero, not print "FAILED" and exit 0.
    sys.exit(main())
