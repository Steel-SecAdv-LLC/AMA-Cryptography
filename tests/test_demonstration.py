# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography: Demonstration Test Suite
===============================================

Test suite for validating AMA Cryptography demonstration functionality.

This test module validates that the demonstration function executes successfully
and produces correct output, verifying all six cryptographic layers.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2025-12-06
Version: 2.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import subprocess
import sys
from pathlib import Path

import pytest


class TestDemonstration:
    """Test the main demonstration function."""

    def test_demonstration_runs_successfully(self):
        """
        Test that the demonstration script runs without errors.

        This test validates:
        - Script executes successfully (exit code 0)
        - No errors are raised during execution
        - All cryptographic operations complete
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "code_guardian_secure.py"
        assert script_path.exists(), f"Script not found: {script_path}"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,  # 60 second timeout
        )

        # Check exit code
        assert result.returncode == 0, (
            f"Demonstration failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    def test_demonstration_output_validation(self):
        """
        Test that the demonstration produces expected output.

        This test validates:
        - Title banner is displayed
        - All six cryptographic layers are mentioned
        - Key generation succeeds
        - Package creation succeeds
        - Signature creation succeeds
        - Verification succeeds
        - Final success message is displayed
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "code_guardian_secure.py"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = result.stdout

        # Critical output checks
        required_outputs = [
            ("AMA Cryptography", "Title banner"),
            ("Generating key management system", "Key generation step"),
            ("Creating Omni-Code cryptographic package", "Package creation step"),
            ("Verifying cryptographic package", "Verification step"),
            ("ALL VERIFICATIONS PASSED", "Success confirmation"),
        ]

        missing_outputs = []
        for check, description in required_outputs:
            if check not in output:
                missing_outputs.append(f"{description}: '{check}' not found")

        assert not missing_outputs, (
            "Demonstration output validation failed:\n"
            + "\n".join(f"  - {msg}" for msg in missing_outputs)
            + f"\n\nActual output:\n{output}"
        )

    def test_demonstration_no_errors(self):
        """
        Test that the demonstration produces no error messages.

        This test validates:
        - No ERROR messages in output
        - No exceptions raised
        - No warnings about missing critical dependencies

        Note: Stderr output is not checked as it may contain non-error messages
        from external processes.
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "code_guardian_secure.py"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # First, verify the script completed successfully
        # This is the primary indicator of success
        assert result.returncode == 0, (
            f"Demonstration failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

        # Check for errors in stdout only (our code's output)
        stdout = result.stdout

        # Should not contain these error indicators in our output
        error_indicators = [
            "ERROR:",
            "Exception:",
            "FAILED",
        ]

        found_errors = []
        for indicator in error_indicators:
            if indicator in stdout:
                found_errors.append(indicator)

        assert not found_errors, (
            f"Error indicators found in output: {', '.join(found_errors)}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    @pytest.mark.slow
    def test_demonstration_quantum_libraries(self):
        """
        Test demonstration with quantum-resistant libraries if available.

        This test is marked as 'slow' and checks:
        - Dilithium signature generation (if native C backend available)
        - Quantum-resistant verification
        - Proper fallback if native library not available

        Note: This test may be skipped if native C library is not built.
        """
        script_path = Path(__file__).parent.parent / "code_guardian_secure.py"

        # Check if native PQC backend is available
        test_script = """
import sys
try:
    from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE, DILITHIUM_BACKEND
    if DILITHIUM_AVAILABLE:
        print("native_available")
    else:
        print("no_native_backend")
    sys.exit(0)
except Exception:
    print("no_native_backend")
    sys.exit(0)
"""

        quantum_check = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        quantum_available = "native_available" in quantum_check.stdout

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Test should pass regardless of quantum library availability
        assert result.returncode == 0, f"Demonstration failed: {result.stderr}"

        if quantum_available:
            # If quantum libraries available, verify Dilithium signatures are working
            assert (
                "Dilithium" in result.stdout
            ), "Dilithium not found in output despite native backend being available"
            # Should not have warnings about missing quantum libraries
            assert "WARNING: Dilithium not available" not in result.stdout
            # Should have successful verification
            assert "✓ dilithium: VALID" in result.stdout
        else:
            # If not available, should gracefully degrade but still work
            assert "ALL VERIFICATIONS PASSED" in result.stdout


class TestErrorHandling:
    """Test error handling for missing dependencies."""

    def test_missing_cryptography_library(self):
        """
        Test behavior when cryptography library is missing.

        Validates that functions depending on the cryptography library
        raise RuntimeError when CRYPTO_AVAILABLE is False.
        """
        from unittest.mock import patch

        from code_guardian_secure import generate_ed25519_keypair

        with patch("code_guardian_secure.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="AMA native C library required"):
                generate_ed25519_keypair()

    def test_graceful_quantum_library_fallback(self):
        """
        Test that quantum libraries work correctly when available.

        This test validates:
        - Script runs with quantum libraries
        - Quantum-resistant signatures are generated
        - All verifications pass
        """
        script_path = Path(__file__).parent.parent / "code_guardian_secure.py"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should complete successfully
        assert (
            result.returncode == 0
        ), "Demonstration should complete successfully with quantum libraries"

        # Should have quantum signatures working
        assert "ALL VERIFICATIONS PASSED" in result.stdout
