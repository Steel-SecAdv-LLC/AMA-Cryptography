# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install a Chocolatey package with retries that key on the OUTCOME, not on
# Chocolatey's exit code.
#
# WHY THIS EXISTS
# ---------------
# Chocolatey v2 exits 0 when it installs nothing.  On 2026-08-21 the community
# feed returned 503 and every Windows lane in both workflows went red on
# PR #394:
#
#     Failed to fetch results from V2 feed at
#       'https://community.chocolatey.org/api/v2/Packages(Id='softhsm.install'...)'
#       : Response status code does not indicate success: 503 (Service Unavailable).
#     Unable to find package 'softhsm.install'.
#     Chocolatey installed 0/0 packages.
#
# `$LASTEXITCODE` was 0 for that run.  The four retry loops in the workflows
# all read
#
#     choco install <pkg> ...
#     if ($LASTEXITCODE -eq 0) { Write-Host "Successfully installed"; break }
#
# so `Attempt 1/5` "succeeded", the loop broke, and the step failed one line
# later at its post-condition check with no retry ever attempted.  A five-way
# retry that cannot see the failure it exists for is not a retry.
#
# Note the direction of the mistake: `.github/scripts/apt-install.sh` says it
# was modelled on "the pattern this repository already uses for the Windows
# Chocolatey install".  The apt script checks real failure; the Chocolatey
# pattern it cited trusts a lying exit code.  The model was the broken one.
#
# WHAT COUNTS AS SUCCESS
# ----------------------
# All three must hold, and each is checked on every attempt:
#
#   1. Chocolatey exited 0.
#   2. Chocolatey did not report installing 0 packages.  This is the 503 case
#      above and it is the whole reason this script exists.
#   3. -RequirePath, when given, exists.  A package can install "successfully"
#      to somewhere the caller cannot use (the Disig SoftHSM2 MSI parents its
#      directory to ROOTDRIVE, which on GitHub's Windows runners is D:, not
#      C:), and a partial or misplaced install should retry rather than fail
#      the job at a later, more confusing step.
#
# Nothing here is `|| true`.  A package that genuinely does not exist, or a
# feed that is down for the whole backoff window, still fails the job — this
# converts a silent false success into an honest failure, never the reverse.
#
# Usage:
#   .github/scripts/choco-install.ps1 -Package cmake `
#       -InstallArgs 'ADD_CMAKE_TO_PATH=System'
#   .github/scripts/choco-install.ps1 -Package softhsm.install `
#       -InstallArgs 'INSTALLDIR=C:\SoftHSM2' `
#       -RequirePath 'C:\SoftHSM2\lib\softhsm2-x64.dll'

[CmdletBinding()]
param(
    # Chocolatey package id, e.g. 'cmake'.
    [Parameter(Mandatory = $true)]
    [string] $Package,

    # Passed through as --install-arguments.  Empty means "no MSI properties".
    [string] $InstallArgs = '',

    # A path that must exist for the install to count.  Empty disables the
    # check, for packages whose payload location the caller does not pin.
    [string] $RequirePath = '',

    [int] $MaxAttempts = 5,

    # Multiplied by the attempt number, so 15 gives 15s, 30s, 45s, 60s.
    # Tests pass 0.
    [int] $BackoffSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Fail with a sentence rather than a symptom when Chocolatey itself is
# absent.  Without this the loop still fails closed, but for the wrong reason:
# `& choco` throws CommandNotFoundException, Set-StrictMode then makes every
# read of the unset $LASTEXITCODE a terminating error that aborts each branch
# statement in turn, and the diagnostic reads "no attempt was made" — which is
# false, an attempt was made and could not be launched.  Observed on
# windows-latest, where this script's own tests shim `choco` with a POSIX
# shell script the runner cannot execute.
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Error "choco is not on PATH; Chocolatey is not installed on this runner."
    exit 1
}

$chocoArgs = @($Package, '-y', '--no-progress')
if ($InstallArgs -ne '') {
    $chocoArgs += @('--install-arguments', $InstallArgs)
}

$lastReason = 'no attempt was made'

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Host "Attempt ${attempt}/${MaxAttempts}: choco install $Package..."

    # Defined before the call so Set-StrictMode cannot turn a read of an
    # unset $LASTEXITCODE into a terminating error that skips every branch
    # below and leaves $lastReason at its placeholder.
    $global:LASTEXITCODE = 0
    $output = (& choco install @chocoArgs 2>&1 | Out-String)
    $code = $LASTEXITCODE
    Write-Host $output

    # (2) The lying-success case.  Matched on Chocolatey's own summary line
    # rather than on the 503, so any cause of "resolved nothing" is caught.
    $installedNothing = $output -match 'installed\s+0/0\s+packages'

    if ($code -ne 0) {
        $lastReason = "choco exited $code"
    }
    elseif ($installedNothing) {
        $lastReason = 'choco exited 0 but installed 0/0 packages (feed outage or unresolvable package)'
    }
    elseif ($RequirePath -ne '' -and -not (Test-Path -LiteralPath $RequirePath)) {
        $lastReason = "choco reported success but $RequirePath does not exist"
    }
    else {
        Write-Host "Successfully installed $Package"
        exit 0
    }

    Write-Host "Install attempt ${attempt} failed: ${lastReason}"
    if ($attempt -lt $MaxAttempts -and $BackoffSeconds -gt 0) {
        $delay = $attempt * $BackoffSeconds
        Write-Host "Waiting ${delay}s before retry..."
        Start-Sleep -Seconds $delay
    }
}

Write-Error "All ${MaxAttempts} attempts to install ${Package} via Chocolatey failed. Last reason: ${lastReason}"
exit 1
