<#
.SYNOPSIS
    Intune Win32 detection script. Self-contained by design.

.DESCRIPTION
    Detects the INSTALLED MECHANISM, not the PIN.

    Detecting on "a TpmPin protector exists" looks tempting now that the PIN is
    assigned by the installer itself, but it still flaps: the installer returns
    1618 (retry later) on devices that are mid-encryption or suspended, and on
    those devices a protector-based rule reports failed until the retry lands.
    Detect the payload; report real PIN coverage with the Remediations pair
    (Detect-BitLockerPinCompliance.ps1 / Remediate-BitLockerPinCompliance.ps1).

    Writes "Installed" to STDOUT and exits 0 when detected.
#>
# Must match the value the installer used.
$Organization = 'WK-Hub'
$AppVersion   = '3.3.0'

$regKey   = "HKLM:\SOFTWARE\$Organization\BitLockerPin"
$taskName = "$Organization BitLocker PIN Enrollment"

# %ProgramData% is not WOW64-redirected, so this resolves identically whether the
# detection rule runs 32- or 64-bit - correctness must not depend on a portal toggle.
# (It also has no space in it, which the installer requires: ServiceUI strips quotes
# from the command line it forwards.)
$root = Join-Path $env:ProgramData "$Organization\BitLockerPin"

try {
    # Registry reads are redirected the same way, so read the 64-bit view explicitly.
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $key  = $hklm.OpenSubKey("SOFTWARE\$Organization\BitLockerPin")
    if (-not $key) { exit 1 }
    $props = [pscustomobject]@{ Version = $key.GetValue('Version') }
    if (-not $props.Version) { exit 1 }
    if ([version]$props.Version -lt [version]$AppVersion) { exit 1 }

    # The three files the app cannot run without. The optional brand images are
    # deliberately NOT checked: the dialog falls back to a text wordmark when
    # they are absent, so requiring them here would report a perfectly working
    # install as missing and make Intune reinstall it forever.
    foreach ($file in @('Set-BitLockerPin.ps1','BitLockerPin.Common.ps1','ServiceUI.exe')) {
        if (-not (Test-Path (Join-Path $root $file))) { exit 1 }
    }

    # The task is legitimately Disabled once a PIN has been set - existence, not
    # state, is what we check.
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { exit 1 }

    # The self-service reset task and its Start-menu shortcut are deliberately
    # NOT checked. The installer treats their registration as non-fatal - a
    # device without them still enrols a PIN, the user just falls back to the
    # service desk to reset it. Detecting on them would turn that soft failure
    # into a hard one: detection would report not-installed, Intune would
    # reinstall on every cycle, and the device would never settle.

    Write-Output 'Installed'
    exit 0
}
catch { exit 1 }
