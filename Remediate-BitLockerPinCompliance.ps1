<#
.SYNOPSIS
    Intune Remediations REMEDIATION script - paired with Detect-BitLockerPinCompliance.ps1.

.DESCRIPTION
    Runs only on devices the detection script marked non-compliant. It does the two
    things that can be fixed without a user present, and nudges the one that cannot:

      1. Removes a stray plain Tpm protector sitting next to a TpmPin protector.
         That combination is the silent killer: Windows documents that the TPM-only
         protector "negates the effects of other TPM-based key protectors", so the
         device boots with NO PIN prompt while looking correctly configured.
         This is a real fix and needs no user.

      2. Re-enables and starts the enrollment task so the user is prompted again.
         The dialog disables its own task after a successful PIN, so a device that
         later loses its PIN protector would otherwise never be asked again.

      3. Reports, without pretending to fix, the states that need a human: an
         unencrypted volume, a missing recovery password, suspended protection.
         Remediation cannot invent encryption or a recovery key, and silently
         "succeeding" on those would hide a real risk.

    Self-contained on purpose - Intune Remediations upload a single file, so this
    cannot dot-source the package's shared module.

.NOTES
    Exit 0 = remediation performed (or nothing left for this script to do)
    Exit 1 = could not remediate; needs attention
    Configure with "Run script in 64-bit PowerShell: Yes".
#>
[CmdletBinding()]
# Must match the value the installer used.
param([string] $Organization = 'WK-Hub')

if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
    $p = $null
    try {
        $p = Start-Process -FilePath "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" `
                           -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
                                           '-Organization',"`"$Organization`"") `
                           -Wait -PassThru -NoNewWindow -ErrorAction Stop
    }
    catch { Write-Output "FAILED: could not relaunch 64-bit ($($_.Exception.Message))"; exit 1 }
    if ($null -eq $p) { Write-Output 'FAILED: relaunch produced no process object'; exit 1 }
    exit $p.ExitCode
}

$sysDrive = $env:SystemDrive
$taskName = "$Organization BitLocker PIN Enrollment"
$fveKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$root     = Join-Path $env:ProgramData "$Organization\BitLockerPin"
$actions  = @()
$problems = @()

function Get-Protector {
    param($Volume, [string[]] $Type)
    @($Volume.KeyProtector | Where-Object { $Type -contains [string]$_.KeyProtectorType })
}

function Invoke-WithStartupAuthRelaxed {
    # BitLocker validates the volume's whole protector set on any change, so a device
    # already non-compliant with its own policy cannot be repaired while that policy
    # is in force (0x80310061 FVE_E_POLICY_REQUIRES_STARTUPPIN). Relax, act, restore -
    # always, including on failure.
    param([Parameter(Mandatory)][scriptblock] $Body)
    $saved = @{}
    try {
        foreach ($n in @('UseTPM','UseTPMPIN')) {
            try {
                $saved[$n] = (Get-ItemProperty -LiteralPath $fveKey -Name $n -ErrorAction Stop).$n
                if ($saved[$n] -ne 2) { Set-ItemProperty -LiteralPath $fveKey -Name $n -Value 2 -Type DWord -Force }
            } catch { }
        }
        & $Body
    }
    finally {
        foreach ($n in @($saved.Keys)) {
            if ($saved[$n] -ne 2) {
                try { Set-ItemProperty -LiteralPath $fveKey -Name $n -Value $saved[$n] -Type DWord -Force } catch { }
            }
        }
    }
}

try { $vol = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop }
catch { Write-Output "FAILED: cannot query BitLocker ($($_.Exception.Message))"; exit 1 }

$hasPin      = [bool](Get-Protector -Volume $vol -Type 'TpmPin','TpmPinStartupKey')
$tpmOnly     = @(Get-Protector -Volume $vol -Type 'Tpm','TpmStartupKey')
$hasRecovery = [bool](Get-Protector -Volume $vol -Type 'RecoveryPassword')

# ----------------------------------------------------------------------
# States a script cannot fix. Report them; do not paper over them.
# ----------------------------------------------------------------------
if ($vol.VolumeStatus -in 'FullyDecrypted','DecryptionInProgress') {
    $problems += "volume is $($vol.VolumeStatus) - encryption must be enabled first (the app shows the user a 'contact IT' notice)"
}
if ($vol.VolumeStatus -eq 'EncryptionInProgress') { $problems += 'encryption still in progress - nothing to do yet' }
if (-not $hasRecovery) { $problems += 'NO recovery password protector - do not enforce a PIN until one exists and is escrowed' }
if ($vol.ProtectionStatus -ne 'On' -and $vol.VolumeStatus -ne 'FullyDecrypted') {
    $problems += "protection is $($vol.ProtectionStatus) (suspended) - a PIN would not be enforced"
}

# ----------------------------------------------------------------------
# 1. The real fix: a TPM-only protector cancelling an existing PIN.
# ----------------------------------------------------------------------
if ($hasPin -and $tpmOnly.Count -gt 0) {
    if (-not $hasRecovery) {
        $problems += 'refusing to remove the TPM-only protector without a recovery password'
    }
    else {
        foreach ($pr in $tpmOnly) {
            try {
                Invoke-WithStartupAuthRelaxed {
                    Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $pr.KeyProtectorId -ErrorAction Stop | Out-Null
                }
                $actions += "removed $($pr.KeyProtectorType) protector that was cancelling the PIN prompt"
            }
            catch { $problems += "could not remove $($pr.KeyProtectorType) protector: $($_.Exception.Message)" }
        }
        $after = Get-BitLockerVolume -MountPoint $sysDrive
        if (Get-Protector -Volume $after -Type 'Tpm','TpmStartupKey') {
            $problems += 'a TPM-only protector is still present - this device still does NOT prompt at boot'
        }
    }
}

# ----------------------------------------------------------------------
# 2. No PIN yet: make sure the enrollment task will ask again.
# ----------------------------------------------------------------------
if (-not $hasPin) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $task) {
        $problems += "enrollment task '$taskName' is missing - the Win32 app is not installed or its install failed"
    }
    else {
        if ($task.State -eq 'Disabled') {
            try   { Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
                    $actions += 'the enrollment task was disabled without a PIN in place - re-enabled it' }
            catch { $problems += "could not re-enable the task: $($_.Exception.Message)" }
        }
        # Starting it only shows a dialog when someone is signed in; the task's own
        # logon and screen-unlock triggers catch everyone else. Harmless either way -
        # the dialog exits quietly when there is no console session.
        try   { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $actions += 'started the enrollment task to prompt the user' }
        catch { $actions += "could not start the task now ($($_.Exception.Message)) - its logon/unlock triggers still apply" }

        if (-not (Test-Path (Join-Path $root 'Set-BitLockerPin.ps1'))) {
            $problems += "payload missing from $root - reinstall the Win32 app"
        }
    }
}

# ----------------------------------------------------------------------
# Report. Intune shows this in the "Remediation output" column.
# ----------------------------------------------------------------------
$summary = "device=$env:COMPUTERNAME hasPin=$hasPin tpmOnlyProtectors=$($tpmOnly.Count) recovery=$hasRecovery " +
           "volume=$($vol.VolumeStatus) protection=$($vol.ProtectionStatus)"

if ($problems.Count -gt 0) {
    Write-Output ("NEEDS ATTENTION: " + ($problems -join '; ') +
                  $(if ($actions.Count) { ' | did: ' + ($actions -join '; ') } else { '' }) +
                  " | $summary")
    exit 1
}

if ($actions.Count -eq 0) {
    Write-Output "NO ACTION AVAILABLE: nothing this script can fix; waiting for the user to set a PIN | $summary"
    exit 0
}

Write-Output ("REMEDIATED: " + ($actions -join '; ') + " | $summary")
exit 0
