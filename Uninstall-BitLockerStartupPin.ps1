<#
.SYNOPSIS
    Removes the enrollment mechanism and restores the FVE policy it changed.

.DESCRIPTION
    By default this does NOT remove the startup PIN protector. Uninstalling a
    deployment tool must not weaken a device's encryption posture, and the PIN in
    place may be one the user chose and remembers.

    -RemovePinProtector is the deliberate rollback path. It is genuinely risky:
    the PIN protector must be removed before a TPM-only one can be added back, so
    there is a window where only the recovery password can unlock the volume. It
    therefore refuses unless a recovery password exists, relaxes the FVE policy
    first so the TPM-only add cannot be blocked by our own settings, verifies the
    result, and exits non-zero if the device would land on the recovery screen -
    rather than reporting a clean uninstall over a broken boot.

.NOTES
    Exit 0 = removed
    Exit 1 = the volume may require a recovery key at next boot - investigate
#>
[CmdletBinding()]
param(
    # Must match the value the installer used, or nothing is found to remove.
    [string] $Organization = 'WK-Hub',
    [switch] $RemovePinProtector,

    # Leave the FVE policy values in place (use when another policy legitimately
    # owns them now).
    [switch] $KeepFvePolicy
)

if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        else { $argList += @("-$($kv.Key)", "`"$($kv.Value)`"") }
    }
    # -NoNewWindow so the child's output reaches the Intune log; see the same note
    # in Install-BitLockerStartupPin.ps1. Null-guarded for the same reason:
    # 'exit $null' is exit 0, which would report a successful uninstall that never ran.
    $p = $null
    try {
        $p = Start-Process -FilePath "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" `
                           -ArgumentList $argList -Wait -PassThru -NoNewWindow -ErrorAction Stop
    }
    catch {
        Write-Host "Could not relaunch in 64-bit PowerShell: $($_.Exception.Message)"
        exit 1
    }
    if ($null -eq $p) { Write-Host 'Relaunch produced no process object.'; exit 1 }
    exit $p.ExitCode
}

. (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')

# Every removal below is best-effort (-ErrorAction SilentlyContinue) so that a
# partially-installed device still cleans up. Without an explicit elevation check
# that combination lies: run unelevated, nothing is removed, and the script still
# exits 0 - so Intune records a successful uninstall over a no-op.
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script must run elevated (Intune runs it as SYSTEM). Nothing was removed.'
    exit 1
}

$root     = Join-Path $env:ProgramData "$Organization\BitLockerPin"
$regKey   = "HKLM:\SOFTWARE\$Organization\BitLockerPin"
$fveKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$taskName = 'WK-Hub BitLocker PIN Enrollment'
$sysDrive = $env:SystemDrive
$exitCode = 0

# Prefer the hardened app folder. Falling back to a FIXED name in %TEMP% would be
# a fixed name in C:\Windows\Temp for SYSTEM, which any user can pre-create as a
# hardlink to a file they want SYSTEM to append to; the run-specific suffix removes
# that predictability.
$script:LogFile = if (Test-Path $root) { Join-Path $root 'uninstall.log' }
                  else { Join-Path $env:TEMP ("$Organization-BitLockerPin-uninstall-{0}.log" -f [guid]::NewGuid().ToString('N')) }

Stop-ScheduledTask       -TaskName $taskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Write-PinLog "Removed scheduled task '$taskName' (if present)."

# Release the staged ServiceUI.exe, or the folder removal below leaves it behind.
Get-Process -Name 'ServiceUI' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "$root\*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

# Protector work FIRST, policy restore afterwards. Restoring the tenant's original
# FVE values before the swap can reinstate a UseTPM = 0 that then blocks the very
# TPM-only add this path exists to perform - the swap needs the permissive policy
# that is still in place. Invoke-WithStartupAuthRelaxed covers the case where the
# pre-existing policy was already restrictive.
if ($RemovePinProtector) {
    try {
        $vol     = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
        $pinProt = @(Get-TpmFamilyProtector -Volume $vol -Type 'TpmPin','TpmPinStartupKey')

        if ($pinProt) {
            if (-not (Get-TpmFamilyProtector -Volume $vol -Type 'RecoveryPassword')) {
                throw 'No recovery password protector on the volume - refusing to remove the PIN protector.'
            }

            foreach ($p in $pinProt) {
                Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null
                Write-PinLog "Removed $($p.KeyProtectorType) protector $($p.KeyProtectorId)." 'WARN'
            }
            Invoke-WithStartupAuthRelaxed {
                Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmProtector -ErrorAction Stop | Out-Null
            }
            Write-PinLog 'Added a TPM-only protector.'

            $after = Get-BitLockerVolume -MountPoint $sysDrive
            if (-not (Get-TpmFamilyProtector -Volume $after -Type 'Tpm','TpmStartupKey')) {
                throw 'No TPM protector present after the swap - this device will require the recovery key at next boot.'
            }
            Write-PinLog "Post-swap protectors: $(($after.KeyProtector.KeyProtectorType | Sort-Object -Unique) -join ',')"
        }
        else { Write-PinLog 'No startup PIN protector present - nothing to roll back.' }
    }
    catch {
        Write-PinLog "PIN protector rollback FAILED: $($_.Exception.Message)" 'ERROR'
        $exitCode = 1
    }
}

if (-not $KeepFvePolicy) {
    $backupRaw = (Get-ItemProperty -Path $regKey -Name 'FvePolicyBackup' -ErrorAction SilentlyContinue).FvePolicyBackup
    if ($backupRaw) {
        foreach ($pair in $backupRaw -split ';') {
            if (-not $pair) { continue }
            $name, $value = $pair -split '=', 2
            if ([string]::IsNullOrEmpty($value)) {
                # Absent before we installed - remove it again.
                Remove-ItemProperty -Path $fveKey -Name $name -ErrorAction SilentlyContinue
                Write-PinLog "  FVE\$name removed (was absent before install)."
            }
            else {
                Set-ItemProperty -Path $fveKey -Name $name -Value ([int]$value) -Type DWord -Force -ErrorAction SilentlyContinue
                Write-PinLog "  FVE\$name restored to $value."
            }
        }
        $fveRestored = $true
    }
    else {
        Write-PinLog 'No FVE policy backup found - leaving the policy untouched rather than guessing.' 'WARN'
        $fveRestored = $false
    }
}
else { $fveRestored = $false }

# Keep the payload if the rollback failed: Set-BitLockerPin.ps1 is what self-heals a
# volume left without a TPM-family protector, so deleting it here would remove the
# recovery path at the exact moment the device needs it.
if ($exitCode -ne 0) {
    Write-PinLog 'Rollback failed - leaving the payload and registry state in place so the device can still self-heal.' 'ERROR'
}
else {
    # Only drop the FVE backup once it has actually been applied (or was
    # deliberately kept), otherwise a later uninstall would restore THIS app's
    # values as if they were the tenant's originals.
    if ($fveRestored -or -not $KeepFvePolicy) {
        Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-PinLog 'Keeping the registry key so the FVE backup survives for a later restore.' 'WARN'
    }

    Remove-DirectorySafely -Path $root

    # Only remove the shared organisation folder if it is genuinely empty. The
    # previous unconditional call deleted the whole %ProgramFiles%\<Organization>
    # tree, taking any sibling app with it.
    $parent = Split-Path $root -Parent
    try {
        if ((Test-Path $parent) -and -not @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop).Count) {
            Remove-DirectorySafely -Path $parent
        }
        elseif (Test-Path $parent) {
            Write-PinLog "Leaving '$parent' - it still contains other files."
        }
    } catch { Write-PinLog "Could not inspect '$parent': $($_.Exception.Message)" 'WARN' }
}

Write-PinLog "Uninstall finished with exit code $exitCode."
exit $exitCode
