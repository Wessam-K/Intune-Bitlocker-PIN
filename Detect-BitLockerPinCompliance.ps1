<#
.SYNOPSIS
    Intune Remediations DETECTION script - reports whether a startup PIN is really
    in place and really enforced at boot.

.DESCRIPTION
    The Win32 app can only tell you whether the enrollment MECHANISM installed. It
    cannot tell you whether the user ever typed a PIN, because that happens later,
    in a dialog, possibly days after the install. This script answers the question
    the app cannot: does this device actually ask for a PIN at power-on?

    Compliant requires ALL of:
      * a TpmPin (or TpmPinStartupKey) protector exists
      * NO plain Tpm / TpmStartupKey protector exists - Windows documents that the
        TPM-only protector "negates the effects of other TPM-based key protectors",
        so a device holding both boots with no PIN prompt while still appearing to
        have one
      * ProtectionStatus is On - a suspended volume has a clear key on disk and
        never prompts
      * a RecoveryPassword protector exists - a mandatory PIN with no recovery key
        is one forgotten PIN away from unrecoverable data loss, so it is part of
        compliance, not a footnote

    Deliberately self-contained: Intune Remediations upload a single file, so this
    cannot dot-source the package's shared module, and it must work on devices where
    the app was never installed.

    STDOUT is one line and lands in the portal's "Detection output" column, so it
    names the reason rather than just the verdict.

.NOTES
    Exit 0 = compliant, no remediation needed
    Exit 1 = non-compliant, run the remediation
    Configure with "Run script in 64-bit PowerShell: Yes".
#>
[CmdletBinding()]
# Must match the value the installer used.
param([string] $Organization = 'WK-Hub')

# The BitLocker module is 64-bit only. Relaunch rather than fail, and null-guard the
# result: 'exit $p.ExitCode' on a failed launch is 'exit $null' = exit 0 = COMPLIANT,
# which would report the entire fleet green from a script that never ran.
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
    $p = $null
    try {
        $p = Start-Process -FilePath "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" `
                           -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
                                           '-Organization',"`"$Organization`"") `
                           -Wait -PassThru -NoNewWindow -ErrorAction Stop
    }
    catch { Write-Output "UNKNOWN: could not relaunch 64-bit ($($_.Exception.Message))"; exit 1 }
    if ($null -eq $p) { Write-Output 'UNKNOWN: relaunch produced no process object'; exit 1 }
    exit $p.ExitCode
}

$sysDrive = $env:SystemDrive
$regKey   = "HKLM:\SOFTWARE\$Organization\BitLockerPin"
$taskName = "$Organization BitLocker PIN Enrollment"
$logName  = 'Microsoft-Windows-BitLocker/BitLocker Management'

function Get-ProtectorNames {
    param($Volume, [string[]] $Type)
    @($Volume.KeyProtector | Where-Object { $Type -contains [string]$_.KeyProtectorType })
}

try {
    $vol = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
}
catch {
    Write-Output "UNKNOWN: cannot query BitLocker on $sysDrive ($($_.Exception.Message))"
    exit 1
}

$hasPin      = [bool](Get-ProtectorNames -Volume $vol -Type 'TpmPin','TpmPinStartupKey')
$hasTpmOnly  = [bool](Get-ProtectorNames -Volume $vol -Type 'Tpm','TpmStartupKey')
$hasRecovery = [bool](Get-ProtectorNames -Volume $vol -Type 'RecoveryPassword')
$protection  = [string]$vol.ProtectionStatus
$volStatus   = [string]$vol.VolumeStatus
$protectors  = (($vol.KeyProtector.KeyProtectorType | Sort-Object -Unique) -join ',')

# App state, for context in the report. Absent simply means the app has not landed.
$props    = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
$appVer   = if ($props.Version) { $props.Version } else { 'not-installed' }
$pinSetOn = if ($props.PinSetOn) { $props.PinSetOn } elseif ($props.PinAssignedOn) { $props.PinAssignedOn } else { 'never' }

$task      = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$taskState = if ($task) { [string]$task.State } else { 'missing' }

# Escrow evidence. Event 845 = the service stored the key. The three-state logic
# matters because Get-WinEvent THROWS when a filter matches nothing, so a naive
# try/catch cannot tell "never escrowed" from "log unreadable".
$escrowed = 'unknown'
try {
    Get-WinEvent -ListLog $logName -ErrorAction Stop | Out-Null
    $escrowed = 'no'
    if ($hasRecovery) {
        $ids = @(Get-ProtectorNames -Volume $vol -Type 'RecoveryPassword' |
                 ForEach-Object { $_.KeyProtectorId.Trim('{','}') })
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = 845 } -MaxEvents 200 -ErrorAction Stop)
            foreach ($e in $events) {
                foreach ($id in $ids) {
                    if ($e.Message -and $e.Message -match [regex]::Escape($id)) { $escrowed = 'yes'; break }
                }
                if ($escrowed -eq 'yes') { break }
            }
        } catch { }   # log readable but no 845 events: stays 'no'
    }
} catch { }           # log missing/unreadable: stays 'unknown'

# Did the user replace the PIN they were given? ChangePIN reuses the protector GUID,
# so comparing stored and current IDs detects nothing - events 777/789 are the only
# reliable signal. The log rolls at ~1 MB, so 'no' means "no evidence", not "never".
$pinChanged = 'no'
try {
    $filter = @{ LogName = $logName; Id = @(777, 789) }
    if ($pinSetOn -ne 'never') { $filter['StartTime'] = [datetime]::Parse($pinSetOn) }
    if (@(Get-WinEvent -FilterHashtable $filter -MaxEvents 20 -ErrorAction Stop).Count -gt 0) { $pinChanged = 'yes' }
} catch { }

$context = "device=$env:COMPUTERNAME volume=$volStatus protection=$protection protectors=$protectors " +
           "recovery=$(if ($hasRecovery) { 'yes' } else { 'NO' }) escrowed=$escrowed " +
           "pinSetOn=$pinSetOn pinChangedByUser=$pinChanged app=$appVer task=$taskState"

# Reasons, most serious first, so the portal column is readable and actionable.
$reasons = @()
if ($volStatus -in 'FullyDecrypted','DecryptionInProgress') { $reasons += 'volume is not encrypted' }
elseif ($volStatus -eq 'EncryptionInProgress')              { $reasons += 'encryption still in progress' }
if (-not $hasRecovery)        { $reasons += 'no recovery password protector' }
if (-not $hasPin)             { $reasons += 'no startup PIN protector - user has not set a PIN' }
if ($hasPin -and $hasTpmOnly) { $reasons += 'TPM-only protector present alongside the PIN - device does NOT prompt at boot' }
if ($protection -ne 'On')     { $reasons += "protection is $protection" }

if ($reasons.Count -eq 0) {
    Write-Output "COMPLIANT: startup PIN is set and enforced | $context"
    exit 0
}

Write-Output ("NONCOMPLIANT: " + ($reasons -join '; ') + " | " + $context)
exit 1
