<#
.SYNOPSIS
    Intune Win32 app - prompts the signed-in user to set a BitLocker startup PIN.

.DESCRIPTION
    Runs as SYSTEM and does everything that needs elevation but no UI:

      1. Relaunch 64-bit (the BitLocker module does not exist in WOW64).
      2. TPM readiness.
      3. FVE policy values that permit a TPMandPIN protector, backed up first so
         uninstall can restore them.
      4. Ensure C: is encrypted, has a recovery password, and that the recovery
         password is escrowed to Entra ID - BEFORE any protector is touched.
      5. Stage the dialog, ServiceUI.exe and any brand images that are present.
      6. Register a scheduled task that runs the dialog in the USER's session.
      7. Register the self-service reset: a trigger-less task the user may start,
         its Start-menu shortcut, and the event source its audit events use.
      8. Write the detection marker.

    It deliberately does not prompt by itself: session 0 has no interactive
    desktop, which is why 'manage-bde -changepin' silently fails when a Win32 app
    calls it directly. ServiceUI.exe hooks explorer.exe to borrow that session's
    desktop while the process stays SYSTEM - which is required, because standard
    users are not administrators on their own devices and adding a key protector
    needs admin rights.

    The PIN itself is chosen by the user in Set-BitLockerPin.ps1.
    -AssignDerivedPin flips to the unattended scheme (PIN derived from the device
    name) and is off by default.

.NOTES
    Exit 0    = success
    Exit 1618 = not ready, retry later (encryption running, protection suspended,
                escrow unconfirmed)
    Exit 1    = hard blocker (no TPM, missing payload, verification failed)
#>
[CmdletBinding()]
param(
    # Vendor namespace: the registry key, the %ProgramData% folder, the scheduled
    # task name, the task author and the wordmark shown when no logo image is
    # supplied all hang off this. It must contain no whitespace - ServiceUI strips
    # quotes from the command line it forwards, so a name with a space would arrive
    # split, and the guard further down refuses to register the task in that case.
    #
    # Intune passes it here and this script forwards it to the dialog, but the
    # detection and remediation scripts are uploaded to Intune on their own and
    # take no arguments - so their defaults have to be edited to match. Change it
    # here, in Set-BitLockerPin.ps1, Detect-*.ps1, Remediate-*.ps1 and
    # Uninstall-*.ps1 together; Test-BitLockerPinApp.ps1 asserts they agree.
    [string] $Organization = 'WK-Hub',

    [ValidateRange(6,20)]
    [int]    $MinimumPin = 6,

    # Detect-BitLockerStartupPin.ps1 carries the same constant and compares it
    # against the Version written below, so the two must move together or every
    # device reports "not installed" forever. 3.3.0 added the self-service reset.
    [string] $AppVersion = '3.3.0',

    # SHA256 of the x64 ServiceUI.exe you supply (see README, "Binaries you must
    # supply yourself"). The default is the MDT 8456 build; if you take the
    # binary from a different MDT release, put ITS hash here rather than
    # loosening the check - this file becomes the SYSTEM entry point of a
    # scheduled task, so it stays pinned.
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string] $ServiceUiSha256 = '1BE85A64AAD2C3CAA0DC28705B49A1548E85157F4D2D522C20FEC4B4570A623F',

    # Unattended mode: derive the PIN from the device name instead of prompting.
    # Off by default - the user picks their own PIN.
    [switch] $AssignDerivedPin,
    [string] $PinPrefix          = '111',
    [ValidateRange(1,19)]
    [int]    $DeviceNumberLength = 4,
    [switch] $AllowHashFallback,

    # Start encryption when the drive is fully decrypted. Leave off when an Intune
    # disk-encryption policy owns that job.
    [switch] $EnableEncryptionIfDecrypted,

    # Skip the Entra escrow requirement. Only for lab devices that are not joined.
    [switch] $SkipEscrowCheck,

    # Log what would happen; touch no protector and no policy value.
    [switch] $DryRun
)

# The Intune Management Extension launches install commands 32-bit; the BitLocker
# module only loads in 64-bit PowerShell.
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        else { $argList += @("-$($kv.Key)", "`"$($kv.Value)`"") }
    }
    # -NoNewWindow, not -WindowStyle Hidden: the child must inherit this console so
    # its output still reaches the Intune Management Extension log. With a hidden
    # window Intune records only the exit code, which makes a failed install
    # impossible to diagnose from the service side.
    $p = $null
    try {
        $p = Start-Process -FilePath "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" `
                           -ArgumentList $argList -Wait -PassThru -NoNewWindow -ErrorAction Stop
    }
    catch {
        Write-Host "Could not relaunch in 64-bit PowerShell: $($_.Exception.Message)"
        exit 1
    }
    # $p is $null if the launch silently failed. 'exit $p.ExitCode' would then be
    # 'exit $null' - which is exit 0, i.e. Intune records a successful install that
    # never ran.
    if ($null -eq $p) { Write-Host 'Relaunch produced no process object.'; exit 1 }
    exit $p.ExitCode
}

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')

# Intune always runs this as SYSTEM. Checked explicitly so a hand-run in a normal
# console fails with one clear line instead of an access-denied stack trace from
# whichever privileged call happens to come first.
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script must run elevated (Intune runs it as SYSTEM). Re-run from an elevated prompt or via the Intune app.'
    exit 1
}

# %ProgramData%, NOT %ProgramFiles%, and the reason is not taste: ServiceUI.exe
# strips double quotes from the command line it forwards. With the payload under
# "C:\Program Files\..." the child receives '-File C:\Program' plus stray arguments,
# fails to find the script, and exits 0xFFFD0000 - which looks like a ServiceUI hook
# failure and is not one. %ProgramData% has no space in it.
# The security trade-off (%ProgramData% is user-writable, %ProgramFiles% is not) is
# handled by Assert-SafeDirectory refusing any pre-existing folder that a user owns,
# and by Protect-Directory stripping inherited access immediately after staging.
$root     = Join-Path $env:ProgramData "$Organization\BitLockerPin"
$regKey   = "HKLM:\SOFTWARE\$Organization\BitLockerPin"
$fveKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$taskName = "$Organization BitLocker PIN Enrollment"
$sysDrive = $env:SystemDrive

# The self-service task. Separate from the enrolment task on purpose: that one is
# ACL'd so no ordinary user can start it, and this one must be startable by
# exactly the people it is for. Keeping them apart means widening the ACL here
# cannot widen it there.
$resetTaskName = "$Organization BitLocker PIN Reset"
$shortcutPath  = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Reset BitLocker PIN.lnk'
$eventSource   = "$Organization-BitLockerPin"

# Files the app genuinely cannot run without. ServiceUI.exe is Microsoft's and is
# NOT redistributed in this package - the operator drops their own copy in beside
# these scripts before building the .intunewin (README, "Binaries you must supply
# yourself").
$payload = @(
    'Set-BitLockerPin.ps1'
    'BitLockerPin.Common.ps1'
    'ServiceUI.exe'
)

# Optional branding, staged only when present. The dialog falls back to a text
# wordmark on a solid colour when a file is absent, so a buyer who never supplies
# artwork still gets a working, coherent window. Detection deliberately does not
# check for these: a missing logo is not a failed install.
$brandingPayload = @(
    'brand-background.png'
    'brand-logo-on-dark.png'
    'brand-logo-square.png'
)

# Bootstrap log FIRST. Anything that throws before a log path exists is invisible:
# the process just exits 1 with an empty install.log and no clue why. That cost a
# debugging cycle, so the log exists before the first thing that can fail.
#
# The name carries a GUID deliberately. This runs as SYSTEM, where $env:TEMP is
# C:\Windows\Temp - world-writable. A predictable filename there is a local
# elevation primitive: a standard user pre-creates it as a symlink/hardlink to a
# protected path, and the SYSTEM process then writes through it. An unguessable
# name removes the pre-creation window. Same pattern as the uninstall script.
$script:LogFile = Join-Path $env:TEMP ("$Organization-BitLockerPin-install-{0}.log" -f [guid]::NewGuid().ToString('N').Substring(0,12))

# %ProgramFiles% is not user-writable, unlike %ProgramData%; validate anyway. Inside
# a try/catch because Assert-SafeDirectory throws on an unexpected owner or a reparse
# point, and an unhandled throw out here would bypass all the reporting below.
try {
    Assert-SafeDirectory -Path (Split-Path $root -Parent)
    Assert-SafeDirectory -Path $root
}
catch {
    Write-PinLog "Cannot use the payload directory: $($_.Exception.Message)" 'ERROR'
    foreach ($p in @((Split-Path $root -Parent), $root)) {
        $owner = try { (Get-Acl -LiteralPath $p).Owner } catch { "unreadable ($($_.Exception.Message))" }
        Write-PinLog "  '$p' exists=$(Test-Path $p) owner=$owner" 'ERROR'
    }
    exit 1
}

# Now that the directory is known good, log into it.
$script:LogFile = Join-Path $root 'install.log'

function Get-Volume0 { Get-BitLockerVolume -MountPoint $sysDrive }

Write-PinLog "=== Install v$AppVersion started as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)$(if ($DryRun) { ' (DRY RUN)' }) ==="
Write-PinLog "Mode: $(if ($AssignDerivedPin) { 'unattended, derived PIN' } else { 'interactive, user chooses the PIN' })"

try {
    # ------------------------------------------------------------------
    # 1. Payload check first - a missing file should fail before we touch policy
    # ------------------------------------------------------------------
    foreach ($file in $payload) {
        if (Test-Path (Join-Path $PSScriptRoot $file)) { continue }
        if ($file -eq 'ServiceUI.exe') {
            # Named separately from the generic message because this one is not a
            # broken build - it is the one file the buyer has to fetch, and being
            # told exactly that beats "missing payload file" in an Intune log.
            throw 'ServiceUI.exe is not in the package. It is a Microsoft binary that is not redistributed here: take the x64 ServiceUI.exe from the MDT installation, copy it next to these scripts, and pass its SHA256 as -ServiceUiSha256 if it is not the pinned MDT 8456 build. See the README section "Binaries you must supply yourself".'
        }
        throw "Missing payload file: $file"
    }

    # Branding is optional; stage whatever artwork is actually there.
    $staged = @($payload) + @($brandingPayload | Where-Object { Test-Path (Join-Path $PSScriptRoot $_) })
    $missingBranding = @($brandingPayload | Where-Object { -not (Test-Path (Join-Path $PSScriptRoot $_)) })
    if ($missingBranding.Count -gt 0) {
        Write-PinLog "No brand image for: $($missingBranding -join ', '). The dialog will draw a '$Organization' wordmark on a solid colour instead."
    }

    $suiSrc = Join-Path $PSScriptRoot 'ServiceUI.exe'
    $sig    = Get-AuthenticodeSignature $suiSrc
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw "ServiceUI.exe signature is not a valid Microsoft signature (status: $($sig.Status))."
    }
    $suiHash = (Get-FileHash $suiSrc -Algorithm SHA256).Hash
    if ($suiHash -ne $ServiceUiSha256) {
        throw "ServiceUI.exe hash mismatch. Expected $ServiceUiSha256, got $suiHash. If you are using a different MDT build, pass -ServiceUiSha256 $suiHash after satisfying yourself the binary is genuine."
    }
    Write-PinLog 'ServiceUI.exe signature and hash verified.'

    if ($AssignDerivedPin) {
        $derived = Get-DerivedStartupPin -Prefix $PinPrefix -NumberLength $DeviceNumberLength `
                                         -AllowHashFallback:$AllowHashFallback
        Write-PinLog "PIN derived from $($derived.Source): $($derived.Pin.Length) digits."
        if ($derived.Pin.Length -lt $MinimumPin) {
            throw "Derived PIN is $($derived.Pin.Length) digits but MinimumPin is $MinimumPin - the add would be rejected."
        }
    }

    # ------------------------------------------------------------------
    # 2. TPM
    # ------------------------------------------------------------------
    $tpm = Get-Tpm
    if (-not $tpm.TpmPresent) { Write-PinLog 'No TPM present. Cannot use TPM+PIN.' 'ERROR'; exit 1 }
    if (-not $tpm.TpmReady) {
        # Provisioning is often still in progress on a freshly imaged device, so
        # this is temporary. 1618 (retry) rather than 1 (permanent failure), or the
        # app would be stuck failed on devices that become ready minutes later.
        Write-PinLog 'TPM present but not ready (provisioning pending?). Asking Intune to retry.' 'WARN'
        exit 1618
    }
    Write-PinLog "TPM ok. Ready=$($tpm.TpmReady) Enabled=$($tpm.TpmEnabled)"

    # ------------------------------------------------------------------
    # 3. FVE policy, with a backup so uninstall can put it back
    # ------------------------------------------------------------------
    $plan = Get-FvePolicyPlan -MinimumPin $MinimumPin

    # Do not weaken settings that are already stricter than ours. Blindly stamping
    # the plan would, for example, drop a tenant's MinimumPIN of 8 back to 6.
    $existingFve = Get-ItemProperty -LiteralPath $fveKey -ErrorAction SilentlyContinue
    if ($existingFve) {
        if ($null -ne $existingFve.MinimumPIN -and
            [int]$existingFve.MinimumPIN -gt [int]$plan['MinimumPIN'] -and
            [int]$existingFve.MinimumPIN -le 20) {
            Write-PinLog "Keeping the stricter existing FVE MinimumPIN ($($existingFve.MinimumPIN)) rather than $($plan['MinimumPIN'])."
            $plan['MinimumPIN'] = [int]$existingFve.MinimumPIN
        }
        if ($existingFve.UseTPMPIN -eq 1) {
            Write-PinLog 'Keeping the stricter existing FVE UseTPMPIN = 1 (require) rather than 2 (allow).'
            $plan['UseTPMPIN'] = 1
        }
        if ($null -ne $existingFve.UseTPM) {
            # Another policy owns this value. Leave it alone: overwriting it would
            # silently change the tenant's posture. The paths that must create a
            # TPM-only protector relax it for the duration of the call instead.
            Write-PinLog "Leaving the existing FVE UseTPM ($($existingFve.UseTPM)) untouched - another policy owns it."
            $plan.Remove('UseTPM')
        }
        if ($existingFve.DisallowStandardUserPINReset -eq 1) {
            Write-PinLog 'FVE DisallowStandardUserPINReset is already 1 - leaving it. Users will NOT be able to change their own PIN.' 'WARN'
            $plan.Remove('DisallowStandardUserPINReset')
        }
    }

    if ($DryRun) {
        foreach ($n in $plan.Keys) { Write-PinLog "  DRYRUN would set FVE\$n = $($plan[$n])" }
    }
    else {
        if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
        $backup = [ordered]@{}
        foreach ($name in $plan.Keys) {
            $prev = Set-FvePolicyValue -Path $fveKey -Name $name -Value $plan[$name]
            $backup[$name] = if ($prev.Existed) { $prev.PreviousValue } else { '' }
            Write-PinLog "  FVE\$name = $($plan[$name])$(if ($prev.Existed) { " (was $($prev.PreviousValue))" } else { ' (was absent)' })"
        }
        # Stamp the backup once only, so a reinstall cannot overwrite the true
        # pre-app state with our own values.
        if (-not (Get-ItemProperty -Path $regKey -Name 'FvePolicyBackup' -ErrorAction SilentlyContinue)) {
            New-ItemProperty -Path $regKey -Name 'FvePolicyBackup' `
                             -Value (($backup.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') `
                             -PropertyType String -Force | Out-Null
        }
    }

    # ------------------------------------------------------------------
    # 4. Encryption + recovery password + escrow
    #
    #    None of this is allowed to fail the install. The deliverable of this
    #    script is the enrollment MECHANISM (staged payload + task, section 6);
    #    the PIN itself is set later by the dialog, which re-checks all of these
    #    preconditions on every run. Returning 1618 from here - as an earlier
    #    version did - meant a device in Autopilot ESP, or one still encrypting,
    #    never got the payload at all, so detection never succeeded and nothing
    #    ever prompted. $notReady just suppresses the optional unattended PIN
    #    assignment below.
    # ------------------------------------------------------------------
    $notReady = $false
    $vol = Get-Volume0
    Write-PinLog "Volume $sysDrive : VolumeStatus=$($vol.VolumeStatus) ProtectionStatus=$($vol.ProtectionStatus) Protectors=$(($vol.KeyProtector.KeyProtectorType | Sort-Object -Unique) -join ',')"

    if ($vol.VolumeStatus -eq 'FullyDecrypted') {
        if (-not $EnableEncryptionIfDecrypted) {
            Write-PinLog 'Drive is decrypted and -EnableEncryptionIfDecrypted was not set. Installing the mechanism anyway; the dialog will wait for encryption.' 'WARN'
            $notReady = $true
        }
        elseif ($DryRun) { Write-PinLog 'DRYRUN would start full encryption (XtsAes256) with a recovery password and a TPM protector.' }
        else {
            # Recovery password in the SAME call that starts encryption: a volume
            # must never be encrypting with only a TPM protector, or a firmware
            # change mid-encryption leaves it unrecoverable.
            # Full encryption, not -UsedSpaceOnly: this drive has been in service,
            # so previously written free space still holds recoverable plaintext.
            Write-PinLog 'Starting full encryption with a recovery password protector.'
            Enable-BitLocker -MountPoint $sysDrive -EncryptionMethod XtsAes256 `
                             -RecoveryPasswordProtector -SkipHardwareTest | Out-Null
            try {
                Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmProtector -ErrorAction Stop | Out-Null
                Write-PinLog 'Added a TPM protector so the device still boots unattended until a PIN is set.'
            }
            catch { Write-PinLog "Could not add a TPM protector: $($_.Exception.Message)" 'WARN' }
            $vol = Get-Volume0
        }
    }
    elseif ($vol.ProtectionStatus -eq 'Off') {
        # Suspended for servicing or a firmware update. Sealing a PIN against PCR
        # values that are about to change is what the suspension prevents.
        Write-PinLog 'BitLocker protection is suspended. Installing the mechanism; the dialog will wait for it to resume.' 'WARN'
        $notReady = $true
    }

    $recovery = @(Get-TpmFamilyProtector -Volume $vol -Type 'RecoveryPassword')
    if (-not $recovery) {
        if ($DryRun) { Write-PinLog 'DRYRUN would add a recovery password protector.' }
        else {
            Write-PinLog 'No recovery password protector - adding one.'
            # Relaxed, and non-fatal. On a device whose profile requires a startup
            # PIN (UseTPMPIN=1) while the volume still has only a Tpm protector, the
            # volume is already policy-non-compliant and even this add is rejected
            # with 0x80310061. Relaxing lets us establish the recovery key; if it
            # still fails, install the mechanism anyway and let the dialog retry -
            # it refuses to touch protectors without a recovery password, so nothing
            # unsafe can follow.
            try {
                Invoke-WithStartupAuthRelaxed {
                    Add-BitLockerKeyProtector -MountPoint $sysDrive -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                }
                $vol = Get-Volume0
                $recovery = @(Get-TpmFamilyProtector -Volume $vol -Type 'RecoveryPassword')
                Write-PinLog 'Recovery password protector added.'
            }
            catch {
                Write-PinLog "Could not add a recovery password protector: $($_.Exception.Message)" 'ERROR'
                $recovery = @()
            }
        }
    }
    if (-not $DryRun -and -not $recovery) {
        # Not fatal: still install the mechanism. The dialog refuses to touch a
        # protector without a recovery password, so nothing unsafe can happen.
        Write-PinLog 'Could not establish a recovery password protector - the dialog will refuse to set a PIN until one exists.' 'ERROR'
        $notReady = $true
    }

    # The recovery key is the only way back if the PIN protector ever fails to
    # unlock, and a key that exists only in the volume's own metadata is
    # unreachable from the pre-boot recovery screen. Escrow is a prerequisite.
    $escrowed = $false
    foreach ($rp in $recovery) {
        if ($DryRun) { Write-PinLog "DRYRUN would escrow $($rp.KeyProtectorId) to Entra ID."; $escrowed = $true; continue }
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $rp.KeyProtectorId -ErrorAction Stop
            Write-PinLog "Escrow call succeeded for $($rp.KeyProtectorId)."
            $escrowed = $true
        }
        catch { Write-PinLog "Escrow call failed for $($rp.KeyProtectorId): $($_.Exception.Message)" 'WARN' }
    }

    if (-not $DryRun -and $recovery) {
        # Event 845 = the service stored it; the cmdlet returning is not proof.
        # Test-RecoveryEscrow returns $true / $false / $null (cannot tell), and a
        # fresh successful call in THIS run counts as evidence because event 845
        # can lag behind the call.
        $confirmed = $false
        foreach ($rp in $recovery) {
            $r = Test-RecoveryEscrow -KeyProtectorId $rp.KeyProtectorId
            if ($r -eq $true) { $confirmed = $true; break }
        }
        if (-not $confirmed -and $escrowed) {
            Write-PinLog 'Event 845 not present yet, but the escrow call succeeded in this run.' 'WARN'
            $confirmed = $true
        }
        if (-not $confirmed) {
            if ($SkipEscrowCheck) { Write-PinLog 'Escrow unconfirmed but -SkipEscrowCheck was set - continuing.' 'WARN' }
            else {
                Write-PinLog 'Recovery key escrow to Entra ID is not confirmed. Installing the mechanism; the dialog will re-check and refuse until escrow succeeds.' 'ERROR'
                $notReady = $true
            }
        }
        else { New-ItemProperty -Path $regKey -Name 'RecoveryEscrowed' -Value 1 -PropertyType DWord -Force | Out-Null }
    }

    # ------------------------------------------------------------------
    # 5. Unattended PIN assignment (opt-in)
    # ------------------------------------------------------------------
    if ($AssignDerivedPin -and -not $DryRun -and $notReady) {
        Write-PinLog 'Skipping the unattended PIN assignment: the volume is not in a safe state for a protector change yet.' 'WARN'
    }
    elseif ($AssignDerivedPin -and -not $DryRun) {
        $vol      = Get-Volume0
        $existing = @(Get-TpmFamilyProtector -Volume $vol -Type 'TpmPin','TpmPinStartupKey')

        if ($existing) { Write-PinLog 'A startup PIN protector already exists - leaving it alone.' }
        else {
            $secure = ConvertTo-PinSecureString -Pin $derived.Pin
            try {
                # Add first: this succeeds even while the TPM-only protector is
                # present, so a failure here has removed nothing.
                Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmAndPinProtector -Pin $secure -ErrorAction Stop | Out-Null
                Write-PinLog 'TpmAndPin protector added.'
            }
            finally { $secure.Dispose() }

            $vol = Get-Volume0
            if (-not (Get-TpmFamilyProtector -Volume $vol -Type 'TpmPin')) {
                throw 'TpmAndPin protector missing after a successful add - refusing to remove the TPM-only protector.'
            }
            New-ItemProperty -Path $regKey -Name 'PinAssignedOn' -Value (Get-Date -Format 's') -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regKey -Name 'PinSource'     -Value $derived.Source -PropertyType String -Force | Out-Null
        }
    }

    # A TPM-only protector alongside a PIN protector cancels the PIN prompt, so
    # clean it up whichever mode produced the PIN.
    if (-not $DryRun) {
        $vol = Get-Volume0
        if (Get-TpmFamilyProtector -Volume $vol -Type 'TpmPin','TpmPinStartupKey') {
            foreach ($p in @(Get-TpmFamilyProtector -Volume $vol -Type 'Tpm','TpmStartupKey')) {
                Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null
                Write-PinLog "Removed $($p.KeyProtectorType) protector $($p.KeyProtectorId) - it would have cancelled the PIN prompt."
            }
        }
    }

    # ------------------------------------------------------------------
    # 6. Stage the payload and register the task
    # ------------------------------------------------------------------
    if ($DryRun) { Write-PinLog 'DRYRUN skipping payload staging and task registration.' }
    else {
        # Stop anything running out of the folder first. During an app upgrade the
        # dialog may be open, and WPF holds file locks on the PNGs it loaded as well
        # as on ServiceUI.exe - so killing only ServiceUI is not enough, and the
        # copy would fail after the task had already been unregistered, leaving the
        # device with no enrollment mechanism at all.
        Stop-ScheduledTask       -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        Get-Process -Name 'ServiceUI' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -like "$root\*" } |
            Stop-Process -Force -ErrorAction SilentlyContinue

        # The dialog is a powershell.exe whose command line references our staged
        # script; match on that rather than on the image path, which is System32.
        Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -like "*Set-BitLockerPin.ps1*" } |
            ForEach-Object {
                Write-PinLog "Stopping the open PIN dialog (PID $($_.ProcessId)) so the payload can be replaced." 'WARN'
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
        Start-Sleep -Milliseconds 500

        # Delete before copying rather than relying on -Force. A stale file whose ACL
        # or read-only attribute blocks an overwrite would otherwise fail the whole
        # install; we own the folder, so removing the file first always works and the
        # fresh copy inherits the folder's ACL cleanly.
        foreach ($file in $staged) {
            $dest = Join-Path $root $file
            try {
                if (Test-Path -LiteralPath $dest) {
                    try { Set-ItemProperty -LiteralPath $dest -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue } catch { }
                    Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
                }
                Copy-Item (Join-Path $PSScriptRoot $file) -Destination $dest -Force -ErrorAction Stop
            }
            catch { throw "Could not stage '$file' to '$dest': $($_.Exception.Message)" }
        }

        # An upgrade that drops previously-supplied artwork must not leave the old
        # image behind, or the dialog keeps showing branding the package no longer
        # contains.
        foreach ($file in $brandingPayload) {
            if ($staged -contains $file) { continue }
            $stale = Join-Path $root $file
            if (Test-Path -LiteralPath $stale) {
                try { Remove-Item -LiteralPath $stale -Force -ErrorAction Stop; Write-PinLog "Removed the stale brand image '$file'." }
                catch { Write-PinLog "Could not remove the stale brand image '$file': $($_.Exception.Message)" 'WARN' }
            }
        }

        Protect-Directory -Path $root
        Write-PinLog "Staged $($staged.Count) payload files into $root and hardened it to SYSTEM + Administrators."

        # SYSTEM, on the user's desktop, via ServiceUI. SYSTEM is required because
        # the users are not local administrators and cannot add a key protector.
        $psExe     = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $serviceUi = Join-Path $root 'ServiceUI.exe'
        $dialog    = Join-Path $root 'Set-BitLockerPin.ps1'

        # Do NOT quote the powershell.exe path. ServiceUI's argument parser is
        # primitive: quotes around the image path make it fail to resolve the
        # executable and the task dies with 0x80070005 (access denied), which
        # looks like a permissions problem and is not one. The path has no spaces.
        # The -File path does have spaces, so that one must stay quoted.
        # ServiceUI strips double quotes from everything it forwards, so NOTHING here
        # may rely on them. That is why the payload lives under a space-free path.
        if ($root -match '\s' -or $psExe -match '\s' -or $dialog -match '\s') {
            throw "Payload path '$root' contains a space. ServiceUI strips quotes, so the dialog would never launch."
        }
        $arguments = '-process:explorer.exe {0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1} -Organization {2} -MinimumPin {3}' -f `
                        $psExe, $dialog, $Organization, $MinimumPin

        # Registered from XML, deliberately, NOT from -Action/-Trigger objects.
        #
        # There is no cmdlet for a session-unlock trigger, so it has to come from
        # New-CimInstance - and the result is typed
        # ...CimInstance#MSFT_TaskSessionStateChangeTrigger, while -Trigger demands
        # ...CimInstance#MSFT_TaskTrigger. Passing a logon trigger and an unlock
        # trigger together therefore fails parameter binding outright:
        #   "Cannot bind argument to parameter 'Trigger', because PSTypeNames of the
        #    argument do not match the PSTypeName required by the parameter"
        # Grafting the expected type name on with PSTypeNames.Insert() is rejected
        # too ("The value supplied is incompatible with the type"). XML sidesteps
        # the whole problem and is also easier to verify afterwards.
        #
        # Triggers: at logon (delayed, because the trigger fires while the session
        # is still being built and before explorer.exe exists for ServiceUI to
        # hook) and on every screen unlock, which is what makes "Remind me later"
        # mean "ask me next time I come back to this machine".
        $esc = { param($s) [Security.SecurityElement]::Escape($s) }
        $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Prompts the signed-in user to set a BitLocker pre-boot startup PIN.</Description>
    <Author>$(& $esc $Organization)</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT2M</Delay>
    </LogonTrigger>
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <Delay>PT20S</Delay>
      <StateChange>SessionUnlock</StateChange>
    </SessionStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$(& $esc $serviceUi)</Command>
      <Arguments>$(& $esc $arguments)</Arguments>
      <WorkingDirectory>$(& $esc $root)</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

        # Registering the task is the single most important thing this script does -
        # without it nothing ever prompts - so it must not be able to abort the
        # install. Try the XML (logon + unlock), and if anything about it is
        # rejected, fall back to a cmdlet registration whose trigger types are
        # known to bind: logon plus an hourly repetition. Worse UX, still works.
        $haveUnlockTrigger = $false
        try {
            Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null

            # Verify the triggers actually landed. A task holding only the logon
            # trigger looks healthy but never re-prompts after a deferral, and
            # nothing else in the system would report that.
            $reg   = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $types = @($reg.Triggers | ForEach-Object { $_.CimClass.CimClassName })
            if ($types -notcontains 'MSFT_TaskLogonTrigger') { throw 'the logon trigger is missing' }
            if ($types -notcontains 'MSFT_TaskSessionStateChangeTrigger') { throw 'the session-unlock trigger is missing' }
            $haveUnlockTrigger = $true
            Write-PinLog "Registered scheduled task '$taskName' from XML (triggers: $($types -join ', '))."
        }
        catch {
            Write-PinLog "XML task registration failed ($($_.Exception.Message)) - falling back to logon + hourly triggers." 'WARN'
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

            $trigLogon = New-ScheduledTaskTrigger -AtLogOn
            $trigLogon.Delay = 'PT2M'
            $trigRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
                            -RepetitionInterval (New-TimeSpan -Minutes 60)

            # Both come from New-ScheduledTaskTrigger, so both carry the
            # #MSFT_TaskTrigger type name that -Trigger requires and the array binds.
            $action    = New-ScheduledTaskAction -Execute $serviceUi -Argument $arguments -WorkingDirectory $root
            $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                            -StartWhenAvailable -MultipleInstances IgnoreNew `
                            -ExecutionTimeLimit (New-TimeSpan -Hours 2)

            Register-ScheduledTask -TaskName $taskName `
                                   -Description 'Prompts the signed-in user to set a BitLocker pre-boot startup PIN.' `
                                   -Action $action -Trigger @($trigLogon, $trigRepeat) `
                                   -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
            Write-PinLog "Registered scheduled task '$taskName' with the fallback triggers (logon +2m, then hourly)." 'WARN'
        }

        if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            throw "Scheduled task '$taskName' does not exist after registration - nothing would ever prompt."
        }
        New-ItemProperty -Path $regKey -Name 'UnlockTrigger' -Value ([int]$haveUnlockTrigger) -PropertyType DWord -Force | Out-Null

        # Default task ACLs let any authenticated user start it on demand. Harmless
        # in itself, but there is no reason to leave a SYSTEM task user-startable.
        try {
            $svc = New-Object -ComObject Schedule.Service
            $svc.Connect()
            $svc.GetFolder('\').GetTask($taskName).SetSecurityDescriptor('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)', 0)
            Write-PinLog 'Restricted the task security descriptor to SYSTEM and Administrators.'
        }
        catch { Write-PinLog "Could not tighten the task ACL: $($_.Exception.Message)" 'WARN' }

        # ------------------------------------------------------------------
        # Self-service reset
        #
        # A second task, with no triggers at all: it exists only to be started on
        # demand from the Start-menu shortcut. Nothing schedules it, so it can
        # never prompt anybody on its own.
        #
        # This one IS deliberately user-startable, which reverses the rule applied
        # to the enrolment task a few lines above. That is the whole point - a user
        # who has forgotten their PIN is not an administrator and cannot elevate,
        # so the only way to let them fix it themselves is to let them start a
        # SYSTEM task. What stops that becoming a hole is inside Set-BitLockerPin
        # -Manage, which refuses unless the caller is the device's enrolled user,
        # the device is under its daily reset limit, AND the person at the keyboard
        # confirms who they are with Windows Hello (or their Windows password).
        # Starting the task is not the privilege; passing those gates is.
        #
        # None of the three steps below may fail the install. Without them a user
        # falls back to the service desk for a reset, which is where they were
        # before this feature existed.
        # ------------------------------------------------------------------
        try {
            $resetArgs = '-process:explorer.exe {0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1} -Organization {2} -MinimumPin {3} -Manage' -f `
                            $psExe, $dialog, $Organization, $MinimumPin

            $rAction    = New-ScheduledTaskAction -Execute $serviceUi -Argument $resetArgs -WorkingDirectory $root
            $rPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
            $rSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                             -StartWhenAvailable -MultipleInstances IgnoreNew `
                             -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

            Unregister-ScheduledTask -TaskName $resetTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $resetTaskName `
                                   -Description 'Lets the assigned user of this device reset their BitLocker startup PIN after confirming their identity with Windows Hello or their Windows password.' `
                                   -Action $rAction -Principal $rPrincipal -Settings $rSettings -ErrorAction Stop | Out-Null

            # GR alone lets a user see the task but not start it, which is what the
            # enrolment task gets. GX is what actually makes it runnable, and is the
            # single bit that makes self-service possible.
            $svc2 = New-Object -ComObject Schedule.Service
            $svc2.Connect()
            $svc2.GetFolder('\').GetTask($resetTaskName).SetSecurityDescriptor('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)', 0)
            Write-PinLog "Registered '$resetTaskName' (no triggers, startable by authenticated users)."
        }
        catch { Write-PinLog "Could not register the self-service reset task: $($_.Exception.Message)" 'WARN' }

        # The Start-menu shortcut is the only part of this the user ever sees.
        # It targets schtasks rather than the dialog directly: launched from the
        # shortcut the script would run as the USER, who cannot touch a key
        # protector. Starting the task is what gets it to SYSTEM.
        try {
            $ws = New-Object -ComObject WScript.Shell
            $sc = $ws.CreateShortcut($shortcutPath)
            $sc.TargetPath       = "$env:SystemRoot\System32\schtasks.exe"
            $sc.Arguments        = "/run /tn `"$resetTaskName`""
            $sc.Description      = 'Set a new BitLocker startup PIN for this computer'
            $sc.WorkingDirectory = "$env:SystemRoot\System32"
            # fvecpl.dll is the BitLocker control-panel icon, so the shortcut looks
            # like what it is. The brand images are PNGs and cannot be used here.
            $sc.IconLocation     = "$env:SystemRoot\System32\fvecpl.dll,0"
            $sc.WindowStyle      = 7   # minimised: schtasks flashes a console otherwise
            $sc.Save()
            Write-PinLog "Created the Start-menu shortcut at $shortcutPath."
        }
        catch { Write-PinLog "Could not create the Start-menu shortcut: $($_.Exception.Message)" 'WARN' }

        # Registering the event source needs admin, so it happens here rather than
        # from the dialog. Without it Write-PinAudit still writes to prompt.log; the
        # difference is whether a reset is visible off the device.
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                New-EventLog -LogName Application -Source $eventSource -ErrorAction Stop
                Write-PinLog "Created the '$eventSource' event source (reset audit events 3200-3204)."
            }
        }
        catch { Write-PinLog "Could not create the event source: $($_.Exception.Message)" 'WARN' }

        # Fire once now in case someone is already signed in.
        try   { Start-ScheduledTask -TaskName $taskName; Write-PinLog 'Started the task immediately.' }
        catch { Write-PinLog "Immediate start failed (no active session?): $($_.Exception.Message)" 'WARN' }

        New-ItemProperty -Path $regKey -Name 'Version'     -Value $AppVersion -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regKey -Name 'InstalledOn' -Value (Get-Date -Format 's') -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regKey -Name 'MinimumPin'  -Value $MinimumPin -PropertyType DWord -Force | Out-Null
    }

    Write-PinLog '=== Install completed successfully ==='
    exit 0
}
catch {
    Write-PinLog "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-PinLog $_.ScriptStackTrace 'ERROR'
    exit 1
}
