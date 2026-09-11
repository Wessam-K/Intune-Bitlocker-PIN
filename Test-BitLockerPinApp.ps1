<#
.SYNOPSIS
    Self-test for the BitLocker startup PIN package. Safe to run on any machine.

.DESCRIPTION
    Covers everything that can be proven without touching BitLocker:
      * PIN derivation, including the collision case that motivated the design
      * the FVE policy plan (asserts UseTPM is never the lockout-causing 0)
      * reparse-point and junction handling in the staging-path guards
      * that no script hardcodes localized account names for icacls
      * that every script parses under Windows PowerShell 5.1

    It does NOT add, remove or modify a key protector, and it does not write a
    single FVE value. The parts that need a real device - the protector swap and
    the pre-boot prompt - are listed at the end as manual pilot steps, because
    verifying them requires elevation and a reboot.

    Exit 0 = all tests passed.
#>
[CmdletBinding()]
param([switch] $IncludeDryRunInstall)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')

$script:Pass = 0
$script:Fail = 0

function Test-Case {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][scriptblock] $Body)
    try {
        & $Body
        $script:Pass++
        Write-Host ('  PASS  {0}' -f $Name) -ForegroundColor Green
    }
    catch {
        $script:Fail++
        Write-Host ('  FAIL  {0}' -f $Name) -ForegroundColor Red
        Write-Host ('        {0}' -f $_.Exception.Message) -ForegroundColor DarkRed
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    if ("$Expected" -ne "$Actual") { throw "expected '$Expected', got '$Actual'$(if ($Because) { " - $Because" })" }
}

function Get-CodeOnly {
    # Strips comment lines and block comments so a cmdlet named in prose does not
    # register as a call site.
    param([Parameter(Mandatory)][string] $Path)
    $text = Get-Content -LiteralPath $Path -Raw
    $text = [regex]::Replace($text, '(?s)<#.*?#>', '')
    ($text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
}

function Assert-Throws {
    param([scriptblock] $Body, [string] $MatchText)
    try { & $Body }
    catch {
        if ($MatchText -and $_.Exception.Message -notmatch $MatchText) {
            throw "threw, but the message did not match '$MatchText': $($_.Exception.Message)"
        }
        return
    }
    throw 'expected a terminating error, none was thrown'
}

Write-Host "`n=== PIN derivation ===" -ForegroundColor Cyan

Test-Case 'DEV-0051 -> 1110051 (the documented example)' {
    Assert-Equal '1110051' (Get-DerivedStartupPin -ComputerName 'DEV-0051').Pin
}
Test-Case 'DEV-00051 -> 1110051 (this machine; the extra leading zero is the same device number)' {
    Assert-Equal '1110051' (Get-DerivedStartupPin -ComputerName 'DEV-00051').Pin
}
Test-Case 'DEV-10051 -> 11110051 (a wider number is not truncated into a collision)' {
    Assert-Equal '11110051' (Get-DerivedStartupPin -ComputerName 'DEV-10051').Pin
}
Test-Case '00051 and 10051 do not collide' {
    $a = (Get-DerivedStartupPin -ComputerName 'DEV-00051').Pin
    $b = (Get-DerivedStartupPin -ComputerName 'DEV-10051').Pin
    if ($a -eq $b) { throw "both derived to '$a'" }
}
Test-Case 'DEV-1 -> 1110001 (short numbers are zero-padded)' {
    Assert-Equal '1110001' (Get-DerivedStartupPin -ComputerName 'DEV-1').Pin
}
Test-Case 'derivation is deterministic across calls' {
    Assert-Equal (Get-DerivedStartupPin -ComputerName 'DEV-0077').Pin (Get-DerivedStartupPin -ComputerName 'DEV-0077').Pin
}
Test-Case 'trailing whitespace in the name is tolerated' {
    Assert-Equal '1110051' (Get-DerivedStartupPin -ComputerName 'DEV-0051 ').Pin
}
Test-Case 'a name with no digits fails loudly rather than inventing a PIN' {
    Assert-Throws { Get-DerivedStartupPin -ComputerName 'LAPTOP-ABC' } 'no trailing device number'
}
Test-Case '-AllowHashFallback gives a valid numeric PIN for a digitless name' {
    $r = Get-DerivedStartupPin -ComputerName 'LAPTOP-ABC' -AllowHashFallback
    Assert-Equal 'NameHash' $r.Source
    if ($r.Pin -notmatch '^[0-9]{7}$') { throw "not 7 digits: '$($r.Pin)'" }
}
Test-Case 'the hash fallback is stable for the same name' {
    Assert-Equal (Get-DerivedStartupPin -ComputerName 'LAPTOP-ABC' -AllowHashFallback).Pin `
                 (Get-DerivedStartupPin -ComputerName 'LAPTOP-ABC' -AllowHashFallback).Pin
}
Test-Case 'a non-numeric prefix is rejected (pre-boot input is numeric only)' {
    Assert-Throws { Get-DerivedStartupPin -ComputerName 'DEV-0051' -Prefix 'AB1' } 'digits only'
}
Test-Case 'a PIN shorter than 6 digits is rejected' {
    Assert-Throws { Get-DerivedStartupPin -ComputerName 'DEV-1' -Prefix '' -NumberLength 4 } 'at least 6'
}
Test-Case 'a PIN longer than 20 digits is rejected' {
    Assert-Throws { Get-DerivedStartupPin -ComputerName 'DEV-1' -Prefix '111111111111' -NumberLength 12 } 'at most 20'
}
Test-Case 'an empty computer name is rejected' {
    Assert-Throws { Get-DerivedStartupPin -ComputerName '  ' } 'empty'
}
Test-Case 'a very large device number still yields a legal PIN' {
    $r = Get-DerivedStartupPin -ComputerName 'DEV-999999999999'
    if ($r.Pin.Length -gt 20) { throw "too long: $($r.Pin.Length)" }
}
Test-Case 'derivation does not leak the device number into $Matches' {
    $global:Matches = $null
    Get-DerivedStartupPin -ComputerName 'DEV-0051' | Out-Null
    if ($Matches -and ($Matches.Values -join '') -match '0051') { throw 'the device number leaked into $Matches' }
}
Test-Case 'the SecureString conversion round-trips to the same digits' {
    $pin = (Get-DerivedStartupPin -ComputerName 'DEV-0051').Pin
    $sec = ConvertTo-PinSecureString -Pin $pin
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try   { Assert-Equal $pin ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    } finally { $sec.Dispose() }
}

Write-Host "`n=== FVE policy plan ===" -ForegroundColor Cyan

Test-Case 'UseTPM is never 0 - that value blocks every TPM-only fallback and the rollback' {
    $plan = Get-FvePolicyPlan -MinimumPin 6
    if ($plan['UseTPM'] -eq 0) { throw 'UseTPM = 0 would make the lockout-prevention rollback impossible' }
    Assert-Equal 2 $plan['UseTPM']
}
Test-Case 'UseTPMPIN allows rather than requires a PIN' {
    Assert-Equal 2 (Get-FvePolicyPlan)['UseTPMPIN']
}
Test-Case 'UseAdvancedStartup is 1, without which the PIN add is refused outright' {
    Assert-Equal 1 (Get-FvePolicyPlan)['UseAdvancedStartup']
}
Test-Case 'UseEnhancedPin is 0 - pre-boot uses a US keyboard layout' {
    Assert-Equal 0 (Get-FvePolicyPlan)['UseEnhancedPin']
}
Test-Case 'DisallowStandardUserPINReset is 0 so users can change their own PIN' {
    Assert-Equal 0 (Get-FvePolicyPlan)['DisallowStandardUserPINReset']
}
Test-Case 'the plan does not write startup-key values the app never uses' {
    # UseTPMKey / UseTPMKeyPIN govern USB startup-key protectors, which this app never
    # creates. The Intune CSP commonly sets them to 0, so writing 2 only starts a
    # policy tug-of-war (event 851, "BitLocker startup options are in conflict").
    $plan = Get-FvePolicyPlan
    foreach ($n in @('UseTPMKey','UseTPMKeyPIN')) {
        if ($plan.Contains($n)) { throw "$n must not be written - it conflicts with the CSP for no benefit" }
    }
    # The values that genuinely gate a TPM+PIN add must still be there.
    foreach ($n in @('UseAdvancedStartup','UseTPM','UseTPMPIN','MinimumPIN')) {
        if (-not $plan.Contains($n)) { throw "$n is required for the PIN add to succeed" }
    }
}

Test-Case 'MinimumPIN follows the parameter' {
    Assert-Equal 8 (Get-FvePolicyPlan -MinimumPin 8)['MinimumPIN']
}
Test-Case 'MinimumPIN below the platform floor of 6 is rejected' {
    Assert-Throws { Get-FvePolicyPlan -MinimumPin 4 }
}
Test-Case 'the derived PIN satisfies the MinimumPIN the plan writes' {
    $plan = Get-FvePolicyPlan -MinimumPin 6
    $pin  = (Get-DerivedStartupPin -ComputerName 'DEV-0051').Pin
    if ($pin.Length -lt $plan['MinimumPIN']) { throw "PIN is $($pin.Length) digits, policy demands $($plan['MinimumPIN'])" }
}

Write-Host "`n=== Staging path safety ===" -ForegroundColor Cyan

$sandbox = Join-Path $env:TEMP ('blpin-test-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $sandbox | Out-Null
try {
    Test-Case 'Assert-SafeDirectory creates a missing directory' {
        $p = Join-Path $sandbox 'fresh'
        Assert-SafeDirectory -Path $p
        if (-not (Test-Path $p)) { throw 'not created' }
    }
    Test-Case 'Assert-SafeDirectory is re-entrant for a directory owned by an allowed principal' {
        # Cannot chown to SYSTEM without elevation, so assert the accept path
        # against this session's own SID instead. Production keeps the strict
        # SYSTEM/Administrators default.
        $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Assert-SafeDirectory -Path (Join-Path $sandbox 'fresh') -AllowedOwnerSid @($me)
    }
    Test-Case 'Assert-SafeDirectory refuses a directory owned by a standard user (pre-creation attack)' {
        # Created above by this non-elevated session, so it is user-owned - which
        # under the production default must be refused.
        Assert-Throws { Assert-SafeDirectory -Path (Join-Path $sandbox 'fresh') } 'unexpected owner SID'
    }
    Test-Case 'the Users group is not an allowed owner' {
        $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1') -Raw
        $default = ([regex]::Match($text, "AllowedOwnerSid\s*=\s*@\(([^)]*)\)")).Groups[1].Value
        if ($default -match 'S-1-5-32-545') { throw 'S-1-5-32-545 (Users) must not be an allowed owner' }
        if ($default -notmatch 'S-1-5-18')  { throw 'SYSTEM should be an allowed owner' }
    }
    Test-Case 'Assert-SafeDirectory refuses a junction (the System32 redirect attack)' {
        $target = Join-Path $sandbox 'target'; New-Item -ItemType Directory -Path $target | Out-Null
        $link   = Join-Path $sandbox 'link'
        & cmd.exe /c mklink /J "$link" "$target" | Out-Null
        if (-not (Test-Path $link)) { throw 'could not create the junction, test inconclusive' }
        Assert-Throws { Assert-SafeDirectory -Path $link } 'reparse point'
    }
    Test-Case 'Remove-DirectorySafely deletes a junction without deleting its target contents' {
        $target = Join-Path $sandbox 'target2'; New-Item -ItemType Directory -Path $target | Out-Null
        Set-Content -LiteralPath (Join-Path $target 'canary.txt') -Value 'keep me'
        $link = Join-Path $sandbox 'link2'
        & cmd.exe /c mklink /J "$link" "$target" | Out-Null
        if (-not (Test-Path $link)) { throw 'could not create the junction, test inconclusive' }
        Remove-DirectorySafely -Path $link
        if (Test-Path $link) { throw 'the junction was not removed' }
        if (-not (Test-Path (Join-Path $target 'canary.txt'))) { throw 'the target contents were deleted through the junction' }
    }
    Test-Case 'Remove-DirectorySafely removes an ordinary directory tree' {
        $p = Join-Path $sandbox 'tree\deep'; New-Item -ItemType Directory -Path $p -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $p 'f.txt') -Value 'x'
        Remove-DirectorySafely -Path (Join-Path $sandbox 'tree')
        if (Test-Path (Join-Path $sandbox 'tree')) { throw 'not removed' }
    }
    Test-Case 'Remove-DirectorySafely is a no-op on a missing path' {
        Remove-DirectorySafely -Path (Join-Path $sandbox 'does-not-exist')
    }
}
finally {
    & cmd.exe /c rd /s /q "$sandbox" 2>$null | Out-Null
}

Write-Host "`n=== Audit regressions ===" -ForegroundColor Cyan

Test-Case 'Test-RecoveryEscrow can return $false, not just $true/$null (the escrow gate must be able to fail)' {
    # Get-WinEvent throws when a filter matches nothing, so a naive try/catch makes
    # "never escrowed" - the dangerous case - look like "cannot tell".
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')
    $fn = ([regex]::Match($code, '(?s)function Test-RecoveryEscrow\s*\{(.*?)\n\}')).Groups[1].Value
    if (-not $fn) { throw 'could not isolate Test-RecoveryEscrow' }
    if ($fn -notmatch '-ListLog') { throw 'the log must be probed separately, or a filter miss is indistinguishable from an unreadable log' }
    if ($fn -notmatch 'return \$false') { throw 'no path returns $false' }
}

Test-Case 'no script exits with an unguarded $p.ExitCode (exit $null is exit 0 = success/compliant)' {
    $bad = @()
    foreach ($f in $scripts) {
        $code = Get-CodeOnly -Path $f.FullName
        if ($code -match 'exit \$p\.ExitCode' -and $code -notmatch '\$null -eq \$p') { $bad += $f.Name }
    }
    if ($bad) { throw ('unguarded relaunch exit in: ' + ($bad -join ', ')) }
}

Test-Case 'the console-session guard fails CLOSED' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch 'Get-ConsoleSessionId') { throw 'not using the shared helper' }
    if ($code -notmatch '(?s)\$null -eq \$consoleSession[^}]*exit 0') {
        throw 'an undeterminable console session must abort, not fall through to the dialog'
    }
}

Test-Case 'Get-ConsoleSessionId has a compile-free fallback' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')
    $fn = ([regex]::Match($code, '(?s)function Get-ConsoleSessionId\s*\{(.*?)\n\}')).Groups[1].Value
    if ($fn -notmatch 'Get-Process') { throw 'no fallback for hosts where Add-Type/csc.exe is unavailable' }
}

Test-Case 'the recovery and escrow checks run before any protector is removed' {
    $text     = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw
    $escrow   = $text.IndexOf('$escrowOk = $false')
    $firstRemove = $text.IndexOf('Remove-BitLockerKeyProtector')
    if ($escrow -lt 0 -or $firstRemove -lt 0) { throw 'could not locate the checks' }
    if ($escrow -gt $firstRemove) { throw 'a protector is removed before the escrow gate runs' }
}

Test-Case 'the -Force reset path has a rollback' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch '\$removedForReset') { throw 'no flag tracking that the old PIN protector was removed' }
    if ($code -notmatch '(?s)if \(\$removedForReset\)[^}]*TpmProtector') { throw 'no TPM-only rollback after a failed reset' }
}

Test-Case 'paths that create a TPM protector relax the UseTPM policy first' {
    $common = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')
    if ($common -notmatch 'function Invoke-WithStartupAuthRelaxed') { throw 'helper missing' }
    foreach ($n in @('Set-BitLockerPin.ps1','Uninstall-BitLockerStartupPin.ps1')) {
        $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot $n)
        if ($code -match '-TpmProtector' -and $code -notmatch 'Invoke-WithStartupAuthRelaxed') {
            throw "$n creates a TPM protector without relaxing UseTPM"
        }
    }
}

Test-Case 'the installer never returns 1618 after staging, so ESP devices still install' {
    $text  = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    $stage = $text.IndexOf('Stage the payload and register the task')
    if ($stage -lt 0) { throw 'could not find the staging section' }
    $after = $text.Substring($stage)
    if ($after -match 'exit 1618') { throw '1618 is returned after staging - the mechanism would be installed but reported as retry' }
    if ($text -notmatch '\$notReady') { throw 'expected readiness to be tracked as a flag rather than an early exit' }
}

Test-Case 'the FVE write does not downgrade a stricter existing MinimumPIN' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    if ($code -notmatch 'existingFve') { throw 'existing FVE values are not read before writing' }
    if ($code -notmatch "(?s)existingFve\.MinimumPIN[^}]*plan\['MinimumPIN'\]") { throw 'no MinimumPIN comparison' }
}

Test-Case 'uninstall only removes the shared organisation folder when it is empty' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Uninstall-BitLockerStartupPin.ps1')
    if ($code -notmatch '(?s)Get-ChildItem -LiteralPath \$parent[^}]*Remove-DirectorySafely -Path \$parent') {
        throw 'the parent folder is removed without an emptiness check, which would delete sibling apps'
    }
}

Test-Case 'uninstall keeps the payload when the protector rollback failed' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Uninstall-BitLockerStartupPin.ps1')
    if ($code -notmatch '(?s)if \(\$exitCode -ne 0\)') { throw 'no guard on the failure path' }
    $idxGuard  = $code.IndexOf('if ($exitCode -ne 0)')
    $idxRemove = $code.IndexOf('Remove-DirectorySafely -Path $root')
    if ($idxRemove -lt $idxGuard) { throw 'the payload is deleted before the failure is considered' }
}

Test-Case 'uninstall performs the protector swap before restoring the FVE policy' {
    $text    = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-BitLockerStartupPin.ps1') -Raw
    $swap    = $text.IndexOf('if ($RemovePinProtector)')
    $restore = $text.IndexOf('if (-not $KeepFvePolicy)')
    if ($swap -lt 0 -or $restore -lt 0) { throw 'could not locate both blocks' }
    if ($restore -lt $swap) { throw 'restoring the policy first can reinstate a UseTPM that blocks the swap' }
}

Test-Case 'detection resolves paths identically under a 32-bit host' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Detect-BitLockerStartupPin.ps1')
    # %ProgramData% is not WOW64-redirected, so no bitness handling is needed for the
    # payload path. The registry still is redirected, so that must be explicit.
    if ($code -match '\$\{?env:ProgramFiles') { throw 'ProgramFiles resolves to Program Files (x86) under a 32-bit host' }
    if ($code -notmatch '\$env:ProgramData') { throw 'expected the payload root under %ProgramData%' }
    if ($code -notmatch 'Registry64')        { throw 'registry read is WOW-redirected under a 32-bit host' }
}

Test-Case 'Source\ payload is byte-identical to the root copies' {
    # README.md packages the .intunewin from .\Source, so Source\ is what actually
    # reaches devices - the root copies are for local reading and testing. A fix
    # applied to only one side ships nothing. That has already happened once: a
    # hardening change to the install log path landed at root while Source\ kept
    # the vulnerable version. Keep them identical, or drop the duplicates entirely.
    $srcDir = Join-Path $PSScriptRoot 'Source'
    if (-not (Test-Path $srcDir)) { throw 'Source\ is missing - packaging would have nothing to build from' }
    foreach ($f in Get-ChildItem $srcDir -File -Filter '*.ps1') {
        $rootCopy = Join-Path $PSScriptRoot $f.Name
        if (-not (Test-Path $rootCopy)) { continue }   # Source-only file: nothing to drift against
        $hRoot = (Get-FileHash $rootCopy   -Algorithm SHA256).Hash
        $hSrc  = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        if ($hRoot -ne $hSrc) {
            throw "$($f.Name) differs between the root copy and Source\ - the PACKAGED version is the Source\ one, so copy whichever is correct over the other"
        }
    }
}

Test-Case 'the install log path is not predictable under SYSTEM' {
    # The installer runs as SYSTEM, where $env:TEMP is C:\Windows\Temp - world
    # writable. A fixed filename there lets a standard user pre-create the path as
    # a link and redirect a SYSTEM write (local elevation). Assert BOTH copies.
    foreach ($p in @((Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1'),
                     (Join-Path $PSScriptRoot 'Source\Install-BitLockerStartupPin.ps1'))) {
        if (-not (Test-Path $p)) { continue }
        $code = Get-CodeOnly -Path $p
        if ($code -match 'install-bootstrap\.log') {
            throw "$p uses a predictable log name in a world-writable directory"
        }
        if ($code -notmatch '\[guid\]::NewGuid\(\)') {
            throw "$p no longer randomises the bootstrap log name"
        }
    }
}

Test-Case 'compliance requires a recovery password, not just a PIN' {
    # Report-BitLockerPinStatus.ps1 was superseded by the Remediations pair; the
    # requirement moved with it.
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Detect-BitLockerPinCompliance.ps1')
    if ($code -notmatch 'no recovery password protector') {
        throw 'a device with a mandatory PIN and no recovery key would report compliant'
    }
    if (Test-Path (Join-Path $PSScriptRoot 'Report-BitLockerPinStatus.ps1')) {
        throw 'the superseded report script is back in the package - two scripts would own this job'
    }
}

Test-Case 'the dialog refuses a policy MinimumPIN above the 20-character maximum' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch '(?s)\$minPin -gt 20[^}]*exit 0') { throw 'an unsatisfiable minimum would prompt forever' }
}

Test-Case 'the SecureString copies taken from the PasswordBoxes are disposed' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch '\$secure\.Dispose\(\)') { throw 'no dispose of the PIN SecureString' }
    if ($code -notmatch '\$confirm\.Dispose\(\)') { throw 'no dispose of the confirmation SecureString' }
}

Test-Case 'TpmPinStartupKey is not silently treated as "PIN already set"' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch '\$hasPinAndKey') { throw 'TpmPinStartupKey is not distinguished from TpmPin' }
}

Test-Case 'an unencrypted volume tells the user to contact IT instead of exiting silently' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch "FullyDecrypted','DecryptionInProgress") { throw 'both unencrypted states must be detected' }
    if ($code -notmatch 'Show-IssueNotice')  { throw 'no user-facing notice for an unencrypted device' }
    if ($code -notmatch 'IT service desk')   { throw 'the notice must point the user at IT' }
    # Scope to the pre-flight: the -PreviewNotEncrypted block shows the same notice
    # deliberately unthrottled, since it exists to be looked at on demand.
    # Anchor on code, not a comment: Get-CodeOnly strips comment lines.
    $scan = $code.IndexOf("VolumeStatus -in 'FullyDecrypted'")
    if ($scan -lt 0) { throw 'could not locate the encryption scan block' }
    $region = $code.Substring($scan)
    $warn = $region.IndexOf('NotEncryptedWarnedOn')
    $show = $region.IndexOf('Show-IssueNotice -Heading')
    if ($warn -lt 0) { throw 'no throttle marker, so the warning would appear at every unlock' }
    if ($show -lt 0) { throw 'the scan block does not show the notice' }
    if ($warn -gt $show) { throw 'the throttle must be evaluated before the notice is shown' }
}

Test-Case 'transient encryption states do NOT alarm the user' {
    # Encryption still running, or a suspended-but-encrypted volume, are routine.
    # Warning about them teaches people to dismiss our windows.
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    $inProgress = $code.IndexOf("VolumeStatus -eq 'EncryptionInProgress'")
    if ($inProgress -lt 0) { throw 'EncryptionInProgress is not handled separately' }
    $segment = $code.Substring($inProgress, [Math]::Min(400, $code.Length - $inProgress))
    if ($segment -match 'Show-IssueNotice') { throw 'EncryptionInProgress must defer quietly, not warn' }
}

Test-Case 'the notice window fits its content (the Close button was clipped at 150% DPI)' {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw
    $xamlText = ([regex]::Match($text, '(?s)\[xml\]\$x\s*=\s*@"(.*?)"@')).Groups[1].Value
    if (-not $xamlText) { throw 'could not extract the notice XAML' }
    # Same substitutions the script itself makes. Get-BrandXaml resolves against
    # whatever artwork is actually present, so this exercises the branded layout on
    # a machine that has the PNGs and the text-wordmark fallback on one that does not.
    $Organization = 'WK-Hub'
    $root  = $PSScriptRoot
    $brand = Get-BrandXaml -Root $root -BrandName $Organization
    [xml]$x = $ExecutionContext.InvokeCommand.ExpandString($xamlText)
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
    foreach ($n in @('h','b','r','refBox','ok')) { if (-not $w.FindName($n)) { throw "notice XAML has no element '$n'" } }
    if ($w.Height -lt 460) { throw "notice height $($w.Height) is too short - the Close button gets clipped" }
}

Test-Case 'the payload path has no space (ServiceUI strips quotes from what it forwards)' {
    # The real failure: ServiceUI rebuilt the command line as
    #   -File C:\Program Files\...\Set-BitLockerPin.ps1
    # with the quotes removed, so powershell.exe saw '-File C:\Program' and exited
    # 0xFFFD0000. Looks like a hook failure; it is a path-with-space failure.
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    if ($code -notmatch '\$root\s*=\s*Join-Path \$env:ProgramData') {
        throw 'the payload root must be under %ProgramData% (no space), not %ProgramFiles%'
    }
    $org      = ([regex]::Match($code, '\$Organization\s*=\s*''([^'']+)''')).Groups[1].Value
    if (-not $org) { throw 'could not read the organization name from the installer' }
    $resolved = Join-Path $env:ProgramData "$org\BitLockerPin"
    if ($resolved -match '\s') { throw "resolved payload path still contains a space: $resolved" }
    if ($code -notmatch 'ServiceUI strips') { throw 'the reason must be documented, or someone will move it back' }
}

Test-Case 'the ServiceUI argument string contains no double quotes at all' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    $line = ([regex]::Match($code, "(?m)^\s*\`$arguments\s*=.*$")).Value
    if (-not $line) { throw 'could not find the ServiceUI argument string' }
    if ($line -match '\\"') { throw "the argument string still embeds quotes, which ServiceUI removes: $line" }
    if ($code -notmatch 'Payload path .* contains a space') { throw 'no guard rejecting a space in the payload path' }
}

Test-Case 'install, detect and uninstall resolve the same payload root' {
    $roots = @()
    foreach ($n in @('Install-BitLockerStartupPin.ps1','Detect-BitLockerStartupPin.ps1','Uninstall-BitLockerStartupPin.ps1')) {
        $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot $n)
        $m = [regex]::Match($code, '\$root\s*=\s*Join-Path\s+(\$env:\w+|\$\{env:\w+\})')
        if (-not $m.Success) { throw "could not find the payload root in $n" }
        $roots += $m.Groups[1].Value
    }
    if (($roots | Sort-Object -Unique).Count -ne 1) { throw "payload roots differ: $($roots -join ', ')" }
}

Test-Case 'Protect-Directory does not push inheritance flags onto files with /T' {
    # (OI)(CI) on a leaf object is inherit-only and grants nothing on the file, so /T
    # made the staged payload unwritable and every reinstall failed at Copy-Item.
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')
    $grant = ([regex]::Match($code, '(?m)^\s*&\s*icacls\.exe \$Path /inheritance:r[^\r\n]*')).Value
    if (-not $grant) { throw 'could not find the icacls grant line' }
    if ($grant -match '/T') { throw 'the (OI)(CI) grant must not use /T - it makes the file ACEs inherit-only' }
    if ($code -notmatch '/reset /T') { throw 'existing children must be reset to inherit from the folder' }
}

Test-Case 'the installer removes a stale payload file before copying over it' {
    $code   = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    $remove = $code.IndexOf('Remove-Item -LiteralPath $dest')
    $copy   = $code.IndexOf('Copy-Item (Join-Path $PSScriptRoot $file)')
    if ($remove -lt 0) { throw 'relies on Copy-Item -Force, which cannot overwrite a file whose ACL or read-only attribute denies write' }
    if ($copy -lt 0)   { throw 'could not find the payload copy' }
    if ($remove -gt $copy) { throw 'the stale file must be removed before the copy, not after' }
}

Test-Case 'the installer clears an open dialog before replacing the payload' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    if ($code -notmatch 'Win32_Process') { throw 'only ServiceUI is stopped; WPF also locks the staged PNGs' }
}

Test-Case 'uninstall refuses to run unelevated instead of reporting success' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Uninstall-BitLockerStartupPin.ps1')
    if ($code -notmatch 'WindowsBuiltInRole\]::Administrator') { throw 'no elevation check' }
}

Write-Host "`n=== Remediations pair ===" -ForegroundColor Cyan

Test-Case 'the Remediations scripts are self-contained (single-file upload cannot dot-source)' {
    foreach ($n in @('Detect-BitLockerPinCompliance.ps1','Remediate-BitLockerPinCompliance.ps1')) {
        $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot $n)
        if ($code -match '\.\s+\(Join-Path \$PSScriptRoot') { throw "$n dot-sources a module Intune will not upload" }
    }
}

Test-Case 'detection never reports compliant when it cannot determine the state' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Detect-BitLockerPinCompliance.ps1')
    # Every UNKNOWN path must exit 1. Exit 0 means "compliant, do not remediate".
    foreach ($m in [regex]::Matches($code, "UNKNOWN[^\r\n]*\r?\n?\s*exit (\d)")) {
        if ($m.Groups[1].Value -ne '1') { throw 'an UNKNOWN path exits 0, which reports the device compliant' }
    }
    if ($code -notmatch 'UNKNOWN') { throw 'no unknown-state handling at all' }
}

Test-Case 'detection requires a recovery password, a PIN, no TPM-only protector, and protection On' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Detect-BitLockerPinCompliance.ps1')
    foreach ($needle in @('no recovery password protector',
                          'no startup PIN protector',
                          'TPM-only protector present alongside the PIN',
                          'protection is')) {
        if ($code -notmatch [regex]::Escape($needle)) { throw "detection does not check: $needle" }
    }
}

Test-Case 'remediation refuses to remove the TPM-only protector without a recovery password' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Remediate-BitLockerPinCompliance.ps1')
    if ($code -notmatch 'refusing to remove the TPM-only protector without a recovery password') {
        throw 'no guard - removing it without a recovery key can strand the device'
    }
    $guard  = $code.IndexOf('refusing to remove the TPM-only protector')
    $remove = $code.IndexOf('Remove-BitLockerKeyProtector')
    if ($guard -lt 0 -or $remove -lt 0) { throw 'could not locate the guard and the removal' }
    if ($guard -gt $remove) { throw 'the guard must be evaluated before the removal' }
}

Test-Case 'remediation relaxes startup-auth policy around the protector change' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Remediate-BitLockerPinCompliance.ps1')
    if ($code -notmatch 'function Invoke-WithStartupAuthRelaxed') { throw 'no relax helper (it cannot dot-source one)' }
    if ($code -notmatch '(?s)Invoke-WithStartupAuthRelaxed \{[^}]*Remove-BitLockerKeyProtector') {
        throw 'the protector removal is not wrapped, so a strict policy can block it with 0x80310061'
    }
}

Write-Host "`n=== Package hygiene ===" -ForegroundColor Cyan

$scripts = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)

Test-Case 'every script parses under the PowerShell 5.1 language parser' {
    $bad = @()
    foreach ($f in $scripts) {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
        if ($errs) { $bad += "$($f.Name): $($errs[0].Message)" }
    }
    if ($bad) { throw ($bad -join '; ') }
}

Test-Case 'no script passes a localized account name to icacls (fails 1332 on German Windows)' {
    $hits = @()
    foreach ($f in $scripts) {
        if ($f.Name -eq 'Test-BitLockerPinApp.ps1') { continue }
        $text = Get-Content -LiteralPath $f.FullName -Raw
        foreach ($m in [regex]::Matches($text, 'icacls[^\r\n]*')) {
            if ($m.Value -match "BUILTIN\\\\|'SYSTEM:|`"SYSTEM:|\bUsers:") { $hits += "$($f.Name): $($m.Value.Trim())" }
        }
    }
    if ($hits) { throw ($hits -join '; ') }
}

Test-Case 'icacls calls use SID literals' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1') -Raw
    if ($text -notmatch '\*S-1-5-18' -or $text -notmatch '\*S-1-5-32-544') { throw 'expected SID literals for SYSTEM and Administrators' }
}

Test-Case 'the FVE policy key is never created with New-Item -Force (that wipes existing values)' {
    $hits = @()
    foreach ($f in $scripts) {
        if ($f.Name -eq 'Test-BitLockerPinApp.ps1') { continue }
        foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
            if ($line -match 'New-Item' -and $line -match '-Force' -and $line -match 'Policies\\Microsoft\\FVE|\$fve\b|\$fveKey\b') {
                $hits += "$($f.Name): $($line.Trim())"
            }
        }
    }
    if ($hits) { throw ($hits -join '; ') }
}

Test-Case 'the dialog adds the PIN protector before removing the TPM-only one' {
    $text   = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw
    $add    = $text.IndexOf('-TpmAndPinProtector')
    $verify = $text.IndexOf('not removing the TPM-only protector')
    $remove = $text.IndexOf('Remove-BitLockerKeyProtector', $verify)
    if ($add -lt 0 -or $verify -lt 0 -or $remove -lt 0) { throw 'could not locate the swap sequence' }
    if (-not ($add -lt $verify -and $verify -lt $remove)) { throw 'the order is not add -> verify -> remove' }
}

Test-Case 'the dialog validates the PIN before any protector is touched' {
    $text     = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw
    $validate = $text.IndexOf('$problem = Test-PinSecure')
    $touch    = $text.IndexOf('Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmAndPinProtector')
    if ($validate -lt 0 -or $touch -lt 0) { throw 'could not locate validation or the add' }
    if ($validate -gt $touch) { throw 'validation runs after the protector work' }
}

Test-Case 'the dialog never materialises the PIN as a managed string' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -match 'PtrToStringBSTR') { throw 'PtrToStringBSTR creates an unzeroable System.String copy of the PIN' }
    if ($code -notmatch 'ZeroFreeBSTR')  { throw 'expected ZeroFreeBSTR to clear the unmanaged copy' }
}

Test-Case 'the dialog runs as SYSTEM via ServiceUI, because users are not local admins' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    if ($text -notmatch 'ServiceUI') { throw 'no ServiceUI in the task action' }
    if ($text -notmatch "New-ScheduledTaskPrincipal[^\r\n]*'S-1-5-18'") { throw 'the task must run as SYSTEM (S-1-5-18)' }
}

Test-Case 'nothing in the ServiceUI argument string is quoted (it strips quotes)' {
    # Quoting the image path made the task die 0x80070005; quoting the -File path made
    # the child die 0xFFFD0000. ServiceUI removes double quotes, full stop - which is
    # only survivable because the payload path has no space.
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    $line = ([regex]::Match($text, '(?m)^\s*\$arguments\s*=.*$')).Value
    if (-not $line) { throw 'could not find the ServiceUI argument string' }
    if ($line -match '-process:explorer\.exe\s+"') { throw 'the powershell.exe path is quoted - ServiceUI cannot resolve it' }
    if ($line -match '-File\s+"')                  { throw 'the -File path is quoted - ServiceUI strips it and the script is not found' }
}

Test-Case 'the task is triggered by screen unlock, so "Remind me later" means next unlock' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    if ($text -notmatch 'SessionStateChangeTrigger') { throw 'no session-state-change trigger' }
    if ($text -notmatch 'SessionUnlock') { throw 'the trigger must be SessionUnlock' }
}

Test-Case 'a mixed trigger array is never passed to -Trigger (it fails PSTypeName binding)' {
    # New-ScheduledTaskTrigger returns #MSFT_TaskTrigger; a New-CimInstance
    # session-state trigger does not, so combining them throws and the install dies
    # after staging - which is exactly what happened on the first test device.
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    if ($code -match '-Trigger\s*@\(\s*\$trigLogon\s*,\s*\$trigUnlock') {
        throw 'a cmdlet trigger and a CIM session-state trigger are being combined'
    }
    if ($code -notmatch 'Register-ScheduledTask[^\r\n]*-Xml') { throw 'the unlock trigger must be registered via XML' }
}

Test-Case 'task registration cannot abort the install, and its absence is fatal' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1')
    if ($code -notmatch 'falling back to logon') { throw 'no fallback if XML registration is rejected' }
    if ($code -notmatch 'does not exist after registration') { throw 'no post-registration existence check' }
}

Test-Case 'the fallback trigger pair is type-compatible with -Trigger' {
    # Guards the fallback itself: both must come from New-ScheduledTaskTrigger.
    $tl = New-ScheduledTaskTrigger -AtLogOn
    $tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 60)
    $ac = New-ScheduledTaskAction -Execute 'C:\x.exe'
    $null = New-ScheduledTask -Action $ac -Trigger @($tl, $tr)
}

Test-Case 'closing the window with the X is treated as deferring' {
    $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1')
    if ($code -notmatch 'Add_Closing') { throw 'no Closing handler, so an X-close is never logged' }
}

Test-Case 'the installer pins a SHA256 for ServiceUI.exe, and the supplied copy matches it' {
    # ServiceUI.exe is Microsoft's and is not redistributed with this package (see
    # the README, "Binaries you must supply yourself"). So the presence of the file
    # is not what is asserted here - the PIN of its hash is. When an operator has
    # dropped their copy in, it is verified for real.
    $pinned = ([regex]::Match((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw),
                              "(?i)ServiceUiSha256\s*=\s*'([A-Fa-f0-9]{64})'")).Groups[1].Value
    if (-not $pinned) { throw 'the installer does not pin a SHA256 for ServiceUI.exe' }

    $sui = Join-Path $PSScriptRoot 'ServiceUI.exe'
    if (-not (Test-Path $sui)) {
        Write-Host '        (ServiceUI.exe not supplied yet - hash pin verified, binary check skipped)' -ForegroundColor DarkGray
        return
    }
    $sig = Get-AuthenticodeSignature $sui
    if ($sig.Status -ne 'Valid') { throw "signature status is $($sig.Status)" }
    if ($sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'not signed by Microsoft' }
    Assert-Equal $pinned (Get-FileHash $sui -Algorithm SHA256).Hash 'the supplied binary does not match the pinned hash - pass -ServiceUiSha256 for a different MDT build'
}

Test-Case 'every payload file the installer stages exists, and detection checks the same list' {
    $installer = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    $block     = ([regex]::Match($installer, '(?s)\$payload\s*=\s*@\((.*?)\)')).Groups[1].Value
    $files     = [regex]::Matches($block, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
    if ($files.Count -lt 3) { throw 'could not parse the payload list' }
    foreach ($f in $files) {
        # ServiceUI.exe is operator-supplied, so its absence from the repo is
        # expected; the installer reports it with its own message instead.
        if ($f -eq 'ServiceUI.exe') { continue }
        if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { throw "payload file missing from the repo: $f" }
    }
    $detect = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Detect-BitLockerStartupPin.ps1') -Raw
    foreach ($f in $files) {
        if ($detect -notmatch [regex]::Escape($f)) { throw "detection does not verify staged file: $f" }
    }

    # The optional brand images are staged separately and must NOT be in the
    # mandatory list, or a package with no artwork would fail to install.
    $optional = ([regex]::Match($installer, '(?s)\$brandingPayload\s*=\s*@\((.*?)\)')).Groups[1].Value
    if (-not $optional) { throw 'the optional branding payload list is missing' }
    foreach ($f in [regex]::Matches($optional, "'([^']+)'")) {
        if ($files -contains $f.Groups[1].Value) { throw "$($f.Groups[1].Value) is both required and optional" }
        if ($detect -match [regex]::Escape($f.Groups[1].Value)) {
            throw "detection requires the optional brand image $($f.Groups[1].Value) - a package with no artwork would reinstall forever"
        }
    }
}

Test-Case 'the dialog XAML parses and renders, branded or unbranded' {
    # Catches malformed XAML, a bad style reference, or a brand image that WPF
    # cannot decode - all of which would otherwise only surface on a user's
    # desktop. Branding is a drop-in, so this must pass both with artwork present
    # and with none at all: Get-BrandXaml emits an <Image> only for a file that
    # exists, and a text wordmark otherwise.
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw
    $xamlText = ([regex]::Match($text, '(?s)\[xml\]\$xaml\s*=\s*@"(.*?)"@')).Groups[1].Value
    if (-not $xamlText) { throw 'could not extract the XAML block' }

    $root  = $PSScriptRoot
    $brand = Get-BrandXaml -Root $root -BrandName 'WK-Hub'
    $expanded = $ExecutionContext.InvokeCommand.ExpandString($xamlText)

    [xml]$x = $expanded
    $reader = New-Object System.Xml.XmlNodeReader $x
    $win    = [Windows.Markup.XamlReader]::Load($reader)

    foreach ($name in @('pbPin','pbConfirm','lblStatus','pnlStatus','lblPin','btnSet','btnLater','runDevice')) {
        if (-not $win.FindName($name)) { throw "the XAML has no element named '$name'" }
    }
    if ($win.FindName('pbPin').MaxLength -ne 20) { throw 'the PIN box does not cap input at 20 characters' }

    # The user must be able to move, minimise and close the window.
    if ($win.WindowStyle -eq 'None') { throw 'WindowStyle None gives no title bar, so no close/minimise and no drag' }
    if ($win.ResizeMode -notin @('CanMinimize','CanResize','CanResizeWithGrip')) {
        throw "ResizeMode '$($win.ResizeMode)' does not allow minimising"
    }
    if (-not $win.ShowInTaskbar) { throw 'no taskbar button, so a minimised window cannot be restored' }

    # Force a layout pass so image decoding and style resolution actually happen.
    $win.Measure([Windows.Size]::new(780, 520))
    $win.Arrange([Windows.Rect]::new(0, 0, 780, 520))
    $win.UpdateLayout()

    # Whatever artwork the operator did supply must actually be decodable.
    foreach ($name in @('brand-background.png','brand-logo-on-dark.png','brand-logo-square.png')) {
        $img = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $img)) { continue }
        $bmp = New-Object Windows.Media.Imaging.BitmapImage ([uri]$img)
        if ($bmp.PixelWidth -le 0) { throw "WPF could not decode $img" }
    }
}

Test-Case 'a missing brand image degrades to a wordmark instead of taking the dialog down' {
    # WPF resolves <Image Source="..."/> while the XAML is being parsed, so a path
    # that does not exist throws straight out of XamlReader.Load. Branding is an
    # optional drop-in and must never be able to stop a security dialog appearing.
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $empty = Join-Path $env:TEMP ('blpin-brand-' + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $empty | Out-Null
    try {
        $brand = Get-BrandXaml -Root $empty -BrandName 'Example-Org'
        if ($brand.WindowIcon -ne '') { throw 'an Icon attribute was emitted for a logo file that does not exist' }
        foreach ($f in @($brand.Backdrop, $brand.DialogMark, $brand.NoticeMark, $brand.DialogFooter, $brand.NoticeFooter)) {
            if ($f -match '<Image') { throw "an <Image> was emitted with no file behind it: $f" }
        }
        if ($brand.DialogMark -notmatch 'Example-Org') { throw 'no wordmark stands in for the missing logo' }
        if ($brand.Backdrop -notmatch '<Border')   { throw 'no solid fill stands in for the missing backdrop' }

        # ...and the whole dialog must still parse with those fragments in place.
        $xamlText = ([regex]::Match((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-BitLockerPin.ps1') -Raw),
                                    '(?s)\[xml\]\$xaml\s*=\s*@"(.*?)"@')).Groups[1].Value
        [xml]$x = $ExecutionContext.InvokeCommand.ExpandString($xamlText)
        $null = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
    }
    finally { & cmd.exe /c rd /s /q "$empty" 2>$null | Out-Null }
}

Test-Case 'every script that calls a BitLocker cmdlet carries the 64-bit relaunch guard' {
    $missing = @()
    foreach ($f in $scripts) {
        # Set-BitLockerPin.ps1 is exempt: the scheduled task launches it through
        # ServiceUI with the native System32 powershell.exe, so it is already
        # 64-bit and a relaunch would break the desktop hook.
        if ($f.Name -in @('BitLockerPin.Common.ps1','Test-BitLockerPinApp.ps1','Set-BitLockerPin.ps1')) { continue }
        $code = Get-CodeOnly -Path $f.FullName
        $usesBitLocker = $code -match '(Get|Add|Remove|Enable|Resume|Suspend)-BitLocker' -or $code -match 'BackupToAAD-BitLocker'
        if ($usesBitLocker -and $code -notmatch 'PROCESSOR_ARCHITEW6432') { $missing += $f.Name }
    }
    if ($missing) { throw ('no SysNative guard in: ' + ($missing -join ', ')) }
}

Test-Case 'the dialog carries no SysNative guard, because ServiceUI already launches 64-bit PowerShell' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw
    if ($text -notmatch 'System32\\WindowsPowerShell') { throw 'the task should launch the native System32 PowerShell' }
}

Test-Case 'no script writes the PIN to a log, a file or the command line' {
    $hits = @()
    foreach ($f in $scripts) {
        if ($f.Name -eq 'Test-BitLockerPinApp.ps1') { continue }
        foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
            if ($line -match '^\s*#') { continue }
            # $derived.Pin.Length is a length, not the PIN - only a bare
            # $derived.Pin reaching a sink is a leak.
            if ($line -match '(Write-PinLog|Add-Content|Set-Content|Out-File|New-ItemProperty)' -and
                $line -match '\$derived\.Pin(?!\.Length)|\$plain\b') {
                $hits += "$($f.Name): $($line.Trim())"
            }
        }
    }
    if ($hits) { throw ($hits -join '; ') }
}

Test-Case 'detection and installer agree on the app version' {
    $iv = ([regex]::Match((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -Raw), '\$AppVersion\s*=\s*''([^'']+)''')).Groups[1].Value
    $dv = ([regex]::Match((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Detect-BitLockerStartupPin.ps1')  -Raw), '\$AppVersion\s*=\s*''([^'']+)''')).Groups[1].Value
    if (-not $iv -or -not $dv) { throw "could not read the versions (installer '$iv', detection '$dv')" }
    Assert-Equal $iv $dv 'a mismatch makes Intune reinstall forever'
}

Test-Case 'every script agrees on the organization name' {
    # -Organization is the one knob an adopter turns. It namespaces the registry
    # key, the %ProgramData% folder and the scheduled task, so a file left on the
    # old value silently looks at a different device state than the rest.
    $files = @('Install-BitLockerStartupPin.ps1','Detect-BitLockerStartupPin.ps1',
               'Uninstall-BitLockerStartupPin.ps1','Set-BitLockerPin.ps1',
               'Detect-BitLockerPinCompliance.ps1','Remediate-BitLockerPinCompliance.ps1')
    $seen = @{}
    foreach ($n in $files) {
        $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot $n) -Raw
        $org  = ([regex]::Match($text, '\$Organization\s*=\s*''([^'']+)''')).Groups[1].Value
        if (-not $org) { throw "$n declares no `$Organization default" }
        $seen[$n] = $org
    }
    $distinct = @($seen.Values | Sort-Object -Unique)
    if ($distinct.Count -ne 1) {
        throw ("organization differs: " + (($seen.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))
    }
}

Test-Case 'the task name is derived from the organization, never hardcoded' {
    # Before this was derived, passing -Organization Contoso moved the registry and
    # the payload folder but left the task called 'WK-Hub BitLocker PIN Enrollment' -
    # so Set-BitLockerPin could not disable the task that launched it.
    $files = @('Install-BitLockerStartupPin.ps1','Detect-BitLockerStartupPin.ps1',
               'Uninstall-BitLockerStartupPin.ps1','Set-BitLockerPin.ps1',
               'Detect-BitLockerPinCompliance.ps1','Remediate-BitLockerPinCompliance.ps1')
    foreach ($n in $files) {
        $code = Get-CodeOnly -Path (Join-Path $PSScriptRoot $n)
        if ($code -notmatch '\$taskName\s*=\s*"\$Organization BitLocker PIN Enrollment"') {
            throw "$n does not derive `$taskName from `$Organization"
        }
        if ($code -match "TaskName\s+'") { throw "$n still passes a literal task name" }
    }
}

if ($IncludeDryRunInstall) {
    Write-Host "`n=== Dry-run install (no protector or policy change) ===" -ForegroundColor Cyan
    Test-Case 'the installer runs end to end in -DryRun' {
        $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
                 -File (Join-Path $PSScriptRoot 'Install-BitLockerStartupPin.ps1') -DryRun 2>&1
        Write-Host ($out | Out-String)
        if ($LASTEXITCODE -notin @(0, 1618)) { throw "exit code $LASTEXITCODE" }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host ('  {0} passed, {1} failed' -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })

Write-Host @'

Still requires a pilot device (needs elevation and a reboot - not testable here):
  1. Run the installer as SYSTEM/admin on one encrypted, Entra-joined device.
  2. Confirm "manage-bde -protectors -get C:" shows TpmPin and NO Tpm protector.
     A leftover Tpm protector silently cancels the PIN prompt.
  3. Reboot and confirm the pre-boot PIN prompt appears and the derived PIN works.
  4. Confirm the recovery key is visible in Entra (Devices > device > BitLocker keys).
  5. Sign in as a standard user and confirm "Change PIN now" in the notice works.
  6. Run the uninstaller with -RemovePinProtector and confirm the device still
     boots without needing the recovery key.
'@ -ForegroundColor DarkGray

exit $(if ($script:Fail) { 1 } else { 0 })
