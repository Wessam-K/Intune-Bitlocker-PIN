<#
.SYNOPSIS
    Shared helpers for the BitLocker startup PIN package. Dot-source; do not run.

.DESCRIPTION
    Single source of truth for:
      * PIN derivation from the device name (helpdesk must be able to reproduce it)
      * logging
      * FVE policy planning (the "safe" value set)
      * staging-path validation and hardening
      * escrow / protector verification against the BitLocker event log

    Everything here must work in Windows PowerShell 5.1 running as SYSTEM.
#>

# Windows caps a startup PIN at 20 characters. Since 1703 the effective floor is
# 6 digits unless MinimumPIN is explicitly lowered, so 6 is our hard floor.
$script:PinMinLength = 6
$script:PinMaxLength = 20

# Channel name has a space and differs from the provider name. Microsoft's Intune
# docs cite "Microsoft-Windows-BitLocker-API/Management", which does not exist on
# the device; this is the real channel.
$script:BitLockerLog = 'Microsoft-Windows-BitLocker/BitLocker Management'

# Locale-independent principals. Never use English names here: on a German
# Windows, icacls 'BUILTIN\Administrators' fails with 1332 ("No mapping between
# account names and security IDs was done") and leaves the ACL untouched.
$script:SidSystem         = '*S-1-5-18'
$script:SidAdministrators = '*S-1-5-32-544'

function Write-PinLog {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO','WARN','ERROR')][string] $Level = 'INFO',
        [string] $Path = $script:LogFile
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($Path) { try { Add-Content -LiteralPath $Path -Value $line -Encoding UTF8 } catch { } }
    Write-Host $line
}

function Get-DerivedStartupPin {
    <#
    .SYNOPSIS
        Derives the initial startup PIN from the device name.

    .DESCRIPTION
        Scheme: <Prefix><device number, zero-padded to NumberLength>

            WKH-0051   -> 111 + 0051  -> 1110051
            WKH-00051  -> 111 + 0051  -> 1110051    (same device number, 51)
            WKH-10051  -> 111 + 10051 -> 11110051   (number wider than the pad)

        The device number is the trailing digit run of the computer name, read as
        an integer (so leading zeros never change the value) and then padded back
        out to NumberLength. Padding the numeric value rather than truncating the
        raw string is what keeps 00051 and 10051 from colliding.

        This PIN is deliberately reproducible by the service desk from the asset
        tag alone - that is the point of the scheme - which also means it is
        guessable by anyone who knows it. It is an ENROLMENT PIN: users are told
        it and told to change it.

    .OUTPUTS
        [pscustomobject] Pin, DeviceNumber, Source
    #>
    [CmdletBinding()]
    param(
        [string] $ComputerName = $env:COMPUTERNAME,
        [string] $Prefix       = '111',
        [ValidateRange(1,19)]
        [int]    $NumberLength = 4,

        # Devices whose name carries no digits normally mean "not in the asset
        # naming scheme" - fail loudly so someone fixes the name or excludes the
        # device, rather than silently assigning a PIN nobody can reproduce.
        [switch] $AllowHashFallback
    )

    if ($Prefix -notmatch '^[0-9]*$') {
        throw "PIN prefix must contain digits only (pre-boot input is numeric): '$Prefix'"
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        throw 'Computer name is empty - cannot derive a PIN.'
    }

    $source   = 'DeviceNumber'
    $trailing = [regex]::Match($ComputerName, '([0-9]+)\s*$')   # does not populate $Matches

    if ($trailing.Success) {
        $number = [uint64]::Parse($trailing.Groups[1].Value)
        $digits = ([string]$number).PadLeft($NumberLength, '0')
    }
    elseif ($AllowHashFallback) {
        # Deterministic, but NOT reproducible from the asset tag by hand. Only
        # reachable when explicitly opted in.
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($ComputerName.ToUpperInvariant())) }
        finally { $sha.Dispose() }
        $acc = [uint64]0
        for ($i = 0; $i -lt 8; $i++) { $acc = ($acc * 256) + $bytes[$i] }
        $modulus = [uint64][Math]::Pow(10, $NumberLength)
        $digits  = ([string]($acc % $modulus)).PadLeft($NumberLength, '0')
        $source  = 'NameHash'
    }
    else {
        throw "Computer name '$ComputerName' has no trailing device number and -AllowHashFallback was not specified."
    }

    $pin = $Prefix + $digits

    if ($pin.Length -lt $script:PinMinLength) {
        throw "Derived PIN is $($pin.Length) digits; BitLocker requires at least $($script:PinMinLength). Lengthen -PinPrefix or -DeviceNumberLength."
    }
    if ($pin.Length -gt $script:PinMaxLength) {
        throw "Derived PIN is $($pin.Length) digits; BitLocker allows at most $($script:PinMaxLength)."
    }
    if ($pin -notmatch '^[0-9]+$') { throw "Derived PIN is not numeric: '$pin'" }

    [pscustomobject]@{ Pin = $pin; DeviceNumber = $digits; Source = $source }
}

function ConvertTo-PinSecureString {
    param([Parameter(Mandatory)][string] $Pin)
    ConvertTo-SecureString -String $Pin -AsPlainText -Force
}

function Get-FvePolicyPlan {
    <#
    .SYNOPSIS
        The FVE values the installer writes, and why each one is safe.

    .DESCRIPTION
        UseTPM / UseTPMPIN / UseTPMKey / UseTPMKeyPIN: 0 = disallow, 1 = require,
        2 = allow.

        UseTPM is deliberately 2 and never 0. These values gate protector
        CREATION, so UseTPM=0 makes every TPM-only fallback fail: the rollback
        after a failed PIN add, Enable-BitLocker on a decrypted drive, and the
        uninstall's protector restore. "Require a PIN" belongs in a compliance
        policy - a policy that blocks the recovery path is worse than a device
        without a PIN. UseTPMPIN is 2 (allow) rather than 1 (require) for the
        same reason.
    #>
    [CmdletBinding()]
    param([ValidateRange(6,20)][int] $MinimumPin = 6)

    # Deliberately NOT written: UseTPMKey and UseTPMKeyPIN. Those govern the
    # startup-key (USB) protector variants, which this app never creates, so setting
    # them buys nothing - and the Intune BitLocker CSP commonly sets them to 0
    # ("do not allow"). Writing 2 there just starts a tug-of-war that the CSP wins on
    # every sync, and produces event 851 "the Group Policy settings for BitLocker
    # startup options are in conflict".
    [ordered]@{
        UseAdvancedStartup                     = 1   # required, else the PIN add fails outright
        EnableBDEWithNoTPM                     = 0
        UseTPM                                 = 2   # allow - never 0, see above
        UseTPMPIN                              = 2   # allow
        MinimumPIN                             = $MinimumPin
        UseEnhancedPin                         = 0   # digits only: pre-boot keyboard is always US layout
        OSEnablePrebootInputProtectorsOnSlates = 1   # tablets with no physical keyboard
        DisallowStandardUserPINReset           = 0   # users may change their own PIN (set explicitly; the default is disputed)
    }
}

function Set-FvePolicyValue {
    <#
    .SYNOPSIS
        Writes one FVE value, returning what was there before.

    .DESCRIPTION
        Never New-Item -Force on the FVE key: the registry provider recreates the
        key and destroys every value already in it - including the Intune
        BitLocker CSP's settings (OSRequireActiveDirectoryBackup,
        EncryptionMethodWithXtsOs, ...).
    #>
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][int]    $Value
    )
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }

    $existing = $null
    $had      = $false
    try {
        $existing = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        $had = $true
    } catch { }

    Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type DWord -Force
    [pscustomobject]@{ Name = $Name; Existed = $had; PreviousValue = $existing }
}

function Assert-SafeDirectory {
    <#
    .SYNOPSIS
        Creates or validates a directory that will hold code executed as SYSTEM.

    .DESCRIPTION
        Closes two attacks:
          * Pre-creation. Under %ProgramData% any standard user can create the
            folder first and, as CREATOR OWNER, keep implicit WRITE_DAC - so they
            can re-grant themselves write access after icacls runs and swap the
            script SYSTEM executes. %ProgramFiles% is not user-writable, which is
            why the payload lives there; this check enforces it anyway.
          * Junctions. A directory junction needs no privilege to create. If the
            staging path is a junction to System32, SYSTEM writes the payload
            there and 'icacls /T' rewrites that tree's ACL.
    #>
    param(
        [Parameter(Mandatory)][string] $Path,

        # SYSTEM, Administrators, or TrustedInstaller. A directory owned by anyone
        # else - in particular by a member of Users - is the pre-creation attack
        # this guard exists to catch. TrustedInstaller is included because it owns
        # many folders Windows itself creates under %ProgramFiles%, so a sibling
        # app or a servicing operation must not hard-fail our install.
        # Overridable so the test suite can exercise the accept path without
        # elevation; production never passes it.
        [string[]] $AllowedOwnerSid = @(
            'S-1-5-18',
            'S-1-5-32-544',
            'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        )
    )

    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing to use '$Path': it is a reparse point (junction/symlink)."
        }
        # Distinguish "cannot read the ACL" from "wrong owner". Both used to surface
        # as one opaque message ("Attempted to perform an unauthorized operation"),
        # which says nothing about which check failed or under whose identity.
        try   { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
        catch { throw "Refusing to use '$Path': its ACL could not be read ($($_.Exception.Message)). Identity: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)." }

        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $AllowedOwnerSid) {
            throw "Refusing to use '$Path': unexpected owner SID '$owner' (allowed: $($AllowedOwnerSid -join ', '))."
        }
    }
    else {
        New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    }
}

function Protect-Directory {
    <#
    .SYNOPSIS
        SYSTEM + Administrators only, inheritance removed, ownership reset.
        Throws on failure instead of silently leaving the folder wide open.
    #>
    param([Parameter(Mandatory)][string] $Path)

    # Grant on the FOLDER only - deliberately no /T here.
    #
    # (OI)(CI) are inheritance flags. Pushing them onto files with /T sets ACEs that
    # are inherit-only on a leaf object, which grant nothing on the file itself: the
    # staged scripts end up with no effective permissions for anyone, and the next
    # install fails with "Access to the path ... is denied" while overwriting its own
    # payload. The first install always worked (files were created before hardening),
    # every one after it failed - a genuinely confusing symptom.
    & icacls.exe $Path /inheritance:r /grant:r "$($script:SidSystem):(OI)(CI)F" "$($script:SidAdministrators):(OI)(CI)F" /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed to harden '$Path' (exit $LASTEXITCODE) - refusing to register a SYSTEM task against it."
    }

    # Existing children may still carry their own explicit (or inherit-only) ACLs
    # from a previous version, so reset them to inherit from the folder above.
    if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -gt 0) {
        & icacls.exe "$Path\*" /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-PinLog "icacls /reset on the children of '$Path' returned $LASTEXITCODE (continuing)." 'WARN'
        }
    }
    & icacls.exe $Path /setowner $script:SidAdministrators /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to set owner on '$Path' (exit $LASTEXITCODE)." }

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Inheritance is still enabled on '$Path' after hardening."
    }
    foreach ($ace in $acl.Access) {
        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @('S-1-5-18','S-1-5-32-544')) {
            throw "Unexpected ACE for '$sid' remains on '$Path'."
        }
    }
}

function Remove-DirectorySafely {
    <#
    .SYNOPSIS
        Deletes a directory without following a junction to its target.

    .DESCRIPTION
        Remove-Item -Recurse -Force in PowerShell 5.1 traverses reparse points and
        deletes the TARGET's contents. 'rd /s' does not.
    #>
    param([Parameter(Mandatory)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        [IO.Directory]::Delete($Path, $false)
        return
    }
    & cmd.exe /c rd /s /q "$Path" 2>$null | Out-Null
}

function Get-TpmFamilyProtector {
    param([Parameter(Mandatory)] $Volume, [Parameter(Mandatory)][string[]] $Type)
    @($Volume.KeyProtector | Where-Object { $Type -contains [string]$_.KeyProtectorType })
}

function Test-RecoveryEscrow {
    <#
    .SYNOPSIS
        Was this recovery protector escrowed to Entra ID?
        $true = yes, $false = no evidence, $null = cannot tell.

    .DESCRIPTION
        No registry marker records escrow, and the cmdlet succeeding is not proof
        the service stored it. Event 845 = backed up, 846 = failed; both carry the
        protector GUID. Local triage only - Graph
        (Get-MgInformationProtectionBitlockerRecoveryKey) is the real answer.

        The three-state return matters, and getting it right is fiddly:
        Get-WinEvent THROWS ("No events were found that match the specified
        selection criteria") when a filter matches nothing. So a naive
        try/catch -> $null makes "this device has never escrowed anything" -
        the dangerous case - indistinguishable from "the log is unreadable", and
        any caller that treats $null as "carry on" then swaps protectors on a
        device whose recovery key exists nowhere but the volume itself.

        Hence: probe the log's existence first, and only report $null when the log
        genuinely cannot be read.
    #>
    param([Parameter(Mandatory)][string] $KeyProtectorId)

    $id = $KeyProtectorId.Trim('{','}')

    # Is the log there and readable at all?
    try { Get-WinEvent -ListLog $script:BitLockerLog -ErrorAction Stop | Out-Null }
    catch { return $null }

    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $script:BitLockerLog; Id = 845 } `
                                 -MaxEvents 200 -ErrorAction Stop)
    }
    catch {
        # Either there are no 845 events, or reading failed. The log exists (probed
        # above), so treat a filter miss as a definite "no evidence".
        return $false
    }

    foreach ($e in $events) {
        if ($e.Message -and $e.Message -match [regex]::Escape($id)) { return $true }
    }
    $false
}

function Invoke-WithStartupAuthRelaxed {
    <#
    .SYNOPSIS
        Runs a script block with the FVE startup-authentication policy temporarily
        set to "allow", then restores the previous values.

    .DESCRIPTION
        BitLocker validates the volume's whole protector set against policy on ANY
        protector change, so a device that is already non-compliant cannot be
        repaired while that policy is in force. Seen in the field: a tenant profile
        sets UseTPM = 0 ("do not allow TPM") and UseTPMPIN = 1 ("require a PIN"),
        the volume still has only a Tpm protector, and every operation - including
        merely adding the recovery password - fails with

            0x80310061 FVE_E_POLICY_REQUIRES_STARTUPPIN
            "Group Policy settings require the use of a PIN at startup."

        That is a deadlock: the PIN add is precisely what would make the volume
        compliant, and policy will not let us get there.

        The same applies to every path that must recreate a plain TPM protector -
        self-heal after an interrupted swap, rollback after a failed PIN add,
        uninstall rollback - because protector CREATION is what policy gates.

        So both values are relaxed to 2 (allow) for the duration of the call and
        always restored, including on failure. The end state this enables (TpmPin
        present, Tpm gone) satisfies the strict policy anyway; the relaxation only
        opens the window needed to reach it. Values that were absent stay absent.
    #>
    param([Parameter(Mandatory)][scriptblock] $Body)

    $fve   = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $saved = @{}
    try {
        foreach ($name in @('UseTPM','UseTPMPIN')) {
            try {
                $saved[$name] = (Get-ItemProperty -LiteralPath $fve -Name $name -ErrorAction Stop).$name
                if ($saved[$name] -ne 2) {
                    Set-ItemProperty -LiteralPath $fve -Name $name -Value 2 -Type DWord -Force
                }
            } catch { }   # absent: leave it absent, the default already allows
        }
        & $Body
    }
    finally {
        foreach ($name in @($saved.Keys)) {
            if ($saved[$name] -ne 2) {
                try { Set-ItemProperty -LiteralPath $fve -Name $name -Value $saved[$name] -Type DWord -Force } catch { }
            }
        }
    }
}

function Get-BrandXaml {
    <#
    .SYNOPSIS
        XAML fragments for the OPTIONAL brand images used by the two windows.

    .DESCRIPTION
        Branding is a drop-in, never a dependency. Put your own PNGs next to the
        dialog under the documented names (see README, "Branding") and they are
        staged and used automatically; supply none and the windows fall back to a
        text wordmark on a solid colour, with the same layout and the same
        behaviour.

        The fragments are BUILT rather than switched on inside the markup,
        because WPF resolves <Image Source="..."/> while the XAML is being
        parsed: a path that does not exist makes XamlReader.Load throw, which
        would take the whole PIN dialog down over a missing logo. An element that
        is never emitted cannot fail to load.

        Window Icon gets the same treatment for the same reason, and is omitted
        entirely rather than left empty - Icon="" is itself a parse error.

    .OUTPUTS
        [pscustomobject] WindowIcon, Backdrop, DialogMark, DialogFooter,
        NoticeMark, NoticeFooter. Each is an XAML fragment, or an empty string
        when there is nothing sensible to draw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Root,

        # Drawn as the wordmark when no logo image is available.
        [string] $BrandName = 'WK-Hub',

        # Fills the rail when no background image is available. Same value as the
        # window background, so the unbranded window looks deliberate, not broken.
        [string] $BrandColour = '#FF16121F'
    )

    $background = Join-Path $Root 'brand-background.png'
    $square     = Join-Path $Root 'brand-logo-square.png'
    $wide       = Join-Path $Root 'brand-logo-on-dark.png'

    # These land in XML attribute values, so escape whatever the paths and the
    # operator-supplied name happen to contain.
    $xBackground = [Security.SecurityElement]::Escape($background)
    $xSquare     = [Security.SecurityElement]::Escape($square)
    $xWide       = [Security.SecurityElement]::Escape($wide)
    $xName       = [Security.SecurityElement]::Escape($BrandName)

    $icon = if (Test-Path -LiteralPath $square) { ' Icon="{0}"' -f $xSquare } else { '' }

    $backdrop = if (Test-Path -LiteralPath $background) {
        '<Image Source="{0}" Stretch="UniformToFill" HorizontalAlignment="Right"/><Border Background="#B316121F"/>' -f $xBackground
    } else {
        '<Border Background="{0}"/>' -f $BrandColour
    }

    # Top of the rail. Laid out by the surrounding StackPanel in the PIN dialog,
    # and positioned absolutely in the smaller notice window - hence two variants
    # of the same idea.
    $dialogMark = if (Test-Path -LiteralPath $square) {
        '<Image Source="{0}" Width="52" HorizontalAlignment="Left" Margin="0,0,0,26"/>' -f $xSquare
    } else {
        '<TextBlock Text="{0}" Foreground="#FFFFFFFF" FontSize="22" FontWeight="Bold" HorizontalAlignment="Left" Margin="0,0,0,26"/>' -f $xName
    }
    $noticeMark = if (Test-Path -LiteralPath $square) {
        '<Image Source="{0}" Width="46" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="26,28,0,0"/>' -f $xSquare
    } else {
        '<TextBlock Text="{0}" Foreground="#FFFFFFFF" FontSize="20" FontWeight="Bold" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="26,28,0,0"/>' -f $xName
    }

    # Bottom of the rail. No text stand-in here on purpose: the wordmark above
    # already names the vendor, and a second copy of it reads as a mistake.
    $dialogFooter = if (Test-Path -LiteralPath $wide) {
        '<Image Source="{0}" Width="104" HorizontalAlignment="Left" VerticalAlignment="Bottom" Margin="30,0,0,26"/>' -f $xWide
    } else { '' }
    $noticeFooter = if (Test-Path -LiteralPath $wide) {
        '<Image Source="{0}" Width="92" HorizontalAlignment="Left" VerticalAlignment="Bottom" Margin="26,0,0,24"/>' -f $xWide
    } else { '' }

    [pscustomobject]@{
        WindowIcon   = $icon
        Backdrop     = $backdrop
        DialogMark   = $dialogMark
        DialogFooter = $dialogFooter
        NoticeMark   = $noticeMark
        NoticeFooter = $noticeFooter
    }
}

function Get-ConsoleSessionId {
    <#
    .SYNOPSIS
        Session ID of the physical console session, or $null if it cannot be told.

    .DESCRIPTION
        Used to make sure the PIN dialog only ever renders for the person actually
        sitting at the machine. ServiceUI attaches to the first explorer.exe it
        finds, which with fast user switching or an RDP session can belong to a
        different, lower-trust user - who would then choose the PIN that every user
        of the device must type at boot.

        WTSGetActiveConsoleSessionId is the authoritative answer, but reaching it
        through Add-Type -MemberDefinition invokes the C# compiler: csc.exe is
        spawned, intermediate files are written to %TEMP% (C:\Windows\Temp for a
        SYSTEM task) and an unsigned assembly is loaded. On a hardened fleet - the
        kind that mandates a pre-boot PIN - EDR killing that spawn, WDAC refusing
        the unsigned output, or a full/ACL-broken %TEMP% are all realistic. So
        there is a compile-free fallback, and callers must treat $null as "do not
        prompt" rather than "carry on".
    #>
    try {
        Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();' `
                 -Name 'Wts' -Namespace 'Native' -ErrorAction Stop
        $id = [int][Native.Wts]::WTSGetActiveConsoleSessionId()
        if ($id -ge 0 -and $id -ne 0xFFFFFFFF) { return $id }
    } catch { }

    # Fallback: no compiler needed. LogonUI owns the console session's desktop
    # while it is locked, and explorer.exe hosts it once unlocked, so the console
    # session is the one running exactly those shell processes.
    try {
        $sessions = @(Get-Process -Name 'explorer','LogonUI' -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty SessionId -Unique |
                      Where-Object { $_ -ne 0 })
        if ($sessions.Count -eq 1) { return [int]$sessions[0] }
    } catch { }

    $null
}

function Test-PinChangedByUser {
    <#
    .SYNOPSIS
        Has anyone changed the PIN since it was assigned?

    .DESCRIPTION
        ChangePIN keeps the same protector GUID ("The new protector will have the
        same GUID"), so comparing a stored KeyProtectorId with the current one
        detects nothing. Event 777 ("The PIN was updated...", carries the
        protector GUID) and 789 ("The PIN was changed.") are the only reliable
        signals. The log caps near 1 MB and rolls, so absence is not proof.
    #>
    param([datetime] $Since)

    $filter = @{ LogName = $script:BitLockerLog; Id = @(777, 789) }
    if ($Since) { $filter['StartTime'] = $Since }
    try { @(Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction Stop).Count -gt 0 }
    catch { $false }
}
