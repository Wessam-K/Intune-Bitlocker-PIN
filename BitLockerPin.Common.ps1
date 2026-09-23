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
      * the self-service reset: its three gates (identity, throttle,
        re-authentication) and its audit trail

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

            DEV-0051   -> 111 + 0051  -> 1110051
            DEV-00051  -> 111 + 0051  -> 1110051    (same device number, 51)
            DEV-10051  -> 111 + 10051 -> 11110051   (number wider than the pad)

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

function Set-BrandedTitleBar {
    <#
    .SYNOPSIS
        Paints the native Windows 11 title bar to match the window body.

    .DESCRIPTION
        A window whose body is near-black under a stock light caption looks
        half-finished. DWM exposes caption, text and border colour on build
        22000+, so the real minimise and close buttons, the drag behaviour,
        snapping and accessibility all keep working - a hand-rolled caption bar
        would lose every one of those. Older builds ignore the call and keep the
        default caption, which is why nothing here is fatal.

        Every window calls this, so the Add-Type is guarded: a second call with
        the same namespace and name throws, and an unguarded throw here would
        take down whichever window happened to open second.

    .PARAMETER Window
        The WPF window. Colours are applied once its handle exists.

    .PARAMETER Colour
        #RRGGBB. COLORREF is 0x00BBGGRR, so the bytes are reversed here rather
        than at each call site, where a hand-swapped literal goes unnoticed
        until someone wonders why the caption is the wrong colour.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Window,
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')]
        [string] $Colour = '#16121F'
    )

    try {
        if (-not ('Native.Dwm' -as [type])) {
            Add-Type -Namespace 'Native' -Name 'Dwm' -MemberDefinition @'
[DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int value, int size);
'@ -ErrorAction Stop
        }

        $r = [Convert]::ToInt32($Colour.Substring(1, 2), 16)
        $g = [Convert]::ToInt32($Colour.Substring(3, 2), 16)
        $b = [Convert]::ToInt32($Colour.Substring(5, 2), 16)
        $colorRef = ($b -shl 16) -bor ($g -shl 8) -bor $r

        $Window.Add_SourceInitialized({
            try {
                $hwnd    = (New-Object Windows.Interop.WindowInteropHelper $Window).Handle
                $caption = $colorRef
                $text    = 0xFFFFFF
                [Native.Dwm]::DwmSetWindowAttribute($hwnd, 35, [ref]$caption, 4) | Out-Null  # DWMWA_CAPTION_COLOR
                [Native.Dwm]::DwmSetWindowAttribute($hwnd, 36, [ref]$text,    4) | Out-Null  # DWMWA_TEXT_COLOR
                [Native.Dwm]::DwmSetWindowAttribute($hwnd, 34, [ref]$caption, 4) | Out-Null  # DWMWA_BORDER_COLOR
            } catch { }
        }.GetNewClosure())
    }
    catch { }
}

function Get-BrandXaml {
    <#
    .SYNOPSIS
        XAML fragments for the OPTIONAL brand images used by the windows.

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

# ======================================================================
# Self-service PIN reset
#
# Windows' own "change PIN" needs the OLD PIN, so it is no help to someone who
# has forgotten it. Replacing the protector is the only route, and that needs
# admin rights a standard user does not have - hence a SYSTEM task they are
# allowed to start.
#
# Three gates stand between "any signed-in user" and "replace the PIN every
# user of this device must type at boot", and each fails CLOSED: the caller
# must be the device's enrolled user, the device must be under its reset limit,
# and the person at the keyboard must prove who they are - with Windows Hello,
# or with their Windows password where Hello cannot run.
# ======================================================================

function Get-EnrolledUpn {
    <#
    .SYNOPSIS
        UPN of the account that enrolled this device into Intune, or $null.

    .DESCRIPTION
        The closest thing to Intune's "primary user" that can be read locally.

        Intune's primaryUser field lives in Graph and needs a token, which a SYSTEM
        task on a laptop with no network cannot get. The MDM enrolment key carries
        the enrolling user's UPN and is written during user-driven enrolment
        (Autopilot user-driven, or a user joining the device from Settings) - and
        for a device enrolled that way the two agree.

        Where they disagree: a device handed to a new owner without re-enrolment
        keeps the old UPN, and a device enrolled by a service account (a device
        enrolment manager, a provisioning package, self-deploying Autopilot)
        carries that account or none. Self-service is refused on both. That is the
        intended direction of failure. Being sent to the service desk is
        recoverable; letting any signed-in user re-PIN a device that is not theirs
        is not.
    #>
    try {
        foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop)) {
            # A real MDM enrolment carries both values. The numeric subkeys beneath
            # them are per-resource and carry neither.
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p.UPN -and $p.ProviderID) { return [string]$p.UPN }
        }
    } catch { }
    $null
}

function Get-ConsoleUser {
    <#
    .SYNOPSIS
        SID and UPN of the person at the physical console, or $null if unknowable.

    .DESCRIPTION
        Built on Get-ConsoleSessionId rather than on whoever owns the explorer.exe
        ServiceUI happened to attach to: with fast user switching or an RDP session
        those differ, and the wrong answer here would let a lower-trust user reset
        the PIN every user of the device must type at boot.

        $null means "cannot tell", and every caller must treat it as a refusal.
    #>
    $id = Get-ConsoleSessionId
    if ($null -eq $id) { return $null }

    $sid = $null
    try {
        $proc = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe' AND SessionId=$id" -ErrorAction Stop)[0]
        if ($proc) { $sid = (Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop).Sid }
    } catch { }
    if (-not $sid) { return $null }

    # IdentityStore is where Windows caches the UPN of an Entra account. A local
    # account has no entry, and that absence is the correct answer rather than a
    # failure: a local account is never the Intune primary user.
    $upn = $null
    try {
        $p = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$sid\IdentityCache\$sid" -ErrorAction Stop
        if ($p.UserName) { $upn = [string]$p.UserName }
    } catch { }

    [pscustomobject]@{ SessionId = $id; Sid = $sid; Upn = $upn }
}

function Test-ConsoleUserIsPrimary {
    <#
    .SYNOPSIS
        Is the person at the console the device's own user? Fails closed.
    #>
    param([string] $EnrolledUpn, $ConsoleUser)

    if (-not $EnrolledUpn)     { Write-PinLog 'No MDM enrolment UPN on this device - cannot establish the primary user.' 'WARN'; return $false }
    if (-not $ConsoleUser)     { Write-PinLog 'Console session could not be identified.' 'WARN'; return $false }
    if (-not $ConsoleUser.Upn) { Write-PinLog "Console user $($ConsoleUser.Sid) has no cached UPN - a local account is never the primary user." 'WARN'; return $false }

    $match = $ConsoleUser.Upn.Trim() -ieq $EnrolledUpn.Trim()
    if (-not $match) { Write-PinLog "Console user $($ConsoleUser.Upn) is not the enrolled user $EnrolledUpn." 'WARN' }
    $match
}

function Test-WindowsPassword {
    <#
    .SYNOPSIS
        Validates a password against an account. $true only on a genuine logon.

    .DESCRIPTION
        The fallback re-authentication, used only when Windows Hello cannot run.

        LOGON32_LOGON_INTERACTIVE validates against cached credentials, so this
        works on a laptop with no line of sight to Entra - which is exactly the
        machine whose user is locked out and needs a new PIN. It needs a cached
        password verifier, though, and Windows only holds one for an account that
        has signed in to this device with its password. On an Entra-joined device
        whose user has only ever used Windows Hello there is none, and LogonUser
        answers ERROR_LOGON_FAILURE (1326) even for the correct password. That is
        why Hello is asked first.

        The password goes SecureString -> unmanaged BSTR -> the API and is
        zero-freed. It never becomes a System.String, which cannot be zeroed and
        would linger in this long-lived SYSTEM process's heap, the page file and
        any crash dump. Same reasoning as Test-PinSecure.

        Add-Type invokes the C# compiler, which on a hardened fleet can be blocked
        by EDR or WDAC - the risk Get-ConsoleSessionId documents. There is no
        compile-free way to verify a credential, so this fails CLOSED: no
        verification means no reset.
    #>
    param(
        [Parameter(Mandatory)][string]       $Upn,
        [Parameter(Mandatory)][securestring] $Password
    )

    try {
        Add-Type -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, IntPtr password, int logonType, int logonProvider, out IntPtr token);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr handle);
'@ -Name 'Logon' -Namespace 'PinAuth' -ErrorAction Stop
    }
    catch {
        Write-PinLog "Cannot verify the password - P/Invoke unavailable: $($_.Exception.Message)" 'ERROR'
        return $false
    }

    $ptr   = [IntPtr]::Zero
    $token = [IntPtr]::Zero
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Password)
        # Domain $null with a UPN-form username is what binds for an Entra account.
        $ok = [PinAuth.Logon]::LogonUser($Upn, $null, $ptr, 2, 0, [ref]$token)
        if (-not $ok) {
            Write-PinLog "Password check failed for $Upn (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))." 'WARN'
        }
        [bool]$ok
    }
    catch {
        Write-PinLog "Password check errored: $($_.Exception.Message)" 'ERROR'
        $false
    }
    finally {
        if ($ptr   -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
        if ($token -ne [IntPtr]::Zero) { [void][PinAuth.Logon]::CloseHandle($token) }
    }
}

function Write-PinAudit {
    <#
    .SYNOPSIS
        Records a reset decision to prompt.log and to the Application event log.

    .DESCRIPTION
        prompt.log stays on the device and is only ever read after someone has
        already gone looking. The Application log is what a collector can pick
        up - Azure Monitor Agent, Windows Event Forwarding, a SIEM forwarder - so
        the event is what makes a reset queryable across every device: the
        difference between a reset being knowable and not.

        The source is created by the installer, which runs as SYSTEM. If it is
        missing the local log still gets the line: auditing must never be the
        thing that fails an operation that otherwise worked.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ResetAllowed','ResetDenied','ResetThrottled','ResetCompleted','ResetFailed')]
        [string] $Action,
        [string] $Detail       = '',
        # Must match the other scripts: the event source is named after it.
        [string] $Organization = 'WK-Hub'
    )

    $ids  = @{ ResetAllowed = 3200; ResetDenied = 3201; ResetThrottled = 3202; ResetCompleted = 3203; ResetFailed = 3204 }
    $bad  = $Action -in 'ResetDenied','ResetThrottled','ResetFailed'
    Write-PinLog "AUDIT $Action - $Detail" $(if ($bad) { 'WARN' } else { 'INFO' })

    try {
        $src = "$Organization-BitLockerPin"
        if ([System.Diagnostics.EventLog]::SourceExists($src)) {
            Write-EventLog -LogName Application -Source $src -EventId $ids[$Action] `
                           -EntryType $(if ($bad) { 'Warning' } else { 'Information' }) `
                           -Message "BitLocker PIN $Action. $Detail" -ErrorAction Stop
        }
    } catch { Write-PinLog "Could not write the audit event: $($_.Exception.Message)" 'WARN' }
}

function Test-PinResetAllowed {
    <#
    .SYNOPSIS
        Throttle. $false once the device has had $MaxPerDay resets in 24 hours.

    .DESCRIPTION
        A legitimate user forgets a PIN once. Repeated resets are either someone
        probing, or a user who has not understood the dialog and is on their way to
        locking themselves out for good - both are better served by the service
        desk than by another attempt.

        Only COMPLETED resets count (Add-PinResetRecord writes them), so a refused
        or abandoned attempt never uses up the day's allowance.

        Fails CLOSED, like the other two gates. An unreadable counter is a support
        case, not a reason to allow unlimited resets - and whoever is asking has
        already reached Windows, so sending them to the service desk strands
        nobody. Only a key or value that does not exist yet reads as "no resets";
        a read that fails for any other reason refuses, and so does a history
        that is not what Add-PinResetRecord writes: an entry that is not a date
        counts as a recent reset rather than being skipped.
    #>
    param(
        [Parameter(Mandatory)][string] $RegKey,
        [int] $MaxPerDay = 3
    )
    try {
        # -ErrorAction Stop, not SilentlyContinue: an access-denied read has to be
        # told apart from "nothing recorded yet", and SilentlyContinue makes both $null.
        $p = Get-ItemProperty -LiteralPath $RegKey -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $true      # the key does not exist yet: no resets yet
    }
    catch {
        Write-PinLog "Could not read the reset history - refusing: $($_.Exception.Message)" 'WARN'
        return $false
    }

    try {
        $history = $p.ResetHistory
        if ($null -eq $history) { return $true }     # no value yet: no resets yet
        if ($history -isnot [string] -and $history -isnot [string[]]) {
            Write-PinLog "The reset history is a $($history.GetType().Name), not a list of dates - refusing." 'WARN'
            return $false
        }

        $cutoff = (Get-Date).AddDays(-1)
        $recent = 0
        foreach ($entry in @($history)) {
            $when = $null
            try { $when = [datetime]::ParseExact($entry, 's', [Globalization.CultureInfo]::InvariantCulture) } catch { }
            if ($null -eq $when -or $when -gt $cutoff) { $recent++ }
        }
        if ($recent -ge $MaxPerDay) {
            Write-PinLog "Reset throttled: $recent resets in the last 24 hours (limit $MaxPerDay)." 'WARN'
            return $false
        }
        $true
    }
    catch {
        Write-PinLog "Could not evaluate the reset history - refusing: $($_.Exception.Message)" 'WARN'
        $false
    }
}

function Add-PinResetRecord {
    <#
    .SYNOPSIS
        Stamps a completed reset into the registry for fleet-wide reporting.

    .DESCRIPTION
        ResetCount and LastResetOn are what an Intune detection script can surface
        across every device; ResetHistory is trimmed to 30 days so the value cannot
        grow without bound. Bookkeeping only - never fails the caller.
    #>
    param([Parameter(Mandatory)][string] $RegKey)
    try {
        if (-not (Test-Path $RegKey)) { New-Item -Path $RegKey -Force | Out-Null }
        $p = Get-ItemProperty -LiteralPath $RegKey -ErrorAction SilentlyContinue

        $cutoff = (Get-Date).AddDays(-30)
        $hist = @()
        if ($p.ResetHistory) {
            $hist = @($p.ResetHistory | Where-Object { try { [datetime]$_ -gt $cutoff } catch { $false } })
        }
        $hist += (Get-Date -Format 's')

        New-ItemProperty -Path $RegKey -Name 'ResetHistory' -Value $hist -PropertyType MultiString -Force | Out-Null
        New-ItemProperty -Path $RegKey -Name 'LastResetOn'  -Value (Get-Date -Format 's') -PropertyType String -Force | Out-Null
        $count = 0; if ($p.ResetCount) { $count = [int]$p.ResetCount }
        New-ItemProperty -Path $RegKey -Name 'ResetCount'   -Value ($count + 1) -PropertyType DWord -Force | Out-Null
    } catch { Write-PinLog "Could not record the reset: $($_.Exception.Message)" 'WARN' }
}

$script:HelloVerifierScript = @'
# Windows Hello verifier. Runs in the CONSOLE USER's session, never as SYSTEM.
# Results: 0 verified, 1 declined by the user, 2 Hello unusable here,
# 3 error, 4 shown but never answered.
#
# Every result is reported twice: over the named pipe the SYSTEM caller created
# for this one process, and as the exit code. The caller trusts neither alone.
# Anything else running as this user can end this process with whatever exit
# code it likes, so a report only counts if it arrives over a connection made
# by this process's own PID - and the exit code agrees with it.
$ErrorActionPreference = 'Stop'

function Send-Result([int] $Code) {
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '__PIPE__', [System.IO.Pipes.PipeDirection]::Out)
        $c.Connect(5000)
        $b = [Text.Encoding]::ASCII.GetBytes("BLPIN-HELLO:$Code")
        $c.Write($b, 0, $b.Length)
        $c.Flush()
        $c.Dispose()
    } catch { }
    exit $Code
}

try {
    Add-Type -AssemblyName PresentationFramework, WindowsBase

    # Declared without any WinRT references so it compiles on a machine that has
    # no Windows SDK. The async operation comes back as a raw IInspectable and is
    # driven over COM directly - that also avoids needing the
    # System.Runtime.WindowsRuntime projection assembly, which is not loaded by
    # default and cannot be relied on being present.
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace PinAuth
{
    [ComImport, Guid("39E050C3-4E74-441A-8DC0-B81104DF949C"),
     InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
    public interface IUserConsentVerifierInterop
    {
        [return: MarshalAs(UnmanagedType.IInspectable)]
        object RequestVerificationForWindowAsync(
            IntPtr appWindow,
            [MarshalAs(UnmanagedType.HString)] string message,
            ref Guid riid);
    }

    // Methods sit in vtable order after the three IInspectable slots; the names
    // are arbitrary, the order is what binds.
    [ComImport, Guid("00000036-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
    public interface IAsyncInfo
    {
        uint get_Id();
        int  get_Status();      // 0 Started, 1 Completed, 2 Canceled, 3 Error
        int  get_ErrorCode();
        void Cancel();
        void Close();
    }

    [ComImport, Guid("fd596ffd-2318-558f-9dbe-d21df43764a5"),
     InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
    public interface IAsyncOperationConsent
    {
        void   put_Completed(IntPtr handler);
        IntPtr get_Completed();
        int    GetResults();    // UserConsentVerificationResult; 0 == Verified
    }

    public static class Hello
    {
        // PowerShell will not QueryInterface a raw __ComObject onto a ComImport
        // interface, so every cast has to happen on this side.
        public static object RequestForWindow(object factory, IntPtr hwnd, string message, Guid riid)
        {
            return ((IUserConsentVerifierInterop) factory)
                   .RequestVerificationForWindowAsync(hwnd, message, ref riid);
        }
        public static int  Status(object op)    { return ((IAsyncInfo) op).get_Status(); }
        public static int  Results(object op)   { return ((IAsyncOperationConsent) op).GetResults(); }
        public static void Close(object op)     { ((IAsyncInfo) op).Close(); }
    }
}
"@

    function Invoke-DoEvents {
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
            [System.Windows.Threading.DispatcherPriority]::Background,
            [System.Windows.Threading.DispatcherOperationCallback] { param($f) $f.Continue = $false; return $null },
            $frame) | Out-Null
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    }

    $null    = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
    $uvType  = [Windows.Security.Credentials.UI.UserConsentVerifier]
    $iid     = $uvType.GetMethod('RequestVerificationAsync').ReturnType.GUID
    $factory = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeMarshal]::GetActivationFactory($uvType)

    # The prompt parents to a window handle. Without one the call is accepted and
    # then never completes - which is exactly how the plain WinRT
    # RequestVerificationAsync fails in a desktop app. The window is small and
    # deliberately NOT topmost, so the credential dialog sits in front of it.
    # Same near-black as the other windows, so it reads as part of the same app.
    $w = New-Object System.Windows.Window
    $w.WindowStyle           = 'None'
    $w.ResizeMode            = 'NoResize'
    $w.Width                 = 360
    $w.Height                = 96
    $w.WindowStartupLocation = 'CenterScreen'
    $w.Topmost               = $false
    $w.ShowInTaskbar         = $false
    $w.Background            = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0x16, 0x12, 0x1F))
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text                = 'Waiting for Windows Hello...'
    $tb.Foreground          = [System.Windows.Media.Brushes]::White
    $tb.HorizontalAlignment = 'Center'
    $tb.VerticalAlignment   = 'Center'
    $tb.FontSize            = 14
    $w.Content = $tb
    $w.Show(); $w.Activate() | Out-Null
    Invoke-DoEvents

    $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper $w).Handle
    if ($hwnd -eq [IntPtr]::Zero) { $w.Close(); Send-Result 3 }

    $op = [PinAuth.Hello]::RequestForWindow($factory, $hwnd, '__MESSAGE__', $iid)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ([PinAuth.Hello]::Status($op) -eq 0 -and $sw.Elapsed.TotalSeconds -lt __TIMEOUT__) {
        Invoke-DoEvents
        Start-Sleep -Milliseconds 100
    }
    $status = [PinAuth.Hello]::Status($op)
    $w.Close(); Invoke-DoEvents

    # Still Started means the prompt was shown and simply never answered. That is
    # a person walking away, not a fault, so it is reported separately.
    if ($status -eq 0) { Send-Result 4 }
    if ($status -ne 1) { Send-Result 3 }

    $r = [PinAuth.Hello]::Results($op)
    [PinAuth.Hello]::Close($op)

    # 0 Verified | 1 DeviceNotPresent | 2 NotConfiguredForUser | 3 DisabledByPolicy
    # 4 DeviceBusy | 5 RetriesExhausted | 6 Canceled
    switch ($r) {
        0       { Send-Result 0 }
        1       { Send-Result 2 }
        2       { Send-Result 2 }
        3       { Send-Result 2 }
        5       { Send-Result 1 }
        6       { Send-Result 1 }
        default { Send-Result 3 }
    }
}
catch { Send-Result 3 }
'@

function Invoke-HelloVerification {
    <#
    .SYNOPSIS
        Asks the console user to prove who they are with Windows Hello.
        Returns 'Verified', 'Declined', 'Unavailable' or 'Error'.

    .DESCRIPTION
        Hello is asked before the password because on an Entra-joined,
        Hello-first device LogonUser rejects even the correct password - see
        Test-WindowsPassword. Hello is the credential those users actually have.

        Three things make this awkward, and all three are handled here:

        1. Windows Hello cannot be invoked by SYSTEM. It belongs to a user session
           and is brokered by CredentialUIBroker running as that user. This dialog
           runs as SYSTEM (ServiceUI only borrows the desktop; it does not change
           the token), so the verifier is launched into the console session with
           the console user's own token via WTSQueryUserToken and
           CreateProcessAsUser.

        2. UserConsentVerifier.RequestVerificationAsync never completes in an
           unpackaged desktop app - it has no window to parent the prompt to and
           stays in the Started state forever. The verifier therefore goes through
           IUserConsentVerifierInterop::RequestVerificationForWindowAsync with a
           real HWND.

        3. The verifier runs AS THE USER, so anything else running as that user
           can interfere with it - end it with exit code 0, for one. An exit code
           is therefore never taken as proof. The verifier reports over a named
           pipe created here before it starts: one client allowed, remote clients
           refused, and the report counts only if the connection comes from the
           verifier's own process id and its exit code says the same thing.

        What that does not stop is code already running as the signed-in user
        that injects into the verifier itself. Nothing launched into a user's
        session can be shielded from that user's own code. The gate is there so
        that someone who finds the machine unlocked cannot reset the PIN with a
        few clicks; it is not a defence against malware in the user's session.

        The verifier is passed as -EncodedCommand rather than written to disk, so
        there is no file a standard user could swap for one of their own.

        Only a verified result maps to 'Verified'. Everything else is reported to
        the caller, which decides whether to fall back or refuse.
    #>
    param(
        [Parameter(Mandatory)][string] $Message,
        [int]                          $SessionId      = -1,
        [int]                          $TimeoutSeconds = 120
    )

    # The child gets a shorter budget than the wait, so a merely slow child
    # reports its own timeout instead of being killed mid-prompt.
    $childTimeout = [Math]::Max(30, $TimeoutSeconds - 15)

    # Unguessable, and used for this one verification only.
    $pipeName = 'BLPIN-' + [guid]::NewGuid().ToString('N')

    $body = $script:HelloVerifierScript.
                Replace('__MESSAGE__', ($Message -replace "'", "''")).
                Replace('__TIMEOUT__', [string]$childTimeout).
                Replace('__PIPE__', $pipeName)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))

    # Windows PowerShell by full path: WinRT type accelerators do not exist in
    # PowerShell 7, so pwsh would fail whatever the caller happens to be running.
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $exe)) {
        Write-PinLog 'Windows PowerShell 5.1 not found - Hello verification cannot run.' 'ERROR'
        return 'Unavailable'
    }
    $childArgs = "-NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -EncodedCommand $b64"

    $isSystem = $false
    try { $isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18' } catch { }

    # SYSTEM must launch into the console user's session with their token.
    # Anyone else is already in their own session - the path a test run or a
    # manual invocation takes - and launches as themselves. Both go through the
    # same launcher, so both get the same authenticated result channel.
    if ($isSystem -and $SessionId -lt 0) {
        $SessionId = Get-ConsoleSessionId
        if ($null -eq $SessionId) {
            Write-PinLog 'No console session - Hello verification cannot be shown to anyone.' 'WARN'
            return 'Unavailable'
        }
    }

    try {
        # Guarded: Add-Type throws if the type is already defined, and a second
        # call in the same process would otherwise be reported as 'Unavailable'.
        if (-not ('PinAuth.UserSession' -as [type])) {
            Add-Type -TypeDefinition $script:UserSessionCSharp -ReferencedAssemblies 'System.Core' -ErrorAction Stop
        }
    }
    catch {
        # Same hardened-fleet exposure Test-WindowsPassword documents: Add-Type
        # runs the C# compiler, which EDR or WDAC can block.
        Write-PinLog "Cannot launch the Hello verifier - P/Invoke unavailable: $($_.Exception.Message)" 'ERROR'
        return 'Unavailable'
    }

    $cmdLine = '"' + $exe + '" ' + $childArgs
    $code = [PinAuth.UserSession]::Run($isSystem, [uint32][Math]::Max(0, $SessionId), $exe, $cmdLine,
                                       $pipeName, $TimeoutSeconds * 1000)

    if ($code -eq -1) {
        Write-PinLog ("Hello verifier could not be started (" +
                      [PinAuth.UserSession]::Stage + " failed, Win32 " +
                      [PinAuth.UserSession]::LastError + ").") 'ERROR'
        return 'Unavailable'
    }

    switch ($code) {
        0       { Write-PinLog 'Windows Hello verification succeeded.'; 'Verified' }
        1       { Write-PinLog 'Windows Hello verification was declined or cancelled.' 'WARN'; 'Declined' }
        2       { Write-PinLog 'Windows Hello is not usable on this device for this user.' 'WARN'; 'Unavailable' }
        4       { Write-PinLog 'Windows Hello prompt was shown but never answered.' 'WARN'; 'Declined' }
        -2      { Write-PinLog 'Windows Hello verification timed out.' 'WARN'; 'Declined' }
        -3      { Write-PinLog ("Windows Hello gave no authenticated result (" + [PinAuth.UserSession]::Stage +
                                "; verifier exit " + [PinAuth.UserSession]::ExitCode + ") - not treated as verified.") 'WARN'; 'Error' }
        default { Write-PinLog "Windows Hello verification errored (result $code)." 'WARN'; 'Error' }
    }
}

# Launcher used by Invoke-HelloVerification: starts the verifier (in the console
# user's session when called as SYSTEM) and collects its result over a named
# pipe that only the verifier's own process can be believed on. Kept as a string
# so the compile only happens on the path that actually needs it; a literal
# here-string, so nothing in the C# is ever expanded by PowerShell.
$script:UserSessionCSharp = @'
using System;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PinAuth
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    // Lets a raw process handle take part in WaitHandle.WaitAny. Does not own it.
    sealed class ProcessWait : WaitHandle
    {
        public ProcessWait(IntPtr h) { SafeWaitHandle = new SafeWaitHandle(h, false); }
    }

    public static class UserSession
    {
        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr h, uint access, IntPtr sa, int imp, int type, out IntPtr dup);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr env);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder cmd,
            IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(string app, StringBuilder cmd,
            IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
            uint outBuffer, uint inBuffer, uint defaultTimeout, ref SECURITY_ATTRIBUTES sa);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision,
            out IntPtr sd, IntPtr size);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);

        public static int LastError;
        public static string Stage = "";
        public static int ExitCode = -1;

        const string ReportPrefix = "BLPIN-HELLO:";

        // -1 could not launch, -2 timed out, -3 no authenticated result,
        // otherwise the result the verifier reported over the pipe.
        //
        // asUser: launch into sessionId with that session's user token (the
        // SYSTEM path). Otherwise launch as the caller, which is what a test run
        // or a manual invocation from the user's own session needs.
        public static int Run(bool asUser, uint sessionId, string exe, string cmdLine, string pipeName, int timeoutMs)
        {
            LastError = 0; Stage = ""; ExitCode = -1;
            IntPtr tok = IntPtr.Zero, dup = IntPtr.Zero, env = IntPtr.Zero, sd = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            NamedPipeServerStream server = null;
            int deadline = Environment.TickCount + timeoutMs;
            try
            {
                // The result channel exists before the child does, with room for
                // exactly one client. Remote clients are refused outright: over
                // SMB the client process id is whatever the remote side claims.
                if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GRGW;;;AU)", 1, out sd, IntPtr.Zero))
                { Stage = "ConvertStringSecurityDescriptor"; LastError = Marshal.GetLastWin32Error(); return -1; }

                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;

                // PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED
                // PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS
                IntPtr h = CreateNamedPipe("\\\\.\\pipe\\" + pipeName, 0x00000001 | 0x00080000 | 0x40000000,
                                           0x00000008, 1, 0, 256, 0, ref sa);
                if (h == new IntPtr(-1))
                { Stage = "CreateNamedPipe"; LastError = Marshal.GetLastWin32Error(); return -1; }
                server = new NamedPipeServerStream(PipeDirection.In, true, false, new SafePipeHandle(h, true));
                IAsyncResult connect = server.BeginWaitForConnection(null, null);

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

                // CreateProcessAsUser may write to the command-line buffer, so it
                // has to be mutable - a marshalled string is not.
                StringBuilder cmd = new StringBuilder(cmdLine, cmdLine.Length + 64);

                if (asUser)
                {
                    if (!WTSQueryUserToken(sessionId, out tok))
                    { Stage = "WTSQueryUserToken"; LastError = Marshal.GetLastWin32Error(); return -1; }

                    // MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary
                    if (!DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 1, out dup))
                    { Stage = "DuplicateTokenEx"; LastError = Marshal.GetLastWin32Error(); return -1; }

                    // A missing environment block is survivable: the child only has to
                    // draw a window, so do not fail the operation over it.
                    if (!CreateEnvironmentBlock(out env, dup, false)) { env = IntPtr.Zero; }

                    si.lpDesktop = "winsta0\\default";

                    // CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
                    if (!CreateProcessAsUser(dup, exe, cmd, IntPtr.Zero, IntPtr.Zero, false,
                                             0x00000400 | 0x08000000, env, null, ref si, out pi))
                    { Stage = "CreateProcessAsUser"; LastError = Marshal.GetLastWin32Error(); return -1; }
                }
                else
                {
                    // CREATE_NO_WINDOW
                    if (!CreateProcess(exe, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x08000000,
                                       IntPtr.Zero, null, ref si, out pi))
                    { Stage = "CreateProcess"; LastError = Marshal.GetLastWin32Error(); return -1; }
                }

                using (ProcessWait exited = new ProcessWait(pi.hProcess))
                {
                    int which = WaitHandle.WaitAny(new WaitHandle[] { connect.AsyncWaitHandle, exited }, Remaining(deadline));
                    if (which == WaitHandle.WaitTimeout)
                    { Stage = "timeout"; TerminateProcess(pi.hProcess, 3); return -2; }
                    if (which == 1)
                    { Stage = "exited without reporting"; ExitCode = ExitCodeOf(pi.hProcess); return -3; }

                    server.EndWaitForConnection(connect);

                    // The one check that matters: the connection must come from the
                    // process launched above. This process holds its handle, so the
                    // id cannot have been recycled.
                    uint clientPid;
                    if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out clientPid))
                    { Stage = "GetNamedPipeClientProcessId"; LastError = Marshal.GetLastWin32Error(); TerminateProcess(pi.hProcess, 3); return -3; }
                    if (clientPid != pi.dwProcessId)
                    { Stage = "report came from process " + clientPid + ", not the verifier"; TerminateProcess(pi.hProcess, 3); return -3; }

                    byte[] buf = new byte[64];
                    int total = 0;
                    while (total < buf.Length)
                    {
                        IAsyncResult rd = server.BeginRead(buf, total, buf.Length - total, null, null);
                        if (!rd.AsyncWaitHandle.WaitOne(Remaining(deadline)))
                        { Stage = "timeout"; TerminateProcess(pi.hProcess, 3); return -2; }
                        int n = server.EndRead(rd);
                        if (n == 0) break;
                        total += n;
                    }

                    if (!exited.WaitOne(Remaining(deadline)))
                    { Stage = "timeout"; TerminateProcess(pi.hProcess, 3); return -2; }
                    ExitCode = ExitCodeOf(pi.hProcess);

                    string report = Encoding.ASCII.GetString(buf, 0, total);
                    if (report.Length != ReportPrefix.Length + 1 || !report.StartsWith(ReportPrefix, StringComparison.Ordinal))
                    { Stage = "malformed report"; return -3; }
                    int result = report[ReportPrefix.Length] - '0';
                    if (result < 0 || result > 9)
                    { Stage = "malformed report"; return -3; }

                    // Two independent statements of the same outcome. If they
                    // disagree, something other than the verifier had a hand in one.
                    if (result != ExitCode)
                    { Stage = "exit code " + ExitCode + " contradicts the report " + result; return -3; }
                    return result;
                }
            }
            catch (Exception e)
            {
                Stage = "exception: " + e.GetType().Name;
                if (pi.hProcess != IntPtr.Zero) TerminateProcess(pi.hProcess, 3);
                return -3;
            }
            finally
            {
                if (server != null) server.Dispose();
                if (pi.hThread  != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
                if (dup != IntPtr.Zero) CloseHandle(dup);
                if (tok != IntPtr.Zero) CloseHandle(tok);
                if (sd  != IntPtr.Zero) LocalFree(sd);
            }
        }

        static int Remaining(int deadline)
        {
            int left = unchecked(deadline - Environment.TickCount);
            return left > 0 ? left : 0;
        }

        static int ExitCodeOf(IntPtr h)
        {
            uint code;
            return GetExitCodeProcess(h, out code) ? (int) code : -1;
        }
    }
}
'@
