<#
.SYNOPSIS
    Asks the signed-in user to choose a BitLocker startup PIN, then applies it.

.DESCRIPTION
    Launched by the scheduled task through ServiceUI.exe, so it runs as SYSTEM but
    renders on the logged-on user's desktop. SYSTEM is required because adding a
    key protector needs admin rights; the user's desktop is required because
    session 0 has none, which is why 'manage-bde -changepin' silently fails when a
    Win32 app tries it directly.

    Order of operations is the safety design:
      1. Validate everything knowable BEFORE touching a protector.
      2. Require a recovery password that is escrowed to Entra ID.
      3. Add the TpmAndPin protector.
      4. Verify it landed, and only then remove the TPM-only protector.

    A volume can hold both a Tpm and a TpmPin protector, and Windows documents
    that the plain Tpm one "negates the effects of other TPM-based key
    protectors" - so the overlap between 3 and 4 still boots unattended, and a
    failure at 3 has removed nothing. Removing first would open a window where
    only the 48-digit recovery key can unlock the volume.

    The PIN never reaches disk, a log, or a command line. It lives in a
    SecureString and goes straight to Add-BitLockerKeyProtector.
#>
[CmdletBinding()]
param(
    # Vendor namespace: the registry key, the %ProgramData% folder, the window
    # title and the wordmark shown when no logo image is supplied all hang off
    # this. It must contain no whitespace - ServiceUI strips quotes from the
    # command line it forwards, so a name with a space would arrive split.
    # Change it here and in the other scripts together; Test-BitLockerPinApp.ps1
    # asserts they agree.
    [string] $Organization = 'WK-Hub',
    [ValidateRange(6,20)]
    [int]    $MinimumPin = 6,

    # Re-prompt even when a PIN protector already exists, replacing it. For the
    # service-desk reset path only: this is the one flow that must remove the PIN
    # protector before adding its replacement.
    [switch] $Force,

    # Self-service entry point, invoked by the Start-menu shortcut through the
    # "<Organization> BitLocker PIN Reset" task. Shows the device's current PIN
    # status and, for the device's enrolled user, under the daily reset limit,
    # and only after they confirm who they are with Windows Hello (or their
    # Windows password where Hello cannot run), turns itself into the reset flow
    # above.
    #
    # -Force remains the service desk's way in and skips those gates by design:
    # the task carrying it is ACL'd to SYSTEM and Administrators, so an ordinary
    # user cannot reach it.
    [switch] $Manage,

    # Show the dialog without touching BitLocker: no pre-flight queries, and
    # "Set PIN" validates the input then stops. For screenshots, helpdesk
    # training, and checking the layout on a real desktop. Needs no privilege.
    [switch] $PreviewUI,

    # Render the "this device is not encrypted" notice and exit. For checking the
    # wording and layout without having to decrypt a machine. Needs no privilege.
    [switch] $PreviewNotEncrypted,

    # Render the self-service windows - the "your PIN is set" page and, if you
    # press "Reset my PIN", the password prompt - and exit. Nothing is verified
    # and nothing is changed. Needs no privilege.
    [switch] $PreviewManage
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'BitLockerPin.Common.ps1')

$root     = $PSScriptRoot
$regKey   = "HKLM:\SOFTWARE\$Organization\BitLockerPin"
$taskName = "$Organization BitLocker PIN Enrollment"
$sysDrive = $env:SystemDrive
$script:LogFile = Join-Path $root 'prompt.log'

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

function Disable-EnrollmentTask {
    try {
        Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        Write-PinLog "Disabled scheduled task '$taskName'."
    } catch { Write-PinLog "Could not disable the task: $($_.Exception.Message)" 'WARN' }
}

function Enable-EnrollmentTask {
    # The inverse, for the one path that can leave a device with no PIN after
    # the task was disabled: a reset that removed the old PIN protector and then
    # failed to add the new one. Re-arming the task brings the ordinary prompt
    # back at the next logon or unlock, without waiting for remediation to run.
    try {
        Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        Write-PinLog "Re-enabled scheduled task '$taskName'."
    } catch { Write-PinLog "Could not re-enable the task: $($_.Exception.Message)" 'WARN' }
}

function Test-PinSecure {
    <#
        Validates without ever materialising the PIN as a managed string. A
        System.String cannot be zeroed, so it lingers in the freed heap of a
        long-lived SYSTEM process - reachable through a crash dump, the page file
        or hiberfil.sys. Reading the BSTRs directly avoids that, and avoids
        -match populating $Matches with the PIN.
    #>
    param(
        [Parameter(Mandatory)][Security.SecureString] $Pin,
        [Parameter(Mandatory)][Security.SecureString] $Confirm,
        [Parameter(Mandatory)][int] $Min
    )

    $pa = [IntPtr]::Zero
    $pb = [IntPtr]::Zero
    try {
        if ($Pin.Length -lt $Min) { return "Your PIN must be at least $Min digits." }
        if ($Pin.Length -gt 20)   { return 'Your PIN can be at most 20 digits.' }

        $pa = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pin)
        $pb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Confirm)

        $allDigits  = $true
        $allSame    = $true
        $ascending  = $true
        $descending = $true
        $first = [Runtime.InteropServices.Marshal]::ReadInt16($pa, 0)

        for ($i = 0; $i -lt $Pin.Length; $i++) {
            $c = [Runtime.InteropServices.Marshal]::ReadInt16($pa, $i * 2)
            if ($c -lt 48 -or $c -gt 57) { $allDigits = $false }
            if ($c -ne $first)           { $allSame   = $false }
            if ($i -gt 0) {
                $prev = [Runtime.InteropServices.Marshal]::ReadInt16($pa, ($i - 1) * 2)
                if ($c -ne $prev + 1) { $ascending  = $false }
                if ($c -ne $prev - 1) { $descending = $false }
            }
        }

        if (-not $allDigits) { return 'Use digits 0-9 only. The startup keyboard cannot type letters reliably.' }

        if ($Pin.Length -ne $Confirm.Length) { return 'The two PINs do not match.' }
        for ($i = 0; $i -lt $Pin.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($pa, $i * 2) -ne
                [Runtime.InteropServices.Marshal]::ReadInt16($pb, $i * 2)) { return 'The two PINs do not match.' }
        }

        if ($allSame)                   { return 'Do not use the same digit repeated.' }
        if ($ascending -or $descending) { return 'Do not use a run of consecutive digits like 123456.' }

        return $null
    }
    finally {
        if ($pa -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pa) }
        if ($pb -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pb) }
    }
}

function Test-ShouldWarn {
    <#
        Throttles a user-facing warning to once per interval. The task runs at every
        logon and every unlock, and nagging someone hourly about something only IT
        can fix trains them to dismiss our windows on sight.
    #>
    param([Parameter(Mandatory)][string] $Name, [int] $Hours = 24)

    try {
        $seen = (Get-ItemProperty -LiteralPath $regKey -Name $Name -ErrorAction Stop).$Name
        if ($seen -and ([datetime]::Parse($seen)).AddHours($Hours) -gt (Get-Date)) { return $false }
    } catch { }

    try {
        if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
        New-ItemProperty -LiteralPath $regKey -Name $Name -Value (Get-Date -Format 's') `
                         -PropertyType String -Force -ErrorAction Stop | Out-Null
    } catch { Write-PinLog "Could not record the '$Name' marker: $($_.Exception.Message)" 'WARN' }
    $true
}

function Show-IssueNotice {
    <#
        A branded, information-only window for states the user cannot act on - the
        drive not being encrypted, for instance. Same visual language as the PIN
        dialog so it is recognisably from IT, with a single dismiss button.
    #>
    param(
        [Parameter(Mandatory)][string] $Heading,
        [Parameter(Mandatory)][string] $Body,
        [string] $Reference
    )

    try {
        # Branding is optional: Get-BrandXaml emits an <Image> only for a file
        # that is actually there, and a wordmark otherwise, so a missing logo can
        # never stop this window from rendering.
        $brand = Get-BrandXaml -Root $root -BrandName $Organization

        [xml]$x = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Organization - device security" Height="480" Width="700"
        WindowStartupLocation="CenterScreen" WindowStyle="SingleBorderWindow"
        ResizeMode="CanMinimize" ShowInTaskbar="True" Topmost="True"$($brand.WindowIcon)
        Background="#FF16121F" FontFamily="Segoe UI">
  <Window.Resources>
    <!-- The notice used the stock button, which reads as an unfinished window
         once everything around it is themed. Same marquee treatment as the
         dialog, kept minimal because this window has exactly one control. -->
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FFD81B74"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="{TemplateBinding Background}" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFFF4D9D"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid Grid.Column="0">
      $($brand.Backdrop)
      $($brand.NoticeMark)
      $($brand.NoticeFooter)
    </Grid>
    <Border Grid.Column="1" Background="#FFF6F4FA">
      <Grid Margin="34,30,34,24">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="h" FontSize="21" FontWeight="SemiBold" Foreground="#FF1A1526" TextWrapping="Wrap" Margin="0,0,0,12"/>
        <TextBlock Grid.Row="1" Name="b" FontSize="13" Foreground="#FF4A4360" TextWrapping="Wrap" LineHeight="20"/>
        <Border Grid.Row="2" Name="refBox" Background="#FFF0FBFC" BorderBrush="#FFCFEEF0" BorderThickness="1"
                CornerRadius="3" Padding="12,9" Margin="0,16,0,0" Visibility="Collapsed">
          <TextBlock Name="r" FontFamily="Consolas" FontSize="12.5" Foreground="#FF0E7C86" TextWrapping="Wrap"/>
        </Border>
        <Button Grid.Row="4" Name="ok" Content="Close" Width="120" Height="36"
                HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,18,0,0" Cursor="Hand"/>
      </Grid>
    </Border>
  </Grid>
</Window>
"@
        $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
        Set-BrandedTitleBar -Window $w
        $w.FindName('h').Text = $Heading
        $w.FindName('b').Text = $Body
        if ($Reference) {
            $w.FindName('r').Text = $Reference
            $w.FindName('refBox').Visibility = 'Visible'
        }
        $w.FindName('ok').Add_Click({ $w.Close() })
        $w.ShowDialog() | Out-Null
    }
    catch { Write-PinLog "Could not show the notice window: $($_.Exception.Message)" 'WARN' }
}

function Show-ManageWindow {
    <#
        The self-service landing page. Tells the user the PIN is set - which is
        most of what they came to find out - and offers the reset.

        Returns $true only if they asked for a reset. Any failure returns $false,
        because a window that could not be drawn must not be read as consent.

        Same layout, palette and optional branding as the notice. The images go
        through Get-BrandXaml for the reason the notice's do: a missing PNG
        would throw out of XamlReader.Load, this function would return $false,
        and a device with no artwork would never be offered the reset at all.
    #>
    param([string] $PinSetOn)

    $result = $false
    try {
        $brand = Get-BrandXaml -Root $root -BrandName $Organization

        [xml]$x = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Organization - startup PIN" Height="480" Width="700"
        WindowStartupLocation="CenterScreen" WindowStyle="SingleBorderWindow"
        ResizeMode="CanMinimize" ShowInTaskbar="True" Topmost="True"$($brand.WindowIcon)
        Background="#FF16121F" FontFamily="Segoe UI">
  <Window.Resources>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="#FFD81B74"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="{TemplateBinding Background}" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFFF4D9D"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Ghost" TargetType="Button" BasedOn="{StaticResource Primary}">
      <Setter Property="Foreground" Value="#FF1A1526"/>
      <Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="Transparent" BorderBrush="#FFCFC9DE" BorderThickness="1" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFEDEAF5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid Grid.Column="0">
      $($brand.Backdrop)
      $($brand.NoticeMark)
      $($brand.NoticeFooter)
    </Grid>
    <Border Grid.Column="1" Background="#FFF6F4FA">
      <Grid Margin="34,30,34,24">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="21" FontWeight="SemiBold" Foreground="#FF1A1526"
                   TextWrapping="Wrap" Margin="0,0,0,12" Text="Your startup PIN is set"/>
        <TextBlock Grid.Row="1" FontSize="13" Foreground="#FF4A4360" TextWrapping="Wrap" LineHeight="20"
                   Text="This computer asks for your PIN before Windows starts. That is what keeps the disk unreadable if the device is lost or stolen.&#10;&#10;If you have forgotten it, you can set a new one here. You will be asked to confirm it is you with Windows Hello (or your Windows password), and the new PIN applies the next time you start the computer."/>
        <Border Grid.Row="2" Name="refBox" Background="#FFF0FBFC" BorderBrush="#FFCFEEF0" BorderThickness="1"
                CornerRadius="3" Padding="12,9" Margin="0,16,0,0" Visibility="Collapsed">
          <TextBlock Name="r" FontFamily="Consolas" FontSize="12.5" Foreground="#FF0E7C86" TextWrapping="Wrap"/>
        </Border>
        <!-- Close is the default button on purpose: Enter must never start a reset. -->
        <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,18,0,0">
          <Button Name="close" Content="Close"        Width="120" Height="36" Margin="0,0,10,0" IsDefault="True" Style="{StaticResource Ghost}"/>
          <Button Name="reset" Content="Reset my PIN" Width="150" Height="36" Style="{StaticResource Primary}"/>
        </StackPanel>
      </Grid>
    </Border>
  </Grid>
</Window>
"@
        $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
        Set-BrandedTitleBar -Window $w
        # The device name is what the service desk asks for, so it is always
        # shown. The date is only known when this app set the PIN - a PIN that
        # predates the install, or one assigned with -AssignDerivedPin, has none.
        $ref = "Device:  $env:COMPUTERNAME"
        if ($PinSetOn) { $ref += "`nPIN set: $PinSetOn" }
        $w.FindName('r').Text = $ref
        $w.FindName('refBox').Visibility = 'Visible'
        $w.FindName('reset').Add_Click({ $script:manageChoice = $true;  $w.Close() })
        $w.FindName('close').Add_Click({ $script:manageChoice = $false; $w.Close() })
        $script:manageChoice = $false
        $w.ShowDialog() | Out-Null
        $result = [bool]$script:manageChoice
    }
    catch { Write-PinLog "Could not show the manage window: $($_.Exception.Message)" 'WARN' }
    $result
}

function Show-PasswordPrompt {
    <#
        Collects the user's Windows password for re-authentication. Only reached
        when Windows Hello cannot run on this device.

        Returns a SecureString, or $null if they cancelled or the window failed.
        WPF's PasswordBox hands back a SecureString directly, so the password is
        never a System.String at any point on this path - the same standard the
        PIN itself is held to.

        The UPN is set from code, not written into the markup: it comes from the
        registry, and text spliced into XAML is text the XML parser interprets.
    #>
    param([string] $Upn)

    $secure = $null
    try {
        $brand = Get-BrandXaml -Root $root -BrandName $Organization

        [xml]$x = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Organization - confirm it is you" Height="300" Width="470"
        WindowStartupLocation="CenterScreen" WindowStyle="SingleBorderWindow"
        ResizeMode="NoResize" ShowInTaskbar="True" Topmost="True"$($brand.WindowIcon)
        Background="#FFF6F4FA" FontFamily="Segoe UI">
  <Window.Resources>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="#FFD81B74"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="{TemplateBinding Background}" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFFF4D9D"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Ghost" TargetType="Button" BasedOn="{StaticResource Primary}">
      <Setter Property="Foreground" Value="#FF1A1526"/>
      <Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="Transparent" BorderBrush="#FFCFC9DE" BorderThickness="1" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFEDEAF5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid Margin="28,24,28,20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" FontSize="17" FontWeight="SemiBold" Foreground="#FF1A1526"
               Text="Confirm it is you" Margin="0,0,0,8"/>
    <TextBlock Grid.Row="1" Name="lead" FontSize="12.5" Foreground="#FF4A4360" TextWrapping="Wrap" LineHeight="18"/>
    <PasswordBox Grid.Row="2" Name="pwd" Height="32" FontSize="14" Margin="0,16,0,0" Padding="6,4"
                 BorderBrush="#FFD9D4E6" BorderThickness="1" Background="White"/>
    <TextBlock Grid.Row="3" Name="msg" FontSize="12" Foreground="#FFC01A56" TextWrapping="Wrap" Margin="0,8,0,0"/>
    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Bottom">
      <Button Name="cancel" Content="Cancel"   Width="100" Height="32" Margin="0,0,8,0" IsCancel="True" Style="{StaticResource Ghost}"/>
      <Button Name="ok"     Content="Continue" Width="110" Height="32" IsDefault="True" Style="{StaticResource Primary}"/>
    </StackPanel>
  </Grid>
</Window>
"@
        $w   = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
        Set-BrandedTitleBar -Window $w
        $w.FindName('lead').Text = "Windows Hello is not available, so enter the Windows password for $Upn to reset this computer's startup PIN."
        $box = $w.FindName('pwd')
        $script:pwdResult = $null
        $w.FindName('ok').Add_Click({
            if ($box.SecurePassword.Length -eq 0) { $w.FindName('msg').Text = 'Enter your password.'; return }
            $script:pwdResult = $box.SecurePassword.Copy()
            $w.Close()
        })
        $w.FindName('cancel').Add_Click({ $script:pwdResult = $null; $w.Close() })
        $w.Add_ContentRendered({ $box.Focus() | Out-Null })
        $w.ShowDialog() | Out-Null
        $secure = $script:pwdResult
        $script:pwdResult = $null
    }
    catch { Write-PinLog "Could not show the password prompt: $($_.Exception.Message)" 'WARN' }
    $secure
}

Write-PinLog "--- PIN dialog invoked$(if ($PreviewUI -or $PreviewManage) { ' (PREVIEW - no BitLocker changes)' })$(if ($Manage) { ' (self-service)' }) ---"

if ($PreviewManage) {
    # Everything the self-service path draws, with nothing behind it: no
    # identity check, no Hello prompt, no password verification, no protector
    # change. For the wording, the layout and the branding.
    if (Show-ManageWindow -PinSetOn (Get-Date -Format 's')) {
        $previewPwd = Show-PasswordPrompt -Upn 'user@example.com'
        if ($previewPwd) { $previewPwd.Dispose() }
    }
    exit 0
}

if ($PreviewNotEncrypted) {
    Show-IssueNotice -Heading 'This device is not encrypted' -Body (
        "BitLocker disk encryption is not switched on for this computer, so the startup PIN " +
        "that protects it cannot be set up yet.`n`n" +
        "This is not something you can fix yourself, and it means the data on this device is " +
        "not protected if it is lost or stolen.`n`n" +
        "Please contact the IT service desk and quote the reference below. You can keep working " +
        "in the meantime."
    ) -Reference "Device: $env:COMPUTERNAME`nIssue:  BitLocker not enabled (volume $sysDrive is FullyDecrypted)"
    exit 0
}

if ($PreviewUI) {
    # Skip straight to the UI. Everything between here and the dialog needs
    # administrator rights, and preview mode exists precisely so it can be run
    # by an ordinary user on an ordinary desktop.
    $minPin = [Math]::Max($MinimumPin, 6)
}
else {

# ----------------------------------------------------------------------
# Only ever draw on the active console session. ServiceUI attaches to the first
# explorer.exe it finds, which on a machine with fast user switching or an RDP
# session can belong to a different user than the one who just signed in - and
# that user would be choosing the PIN everyone types at boot.
# ----------------------------------------------------------------------
# Fails CLOSED. Previously any failure here was caught, logged as a warning, and
# execution continued - so on a device where the check could not run, the SYSTEM
# dialog rendered on whatever desktop ServiceUI happened to hook.
$mySession      = [Diagnostics.Process]::GetCurrentProcess().SessionId
$consoleSession = Get-ConsoleSessionId
if ($null -eq $consoleSession) {
    Write-PinLog 'Could not determine the console session - refusing to prompt (the wrong user must never choose the boot PIN).' 'ERROR'
    exit 0
}
if ($mySession -ne $consoleSession) {
    Write-PinLog "Session $mySession is not the console session ($consoleSession) - not prompting." 'WARN'
    exit 0
}

# ----------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------
try { $vol = Get-BitLockerVolume -MountPoint $sysDrive }
catch { Write-PinLog "Cannot query BitLocker: $($_.Exception.Message)" 'ERROR'; exit 1 }

# ----------------------------------------------------------------------
# Encryption scan. A device with no encryption cannot have a startup PIN, and the
# user cannot fix that themselves - so tell them plainly and point them at IT
# rather than exiting silently and leaving the device quietly unprotected.
#
# Deliberately NOT warned about: EncryptionInProgress (it is working, just not
# finished) and a suspended-but-encrypted volume (routine during servicing).
# Alarming people about transient states is how warnings get ignored.
# ----------------------------------------------------------------------
if ($vol.VolumeStatus -in 'FullyDecrypted','DecryptionInProgress') {
    Write-PinLog "Volume is $($vol.VolumeStatus) - no encryption, so no PIN is possible. Informing the user." 'ERROR'
    if (Test-ShouldWarn -Name 'NotEncryptedWarnedOn' -Hours 24) {
        Show-IssueNotice -Heading 'This device is not encrypted' -Body (
            "BitLocker disk encryption is not switched on for this computer, so the startup PIN " +
            "that protects it cannot be set up yet.`n`n" +
            "This is not something you can fix yourself, and it means the data on this device is " +
            "not protected if it is lost or stolen.`n`n" +
            "Please contact the IT service desk and quote the reference below. You can keep working " +
            "in the meantime."
        ) -Reference "Device: $env:COMPUTERNAME`nIssue:  BitLocker not enabled (volume $sysDrive is $($vol.VolumeStatus))"
    }
    else { Write-PinLog 'User was already warned within the last 24 hours - not showing the notice again.' }
    exit 0
}

if ($vol.VolumeStatus -eq 'EncryptionInProgress') {
    Write-PinLog 'Encryption is still in progress - deferring quietly until it finishes.' 'WARN'
    exit 0
}

if ($vol.ProtectionStatus -eq 'Off') {
    # Suspended for a firmware update or servicing. Sealing a PIN against PCR
    # values that are about to change is what the suspension exists to prevent.
    Write-PinLog 'BitLocker protection is suspended - deferring to the next task run.' 'WARN'
    exit 0
}

# ----------------------------------------------------------------------
# Recovery safety net FIRST. Nothing below may add or remove a protector until
# a recovery password exists and is known to be escrowed - including the
# "a PIN already exists, just tidy up" path, which still removes a protector.
# ----------------------------------------------------------------------
$recovery = @(Get-TpmFamilyProtector -Volume $vol -Type 'RecoveryPassword')
if (-not $recovery) {
    Write-PinLog 'No recovery password protector on this volume - refusing to change protectors.' 'ERROR'
    exit 0
}

# Three-state on purpose: $true escrowed, $false no evidence, $null cannot tell.
# $null must not mean "carry on" - that is how a device with no escrowed key ends
# up with a PIN as the only way in.
$escrowOk = $false
$escrowUnknown = $false
foreach ($rp in $recovery) {
    $r = Test-RecoveryEscrow -KeyProtectorId $rp.KeyProtectorId
    if ($r -eq $true) { $escrowOk = $true; break }
    if ($null -eq $r) { $escrowUnknown = $true }
}
if (-not $escrowOk) {
    Write-PinLog 'Recovery key not confirmed as backed up to Entra ID - attempting escrow now.' 'WARN'
    foreach ($rp in $recovery) {
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $rp.KeyProtectorId -ErrorAction Stop
            # A successful call in THIS run is acceptable evidence: event 845 can lag,
            # and discarding a fresh success would block enrollment indefinitely.
            Write-PinLog "Escrow call succeeded for $($rp.KeyProtectorId)."
            $escrowOk = $true
        } catch { Write-PinLog "Escrow call failed for $($rp.KeyProtectorId): $($_.Exception.Message)" 'WARN' }
    }
}
if (-not $escrowOk) {
    if ($escrowUnknown) {
        Write-PinLog 'Escrow state could not be determined (BitLocker log unreadable) and the escrow call failed - deferring.' 'ERROR'
    } else {
        Write-PinLog 'Recovery key is not escrowed to Entra ID - deferring rather than making a PIN the only way in.' 'ERROR'
    }
    exit 0
}

# ----------------------------------------------------------------------
# Protector inventory. TpmPinStartupKey is deliberately NOT treated as "we are
# done": it needs a USB startup key as well as a PIN, so silently removing the
# plain TPM protector next to it would change this device's boot requirements to
# something the user may not be able to satisfy.
# ----------------------------------------------------------------------
$hasPin      = @(Get-TpmFamilyProtector -Volume $vol -Type 'TpmPin')
$hasPinAndKey = @(Get-TpmFamilyProtector -Volume $vol -Type 'TpmPinStartupKey')
$hasTpm      = @(Get-TpmFamilyProtector -Volume $vol -Type 'Tpm','TpmStartupKey')

if ($hasPinAndKey -and -not $Force) {
    Write-PinLog 'Volume uses a TPM+PIN+startup-key protector. Leaving it untouched - removing the TPM protector here would demand a USB key at boot. Needs manual review.' 'ERROR'
    exit 0
}

# Self-heal: an encrypted volume with no TPM-family protector at all means a
# previous swap died between the remove and the add, so it currently boots only
# via the recovery key. Restore bootability before doing anything else. Creating a
# TPM protector is policy-gated, hence the temporary relax.
if (-not $hasPin -and -not $hasPinAndKey -and -not $hasTpm) {
    Write-PinLog 'Encrypted volume has no TPM-family protector - a previous run was interrupted. Restoring a TPM protector.' 'WARN'
    try {
        Invoke-WithStartupAuthRelaxed {
            Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmProtector -ErrorAction Stop | Out-Null
        }
        $vol    = Get-BitLockerVolume -MountPoint $sysDrive
        $hasTpm = @(Get-TpmFamilyProtector -Volume $vol -Type 'Tpm','TpmStartupKey')
        Write-PinLog 'TPM protector restored.'
    } catch { Write-PinLog "Could not restore a TPM protector: $($_.Exception.Message)" 'ERROR' }
}

# ----------------------------------------------------------------------
# Self-service reset. Three gates, each failing closed, between an ordinary
# signed-in user and the protector-replacement path.
#
# Ordering is deliberate: identity, then throttle, then re-authentication.
# Identity first, because asking a stranger for a credential tells them the
# credential was the only thing in their way. Throttle before
# re-authentication, because a Hello prompt that cannot lead anywhere only
# teaches people to approve prompts without reading them. The throttle counts
# completed resets only, so a refused attempt never costs the real user a slot.
#
# A device with no PIN yet never reaches this block: -Manage there falls
# through to the ordinary first-PIN dialog, the same one the enrolment task
# shows at logon.
# ----------------------------------------------------------------------
if ($Manage -and $hasPin -and -not $Force) {

    $pinSetOn = ''
    try { $pinSetOn = [string](Get-ItemProperty -LiteralPath $regKey -ErrorAction Stop).PinSetOn } catch { }

    if (-not (Show-ManageWindow -PinSetOn $pinSetOn)) {
        Write-PinLog 'Self-service: the user closed the window without asking for a reset.'
        exit 0
    }

    $enrolled = Get-EnrolledUpn
    $console  = Get-ConsoleUser

    if (-not (Test-ConsoleUserIsPrimary -EnrolledUpn $enrolled -ConsoleUser $console)) {
        Write-PinAudit -Action 'ResetDenied' -Organization $Organization `
                       -Detail "Console user '$($console.Upn)' is not the enrolled user '$enrolled' on $env:COMPUTERNAME."
        Show-IssueNotice -Heading 'Only the assigned user can reset this PIN' -Body (
            "The startup PIN on this computer can only be reset by the person it is assigned to " +
            "in our device records.`n`n" +
            "If this is your computer, its records may be out of date - that happens when a device " +
            "changes hands without being re-enrolled.`n`n" +
            "Please contact the IT service desk and quote the reference below. They can reset the PIN for you."
        ) -Reference "Device:    $env:COMPUTERNAME`nSigned in: $(if ($console -and $console.Upn) { $console.Upn } else { 'could not be determined' })`nAssigned:  $(if ($enrolled) { $enrolled } else { 'not recorded' })"
        exit 0
    }

    if (-not (Test-PinResetAllowed -RegKey $regKey)) {
        Write-PinAudit -Action 'ResetThrottled' -Organization $Organization `
                       -Detail "Reset limit reached on $env:COMPUTERNAME for $($console.Upn)."
        Show-IssueNotice -Heading 'Too many PIN resets today' -Body (
            "This computer's startup PIN has already been reset several times in the last 24 hours, " +
            "so self-service has been paused.`n`n" +
            "This limit exists because repeatedly changing the PIN is a common way to end up locked " +
            "out of the machine entirely.`n`n" +
            "Please contact the IT service desk and quote the reference below."
        ) -Reference "Device: $env:COMPUTERNAME`nUser:   $($console.Upn)"
        exit 0
    }

    # Identity is established; now prove the person at the keyboard is that user
    # and not someone who found the laptop unlocked. A live Windows session
    # already reaches the data, so this is not protecting confidentiality - it
    # stops a passer-by choosing a PIN they know and locking the owner out of
    # pre-boot.
    #
    # Windows Hello first. On an Entra-joined, Hello-first device LogonUser
    # rejects even the correct password, because there is no cached password
    # verifier to check it against (see Test-WindowsPassword). Hello is the
    # credential those users actually hold, so asking for it is both the only
    # reliable check there and the one that matches how they already sign in.
    $method = $null
    $hello  = Invoke-HelloVerification -SessionId $console.SessionId -Message (
        "Verify your identity to reset the BitLocker startup PIN on $env:COMPUTERNAME")

    if ($hello -eq 'Verified') {
        $method = 'Windows Hello'
    }
    elseif ($hello -eq 'Declined') {
        # The prompt was shown and not satisfied - cancelled, or the PIN/biometric
        # was wrong often enough for Windows to give up. Falling back to a password
        # here would turn a failed check into a second guess at a different
        # credential, so it stops.
        Write-PinAudit -Action 'ResetDenied' -Organization $Organization `
                       -Detail "Windows Hello verification declined for $($console.Upn) on $env:COMPUTERNAME."
        Show-IssueNotice -Heading 'Identity was not verified' -Body (
            "Windows Hello did not confirm your identity, so the startup PIN has not been " +
            "changed.`n`n" +
            "Start again from the Start menu and try once more. If it keeps failing, contact the " +
            "IT service desk - they can reset the PIN for you."
        ) -Reference "Device: $env:COMPUTERNAME`nUser:   $($console.Upn)"
        exit 0
    }
    else {
        # Hello could not produce a verified result: not enrolled, blocked by
        # policy, the verifier could not be launched, or its result could not be
        # authenticated. The user may still genuinely be locked out, so the
        # password path remains as the fallback - itself a real credential check,
        # which works where there is a cached verifier and fails closed where
        # there is not.
        Write-PinLog "Windows Hello unusable ($hello) - falling back to the password check." 'WARN'

        $securePwd = Show-PasswordPrompt -Upn $console.Upn
        if (-not $securePwd) {
            Write-PinLog 'Self-service: the user cancelled the password prompt.'
            exit 0
        }

        $verified = $false
        try     { $verified = Test-WindowsPassword -Upn $console.Upn -Password $securePwd }
        finally { $securePwd.Dispose() }

        if (-not $verified) {
            Write-PinAudit -Action 'ResetDenied' -Organization $Organization `
                           -Detail "Password verification failed for $($console.Upn) on $env:COMPUTERNAME."
            Show-IssueNotice -Heading 'That password was not accepted' -Body (
                "The Windows password you entered could not be verified, so the startup PIN has not " +
                "been changed.`n`n" +
                "Start again from the Start menu and try once more. If it keeps failing, contact the " +
                "IT service desk - they can reset the PIN for you."
            ) -Reference "Device: $env:COMPUTERNAME`nUser:   $($console.Upn)"
            exit 0
        }
        $method = 'Windows password'
    }

    Write-PinAudit -Action 'ResetAllowed' -Organization $Organization `
                   -Detail "$($console.Upn) verified by $method on $env:COMPUTERNAME; replacing the startup PIN."

    # Every gate passed. Become the reset path: the block below is skipped and the
    # dialog opens, and the replacement logic keys off $Force exactly as it does
    # for the service desk.
    $Force = $true
    $script:SelfService = $true
}

if ($hasPin -and -not $Force) {
    # A leftover TPM-only protector cancels the PIN prompt, so clean it up rather
    # than reporting success over a device that never asks for the PIN.
    $stillThere = @()
    foreach ($p in $hasTpm) {
        Write-PinLog "Removing $($p.KeyProtectorType) protector $($p.KeyProtectorId) - it cancels the PIN prompt." 'WARN'
        try   { Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null }
        catch { Write-PinLog "Could not remove $($p.KeyProtectorId): $($_.Exception.Message)" 'ERROR'; $stillThere += $p }
    }
    if ($stillThere.Count -gt 0) {
        # Do NOT disable the task here. This device has a PIN protector that is
        # being cancelled at boot by a protector we failed to remove; disabling the
        # task would strand it in that state forever while detection still says
        # Installed.
        Write-PinLog 'A TPM-only protector remains, so this device does not actually prompt for a PIN. Leaving the task enabled to retry.' 'ERROR'
        exit 0
    }
    Write-PinLog 'Startup PIN already configured. Nothing to do.'
    Disable-EnrollmentTask
    exit 0
}

# ----------------------------------------------------------------------
# Re-assert the FVE values needed for the add. They are written at install time,
# but the Intune BitLocker CSP owns the same registry key and re-stamps it on
# every sync - so by the time a user finally sets a PIN the policy may no longer
# permit one. Running as SYSTEM, we can put it back.
# ----------------------------------------------------------------------
$fveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
try {
    $cur = Get-ItemProperty -LiteralPath $fveKey -ErrorAction SilentlyContinue
    if ($cur.UseAdvancedStartup -ne 1) {
        Set-FvePolicyValue -Path $fveKey -Name 'UseAdvancedStartup' -Value 1 | Out-Null
        Write-PinLog 'Re-asserted FVE UseAdvancedStartup = 1 (something had reverted it).' 'WARN'
    }
    if ($cur.UseTPMPIN -ne 1 -and $cur.UseTPMPIN -ne 2) {
        Set-FvePolicyValue -Path $fveKey -Name 'UseTPMPIN' -Value 2 | Out-Null
        Write-PinLog 'Re-asserted FVE UseTPMPIN = 2 (something had reverted it).' 'WARN'
    }
} catch { Write-PinLog "Could not re-assert the FVE policy: $($_.Exception.Message)" 'WARN' }

$minPin = [Math]::Max($MinimumPin, 6)
try {
    $polMin = (Get-ItemProperty $fveKey -Name MinimumPIN -ErrorAction Stop).MinimumPIN
    if ($polMin -gt $minPin) { $minPin = $polMin }
} catch { }
if ($minPin -gt 20) {
    # BitLocker caps a PIN at 20 characters, so a policy minimum above that makes
    # the dialog unsatisfiable - it would reject every possible input at every
    # unlock, forever.
    Write-PinLog "FVE MinimumPIN is $minPin, above BitLocker's 20-character maximum - no PIN can satisfy it. Deferring." 'ERROR'
    exit 0
}
Write-PinLog "Minimum PIN length in effect: $minPin"

}   # end of the non-preview pre-flight

# ----------------------------------------------------------------------
# UI
#
# The brand images are OPTIONAL drop-ins (see README, "Branding"). Get-BrandXaml
# emits an <Image> only for a file that exists and a text wordmark on a solid
# colour otherwise, because WPF resolves an image path while the XAML is being
# parsed - a missing PNG would otherwise throw out of XamlReader.Load and take
# the dialog with it, which must never happen over a logo.
# ----------------------------------------------------------------------
$brand = Get-BrandXaml -Root $root -BrandName $Organization

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Set your startup PIN" Height="560" Width="796"
        WindowStartupLocation="CenterScreen"
        WindowStyle="SingleBorderWindow" ResizeMode="CanMinimize"
        ShowInTaskbar="True" Topmost="True"$($brand.WindowIcon)
        Background="#FF16121F" FontFamily="Segoe UI">

  <Window.Resources>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="#FFD81B74"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="{TemplateBinding Background}" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFFF4D9D"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="b" Property="Background" Value="#FFBDB6CC"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Ghost" TargetType="Button" BasedOn="{StaticResource Primary}">
      <Setter Property="Foreground" Value="#FF1A1526"/>
      <Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Name="b" Background="Transparent" BorderBrush="#FFCFC9DE" BorderThickness="1" CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FFEDEAF5"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="b" Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="PasswordBox">
      <Setter Property="Height" Value="40"/>
      <Setter Property="FontSize" Value="18"/>
      <Setter Property="FontFamily" Value="Consolas"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="BorderBrush" Value="#FFD9D4E6"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="MaxLength" Value="20"/>
      <Setter Property="Background" Value="White"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="270"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- Brand rail -->
    <Grid Grid.Column="0">
      $($brand.Backdrop)
      <StackPanel Margin="30,34,30,30" VerticalAlignment="Top">
        $($brand.DialogMark)
        <TextBlock Text="P R E - B O O T" FontFamily="Consolas" FontSize="11"
                   Foreground="#FF5CE1E6" Margin="0,0,0,7"/>
        <TextBlock Text="Device security" Foreground="#FFFFFFFF" FontSize="21" FontWeight="SemiBold" TextWrapping="Wrap"/>
        <Grid Width="132" HorizontalAlignment="Left" Margin="0,16,0,16">
          <Grid.ColumnDefinitions><ColumnDefinition Width="78"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Rectangle Grid.Column="0" Height="2" Fill="#FF5CE1E6"/>
          <Rectangle Grid.Column="1" Height="2" Fill="#FFD81B74"/>
        </Grid>
        <TextBlock Foreground="#CCFFFFFF" FontSize="12.5" TextWrapping="Wrap" LineHeight="19">
          This drive is encrypted with BitLocker. A startup PIN adds a second step
          before Windows loads, so a stolen device cannot simply be switched on.
        </TextBlock>
      </StackPanel>
      $($brand.DialogFooter)
    </Grid>

    <!-- Form -->
    <Border Grid.Column="1" Background="#FFF6F4FA">
      <Grid Margin="38,34,38,28">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Choose your startup PIN" FontSize="24" FontWeight="SemiBold"
                   Foreground="#FF1A1526" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="1" Foreground="#FF6B6480" FontSize="13" TextWrapping="Wrap" Margin="0,0,0,22" LineHeight="20">
          You will type this every time <Run FontWeight="SemiBold" Name="runDevice"/> starts, before Windows loads.
          Choose something you will remember - IT cannot look it up for you.
        </TextBlock>

        <TextBlock Grid.Row="2" Name="lblPin" FontSize="12.5" FontWeight="SemiBold"
                   Foreground="#FF1A1526" Margin="0,0,0,6"/>
        <PasswordBox Grid.Row="3" Name="pbPin" Margin="0,0,0,16"/>

        <TextBlock Grid.Row="4" Text="Confirm PIN" FontSize="12.5" FontWeight="SemiBold"
                   Foreground="#FF1A1526" Margin="0,0,0,6"/>
        <PasswordBox Grid.Row="5" Name="pbConfirm"/>

        <Border Grid.Row="6" Background="#FFF0FBFC" BorderBrush="#FFCFEEF0" BorderThickness="1"
                CornerRadius="3" Padding="14,11" Margin="0,18,0,0">
          <StackPanel>
            <TextBlock Text="Before you choose" FontSize="12" FontWeight="SemiBold"
                       Foreground="#FF0E7C86" Margin="0,0,0,7"/>
            <TextBlock Name="lblRules" Foreground="#FF4A4360" FontSize="12" TextWrapping="Wrap" LineHeight="18"/>
          </StackPanel>
        </Border>

        <Border Grid.Row="7" Name="pnlStatus" Background="#FFFFEBF1" BorderBrush="#FFFFC9DC"
                BorderThickness="1" CornerRadius="3" Padding="12,9" Margin="0,12,0,0"
                VerticalAlignment="Top" Visibility="Collapsed">
          <TextBlock Name="lblStatus" TextWrapping="Wrap" FontSize="12.5" Foreground="#FFC01A56"/>
        </Border>

        <StackPanel Grid.Row="9" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
          <Button Name="btnLater" Content="Remind me later" Width="140" Height="38" Margin="0,0,10,0" Style="{StaticResource Ghost}"/>
          <Button Name="btnSet"   Content="Set PIN"         Width="140" Height="38" IsDefault="True" Style="{StaticResource Primary}"/>
        </StackPanel>
      </Grid>
    </Border>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$win    = [Windows.Markup.XamlReader]::Load($reader)

# Paint the native title bar to match the window instead of building custom
# chrome. See Set-BrandedTitleBar in BitLockerPin.Common.ps1.
Set-BrandedTitleBar -Window $win

$pbPin     = $win.FindName('pbPin')
$pbConfirm = $win.FindName('pbConfirm')
$lblStatus = $win.FindName('lblStatus')
$pnlStatus = $win.FindName('pnlStatus')
$lblPin    = $win.FindName('lblPin')
$btnSet    = $win.FindName('btnSet')
$btnLater  = $win.FindName('btnLater')
$runDevice = $win.FindName('runDevice')

$lblRules = $win.FindName('lblRules')

$lblPin.Text    = "New PIN ($minPin to 20 digits)"
$runDevice.Text = $env:COMPUTERNAME
$lblRules.Text  = [string]::Join("`n", @(
    "-  $minPin to 20 digits, numbers only."
    '-  The startup keyboard always uses the US layout, so letters and symbols would be mistyped.'
    '-  Avoid repeated digits (222222) and runs (123456).'
    '-  You can change it later at any time - no admin rights needed.'
))
$script:success = $false

function Show-Status {
    param([string] $Text, [switch] $Info)
    $lblStatus.Text = $Text
    if ($Info) {
        $pnlStatus.Background  = '#FFF0FBFC'
        $pnlStatus.BorderBrush = '#FFCFEEF0'
        $lblStatus.Foreground  = '#FF0E7C86'
    }
    else {
        $pnlStatus.Background  = '#FFFFEBF1'
        $pnlStatus.BorderBrush = '#FFFFC9DC'
        $lblStatus.Foreground  = '#FFC01A56'
    }
    $pnlStatus.Visibility = 'Visible'
}

$btnLater.Add_Click({ $win.Close() })

# Closing the window with the X counts as deferring, same as the button. The task
# fires again on the next screen unlock, so "later" means "next time you come back
# to this machine" rather than a timer.
$win.Add_Closing({
    if (-not $script:success) {
        Write-PinLog 'Dialog dismissed without setting a PIN - will ask again after the next unlock.'
    }
})

$btnSet.Add_Click({
    $secure  = $pbPin.SecurePassword
    $confirm = $pbConfirm.SecurePassword

    # Everything knowable is checked before a protector is touched, so a bad PIN
    # can never put the volume into the swap window.
    $problem = Test-PinSecure -Pin $secure -Confirm $confirm -Min $minPin
    if ($problem) {
        Show-Status $problem
        try { $secure.Dispose(); $confirm.Dispose() } catch { }
        return
    }

    if ($PreviewUI) {
        Show-Status 'That PIN would be accepted. This is a preview - nothing was changed on this device.' -Info
        Write-PinLog 'Preview: a valid PIN was entered; no protector was touched.'
        return
    }

    $btnSet.IsEnabled   = $false
    $btnLater.IsEnabled = $false
    Show-Status 'Applying your PIN, please wait...' -Info
    $win.Dispatcher.Invoke([Action]{}, 'Render')

    $removedForReset = $false
    try {
        $current = Get-BitLockerVolume -MountPoint $sysDrive

        if ($Force) {
            # The reset path is the one flow that MUST remove before it adds: only
            # one TpmPin protector may exist, and the old PIN is unknown so it
            # cannot be reused. That opens a window where the volume is bootable
            # only by recovery key, so it is guarded by the recovery/escrow checks
            # above and by the rollback in the catch below.
            foreach ($p in @(Get-TpmFamilyProtector -Volume $current -Type 'TpmPin','TpmPinStartupKey')) {
                Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null
                $removedForReset = $true
                Write-PinLog "Removed the existing PIN protector $($p.KeyProtectorId) for a reset." 'WARN'
            }
        }

        # Add first. This succeeds even while the TPM-only protector is still
        # present, so nothing is at risk if it fails.
        #
        # Relaxed, because BitLocker validates the volume's WHOLE protector set on
        # any change: on a device whose profile requires a startup PIN
        # (UseTPMPIN=1) and disallows TPM-only (UseTPM=0), a volume still holding
        # just a Tpm protector is already non-compliant, and the very add that
        # would fix it is rejected with 0x80310061. The policy is restored
        # immediately afterwards, and the end state satisfies it.
        Invoke-WithStartupAuthRelaxed {
            Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmAndPinProtector -Pin $secure -ErrorAction Stop | Out-Null
        }
        Write-PinLog 'TpmAndPin protector added.'

        $current = Get-BitLockerVolume -MountPoint $sysDrive
        if (-not (Get-TpmFamilyProtector -Volume $current -Type 'TpmPin')) {
            throw 'The PIN protector is not present after the add - not removing the TPM-only protector.'
        }

        foreach ($p in @(Get-TpmFamilyProtector -Volume $current -Type 'Tpm','TpmStartupKey')) {
            Remove-BitLockerKeyProtector -MountPoint $sysDrive -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null
            Write-PinLog "Removed $($p.KeyProtectorType) protector $($p.KeyProtectorId)."
        }

        $final = Get-BitLockerVolume -MountPoint $sysDrive
        if (Get-TpmFamilyProtector -Volume $final -Type 'Tpm','TpmStartupKey') {
            Write-PinLog 'A TPM-only protector is still present - the PIN prompt would be skipped at boot.' 'ERROR'
            throw 'Could not remove the old protector. Contact the IT service desk.'
        }
        Write-PinLog "Final protectors: $(($final.KeyProtector.KeyProtectorType | Sort-Object -Unique) -join ',')"

        # Bookkeeping only - never let it fail an operation that already worked.
        $script:success = $true
        try {
            if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
            New-ItemProperty -Path $regKey -Name 'PinSetOn' -Value (Get-Date -Format 's') `
                             -PropertyType String -Force -ErrorAction Stop | Out-Null
        } catch { Write-PinLog "Could not write the PinSetOn marker: $($_.Exception.Message)" 'WARN' }

        # A self-service reset is the one path a user can drive on their own, so
        # it is the one that has to leave a trail: the counter feeds the throttle
        # and the event makes it visible off the device.
        if ($script:SelfService) {
            Add-PinResetRecord -RegKey $regKey
            Write-PinAudit -Action 'ResetCompleted' -Organization $Organization `
                           -Detail "Startup PIN replaced on $env:COMPUTERNAME by its assigned user."
        }

        Disable-EnrollmentTask
        $win.Close()
    }
    catch {
        # Captured now: the rollback below has its own try/catch, and the status
        # line must describe the failure that got us here, not a later one.
        $failure = $_.Exception.Message
        Write-PinLog "Failed to set the PIN: $failure" 'ERROR'

        # If the reset removed the old PIN protector and the replacement did not
        # land, the volume may now have no TPM-family protector at all and would
        # boot to the recovery screen. Put a TPM-only protector back so the device
        # still starts.
        $noPinNow = $false
        if ($removedForReset) {
            $restored = $false
            $pinNow   = $false
            try {
                $now = Get-BitLockerVolume -MountPoint $sysDrive
                if (-not (Get-TpmFamilyProtector -Volume $now -Type 'Tpm','TpmStartupKey','TpmPin','TpmPinStartupKey')) {
                    Invoke-WithStartupAuthRelaxed {
                        Add-BitLockerKeyProtector -MountPoint $sysDrive -TpmProtector -ErrorAction Stop | Out-Null
                    }
                    Write-PinLog 'Rolled back to a TPM-only protector so the device still boots.' 'WARN'
                }
                $after    = Get-BitLockerVolume -MountPoint $sysDrive
                $restored = [bool](Get-TpmFamilyProtector -Volume $after -Type 'Tpm','TpmStartupKey','TpmPin','TpmPinStartupKey')
                $pinNow   = [bool](Get-TpmFamilyProtector -Volume $after -Type 'TpmPin','TpmPinStartupKey')
            }
            catch { Write-PinLog "Rollback failed: $($_.Exception.Message)" 'ERROR' }

            if (-not $restored) {
                Write-PinLog 'NO TPM-FAMILY PROTECTOR REMAINS - this device will require the recovery key at next boot.' 'ERROR'
                [Windows.MessageBox]::Show(
                    "Something went wrong and this device is not safe to restart.`n`n" +
                    "Please contact the IT service desk before rebooting, and quote 'BitLocker PIN rollback failed'.",
                    'Do not restart this device', 'OK', 'Error') | Out-Null
            }
            elseif (-not $pinNow) {
                # The old PIN is gone and the new one never landed, so the device
                # now starts on the TPM alone - no PIN at all. A bare "could not
                # set your PIN" would leave the user believing the old PIN still
                # stands. Say what actually happened, and re-arm the enrolment
                # task so the ordinary prompt comes back at the next unlock even
                # if they walk away from this window.
                Write-PinLog 'The old PIN was removed and the new one was not added - this device now starts WITHOUT a PIN.' 'ERROR'
                Enable-EnrollmentTask
                $noPinNow = $true
            }
        }

        if ($script:SelfService) {
            Write-PinAudit -Action 'ResetFailed' -Organization $Organization `
                           -Detail ("Reset failed on $env:COMPUTERNAME : $failure" +
                                    $(if ($noPinNow) { ' - the device is left WITHOUT a startup PIN until one is set.' }))
        }

        if ($noPinNow) {
            # Short on purpose - the status panel is a few lines tall. The
            # underlying error is already in prompt.log and the audit event.
            Show-Status ("Your old PIN was removed but the new one could not be set, so this computer " +
                         "now starts WITHOUT a PIN. Try again now, or you will be asked at your next unlock.")
        }
        else {
            Show-Status "Could not set your PIN: $failure"
        }
        $btnSet.IsEnabled   = $true
        $btnLater.IsEnabled = $true
    }
    finally {
        # The PasswordBox hands out a fresh SecureString each time it is read; these
        # copies are ours to dispose.
        if ($secure)  { try { $secure.Dispose()  } catch { } }
        if ($confirm) { try { $confirm.Dispose() } catch { } }
    }
})

$win.ShowDialog() | Out-Null

if ($script:success) {
    [Windows.MessageBox]::Show(
        "Your startup PIN is set.`n`nFrom the next restart you will be asked for this PIN before Windows starts." +
        "`n`nYou can change it any time: press Start, type cmd, and run" +
        "`n    manage-bde -changepin C:`n`nIf you forget it, contact the IT service desk for a recovery key.",
        'Startup PIN set', 'OK', 'Information') | Out-Null
    Write-PinLog '--- Completed successfully ---'
}
exit 0
