# BitLocker Startup PIN — Troubleshooting Reference

Every diagnostic command used to get this app working, with what the output means.

**Paths and names**

| Thing | Value |
|---|---|
| Payload folder | `C:\ProgramData\WK-Hub\BitLockerPin` |
| Scheduled task (enrolment) | `WK-Hub BitLocker PIN Enrollment` |
| Scheduled task (self-service reset) | `WK-Hub BitLocker PIN Reset` |
| Start-menu shortcut | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Reset BitLocker PIN.lnk` |
| Registry markers | `HKLM:\SOFTWARE\WK-Hub\BitLockerPin` |
| FVE policy | `HKLM:\SOFTWARE\Policies\Microsoft\FVE` |
| BitLocker event log | `Microsoft-Windows-BitLocker/BitLocker Management` |
| Reset audit events | Application log, source `WK-Hub-BitLockerPin`, IDs 3200–3204 |

The task names and the event source are derived from `-Organization` (default
`WK-Hub`); the shortcut name is the same for every organization.

**Elevation.** The payload folder is locked to SYSTEM + Administrators, so every log
read needs an elevated prompt. Start → type `powershell` → **Ctrl+Shift+Enter**.
Confirm before anything else — this must print `True`:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

---

## 1. The one command that answers "why didn't the PIN dialog appear?"

**Needs elevation.**

```powershell
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' -Tail 25
```

This is the dialog's own log. It records every path `Set-BitLockerPin.ps1` takes,
including the silent ones. What you'll see and what it means:

| Line in `prompt.log` | Meaning | Action |
|---|---|---|
| `--- PIN dialog invoked ---` and nothing after | Started but died; look for an `[ERROR]` line below it | — |
| `--- PIN dialog invoked (self-service) ---` | Started from the **Reset BitLocker PIN** shortcut, through the reset task | See section 11 |
| `AUDIT <Action> - …` | A self-service reset decision; the same text goes to events 3200–3204 | See sections 5 and 11 |
| `User deferred.` | User clicked **Remind me later** | Normal. Returns at next unlock |
| `Dialog dismissed without setting a PIN` | User closed the window with **X** | Normal. Returns at next unlock |
| `--- Completed successfully ---` | PIN set; task disables itself | Done |
| `Startup PIN already configured. Nothing to do.` | A `TpmPin` protector already exists | Done |
| `Session N is not the console session (M)` | Another session (RDP / fast user switching) — refuses on purpose | Have the person at the machine sign in |
| `Could not determine the console session` | `Add-Type`/`csc.exe` blocked **and** the fallback failed. Fails closed by design | Check EDR/WDAC blocking `csc.exe`, and `%TEMP%` health |
| `Volume is FullyDecrypted - no encryption` | Not encrypted; user gets the "contact IT" notice | Fix encryption first |
| `Encryption is still in progress` | Waiting, deliberately silent | Wait for encryption to finish |
| `BitLocker protection is suspended` | Suspended for servicing/firmware | Resume protection, or wait |
| `No recovery password protector on this volume` | Refuses to touch protectors without a recovery key | Add + escrow a recovery password |
| `Recovery key is not escrowed to Entra ID` | Escrow unconfirmed (no event 845) and the escrow call failed | Check network / Entra join |
| `FVE MinimumPIN is N, above ... 20-character maximum` | Policy demands a PIN longer than BitLocker allows | Lower `MinimumPIN` |
| `A TPM-only protector remains` | Removal failed; device does **not** prompt at boot | Investigate; task stays enabled to retry |
| `PIN protector present alongside a TPM-only protector` | Self-repair removing the protector that cancels the PIN | Normal, informational |

Live tail while you reproduce:

```powershell
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' -Wait -Tail 5
```

---

## 2. Other logs

**Installer log** (elevated) — FVE values written, escrow result, staging, task registration:

```powershell
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\install.log' -Tail 40
```

Two lines here are informational rather than faults:
`No brand image for: …` means no artwork was supplied, so the windows draw a text
wordmark — see [BRANDING.md](BRANDING.md). `Removed the stale brand image …` means an
upgrade dropped artwork the previous version shipped.

The self-service reset adds three lines: `Registered 'WK-Hub BitLocker PIN Reset' …`,
`Created the Start-menu shortcut at …` and `Created the 'WK-Hub-BitLockerPin' event
source …` (the last only on the first install, while the source does not yet exist).
If any of the three fails you get a `[WARN]` line instead — `Could not register the
self-service reset task`, `Could not create the Start-menu shortcut`, `Could not
create the event source` — and the install still succeeds. See section 11.

**Bootstrap log** — only used when the installer failed *before* the payload folder was
usable (bad owner, reparse point). Lands in the temp folder of whoever ran it:

The name carries a random suffix on purpose: under SYSTEM `$env:TEMP` is
`C:\Windows\Temp`, which is world-writable, and a predictable filename there lets a
standard user pre-create the path as a link and redirect a SYSTEM write. Match on the
prefix rather than a fixed name:

```powershell
# whoever ran it — newest first
Get-ChildItem "$env:TEMP\WK-Hub-BitLockerPin-install-*.log" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 20

# when Intune ran it (SYSTEM)
Get-ChildItem 'C:\Windows\Temp\WK-Hub-BitLockerPin-install-*.log' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 20
```

**Uninstall log** — in the payload folder if it still exists, otherwise a GUID-suffixed
file in temp:

```powershell
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\uninstall.log' -Tail 30
Get-ChildItem "$env:TEMP\WK-Hub-BitLockerPin-uninstall-*.log" |
    Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content
```

---

## 3. Scheduled task

```powershell
$t = Get-ScheduledTask     -TaskName 'WK-Hub BitLocker PIN Enrollment'
$i = Get-ScheduledTaskInfo -TaskName 'WK-Hub BitLocker PIN Enrollment'
"State      : $($t.State)"
"Triggers   : $(($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', ')"
"LastRun    : $($i.LastRunTime)"
("LastResult : 0x{0:X8}" -f $i.LastTaskResult)
"Action     : $($t.Actions[0].Execute)"
"Arguments  : $($t.Actions[0].Arguments)"
```

**State**

- `Ready` — armed, waiting for a logon or unlock
- `Running` — the dialog is open right now
- `Disabled` — a PIN was set successfully; the dialog disables its own task

**Triggers** — both must be listed:

- `MSFT_TaskLogonTrigger` (logon, 2-minute delay)
- `MSFT_TaskSessionStateChangeTrigger` (screen unlock, 20-second delay)

If you instead see `MSFT_TaskLogonTrigger` + `MSFT_TaskTimeTrigger`, XML registration
was rejected and the installer fell back to logon + hourly. Check `install.log` for
`XML task registration failed`; the `UnlockTrigger` registry value will be `0`.

**LastResult**

| Code | Meaning |
|---|---|
| `0x00000000` | Ran and exited cleanly — read `prompt.log` for which path it took |
| `0x00041301` | Task currently running (dialog open) |
| `0x00041303` | Task has never run |
| `0x00041306` | Task was terminated (hit its 2-hour limit; 30 minutes for the reset task) |
| `0x80070005` | ServiceUI could not resolve the program — a **quoted** image path |
| `0xFFFD0000` (`-196608`) | Child process failed to start — a **space or quotes** in the `-File` path |

Force a run without waiting for a logon or unlock (**elevated**):

```powershell
Start-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment'
```

Trigger it the way a user would: press **Win+L**, sign back in, wait ~20 seconds.

### The self-service reset task

`WK-Hub BitLocker PIN Reset` is a second task with **no triggers at all**. Nothing
schedules it, so it never prompts anyone on its own; it runs only when the **Reset
BitLocker PIN** shortcut (or an administrator) starts it. Like the enrolment task it
runs as SYSTEM through ServiceUI, here calling `Set-BitLockerPin.ps1 … -Manage`. It
ignores a second start while one is running (`IgnoreNew`) and stops after 30 minutes.

```powershell
$r  = Get-ScheduledTask     -TaskName 'WK-Hub BitLocker PIN Reset'
$ri = Get-ScheduledTaskInfo -TaskName 'WK-Hub BitLocker PIN Reset'
"State      : $($r.State)"
"Triggers   : $(@($r.Triggers).Count)"
"LastRun    : $($ri.LastRunTime)"
("LastResult : 0x{0:X8}" -f $ri.LastTaskResult)
"Arguments  : $($r.Actions[0].Arguments)"
```

Expected: `State` is `Ready` (`Running` while the window is open) — this task is never
disabled; `Triggers` is `0`; `Arguments` ends in `-Manage`. `LastRun` is the last time
anyone used the shortcut.

**Who may start which task.** The installer sets a different security descriptor on
each. Both give SYSTEM and Administrators full control; they differ only in the entry
for authenticated users (`AU`):

| Task | Set by the installer | Authenticated users |
|---|---|---|
| Enrolment | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)` | `GR` — can see the task, cannot start it |
| Reset | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)` | `GRGX` — can see it **and start it** |

`GX` is the single bit that makes self-service possible. Starting the task is not the
privilege; passing the gates inside `-Manage` is (section 11). Read the descriptors
back (**elevated**):

```powershell
$svc = New-Object -ComObject Schedule.Service; $svc.Connect()
foreach ($n in 'WK-Hub BitLocker PIN Enrollment','WK-Hub BitLocker PIN Reset') {
    '{0,-32} {1}' -f $n, $svc.GetFolder('\').GetTask($n).GetSecurityDescriptor(4)
}
```

Windows stores the generic rights translated, so the `AU` entry typically reads back
as `FR` on the enrolment task and as read-plus-execute (`0x1200a9`) on the reset task.
The definitive test is functional — from a **standard user's** (non-elevated) prompt.
The first command really starts the self-service flow; press **Close** in the window
it opens (**Remind me later** if the device has no PIN yet and it shows the PIN dialog).

```powershell
schtasks /run /tn "WK-Hub BitLocker PIN Reset"        # SUCCESS: Attempted to run ...
schtasks /run /tn "WK-Hub BitLocker PIN Enrollment"   # ERROR: Access is denied.
```

If the first one is also denied, the reset task's ACL was not applied — look for
`Could not register the self-service reset task` in `install.log`.

---

## 4. Registry markers

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin' |
    Select-Object Version, InstalledOn, MinimumPin, UnlockTrigger, RecoveryEscrowed,
                  PinSetOn, PinAssignedOn, NotEncryptedWarnedOn, FvePolicyBackup,
                  ResetCount, LastResetOn, ResetHistory
```

| Value | Meaning |
|---|---|
| `Version` | Installed app version. Detection compares against this — absence means the install did not finish |
| `InstalledOn` | Last successful install (ISO-8601) |
| `UnlockTrigger` | `1` = unlock trigger registered, `0` = fallback triggers in use |
| `RecoveryEscrowed` | `1` = recovery key confirmed in Entra at install time |
| `PinSetOn` | Written by the dialog whenever a PIN is set — first PIN, self-service reset or `-Force` |
| `PinAssignedOn` | Written only by the optional unattended `-AssignDerivedPin` mode |
| `NotEncryptedWarnedOn` | Last time the "not encrypted" notice was shown (throttled to 24 h) |
| `FvePolicyBackup` | Pre-install FVE values, `Name=Value;…`; an empty value means "was absent" |
| `ResetHistory` | `REG_MULTI_SZ`, one `yyyy-MM-ddTHH:mm:ss` timestamp per **completed** self-service reset, trimmed to 30 days. The daily limit is counted from this value |
| `LastResetOn` | Time of the last completed self-service reset (ISO-8601) |
| `ResetCount` | `DWORD`, total completed self-service resets on this device. Never trimmed |

The three reset values are absent until the first self-service reset completes.
Refused and abandoned attempts write nothing here (they are in `prompt.log` and the
event log), and a service-desk `-Force` reset does not count either.

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin').ResetHistory   # one line per reset
```

---

## 5. BitLocker state

```powershell
# elevated
Get-BitLockerVolume -MountPoint C: | Format-List VolumeStatus, ProtectionStatus, KeyProtector
manage-bde -protectors -get C:
manage-bde -status C:
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled
```

**A correctly enrolled device shows** `TpmPin` **and** `RecoveryPassword`, with **no**
`Tpm` protector.

> A plain `Tpm` protector alongside `TpmPin` means the device boots with **no PIN prompt
> at all** — Windows documents that the TPM-only protector "negates the effects of other
> TPM-based key protectors". `TpmPin` being present is not sufficient; the `Tpm` one must
> be gone.

### Event log (readable by a standard user — no elevation needed)

```powershell
$log = 'Microsoft-Windows-BitLocker/BitLocker Management'
Get-WinEvent -FilterHashtable @{ LogName = $log; Id = @(775,776,777,789,845,846,778,851) } -MaxEvents 30 |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap
```

| ID | Meaning |
|---|---|
| 775 | Protector created (`ProtectorType`: `0x1` Tpm, `0x3` RecoveryPassword, `0x4` TpmPin) |
| 776 | Protector removed |
| **777** | PIN was **updated** (carries the protector GUID) |
| **789** | PIN was changed |
| 790 / 791 | PIN change failed / change facility locked out |
| **845** | Recovery info backed up to Entra ID — the escrow proof this app requires |
| **846** | Escrow **failed** (carries the HRESULT) |
| 778 | Volume reverted to an unprotected state |
| 851 | Silent encryption failed — often *"Group Policy settings for BitLocker startup options are in conflict"* |

Did anyone change their PIN? (777/789 are the only reliable signal — `ChangePIN` reuses
the protector GUID, so comparing IDs detects nothing):

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; Id = @(777,789) } -MaxEvents 10
```

Was the recovery key really escrowed?

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; Id = @(845,846) } -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap
```

### Reset audit events (Application log)

Every self-service reset decision is written to the **Application** log under the
source `WK-Hub-BitLockerPin`, and the same text to `prompt.log` as an `AUDIT` line.
The events are what a collector can pick up off the device — Azure Monitor Agent with a
data collection rule, Windows Event Forwarding, a SIEM forwarder; configure whichever
you use to gather this source. Reading them locally normally needs no elevation:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='WK-Hub-BitLockerPin' } -MaxEvents 20 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap
```

| ID | Action | Level | Meaning |
|---|---|---|---|
| 3200 | `ResetAllowed` | Information | All three gates passed (enrolled user, under the limit, identity confirmed); the PIN dialog is about to open. The message says which method verified them: `Windows Hello` or `Windows password` |
| 3201 | `ResetDenied` | Warning | Not the enrolled user, Windows Hello declined, or the password was rejected — the message says which |
| 3202 | `ResetThrottled` | Warning | The device has reached its limit of 3 completed resets in 24 hours |
| 3203 | `ResetCompleted` | Information | The new PIN protector is in place |
| 3204 | `ResetFailed` | Warning | The protector change failed. If the message ends *"the device is left WITHOUT a startup PIN until one is set"*, see section 11 |

A 3200 with no 3203 or 3204 after it usually means the user reached the PIN dialog and
closed it without setting a PIN — `prompt.log` confirms. Only the self-service flow
writes these IDs; a service-desk `-Force` reset writes none of them (the BitLocker
log's 775/776 still record the protector change).

---

## 6. FVE policy

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' |
    Select-Object UseAdvancedStartup, UseTPM, UseTPMPIN, MinimumPIN, UseEnhancedPin,
                  DisallowStandardUserPINReset, OSEnablePrebootInputProtectorsOnSlates,
                  UseTPMKey, UseTPMKeyPIN, OSRequireActiveDirectoryBackup
```

Semantics for `UseTPM*`: **0 = disallow, 1 = require, 2 = allow.**

| Value | Required | Why |
|---|---|---|
| `UseAdvancedStartup` | `1` | Without it the PIN add fails: *"Group Policy settings do not permit the use of a startup PIN"* |
| `UseTPMPIN` | `1` or `2` | `0` blocks the PIN add outright |
| `UseTPM` | `2` (never `0`) | `0` blocks every TPM-only fallback, including the lockout-prevention rollback |
| `MinimumPIN` | 6–20 | Above 20 makes the dialog unsatisfiable |
| `UseEnhancedPin` | `0` | Pre-boot keyboard is always US layout; alphanumeric PINs get mistyped |
| `DisallowStandardUserPINReset` | `0` | `1` stops users changing their own PIN with Windows' change-PIN, which needs the old PIN. The self-service reset for a forgotten PIN does not depend on it |

**If `UseTPMPIN` keeps flipping back to `0`,** an Intune BitLocker profile owns this key
and is re-stamping it. In the profile set *Operating System Drives → Require additional
authentication at startup → **Configure TPM startup PIN: Allow startup PIN with TPM***,
or exclude these devices from that profile. The dialog re-asserts the value at prompt
time, but that is a safety net, not a fix.

The app deliberately does **not** write `UseTPMKey` / `UseTPMKeyPIN` — it never creates
USB startup-key protectors, and writing them fights the CSP for no benefit (that fight
produces event 851).

---

## 7. Detection and Intune

Run detection exactly as Intune does (**elevated**; `0` = Installed):

```powershell
.\Detect-BitLockerStartupPin.ps1
"detection exit: $LASTEXITCODE"
```

Real PIN coverage — the Remediations pair, run exactly as Intune does (**elevated**;
detection `0` = compliant, `1` = remediate):

```powershell
$p = '.'      # or the full path to your checkout
& "$p\Detect-BitLockerPinCompliance.ps1"
"detection exit: $LASTEXITCODE   (0 = compliant)"

# only on a device the detection marked non-compliant
& "$p\Remediate-BitLockerPinCompliance.ps1"
"remediation exit: $LASTEXITCODE   (0 = handled, 1 = needs attention)"
```

Detection output decodes as:

| Prefix | Meaning |
|---|---|
| `COMPLIANT:` | PIN protector present, no TPM-only protector, protection On, recovery password present |
| `NONCOMPLIANT: no startup PIN protector` | The user has not set a PIN yet — the common case |
| `NONCOMPLIANT: TPM-only protector present alongside the PIN` | Device does **not** prompt at boot; remediation fixes this |
| `NONCOMPLIANT: no recovery password protector` | Do not enforce a PIN until this is fixed |
| `NONCOMPLIANT: volume is not encrypted` | The app shows the user a "contact IT" notice |
| `UNKNOWN:` | Could not determine state — always exits 1, never reports compliant |

Other fields on the same line: `pinSetOn` (when it was set, or `never`),
`pinChangedByUser` (events 777/789 — did they replace an IT-issued PIN), `escrowed`,
`app`, `task`.

`Report-BitLockerPinStatus.ps1` was superseded by this pair and removed; the self-test
fails if it ever comes back, so that two scripts never own this job.

Intune Management Extension logs — `AppWorkload.log` holds install and detection activity:

```powershell
$d = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
Select-String -Path "$d\AppWorkload.log" -Pattern 'BitLocker-Startup-Pin','BitLockerStartupPin' -SimpleMatch |
    Select-Object -Last 20 | ForEach-Object { ($_.Line -replace '\s+',' ').Trim() }

Select-String -Path "$d\AppWorkload.log" -Pattern 'detection state','enforcement state','exit code' |
    Select-Object -Last 20 | ForEach-Object { ($_.Line -replace '\s+',' ').Trim() }
```

Useful strings: `DetectionActionHandler`, `detection state: NotDetected`,
`ResultantAppState`, `Win32AppDownloadExecutor`.

**Installer exit codes**

| Code | Meaning | Intune |
|---|---|---|
| 0 | Enrollment mechanism installed | Success |
| 1618 | TPM present but not yet provisioned | Retry |
| 3010 | Success, soft reboot | Success |
| 1 | Hard failure — read `install.log` | Failed |

Intune retries a failed install 3 times at 5-minute intervals, then waits for the 8-hour
re-evaluation. Force a check-in from **Company Portal → Sync**, or the portal's **Sync**
device action.

---

## 8. Previewing the UI (no admin, no BitLocker changes)

Run these from the repo folder:

```powershell
.\Set-BitLockerPin.ps1 -PreviewUI              # the PIN dialog; Set PIN only validates
.\Set-BitLockerPin.ps1 -PreviewNotEncrypted    # the "device is not encrypted" notice
.\Set-BitLockerPin.ps1 -PreviewManage          # the self-service "Your startup PIN is set" window;
                                               # "Reset my PIN" then shows the password prompt
```

`-PreviewManage` verifies nothing and changes nothing: there is no identity check, no
Windows Hello prompt, and the password you type is discarded. It shows the windows a
user sees, for checking wording, layout and branding.

All three preview modes work with or without brand images present — without them the
rail draws the organization name as a wordmark on a solid colour.

Self-test suite (119 cases, touches no BitLocker state, needs no elevation). The
self-service identity comparison runs for real against synthetic identities, the
throttle against a throwaway registry key, and the Windows Hello result channel against
throwaway child processes:

```powershell
.\Test-BitLockerPinApp.ps1
```

---

## 9. Manual install, reset, uninstall

All **elevated**, from the repo folder.

```powershell
# install exactly as Intune does
.\Install-BitLockerStartupPin.ps1 -MinimumPin 6

# log everything, change nothing
.\Install-BitLockerStartupPin.ps1 -DryRun

# force a user to choose a NEW PIN (removes the old protector first; guarded and rolled back)
# the service desk's way in: skips the self-service gates, writes no reset events
& 'C:\ProgramData\WK-Hub\BitLockerPin\Set-BitLockerPin.ps1' -Force

# remove the mechanism, keep the PIN protector
.\Uninstall-BitLockerStartupPin.ps1

# remove the mechanism AND roll the PIN back to TPM-only
.\Uninstall-BitLockerStartupPin.ps1 -RemovePinProtector
```

Start the self-service reset by hand — exactly what the **Reset BitLocker PIN** shortcut
does. This one needs **no** elevation; run it as the signed-in user at the console:

```powershell
schtasks /run /tn "WK-Hub BitLocker PIN Reset"
```

On a device that already has a PIN it goes through all the gates (enrolled user, daily
limit, Windows Hello or password), so it reproduces what the user sees; on a device
with no PIN yet it simply shows the ordinary first-PIN dialog. Gate decisions land in
`prompt.log` and events 3200–3204. Use `-Force` above when the gates themselves are
the problem.

The uninstaller removes the reset task and the shortcut but deliberately **leaves the
event source** registered, so the reset events already in the Application log stay
readable.

Full clean slate before a re-test:

```powershell
Unregister-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Reset' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Reset BitLocker PIN.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\ProgramData\WK-Hub' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\WK-Hub' -Recurse -Force -ErrorAction SilentlyContinue
```

Removing `HKLM:\SOFTWARE\WK-Hub` also clears `ResetHistory`, so the daily reset limit
starts from zero. The event source is left alone here too; remove it only if you accept
that earlier reset events will no longer render
(`Remove-EventLog -Source 'WK-Hub-BitLockerPin'`).

Rebuild the package after editing any script. `ServiceUI.exe` and
`IntuneWinAppUtil.exe` are Microsoft binaries you supply yourself — see
[docs/REFERENCE.md §5.1](docs/REFERENCE.md#51-binaries-you-must-supply-yourself). The `brand-*.png` files are optional; without them
the branded windows (the PIN dialog, the notice and the self-service window) fall back
to a text wordmark.

```powershell
Copy-Item .\Install-BitLockerStartupPin.ps1,.\Uninstall-BitLockerStartupPin.ps1,`
          .\Set-BitLockerPin.ps1,.\BitLockerPin.Common.ps1,.\ServiceUI.exe `
          -Destination .\Source -Force
Copy-Item .\brand-*.png -Destination .\Source -Force -ErrorAction SilentlyContinue

.\IntuneWinAppUtil.exe -c .\Source -s Install-BitLockerStartupPin.ps1 -o .\Output -q
```

---

## 10. Failure signatures seen during development

Each of these cost real time. If you see the symptom, this is the cause.

| Symptom | Cause | Fix |
|---|---|---|
| Task `LastResult 0x80070005`, no dialog | ServiceUI's image path was **quoted**; it strips quotes and then cannot resolve the program | Pass the `powershell.exe` path unquoted |
| Task `LastResult 0xFFFD0000` (`-196608`), no dialog | ServiceUI stripped the quotes around `-File "C:\Program Files\..."`, so PowerShell saw `-File C:\Program` | Payload path must contain **no space** — hence `%ProgramData%` |
| Install exits 1, `install.log` **empty** | Failure before the log path existed (directory owner / reparse check) | Bootstrap log now covers this |
| Install exits 1: *"ServiceUI.exe is not in the package"* | The Microsoft binary was never copied into `Source\` before packaging — it is not redistributed here | [docs/REFERENCE.md §5.1](docs/REFERENCE.md#51-binaries-you-must-supply-yourself) |
| Install exits 1: *"ServiceUI.exe hash mismatch"* | A `ServiceUI.exe` from a different MDT build than the pinned one | Verify the binary is genuine, then pass `-ServiceUiSha256 <hash>`. Do not remove the check |
| Install exits 1 at the payload copy: *"Access to the path … is denied"* | `icacls (OI)(CI)F` applied with `/T` made the file ACEs **inherit-only**, granting nothing on the files | Grant on the folder only, then `icacls <folder>\* /reset /T` |
| Install exits 1 at task registration | Mixing a `New-ScheduledTaskTrigger` object with a `New-CimInstance` unlock trigger fails PSTypeName binding | Register the task from XML |
| `XML task registration failed … (21,35):LogonType:ServiceAccount` | `<LogonType>` is out of range for the SYSTEM principal | Omit `LogonType`; keep only `UserId` + `RunLevel` |
| `icacls` exit `1332`, ACL silently unchanged | English account names don't resolve on a non-English Windows | Use SID literals (`*S-1-5-18`, `*S-1-5-32-544`) |
| Detection never succeeds, app reinstalls forever | Detection resolved `Program Files (x86)` under a 32-bit host | `%ProgramData%` + `Registry64` view |
| Device boots with no PIN prompt though `TpmPin` exists | A leftover `Tpm` protector cancels it | Remove the `Tpm` protector; reporting fails this state |
| App shows Installed but nothing appears | No logon/unlock since install — the task is `Ready`, waiting for a trigger | Press **Win+L**, sign back in, wait ~20 s |

---

## 11. Self-service PIN reset

**How it works, in one pass.** A user who has forgotten their PIN needs the 48-digit
**recovery key once**, to get past the pre-boot screen and into Windows — the reset only
exists inside Windows. There they choose **Start → Reset BitLocker PIN**, which starts
the `WK-Hub BitLocker PIN Reset` task, which runs `Set-BitLockerPin.ps1 -Manage` as
SYSTEM on their desktop. The same console-session guard and pre-flight as enrolment
apply (encrypted, protection on, recovery password present and escrowed), so everything
in section 1 still holds. A device with **no PIN yet** gets the ordinary first-PIN
dialog. A device **with** a PIN gets the "Your startup PIN is set" window: **Close** is
the default button, so Enter never starts a reset. **Reset my PIN** then runs three
gates in order, each failing closed:

1. **Identity** — the console user's cached Entra UPN must equal the UPN recorded at MDM
   enrolment.
2. **Throttle** — at most 3 completed self-service resets in a rolling 24 hours.
3. **Re-authentication** — a Windows Hello prompt in the user's own session. Only when
   Hello cannot run at all does it fall back to the user's Windows password.

All three passed → event 3200, then the normal PIN dialog in reset mode (the same code
path as the service desk's `-Force`). Success → event 3203 and the reset values in
section 4.

Everything below uses the default organization `WK-Hub`; substitute yours in the task
name, the registry path and the event source if you changed `-Organization`.

```powershell
# what the shortcut runs (as the signed-in user; no elevation)
schtasks /run /tn "WK-Hub BitLocker PIN Reset"

# every reset decision, newest last
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='WK-Hub-BitLockerPin' } -MaxEvents 50 |
    Sort-Object TimeCreated | Format-Table TimeCreated, Id, Message -Wrap

# the self-service trail in prompt.log (elevated)
Select-String -Path 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' `
              -Pattern 'self-service','AUDIT','Hello','password','Reset throttled','reset history',
                       'enrolled user','enrolment UPN','cached UPN','WITHOUT a PIN','Rolled back','Failed to set' |
    Select-Object -Last 30 | ForEach-Object Line

# reset bookkeeping for this device
Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin' |
    Select-Object PinSetOn, ResetCount, LastResetOn, ResetHistory
```

Whichever gate refused, the service desk can still reset the PIN with `-Force`
(section 9): it skips all three gates and is reachable only by administrators.

### The Start-menu shortcut is missing

**Cause.** The installer could not create the shortcut or register the reset task.
Either failure is a `[WARN]` in `install.log`, never an install failure — without them
the user simply falls back to the service desk. Detection deliberately checks neither,
so Intune still reports the app as Installed. The other cause is a device still on a
release before 3.3.0, which has no self-service at all.

**What to do** (elevated):

```powershell
Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Reset BitLocker PIN.lnk"
Get-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Reset' -ErrorAction SilentlyContinue
(Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin').Version        # 3.3.0 or later
Select-String -Path 'C:\ProgramData\WK-Hub\BitLockerPin\install.log' `
              -Pattern 'reset task','Start-menu shortcut','event source' |
    Select-Object -Last 6 | ForEach-Object Line
```

The `WARN` line carries the exception. Fix what it names, then reinstall (section 9,
or let Intune reinstall a new package version). Reinstalling registers the task, the
shortcut and the event source; a device that already has a PIN is not re-prompted. If
the task exists but the shortcut does not, the user can run the `schtasks /run` line
above in the meantime.

### The shortcut runs but no window appears

**Cause.** The task started, and `Set-BitLockerPin.ps1` chose not to show anything.
Because the reset uses the same pre-flight as enrolment, the reasons are the ones in the
section 1 table: not the console session (an RDP session), encryption still in progress,
protection suspended, no recovery password, recovery key not escrowed. A second click
while the window is already open is ignored (`IgnoreNew`), and the open window may be
behind another one.

**What to do.** Read the tail of `prompt.log` (section 1). The last
`--- PIN dialog invoked (self-service) ---` line and whatever follows it names the
reason. `Get-ScheduledTaskInfo` on the reset task (section 3) confirms whether it ran at
all.

### "Only the assigned user can reset this PIN"

Event **3201** with *"Console user '…' is not the enrolled user '…'"*.

**Cause.** The identity gate compares the Entra UPN Windows has cached for the console
user with the UPN recorded when the device enrolled into Intune. They differ, or one of
them is missing. `prompt.log` says which:

| Line in `prompt.log` | Cause |
|---|---|
| `Console user user@example.com is not the enrolled user …` | A different person, or a device that changed hands without being re-enrolled |
| `Console user S-1-5-21-… has no cached UPN - a local account is never the primary user.` | Signed in with a local account |
| `No MDM enrolment UPN on this device - cannot establish the primary user.` | Enrolled by a service account — a device enrolment manager, a provisioning package or self-deploying Autopilot — which records that account or none |
| `Console session could not be identified.` | Same fail-closed case as `Could not determine the console session` in section 1 |

That direction of failure is deliberate. Being sent to the service desk is recoverable;
letting any signed-in user re-PIN someone else's device is not. The notice shows a
reference box with the device name, the signed-in UPN and the assigned UPN, so the
user can quote both values to the service desk.

**What to do.** Compare the two values yourself (elevated):

```powershell
# 1. the UPN recorded at MDM enrolment (the Enrollments key that also carries ProviderID)
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Where-Object { $_.UPN -and $_.ProviderID } | Select-Object UPN, ProviderID

# 2. the UPN cached for each signed-in user; the gate uses the console session's row
query session
Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
    $sid = (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid
    [pscustomobject]@{
        Session = $_.SessionId
        Sid     = $sid
        Upn     = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$sid\IdentityCache\$sid" `
                       -ErrorAction SilentlyContinue).UserName
    }
}
```

`query session` marks the console session `console`; the row with that session ID is
the one the gate compares. The comparison ignores case and surrounding spaces, so any
visible difference is a real one. An empty `Upn` is a local account. If the device
genuinely belongs to the signed-in user now, re-enrol it under that user — changing the
primary user in the Intune portal does not rewrite the local enrolment UPN. Until then,
reset with `-Force`. Shared and kiosk devices should be excluded from the app for this
reason among others.

### "Too many PIN resets today"

Event **3202**.

**Cause.** The device already has 3 **completed** self-service resets in the last
24 hours (`ResetHistory`, section 4). Refused and abandoned attempts, failed resets
and service-desk `-Force` resets do not count. `prompt.log` reads
`Reset throttled: 3 resets in the last 24 hours (limit 3).`

If it reads `Could not read the reset history - refusing: …`,
`The reset history is a <type>, not a list of dates - refusing.` or
`Could not evaluate the reset history - refusing: …` instead, the throttle could not
trust `ResetHistory` and failed **closed** — the user sees the same notice, but the
cause is the value, not the number of resets. An entry that is not a date also counts
as a recent reset, so a damaged history can produce the ordinary `Reset throttled`
line too; look at the value itself.

**What to do.** Several resets in one day are worth a conversation first: either
someone is probing, or the user is on the way to locking themselves out. Then either
reset it for them with `-Force` (not counted, not throttled), or lift the limit by
clearing the history (elevated):

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin').ResetHistory     # what is being counted
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin' -Name ResetHistory
```

The next completed reset recreates it. `ResetCount` and `LastResetOn` are left alone,
so the device's history stays visible. Clear it only with a reason, and record why.
Otherwise the limit lifts by itself 24 hours after the oldest of the counted resets.

### The Windows Hello prompt never appears

**Symptom.** After **Reset my PIN** the user gets the "Confirm it is you" password window
instead of Hello, and `prompt.log` has
`Windows Hello unusable (Unavailable) - falling back to the password check.`
(or `(Error)`).

**Cause.** The line just before it says why Hello could not run:

| Line before it | Cause |
|---|---|
| `Windows Hello is not usable on this device for this user.` | Hello is not set up for this user, there is no Hello-capable device, or policy disables it |
| `Cannot launch the Hello verifier - P/Invoke unavailable: …` | `Add-Type` (the C# compiler, `csc.exe`) is blocked, usually by WDAC or EDR — the same exposure as the console-session check |
| `Hello verifier could not be started (<stage> failed, Win32 <n>).` | Launching the verifier into the user's session failed at `WTSQueryUserToken`, `DuplicateTokenEx`, `CreateProcessAsUser`, `CreateNamedPipe` or the security-descriptor step |
| `Windows PowerShell 5.1 not found - Hello verification cannot run.` | The verifier needs Windows PowerShell 5.1; PowerShell 7 cannot host it |
| `Windows Hello verification errored (result <n>).` | The verifier itself hit an error |
| `Windows Hello gave no authenticated result (…)` | See the next entry |

The password fallback is a real credential check, but it only works where Windows
holds a cached password for the account — see "Password rejected" below. When `Add-Type`
is blocked, the password check cannot run either (`Cannot verify the password -
P/Invoke unavailable`), so self-service cannot work on that device until `csc.exe` is
allowed; use `-Force`.

**A different symptom: the prompt appeared but nothing happened.** The verifier shows a
small dark *"Waiting for Windows Hello..."* window, and the Hello prompt opens in front
of it. If the user cancels, fails too often, or leaves it for about two minutes,
`prompt.log` reads `declined or cancelled`, `shown but never answered` or `timed out`,
the user sees **"Identity was not verified"**, and event 3201 says
*"Windows Hello verification declined"*. There is deliberately **no** password fallback
after a declined Hello prompt — that would turn a failed check into a second guess at a
different credential. The user starts again from the Start menu and answers the prompt.

### prompt.log says "gave no authenticated result"

Full line:
`Windows Hello gave no authenticated result (<stage>; verifier exit <n>) - not treated as verified.`

**What it means.** The Hello verifier runs as the signed-in user (Hello cannot run as
SYSTEM), so anything else running as that user could end it with a fake exit code. The
exit code is therefore never trusted alone: the verifier reports over a one-time named
pipe that SYSTEM creates before launching it, and a result counts only if it arrives
from the verifier's own process ID **and** the exit code agrees. This line means that
check failed — the result could not be authenticated. It is treated neither as verified
nor as declined; the user falls through to the password prompt (logged as
`Windows Hello unusable (Error)`).

The stage in brackets says what went wrong:

| Stage | Meaning |
|---|---|
| `exited without reporting` | The verifier process ended without sending a report — it crashed, was closed, or was ended by something else |
| `report came from process <n>, not the verifier` | Another process connected to the pipe |
| `malformed report` | Something arrived on the pipe that was not a valid report |
| `exit code <x> contradicts the report <y>` | The report and the exit code disagree |
| `GetNamedPipeClientProcessId`, `exception: …` | The check itself could not complete |

**What to do.** A single occurrence can be a crash or a user closing windows. Repeated
occurrences on one device deserve a look: something in the user's session may be
interfering with the verifier — security software hooking PowerShell, or something
worse. Be clear about the limit, too: code already running as the signed-in user can
still inject into the verifier itself. The gate stops a passer-by at an unlocked
session; it is not a defence against malware in the user's session.

### Password rejected on an Entra-joined, Hello-only device

**Symptom.** The user types their correct password and gets **"That password was not
accepted"**; event 3201 *"Password verification failed"*; `prompt.log` has
`Password check failed for user@example.com (Win32 1326).`

**Cause.** 1326 is `ERROR_LOGON_FAILURE`. The check validates against **cached**
credentials, so it works offline — but Windows only caches a password verifier for an
account that has signed in to this device with its password at least once. On an
Entra-joined device whose user has only ever used Windows Hello there is none, and the
correct password is rejected with 1326 exactly like a wrong one. Other codes are
ordinary logon errors; `net helpmsg <n>` decodes them.

**What to do.** The user resets through Windows Hello instead — which is why Windows
Hello for Business being provisioned matters for self-service on Entra-joined devices.
If Hello is not available, either the user signs in to Windows once with their password
(after which the fallback works), or the service desk resets with `-Force`.

### The device was left WITHOUT a PIN after a failed reset

**Symptom.** The PIN dialog says *"Your old PIN was removed but the new one could not be
set, so this computer now starts WITHOUT a PIN. Try again now, or you will be asked at
your next unlock."* Event **3204**'s message ends
*"- the device is left WITHOUT a startup PIN until one is set."* In `prompt.log`:

```text
[ERROR] Failed to set the PIN: <the real error>
[WARN]  Rolled back to a TPM-only protector so the device still boots.
[ERROR] The old PIN was removed and the new one was not added - this device now starts WITHOUT a PIN.
[INFO]  Re-enabled scheduled task 'WK-Hub BitLocker PIN Enrollment'.
```

**Cause.** The reset had already removed the old PIN protector, and adding the new one
failed. Rather than leave a volume that would boot to the recovery screen, the dialog
put a TPM-only protector back: the device starts, but with **no PIN**. It re-enabled the
enrolment task so the ordinary PIN prompt returns at the next logon or unlock, even if
the user walks away. The daily Remediation also reports it
(`NONCOMPLIANT: no startup PIN protector`). A failed reset does not count toward the
daily limit.

**What to do.** Confirm the state (elevated):

```powershell
manage-bde -protectors -get C:      # expect "TPM" + "Numerical Password", no "TPM And PIN"
(Get-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment').State     # expect Ready
```

Fix whatever the `Failed to set the PIN:` line names — a policy refusal points at the FVE
values in section 6 — then have the user set a PIN: straight away in the same dialog, at
the next unlock, or with `-Force`. If `prompt.log` shows `Could not re-enable the task`
instead, run `Enable-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment'`.

If even the rollback failed, the user saw **"Do not restart this device"** and
`prompt.log` has `Rollback failed:`. The volume may have no TPM-family protector left and
would boot to the recovery screen. Before anyone restarts it, check with
`manage-bde -protectors -get C:` and, if there is no TPM protector, add one:
`manage-bde -protectors -add C: -tpm`.

### No reset events in the Application log

**Cause.** The `WK-Hub-BitLockerPin` event source is not registered. The installer
creates it, and a failure is a `[WARN]` in `install.log` (`Could not create the event
source`), not an install failure. Without the source the reset still works and
`prompt.log` still gets every `AUDIT` line; only the event — the part a collector can
see off the device — is skipped, silently. If `prompt.log` has
`Could not write the audit event: …` instead, the source exists and the write itself
failed.

**What to do** (elevated):

```powershell
[System.Diagnostics.EventLog]::SourceExists('WK-Hub-BitLockerPin')        # expect True
Select-String -Path 'C:\ProgramData\WK-Hub\BitLockerPin\install.log' -Pattern 'event source' |
    Select-Object -Last 3 | ForEach-Object Line
Select-String -Path 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' -Pattern 'AUDIT' |
    Select-Object -Last 10 | ForEach-Object Line
```

Register it by reinstalling, or directly with
`New-EventLog -LogName Application -Source 'WK-Hub-BitLockerPin'`. Decisions made
before that exist only as `AUDIT` lines in `prompt.log`. The `Created the … event
source` line appears only on the install that created it, so its absence from a later
install is not a fault. If the events are on the device but not in your central log,
the collector is not gathering this source.
