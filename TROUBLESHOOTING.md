# BitLocker Startup PIN — Troubleshooting Reference

Every diagnostic command used to get this app working, with what the output means.

**Paths and names**

| Thing | Value |
|---|---|
| Payload folder | `C:\ProgramData\WK-Hub\BitLockerPin` |
| Scheduled task | `WK-Hub BitLocker PIN Enrollment` |
| Registry markers | `HKLM:\SOFTWARE\WK-Hub\BitLockerPin` |
| FVE policy | `HKLM:\SOFTWARE\Policies\Microsoft\FVE` |
| BitLocker event log | `Microsoft-Windows-BitLocker/BitLocker Management` |

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
wordmark — see the README, "Branding". `Removed the stale brand image …` means an
upgrade dropped artwork the previous version shipped.

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
| `0x00041306` | Task was terminated (hit its 2-hour limit) |
| `0x80070005` | ServiceUI could not resolve the program — a **quoted** image path |
| `0xFFFD0000` (`-196608`) | Child process failed to start — a **space or quotes** in the `-File` path |

Force a run without waiting for a logon or unlock (**elevated**):

```powershell
Start-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment'
```

Trigger it the way a user would: press **Win+L**, sign back in, wait ~20 seconds.

---

## 4. Registry markers

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin' |
    Select-Object Version, InstalledOn, MinimumPin, UnlockTrigger, RecoveryEscrowed,
                  PinSetOn, PinAssignedOn, NotEncryptedWarnedOn, FvePolicyBackup
```

| Value | Meaning |
|---|---|
| `Version` | Installed app version. Detection compares against this — absence means the install did not finish |
| `InstalledOn` | Last successful install (ISO-8601) |
| `UnlockTrigger` | `1` = unlock trigger registered, `0` = fallback triggers in use |
| `RecoveryEscrowed` | `1` = recovery key confirmed in Entra at install time |
| `PinSetOn` | Written by the dialog when a user chose a PIN |
| `PinAssignedOn` | Written only by the optional unattended `-AssignDerivedPin` mode |
| `NotEncryptedWarnedOn` | Last time the "not encrypted" notice was shown (throttled to 24 h) |
| `FvePolicyBackup` | Pre-install FVE values, `Name=Value;…`; an empty value means "was absent" |

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
| `DisallowStandardUserPINReset` | `0` | `1` stops users changing their own PIN |

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
```

Both preview modes work with or without brand images present — without them the rail
draws the organization name as a wordmark on a solid colour.

Self-test suite (89 cases, touches no BitLocker state):

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
& 'C:\ProgramData\WK-Hub\BitLockerPin\Set-BitLockerPin.ps1' -Force

# remove the mechanism, keep the PIN protector
.\Uninstall-BitLockerStartupPin.ps1

# remove the mechanism AND roll the PIN back to TPM-only
.\Uninstall-BitLockerStartupPin.ps1 -RemovePinProtector
```

Full clean slate before a re-test:

```powershell
Unregister-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item 'C:\ProgramData\WK-Hub' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\WK-Hub' -Recurse -Force -ErrorAction SilentlyContinue
```

Rebuild the package after editing any script. `ServiceUI.exe` and
`IntuneWinAppUtil.exe` are Microsoft binaries you supply yourself — see the README,
"Binaries you must supply yourself". The `brand-*.png` files are optional; without them
both windows fall back to a text wordmark.

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
| Install exits 1: *"ServiceUI.exe is not in the package"* | The Microsoft binary was never copied into `Source\` before packaging — it is not redistributed here | README, "Binaries you must supply yourself" |
| Install exits 1: *"ServiceUI.exe hash mismatch"* | A `ServiceUI.exe` from a different MDT build than the pinned one | Verify the binary is genuine, then pass `-ServiceUiSha256 <hash>`. Do not remove the check |
| Install exits 1 at the payload copy: *"Access to the path … is denied"* | `icacls (OI)(CI)F` applied with `/T` made the file ACEs **inherit-only**, granting nothing on the files | Grant on the folder only, then `icacls <folder>\* /reset /T` |
| Install exits 1 at task registration | Mixing a `New-ScheduledTaskTrigger` object with a `New-CimInstance` unlock trigger fails PSTypeName binding | Register the task from XML |
| `XML task registration failed … (21,35):LogonType:ServiceAccount` | `<LogonType>` is out of range for the SYSTEM principal | Omit `LogonType`; keep only `UserId` + `RunLevel` |
| `icacls` exit `1332`, ACL silently unchanged | English account names don't resolve on a non-English Windows | Use SID literals (`*S-1-5-18`, `*S-1-5-32-544`) |
| Detection never succeeds, app reinstalls forever | Detection resolved `Program Files (x86)` under a 32-bit host | `%ProgramData%` + `Registry64` view |
| Device boots with no PIN prompt though `TpmPin` exists | A leftover `Tpm` protector cancels it | Remove the `Tpm` protector; reporting fails this state |
| App shows Installed but nothing appears | No logon/unlock since install — the task is `Ready`, waiting for a trigger | Press **Win+L**, sign back in, wait ~20 s |
