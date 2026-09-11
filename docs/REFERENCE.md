# BitLocker Startup PIN — engineering reference

> Deep reference. If you just want to deploy it, start with **[QUICKSTART.md](../QUICKSTART.md)**.

Prompts the signed-in user to choose a BitLocker pre-boot startup PIN (TPM+PIN) and
applies it. Users do **not** need local administrator rights.

| | |
|---|---|
| **Package** | `Output\Install-BitLockerStartupPin.intunewin` |
| **Version** | 3.1.0 |
| **Tests** | 92 passing (`Test-BitLockerPinApp.ps1`) |
| **Target** | Windows 10 1809+ / Windows 11, x64, Entra-joined, TPM 2.0 |
| **Troubleshooting** | [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) |

---

## 1. What the user sees

**A window at logon, and after every screen unlock, until a PIN is set.** It shows
the device name, two PIN boxes, the rules, and inline validation. The title bar is a real
Windows caption painted in the brand colour, so the window can be moved, minimised and
closed normally.

- **Set PIN** — validates, applies the protector, confirms, and disables its own task.
- **Remind me later** (or the **X**) — asks again **at the next screen unlock**. Event-based
  on purpose: it catches people when they return to the machine instead of interrupting
  them on a timer.

**If the device is not encrypted**, they get a different, information-only notice: it says
so plainly, says it is not something they can fix, and gives a copyable reference line
(device name + volume state) for the service desk. Throttled to once per 24 hours.
Encryption still *in progress*, or a suspended-but-encrypted volume, stay silent —
warning about transient states teaches people to dismiss IT windows.

Preview either window, no admin and no BitLocker changes:

```powershell
.\Set-BitLockerPin.ps1 -PreviewUI              # the PIN dialog
.\Set-BitLockerPin.ps1 -PreviewNotEncrypted    # the "not encrypted" notice
```

---

## 2. Architecture

### The problem it works around

Adding a BitLocker key protector requires administrator rights, and our users have none.
Intune runs in **session 0**, which has no interactive desktop — which is why
`manage-bde -changepin` silently fails when a Win32 app calls it directly. So the PIN
cannot be collected by the installer, and it cannot be applied by the user.

The app therefore splits into an unattended part and an interactive part, and bridges the
session boundary with `ServiceUI.exe`.

```
┌─ Intune Management Extension (SYSTEM, session 0, 32-bit) ────────────────┐
│                                                                         │
│  Install-BitLockerStartupPin.ps1                                        │
│    ├─ relaunch via %windir%\SysNative ─────────────► 64-bit PowerShell  │
│    ├─ TPM readiness            (Get-Tpm)                                │
│    ├─ FVE policy + backup      (HKLM\...\Policies\Microsoft\FVE)        │
│    ├─ encryption / recovery password / Entra escrow (event 845)         │
│    ├─ stage payload            ─► C:\ProgramData\<Org>\BitLockerPin     │
│    ├─ harden folder            (icacls, SID literals, SYSTEM+Admins)    │
│    └─ register scheduled task  (Task Scheduler XML 1.2)                 │
│                                                                         │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ triggers: logon +2 min, session unlock +20 s
                              ▼
┌─ Task "WK-Hub BitLocker PIN Enrollment" (SYSTEM, HighestAvailable) ─────┐
│                                                                         │
│  ServiceUI.exe -process:explorer.exe  powershell.exe -File …            │
│    └─ hooks explorer.exe to borrow the user's desktop,                  │
│       while the process itself stays SYSTEM                             │
│                                                                         │
└─────────────────────────────┬───────────────────────────────────────────┘
                              ▼
┌─ Set-BitLockerPin.ps1  (SYSTEM, rendering in the user's session) ───────┐
│                                                                         │
│  console-session guard (fail closed)                                    │
│  encryption scan ─► not encrypted? ─► "contact IT" notice, exit         │
│  recovery password + escrow gate   ─► refuse if unproven                │
│  WPF dialog (XAML) ─► SecureString validation (no managed string)       │
│  ADD TpmAndPin ─► verify ─► REMOVE Tpm ─► verify ─► disable own task    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Reporting, deployed separately as an Intune Remediation:
  Detect-BitLockerPinCompliance.ps1    ─► is a PIN really set and enforced?
  Remediate-BitLockerPinCompliance.ps1 ─► fix what a script can, prompt again
```

### Why the protector order is add → verify → remove

A volume can hold **both** a `Tpm` and a `TpmPin` protector, and Windows documents that the
plain TPM protector *"negates the effects of other TPM-based key protectors"*. So a device
holding both boots with **no PIN prompt at all**, while any check that merely looks for
`TpmPin` reports success.

Adding first means the device stays bootable throughout, and a failed add has removed
nothing. Removing first — the obvious order, and what most published scripts do — opens a
window in which only the 48-digit recovery key can unlock the volume.

### State it owns on the device

Everything is namespaced under the `-Organization` value, which defaults to `WK-Hub`.
Change it once in each script (the self-test asserts they agree) and every path below
moves with it.

| Location | Contents |
|---|---|
| `C:\ProgramData\WK-Hub\BitLockerPin` | payload, `install.log`, `prompt.log`; ACL: SYSTEM + Administrators only |
| `HKLM\SOFTWARE\WK-Hub\BitLockerPin` | `Version`, `InstalledOn`, `MinimumPin`, `UnlockTrigger`, `RecoveryEscrowed`, `PinSetOn`, `NotEncryptedWarnedOn`, `FvePolicyBackup` |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | 8 values, previous state saved for uninstall |
| Task Scheduler | `WK-Hub BitLocker PIN Enrollment` |

---

## 3. Languages, frameworks and tooling

Everything is Windows-native and needs no runtime beyond what ships with the OS —
deliberately, so there is nothing to install, patch, or get blocked by app control.

| Technology | Where | Why this and not something else |
|---|---|---|
| **Windows PowerShell 5.1** | all eight scripts | What ships in-box and what the Intune agent and Task Scheduler invoke. PowerShell 7 is not on a stock image, and the `BitLocker` module is a CDXML module over WMI that 5.1 loads natively |
| **XAML / WPF** (`PresentationFramework`) | the PIN dialog and the notice window | In-box GUI with real layout and DPI scaling. WinForms would not scale cleanly at 150 %; a web UI would need a runtime |
| **Task Scheduler XML** (schema 1.2) | task registration | The session-unlock trigger has no cmdlet, and mixing a `New-CimInstance` trigger with a `New-ScheduledTaskTrigger` one fails PSTypeName binding. XML sidesteps both |
| **C# via `Add-Type`** (P/Invoke) | `dwmapi!DwmSetWindowAttribute` for the brand-coloured caption; `kernel32!WTSGetActiveConsoleSessionId` for the session guard | No managed API exposes either. Both have compile-free fallbacks, because `Add-Type` spawns `csc.exe` and EDR/WDAC can block that |
| **WMI / CIM** | `Win32_Process` (find an open dialog), `MSFT_ScheduledTask`, `Win32_EncryptableVolume` via the `BitLocker` module | Architecture-neutral and in-box |
| **Win32 console tools** | `icacls.exe` (folder hardening), `manage-bde.exe` (user-facing PIN change) | `icacls` is called with **SID literals** only — English account names fail with exit 1332 on non-English Windows |
| **`ServiceUI.exe`** | session-0 → user-desktop bridge | Microsoft binary, x64, Microsoft-signed, **SHA256-pinned** by the installer. Not shipped with this package — see §5 |
| **Markdown** | this file, `TROUBLESHOOTING.md` | — |
| **IntuneWinAppUtil.exe** | packaging | Microsoft Win32 Content Prep Tool. Not shipped with this package — see §5 |

**Not used, on purpose:** Electron or any bundled runtime (adds ~150 MB and solves nothing
— a non-admin process still cannot add a key protector); compiled binaries (nothing to
sign or version); PowerShell 7 (not on a stock image); external modules (nothing to trust
or update).

---

## 4. Components

| File | Runs as | Job |
|---|---|---|
| `Install-BitLockerStartupPin.ps1` | SYSTEM | FVE policy, encryption/escrow checks, staging, task registration |
| `Set-BitLockerPin.ps1` | SYSTEM, on the user's desktop | the dialog and the notice; validates the PIN and swaps the protector |
| `BitLockerPin.Common.ps1` | dot-sourced | shared helpers: escrow check, policy relax, path hardening, console session |
| `ServiceUI.exe` | — | lends session 0 the user's desktop. **You supply this** — see §5 |
| `brand-*.png` | — | optional brand images used by both windows — see §5 |
| `Detect-BitLockerStartupPin.ps1` | SYSTEM | Win32 **app** detection rule (uploaded separately) |
| `Uninstall-BitLockerStartupPin.ps1` | SYSTEM | removes the mechanism, restores the FVE policy |
| `Detect-BitLockerPinCompliance.ps1` | SYSTEM, 64-bit | **Remediations** detection — is a PIN really set and enforced? |
| `Remediate-BitLockerPinCompliance.ps1` | SYSTEM, 64-bit | **Remediations** fix — clears a cancelling protector, re-prompts |
| `Test-BitLockerPinApp.ps1` | any | 89-case self-test, touches no BitLocker state |

`Source\` is the packaging staging folder — the content-prep tool reads it, not the repo
root. Copy the four scripts into it (plus `ServiceUI.exe` and any brand PNGs) before
building; §5 has the exact command.

---

## 5. What you must supply, and how to build

### 5.1 Binaries you must supply yourself

Two Microsoft tools are needed and are **deliberately not redistributed here** — their
licences are Microsoft's to grant, not this package's. Download them once, keep them out
of source control, and the rest works unchanged.

| File | Where it comes from | Where to put it |
|---|---|---|
| `ServiceUI.exe` (x64) | Microsoft Deployment Toolkit (MDT). Install the MDT MSI, then take the x64 build from `C:\Program Files\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x64\ServiceUI.exe`. MDT has been retired, so archive a copy of the MSI once you have it | next to these scripts, and into `Source\` before packaging |
| `IntuneWinAppUtil.exe` | Microsoft Win32 Content Prep Tool — the official repository is `microsoft/Microsoft-Win32-Content-Prep-Tool` on GitHub; download the released `IntuneWinAppUtil.exe` | anywhere on `PATH`, or the repo root |

The installer refuses to run without `ServiceUI.exe`, checks that it carries a valid
Microsoft Authenticode signature, and compares its SHA256 against a pinned value — this
binary becomes the entry point of a SYSTEM scheduled task, so it is not taken on trust.
The pinned default is the MDT 8456 x64 build. If your copy comes from a different MDT
release the install fails with the hash it actually saw; satisfy yourself the binary is
genuine and then pass that hash:

```powershell
.\Install-BitLockerStartupPin.ps1 -ServiceUiSha256 '<SHA256 OF YOUR SERVICEUI.EXE>'
```

Loosening or removing the check is the wrong fix.

### 5.2 Branding (optional)

Both windows draw a brand rail. It is a **drop-in, never a dependency**: supply artwork
and it is staged and used automatically; supply none and the windows fall back to a text
wordmark on a solid colour, with the same layout and the same behaviour. A missing image
can never stop the dialog appearing — the markup for an image is only emitted when the
file is actually there, because WPF resolves `<Image Source="…"/>` while the XAML is
being parsed.

Drop your own PNGs next to the scripts (and into `Source\` before packaging) under exactly
these names:

| File | Used for | Suggested size |
|---|---|---|
| `brand-logo-square.png` | window icon and the mark at the top of the rail | 256 × 256, transparent background |
| `brand-logo-on-dark.png` | wordmark at the foot of the rail; must read on a dark backdrop | ~600 × 160, transparent background |
| `brand-background.png` | backdrop image behind the rail, overlaid with a dark scrim | ~800 × 1200, portrait |

Any of the three can be omitted independently. The wordmark text and the fallback colour
come from `Get-BrandXaml` in `BitLockerPin.Common.ps1`: the text is the `-Organization`
value, and `-BrandColour` (default `#FF2E3A38`) is the same value as the window
background, so an unbranded window looks deliberate rather than broken. An upgrade that
drops artwork the previous version had also removes the stale file from the device.

### 5.3 Build

```powershell
Copy-Item .\Install-BitLockerStartupPin.ps1,.\Uninstall-BitLockerStartupPin.ps1,`
          .\Set-BitLockerPin.ps1,.\BitLockerPin.Common.ps1,.\ServiceUI.exe `
          -Destination .\Source -Force
# plus any brand-*.png you supplied
Copy-Item .\brand-*.png -Destination .\Source -Force -ErrorAction SilentlyContinue

.\IntuneWinAppUtil.exe -c .\Source -s Install-BitLockerStartupPin.ps1 -o .\Output -q
```

The packager reads `Source\`, not the repo root, so an edited script that was not copied
across ships the old version.

---

## 6. Intune: the Win32 app

Create **Apps → Windows app (Win32)** and upload the `.intunewin`. To update, replace the
package file in **Properties** — do not create a second app.

**Program**

| Field | Value |
|---|---|
| Installer type | Command line |
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BitLockerStartupPin.ps1 -MinimumPin 6` |
| Uninstaller type | Command line |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-BitLockerStartupPin.ps1` |
| Installation time required | 15 mins |
| Install behavior | **System** |
| Device restart behavior | No specific action |

Bitness is handled by the scripts: each relaunches itself through `%windir%\SysNative` when
it sees `PROCESSOR_ARCHITEW6432`, so plain `powershell.exe` lands in 64-bit either way.

**Requirements:** OS architecture x64, minimum Windows 10 1809.

**Detection rules:** *Use a custom detection script* → upload
`Detect-BitLockerStartupPin.ps1`. Run as 32-bit: **No**. Enforce signature check: **No**.
Leave the manual Type/Path/Code rules empty.

> Re-upload the detection script whenever you replace the package. Both carry the same
> version, and a mismatch causes either a permanent reinstall loop or a stuck stale build.

**Return codes** — add 1618 if not already present:

| Code | Meaning | Type |
|---|---|---|
| 0 | Enrollment mechanism installed | Success |
| 1707 | — | Success |
| 1618 | TPM present but not yet provisioned | **Retry** |
| 3010 | Success, soft reboot | Soft reboot |
| 1641 | — | Hard reboot |
| 1 | Hard failure — read `install.log` | Failed |

**The installer returns 0 even when no PIN is set yet, deliberately.** It installs the
*mechanism*; the PIN comes later from the dialog, which re-checks every precondition each
run. An earlier version returned 1618 while a volume was still encrypting, which meant a
device in Autopilot ESP never received the payload — so detection never succeeded and
nothing ever prompted.

**Assignment:** device groups, Required. Start with 5–10 devices. Exclude shared/kiosk
machines and anything patched by Wake-on-LAN.

---

## 7. Intune: the Remediation (PIN coverage)

**The Win32 app can only report Installed or Failed — that is the mechanism, not the PIN.**
A device can show *Installed* for weeks while the user keeps clicking *Remind me later*.
This pair answers the real question.

**Devices → Scripts and remediations → Create**

| Field | Value |
|---|---|
| Detection script | `Detect-BitLockerPinCompliance.ps1` |
| Remediation script | `Remediate-BitLockerPinCompliance.ps1` |
| Run this script using the logged-on credentials | **No** |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | **Yes** |
| Schedule | Daily |

**Detection reports compliant only when all four hold:** a `TpmPin` protector exists, **no**
plain `Tpm` protector remains, `ProtectionStatus` is On, **and** a recovery password
exists. It never reports compliant when it cannot tell — an unreadable volume returns
`UNKNOWN … exit 1`, so a broken query can never turn the fleet green.

Its single output line lands in the portal's *Detection output* column and names the reason
plus the full context, for example:

```
NONCOMPLIANT: no startup PIN protector - user has not set a PIN | device=DEV-00051
volume=FullyEncrypted protection=On protectors=Tpm,RecoveryPassword recovery=yes
escrowed=yes pinSetOn=never pinChangedByUser=no app=3.1.0 task=Ready
```

so you can sort the report by *who has not set a PIN* versus *who cannot*.

**Remediation** does what a script legitimately can:

1. Removes a stray `Tpm` protector that is cancelling an existing PIN — a real fix, needing
   no user, and refused unless a recovery password exists.
2. Re-enables and restarts the enrollment task so the user is prompted again.
3. **Reports rather than pretends** for anything needing a human — unencrypted volume,
   missing recovery password, suspended protection — and exits non-zero so it surfaces.

`pinChangedByUser` comes from events 777/789, the only reliable signal: `ChangePIN` reuses
the protector GUID, so comparing stored and current IDs detects nothing. Use it to see who
is still on a PIN that IT handed them.

---

## 8. Design decisions worth knowing

**`UseTPM` is never set to 0.** FVE values gate protector *creation*, so `UseTPM=0` makes
every TPM-only fallback impossible — including the rollback after a failed add. Enforce
"PIN required" with a compliance policy instead.

**Protector work runs with startup-auth policy temporarily relaxed.** BitLocker validates
the volume's whole protector set on *any* change, so a device already non-compliant with
its own policy cannot be repaired. Seen in the field: a profile setting `UseTPM=0` +
`UseTPMPIN=1` on a volume still holding only a `Tpm` protector made even *adding the
recovery password* fail with `0x80310061` — a deadlock, since the PIN add is what would
make it compliant. `Invoke-WithStartupAuthRelaxed` relaxes both values for the duration of
each call and always restores them; the end state satisfies the strict policy anyway.

**Escrow is a prerequisite, enforced at the point of change.** The dialog will not touch a
protector unless a recovery password exists *and* Entra escrow is either confirmed by event
845 or freshly succeeded in that run. The check is three-state — escrowed / no evidence /
cannot tell — because `Get-WinEvent` **throws** when a filter matches nothing, so a naive
`try/catch` collapses "never escrowed" into "log unreadable".

**Digits only.** `UseEnhancedPin = 0`: the pre-boot keyboard is always US layout, so an
alphanumeric PIN gets mistyped at boot on a German keyboard.

**The PIN never becomes a managed string.** A `System.String` cannot be zeroed, so it would
linger in the freed heap of a long-lived SYSTEM process. Validation reads the
`SecureString` BSTRs directly and zeroes them, and never uses `-match` (which would leave
the PIN in `$Matches`).

**`icacls` uses SID literals, never account names,** which fail with exit 1332 on
non-English Windows and leave the ACL untouched.

**The payload path must contain no space.** ServiceUI strips double quotes from the command
line it forwards, so a path under `C:\Program Files\...` arrives as `-File C:\Program` and
the dialog never starts. The installer throws if the path ever contains whitespace.

**The dialog only draws on the console session,** and fails closed if it cannot determine
which — otherwise, with fast user switching or RDP, the wrong user could choose the PIN
everyone types at boot.

**Policy ownership.** The app writes only what a PIN needs, and never `UseTPMKey` /
`UseTPMKeyPIN` — it creates no USB startup-key protectors, and writing those merely fights
the Intune BitLocker CSP, producing event 851 *"BitLocker startup options are in
conflict"*. If `UseTPMPIN` keeps reverting to `0`, set *Configure TPM startup PIN: Allow
startup PIN with TPM* in the profile, or exclude these devices from it.

---

## 9. Changing or resetting a PIN

- **User, self-service, no admin:** `manage-bde -changepin C:` or Control Panel → BitLocker
  → *Change PIN*. Requires the current PIN.
- **Service desk forcing a new PIN:** run `Set-BitLockerPin.ps1 -Force` as SYSTEM. This is
  the one path that must remove the PIN protector before adding its replacement, so it
  verifies a recovery password first and rolls back to a TPM-only protector if the
  replacement fails.
- **Forgotten PIN:** issue the recovery key from Entra (*Devices → device → BitLocker
  keys*). Nobody can read or reset a user's PIN.

**Unattended mode** (PIN derived from the device name) is implemented and tested but **off
by default**: `-AssignDerivedPin -PinPrefix "111" -DeviceNumberLength 4` turns a device named
`DEV-0051` into `1110051`. Such a PIN is guessable by anyone who knows the naming scheme, so it only
makes sense as an enrolment PIN users are told to change.

---

## 10. Testing

```powershell
.\Test-BitLockerPinApp.ps1
```

92 cases: PIN derivation, the FVE plan, junction and ownership handling, the `ServiceUI.exe`
hash pin, payload/detection agreement, a real XAML render of both windows branded and
unbranded, the Remediations pair's fail-safe behaviour, and a regression for every bug found
during development. It changes no BitLocker state, and it passes with no `ServiceUI.exe`
and no brand images present — those checks verify the supplied file when there is one.

**Verify on a pilot device before widening the ring:**

1. Install; confirm the dialog appears at logon or unlock.
2. `manage-bde -protectors -get C:` shows `TpmPin` and **no** `Tpm` protector.
3. Reboot: the pre-boot prompt appears and the chosen PIN works.
4. The recovery key is visible in Entra.
5. As a standard user, `manage-bde -changepin C:` succeeds.
6. `Uninstall-BitLockerStartupPin.ps1 -RemovePinProtector` leaves the device booting without
   the recovery key.

---

## 11. Troubleshooting

See **[TROUBLESHOOTING.md](../TROUBLESHOOTING.md)** — every diagnostic command, what each log
line means, task result codes, and the failure signatures hit during development.

The single most useful command when the dialog does not appear (needs elevation):

```powershell
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' -Tail 25
```

The dialog logs every exit path it takes — deferral, wrong session, suspended volume,
escrow refusal, unencrypted drive — so that file names the reason instead of leaving you
guessing.

---

## 12. Rollout gotchas

- **Autopilot / ESP:** the app installs during device prep; the dialog appears at first
  sign-in (2-minute logon delay).
- **Wake-on-LAN patching breaks.** A pre-boot PIN stops unattended reboots. Deploy
  BitLocker Network Unlock first, or accept the PIN screen.
- **Shared / kiosk / lab devices:** exclude them. There is no "the user" to own a PIN.
- **`OSRequireActiveDirectoryBackup`** (*"Do not enable BitLocker until recovery information
  is stored"*) makes Windows wait only ~60 s for a network connection. On an offline or
  captive-portal device that can make protector operations fail — the app degrades safely,
  but enrollment quietly will not complete. Test one roaming device.
- **A device encrypted with only a `Tpm` protector and nothing escrowed** is one firmware
  update away from unrecoverable data. The Remediation detection surfaces these
  (`recovery=NO`); fix those before worrying about PINs.
- **Pilot with 5–10 devices** and rehearse the recovery-key process with the service desk
  before widening.
