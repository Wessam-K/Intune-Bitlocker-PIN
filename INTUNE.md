# Intune configuration

Everything you set in the portal, and — more importantly — how to stop this app
and your BitLocker policy from fighting each other.

- [The Win32 app](#the-win32-app)
- [Detection](#detection)
- [Remediations](#remediations)
- [Disk encryption policy](#disk-encryption-policy)
- [Compliance policy](#compliance-policy)
- [Autopilot and ESP](#autopilot-and-esp)

---

## The Win32 app

**Apps → Windows → Add → Windows app (Win32)**, upload the `.intunewin`.

To update later, replace the package file in **Properties**. Do **not** create a
second app.

### Program

| Field | Value |
|---|---|
| Installer type | Command line |
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BitLockerStartupPin.ps1 -MinimumPin 6` |
| Uninstaller type | Command line |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-BitLockerStartupPin.ps1` |
| Installation time required | 15 mins |
| Install behavior | **System** |
| Device restart behavior | No specific action |

Append `-Organization Contoso` to the install command if you changed the name.

You do not need to worry about bitness. The Intune Management Extension launches
install commands 32-bit, and the BitLocker module only loads in 64-bit
PowerShell — so every script relaunches itself through `%windir%\SysNative` when
it sees `PROCESSOR_ARCHITEW6432`. Plain `powershell.exe` lands in 64-bit either
way.

### Requirements

| Field | Value |
|---|---|
| Operating system architecture | **x64** |
| Minimum operating system | Windows 10 1809 |

### Return codes

Add **1618** if it is not already in the list. The rest are defaults.

| Code | Meaning | Type |
|---|---|---|
| 0 | Enrollment mechanism installed | Success |
| 1707 | — | Success |
| **1618** | **Not ready — encrypting, suspended, or escrow unconfirmed** | **Retry** |
| 3010 | Success, soft reboot | Soft reboot |
| 1641 | — | Hard reboot |
| 1 | Hard failure — read `install.log` | Failed |

**The installer returns 0 even when no PIN is set yet, and that is deliberate.**
It installs the *mechanism*; the PIN comes later from the dialog, which re-checks
every precondition on each run. An earlier version returned 1618 while a volume
was still encrypting — which meant a device in Autopilot ESP never received the
payload, so detection never succeeded and nothing ever prompted.

### Assignment

Device groups, **Required**. Start with 5–10 devices.

**Exclude** shared and kiosk machines, and anything you patch by Wake-on-LAN. A
pre-boot PIN prompt stops unattended boot dead.

---

## Detection

**Detection rules → Use a custom detection script** → upload
`Detect-BitLockerStartupPin.ps1`.

| Field | Value |
|---|---|
| Run script as 32-bit process | **No** |
| Enforce script signature check | No |

Leave the manual Type/Path/Code rules empty.

> **Re-upload the detection script every time you replace the package.** Both
> carry the same version string, and a mismatch causes either a permanent
> reinstall loop (detection older than the package) or a stuck stale build
> (detection newer).

It detects the **installed mechanism**, not the PIN. Detecting on "a `TpmPin`
protector exists" looks tempting, but it flaps: the installer returns 1618 on
devices that are mid-encryption, and a protector-based rule reports *failed* on
those until the retry lands. Real PIN coverage is the Remediations pair's job.

---

## Remediations

The Win32 app can only report *Installed* or *Failed*. A device can sit on
*Installed* for weeks while the user clicks *Remind me later* every morning. This
pair answers the question you actually care about.

**Devices → Scripts and remediations → Create**

| Field | Value |
|---|---|
| Detection script | `Detect-BitLockerPinCompliance.ps1` |
| Remediation script | `Remediate-BitLockerPinCompliance.ps1` |
| Run this script using the logged-on credentials | **No** |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | **Yes** |
| Schedule | Daily |

### What counts as compliant

All four must hold:

1. A `TpmPin` protector exists.
2. **No** plain `Tpm` protector remains — a leftover one silently cancels the PIN
   prompt at boot.
3. `ProtectionStatus` is `On`.
4. A recovery password exists.

It never reports compliant when it cannot tell. An unreadable volume returns
`UNKNOWN … exit 1`, so a broken query can never turn the fleet green.

### Reading the output

The single output line lands in the portal's **Detection output** column and
names the reason plus full context:

```
NONCOMPLIANT: no startup PIN protector - user has not set a PIN | device=DEV-00051
volume=FullyEncrypted protection=On protectors=Tpm,RecoveryPassword recovery=yes
escrowed=yes pinSetOn=never pinChangedByUser=no app=3.1.0 task=Ready
```

Sort the report on that column to separate **who has not set a PIN** from **who
cannot**.

`pinChangedByUser` comes from BitLocker events 777/789 — the only reliable
signal, because `ChangePIN` reuses the protector GUID, so comparing stored and
current IDs detects nothing. Use it to find who is still on a PIN that IT handed
them.

### What remediation will and will not do

It does what a script legitimately can:

1. Removes a stray `Tpm` protector that is cancelling an existing PIN. A real fix
   needing no user — and refused unless a recovery password exists.
2. Re-enables and restarts the enrollment task so the user is prompted again.

For anything needing a human — unencrypted volume, missing recovery password,
suspended protection — it **reports rather than pretends**, and exits non-zero so
it surfaces in the portal.

---

## Disk encryption policy

This is where deployments go wrong. Read it before you assign anything.

### Who owns what

| Job | Owner |
|---|---|
| Turning encryption **on**, choosing the cipher, escrowing the recovery key | Your Intune **disk encryption policy** |
| Collecting a PIN from the user and swapping the protector | **This app** |

Keep that split. Do not ask this app to start encryption on a managed fleet —
`-EnableEncryptionIfDecrypted` exists for lab devices and is off by default.

### Order of operations

1. Assign the disk-encryption policy. Let devices finish encrypting **and**
   confirm the recovery key is visible in Entra.
2. *Then* assign this app.

Reversing that order is harmless but slow: the installer returns 1618 (Retry) on
every device that is still encrypting, and waits for Intune to come back.

### The FVE values this app writes

`HKLM\SOFTWARE\Policies\Microsoft\FVE` — **backed up before the first write, and
restored on uninstall**.

| Value | Set to | Why |
|---|---|---|
| `UseAdvancedStartup` | `1` | Required. Without it, adding a PIN protector fails outright |
| `EnableBDEWithNoTPM` | `0` | No TPM, no PIN |
| `UseTPM` | `2` (allow) | **Never 0.** These values gate protector *creation*, so `UseTPM=0` makes every TPM-only fallback fail — including the rollback path, which would strand a device |
| `UseTPMPIN` | `2` (allow) | `2` not `1`, so a device that cannot take a PIN yet is not left unable to create any protector |
| `MinimumPIN` | your `-MinimumPin` | Default 6 |
| `UseEnhancedPin` | `0` | Digits only — the pre-boot keyboard is always US layout, so letters and symbols get mistyped |
| `OSEnablePrebootInputProtectorsOnSlates` | `1` | Tablets with no physical keyboard |
| `DisallowStandardUserPINReset` | `0` | Users may change their own PIN without calling anyone |

Two things it deliberately does **not** touch:

- **`UseTPMKey` and `UseTPMKeyPIN`** (the USB startup-key variants). This app
  never creates those protectors, so setting them buys nothing — and the Intune
  BitLocker CSP commonly sets them to `0`. Writing `2` there starts a tug-of-war
  the CSP wins on every sync, and produces event **851, "the Group Policy
  settings for BitLocker startup options are in conflict"**.
- **An existing `UseTPM`**, if another policy already set it. The installer logs
  that it is leaving it alone rather than overwriting a deliberate choice.

It also keeps a *stricter* existing setting: if it finds `UseTPMPIN = 1`
("require"), it leaves it at 1 rather than relaxing it to 2 ("allow").

### Conflicts to avoid

| Your policy sets | Result | Fix |
|---|---|---|
| **Require additional authentication at startup** = *Not configured* / *Disabled* | The CSP writes `UseAdvancedStartup = 0` on every sync and the PIN add fails | Set it to **Enabled** in your policy |
| **Configure TPM startup PIN** = *Do not allow startup PIN with TPM* | PIN creation is blocked | Set to **Allow** or **Require** |
| **Configure TPM startup** = *Do not allow TPM* | Blocks the TPM-only fallback, so rollback and error paths strand devices | Set to **Allow startup with TPM** |
| **Minimum PIN length** set in both your policy and `-MinimumPin` | The dialog honours whichever is higher, but the two disagreeing is confusing to support | Pick one. Prefer the Intune policy, and match `-MinimumPin` to it |
| Enhanced PIN enabled in policy | Users can enter letters they cannot retype on the pre-boot US-layout keyboard | Leave enhanced PINs off |

Settings-catalog path for all of these: **Administrative Templates → Windows
Components → BitLocker Drive Encryption → Operating System Drives**.

**In short:** configure your BitLocker policy to *permit* TPM+PIN, and let this
app *apply* it. If your policy forbids what the app is trying to create, the CSP
wins on every sync and the app loses on every run.

### Verifying there is no conflict

On a device that is misbehaving:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' |
    Select-Object UseAdvancedStartup, UseTPM, UseTPMPIN, MinimumPIN, UseEnhancedPin

# Event 851 here means two policies disagree.
Get-WinEvent -LogName 'Microsoft-Windows-BitLocker/BitLocker Management' -MaxEvents 40 |
    Where-Object Id -in 851, 845, 777, 789 |
    Select-Object TimeCreated, Id, Message
```

---

## Compliance policy

If you have a compliance policy requiring BitLocker, it checks *encryption*, not
*a startup PIN*. It will pass on a device that has never shown the dialog.

Use the [Remediations pair](#remediations) for PIN coverage reporting. If you
want PIN state to affect compliance, use a **custom compliance script** rather
than trying to bend the built-in BitLocker setting — the built-in one has no
concept of protector type.

Do **not** make a device non-compliant for lacking a PIN while the dialog is
still asking politely. You will lock people out of resources over a window they
have not seen yet.

---

## Autopilot and ESP

Do not put this app in the **Enrollment Status Page** blocking list.

At ESP time the disk is usually still encrypting, so the installer correctly
returns 1618 (Retry). A blocking ESP app that returns a retry code holds the
device on the ESP screen until it times out.

Assign it as a normal Required app instead. It lands after ESP, the user signs
in, and the dialog appears at the next logon or unlock — which is the intended
flow anyway, since there is no point asking for a PIN before there is a user to
ask.
