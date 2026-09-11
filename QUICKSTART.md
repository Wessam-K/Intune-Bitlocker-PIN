# Quick start

Ten steps, roughly an hour including the pilot. Every command is copy-paste.

If a step fails, the answer is almost always in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

> **Before anything else:** open the Entra portal, pick a device you manage, and
> find its BitLocker recovery key (**Devices → the device → BitLocker keys**). If
> you cannot do that today, stop. A pre-boot PIN turns "forgot my password" into
> "needs a recovery key", and you need that path working *first*.

---

## Step 1 — Check a device qualifies

Run this on one device you intend to pilot with. It only reads.

```powershell
# Needs an elevated PowerShell.
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled
Get-BitLockerVolume -MountPoint $env:SystemDrive |
    Select-Object VolumeStatus, ProtectionStatus, @{n='Protectors';e={
        ($_.KeyProtector.KeyProtectorType) -join ','}}
```

You want:

| Field | Wanted | If not |
|---|---|---|
| `TpmPresent` / `TpmReady` | `True` | No TPM 2.0 — this device cannot use a startup PIN |
| `VolumeStatus` | `FullyEncrypted` | Encrypt it first; see [INTUNE.md](INTUNE.md#disk-encryption-policy) |
| `ProtectionStatus` | `On` | Protection is suspended — resume it |
| `Protectors` | includes `RecoveryPassword` | **Stop.** No recovery key means no way back |

`Tpm` in the protector list is normal — that is the TPM-only protector this app
replaces with `TpmPin`.

---

## Step 2 — Get the two Microsoft binaries

Neither is included here. Their licences are Microsoft's to grant, not this
package's.

**`ServiceUI.exe` (x64)** — from the Microsoft Deployment Toolkit. Install the MDT
MSI, then take the x64 build from:

```
C:\Program Files\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x64\ServiceUI.exe
```

MDT is retired, so **archive a copy of that MSI** once you have it.

**`IntuneWinAppUtil.exe`** — the Microsoft Win32 Content Prep Tool. Download the
released binary from the `microsoft/Microsoft-Win32-Content-Prep-Tool` repository
on GitHub.

Put `ServiceUI.exe` next to these scripts and `IntuneWinAppUtil.exe` anywhere on
your `PATH`. Both are in `.gitignore`, so neither gets committed by accident.

The installer verifies `ServiceUI.exe` carries a valid Microsoft Authenticode
signature and matches a **pinned SHA256** — it becomes the entry point of a SYSTEM
scheduled task, so it is not taken on trust. The pinned default is the MDT 8456
x64 build. If your copy is from a different MDT release the install fails and
tells you the hash it saw. Satisfy yourself the binary is genuine, then pass it:

```powershell
.\Install-BitLockerStartupPin.ps1 -ServiceUiSha256 '<SHA256 OF YOUR SERVICEUI.EXE>'
```

Loosening or deleting that check is the wrong fix.

---

## Step 3 — Set your organization name (optional, but do it)

`-Organization` is the one knob everybody turns. It namespaces the registry key,
the `%ProgramData%` folder, the scheduled task name, and the wordmark shown when
you supply no logo. It defaults to `WK-Hub`.

**It must contain no spaces** — `ServiceUI.exe` strips quotes from the command
line it forwards, so a name with a space arrives split and the install refuses to
register the task.

Intune passes `-Organization` to the installer, but the detection and remediation
scripts are uploaded to Intune on their own and **take no arguments**, so their
defaults have to match. Change all six together:

```powershell
# Replace Contoso with your own single-word name.
$org   = 'Contoso'
$files = @('Install-BitLockerStartupPin.ps1','Detect-BitLockerStartupPin.ps1',
           'Uninstall-BitLockerStartupPin.ps1','Set-BitLockerPin.ps1',
           'Detect-BitLockerPinCompliance.ps1','Remediate-BitLockerPinCompliance.ps1')
foreach ($f in $files) {
    (Get-Content $f -Raw).Replace("`$Organization = 'WK-Hub'", "`$Organization = '$org'") |
        Set-Content $f -NoNewline
}

# Prove it took. This must print "92 passed, 0 failed".
.\Test-BitLockerPinApp.ps1
```

Two of those 92 tests exist specifically to catch a half-finished rename: one
asserts all six files agree on the name, the other asserts the task name is
*derived* from it rather than hardcoded.

---

## Step 4 — Add your branding (optional)

Skip this and the dialog draws your organization name as a text wordmark on a
solid colour — deliberate-looking, not broken. To use your own artwork, see
**[BRANDING.md](BRANDING.md)**. It takes three PNGs and about five minutes.

---

## Step 5 — Build the `.intunewin`

`Source\` starts empty — it is a staging folder, not a second copy of the repo.
The packager reads it rather than the repo root, so an edited script you forgot
to copy across ships the old version. Always run both commands together.

```powershell
Copy-Item .\Install-BitLockerStartupPin.ps1,.\Uninstall-BitLockerStartupPin.ps1,`
          .\Set-BitLockerPin.ps1,.\BitLockerPin.Common.ps1,.\ServiceUI.exe `
          -Destination .\Source -Force

# Only if you added branding in step 4.
Copy-Item .\brand-*.png -Destination .\Source -Force -ErrorAction SilentlyContinue

.\IntuneWinAppUtil.exe -c .\Source -s Install-BitLockerStartupPin.ps1 -o .\Output -q
```

You now have `Output\Install-BitLockerStartupPin.intunewin`.

---

## Step 6 — Create the Intune app

**Apps → Windows → Add → Windows app (Win32)** and upload the `.intunewin`.

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BitLockerStartupPin.ps1 -MinimumPin 6` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-BitLockerStartupPin.ps1` |
| Install behavior | **System** |
| Device restart behavior | No specific action |
| Requirements | x64, Windows 10 1809 or later |

Add `-Organization Contoso` to the install command if you changed it in step 3.

Full field-by-field detail, including the return codes you must add, is in
**[INTUNE.md](INTUNE.md)**.

---

## Step 7 — Upload the detection script

**Detection rules → Use a custom detection script** → upload
`Detect-BitLockerStartupPin.ps1`. Run as 32-bit: **No**. Enforce signature check:
**No**. Leave the manual Type/Path/Code rules empty.

> Re-upload this script **every time** you replace the package. Both carry the
> same version number, and a mismatch causes either a permanent reinstall loop or
> a stuck stale build.

---

## Step 8 — Assign to a pilot group

Device group, **Required**, **5–10 devices**.

Exclude shared and kiosk machines, and anything you patch via Wake-on-LAN — a
pre-boot PIN prompt stops unattended boot dead.

---

## Step 9 — Verify on a pilot device

Wait for the app to install, then on the device (swap `WK-Hub` for your own name
if you changed it in step 3):

```powershell
# 1. Did the payload land?
Get-ItemProperty 'HKLM:\SOFTWARE\WK-Hub\BitLockerPin' | Format-List

# 2. Is the task registered and enabled?
Get-ScheduledTask -TaskName 'WK-Hub BitLocker PIN Enrollment' | Select-Object State

# 3. Watch the dialog's own log while you sign out and back in.
Get-Content 'C:\ProgramData\WK-Hub\BitLockerPin\prompt.log' -Wait -Tail 5
```

Sign out and back in. The dialog should appear within about two minutes. Set a
PIN, then confirm the protector actually swapped:

```powershell
manage-bde -protectors -get C:
```

You want **`TpmPin`** present and **no** plain `Tpm` protector. A leftover
TPM-only protector silently cancels the PIN prompt at boot — the device starts
straight into Windows and nobody notices the PIN never applied.

**Then reboot** and confirm the pre-boot prompt appears and your PIN works.

---

## Step 10 — Add the Remediation

The Win32 app can only report *Installed* or *Failed*. That is the mechanism, not
the PIN — a device shows *Installed* for weeks while the user keeps clicking
*Remind me later*. This pair answers the real question.

**Devices → Scripts and remediations → Create**

| Field | Value |
|---|---|
| Detection script | `Detect-BitLockerPinCompliance.ps1` |
| Remediation script | `Remediate-BitLockerPinCompliance.ps1` |
| Run using logged-on credentials | **No** |
| Run in 64-bit PowerShell | **Yes** |
| Schedule | Daily |

Details and what each output line means: **[INTUNE.md](INTUNE.md#remediations)**.

---

## Rolling back

```powershell
# Removes the mechanism, restores the FVE policy. LEAVES the PIN in place.
.\Uninstall-BitLockerStartupPin.ps1

# The explicit rollback: also puts the device back on a TPM-only protector.
.\Uninstall-BitLockerStartupPin.ps1 -RemovePinProtector
```

`-RemovePinProtector` is genuinely risky and says so: the PIN protector must come
off before a TPM-only one can go back on, so there is a window where only the
recovery password can unlock the volume. It refuses to run without a recovery
password, and exits non-zero rather than report a clean uninstall over a device
that will boot to the recovery screen.

In Intune, remove the assignment or change it to **Uninstall** — do not delete the
app, or devices keep the payload forever with nothing left to remove it.

---

## Common first-run problems

| Symptom | Cause |
|---|---|
| App installs, nothing ever prompts | Detection script not re-uploaded after a package change |
| Task exists but dialog never appears | `ServiceUI.exe` missing from `Source\` when you built |
| Install exits `1618` | Device is mid-encryption or protection is suspended. This is a **retry** code, not a failure — Intune will come back |
| Install exits `1` immediately | No TPM, or the recovery key has not escrowed to Entra yet |
| Dialog appears, PIN rejected | A conflicting FVE policy — see [INTUNE.md](INTUNE.md#disk-encryption-policy) |

Everything else: **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.
