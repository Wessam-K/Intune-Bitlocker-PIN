# BitLocker Startup PIN for Intune

Ask your users to set a BitLocker **pre-boot startup PIN** — and let them do it
themselves, without local administrator rights.

Windows can require a PIN before it even starts loading. That is the difference
between "a stolen laptop is encrypted" and "a stolen laptop is encrypted *and*
cannot be switched on". Intune has no built-in way to collect that PIN from the
person sitting at the keyboard. This package is that missing piece.

![The PIN dialog as a user sees it](docs/screenshots/pin-dialog.png)

---

## What it actually does

1. Intune installs it as a Win32 app. It runs as SYSTEM and checks the device is
   ready: TPM present, `C:` encrypted, a recovery key exists **and has been
   escrowed to Entra ID**.
2. It registers a scheduled task that shows the dialog above **in the signed-in
   user's session**, at logon and after every screen unlock, until a PIN is set.
3. The user types a PIN. The app adds the new `TpmPin` protector, verifies it,
   and only then removes the old TPM-only one.
4. A separate Intune **Remediation** reports who actually has a PIN — because an
   app that says *Installed* tells you nothing about whether anyone used it.

If the device is not encrypted, the user gets a plain-language notice with a
reference to quote to the service desk, instead of a dialog they cannot act on.

---

## Why it is built this strangely

Two facts collide:

- Adding a BitLocker key protector **requires administrator rights**, and your
  users do not have them.
- Intune runs in **session 0**, which has no desktop — which is exactly why
  `manage-bde -changepin` silently does nothing when a Win32 app calls it.

So the PIN cannot be collected by the installer, and it cannot be applied by the
user. The app splits in two and bridges the gap with Microsoft's `ServiceUI.exe`,
which lends session 0 the user's desktop while the process stays SYSTEM.

The long version, with the failures that shaped each decision, is in
[docs/REFERENCE.md](docs/REFERENCE.md).

---

## Requirements

| | |
|---|---|
| **Devices** | Windows 10 1809+ or Windows 11, x64, TPM 2.0 |
| **Join type** | Entra-joined or Entra hybrid-joined (the recovery key must escrow) |
| **Management** | Microsoft Intune |
| **You supply** | `ServiceUI.exe` (from MDT) and `IntuneWinAppUtil.exe` — neither is redistributed here |
| **Tests** | 92 passing, touching no BitLocker state (`Test-BitLockerPinApp.ps1`) |

---

## Start here

| Guide | What it covers |
|---|---|
| **[QUICKSTART.md](QUICKSTART.md)** | Get it deployed to a pilot group, step by step |
| **[INTUNE.md](INTUNE.md)** | Every Intune field, and how to stop it fighting your disk-encryption policy |
| **[BRANDING.md](BRANDING.md)** | Put your own logo and wallpaper in the dialog |
| **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** | It is not prompting. Now what? |
| **[docs/REFERENCE.md](docs/REFERENCE.md)** | Architecture, design decisions, every knob |

**Try the dialog right now.** No admin rights, no BitLocker changes, nothing
installed:

```powershell
.\Set-BitLockerPin.ps1 -PreviewUI              # the PIN dialog
.\Set-BitLockerPin.ps1 -PreviewNotEncrypted    # the "not encrypted" notice
```

---

## What it changes on a device

Everything is namespaced under `-Organization` (default `WK-Hub` — change it to
your own in [QUICKSTART.md](QUICKSTART.md) step 3).

| | |
|---|---|
| `C:\ProgramData\<Org>\BitLockerPin` | payload and logs; readable by SYSTEM and Administrators only |
| `HKLM\SOFTWARE\<Org>\BitLockerPin` | version and state markers |
| Scheduled task `<Org> BitLocker PIN Enrollment` | runs the dialog in the user's session |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | the startup-auth values a TPM+PIN protector needs — **backed up first, restored on uninstall** |

It never writes a PIN to a log, a file, or a command line, and it never removes a
working protector before its replacement is verified.

---

## Safety notes worth reading before you deploy

- **Rehearse recovery first.** A pre-boot PIN means a forgotten PIN is a recovery-key
  event. Confirm your service desk can find a key in Entra before you assign this
  to anyone.
- **Pilot with 5–10 devices.** Not a ring. Not a department.
- **Exclude shared, kiosk and Wake-on-LAN devices.** A pre-boot prompt stops
  unattended boot dead.
- Uninstalling deliberately **leaves the PIN in place**. Removing a deployment tool
  must not quietly weaken a device. `-RemovePinProtector` is the explicit rollback.

---

## Licence

MIT — see [LICENSE](LICENSE). `ServiceUI.exe` and `IntuneWinAppUtil.exe` are
Microsoft's, licensed by Microsoft, and are not distributed with this repository.
