# Autopilot Device Hash Gather Utility — v2.0

A single-file WPF PowerShell tool that captures a Windows device's Autopilot hardware hash and uploads it directly to Microsoft Intune via the Graph REST API. No modules. No portal. No external scripts. Just plug in the USB, enter the passphrase, click **Start**.

> Built by **PixelTech** · Author: Abhinay Pal

---

## At a glance

<!-- SCREENSHOT: hero shot of the Hash Upload tab mid-run (phase stepper lit, console showing "Profile → assigned and in sync") -->
![Hash Upload tab — run in progress](./docs/screenshots/01-hash-upload-running.png)

**What it does in one paragraph.** On first launch it spins up its own Entra app registration (with the minimum Graph permissions for Autopilot), encrypts the client secret with a passphrase you choose, and saves the config next to the script. On every run after that it captures the hardware hash from WMI, uploads it to Intune, and polls until the deployment profile is actually assigned — translating Graph state codes into plain English along the way. The config + passphrase are fully portable: the same USB stick unlocks the tool on any Windows machine.

---

## The UI

<!-- SCREENSHOT: Settings tab with Group Tag / Tenant ID fields visible -->
![Settings tab](./docs/screenshots/02-settings.png)

<!-- SCREENSHOT: About tab showing the details card and "What's new in v2.0" -->
![About tab](./docs/screenshots/03-about.png)

Three tabs:
- **Hash Upload** — device info card, 4-phase stepper, live console, progress bar, Start / Abort / Close.
- **Settings** — Group Tag, Tenant ID, Save Settings, Reset App Registration.
- **About** — version, release date, developer, platform, auth mechanism, secret storage scheme.

---

## What's new in v2.0

### 1. Truly standalone — no external dependencies
Previous versions relied on `AzureAD`, `WindowsAutoPilotIntune`, and the community `Get-WindowsAutoPilotInfo.ps1` script. All of that is **gone**. v2.0 talks directly to Microsoft Graph over HTTPS using `Invoke-RestMethod`, which eliminates:

- The 32-bit / 64-bit processor-architecture mismatch in `AzureAD`'s `CommonLibrary.dll`.
- "Module found but could not be loaded" errors caused by Mark-of-the-Web on USB-delivered files.
- `ProcessorArchitecture=None` runspace quirks.
- The need to keep a bundled `Modules\` folder in sync with upstream updates.

### 2. Auto-provisioned Entra app registration
On first run, the tool opens a browser for admin sign-in and creates its own App Registration in your tenant (`PixelTech - Autopilot Hash Upload`) with exactly the Graph permissions it needs:

- `DeviceManagementServiceConfig.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`

Client credentials (client ID + encrypted secret + tenant ID) are saved to `AutopilotApp_Config.json` for future runs. Subsequent launches go straight to hash upload — no sign-in required until the secret expires (2 years).

### 3. Real-time Autopilot deployment-profile tracking
After the hash is accepted, the tool polls `deploymentProfileAssignmentStatus` every 10 seconds and shows plain-English progress in the console:

```
[Profile]   Looking for a matching deployment profile… [10s]
[Profile] → Profile scheduled — Intune is applying it now [21s]
[Profile] → Profile assigned and in sync — 'Corp Autopilot' [208s]
```

Raw Graph state names are translated to friendly messages. A `→` marks actual state transitions in the heartbeat stream. Progress bar ticks live during the wait. The run only reports "Completed" once Intune actually reports `assignedInSync` / `assignedOutOfSync` / `assignedUnknownSyncState`.

If no Group Tag is supplied, the profile-assignment poll is **skipped** (there's no way for a profile to bind without group membership), so the tool finishes as soon as the hash is registered.

### 4. Portable AES-256 secret encryption with passphrase
The Entra client secret is no longer stored in plaintext. v2.0 uses:

- **AES-256-CBC** with **PBKDF2-SHA1 (200,000 iterations)** for key derivation.
- A **passphrase** the tech enters once per session (masked WPF prompt, always-on-top).
- **Portable** — the USB stick + passphrase work on any Windows machine. Nothing is tied to the machine or the Windows user.

Stored format: `enc:aes256:v1:<base64 salt>:<base64 iv>:<base64 ciphertext>`

Legacy plaintext and DPAPI-encrypted configs from earlier builds are auto-migrated on first launch.

### 5. WPF light-theme UI (ported from WinForms)
- DPI-crisp text at any display scale (WPF uses DirectWrite and device-independent pixels — no more blur at 150%).
- Lavender-fog gradient chrome with white content cards.
- Phase stepper (Prepare → Authenticate → Upload Hash → Complete) with a pulsing blue glow on the active step and a static green glow on completed steps.
- Pill-shaped progress bar with smooth fill animation.
- Resizable window — layout holds together at any size.

### 6. Live config — no "Save" required
Group Tag and Tenant ID typed on the Settings tab are now picked up immediately when the next run starts. The Save button persists them for future launches but is no longer a prerequisite.

### 7. Robust cancellation and error handling
- **Abort** during browser sign-in actually stops the wait loop (previously it froze the UI).
- Dismissing the passphrase prompt cleanly resets the UI instead of crashing the click handler.
- All dispose paths in the window-closing handler are wrapped individually so Close / X can never throw.
- Cancellation is type-safe via `OperationCanceledException` with explicit markers.

### 8. Dedicated About tab
Version, release date, developer, platform, and purpose now live in a scrollable card on their own tab instead of cluttering the header badge and footer.

---

## What you need to run it

### Requirements
| | |
|---|---|
| OS | Windows 10 1809+ or Windows 11 |
| PowerShell | 5.1 (shipped with Windows) — **no** PowerShell 7 required |
| Architecture | x64 or ARM64 (both work — no AzureAD, so no 32-bit gymnastics) |
| Rights on target device | Local Administrator |
| Rights in tenant (first run only) | Global Administrator *or* Application Administrator *or* Cloud Application Administrator *or* Intune Administrator + Privileged Role Administrator |
| Network | Outbound 443 to `graph.microsoft.com` and `login.microsoftonline.com` |

### What is **NOT** required
- ❌ `AzureAD` PowerShell module
- ❌ `AzureADPreview`
- ❌ `Microsoft.Graph` SDK
- ❌ `WindowsAutoPilotIntune` module
- ❌ `Get-WindowsAutoPilotInfo.ps1` community script
- ❌ Any `Modules\` folder bundled with the tool
- ❌ A pre-existing App Registration in Entra
- ❌ Admin PowerShell prompt (the tool elevates as needed)

**Just the single `.ps1` file.**

---

## Files in this package

| File | Purpose |
|---|---|
| `Gather Autopilot Hash.WPF.ps1` | The tool — UI, auth, hash capture, upload, profile polling. Run this. |
| `Gather Autopilot Hash.ps1` | Legacy WinForms build, kept as fallback. |
| `AutopilotApp_Config.json` | Created on first run. Stores client ID, encrypted secret, tenant ID, group tag. |
| `logo.png` *(optional)* | Drop a 96×96 or 128×128 PNG next to the script to replace the header placeholder with your own logo. |
| `README.md` | This file. |
| `LICENSE` | CC BY-NC 4.0. |

Logs are written to `C:\AutopilotLogs\AutopilotLog_<timestamp>.txt`.

---

## First-run flow

1. Launch `Gather Autopilot Hash.WPF.ps1` (right-click → Run with PowerShell, or via an elevated prompt).
2. Optional: enter a Group Tag on the **Settings** tab.
3. Click **Start Autopilot Collection**.
4. A browser opens → sign in with a tenant admin account.
5. A passphrase prompt appears → create a passphrase (min 8 chars). Remember it — you'll enter it on every subsequent machine.
6. The tool creates the app registration, captures the hardware hash from WMI, uploads it, and (if a Group Tag was set) waits for profile assignment.

## Subsequent runs (same or different machine)

1. Launch the tool.
2. Enter the passphrase when prompted.
3. Click **Start** — skips straight to hash capture + upload.

## OOBE flow

During Windows Out-Of-Box Experience:

1. Connect to network on the OOBE network screen.
2. Press **Shift+F10** to open a command prompt.
3. Run `powershell -ExecutionPolicy Bypass -File "E:\Gather Autopilot Hash.WPF.ps1"` (replace `E:` with your USB drive letter).
4. Enter the passphrase when prompted.
5. Wait for `[Profile] → Profile assigned and in sync`.
6. Close the tool and run `shutdown /r /t 0` — OOBE restarts and picks up the profile.

> **Note**: the **first-ever run** requires an interactive browser for admin sign-in and is not reliable inside OOBE. Do the first run on any non-OOBE machine to generate `AutopilotApp_Config.json`, then carry that USB to field devices — OOBE needs only the passphrase from that point on.

---

## Customizing the UI

### Replace the header logo
Drop a PNG next to the script named `logo.png`. On launch the tool looks for `$ScriptDir\logo.png` and swaps it in automatically; if the file isn't present, a neutral grey "LOGO" placeholder is shown. Recommended dimensions: square, 96×96 or 128×128 px, transparent background.

### Change the accent color
The accent palette is defined once in the XAML — search for `#7C3AED` (violet) and replace with your preferred hex. Common alternatives:
- Fluent blue: `#0078D4`
- Teal: `#0D9488`
- Indigo: `#4F46E5`
- Royal blue: `#1D4ED8`

### Change the chrome gradient
Search for `<LinearGradientBrush` in the XAML. The two gradient stops (`#F5F3FF` and `#EDE9FE`) drive the window background. Swap them for any two-tone pair you like.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Passphrase prompt is behind the main window | Already fixed — it's `Topmost`. If it ever happens, Alt+Tab to find it. |
| "Device did not appear in Autopilot inventory within 3 minutes" | Hash was accepted but Graph's inventory sync is lagging. Rerun — it'll usually find it within 30 s. |
| "Profile assignment timed out" | Hash is registered, but no Autopilot deployment profile is assigned to a group the device matches. Check Group Tag spelling and profile → group assignments in Intune. |
| "Wrong passphrase" 3 times | Delete `AutopilotApp_Config.json` and re-register from scratch. |
| Script won't run — "execution policy" error | `powershell -ExecutionPolicy Bypass -File "Gather Autopilot Hash.WPF.ps1"` |
| Script file is blocked (Mark-of-the-Web) | `Unblock-File "Gather Autopilot Hash.WPF.ps1"` |
| XAML parse error on launch | Make sure no one edited the script with a non-UTF-8 editor. Re-extract from the original archive if in doubt. |

---

## Security notes

- The client secret in `AutopilotApp_Config.json` is encrypted with AES-256-CBC; the passphrase never touches disk.
- Access tokens are kept in memory only and are never logged.
- The auto-provisioned app registration holds exactly two Graph permissions — both the minimum for Autopilot import + profile read. You can audit/revoke them in **Entra → App registrations → PixelTech - Autopilot Hash Upload** at any time.
- If a USB stick is lost, rotate the client secret in Entra (or delete the app registration entirely and re-register on the next run).

---

## License

This project is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** — see [LICENSE](./LICENSE).

You may **share and adapt** the material for any purpose **except commercial use**, provided you give appropriate credit. For commercial licensing, contact PixelTech.

---

## Version

**2.0.0** — 2026-04-24
Developer: **Abhinay Pal** · PixelTech
