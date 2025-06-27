# Evo Credential Provider Installer (v2.3+ Only)

This repository contains a PowerShell script to install, upgrade, or remove the **Evo Credential Provider** on Windows systems. It supports both **interactive** and **silent** operation modes, enabling easy integration into manual admin workflows or automated deployment systems (e.g., RMM tools, Intune, GPO, etc.).

---

## 📄 Script: `Install-EvoAgent.ps1`

### ✔️ Features

- Installs the Evo Credential Provider MSI or ZIP package (automatically extracts ZIP)
- Automatically downloads the latest stable or beta version if no path is provided
- Supports uninstall/removal logic
- Silent mode support for unattended installations
- Upgrade-safe: checks version before proceeding
- Accepts legacy JSON blob configs or individual parameters
- Includes integrated `-Help` functionality and CLI examples

---

## 🔧 Parameters

| Parameter                 | Description                                                   |
| ------------------------- | ------------------------------------------------------------- |
| `-EnvironmentUrl`         | Evo portal base URL (e.g., `https://yourorg.evosecurity.com`) |
| `-EvoDirectory`           | Your Evo organization/directory name                          |
| `-AccessToken`            | Evo API access token                                          |
| `-Secret`                 | Evo API secret                                                |
| `-CredentialMode`         | `SecureLogin`, `ElevatedLogin`, or `SecureAndElevatedLogin`   |
| `-OnlyEvoLoginCredential` | If true, Evo becomes the only credential provider             |
| `-MSIPath`                | Optional path to `.msi` or `.zip` file                        |
| `-Upgrade`                | Ensure only newer versions replace installed ones             |
| `-Remove`                 | Uninstalls the Evo Credential Provider                        |
| `-Interactive`            | Runs installer with UI instead of silent mode                 |
| `-Log`                    | Enables install/uninstall logging                             |
| `-Beta`                   | Pulls installer from Evo's beta channel                       |
| `-Json`                   | Legacy option to supply a JSON config blob or file            |
| `-Help`                   | Displays built-in help text                                   |

---

## 🚀 Example Usages

### Basic Install

```powershell
.\Install-EvoAgent.ps1 -EnvironmentUrl "https://myorg.evosecurity.com" -EvoDirectory "MyOrg" -AccessToken "abc123" -Secret "xyz789"
```

### With Upgrade Check and Logging

```powershell
.\Install-EvoAgent.ps1 -Upgrade -Log
```

### Removal

```powershell
.\Install-EvoAgent.ps1 -Remove -Interactive -Log
```

### Legacy JSON Blob

```powershell
.\Install-EvoAgent.ps1 -Json '{ "EnvironmentUrl": "...", "EvoDirectory": "...", "AccessToken": "...", "Secret": "..." }'
```

---

## ⚠️ Notes

- **Admin Rights Required**: Must be run from an elevated shell unless `-Interactive` is used.
- Supports both x64 and ARM64 architectures.
- Logs (if enabled) are written to the system temporary folder.

---

## 📬 Support

Please contact [support@evosecurity.com](mailto\:support@evosecurity.com) for assistance.

---

## 📝 License

Copyright © Evo Security Technologies. All rights reserved.

