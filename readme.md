# Evo Deployment Scripts

This repository contains PowerShell scripts to install, upgrade, or remove the **Evo Credential Provider** or the **Evo LDAP Agent** on Windows systems. It supports both **interactive** and **silent** operation modes, enabling easy integration into manual admin workflows or automated deployment systems (e.g., RMM tools, Intune, GPO, etc.).

---

## 📄 Script: `InstallEvoAgent.ps1` (v2.3+ Only)

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

| Parameter                 | Description                                                   | Default                                     |
| ------------------------- | ------------------------------------------------------------- | ------------------------------------------- |
| `-EnvironmentUrl`         | Evo portal base URL (e.g., `https://yourorg.evosecurity.com`) |                                             |
| `-EvoDirectory`           | Your Evo organization/directory name                          |                                             |
| `-AccessToken`            | Evo API access token                                          |                                             |
| `-Secret`                 | Evo API secret                                                |                                             |
| `-FailSafeUser`           | Optional username to use as a fallback if Evo login fails     |                                             |
| `-MFATimeOut`             | Optional grace period to not require MFA for an unlock (in minutes from previous MFA prompt) | 0            |
| `-CredentialMode`         | `SecureLogin`, `ElevatedLogin`, or `SecureAndElevatedLogin`   | SecureAndElevatedLogin                      |
| `-OnlyEvoLoginCredential` | If set, Evo becomes the only credential provider              | 0                                           |
| `-RememberLastUserName`   | Optional flag to remember the last username used              | 1                                           |
| `-DisableUpdate`          | Optional flag to disable auto updates                         | 0                                           |
| `-JitMode`                | Optional flag to enable Just-In-Time admin accounts           | 0                                           |
| `-EndUserElevation`       | Optional flag to enable end-user elevation                    | 0                                           |
| `-UserAdminEscalation`    | Optional flag to prompt admins with the end-user elevation prompt instead of the standard UAC prompt | 0    |
| `-CustomPrompt`           | Optional string to customize the login prompt                 |                                             |
| `-CustomImage`            | Optional path to custom login image (URL or local file path   |                                             |
| `-NoElevatedRDP`          | Optional flag to disable elevation for RDP sessions when Evo is the sole login agent | 1                    |
| `-UACExtension`           | Optional setting to enable UAC extension (0=disabled, 1=enabled, other credential providers available in UAC dialog, 2=enabled, Evo exclusive in UAC dialog )                      | 0                                           |
| `-MSIPath`                | Optional path to `.msi` or `.zip` file                        |                                             |
| `-Upgrade`                | Ensure only newer versions replace installed ones             |                                             |
| `-Remove`                 | Uninstalls the Evo Credential Provider                        |                                             |
| `-Interactive`            | Runs installer with UI instead of silent mode                 |                                             |
| `-Log`                    | Enables install/uninstall logging                             |                                             |
| `-Beta`                   | Pulls installer from Evo's beta channel                       |                                             |
| `-Json`                   | Legacy option to supply a JSON config blob or file            |                                             |
| `-Help`                   | Displays built-in help text                                   |                                             |


`-EnvironmentUrl`, `-EvoDirectory`, `-AccessToken`, and `-Secret` parameters are required except on upgrades or removal.\
When upgrading, any unspecified parameters are inherited from the previous install.

---

## 🚀 Example Usages

### Basic Install

```powershell
.\InstallEvoAgent.ps1 -EnvironmentUrl "https://myorg.evosecurity.com" -EvoDirectory "MyOrg" -AccessToken "abc123" -Secret "xyz789"
```

### With Upgrade Check and Logging

```powershell
.\InstallEvoAgent.ps1 -Upgrade -Log
```

### Removal

```powershell
.\InstallEvoAgent.ps1 -Remove -Interactive -Log
```

### Legacy JSON Blob

```powershell
.\InstallEvoAgent.ps1 -Json '{ "EnvironmentUrl": "...", "EvoDirectory": "...", "AccessToken": "...", "Secret": "..." }'
```

### Legacy JSON File

```powershell
.\InstallEvoAgent.ps1 -Json 'c:\path\to\install.json'
```

---
## 📄 Script: `InstallLdapAgent.ps1`

### ✔️ Features

- Installs the Evo LDAP Agent MSI or ZIP package (automatically extracts ZIP)
- Automatically downloads the latest stable or beta version if no path is provided
- Supports uninstall/removal logic
- Silent mode support for unattended installations
- Upgrade-safe: checks version before proceeding
- Accepts legacy JSON blob configs or individual parameters
- Includes integrated `-Help` functionality and CLI examples

---

## 🔧 Parameters

| Parameter                 | Description                                                   | Default                                     |
| ------------------------- | ------------------------------------------------------------- | ------------------------------------------- |
| `-EnvironmentUrl`         | Evo portal base URL (e.g., `https://yourorg.evosecurity.com`) |                                             |
| `-EvoDirectory`           | Your Evo organization/directory name                          |                                             |
| `-AccessToken`            | Evo API access token                                          |                                             |
| `-Secret`                 | Evo API secret                                                |                                             |
| `-SyncSecurityGroup`      | AD security group(s) to sync. Separate muliple groups with `;`|                                             |
| `-UpdateInterval`         | Optional interval in minutes to sync AD users                 | 10                                          |
| `-DisableUpdate`          | Optional flag to disable auto updates                         | 0                                           |
| `-MSIPath`                | Optional path to `.msi` or `.zip` file                        |                                             |
| `-Upgrade`                | Ensure only newer versions replace installed ones             |                                             |
| `-Remove`                 | Uninstalls the Evo Credential Provider                        |                                             |
| `-Interactive`            | Runs installer with UI instead of silent mode                 |                                             |
| `-Log`                    | Enables install/uninstall logging                             |                                             |
| `-Beta`                   | Pulls installer from Evo's beta channel                       |                                             |
| `-Json`                   | Legacy option to supply a JSON config blob or file            |                                             |
| `-Help`                   | Displays built-in help text                                   |                                             |


`-EnvironmentUrl`, `-EvoDirectory`, `-AccessToken`, and `-Secret` parameters are required except on upgrades or removal.\
When upgrading, any unspecified parameters are inherited from the previous install.

---

## 🚀 Example Usages

### Basic Install

```powershell
.\InstallLdapAgent.ps1 -EnvironmentUrl "https://myorg.evosecurity.com" -EvoDirectory "MyOrg" -AccessToken "abc123" -Secret "xyz789" -SyncSecurityGroup "EvoSync"
```

### With Upgrade Check and Logging

```powershell
.\InstallLdapAgent.ps1 -Upgrade -Log
```

### Removal

```powershell
.\InstallLdapAgent.ps1 -Remove -Interactive -Log
```

### Legacy JSON Blob

```powershell
.\InstallLdapAgent.ps1 -Json '{ "EnvironmentUrl": "...", "EvoDirectory": "...", "AccessToken": "...", "Secret": "...", "SyncSecurityGroup": "..." }'
```

### Legacy JSON File

```powershell
.\InstallLdapAgent.ps1 -Json 'c:\path\to\install.json'
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

