# CLICOM 2.0.0 Uninstallation Guide (Windows)

This document describes how to safely remove CLICOM from your Windows system.

---

## Uninstallation Methods

### Method 1: Automated Script (Recommended)

1. Open PowerShell and navigate to the directory containing `uninstall.ps1` (or extract it from the package).
2. Run the uninstallation script:
   ```powershell
   .\uninstall.ps1
   ```
3. By default, `uninstall.ps1`:
   - Removes the installed program binaries directory: `%LOCALAPPDATA%\Programs\clicom`.
   - Cleans up `%LOCALAPPDATA%\Programs\clicom\bin` from your **User `PATH`** environment variable.
   - **Preserves** all user data, credentials, encryption keys, and audio history located in `%LOCALAPPDATA%\clicom`.
4. If you also wish to permanently purge user data and databases:
   ```powershell
   .\uninstall.ps1 -PurgeUserData
   ```

---

### Method 2: Manual Removal

1. Delete the installed binaries directory:
   ```powershell
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Programs\clicom"
   ```
2. Remove `%LOCALAPPDATA%\Programs\clicom\bin` from your User `PATH` via Windows System Properties or PowerShell:
   ```powershell
   $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
   $newPath = ($userPath -split ';' | Where-Object { $_ -ne "$env:LOCALAPPDATA\Programs\clicom\bin" }) -join ';'
   [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
   ```
3. (Optional) Remove configuration and databases:
   ```powershell
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\clicom"
   ```
