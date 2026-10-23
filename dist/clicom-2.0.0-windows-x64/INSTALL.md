# CLICOM 2.0.0 Installation Guide (Windows)

This document describes how to install and configure CLICOM 2.0.0 on Windows systems.

---

## Prerequisites

- **Operating System:** Windows 10 (64-bit), Windows 11 (64-bit), or Windows Server 2016+.
- **Hardware:** Audio input (microphone) and output (speakers/headphones) device for voice features.
- **Privileges:** Standard user privileges (Administrator rights are **NOT** required for user install).

---

## Installation Methods

### Method 1: Automated Script (Recommended)

1. Extract the `clicom-2.0.0-windows-x64.zip` package to any temporary folder.
2. Open PowerShell and run the installation script:
   ```powershell
   .\install.ps1
   ```
3. What this script does:
   - Copies executables and runtime libraries to `%LOCALAPPDATA%\Programs\clicom\bin`.
   - Copies default configuration templates to `%LOCALAPPDATA%\clicom\config\` (never overwriting existing custom configs).
   - Appends `%LOCALAPPDATA%\Programs\clicom\bin` to your **User `PATH`** environment variable.
   - Preserves all existing user profiles, identities, and databases in `%LOCALAPPDATA%\clicom`.
4. Open a fresh PowerShell or Command Prompt terminal, then verify:
   ```cmd
   clicom --version
   clicom-server --version
   ```

---

### Method 2: Manual Portable Setup

If you prefer a completely self-contained portable directory:
1. Extract the distribution archive to your chosen location (e.g. `C:\Tools\clicom`).
2. Run `clicom.exe` or `clicom-server.exe` directly from the `bin\` folder:
   ```cmd
   cd C:\Tools\clicom\bin
   .\clicom.exe --help
   ```
3. Runtime libraries (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `libopus-0.dll`, `libsqlite3-0.dll`) reside alongside the executables in `bin\`, so no external PATH modifications are required.

---

## Initial Configuration

### Running the Server
By default, `clicom-server.exe` listens securely on localhost (`127.0.0.1:4821`):
```cmd
clicom-server --config "%LOCALAPPDATA%\clicom\config\server.conf"
```
Or run directly with defaults:
```cmd
clicom-server --port 4821
```

### Running the Client
Connect to the local or remote server:
```cmd
clicom --host 127.0.0.1 --port 4821 --node Alice
```

For TLS connections, provide your server certificate or CA path:
```cmd
clicom --host myvoice.internal --port 4821 --ca certs/ca.crt
```
