# CLICOM 2.0.0 — User Installation Script
# Installs executables to %LOCALAPPDATA%\Programs\clicom\bin
# Adds bin directory to the User PATH environment variable
# Copies template configs without overwriting existing configs

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\clicom",
    [string]$ConfigDir  = "$env:LOCALAPPDATA\clicom\config"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installing CLICOM 2.0.0 (User Scope)  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
    $scriptRoot = (Get-Location).Path
}

$sourceBin = Join-Path $scriptRoot "bin"
$sourceConfig = Join-Path $scriptRoot "config"

if (-not (Test-Path $sourceBin)) {
    Write-Error "Source 'bin' directory not found at $sourceBin. Please run from distribution root."
    exit 1
}

# 1. Target bin directory
$targetBin = Join-Path $InstallDir "bin"
Write-Host "[1/4] Preparing target installation directory: $targetBin"
New-Item -ItemType Directory -Force -Path $targetBin | Out-Null

# 2. Copy binaries and runtime libraries
Write-Host "[2/4] Copying executables and libraries..."
Get-ChildItem -Path $sourceBin -File | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $targetBin -Force
    Write-Host "  - Installed $($_.Name)" -ForegroundColor Green
}

# 3. Setup configuration templates
Write-Host "[3/4] Checking user configuration directory: $ConfigDir"
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

if (Test-Path $sourceConfig) {
    Get-ChildItem -Path $sourceConfig -File | ForEach-Object {
        $destPath = Join-Path $ConfigDir $_.Name
        if (-not (Test-Path $destPath)) {
            Copy-Item -Path $_.FullName -Destination $destPath
            Write-Host "  - Created default config: $($_.Name)" -ForegroundColor Green
        } else {
            Write-Host "  - Preserved existing config: $($_.Name)" -ForegroundColor Yellow
        }
    }
}

# 4. Update User PATH if needed
Write-Host "[4/4] Updating User environment PATH..."
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathParts = if ($userPath) { $userPath -split ';' } else { @() }

if ($pathParts -notcontains $targetBin) {
    $newPath = ($pathParts + $targetBin) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "  - Added $targetBin to User PATH." -ForegroundColor Green
} else {
    Write-Host "  - User PATH already includes $targetBin." -ForegroundColor Yellow
}

Write-Host "`nInstallation successfully completed!" -ForegroundColor Cyan
Write-Host "Executables located at: $targetBin"
Write-Host "To start using CLICOM, open a new command prompt or PowerShell window and run:"
Write-Host "  clicom --version" -ForegroundColor White
Write-Host "  clicom-server --version" -ForegroundColor White
