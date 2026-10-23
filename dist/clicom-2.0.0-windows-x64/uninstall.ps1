# CLICOM 2.0.0 — User Uninstallation Script
# Removes executables from %LOCALAPPDATA%\Programs\clicom
# Removes bin directory from User PATH environment variable
# Preserves user data and databases unless -PurgeUserData is explicitly passed

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\clicom",
    [string]$DataDir    = "$env:LOCALAPPDATA\clicom",
    [switch]$PurgeUserData = $false
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Uninstalling CLICOM (User Scope)      " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$targetBin = Join-Path $InstallDir "bin"

# 1. Remove binaries
if (Test-Path $InstallDir) {
    Write-Host "[1/3] Removing installed program directory: $InstallDir"
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "  - Successfully deleted $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[1/3] Program directory does not exist: $InstallDir" -ForegroundColor Yellow
}

# 2. Clean User PATH
Write-Host "[2/3] Cleaning User environment PATH..."
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath) {
    $pathParts = $userPath -split ';' | Where-Object { 
        $_ -and ($_ -ne $targetBin) -and ($_ -ne $InstallDir)
    }
    $newPath = $pathParts -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "  - Cleaned CLICOM entries from User PATH." -ForegroundColor Green
}

# 3. Handle User Data
Write-Host "[3/3] Checking user data directory: $DataDir"
if (Test-Path $DataDir) {
    if ($PurgeUserData) {
        Write-Host "  - -PurgeUserData specified. Deleting user data and databases..." -ForegroundColor Red
        Remove-Item -Path $DataDir -Recurse -Force
        Write-Host "  - User data deleted." -ForegroundColor Green
    } else {
        Write-Host "  - Preserved user data at: $DataDir" -ForegroundColor Yellow
        Write-Host "    (Use -PurgeUserData switch to permanently delete user data and databases)." -ForegroundColor Gray
    }
}

Write-Host "`nUninstallation completed successfully." -ForegroundColor Cyan
