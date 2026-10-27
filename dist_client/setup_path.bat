@echo off
setlocal enabledelayedexpansion

set "TARGET_DIR=%~dp0"
if "%TARGET_DIR:~-1%"=="\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"

echo ========================================================
echo  CLICOM Command Setup - Adding to Windows PATH
echo ========================================================
echo Target Folder: !TARGET_DIR!
echo.

setx PATH "%PATH%;!TARGET_DIR!" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Added to User PATH! You can now type clicom anywhere.
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$d = '%TARGET_DIR%'; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($p -notlike ('*' + $d + '*')) { [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';' + $d), 'User'); Write-Host '[SUCCESS] Added to User PATH!' -ForegroundColor Green } else { Write-Host '[OK] Already in User PATH!' -ForegroundColor Yellow }"
)

echo.
echo Please restart any open CMD or PowerShell windows for the change to take effect.
echo Then simply type: clicom
pause
