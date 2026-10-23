@echo off
setlocal enabledelayedexpansion

echo CLICOM — Phase 0 Local Test Script
echo =====================================
echo.
echo This script verifies the Phase 0 build on one Windows PC.
echo It tests: version output, self-test, and --help for both executables.
echo.
echo Future phases will launch three separate CMD windows:
echo   CMD 1: clicom-server
echo   CMD 2: clicom --node NODE-A
echo   CMD 3: clicom --node NODE-B
echo.

:: ── Find build directory ──────────────────────────────────────────────────
set BUILD_DIR=
if exist "build\windows-ninja-debug\clicom.exe" (
    set BUILD_DIR=build\windows-ninja-debug
) else if exist "build\windows-msvc-debug\Debug\clicom.exe" (
    set BUILD_DIR=build\windows-msvc-debug\Debug
) else if exist "build\windows-mingw-debug\clicom.exe" (
    set BUILD_DIR=build\windows-mingw-debug
)

if "%BUILD_DIR%"=="" (
    echo ERROR: Could not find clicom.exe. Build the project first:
    echo        scripts\build_windows.bat
    exit /b 1
)

echo Build directory: %BUILD_DIR%
echo.

:: ── Test client ──────────────────────────────────────────────────────────
echo ── Client Tests ─────────────────────────────────────────────────────
echo.
echo [clicom --version]
%BUILD_DIR%\clicom.exe --version
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo [clicom --test]
%BUILD_DIR%\clicom.exe --test
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo [clicom --help]
%BUILD_DIR%\clicom.exe --help
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo [clicom --node NODE-A]
%BUILD_DIR%\clicom.exe --node NODE-A
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo ── Server Tests ─────────────────────────────────────────────────────
echo.
echo [clicom-server --version]
%BUILD_DIR%\clicom-server.exe --version
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo [clicom-server --test]
%BUILD_DIR%\clicom-server.exe --test
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo [clicom-server --help]
%BUILD_DIR%\clicom-server.exe --help
if %ERRORLEVEL% NEQ 0 ( echo FAIL & exit /b 1 )

echo.
echo =====================================================
echo Phase 0 local test: ALL CHECKS PASSED
echo =====================================================
echo.
endlocal
