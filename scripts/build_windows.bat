@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   CLICOM Build Script - Windows
echo   Software v2.0.0 / Protocol CLIPv1.0
echo ============================================================
echo.

:: ── Check for CMake ──────────────────────────────────────────────────────
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "C:\msys64\ucrt64\bin\cmake.exe" (
        set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;!PATH!"
    ) else if exist "C:\msys64\mingw64\bin\cmake.exe" (
        set "PATH=C:\msys64\mingw64\bin;C:\msys64\usr\bin;!PATH!"
    )
)

where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found.
    echo        Install CMake 3.25+ and add it to your PATH.
    echo        Download: https://cmake.org/download/
    exit /b 1
)
for /f "tokens=*" %%v in ('cmake --version ^| findstr /r "cmake version"') do (
    echo Found: %%v
)

:: ── Detect compiler and select generator ─────────────────────────────────
set GENERATOR=
set BUILD_DIR=

:: Try Ninja first (works with MSVC, MinGW, and Clang)
where ninja >nul 2>&1
set HAVE_NINJA=%ERRORLEVEL%

:: Check for MSVC (cl.exe)
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if %HAVE_NINJA% EQU 0 (
        echo Compiler : MSVC  ^(Ninja generator^)
        set GENERATOR=Ninja
        set BUILD_DIR=build\windows-ninja-debug
        :: Ninja with MSVC needs the VS environment. Assume developer prompt.
        goto :do_build
    )
    echo Compiler : MSVC  ^(Visual Studio 17 2022 generator^)
    set GENERATOR=Visual Studio 17 2022
    set BUILD_DIR=build\windows-msvc-debug
    goto :do_build
)

:: Check for MinGW / GCC
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if %HAVE_NINJA% EQU 0 (
        echo Compiler : MinGW GCC  ^(Ninja generator^)
        set GENERATOR=Ninja
        set BUILD_DIR=build\windows-ninja-debug
        goto :do_build
    )
    echo Compiler : MinGW GCC  ^(MinGW Makefiles generator^)
    set GENERATOR=MinGW Makefiles
    set BUILD_DIR=build\windows-mingw-debug
    goto :do_build
)

echo ERROR: No C compiler found.
echo        Install one of:
echo          - Visual Studio 2022 (with Desktop C++ workload)
echo          - MinGW-w64 (https://www.mingw-w64.org/)
exit /b 1

:do_build
echo Generator: %GENERATOR%
echo Build dir: %BUILD_DIR%
echo.

:: ── Step 1: Configure ────────────────────────────────────────────────────
echo [1/3] Configuring...
cmake -S . -B %BUILD_DIR% ^
      -G "%GENERATOR%" ^
      -DCMAKE_BUILD_TYPE=Debug ^
      -DCLICOM_BUILD_CLIENT=ON ^
      -DCLICOM_BUILD_SERVER=ON ^
      -DCLICOM_BUILD_TESTS=ON

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: CMake configuration failed.
    exit /b 1
)

:: ── Step 2: Build ────────────────────────────────────────────────────────
echo.
echo [2/3] Building...
cmake --build %BUILD_DIR% --config Debug --parallel 4

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Build failed.
    exit /b 1
)

:: ── Step 3: Test ─────────────────────────────────────────────────────────
echo.
echo [3/3] Running tests...
ctest --test-dir %BUILD_DIR% -C Debug --output-on-failure

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: One or more tests failed. See output above.
    exit /b 1
) else (
    echo.
    echo All tests passed.
)

echo.
echo ============================================================
echo Build complete.
echo Executables: %BUILD_DIR%\
echo   clicom.exe
echo   clicom-server.exe
echo ============================================================
echo.
endlocal
