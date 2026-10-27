@echo off
setlocal enabledelayedexpansion

:: Determine installation base directory
set "BASE_DIR=%~dp0"
if "%BASE_DIR:~-1%"=="\" set "BASE_DIR=%BASE_DIR:~0,-1%"

:: Detect if dist_client subfolder exists (repository root) or if running inside dist_client
if exist "%BASE_DIR%\dist_client\libclicom_engine.dll" (
    set "CLIENT_DIR=%BASE_DIR%\dist_client"
) else (
    set "CLIENT_DIR=%BASE_DIR%"
)

:: Locate server executable
if exist "%CLIENT_DIR%\clicom-server.exe" (
    set "SERVER_EXE=%CLIENT_DIR%\clicom-server.exe"
    set "SERVER_DIR=%CLIENT_DIR%"
) else if exist "%BASE_DIR%\build\windows-ninja-debug\server\clicom-server.exe" (
    set "SERVER_EXE=%BASE_DIR%\build\windows-ninja-debug\server\clicom-server.exe"
    set "SERVER_DIR=%BASE_DIR%"
) else (
    set "SERVER_EXE=%CLIENT_DIR%\clicom-server.exe"
    set "SERVER_DIR=%CLIENT_DIR%"
)

:: Handle command-line arguments if provided
set "ARG1=%~1"
if /i "%ARG1%"=="server" goto :do_server
if /i "%ARG1%"=="s" goto :do_server
if /i "%ARG1%"=="client" goto :do_client_args
if /i "%ARG1%"=="c" goto :do_client_args

echo >____________Welcome to CLICOM___________
set /p "CHOICE=>client or server: "
set "CHOICE=!CHOICE: =!"

if /i "!CHOICE!"=="server" goto :do_server
if /i "!CHOICE!"=="s" goto :do_server
if /i "!CHOICE!"=="1" goto :do_server
if /i "!CHOICE!"=="client" goto :do_client
if /i "!CHOICE!"=="c" goto :do_client
if /i "!CHOICE!"=="2" goto :do_client

echo [!] Invalid selection. Please enter 'client' or 'server'.
pause
exit /b 1

:do_server
set "PORT=%~2"
if "!PORT!"=="" set "PORT=8443"

echo ========================================================
echo  CLICOM Tactical Communications Server
echo ========================================================
echo  YOUR ACTIVE IP ADDRESS FOR CLIENTS:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    set "RAW_IP=%%a"
    set "RAW_IP=!RAW_IP: =!"
    if "!RAW_IP:~0,7!" neq "169.254" if "!RAW_IP:~0,4!" neq "127." (
        echo    --^> !RAW_IP!
    )
)
echo ========================================================
echo  Listening on 0.0.0.0:!PORT! (TLS 1.3 Active)
echo ========================================================

cd /d "!SERVER_DIR!"
if not exist "!SERVER_EXE!" (
    echo [ERROR] Server executable not found at: !SERVER_EXE!
    pause
    exit /b 1
)

"!SERVER_EXE!" --bind 0.0.0.0 --port !PORT! --tls --cert certs/server.crt --key certs/server.key --db clicom.db
pause
exit /b 0

:do_client
set /p "TARGET_IP=>enter ip: "
set "TARGET_IP=!TARGET_IP: =!"
if "!TARGET_IP!"=="" set "TARGET_IP=127.0.0.1"

set /p "CLIENT_NAME=>name: "
set "CLIENT_NAME=!CLIENT_NAME: =!"
if "!CLIENT_NAME!"=="" set "CLIENT_NAME=OPERATOR"

set /p "TARGET_PORT=>port number: "
set "TARGET_PORT=!TARGET_PORT: =!"
if "!TARGET_PORT!"=="" set "TARGET_PORT=8443"

goto :run_client

:do_client_args
set "TARGET_IP=%~2"
set "CLIENT_NAME=%~3"
set "TARGET_PORT=%~4"
if "!TARGET_IP!"=="" set "TARGET_IP=127.0.0.1"
if "!CLIENT_NAME!"=="" set "CLIENT_NAME=OPERATOR"
if "!TARGET_PORT!"=="" set "TARGET_PORT=8443"

:run_client
echo ========================================================
echo  CLICOM Tactical Client - Connecting to !TARGET_IP!:!TARGET_PORT!
echo  Operator Handle: !CLIENT_NAME!
echo ========================================================

cd /d "!CLIENT_DIR!"
set "PATH=!CLIENT_DIR!;!PATH!"

python -m client.cli -s !TARGET_IP! -p !TARGET_PORT! --ca-cert certs/ca.crt -n !CLIENT_NAME!
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo If textual is missing, install it with: pip install textual
    pause
)
exit /b 0
