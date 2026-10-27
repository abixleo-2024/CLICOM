@echo off
set PORT=8443
if not "%1"=="" set PORT=%1

echo ========================================================
echo  CLICOM Tactical Communications Server
echo ========================================================
echo  YOUR ACTIVE IP ADDRESS FOR CLIENTS:
for /f "tokens=4" %%a in ('route print ^| findstr 0.0.0.0 ^| findstr /v "255.255.255.255" ^| findstr /v "On-link"') do (
    if not "%%a"=="" echo    --> %%a
)
echo ========================================================
echo  Listening on 0.0.0.0:%PORT% (TLS 1.3 Active)
echo ========================================================
.\build\windows-ninja-debug\server\clicom-server.exe --bind 0.0.0.0 --port %PORT% --tls --cert certs/server.crt --key certs/server.key --db clicom.db
pause
