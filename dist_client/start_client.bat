@echo off
set SERVER_IP=%1
set NODE_NAME=%2
set PORT=%3
if "%SERVER_IP%"=="" set SERVER_IP=127.0.0.1
if "%NODE_NAME%"=="" set NODE_NAME=OPERATOR-NODE
if "%PORT%"=="" set PORT=8443

echo ========================================================
echo  CLICOM Tactical Client - Connecting to %SERVER_IP%:%PORT%
echo ========================================================
pip install textual >nul 2>&1
python -m client.cli -s %SERVER_IP% -p %PORT% --ca-cert certs/ca.crt -n %NODE_NAME%
pause
