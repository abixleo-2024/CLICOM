@echo off
echo ========================================================
echo  CLICOM Stealth Internet Tunnel
echo  Forwarding local port 8443 to the public internet...
echo ========================================================
echo Connecting to public relay...
echo Once connected, look for the 'tcp://...' address below.
echo.
ssh -p 443 -o StrictHostKeyChecking=no -R0:localhost:8443 tcp@free.pinggy.io
pause
