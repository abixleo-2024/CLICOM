@echo off
echo ========================================================
echo  CLICOM Stealth Internet Tunnel (via Serveo)
echo  Forwarding local port 8443 to the public internet...
echo ========================================================
echo Connecting to public relay...
echo.
echo Look for: 'Forwarding TCP connections from serveo.net:XXXXX'
echo Give that port number (XXXXX) to your friend!
echo ========================================================
echo.
ssh -o StrictHostKeyChecking=no -R 0:localhost:8443 serveo.net
pause
