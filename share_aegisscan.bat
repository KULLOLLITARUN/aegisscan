@echo off
rem Double-click to share AegisScan from this PC through a free Cloudflare tunnel.
rem Needs deploy\tunnel\cloudflared.exe (see README, "Free option: run it on your own PC").
rem Extra options are passed through, for example:  share_aegisscan.bat -NewToken
title AegisScan sharing
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "deploy\tunnel\start-tunnel.ps1" %*
echo.
echo The scanner has stopped. Press any key to close this window.
pause >nul
