@echo off
rem Double-click to scan ANY folder on this PC (local use only, nothing is shared).
rem Stops a previous AegisScan on the same port, starts a new one with every folder allowed,
rem and opens it in your browser. Optional: scan_any_folder.bat 8010   (to use another port)
title AegisScan - any folder
cd /d "%~dp0"

set "PORT=8000"
if not "%~1"=="" set "PORT=%~1"

rem A server left over from an earlier run would keep answering with the old settings.
powershell -NoProfile -Command "$p=%PORT%; Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $w=Get-CimInstance Win32_Process -Filter ('ProcessId='+$_.OwningProcess); if ($w.CommandLine -match 'main\.py\s+--server') { Write-Host ('Stopping the previous AegisScan (process '+$w.ProcessId+')...'); Stop-Process -Id $w.ProcessId -Force } }; Start-Sleep -Milliseconds 800"

rem Open the browser a few seconds after the server starts.
start "" /b cmd /c "timeout /t 5 /nobreak >nul & start http://localhost:%PORT%/dashboard"

call "%~dp0run_aegisscan.bat" --allow-any %PORT%

echo.
echo AegisScan has stopped. Press any key to close this window.
pause >nul
