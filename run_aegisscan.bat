@echo off
rem AegisScan launcher for Windows.
rem Builds the React UI if it has not been built yet (or when you pass --rebuild),
rem then starts the web server. Usage:  run_aegisscan.bat [--rebuild] [port]
rem
rem Calls node directly instead of "npm run" because this project's folder name
rem contains "&", which cmd.exe would split on.

setlocal
cd /d "%~dp0"

set "REBUILD=0"
set "PORT=8000"
:args
if "%~1"=="" goto args_done
if /i "%~1"=="--rebuild" (set "REBUILD=1") else (set "PORT=%~1")
shift
goto args
:args_done

rem Prefer the project's virtual environment when there is one. The interpreter is called
rem directly because activate.bat can carry a stale hard-coded path.
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"

rem ---- UI build ----
if not exist "scanner\server\dist\index.html" set "REBUILD=1"
if "%REBUILD%"=="1" (
    where node >nul 2>&1
    if errorlevel 1 (
        echo [warn] Node.js was not found, so the UI cannot be built. Install Node 22 or newer.
        echo        The server will start with its basic fallback page.
        goto start_server
    )
    pushd ui
    if not exist "node_modules\vite\bin\vite.js" (
        echo Installing UI dependencies...
        call npm ci
        if errorlevel 1 (
            echo [error] npm ci failed.
            popd
            exit /b 1
        )
    )
    echo Building the UI...
    node node_modules\vite\bin\vite.js build
    if errorlevel 1 (
        echo [error] UI build failed.
        popd
        exit /b 1
    )
    popd
)

:start_server
echo.
echo Starting AegisScan on http://localhost:%PORT%  (Ctrl+C to stop)
"%PY%" main.py --server --port %PORT%
endlocal
