@echo off
rem AegisScan launcher for Windows.
rem Builds the React UI if it has not been built yet (or when you pass --rebuild),
rem then starts the web server. Usage:
rem   run_aegisscan.bat [--rebuild] [--allow "D:\some\folder"] [port]
rem
rem The server only scans inside this project unless more folders are allowed.
rem --allow can be repeated; the folders are added to AEGISSCAN_ALLOWED_ROOTS (which you can
rem also set yourself before running this file).
rem
rem Calls node directly instead of "npm run" because this project's folder name
rem contains "&", which cmd.exe would split on.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "REBUILD=0"
set "PORT=8000"
:args
if "%~1"=="" goto args_done
if /i "%~1"=="--rebuild" (
    set "REBUILD=1"
    shift
    goto args
)
if /i "%~1"=="--allow" (
    if "%~2"=="" (
        echo [error] --allow needs a folder path.
        exit /b 1
    )
    if defined AEGISSCAN_ALLOWED_ROOTS (
        set "AEGISSCAN_ALLOWED_ROOTS=%AEGISSCAN_ALLOWED_ROOTS%;%~2"
    ) else (
        set "AEGISSCAN_ALLOWED_ROOTS=%~2"
    )
    shift
    shift
    goto args
)
set "PORT=%~1"
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
if defined AEGISSCAN_ALLOWED_ROOTS (echo Extra scan roots: !AEGISSCAN_ALLOWED_ROOTS!) else (echo Scans are limited to this project folder. Use --allow "folder" to add more.)
"%PY%" main.py --server --port %PORT%
endlocal
