@echo off
setlocal

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-all.ps1"
set EXIT_CODE=%ERRORLEVEL%

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Build failed with exit code %EXIT_CODE%.
) else (
    echo.
    echo Build script completed.
)

exit /b %EXIT_CODE%
