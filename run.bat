@echo off
title Warden WAF
cd /d "%~dp0"

if not exist "warden.exe" (
  echo [Error] warden.exe not found. Run install.bat first.
  goto :end
)
if not exist "config.json" (
  echo [Error] config.json not found
  goto :end
)
if not exist "rules\coraza.conf" (
  echo [Error] rules\coraza.conf not found
  goto :end
)

echo Starting WAF (keep this window open)...
echo Config: %CD%\config.json
echo If you edited main.go or other source, run install.bat to rebuild first.
echo Health check: http://127.0.0.1/healthz
echo Press Ctrl+C to stop
echo.

warden.exe -config config.json
echo.
echo Process exited, code: %ERRORLEVEL%
if exist "logs\startup-error.log" (
  echo.
  echo --- logs\startup-error.log ---
  type "logs\startup-error.log"
)

:end
echo.
pause
