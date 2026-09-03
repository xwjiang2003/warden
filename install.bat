@echo off
title Warden WAF build
cd /d "%~dp0"

REM Use China Go module mirror (edit if needed)
set "GOPROXY=https://goproxy.cn,https://goproxy.io,direct"
set "GOSUMDB=sum.golang.google.cn"

echo ========================================
echo   Warden WAF build
echo   Dir: %CD%
echo   GOPROXY=%GOPROXY%
echo ========================================
echo.

set "GOEXE=go"
where go >nul 2>&1
if errorlevel 1 (
  if exist "%ProgramFiles%\Go\bin\go.exe" (
    set "PATH=%ProgramFiles%\Go\bin;%PATH%"
  ) else if exist "%LocalAppData%\Programs\Go\bin\go.exe" (
    set "PATH=%LocalAppData%\Programs\Go\bin;%PATH%"
  ) else (
    echo [Error] Go not found. Install from https://go.dev/dl/
    goto :end_pause
  )
)

echo [1/3] Go version:
go version
if errorlevel 1 goto :end_pause
echo.

echo [2/3] go mod tidy ...
echo (if it fails, edit GOPROXY at top, or run set-proxy.bat)
go mod tidy
if errorlevel 1 (
  echo.
  echo [Error] Failed to download deps. Try:
  echo   1. run set-proxy.bat then retry
  echo   2. use mobile hotspot / VPN proxy
  echo   3. ask admin to allow goproxy.cn on port 443
  goto :end_pause
)
echo.

echo [3/3] build warden.exe ...
go build -o warden.exe ./cmd/warden
if errorlevel 1 (
  echo [Error] build failed
  goto :end_pause
)

echo.
echo ========================================
echo   Build OK: %CD%\warden.exe
echo   Run: double-click run.bat (do NOT run exe directly)
echo ========================================
echo.

:end_pause
echo Press any key to close...
pause >nul
