@echo off
chcp 65001 >nul 2>&1
title 沃盾 编译
cd /d "%~dp0"

REM 国内网络：使用 Go 模块镜像（可编辑为本机代理）
set "GOPROXY=https://goproxy.cn,https://goproxy.io,direct"
set "GOSUMDB=sum.golang.google.cn"

echo ========================================
echo   沃盾 编译安装
echo   目录: %CD%
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
    echo [错误] 未检测到 Go，请先安装 https://go.dev/dl/
    goto :end_pause
  )
)

echo [1/3] Go 版本:
go version
if errorlevel 1 goto :end_pause
echo.

echo [2/3] 下载依赖 go mod tidy ...
echo （若仍失败，可编辑本 bat 顶部 GOPROXY，或运行 set-proxy.bat）
go mod tidy
if errorlevel 1 (
  echo.
  echo [错误] 下载依赖失败。可尝试:
  echo   1. 运行 set-proxy.bat 后重试
  echo   2. 手机热点 / 代理 VPN 后再运行 install.bat
  echo   3. 公司网络限制 443 时联系网管放行 goproxy.cn
  goto :end_pause
)
echo.

echo [3/3] 编译 warden.exe ...
go build -o warden.exe ./cmd/warden
if errorlevel 1 (
  echo [错误] 编译失败
  goto :end_pause
)

echo.
echo ========================================
echo   编译成功: %CD%\warden.exe
echo   运行: 请双击 run.bat（不要直接双击 exe，否则窗口会闪退）
echo ========================================
echo.

:end_pause
echo 按任意键关闭窗口...
pause >nul
