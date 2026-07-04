@echo off
chcp 65001 >nul 2>&1
title pyfls-waf
cd /d "%~dp0"

if not exist "pyfls-waf.exe" (
  echo [错误] 未找到 pyfls-waf.exe，请先运行 install.bat 编译
  goto :end
)
if not exist "config.json" (
  echo [错误] 未找到 config.json
  goto :end
)
if not exist "rules\coraza.conf" (
  echo [错误] 未找到 rules\coraza.conf
  goto :end
)

echo 启动 WAF（本窗口需保持打开）...
echo 配置: %CD%\config.json
echo 若刚改过 main.go / ratelimit.go 请先运行 install.bat 重新编译
echo 健康检查: http://127.0.0.1/healthz  （WAF 监听 80，需管理员运行）
echo 按 Ctrl+C 可停止
echo.

pyfls-waf.exe -config config.json
echo.
echo 进程已退出，退出码: %ERRORLEVEL%
if exist "logs\startup-error.log" (
  echo.
  echo --- logs\startup-error.log ---
  type "logs\startup-error.log"
)

:end
echo.
pause
