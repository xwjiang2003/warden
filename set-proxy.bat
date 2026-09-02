@echo off
chcp 65001 >nul 2>&1
echo 设置当前窗口 Go 代理（国内镜像）
set "GOPROXY=https://goproxy.cn,https://goproxy.io,direct"
set "GOSUMDB=sum.golang.google.cn"
echo GOPROXY=%GOPROXY%
echo GOSUMDB=%GOSUMDB%
echo.
echo 可选 - 若你有本地 HTTP 代理，取消下面两行注释并改成你的地址:
REM set "HTTP_PROXY=http://127.0.0.1:7890"
REM set "HTTPS_PROXY=http://127.0.0.1:7890"
echo.
echo 本窗口已生效。请在本窗口执行:
echo   cd /d %~dp0
echo   go mod tidy
echo   go build -o warden.exe .
echo.
echo 要永久生效（用户环境变量），以管理员运行:
echo   setx GOPROXY "https://goproxy.cn,https://goproxy.io,direct"
echo   setx GOSUMDB "sum.golang.google.cn"
echo.
pause
