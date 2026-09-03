@echo off
echo Set Go proxy for this window (China mirror)
set "GOPROXY=https://goproxy.cn,https://goproxy.io,direct"
set "GOSUMDB=sum.golang.google.cn"
echo GOPROXY=%GOPROXY%
echo GOSUMDB=%GOSUMDB%
echo.
echo Optional - if you have a local HTTP proxy, uncomment and edit below:
REM set "HTTP_PROXY=http://127.0.0.1:7890"
REM set "HTTPS_PROXY=http://127.0.0.1:7890"
echo.
echo Now run in this window:
echo   cd /d %~dp0
echo   go mod tidy
echo   go build -o warden.exe ./cmd/warden
echo.
echo To persist (user env var), run as admin:
echo   setx GOPROXY "https://goproxy.cn,https://goproxy.io,direct"
echo   setx GOSUMDB "sum.golang.google.cn"
echo.
pause
