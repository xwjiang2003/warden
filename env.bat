@echo off
REM 在 cmd 中 source: 先 cd 到本目录，再 call env.bat
set "GOPROXY=https://goproxy.cn,https://goproxy.io,direct"
set "GOSUMDB=sum.golang.google.cn"
