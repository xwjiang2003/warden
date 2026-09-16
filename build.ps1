# Warden 跨平台编译脚本
#
# 一次编译出全部发布目标（Go 交叉编译，不需要目标平台的机器）：
#   warden.exe           Windows / amd64
#   warden               Linux   / amd64
#   warden-linux-arm64   Linux   / arm64
#
# 用法：
#   .\build.ps1                  # 编译全部目标（推荐）
#   .\build.ps1 -WindowsOnly     # 只编 Windows 版本（本机调试，最快）
#   .\build.ps1 -Version 1.0.2   # 构建时注入版本号
param(
    [switch]$WindowsOnly,
    [string]$Version
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# SQLite 用的是纯 Go 实现（modernc.org/sqlite），交叉编译必须显式关闭 cgo，
# 否则 GOOS=linux 时 go 会去找对应平台的 C 工具链并失败。
$env:CGO_ENABLED = "0"

function Invoke-GoBuild {
    param(
        [string]$GoOs,
        [string]$GoArch,
        [string]$OutFile,
        [string]$LdFlags
    )

    Write-Host "==> $OutFile  ($GoOs/$GoArch)"
    $env:GOOS = $GoOs
    $env:GOARCH = $GoArch
    if ($LdFlags) {
        go build -ldflags $LdFlags -o $OutFile ./cmd/warden
    } else {
        go build -o $OutFile ./cmd/warden
    }
    $code = $LASTEXITCODE
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "编译失败：$OutFile ($GoOs/$GoArch)" }
}

$ldflags = ""
if ($Version) { $ldflags = "-X warden/internal/version.Version=$Version" }

Write-Host "[1/2] go mod tidy ..."
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/2] 编译 ..."
Invoke-GoBuild -GoOs windows -GoArch amd64 -OutFile warden.exe -LdFlags $ldflags
if (-not $WindowsOnly) {
    # Linux 产物不带扩展名，解压后 ./warden 即可执行
    Invoke-GoBuild -GoOs linux -GoArch amd64 -OutFile warden -LdFlags $ldflags
    Invoke-GoBuild -GoOs linux -GoArch arm64 -OutFile warden-linux-arm64 -LdFlags $ldflags
}
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "构建完成："
foreach ($f in @("warden.exe", "warden", "warden-linux-arm64")) {
    if (Test-Path $f) {
        Write-Host ("  {0,-20} {1,12:N0} bytes" -f $f, (Get-Item $f).Length)
    }
}
Write-Host ""
Write-Host "Windows: 双击 run.bat"
Write-Host "Linux:   chmod +x run.sh && ./run.sh"
