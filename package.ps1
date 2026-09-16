# Warden 发布打包脚本
#
# 产出一个 zip，Windows 与 Linux 的产物平铺在根目录 —— 不论在什么系统上解压都能直接用：
#   warden.exe           Windows / amd64
#   warden               Linux   / amd64
#   warden-linux-arm64   Linux   / arm64
#   run.bat / run.sh     各平台启动脚本
#   config.json          默认配置
#   rules/coraza.conf    WAF 规则
#   data/ip2region.xdb   IP 归属库（国外/云厂商拦截依赖；-SkipIPDB 可排除，省约 10MB）
#   LICENSE / NOTICE     Apache-2.0 第 4 条要求分发时随附
#
# 用法：
#   .\package.ps1                  # 先编译全部平台，再打包
#   .\package.ps1 -NoBuild         # 跳过编译，用现有二进制打包
#   .\package.ps1 -SkipIPDB        # 不打进 data/ip2region.xdb
#   .\package.ps1 -Version 1.0.2   # 覆盖版本号（默认取自 internal/version/version.go）
param(
    [switch]$NoBuild,
    [switch]$SkipIPDB,
    [string]$Version
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Get-ProjectVersion {
    $m = Select-String -Path "internal\version\version.go" -Pattern 'Version\s*=\s*"([^"]+)"' |
         Select-Object -First 1
    if (-not $m) { throw "无法从 internal\version\version.go 解析版本号" }
    return $m.Matches[0].Groups[1].Value
}

if (-not $Version) { $Version = Get-ProjectVersion }
Write-Host "版本：$Version"

if (-not $NoBuild) {
    Write-Host "==> 编译 Windows/amd64 + Linux/amd64 + Linux/arm64"
    & .\build.ps1 -Version $Version
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$required = @("warden.exe", "warden", "warden-linux-arm64", "run.bat", "run.sh", "config.json")
foreach ($f in $required) {
    if (-not (Test-Path $f)) { throw "缺少 $f：请先执行 .\build.ps1 完成编译（或检查文件是否被误删）" }
}

$build = "dist\warden"
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$build\rules" | Out-Null

foreach ($f in $required) { Copy-Item $f "$build\" -Force }
Copy-Item "rules\coraza.conf" "$build\rules\" -Force
# Apache-2.0 第 4 条要求：分发时必须随附许可与声明文件
Copy-Item "LICENSE" "$build\" -Force
Copy-Item "NOTICE" "$build\" -Force

if (-not $SkipIPDB) {
    if (Test-Path "data\ip2region.xdb") {
        New-Item -ItemType Directory -Force -Path "$build\data" | Out-Null
        Copy-Item "data\ip2region.xdb" "$build\data\" -Force
    } else {
        Write-Warning "未找到 data\ip2region.xdb：国外/云厂商 IP 拦截将不可用（预期如此可加 -SkipIPDB）"
    }
}

$dest = "dist\warden-v$Version.zip"
if (Test-Path $dest) { Remove-Item $dest -Force }

# 不用 Compress-Archive：它会把目录分隔符写成 '\'，Linux/macOS 解压后会得到
# 名字里带反斜杠的文件（rules/coraza.conf 会变成 rules\coraza.conf 而加载失败）。
# 这里直接用 .NET ZipFile，条目名统一用 '/'（ZIP 规范要求的分隔符）。
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$destPath = Join-Path (Get-Location) $dest
$rootPath = (Resolve-Path $build).Path
$zip = [System.IO.Compression.ZipFile]::Open($destPath, "Create")
try {
    Get-ChildItem $build -Recurse -File | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($rootPath.Length + 1).Replace("\", "/")
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, $_.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        Write-Host ("  + {0,-24} {1,12:N0}" -f $rel, $_.Length)
    }
} finally {
    $zip.Dispose()
}

Write-Host "OK: $dest  $((Get-Item $dest).Length) bytes"
Write-Host ("SHA256: " + (Get-FileHash $dest -Algorithm SHA256).Hash)
