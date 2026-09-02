$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$build = "dist\warden"
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$build\rules" | Out-Null
New-Item -ItemType Directory -Force -Path "$build\logs" | Out-Null

Copy-Item "warden.exe" "$build\" -Force
Copy-Item "config.json" "$build\" -Force
Copy-Item "run.bat" "$build\" -Force
Copy-Item "rules\coraza.conf" "$build\rules\" -Force

$dest = "dist\warden.zip"
if (Test-Path $dest) { Remove-Item $dest -Force }

Compress-Archive -Path "$build\*" -DestinationPath $dest -Force

Write-Host "OK: $((Get-Item $dest).Length) bytes"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::OpenRead($dest).Entries | ForEach-Object { Write-Host $_.FullName $_.Length }
