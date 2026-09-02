# Windows 编译脚本
Set-Location $PSScriptRoot
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -o warden.exe .
if ($LASTEXITCODE -eq 0) {
    Write-Host "OK: warden.exe"
    Write-Host "Run: .\warden.exe -config config.json"
}
