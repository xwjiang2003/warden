# Windows 编译脚本
Set-Location $PSScriptRoot
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -o pyfls-waf.exe .
if ($LASTEXITCODE -eq 0) {
    Write-Host "OK: pyfls-waf.exe"
    Write-Host "Run: .\pyfls-waf.exe -config config.json"
}
