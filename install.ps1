#Requires -Version 5.1
<#
.SYNOPSIS
    Install ProcessGuard MCP and register it with Claude Desktop.

.DESCRIPTION
    Installs the processguard-mcp binary under %LOCALAPPDATA%\ProcessGuard and adds an
    entry to Claude Desktop's claude_desktop_config.json. Native Stage-0 tools work
    immediately with no further configuration.

    With -BinaryPath, installs a prebuilt (signed release) binary. Without it, builds
    from source using `go build` (requires Go 1.22+).

.PARAMETER BinaryPath
    Path to a prebuilt processguard-mcp.exe (e.g. from a verified GitHub Release).

.EXAMPLE
    .\install.ps1
    .\install.ps1 -BinaryPath .\processguard-mcp.exe
#>
param(
    [string]$BinaryPath
)

$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:LOCALAPPDATA 'ProcessGuard'
$target = Join-Path $installDir 'processguard-mcp.exe'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

if ($BinaryPath) {
    Write-Host "Installing from $BinaryPath ..."
    Copy-Item -Path $BinaryPath -Destination $target -Force
}
else {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go is not installed. Install Go 1.22+ from https://go.dev/dl/, or re-run with -BinaryPath pointing at a downloaded release binary."
    }
    Write-Host "Building processguard-mcp from source ..."
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    Push-Location $scriptRoot
    try {
        $version = (git describe --tags --always 2>$null)
        if (-not $version) { $version = 'dev' }
        go build -ldflags "-s -w -X main.Version=$version" -o $target .
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    }
    finally { Pop-Location }
}
Write-Host "Installed to $target" -ForegroundColor Green

# ── Register with Claude Desktop ────────────────────────────────────────────
$claudeCfg = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
$claudeDir = Split-Path -Parent $claudeCfg

if (-not (Test-Path $claudeDir)) {
    Write-Warning "Claude Desktop config dir not found ($claudeDir). Is Claude Desktop installed? Skipping registration."
}
else {
    if (Test-Path $claudeCfg) {
        $cfg = Get-Content $claudeCfg -Raw | ConvertFrom-Json
    }
    else {
        $cfg = [pscustomobject]@{}
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'mcpServers')) {
        $cfg | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    $server = [pscustomobject]@{ command = $target; args = @() }
    $cfg.mcpServers | Add-Member -NotePropertyName 'processguard' -NotePropertyValue $server -Force
    ($cfg | ConvertTo-Json -Depth 10) | Set-Content -Path $claudeCfg -Encoding UTF8
    Write-Host "Registered 'processguard' in $claudeCfg" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Restart Claude Desktop, then ask it to run 'list_processes'." -ForegroundColor Cyan
Write-Host "Native tools work now. To enable optional stages (Autoruns / Sysmon / VirusTotal / GeoIP),"
Write-Host "copy config.example.json to '$installDir\config.json' and fill in the paths/keys."
