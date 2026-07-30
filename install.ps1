#Requires -Version 5.1
<#
.SYNOPSIS
    Install ProcessGuard MCP and register it with Claude Desktop.

.DESCRIPTION
    Installs the processguard-mcp binary under %ProgramFiles%\ProcessGuard (an
    admin-only-writable location) and adds an entry to Claude Desktop's
    claude_desktop_config.json. The server runs elevated, so a user-writable install
    dir would let a standard user or malware swap the binary that then runs with
    Administrator rights -- hence Program Files. Must be run from an elevated PowerShell.
    Native Stage-0 tools work immediately with no further configuration.

    With -BinaryPath, installs a prebuilt (signed release) binary. Without it, builds
    from source using `go build` (requires Go 1.25+).

.PARAMETER BinaryPath
    Path to a prebuilt processguard-mcp.exe (e.g. from a verified GitHub Release).

.PARAMETER ExpectedSha256
    Expected SHA256 of the EXE at -BinaryPath. When supplied, the binary is verified
    before install and a mismatch aborts. Strongly recommended with -BinaryPath --
    otherwise an unverified, potentially tampered elevated-privilege binary is installed.

    NOTE: the published SHA256SUMS lists the hashes of the ZIP archives, not of the exe
    inside them, so you cannot copy a value straight out of it for this parameter. The
    supported chain is: verify the ARCHIVE (cosign + SHA256SUMS, see the README's
    "Verifying a release"), then take the exe's hash from the archive you just verified:

        Get-FileHash .\processguard-mcp.exe -Algorithm SHA256

    Verifying the archive is what establishes provenance; this parameter then guards the
    copy itself. Omitting it after a verified extraction is reasonable -- the warning
    below is aimed at installing a binary of unknown origin.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -BinaryPath .\processguard-mcp.exe -ExpectedSha256 <hash-from-SHA256SUMS>
#>
param(
    [string]$BinaryPath,
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'

# Upgrading over a RUNNING server is the normal case, not an edge case: upgrading is
# chiefly what this installer is for. Copy-Item's bare System.IO.IOException ("being
# used by another process") names neither the holder nor the remedy, so detect the
# condition up front and say exactly what to stop.
function Assert-TargetNotInUse([string]$path) {
    if (-not (Test-Path $path)) { return }

    # Filter by process NAME first: enumerating .Path across every process raises
    # access errors for protected processes this script has no business inspecting.
    $holders = @(
        Get-Process -Name 'processguard-mcp' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $path }
    )
    if ($holders.Count -eq 0) { return }

    $detail = ($holders | ForEach-Object { "PID $($_.Id)" }) -join ', '
    throw @"
Cannot install: '$path' is in use by $($holders.Count) running process(es): $detail

That is ProcessGuard itself, almost certainly running as an MCP server started by Claude.
Stop it and re-run this installer:

    Get-Process processguard-mcp | Stop-Process -Force

Claude starts a fresh server the next time it connects, so nothing is lost. Fully
quitting Claude Desktop has the same effect.
"@
}

# The server runs elevated, so its binary must live where a non-admin cannot
# replace it (otherwise: plant a malicious exe, wait for the next elevated run).
# Program Files is admin-only-writable; installing there requires elevation.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This installer must run elevated. Installing to $env:ProgramFiles\ProcessGuard (admin-only) prevents binary-planting against the elevated server. Re-run from an Administrator PowerShell."
}

$installDir = Join-Path $env:ProgramFiles 'ProcessGuard'
$target = Join-Path $installDir 'processguard-mcp.exe'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

if ($BinaryPath) {
    if ($ExpectedSha256) {
        $want = ($ExpectedSha256.Trim().ToUpper() -replace '^SHA256:', '')
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $BinaryPath).Hash
        if ($got -ne $want) {
            throw "SHA256 mismatch for ${BinaryPath}:`n  expected $want`n  actual   $got`nRefusing to install an unverified binary."
        }
        Write-Host "SHA256 verified." -ForegroundColor Green
    }
    else {
        Write-Warning "Installing $BinaryPath WITHOUT verification. Verify the release first (README 'Verifying a release'): pass -ExpectedSha256 <hash from SHA256SUMS>, or run 'cosign verify-blob' + 'sha256sum -c' before installing an elevated-privilege binary."
    }
    Assert-TargetNotInUse $target
    Write-Host "Installing from $BinaryPath ..."
    Copy-Item -Path $BinaryPath -Destination $target -Force
}
else {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go is not installed. Install Go 1.25+ from https://go.dev/dl/, or re-run with -BinaryPath pointing at a downloaded release binary."
    }
    # The build writes straight to $target, so it hits the same in-use failure.
    Assert-TargetNotInUse $target
    Write-Host "Building processguard-mcp from source ..."
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    Push-Location $scriptRoot
    try {
        $version = (git describe --tags --always 2>$null)
        if (-not $version) { $version = 'dev' }
        # Match the Makefile/goreleaser ldflags so a source install reports a real
        # commit + build date in serverInfo instead of "none"/"unknown".
        $commit = (git rev-parse --short HEAD 2>$null)
        if (-not $commit) { $commit = 'none' }
        $buildDate = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        go build -ldflags "-s -w -X main.Version=$version -X main.Commit=$commit -X main.BuildDate=$buildDate" -o $target .
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    }
    finally { Pop-Location }
}
Write-Host "Installed to $target" -ForegroundColor Green
# Print the installed exe's hash: SHA256SUMS publishes ARCHIVE hashes only, so this is
# the value to pass to -ExpectedSha256 on a later re-install, and the one to compare if
# you ever need to confirm which build is deployed.
Write-Host "  SHA256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash)"

# Harden config.json if it already exists (upgrade / re-install): it may hold the
# VirusTotal API key, and files under Program Files are world-READABLE by default.
# Restrict it to Administrators + SYSTEM so a non-admin can neither read the key nor
# plant a config the elevated server would load. The binary itself stays
# Users-readable so the non-elevated Stage-0 mode keeps working.
$installConfig = Join-Path $installDir 'config.json'
if (Test-Path $installConfig) {
    icacls $installConfig /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
    Write-Host "Restricted existing config.json to Administrators + SYSTEM." -ForegroundColor Green
}

# -- Register with Claude Desktop --------------------------------------------
$claudeCfg = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
$claudeDir = Split-Path -Parent $claudeCfg

if (-not (Test-Path $claudeDir)) {
    Write-Warning "Claude Desktop config dir not found ($claudeDir). Is Claude Desktop installed? Skipping registration."
}
else {
    if (Test-Path $claudeCfg) {
        $cfg = Get-Content $claudeCfg -Raw | ConvertFrom-Json
        # Back up the existing config before rewriting it (so a bad write is recoverable).
        Copy-Item $claudeCfg "$claudeCfg.bak" -Force
    }
    else {
        $cfg = [pscustomobject]@{}
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'mcpServers')) {
        $cfg | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    $server = [pscustomobject]@{ command = $target; args = @() }
    $cfg.mcpServers | Add-Member -NotePropertyName 'processguard' -NotePropertyValue $server -Force
    # -Depth 32 (not the default) avoids silently flattening deeply-nested sibling MCP
    # entries into type-name strings; validate the JSON re-parses before overwriting.
    $json = $cfg | ConvertTo-Json -Depth 32
    try { $null = $json | ConvertFrom-Json } catch {
        throw "Refusing to write claude_desktop_config.json -- re-serialized JSON did not validate: $_"
    }
    # WriteAllText with UTF8Encoding($false) -- NOT `Set-Content -Encoding UTF8`. Under Windows
    # PowerShell 5.1 (which this script #Requires) `-Encoding UTF8` writes a UTF-8 BOM. Electron
    # reads this file as utf8 and hands the string to JSON.parse, which rejects a leading U+FEFF
    # ("Unexpected token"). A BOM here therefore breaks the ENTIRE mcpServers block -- every MCP
    # server silently fails to load, not just this one. $claudeCfg is absolute, so WriteAllText's
    # CWD-relative path resolution is not a hazard here.
    [System.IO.File]::WriteAllText($claudeCfg, $json, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Registered 'processguard' in $claudeCfg (backup at $claudeCfg.bak)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Restart Claude Desktop, then ask it to run 'list_processes'." -ForegroundColor Cyan
Write-Host "Native tools work now. To enable optional stages (Autoruns / Sysmon / VirusTotal / GeoIP),"
Write-Host "copy config.example.json to '$installDir\config.json' (an admin-only write) and fill in the"
Write-Host "paths/keys, then lock the file so the VT API key is not world-readable under Program Files:"
Write-Host "  icacls `"$installDir\config.json`" /inheritance:r /grant:r Administrators:F SYSTEM:F" -ForegroundColor Yellow
