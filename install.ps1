<#
.SYNOPSIS
    MATT easy installer for Windows.
.DESCRIPTION
    Downloads the latest matt.pyz release (MATT has zero runtime
    dependencies -- it's pure Python standard library) and puts a `matt`
    command on your PATH. Re-runnable and safe: running it again just
    re-downloads the latest release over the old one.

    Live ARP-poison MITM capture (tcpdump/ettercap) is Linux-only and is not
    set up here -- use Kali for that. Offline analysis (--analyze-only),
    --identify, and --crack (with hashcat) work fully on Windows.
.EXAMPLE
    irm https://raw.githubusercontent.com/manatthetop/MATT/main/install.ps1 | iex
#>

$ErrorActionPreference = "Stop"

function Say($msg)  { Write-Host "[matt] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[matt] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[matt] $msg" -ForegroundColor Yellow }

Say "MATT easy installer (Windows)"

# 1. Python 3.11+ is required -- MATT itself has zero dependencies beyond it.
$python = $null
foreach ($cand in @("python", "python3", "py")) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        & $cand -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { $python = $cand; break }
    }
}
if (-not $python) {
    Warn "Python 3.11+ not found on PATH."
    Warn "Install it from https://www.python.org/downloads/ (or: winget install Python.Python.3.12) and re-run this script."
    exit 1
}
Ok "using $python ($((& $python --version) 2>&1))"

# 2. Download the latest matt.pyz release and the offline demo capture.
$installDir = Join-Path $env:LOCALAPPDATA "MATT"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $installDir "examples") | Out-Null

$pyzPath = Join-Path $installDir "matt.pyz"
Say "downloading the latest matt.pyz release ..."
Invoke-WebRequest -Uri "https://github.com/manatthetop/MATT/releases/latest/download/matt.pyz" -OutFile $pyzPath
Ok "saved to $pyzPath"

$examplePath = Join-Path $installDir "examples\enterprise_capture.json"
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/manatthetop/MATT/main/examples/enterprise_capture.json" -OutFile $examplePath
} catch {
    Warn "could not fetch the demo capture (skipping -- matt.pyz itself still works)"
}

# 3. A `matt.cmd` shim so `matt` works from any shell, cmd or PowerShell.
$cmdPath = Join-Path $installDir "matt.cmd"
"@echo off`r`n$python `"$pyzPath`" %*" | Set-Content -Path $cmdPath -Encoding ASCII
Ok "created $cmdPath"

# 4. Put $installDir on the user's PATH (persistent) if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$already = ($userPath -split ";") | Where-Object { $_ -eq $installDir }
if (-not $already) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Ok "added $installDir to your PATH (open a new terminal to pick it up there)"
} else {
    Ok "$installDir already on PATH"
}
$env:Path = "$env:Path;$installDir"   # usable immediately in this session too

# 5. Tell the operator what actually works here.
Write-Host ""
Ok "done. Try it right now, in this session:"
Write-Host "    matt --help"
if (Test-Path $examplePath) {
    Write-Host "    matt --analyze-only `"$examplePath`" --table"
}
Write-Host ""
Warn "Live ARP-poison MITM capture (tcpdump/ettercap) is Linux-only -- use Kali for that."
Warn "Offline analysis, --identify and --crack all work fully on Windows."
Write-Host ""
Warn "For --crack you also need hashcat on PATH, e.g.:  choco install hashcat"
Warn "Known issue: on some Windows boxes the chocolatey hashcat shim is broken"
Warn "and silently redirects to powershell.exe instead of the real binary. If"
Warn "'hashcat --version' doesn't print a version, find the real hashcat.exe"
Warn "under C:\tools\hashcat-*\ and put THAT folder ahead of"
Warn "C:\ProgramData\chocolatey\bin on PATH."
