<#
  install.ps1 - installs the `pcscan` command on Windows.

  Run in PowerShell:
      powershell -ExecutionPolicy Bypass -File .\install.ps1

  - Copies pcscan.ps1 to %LOCALAPPDATA%\pcscan
  - Creates a `pcscan` command on your PATH (pcscan.cmd shim)
  - Updates Microsoft Defender signatures (the built-in Windows antivirus)
  - Optionally installs ClamAV too (via winget) if you pass -WithClamAV
#>
[CmdletBinding()]
param([switch]$WithClamAV)
$ErrorActionPreference = 'Stop'

$src = Join-Path $PSScriptRoot 'pcscan.ps1'
if (-not (Test-Path $src)) { Write-Host "[x] pcscan.ps1 not found next to this installer." -ForegroundColor Red; exit 1 }

$dest = Join-Path $env:LOCALAPPDATA 'pcscan'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item $src (Join-Path $dest 'pcscan.ps1') -Force
Write-Host "==> Installed pcscan.ps1 to $dest" -ForegroundColor Green

# Create a launcher shim: pcscan.cmd
$shim = Join-Path $dest 'pcscan.cmd'
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\pcscan\pcscan.ps1" %*
"@ | Set-Content -Encoding ASCII $shim
Write-Host "==> Created launcher: $shim" -ForegroundColor Green

# Add install dir to the USER PATH if missing
$userPath = [Environment]::GetEnvironmentVariable('Path','User')
if ($userPath -notlike "*$dest*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$dest", 'User')
  Write-Host "==> Added $dest to your PATH (open a NEW terminal to use 'pcscan')." -ForegroundColor Yellow
}

# Update Microsoft Defender signatures (native Windows AV)
Write-Host "==> Updating Microsoft Defender signatures..." -ForegroundColor Green
try { Update-MpSignature; Write-Host "    Defender signatures updated." -ForegroundColor Green }
catch { Write-Host "    Could not update Defender signatures (run as Administrator to force)." -ForegroundColor Yellow }

# Optional: ClamAV via winget
if ($WithClamAV) {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "==> Installing ClamAV via winget..." -ForegroundColor Green
    winget install --id ClamAV.ClamAV -e --accept-source-agreements --accept-package-agreements
    Write-Host "    After install, run 'freshclam' to download ClamAV signatures." -ForegroundColor Yellow
  } else {
    Write-Host "    winget not found - skipping ClamAV. (Windows Defender is already your AV.)" -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "Done. Open a NEW terminal, then run:" -ForegroundColor Green
Write-Host "  pcscan                  (interactive menu)"
Write-Host "  pcscan -Diff            (what changed since baseline)"
Write-Host "  pcscan -Malware         (Defender status + quick scan)"
Write-Host "  pcscan -SaveBaseline    (first-time setup)"
