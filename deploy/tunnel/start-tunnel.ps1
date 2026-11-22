<#
.SYNOPSIS
  Run AegisScan in hosted mode on this PC and share it through a free Cloudflare quick tunnel.

.DESCRIPTION
  Starts the server in hosted mode (folder upload or Git URL, access token required) bound to
  127.0.0.1 only, then opens a Cloudflare quick tunnel to it and prints the public https address.
  Nothing is exposed on your network: the tunnel program makes an outbound connection and forwards
  requests to localhost. The address changes every time you run this. Press Ctrl+C to stop both.

  Needs cloudflared.exe: put it in deploy\tunnel\ (it is git-ignored) or anywhere on PATH. Download:
  https://github.com/cloudflare/cloudflared/releases/latest (cloudflared-windows-amd64.exe, rename
  to cloudflared.exe). No Cloudflare account is needed for quick tunnels.

.PARAMETER Port
  Local port for the server. Default 8150.

.PARAMETER Token
  Access token for the scanner (16+ characters). Order of use: this parameter, the
  AEGISSCAN_ACCESS_TOKEN environment variable, the token saved on this PC, otherwise a random one is
  generated and saved. The saved token is encrypted for your Windows account and stored in
  %LOCALAPPDATA%\AegisScan\token.dat, outside the project.

.PARAMETER NewToken
  Ignore the saved token, generate a fresh one and save it (use this if the token leaked).

.PARAMETER NoTunnel
  Start only the local server (for testing), without a public address.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\tunnel\start-tunnel.ps1
#>
param(
  [int]$Port = 8150,
  [string]$Token = $env:AEGISSCAN_ACCESS_TOKEN,
  [switch]$NewToken,
  [switch]$NoTunnel
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$logDir = Join-Path $env:TEMP 'aegisscan-tunnel'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Stop-Tree([System.Diagnostics.Process]$p) {
  if ($p -and -not $p.HasExited) { & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null }
}

# ---- token: supplied, saved on this PC (encrypted for this Windows account), or new ----
$tokenFile = Join-Path $env:LOCALAPPDATA 'AegisScan\token.dat'

function Read-SavedToken {
  if (-not (Test-Path -LiteralPath $tokenFile)) { return $null }
  try {
    $secure = ConvertTo-SecureString ((Get-Content -LiteralPath $tokenFile -Raw).Trim())
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  } catch { return $null }   # unreadable (for example from another Windows account): make a new one
}

function Save-Token([string]$value) {
  New-Item -ItemType Directory -Force -Path (Split-Path $tokenFile) | Out-Null
  ConvertTo-SecureString $value -AsPlainText -Force | ConvertFrom-SecureString | Set-Content -LiteralPath $tokenFile -Encoding ascii
}

$tokenSource = 'supplied'
if (-not $Token -and -not $NewToken) {
  $saved = Read-SavedToken
  if ($saved) { $Token = $saved; $tokenSource = 'saved' }
}
if (-not $Token -or $NewToken) {
  $bytes = New-Object byte[] 24
  $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  $rng.GetBytes($bytes)
  $Token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  Save-Token $Token
  $tokenSource = 'new'
}
if ($Token.Length -lt 16) { throw "The access token must be at least 16 characters." }

# ---- python and UI build ----
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = 'python' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'scanner\server\dist\index.html'))) {
  Write-Host "Building the UI first..."
  Push-Location (Join-Path $root 'ui')
  try {
    if (-not (Test-Path -LiteralPath 'node_modules\vite\bin\vite.js')) { & npm ci; if ($LASTEXITCODE) { throw "npm ci failed" } }
    & node node_modules\vite\bin\vite.js build
    if ($LASTEXITCODE) { throw "UI build failed" }
  } finally { Pop-Location }
}

# ---- tunnel program ----
$cloudflared = $null
if (-not $NoTunnel) {
  $local = Join-Path $PSScriptRoot 'cloudflared.exe'
  if (Test-Path -LiteralPath $local) { $cloudflared = $local }
  else {
    $found = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($found) { $cloudflared = $found.Source }
  }
  if (-not $cloudflared) {
    throw "cloudflared.exe was not found. Download cloudflared-windows-amd64.exe from https://github.com/cloudflare/cloudflared/releases/latest, rename it to cloudflared.exe and put it in $PSScriptRoot (or on PATH). Or run with -NoTunnel to test locally."
  }
}

$server = $null
$tunnel = $null
try {
  # ---- server (hosted mode, localhost only) ----
  $saved = @{}
  $settings = @{ AEGISSCAN_MODE = 'hosted'; AEGISSCAN_ACCESS_TOKEN = $Token; AEGISSCAN_HOST = '127.0.0.1'; PORT = "$Port" }
  foreach ($k in $settings.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $settings[$k], 'Process') }
  try {
    $server = Start-Process -FilePath $py -ArgumentList 'main.py', '--server' -WorkingDirectory $root -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $logDir 'server.out.log') -RedirectStandardError (Join-Path $logDir 'server.err.log')
  } finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
  }

  $healthy = $false
  for ($i = 0; $i -lt 60; $i++) {
    if ($server.HasExited) { break }
    try { if ((Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/api/health" -TimeoutSec 2).StatusCode -eq 200) { $healthy = $true; break } } catch { Start-Sleep -Milliseconds 500 }
  }
  if (-not $healthy) {
    Write-Host "The server did not start. Last log lines:"
    Get-Content (Join-Path $logDir 'server.err.log') -Tail 15 -ErrorAction SilentlyContinue
    Get-Content (Join-Path $logDir 'server.out.log') -Tail 15 -ErrorAction SilentlyContinue
    throw "Server start failed (is port $Port already in use?)."
  }

  # ---- tunnel ----
  $url = "http://127.0.0.1:$Port  (this PC only; no tunnel)"
  if (-not $NoTunnel) {
    $tlog = Join-Path $logDir 'tunnel.err.log'
    $tunnel = Start-Process -FilePath $cloudflared -ArgumentList 'tunnel', '--no-autoupdate', '--url', "http://127.0.0.1:$Port" -PassThru -WindowStyle Hidden `
      -RedirectStandardError $tlog -RedirectStandardOutput (Join-Path $logDir 'tunnel.out.log')
    $url = $null
    for ($i = 0; $i -lt 80 -and -not $url; $i++) {
      Start-Sleep -Milliseconds 500
      if ($tunnel.HasExited) { break }
      if (Test-Path -LiteralPath $tlog) {
        $m = Select-String -Path $tlog -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($m) { $url = $m.Matches[0].Value }
      }
    }
    if (-not $url) {
      Write-Host "The tunnel did not report an address. Last log lines:"
      Get-Content $tlog -Tail 15 -ErrorAction SilentlyContinue
      throw "Tunnel start failed."
    }
  }

  Write-Host ""
  Write-Host "AegisScan is running."
  Write-Host "  Address : $url"
  switch ($tokenSource) {
    'new'      { Write-Host "  Token   : $Token   (new; saved on this PC so it stays the same next time)" }
    'saved'    { Write-Host "  Token   : $Token   (your saved token, the same as last time)" }
    default    { Write-Host "  Token   : the one you supplied" }
  }
  if (-not $NoTunnel) {
    try { Set-Clipboard -Value $url; Write-Host "  (The address is copied to your clipboard.)" } catch { }
    Write-Host ""
    Write-Host "Message you can send (send the token separately):"
    Write-Host "  Try my code scanner: $url"
    Write-Host "  Guide: https://github.com/KULLOLLITARUN/aegisscan/blob/main/docs/USER_GUIDE.md"
  }
  Write-Host ""
  Write-Host "Keep this window open: closing it, or pressing Ctrl+C, stops the scanner and the tunnel."
  Write-Host "The address changes every time you start this. Only share it with people you trust."
  Write-Host "To change the token: run again with -NewToken."
  while (-not $server.HasExited) { Start-Sleep -Seconds 2 }
  Write-Host "The server stopped. See $logDir for logs."
}
finally {
  Stop-Tree $tunnel
  Stop-Tree $server
}
