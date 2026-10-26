$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker Desktop is required. Install Docker Desktop, then run this launcher again."
}
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
New-Item -ItemType Directory -Force -Path "state" | Out-Null
# Compose reads GUARD_PORT from .env, but PowerShell does not automatically
# export that value. Read only the selected port, never execute the .env file.
$port = if ($env:GUARD_PORT) { $env:GUARD_PORT } else {
  $entry = Get-Content ".env" | Where-Object { $_ -match '^\s*GUARD_PORT\s*=' } | Select-Object -Last 1
  if ($entry) {
    $value = (($entry -split '=', 2)[1] -replace '\s+#.*$', '').Trim()
    $value.Trim([char]'"').Trim([char]"'")
  } else { "8080" }
}
if ($port -notmatch '^\d+$' -or [int64]$port -lt 1 -or [int64]$port -gt 65535) {
  throw "Invalid GUARD_PORT: use a port from 1 to 65535."
}
docker compose -f compose.yml up -d --build guard
$url = "http://127.0.0.1:$port/setup"
for ($attempt = 0; $attempt -lt 60; $attempt++) {
  try { Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/health" -TimeoutSec 3 | Out-Null; break }
  catch { if ($attempt -eq 59) { throw "Guard did not become ready. Run: docker compose -f compose.yml logs guard" }; Start-Sleep -Seconds 1 }
}
Start-Process $url
Write-Host "AccessProof Guard setup is open at $url"
