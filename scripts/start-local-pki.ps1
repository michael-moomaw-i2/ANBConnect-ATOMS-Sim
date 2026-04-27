param(
  [string]$CertDir = ".\certs",
  [int]$Port = 4010,
  [switch]$NoClientCertRequired
)

$simDir = Split-Path -Parent $PSScriptRoot
Push-Location $simDir
try {
  $resolvedCertDir = if ([System.IO.Path]::IsPathRooted($CertDir)) {
    [System.IO.Path]::GetFullPath($CertDir)
  } else {
    [System.IO.Path]::GetFullPath((Join-Path $simDir $CertDir))
  }

  $serverPfx = Join-Path $resolvedCertDir 'atoms-server.pfx'
  $rootCa = Join-Path $resolvedCertDir 'dev-root-ca.cer'

  if (-not (Test-Path $serverPfx)) {
    throw "Server PFX not found: $serverPfx"
  }
  if (-not (Test-Path $rootCa)) {
    throw "Root CA file not found: $rootCa"
  }

  $env:PORT = [string]$Port
  $env:HTTPS_ENABLED = 'true'
  $env:HTTPS_PFX_FILE = $serverPfx
  $env:HTTPS_PFX_PASSWORD = 'Passw0rd!'
  $env:HTTPS_CA_FILE = $rootCa
  $env:HTTPS_REQUEST_CLIENT_CERT = 'true'
  $env:HTTPS_REQUIRE_CLIENT_CERT = if ($NoClientCertRequired) { 'false' } else { 'true' }

  Write-Host "Starting ATOMS sim with local PKI defaults..."
  Write-Host "  URL: https://localhost:$Port/graphql"
  Write-Host "  Server PFX: $serverPfx"
  Write-Host "  Root CA: $rootCa"
  Write-Host "  Require client cert: $($env:HTTPS_REQUIRE_CLIENT_CERT)"

  if (-not (Test-Path (Join-Path $simDir 'node_modules'))) {
    Write-Host 'Installing npm dependencies for atoms-sim...'
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
  }

  npm start
  if ($LASTEXITCODE -ne 0) { throw "npm start failed with exit code $LASTEXITCODE" }
}
finally {
  Pop-Location
}
