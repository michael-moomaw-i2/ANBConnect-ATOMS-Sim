param(
  [string]$DataDir = ".\data",
  [ValidateSet("ExampleNodes", "Empty")]
  [string]$Profile = "ExampleNodes"
)

$ErrorActionPreference = "Stop"
$simDir = Split-Path -Parent $PSScriptRoot
$resolvedDataDir = if ([System.IO.Path]::IsPathRooted($DataDir)) {
  [System.IO.Path]::GetFullPath($DataDir)
} else {
  [System.IO.Path]::GetFullPath((Join-Path $simDir $DataDir))
}

New-Item -ItemType Directory -Force -Path $resolvedDataDir | Out-Null
$storeFile = Join-Path $resolvedDataDir 'atoms-sim-store.json'

if ($Profile -eq "ExampleNodes") {
  $fixture = Join-Path $simDir 'fixtures\example-nodes-store.json'
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "Example fixture not found: $fixture"
  }
  Copy-Item -LiteralPath $fixture -Destination $storeFile -Force
  Write-Host "Reset ATOMS sim store to PDF-derived Query for Nodes fixture:"
  Write-Host "  $storeFile"
  Write-Host "The fixture is ready. Restart the simulator only if it is already running."
  exit 0
}

if (Test-Path -LiteralPath $storeFile) {
  Remove-Item -LiteralPath $storeFile -Force
  Write-Host "Removed ATOMS sim store: $storeFile"
} else {
  Write-Host "No ATOMS sim store found at: $storeFile"
}
