param(
  [string]$DataDir = ".\data"
)

$simDir = Split-Path -Parent $PSScriptRoot
$resolvedDataDir = if ([System.IO.Path]::IsPathRooted($DataDir)) {
  [System.IO.Path]::GetFullPath($DataDir)
} else {
  [System.IO.Path]::GetFullPath((Join-Path $simDir $DataDir))
}

$storeFile = Join-Path $resolvedDataDir 'atoms-sim-store.json'
if (Test-Path $storeFile) {
  Remove-Item $storeFile -Force
  Write-Host "Removed ATOMS sim store: $storeFile"
} else {
  Write-Host "No ATOMS sim store found at: $storeFile"
}
