param(
    [string]$OutputDir = ".\certs",
    [string]$Password = "Passw0rd!",
    [string]$DnsName = "localhost",
    [string]$ClientSubject = "ANBConnect ATOMS Dev Client",
    [string]$ServerSubject = "ANBConnect ATOMS Dev Server"
)

$ErrorActionPreference = 'Stop'

$baseDir = Split-Path -Parent $PSScriptRoot
$resolvedOutput = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
  [System.IO.Path]::GetFullPath($OutputDir)
} else {
  [System.IO.Path]::GetFullPath((Join-Path $baseDir $OutputDir))
}
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null

$rootSubject = 'CN=ANBConnect Dev Root CA'
$root = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $rootSubject `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -KeyUsageProperty All `
    -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=1') `
    -NotAfter (Get-Date).AddYears(5) `
    -CertStoreLocation 'Cert:\CurrentUser\My'

$server = New-SelfSignedCertificate `
    -Type SSLServerAuthentication `
    -DnsName $DnsName `
    -Subject "CN=$DnsName" `
    -Signer $root `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(2) `
    -CertStoreLocation 'Cert:\CurrentUser\My'

$client = New-SelfSignedCertificate `
    -Type Custom `
    -Subject "CN=$ClientSubject" `
    -Signer $root `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
    -NotAfter (Get-Date).AddYears(2) `
    -CertStoreLocation 'Cert:\CurrentUser\My'

$securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

$rootCer = Join-Path $resolvedOutput 'dev-root-ca.cer'
$serverCer = Join-Path $resolvedOutput 'atoms-server.cer'
$serverPfx = Join-Path $resolvedOutput 'atoms-server.pfx'
$clientCer = Join-Path $resolvedOutput 'atoms-client.cer'
$clientPfx = Join-Path $resolvedOutput 'atoms-client.pfx'

Export-Certificate -Cert $root -FilePath $rootCer -Force | Out-Null
Export-Certificate -Cert $server -FilePath $serverCer -Force | Out-Null
Export-PfxCertificate -Cert $server -FilePath $serverPfx -Password $securePassword -Force | Out-Null
Export-Certificate -Cert $client -FilePath $clientCer -Force | Out-Null
Export-PfxCertificate -Cert $client -FilePath $clientPfx -Password $securePassword -Force | Out-Null

Write-Host ''
Write-Host 'Created development PKI artifacts:' -ForegroundColor Cyan
Write-Host "  Root CA:      $rootCer"
Write-Host "  Server cert:  $serverCer"
Write-Host "  Server PFX:   $serverPfx"
Write-Host "  Client cert:  $clientCer"
Write-Host "  Client PFX:   $clientPfx"
Write-Host ''
Write-Host 'Useful next steps:' -ForegroundColor Yellow
Write-Host "  1. Import the root CA into Trusted Root Certification Authorities if needed."
Write-Host "  2. Start atoms-sim with .\start-local-pki.ps1 for the default local HTTPS + mTLS setup."
Write-Host "  3. In ANB Connect, choose ATOMS -> PKI Certificate -> PFX File and select $clientPfx."
Write-Host ''
Write-Host 'Thumbprints:' -ForegroundColor Green
Write-Host "  Root CA:     $($root.Thumbprint)"
Write-Host "  Server cert: $($server.Thumbprint)"
Write-Host "  Client cert: $($client.Thumbprint)"
