[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$msi = Join-Path $PWD "packages\Release\wincred-libsecret-wsl-plugin.msi"
$signature = Get-AuthenticodeSignature -LiteralPath $msi
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
{
    throw "Azure Artifact Signing did not produce a valid MSI signature: $($signature.Status) ($($signature.StatusMessage))."
}
$certificate = $signature.SignerCertificate
if ($null -eq $certificate -or
    [string]::IsNullOrWhiteSpace($certificate.Subject) -or
    [string]::IsNullOrWhiteSpace($certificate.Issuer) -or
    $certificate.Thumbprint -notmatch "^[A-Fa-f0-9]{40}$")
{
    throw "Azure Artifact Signing did not expose complete signer metadata."
}
@"
Subject: $($certificate.Subject)
Issuer: $($certificate.Issuer)
Thumbprint: $($certificate.Thumbprint)
"@.Trim() | Set-Content -LiteralPath (Join-Path $PWD "packages\Release\wincred-libsecret-release-signing.txt") -Encoding ascii
