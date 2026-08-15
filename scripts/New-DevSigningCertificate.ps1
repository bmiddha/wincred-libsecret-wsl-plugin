[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 3650)]
    [int]$ValidityDays = 7,
    [ValidateSet("Development")]
    [string]$Purpose = "Development",
    [string]$StatePath,
    [switch]$TrustForCurrentUser,
    [switch]$TrustForLocalMachine,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string[]]$SignPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "Signing.Common.ps1")

$repoRoot = Split-Path -Parent $PSScriptRoot
$certificateName = "WinCred Libsecret development signing"
if ([string]::IsNullOrEmpty($StatePath))
{
    $StatePath = Join-Path $repoRoot "artifacts\dev-signing\certificate-state.json"
}
$stateDirectory = Split-Path -Parent $StatePath
$certificatePath = Join-Path $stateDirectory "wincred-libsecret-dev-signing.cer"

if ($TrustForCurrentUser -and $TrustForLocalMachine)
{
    throw "Specify either -TrustForCurrentUser or -TrustForLocalMachine, not both."
}
if (Test-Path -LiteralPath $StatePath)
{
    throw "Developer signing state already exists at '$StatePath'. Remove it with Remove-DevSigningCertificate.ps1 first."
}

$trustedStores = if ($TrustForLocalMachine)
{
    @("Cert:\LocalMachine\TrustedPublisher", "Cert:\LocalMachine\Root")
}
elseif ($TrustForCurrentUser)
{
    @("Cert:\CurrentUser\TrustedPublisher")
}
else
{
    @()
}

if ($WhatIfPreference)
{
    Write-Host "Would create a non-exportable, $ValidityDays-day $Purpose code-signing certificate in CurrentUser\My."
    foreach ($store in $trustedStores) { Write-Host "Would import its public certificate into $store." }
    return
}

New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$certificate = $null
try
{
    $certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$certificateName" `
    -FriendlyName $certificateName `
    -CertStoreLocation Cert:\CurrentUser\My `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).ToUniversalTime().AddDays($ValidityDays)

    Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null
    foreach ($store in $trustedStores)
    {
        try
        {
            Import-Certificate -FilePath $certificatePath -CertStoreLocation $store | Out-Null
        }
        catch
        {
            throw "Could not trust the public development certificate in $store. Run an elevated session if policy requires it: $($_.Exception.Message)"
        }
    }

    if ($SignPath)
    {
        foreach ($item in $SignPath)
        {
            $resolved = (Resolve-Path -LiteralPath $item -ErrorAction Stop).Path
            if ([IO.Path]::GetExtension($resolved).ToLowerInvariant() -notin ".dll", ".exe", ".msi")
            {
                throw "Refusing to sign unsupported artifact '$resolved'."
            }
            $result = Set-AuthenticodeSignature -LiteralPath $resolved -Certificate $certificate -HashAlgorithm SHA256
            $written = Get-AuthenticodeSignature -LiteralPath $resolved
            if ($null -eq $written.SignerCertificate -or
                !$written.SignerCertificate.Thumbprint.Equals($certificate.Thumbprint, [StringComparison]::OrdinalIgnoreCase))
            {
                throw "Signing '$resolved' did not write the expected development certificate: $($result.StatusMessage)"
            }
        }
    }

    $stateJson = [ordered]@{
        purpose = $Purpose
        thumbprint = $certificate.Thumbprint
        subject = $certificate.Subject
        certificatePath = $certificatePath
        trustedForCurrentUser = [bool]$TrustForCurrentUser
        trustedForLocalMachine = [bool]$TrustForLocalMachine
        trustedPublisherStore = if ($trustedStores.Count -eq 0) { $null } else { $trustedStores[0] }
        trustedStores = $trustedStores
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        expiresUtc = $certificate.NotAfter.ToUniversalTime().ToString("o")
    } | ConvertTo-Json
    [IO.File]::WriteAllText($StatePath, $stateJson, [Text.UTF8Encoding]::new($false))
    Write-Host "Created $Purpose signing certificate $($certificate.Thumbprint). State: $StatePath"
}
catch
{
    if ($null -ne $certificate)
    {
        foreach ($store in $trustedStores)
        {
            Remove-Item -LiteralPath "$store\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $certificatePath -Force -ErrorAction SilentlyContinue
    throw
}
