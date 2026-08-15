[CmdletBinding(SupportsShouldProcess)]
param([string]$StatePath)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($StatePath))
{
    $StatePath = Join-Path $repoRoot "artifacts\dev-signing\certificate-state.json"
}
if (!(Test-Path -LiteralPath $StatePath))
{
    Write-Host "No development signing state exists at '$StatePath'."
    return
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$knownSubjects = @(
    "CN=WinCred Libsecret development signing",
    "CN=WinCred Libsecret release signing"
)
if ($state.subject -notin $knownSubjects -or
    $state.thumbprint -notmatch "^[A-Fa-f0-9]{40}$")
{
    throw "Refusing to remove a certificate not created by New-DevSigningCertificate.ps1."
}

$trustedStores = @()
$trustedStoresProperty = $state.PSObject.Properties["trustedStores"]
if ($null -ne $trustedStoresProperty)
{
    $trustedStores = @($trustedStoresProperty.Value | Where-Object { ![string]::IsNullOrWhiteSpace([string]$_) })
}
else
{
    $trustedPublisherStoreProperty = $state.PSObject.Properties["trustedPublisherStore"]
    if ($null -ne $trustedPublisherStoreProperty -and ![string]::IsNullOrWhiteSpace([string]$trustedPublisherStoreProperty.Value))
    {
        $trustedStores = @([string]$trustedPublisherStoreProperty.Value)
    }
    elseif ($state.PSObject.Properties["trustedForCurrentUser"] -and [bool]$state.trustedForCurrentUser)
    {
        $trustedStores = @("Cert:\CurrentUser\TrustedPublisher")
    }
}

foreach ($store in $trustedStores)
{
    $path = "$store\$($state.thumbprint)"
    if (Test-Path -LiteralPath $path)
    {
        if ($PSCmdlet.ShouldProcess($path, "Remove development signing certificate"))
        {
            Remove-Item -LiteralPath $path -Force
        }
    }
}
$privateKeyPath = "Cert:\CurrentUser\My\$($state.thumbprint)"
if (Test-Path -LiteralPath $privateKeyPath)
{
    if ($PSCmdlet.ShouldProcess($privateKeyPath, "Remove development signing certificate"))
    {
        Remove-Item -LiteralPath $privateKeyPath -Force
    }
}
if ($PSCmdlet.ShouldProcess($StatePath, "Remove development signing state and public certificate"))
{
    Remove-Item -LiteralPath $state.certificatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StatePath -Force
}
