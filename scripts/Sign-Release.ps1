[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string[]]$Path,
    [Parameter(Mandatory, ParameterSetName = "Thumbprint")]
    [ValidatePattern("^[A-Fa-f0-9]{40}$")]
    [string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = "Pfx")]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CertificatePath,
    [Parameter(ParameterSetName = "Pfx")]
    [SecureString]$CertificatePassword,
    [ValidatePattern("^https?://")]
    [string]$TimestampUrl
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "Signing.Common.ps1")

$resolvedPaths = @(
    $Path | ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path } |
        Sort-Object -Unique
)
foreach ($item in $resolvedPaths)
{
    if ([IO.Path]::GetExtension($item).ToLowerInvariant() -notin ".dll", ".exe", ".msi")
    {
        throw "Refusing to sign unsupported artifact '$item'. Only DLL, EXE, and MSI files are accepted."
    }
}

if ($WhatIfPreference)
{
    $timestampDescription = if ([string]::IsNullOrWhiteSpace($TimestampUrl)) { "" } else { " and timestamp '$TimestampUrl'" }
    foreach ($item in $resolvedPaths)
    {
        $PSCmdlet.ShouldProcess($item, "Sign with SHA-256 Authenticode$timestampDescription") | Out-Null
    }
    return
}

if ($PSCmdlet.ParameterSetName -eq "Pfx")
{
    $resolvedCertificate = Resolve-CodeSigningCertificate `
        -CertificatePath $CertificatePath `
        -CertificatePassword (Get-SigningPassword -Password $CertificatePassword)
}
else
{
    $resolvedCertificate = Resolve-CodeSigningCertificate -CertificateThumbprint $CertificateThumbprint
}
try
{
    foreach ($item in $resolvedPaths)
    {
        $timestampDescription = if ([string]::IsNullOrWhiteSpace($TimestampUrl)) { "" } else { " and timestamp '$TimestampUrl'" }
        if ($PSCmdlet.ShouldProcess($item, "Sign with SHA-256 Authenticode$timestampDescription"))
        {
            $signingParameters = @{
                LiteralPath = $item
                Certificate = $resolvedCertificate.Certificate
                HashAlgorithm = "SHA256"
            }
            if (![string]::IsNullOrWhiteSpace($TimestampUrl))
            {
                $signingParameters.TimestampServer = $TimestampUrl
            }
            $result = Set-AuthenticodeSignature @signingParameters
            if ($result.Status -ne "Valid")
            {
                throw "Signing '$item' returned $($result.Status): $($result.StatusMessage)"
            }
        }
    }
    if (!$WhatIfPreference)
    {
        Assert-ReleaseSignature -Path $resolvedPaths
    }
}
finally
{
    Remove-ImportedSigningCertificate -Thumbprint $resolvedCertificate.ImportedThumbprint
}
