Set-StrictMode -Version Latest

function Get-SigningState
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path
    )

    foreach ($item in $Path)
    {
        $resolved = (Resolve-Path -LiteralPath $item -ErrorAction Stop).Path
        $signature = Get-AuthenticodeSignature -LiteralPath $resolved
        [PSCustomObject]@{
            Path = $resolved
            Status = $signature.Status.ToString()
            StatusMessage = $signature.StatusMessage
            SignerSubject = if ($null -eq $signature.SignerCertificate) { $null } else { $signature.SignerCertificate.Subject }
            SignerThumbprint = if ($null -eq $signature.SignerCertificate) { $null } else { $signature.SignerCertificate.Thumbprint }
            TimeStamperSubject = if ($null -eq $signature.TimeStamperCertificate) { $null } else { $signature.TimeStamperCertificate.Subject }
        }
    }
}

function Get-SigningPassword
{
    [CmdletBinding()]
    param(
        [SecureString]$Password,
        [string]$EnvironmentVariable = "WINCRED_SIGNING_CERT_PASSWORD"
    )

    if ($null -ne $Password)
    {
        return $Password
    }

    $fromEnvironment = [Environment]::GetEnvironmentVariable($EnvironmentVariable, "Process")
    if ([string]::IsNullOrEmpty($fromEnvironment))
    {
        $fromEnvironment = [Environment]::GetEnvironmentVariable($EnvironmentVariable, "User")
    }
    if ([string]::IsNullOrEmpty($fromEnvironment))
    {
        $fromEnvironment = [Environment]::GetEnvironmentVariable($EnvironmentVariable, "Machine")
    }
    if (![string]::IsNullOrEmpty($fromEnvironment))
    {
        $characters = $fromEnvironment.ToCharArray()
        try
        {
            $securePassword = [System.Security.SecureString]::new()
            foreach ($character in $characters)
            {
                $securePassword.AppendChar($character)
            }
            $securePassword.MakeReadOnly()
            return $securePassword
        }
        finally
        {
            [Array]::Clear($characters, 0, $characters.Length)
        }
    }

    return Read-Host "PFX password" -AsSecureString
}

function Resolve-CodeSigningCertificate
{
    [CmdletBinding(DefaultParameterSetName = "Thumbprint")]
    param(
        [Parameter(Mandatory, ParameterSetName = "Thumbprint")]
        [ValidatePattern("^[A-Fa-f0-9]{40}$")]
        [string]$CertificateThumbprint,
        [Parameter(Mandatory, ParameterSetName = "Pfx")]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$CertificatePath,
        [Parameter(ParameterSetName = "Pfx")]
        [SecureString]$CertificatePassword
    )

    $importedThumbprint = $null
    if ($PSCmdlet.ParameterSetName -eq "Pfx")
    {
        $existingThumbprints = @(
            foreach ($existingCertificate in Get-ChildItem -Path Cert:\CurrentUser\My)
            {
                $existingCertificate.Thumbprint
            }
        )
        $certificate = Import-PfxCertificate `
            -FilePath $CertificatePath `
            -CertStoreLocation Cert:\CurrentUser\My `
            -Password (Get-SigningPassword -Password $CertificatePassword)
        $certificate = @($certificate | Where-Object { $_.HasPrivateKey }) | Select-Object -First 1
        if ($null -eq $certificate)
        {
            throw "The PFX did not contain a certificate with a private key."
        }
        if ($certificate.Thumbprint -notin $existingThumbprints)
        {
            $importedThumbprint = $certificate.Thumbprint
        }
    }
    else
    {
        $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
    }

    if (!$certificate.HasPrivateKey)
    {
        throw "Certificate '$($certificate.Thumbprint)' has no private key."
    }
    $codeSigningUsage = [System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3").Value
    $enhancedKeyUsages = @(
        foreach ($usage in $certificate.EnhancedKeyUsageList)
        {
            [string]$usage.ObjectId
        }
    )
    if ($enhancedKeyUsages -notcontains $codeSigningUsage)
    {
        throw "Certificate '$($certificate.Thumbprint)' is not valid for code signing."
    }

    [PSCustomObject]@{
        Certificate = $certificate
        ImportedThumbprint = $importedThumbprint
    }
}

function Remove-ImportedSigningCertificate
{
    [CmdletBinding()]
    param([string]$Thumbprint)

    if (![string]::IsNullOrEmpty($Thumbprint))
    {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -Force -ErrorAction Stop
    }
}

function Assert-ReleaseSignature
{
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path)

    $invalid = @(Get-SigningState -Path $Path | Where-Object { $_.Status -ne "Valid" })
    if ($invalid.Count -gt 0)
    {
        $description = $invalid | ForEach-Object { "$($_.Path): $($_.Status) ($($_.StatusMessage))" }
        throw "Authenticode verification failed:`n$($description -join "`n")"
    }
}
