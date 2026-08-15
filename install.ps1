[CmdletBinding()]
param(
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:Repository = "bmiddha/wincred-libsecret-wsl-plugin"
$script:GitHubApiHeaders = @{
    Accept = "application/vnd.github+json"
    "User-Agent" = "wincred-libsecret-wsl-plugin-installer"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$script:RequiredAssets = @(
    "wincred-libsecret-wsl-plugin.msi",
    "checksums.sha256",
    "wincred-libsecret-release-signing.txt"
)

function Assert-Administrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Get-Sha256
{
    param([Parameter(Mandatory)][string]$Path)

    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ReleaseAsset
{
    param(
        [Parameter(Mandatory)][object[]]$Assets,
        [Parameter(Mandatory)][string]$Name
    )

    $matches = @($Assets | Where-Object { $_.name -eq $Name })
    if ($matches.Count -ne 1)
    {
        throw "Release is missing exactly one required asset named '$Name'."
    }
    $matches[0]
}

function Invoke-GitHubRequest
{
    param([Parameter(Mandatory)][string]$Uri)

    try
    {
        Invoke-RestMethod -Uri $Uri -Headers $script:GitHubApiHeaders
    }
    catch
    {
        throw "Could not retrieve '$Uri'. The repository and selected release must be public: $($_.Exception.Message)"
    }
}

function Save-ReleaseAsset
{
    param(
        [Parameter(Mandatory)][object]$Asset,
        [Parameter(Mandatory)][string]$DestinationDirectory
    )

    $downloadUri = [Uri]$Asset.browser_download_url
    if ($downloadUri.Scheme -ne "https" -or $downloadUri.Host -notin "github.com", "objects.githubusercontent.com")
    {
        throw "Release asset '$($Asset.name)' does not have an expected GitHub HTTPS download URL."
    }

    $destination = Join-Path $DestinationDirectory $Asset.name
    try
    {
        Invoke-WebRequest -Uri $downloadUri -Headers $script:GitHubApiHeaders -OutFile $destination
    }
    catch
    {
        throw "Could not download release asset '$($Asset.name)': $($_.Exception.Message)"
    }

    $destination
}

function Assert-GitHubAssetDigest
{
    param(
        [Parameter(Mandatory)][object]$Asset,
        [Parameter(Mandatory)][string]$Path
    )

    $digestProperty = $Asset.PSObject.Properties["digest"]
    $digest = if ($null -eq $digestProperty) { $null } else { [string]$digestProperty.Value }
    if ($digest -notmatch "^sha256:([A-Fa-f0-9]{64})$")
    {
        throw "GitHub did not provide a SHA-256 digest for release asset '$($Asset.name)'."
    }
    $expected = $Matches[1]

    $actual = Get-Sha256 -Path $Path
    if (!$actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase))
    {
        throw "GitHub asset digest mismatch for '$($Asset.name)'."
    }
}

function Get-Checksums
{
    param([Parameter(Mandatory)][string]$Path)

    $checksums = @{}
    foreach ($line in Get-Content -LiteralPath $Path)
    {
        if ([string]::IsNullOrWhiteSpace($line))
        {
            continue
        }
        if ($line -notmatch "^(?<hash>[A-Fa-f0-9]{64}) \*(?<name>[^\\/]+)$")
        {
            throw "Invalid checksum entry: '$line'."
        }
        if ($checksums.ContainsKey($Matches.name))
        {
            throw "Duplicate checksum entry for '$($Matches.name)'."
        }
        $checksums.Add($Matches.name, $Matches.hash.ToLowerInvariant())
    }

    $checksums
}

function Assert-Checksum
{
    param(
        [Parameter(Mandatory)][hashtable]$Checksums,
        [Parameter(Mandatory)][string]$Path
    )

    $name = Split-Path -Leaf $Path
    if (!$Checksums.ContainsKey($name))
    {
        throw "checksums.sha256 has no entry for '$name'."
    }

    $actual = Get-Sha256 -Path $Path
    if ($actual -ne $Checksums[$name])
    {
        throw "Checksum mismatch for '$name'."
    }
}

function Get-ReleaseSigningMetadata
{
    param([Parameter(Mandatory)][string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw
    $metadata = @{}
    foreach ($field in @(
        @{ Name = "Subject"; Pattern = "(?m)^Subject: (.+?)\r?$" },
        @{ Name = "Issuer"; Pattern = "(?m)^Issuer: (.+?)\r?$" },
        @{ Name = "Thumbprint"; Pattern = "(?m)^Thumbprint: ([A-Fa-f0-9]{40})\r?$" }
    ))
    {
        $matches = [regex]::Matches($content, $field.Pattern)
        if ($matches.Count -ne 1)
        {
            throw "Release signing metadata is missing an unambiguous '$($field.Name)' field."
        }
        $metadata[$field.Name] = $matches[0].Groups[1].Value
    }

    $metadata
}

function Assert-MsiSignature
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$ExpectedSigner
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
    {
        throw "MSI Authenticode validation failed: $($signature.Status) ($($signature.StatusMessage))."
    }
    $certificate = $signature.SignerCertificate
    if ($null -eq $certificate)
    {
        throw "MSI signature does not contain a signer certificate."
    }
    if (!$certificate.Thumbprint.Equals($ExpectedSigner.Thumbprint, [StringComparison]::OrdinalIgnoreCase) -or
        $certificate.Subject -ne $ExpectedSigner.Subject -or
        $certificate.Issuer -ne $ExpectedSigner.Issuer)
    {
        throw "MSI signer does not match the published release signing metadata."
    }
}

Assert-Administrator

if ([string]::IsNullOrWhiteSpace($Version))
{
    throw "Version must be 'latest' or a release version such as 'v0.1.0'."
}
$requestedVersion = $Version.Trim()
$releaseUri = if ($requestedVersion.Equals("latest", [StringComparison]::OrdinalIgnoreCase))
{
    "https://api.github.com/repos/$script:Repository/releases/latest"
}
else
{
    $tag = if ($requestedVersion.StartsWith("v", [StringComparison]::OrdinalIgnoreCase))
    {
        $requestedVersion
    }
    else
    {
        "v$requestedVersion"
    }
    "https://api.github.com/repos/$script:Repository/releases/tags/$([Uri]::EscapeDataString($tag))"
}

$release = Invoke-GitHubRequest -Uri $releaseUri
if ([bool]$release.draft)
{
    throw "Refusing to install a draft release."
}
if ([string]::IsNullOrWhiteSpace($release.tag_name))
{
    throw "GitHub did not return a release tag."
}

$assets = @($release.assets)
$selectedAssets = @{}
foreach ($name in $script:RequiredAssets)
{
    $selectedAssets[$name] = Get-ReleaseAsset -Assets $assets -Name $name
}

$downloadDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    "WinCredLibsecret-$($release.tag_name)-$([Guid]::NewGuid().ToString('N'))"
)
New-Item -ItemType Directory -Path $downloadDirectory | Out-Null

try
{
    $downloaded = @{}
    foreach ($name in $script:RequiredAssets)
    {
        $asset = $selectedAssets[$name]
        $downloaded[$name] = Save-ReleaseAsset -Asset $asset -DestinationDirectory $downloadDirectory
        Assert-GitHubAssetDigest -Asset $asset -Path $downloaded[$name]
    }

    $checksums = Get-Checksums -Path $downloaded["checksums.sha256"]
    foreach ($name in @(
        "wincred-libsecret-wsl-plugin.msi",
        "wincred-libsecret-release-signing.txt"
    ))
    {
        Assert-Checksum -Checksums $checksums -Path $downloaded[$name]
    }

    $metadata = Get-ReleaseSigningMetadata -Path $downloaded["wincred-libsecret-release-signing.txt"]
    Assert-MsiSignature -Path $downloaded["wincred-libsecret-wsl-plugin.msi"] -ExpectedSigner $metadata

    $installer = Start-Process `
        -FilePath "msiexec.exe" `
        -ArgumentList @("/i", "`"$($downloaded["wincred-libsecret-wsl-plugin.msi"])`"", "/qn", "/norestart") `
        -Wait `
        -PassThru
    if ($installer.ExitCode -notin 0, 3010)
    {
        throw "MSI installation failed with exit code $($installer.ExitCode)."
    }

    Write-Host "Installed WinCred Libsecret WSL Plugin $($release.tag_name)."
    if ($installer.ExitCode -eq 3010)
    {
        Write-Warning "Windows requested a restart to complete installation."
    }
    Write-Host "Enable a distribution with:"
    Write-Host "  & `"$env:ProgramFiles\WinCredLibsecret\wincred-libsecret.exe`" distro enable <distro-name>"
}
finally
{
    if (Test-Path -LiteralPath $downloadDirectory)
    {
        Remove-Item -LiteralPath $downloadDirectory -Recurse -Force
    }
}
