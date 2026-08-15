[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$Version,
    [string]$StageDirectory,
    [string]$OutputDirectory,
    [switch]$SkipBuild,
    [switch]$PrepareOnly,
    [switch]$UsePreparedStage,
    [switch]$Sign,
    [ValidatePattern("^[A-Fa-f0-9]{40}$")]
    [string]$CertificateThumbprint,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CertificatePath,
    [SecureString]$CertificatePassword,
    [ValidatePattern("^https?://")]
    [string]$TimestampUrl
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($Version))
{
    $Version = (Select-String -LiteralPath (Join-Path $repoRoot "Cargo.toml") -Pattern '^version = "([^"]+)"$').Matches[0].Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$')
{
    throw "MSI version '$Version' must have three or four numeric components."
}
if ([string]::IsNullOrEmpty($StageDirectory))
{
    $StageDirectory = Join-Path $repoRoot "packages\stage\$Configuration"
}
if ([string]::IsNullOrEmpty($OutputDirectory))
{
    $OutputDirectory = Join-Path $repoRoot "packages\$Configuration"
}
if ($Sign)
{
    if ([string]::IsNullOrEmpty($CertificateThumbprint) -eq [string]::IsNullOrEmpty($CertificatePath))
    {
        throw "Specify exactly one of -CertificateThumbprint or -CertificatePath with -Sign."
    }
}
if ($PrepareOnly -and $UsePreparedStage)
{
    throw "Specify either -PrepareOnly or -UsePreparedStage, not both."
}
if ($PrepareOnly -and $Sign)
{
    throw "-PrepareOnly cannot sign artifacts because it does not build the MSI."
}
if ($UsePreparedStage -and $Sign)
{
    throw "-UsePreparedStage cannot use -Sign; sign the staged payload and MSI externally."
}
if ($UsePreparedStage -and !$SkipBuild)
{
    throw "-UsePreparedStage requires -SkipBuild so it cannot rebuild inputs while reusing a staged package."
}

if (!$SkipBuild)
{
    & (Join-Path $PSScriptRoot "build.ps1") -Configuration $Configuration
    if ($LASTEXITCODE -ne 0)
    {
        throw "Build failed before MSI assembly."
    }
}

if (!$UsePreparedStage)
{
    & (Join-Path $PSScriptRoot "Assemble-Package.ps1") -Configuration $Configuration -OutputDirectory $StageDirectory -Prepare
}

function Invoke-PackageSigning
{
    param([Parameter(Mandatory)][string[]]$Path)
    $signingArguments = @{ Path = $Path }
    if (![string]::IsNullOrWhiteSpace($TimestampUrl))
    {
        $signingArguments.TimestampUrl = $TimestampUrl
    }
    if (![string]::IsNullOrEmpty($CertificatePath))
    {
        $signingArguments.CertificatePath = $CertificatePath
        $signingArguments.CertificatePassword = $CertificatePassword
    }
    else
    {
        $signingArguments.CertificateThumbprint = $CertificateThumbprint
    }
    & (Join-Path $PSScriptRoot "Sign-Release.ps1") @signingArguments
}

if ($Sign)
{
    Invoke-PackageSigning -Path @(
        (Join-Path $StageDirectory "windows\wincred-libsecret-wsl-plugin.dll"),
        (Join-Path $StageDirectory "windows\wincred-libsecret.exe"),
        (Join-Path $StageDirectory "windows\wincred-libsecret-broker.exe")
    )
}

if ($PrepareOnly)
{
    Write-Host "Prepared package stage: $StageDirectory"
    return
}

& (Join-Path $PSScriptRoot "Assemble-Package.ps1") -Configuration $Configuration -OutputDirectory $StageDirectory -Finalize

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
& dotnet tool restore
if ($LASTEXITCODE -ne 0)
{
    throw "Could not restore the pinned WiX tool manifest."
}

$wixProject = Join-Path $repoRoot "packaging\wix\WinCredLibsecret.wixproj"
& dotnet build $wixProject `
    --configuration Release `
    "--property:ProductVersion=$Version" `
    "--property:SourceDir=$([IO.Path]::GetFullPath($StageDirectory))" `
    "--property:OutputPath=$([IO.Path]::GetFullPath($OutputDirectory))"
if ($LASTEXITCODE -ne 0)
{
    throw "WiX MSI build failed."
}

$msi = Join-Path $OutputDirectory "wincred-libsecret-wsl-plugin.msi"
if (!(Test-Path -LiteralPath $msi -PathType Leaf))
{
    throw "WiX completed without creating '$msi'."
}
if ($Sign)
{
    Invoke-PackageSigning -Path $msi
}

$msiChecksum = "$(Get-FileHash -LiteralPath $msi -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLowerInvariant() }) *$([IO.Path]::GetFileName($msi))"
[IO.File]::WriteAllText((Join-Path $OutputDirectory "checksums.sha256"), "$msiChecksum`n", [Text.UTF8Encoding]::new($false))
Write-Host "Created MSI: $msi"
