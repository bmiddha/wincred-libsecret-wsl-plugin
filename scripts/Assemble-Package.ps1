[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory,
    [switch]$Prepare,
    [switch]$Finalize
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Utf8NoBom
{
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Get-RelativePackagePath
{
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$Path)
    [IO.Path]::GetRelativePath($BasePath, $Path).Replace("\", "/")
}

function Get-Sha256
{
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $repoRoot "artifacts\$Configuration"
if ([string]::IsNullOrEmpty($OutputDirectory))
{
    $OutputDirectory = Join-Path $repoRoot "packages\stage\$Configuration"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

if (!$Prepare -and !$Finalize)
{
    $Prepare = $true
    $Finalize = $true
}

if ($Prepare)
{
    if (!(Test-Path -LiteralPath $artifactRoot -PathType Container))
    {
        throw "Build artifacts are missing at '$artifactRoot'. Run scripts\build.ps1 first."
    }

    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $files = @(
        @{ Source = "windows\wincred-libsecret-wsl-plugin.dll"; Destination = "windows\wincred-libsecret-wsl-plugin.dll" },
        @{ Source = "windows\wincred-libsecret.exe"; Destination = "windows\wincred-libsecret.exe" },
        @{ Source = "windows\wincred-libsecret-broker.exe"; Destination = "windows\wincred-libsecret-broker.exe" },
        @{ Source = "symbols\wincred-libsecret-wsl-plugin.pdb"; Destination = "symbols\wincred-libsecret-wsl-plugin.pdb" },
        @{ Source = "symbols\wincred-libsecret.pdb"; Destination = "symbols\wincred-libsecret.pdb" },
        @{ Source = "symbols\wincred-libsecret-broker.pdb"; Destination = "symbols\wincred-libsecret-broker.pdb" },
        @{ Source = "linux\wincred-libsecret-provider"; Destination = "linux\wincred-libsecret-provider" },
        @{ Source = "linux\wincred-libsecret-bootstrap.sh"; Destination = "linux\wincred-libsecret-bootstrap.sh" },
        @{ Source = "linux\org.freedesktop.secrets.service"; Destination = "linux\org.freedesktop.secrets.service" },
        @{ Source = "linux\wincred-libsecret.service"; Destination = "linux\wincred-libsecret.service" },
        @{ Source = "linux\wincred-libsecret-refresh.service"; Destination = "linux\wincred-libsecret-refresh.service" },
        @{ Source = "linux\wincred-libsecret-interop.service"; Destination = "linux\wincred-libsecret-interop.service" },
        @{ Source = "linux\manifest.sha256"; Destination = "linux\manifest.sha256" },
        @{ Source = "..\LICENSE"; Destination = "licenses\LICENSE.txt" },
        @{ Source = "..\packaging\NOTICE.txt"; Destination = "licenses\NOTICE.txt" }
    )
    foreach ($file in $files)
    {
        $source = if ($file.Source.StartsWith(".."))
        {
            Join-Path $repoRoot $file.Source.Substring(3)
        }
        else
        {
            Join-Path $artifactRoot $file.Source
        }
        if (!(Test-Path -LiteralPath $source -PathType Leaf))
        {
            throw "Required package input is missing: '$source'."
        }
        $destination = Join-Path $OutputDirectory $file.Destination
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
}

if ($Finalize)
{
    if (!(Test-Path -LiteralPath $OutputDirectory -PathType Container))
    {
        throw "Package stage '$OutputDirectory' is absent. Run with -Prepare before -Finalize."
    }

    $metadataDirectory = Join-Path $OutputDirectory "metadata"
    New-Item -ItemType Directory -Path $metadataDirectory -Force | Out-Null
    $cargoMetadata = & cargo metadata `
        --manifest-path (Join-Path $repoRoot "Cargo.toml") `
        --format-version 1 `
        --locked | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0)
    {
        throw "cargo metadata failed while generating dependency metadata."
    }
    $dependencyPackages = @(
        $cargoMetadata.packages |
            ForEach-Object {
                [ordered]@{
                    name = $_.name
                    version = $_.version
                    license = if ([string]::IsNullOrEmpty($_.license)) { "NOASSERTION" } else { $_.license }
                    source = if ([string]::IsNullOrEmpty($_.source)) { "workspace" } else { $_.source }
                }
            } |
            Sort-Object name, version, source
    )
    $dependencyMetadata = [ordered]@{
        format = "wincred-libsecret dependency metadata v1"
        cargoLockSha256 = Get-Sha256 (Join-Path $repoRoot "Cargo.lock")
        packages = $dependencyPackages
    }
    $dependencyPath = Join-Path $metadataDirectory "dependency-metadata.json"
    Write-Utf8NoBom -Path $dependencyPath -Content (($dependencyMetadata | ConvertTo-Json -Depth 5) + "`n")

    $versionMatch = Select-String -LiteralPath (Join-Path $repoRoot "Cargo.toml") -Pattern '^version = "([^"]+)"$'
    $version = $versionMatch.Matches[0].Groups[1].Value
    if ([string]::IsNullOrEmpty($version))
    {
        throw "Could not determine the workspace version from Cargo.toml."
    }
    $versionManifestPath = Join-Path $metadataDirectory "version-manifest.json"
    $checksumsPath = Join-Path $metadataDirectory "checksums.sha256"
    Remove-Item -LiteralPath $versionManifestPath, $checksumsPath -Force -ErrorAction SilentlyContinue
    $manifestFiles = @(
        Get-ChildItem -LiteralPath $OutputDirectory -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = Get-RelativePackagePath -BasePath $OutputDirectory -Path $_.FullName
                    sha256 = Get-Sha256 $_.FullName
                    size = $_.Length
                }
            }
    )
    $versionManifest = [ordered]@{
        format = "wincred-libsecret version manifest v1"
        version = $version
        configuration = $Configuration
        files = $manifestFiles
    }
    Write-Utf8NoBom -Path $versionManifestPath -Content (($versionManifest | ConvertTo-Json -Depth 5) + "`n")

    $checksumLines = @(
        Get-ChildItem -LiteralPath $OutputDirectory -Recurse -File |
            Where-Object { $_.FullName -ne $checksumsPath } |
            Sort-Object FullName |
            ForEach-Object {
                "$(Get-Sha256 $_.FullName) *$(Get-RelativePackagePath -BasePath $OutputDirectory -Path $_.FullName)"
            }
    )
    Write-Utf8NoBom -Path $checksumsPath -Content (($checksumLines -join "`n") + "`n")
    Write-Host "Assembled deterministic package stage: $OutputDirectory"
}
