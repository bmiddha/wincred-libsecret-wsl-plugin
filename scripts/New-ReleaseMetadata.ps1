[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Utf8NoBom
{
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Get-Sha256
{
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
$cargoLock = Join-Path $repoRoot "Cargo.lock"
$metadata = & cargo metadata --locked --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0)
{
    throw "cargo metadata failed while generating the CycloneDX SBOM."
}

$components = @(
    $metadata.packages |
        Sort-Object name, version, source |
        ForEach-Object {
            $component = [ordered]@{
                type = "library"
                name = $_.name
                version = $_.version
                licenses = @(
                    [ordered]@{
                        license = [ordered]@{
                            id = if ([string]::IsNullOrWhiteSpace($_.license)) { "NOASSERTION" } else { $_.license }
                        }
                    }
                )
            }
            if (![string]::IsNullOrWhiteSpace($_.source))
            {
                $component.purl = "pkg:cargo/$($_.name)@$($_.version)"
                $component.externalReferences = @(
                    [ordered]@{
                        type = "distribution"
                        url = $_.source
                    }
                )
            }
            $component
        }
)
$sbom = [ordered]@{
    bomFormat = "CycloneDX"
    specVersion = "1.5"
    version = 1
    metadata = [ordered]@{
        component = [ordered]@{
            type = "application"
            name = "wincred-libsecret-wsl-plugin"
            version = ($metadata.packages | Where-Object { $_.name -eq "wincred-libsecret-protocol" } | Select-Object -First 1).version
            hashes = @(
                [ordered]@{
                    alg = "SHA-256"
                    content = Get-Sha256 $cargoLock
                }
            )
        }
    }
    components = $components
}
$sbomPath = Join-Path $output "sbom.cdx.json"
Write-Utf8NoBom -Path $sbomPath -Content (($sbom | ConvertTo-Json -Depth 8) + "`n")

$checksumPath = Join-Path $output "checksums.sha256"
$checksumLines = @(
    Get-ChildItem -LiteralPath $output -File |
        Where-Object { $_.FullName -ne $checksumPath } |
        Sort-Object Name |
        ForEach-Object { "$(Get-Sha256 $_.FullName) *$($_.Name)" }
)
Write-Utf8NoBom -Path $checksumPath -Content (($checksumLines -join "`n") + "`n")
Write-Host "Generated deterministic SBOM and checksums in $output"
