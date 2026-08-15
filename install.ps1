[CmdletBinding()]
param(
    [string]$Version = "latest",
    [switch]$IncludePrerelease,
    [switch]$ElevatedInstall,
    [int]$WaitForProcessId = 0,
    [string]$UninstallProductCode
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

function Test-Administrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProgramFilesDirectory
{
    $baseKey = $null
    $currentVersion = $null
    try
    {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $currentVersion = $baseKey.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion", $false)
        if ($null -eq $currentVersion)
        {
            throw "Windows did not provide the Program Files registry key."
        }
        $directory = $currentVersion.GetValue(
            "ProgramFilesDir",
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($directory -isnot [string] -or
            [string]::IsNullOrWhiteSpace($directory) -or
            ![IO.Path]::IsPathRooted($directory) -or
            $directory.Contains("%"))
        {
            throw "Windows did not provide an absolute Program Files directory."
        }
        $directory
    }
    finally
    {
        if ($null -ne $currentVersion) { $currentVersion.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

$script:ProgramFilesDirectory = Get-ProgramFilesDirectory

function Invoke-ElevatedInstaller
{
    param([Parameter(Mandatory)][string]$RequestedVersion, [switch]$IncludePrerelease)

    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "`"$PSCommandPath`"",
        "-Version",
        $RequestedVersion,
        "-ElevatedInstall"
    )
    if ($IncludePrerelease)
    {
        $arguments += "-IncludePrerelease"
    }
    $process = Start-Process `
        -FilePath (Join-Path $PSHOME "powershell.exe") `
        -Verb RunAs `
        -ArgumentList $arguments `
        -Wait `
        -PassThru
    if ($process.ExitCode -notin 0, 3010)
    {
        throw "Elevated MSI installation failed with exit code $($process.ExitCode)."
    }
    $process.ExitCode
}

function Wait-InitiatingProcess
{
    param([int]$ProcessId)

    if ($ProcessId -lt 0)
    {
        throw "WaitForProcessId must be a non-negative process ID."
    }
    if ($ProcessId -gt 0)
    {
        $initiatingProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -ne $initiatingProcess)
        {
            Wait-Process -InputObject $initiatingProcess
        }
    }
}

function Invoke-ElevatedUninstaller
{
    param([Parameter(Mandatory)][string]$ProductCode)

    $msiExec = Join-Path ([Environment]::SystemDirectory) "msiexec.exe"
    $process = Start-Process `
        -FilePath $msiExec `
        -Verb RunAs `
        -ArgumentList @("/x", $ProductCode, "/qn", "/norestart") `
        -Wait `
        -PassThru
    if ($process.ExitCode -notin 0, 1605, 3010)
    {
        throw "MSI uninstall failed with exit code $($process.ExitCode)."
    }
    if ($process.ExitCode -eq 3010)
    {
        Write-Warning "Windows requested a restart to complete uninstallation."
    }
}

function Invoke-DistroRefresh
{
    $installedCli = Join-Path $script:ProgramFilesDirectory "WinCredLibsecret\wincred-libsecret.exe"
    if (!(Test-Path -LiteralPath $installedCli -PathType Leaf))
    {
        throw "MSI installation completed but the installed CLI is missing: '$installedCli'."
    }
    & $installedCli distro refresh --all
    if ($LASTEXITCODE -ne 0)
    {
        throw "MSI installation completed, but enabled WSL distributions could not be refreshed and validated."
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

function ConvertTo-SemanticVersion
{
    param([Parameter(Mandatory)][string]$Tag)

    $match = [regex]::Match(
        $Tag,
        '^[vV]?(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
    )
    if (!$match.Success)
    {
        return $null
    }
    [UInt64]$major = 0
    [UInt64]$minor = 0
    [UInt64]$patch = 0
    if (![UInt64]::TryParse($match.Groups["major"].Value, [ref]$major) -or
        ![UInt64]::TryParse($match.Groups["minor"].Value, [ref]$minor) -or
        ![UInt64]::TryParse($match.Groups["patch"].Value, [ref]$patch))
    {
        return $null
    }
    $prerelease = if ($match.Groups["prerelease"].Success)
    {
        $match.Groups["prerelease"].Value
    }
    else
    {
        $null
    }
    if ($null -ne $prerelease)
    {
        foreach ($identifier in $prerelease.Split("."))
        {
            if ($identifier -match '^\d+$' -and $identifier.Length -gt 1 -and $identifier.StartsWith("0"))
            {
                return $null
            }
        }
    }
    [PSCustomObject]@{
        Major = $major
        Minor = $minor
        Patch = $patch
        Prerelease = $prerelease
    }
}

function Compare-SemanticVersion
{
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    foreach ($component in @("Major", "Minor", "Patch"))
    {
        $comparison = $Left.$component.CompareTo($Right.$component)
        if ($comparison -ne 0)
        {
            return $comparison
        }
    }
    if ($null -eq $Left.Prerelease)
    {
        if ($null -eq $Right.Prerelease) { return 0 }
        return 1
    }
    if ($null -eq $Right.Prerelease)
    {
        return -1
    }

    $leftIdentifiers = $Left.Prerelease.Split(".")
    $rightIdentifiers = $Right.Prerelease.Split(".")
    $count = [Math]::Min($leftIdentifiers.Count, $rightIdentifiers.Count)
    for ($index = 0; $index -lt $count; $index++)
    {
        $leftIdentifier = $leftIdentifiers[$index]
        $rightIdentifier = $rightIdentifiers[$index]
        $leftNumeric = $leftIdentifier -match '^\d+$'
        $rightNumeric = $rightIdentifier -match '^\d+$'
        if ($leftNumeric -and $rightNumeric)
        {
            $comparison = $leftIdentifier.Length.CompareTo($rightIdentifier.Length)
            if ($comparison -eq 0)
            {
                $comparison = [string]::CompareOrdinal($leftIdentifier, $rightIdentifier)
            }
        }
        elseif ($leftNumeric)
        {
            $comparison = -1
        }
        elseif ($rightNumeric)
        {
            $comparison = 1
        }
        else
        {
            $comparison = [string]::CompareOrdinal($leftIdentifier, $rightIdentifier)
        }
        if ($comparison -ne 0)
        {
            return $comparison
        }
    }
    $leftIdentifiers.Count.CompareTo($rightIdentifiers.Count)
}

function Select-NewestPublicRelease
{
    param([Parameter(Mandatory)][object[]]$Releases)

    $selected = $null
    $selectedVersion = $null
    foreach ($release in $Releases)
    {
        if ([bool]$release.draft)
        {
            continue
        }
        $version = ConvertTo-SemanticVersion -Tag ([string]$release.tag_name)
        if ($null -eq $version)
        {
            continue
        }
        if ($null -eq $selectedVersion -or (Compare-SemanticVersion -Left $version -Right $selectedVersion) -gt 0)
        {
            $selected = $release
            $selectedVersion = $version
        }
    }
    if ($null -eq $selected)
    {
        throw "GitHub did not return a public stable or prerelease semantic-version release."
    }
    $selected
}

if (![string]::IsNullOrWhiteSpace($UninstallProductCode))
{
    if ($UninstallProductCode -notmatch '^\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$')
    {
        throw "UninstallProductCode must be a Windows Installer product GUID."
    }
    if (Test-Administrator)
    {
        throw "Run the uninstall command from a non-elevated PowerShell session. It requests elevation only for MSI removal after WSL cleanup."
    }
    Wait-InitiatingProcess -ProcessId $WaitForProcessId
    Invoke-ElevatedUninstaller -ProductCode $UninstallProductCode
    Write-Host "Uninstalled WinCred Libsecret WSL Plugin. The Windows Credential Manager vault was preserved."
    return
}

if ([string]::IsNullOrWhiteSpace($Version))
{
    throw "Version must be 'latest' or a release version such as 'v0.1.0'."
}
$requestedVersion = $Version.Trim()
if ($requestedVersion -notmatch '^(?i:latest)$|^[vV]?\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$')
{
    throw "Version must be 'latest' or a semantic release version such as 'v0.1.0', 'v0.2.0-rc.1', or 'v0.2.0+build.1'."
}
if (!(Test-Administrator))
{
    Wait-InitiatingProcess -ProcessId $WaitForProcessId
    $installerExitCode = Invoke-ElevatedInstaller `
        -RequestedVersion $requestedVersion `
        -IncludePrerelease:$IncludePrerelease
    Invoke-DistroRefresh
    Write-Host "Installed WinCred Libsecret WSL Plugin $requestedVersion and refreshed enabled WSL distributions."
    if ($installerExitCode -eq 3010)
    {
        Write-Warning "Windows requested a restart to complete installation."
    }
    Write-Host "Enable a distribution with:"
    Write-Host "  & `"$script:ProgramFilesDirectory\WinCredLibsecret\wincred-libsecret.exe`" distro enable <distro-name>"
    return
}
if (!$ElevatedInstall)
{
    throw "Run the installer from a non-elevated PowerShell session. It requests elevation only for MSI installation, then safely refreshes WSL distributions without elevation."
}

$release = if ($requestedVersion.Equals("latest", [StringComparison]::OrdinalIgnoreCase))
{
    if ($IncludePrerelease)
    {
        $releases = @(Invoke-GitHubRequest -Uri "https://api.github.com/repos/$script:Repository/releases?per_page=100")
        Select-NewestPublicRelease -Releases $releases
    }
    else
    {
        Invoke-GitHubRequest -Uri "https://api.github.com/repos/$script:Repository/releases/latest"
    }
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
    Invoke-GitHubRequest -Uri "https://api.github.com/repos/$script:Repository/releases/tags/$([Uri]::EscapeDataString($tag))"
}
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

$installerCache = Join-Path $script:ProgramFilesDirectory "WinCredLibsecret\installer-cache"
New-Item -ItemType Directory -Path $installerCache -Force | Out-Null
if ((Get-Item -LiteralPath $installerCache -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
{
    throw "Refusing reparse-point installer cache '$installerCache'."
}
$downloadDirectory = Join-Path $installerCache (
    "WinCredLibsecret-$($release.tag_name)-$([Guid]::NewGuid().ToString('N'))"
)
New-Item -ItemType Directory -Path $downloadDirectory | Out-Null

$installerExitCode = $null
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
        -FilePath (Join-Path ([Environment]::SystemDirectory) "msiexec.exe") `
        -ArgumentList @("/i", "`"$($downloaded["wincred-libsecret-wsl-plugin.msi"])`"", "/qn", "/norestart") `
        -Wait `
        -PassThru
    if ($installer.ExitCode -notin 0, 3010)
    {
        throw "MSI installation failed with exit code $($installer.ExitCode)."
    }
    $installerExitCode = $installer.ExitCode

}
finally
{
    if (Test-Path -LiteralPath $downloadDirectory)
    {
        Remove-Item -LiteralPath $downloadDirectory -Recurse -Force
    }
    if ((Test-Path -LiteralPath $installerCache -PathType Container) -and
        @(
            Get-ChildItem -LiteralPath $installerCache -Force
        ).Count -eq 0)
    {
        Remove-Item -LiteralPath $installerCache -Force
    }
}
exit $installerExitCode
