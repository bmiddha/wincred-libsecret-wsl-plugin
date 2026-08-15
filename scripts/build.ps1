[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$WslDistribution = "Ubuntu-24.04",
    [switch]$SkipWindows,
    [switch]$SkipLinux,
    [switch]$Clean,
    [switch]$Package
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $repoRoot "artifacts\$Configuration"
. (Join-Path $PSScriptRoot "VisualStudio.ps1")

if ($Clean)
{
    Remove-Item -LiteralPath (Join-Path $repoRoot "build") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $repoRoot "target") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

if (!$SkipWindows)
{
    $installationPath = Import-VisualStudioEnvironment

    $cmake = Join-Path $installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (!(Test-Path -LiteralPath $cmake))
    {
        throw "Visual Studio CMake was not found at '$cmake'."
    }

    $ninjaDirectory = Join-Path $installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
    if (Test-Path -LiteralPath $ninjaDirectory)
    {
        $env:PATH = "$ninjaDirectory;$env:PATH"
    }

    $cargoArguments = @("build", "--locked", "--workspace", "--exclude", "wincred-libsecret-provider")
    if ($Configuration -eq "Release")
    {
        $cargoArguments += "--release"
    }

    & cargo @cargoArguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "The Windows Rust build failed."
    }

    & $cmake --preset windows-x64
    if ($LASTEXITCODE -ne 0)
    {
        throw "CMake configuration failed."
    }

    $buildPreset = "windows-x64-$($Configuration.ToLowerInvariant())"
    & $cmake --build --preset $buildPreset
    if ($LASTEXITCODE -ne 0)
    {
        throw "The C++ plugin build failed."
    }

    $cargoProfile = if ($Configuration -eq "Release") { "release" } else { "debug" }
    $windowsArtifactDirectory = Join-Path $artifactRoot "windows"
    New-Item -ItemType Directory -Path $windowsArtifactDirectory -Force | Out-Null
    Copy-Item (Join-Path $repoRoot "target\$cargoProfile\wincred-libsecret.exe") $windowsArtifactDirectory -Force
    Copy-Item (Join-Path $repoRoot "target\$cargoProfile\wincred-libsecret-broker.exe") $windowsArtifactDirectory -Force

    $symbolsArtifactDirectory = Join-Path $artifactRoot "symbols"
    New-Item -ItemType Directory -Path $symbolsArtifactDirectory -Force | Out-Null
    Copy-Item (Join-Path $repoRoot "target\$cargoProfile\wincred_libsecret.pdb") `
        (Join-Path $symbolsArtifactDirectory "wincred-libsecret.pdb") -Force
    Copy-Item (Join-Path $repoRoot "target\$cargoProfile\wincred_libsecret_broker.pdb") `
        (Join-Path $symbolsArtifactDirectory "wincred-libsecret-broker.pdb") -Force
}

if (!$SkipLinux)
{
    $linuxScript = Join-Path $repoRoot "scripts\build-linux.sh"
    $wslRepoRoot = (& wsl.exe -d $WslDistribution -- wslpath -a ($repoRoot -replace "\\", "/")).Trim()
    if (!$wslRepoRoot)
    {
        throw "Could not translate the repository path for WSL distribution '$WslDistribution'."
    }

    & wsl.exe -d $WslDistribution -- bash "$wslRepoRoot/scripts/build-linux.sh" $Configuration
    if ($LASTEXITCODE -ne 0)
    {
        throw "The Linux provider build failed."
    }
}

if ($Package)
{
    if ($SkipWindows -or $SkipLinux)
    {
        throw "-Package requires both Windows and Linux artifacts. Do not use it with -SkipWindows or -SkipLinux."
    }

    & (Join-Path $PSScriptRoot "package.ps1") -Configuration $Configuration -SkipBuild
    if ($LASTEXITCODE -ne 0)
    {
        throw "The MSI package build failed."
    }
}
