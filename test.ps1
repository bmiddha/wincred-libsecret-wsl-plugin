[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$WslDistribution = "Ubuntu-24.04",
    [switch]$RunLinux,
    [switch]$RunWinCredLive
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = $PSScriptRoot
. (Join-Path $repoRoot "scripts\VisualStudio.ps1")

& cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0)
{
    throw "cargo fmt check failed."
}

$installationPath = Import-VisualStudioEnvironment
& cargo check --locked --workspace --all-targets
if ($LASTEXITCODE -ne 0)
{
    throw "Windows Rust check failed."
}

& cargo test --locked --workspace --all-targets
if ($LASTEXITCODE -ne 0)
{
    throw "Windows Rust tests failed."
}

& cargo clippy --locked --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0)
{
    throw "Windows Rust clippy failed."
}

$cmake = Join-Path $installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if (!(Test-Path -LiteralPath $cmake))
{
    throw "Visual Studio CMake was not found at '$cmake'."
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
    throw "CMake build failed."
}
$ctest = Join-Path (Split-Path $cmake) "ctest.exe"
& $ctest --preset $buildPreset
if ($LASTEXITCODE -ne 0)
{
    throw "CTest failed."
}

if ($RunWinCredLive)
{
    $env:WINCRED_LIVE_TESTS = "1"
    & cargo test --locked -p wincred-libsecret-broker --test wincred_integration -- --ignored --test-threads=1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Live WinCred integration test failed."
    }
}

if ($RunLinux)
{
    $wslPath = (& wsl.exe -d $WslDistribution -- wslpath -a ($repoRoot -replace "\\", "/")).Trim()
    if (!$wslPath)
    {
        throw "Could not translate the repository path for WSL distribution '$WslDistribution'."
    }
    & wsl.exe -d $WslDistribution -- bash "$wslPath/scripts/test-linux.sh"
    if ($LASTEXITCODE -ne 0)
    {
        throw "Linux component tests failed."
    }
}
