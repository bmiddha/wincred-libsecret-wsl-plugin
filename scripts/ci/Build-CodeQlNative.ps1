[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

& cargo build --locked --workspace --exclude wincred-libsecret-provider
. .\scripts\VisualStudio.ps1
$installationPath = Import-VisualStudioEnvironment
$cmake = Join-Path $installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
& $cmake --preset windows-x64
if ($LASTEXITCODE -ne 0)
{
    throw "CMake configuration failed."
}
& $cmake --build --preset windows-x64-release
if ($LASTEXITCODE -ne 0)
{
    throw "Native build failed."
}
