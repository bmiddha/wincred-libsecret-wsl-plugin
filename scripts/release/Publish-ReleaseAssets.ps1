[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$assets = @(Get-ChildItem -LiteralPath .\packages\Release -File | ForEach-Object FullName)
if ($assets.Count -eq 0)
{
    throw "No release assets were generated."
}
$existingRelease = @(
    & gh release list --limit 1000 --json tagName,isPrerelease --repo $env:GITHUB_REPOSITORY |
        ConvertFrom-Json |
        Where-Object { $_.tagName -eq $env:TAG }
)
if ($existingRelease.Count -gt 0)
{
    $expectedPrerelease = $env:PRERELEASE -eq "true"
    if ([bool]$existingRelease[0].isPrerelease -ne $expectedPrerelease)
    {
        throw "Existing release '$env:TAG' has an unexpected prerelease state."
    }
    & gh release upload $env:TAG @assets --clobber --repo $env:GITHUB_REPOSITORY
}
else
{
    $arguments = @(
        "release", "create", $env:TAG
    ) + $assets + @(
        "--verify-tag",
        "--title", "WinCred Libsecret WSL Plugin $env:TAG",
        "--notes-file", $env:RELEASE_NOTES_PATH,
        "--repo", $env:GITHUB_REPOSITORY
    )
    if ($env:PRERELEASE -eq "true")
    {
        $arguments += "--prerelease"
    }
    & gh @arguments
}
if ($LASTEXITCODE -ne 0)
{
    throw "Could not publish release '$env:TAG'."
}
