[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$manifest = Get-Content -LiteralPath Cargo.toml -Raw
$workspacePackage = [regex]::Match(
    $manifest,
    '(?ms)^\[workspace\.package\]\r?\n(?<body>.*?)(?=^\[|\z)'
)
$packageVersion = [regex]::Match(
    $workspacePackage.Groups['body'].Value,
    '(?m)^version\s*=\s*"(?<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"\s*$'
)
if (!$workspacePackage.Success -or !$packageVersion.Success)
{
    throw "Cargo.toml is missing a three-part [workspace.package] version."
}
$tag = "v$($packageVersion.Groups['version'].Value)"
& git fetch --tags --force
if ($LASTEXITCODE -ne 0)
{
    throw "Could not fetch release tags."
}
$existing = @(& git tag --list $tag)
if ($existing -contains $tag)
{
    $tagCommit = (& git rev-list -n 1 $tag).Trim()
    if ($tagCommit -ne $env:RELEASE_SHA)
    {
        throw "Release tag '$tag' already points to '$tagCommit', not the release commit."
    }
}
"tag=$tag" >> $env:GITHUB_OUTPUT
