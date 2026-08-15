[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$existing = @(& git tag --list $env:TAG)
if ($existing -contains $env:TAG)
{
    $tagCommit = (& git rev-list -n 1 $env:TAG).Trim()
    if ($tagCommit -ne $env:RELEASE_SHA)
    {
        throw "Release tag '$env:TAG' already points to '$tagCommit', not the release commit."
    }
    Write-Host "Reusing existing release tag '$env:TAG'."
    exit 0
}
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
& git tag -a $env:TAG $env:RELEASE_SHA -m "wincred-libsecret-wsl-plugin $env:TAG"
if ($LASTEXITCODE -ne 0)
{
    throw "Could not create release tag '$env:TAG'."
}
& git push origin "refs/tags/$env:TAG"
if ($LASTEXITCODE -ne 0)
{
    throw "Could not push release tag '$env:TAG'."
}
