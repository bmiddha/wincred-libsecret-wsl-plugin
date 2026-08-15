[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$')]
    [string]$Repository,

    [Parameter(Mandatory)]
    [ValidatePattern('^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$')]
    [string]$Tag,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ReleaseSha
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN))
{
    throw "GH_TOKEN must contain a GitHub App installation token."
}

$referencePath = "repos/$Repository/git/matching-refs/tags/$Tag"
$referenceOutput = & gh api $referencePath
if ($LASTEXITCODE -ne 0)
{
    throw "Could not query the existing '$Tag' tag reference."
}
$references = @($referenceOutput | ConvertFrom-Json)
$matchingReferences = @(
    $references |
        Where-Object { $_.ref -eq "refs/tags/$Tag" }
)
if ($matchingReferences.Count -gt 1)
{
    throw "GitHub returned multiple references for '$Tag'."
}

if ($matchingReferences.Count -eq 1)
{
    $reference = $matchingReferences[0]
    switch ($reference.object.type)
    {
        "commit"
        {
            $taggedCommit = $reference.object.sha
            break
        }
        "tag"
        {
            $tagObjectOutput = & gh api "repos/$Repository/git/tags/$($reference.object.sha)"
            if ($LASTEXITCODE -ne 0)
            {
                throw "Could not resolve the existing '$Tag' tag object."
            }
            $tagObject = $tagObjectOutput | ConvertFrom-Json
            if ($tagObject.object.type -ne "commit")
            {
                throw "Existing '$Tag' does not reference a commit."
            }
            $taggedCommit = $tagObject.object.sha
            break
        }
        default
        {
            throw "Existing '$Tag' has unsupported reference type '$($reference.object.type)'."
        }
    }

    if (!$taggedCommit.Equals($ReleaseSha, [StringComparison]::OrdinalIgnoreCase))
    {
        throw "Release tag '$Tag' already points to '$taggedCommit', not the release commit."
    }
    Write-Host "Reusing existing release tag '$Tag'."
}
else
{
    $tagger = [ordered]@{
        name = "github-actions[bot]"
        email = "41898282+github-actions[bot]@users.noreply.github.com"
        date = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $tagRequest = [ordered]@{
        tag = $Tag
        message = "wincred-libsecret-wsl-plugin $Tag"
        object = $ReleaseSha
        type = "commit"
        tagger = $tagger
    } | ConvertTo-Json -Depth 3 -Compress
    $tagObjectOutput = $tagRequest |
        & gh api --method POST "repos/$Repository/git/tags" --input -
    if ($LASTEXITCODE -ne 0)
    {
        throw "Could not create the annotated '$Tag' tag object."
    }
    $tagObject = $tagObjectOutput | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($tagObject.sha))
    {
        throw "GitHub did not return an object ID for the '$Tag' tag."
    }

    $referenceRequest = [ordered]@{
        ref = "refs/tags/$Tag"
        sha = $tagObject.sha
    } | ConvertTo-Json -Compress
    $referenceRequest |
        & gh api --method POST "repos/$Repository/git/refs" --input - |
        Out-Null
    if ($LASTEXITCODE -ne 0)
    {
        throw "Could not create the '$Tag' tag reference."
    }
    Write-Host "Created annotated release tag '$Tag'."
}

& git fetch --force origin "refs/tags/${Tag}:refs/tags/$Tag"
if ($LASTEXITCODE -ne 0)
{
    throw "Could not fetch the '$Tag' tag into the release checkout."
}
$resolvedCommit = (& git rev-list -n 1 $Tag).Trim()
if (!$resolvedCommit.Equals($ReleaseSha, [StringComparison]::OrdinalIgnoreCase))
{
    throw "Fetched release tag '$Tag' points to '$resolvedCommit', not the release commit."
}
