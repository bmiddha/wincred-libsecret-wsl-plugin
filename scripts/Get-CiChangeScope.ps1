[CmdletBinding()]
param(
    [string[]]$ChangedPath,
    [switch]$WriteGitHubOutput
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$nonBuildPathPatterns = @(
    '^(?:README|CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)\.md$',
    '^(?:LICENSE|NOTICE)(?:\.md)?$',
    '^docs/',
    '^assets/',
    '^(?:\.editorconfig|\.gitattributes|\.gitignore)$',
    '^\.config/cliff\.toml$',
    '^\.github/(?:ISSUE_TEMPLATE/|FUNDING\.yml$|dependabot\.yml$|CODEOWNERS$|labeler\.yml$)'
)

function Test-NonBuildPath
{
    param([Parameter(Mandatory)][string]$Path)

    $normalizedPath = $Path.Replace("\", "/").Trim()
    while ($normalizedPath.StartsWith("./", [StringComparison]::Ordinal))
    {
        $normalizedPath = $normalizedPath.Substring(2)
    }

    if ([string]::IsNullOrWhiteSpace($normalizedPath))
    {
        return $false
    }

    foreach ($pattern in $nonBuildPathPatterns)
    {
        if ([regex]::IsMatch(
            $normalizedPath,
            $pattern,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ))
        {
            return $true
        }
    }

    $false
}

function Get-PullRequestChangedPath
{
    if ([string]::IsNullOrWhiteSpace($env:GITHUB_EVENT_PATH))
    {
        throw "GITHUB_EVENT_PATH is required to classify a pull request."
    }

    $event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
    $baseSha = [string]$event.pull_request.base.sha
    $headSha = [string]$event.pull_request.head.sha
    if ([string]::IsNullOrWhiteSpace($baseSha) -or
        [string]::IsNullOrWhiteSpace($headSha))
    {
        throw "The pull request event does not contain base and head commit SHAs."
    }

    $paths = @(& git diff --name-only --no-renames $baseSha $headSha)
    if ($LASTEXITCODE -ne 0)
    {
        throw "Could not determine changed paths between '$baseSha' and '$headSha'."
    }

    @(
        $paths |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ }
    )
}

$isPullRequest = $env:GITHUB_EVENT_NAME -eq "pull_request"
[string[]]$paths = @(
    if ($PSBoundParameters.ContainsKey("ChangedPath"))
    {
        $ChangedPath
    }
    elseif ($isPullRequest)
    {
        Get-PullRequestChangedPath
    }
)

$requiresFullValidation = $true
if ($PSBoundParameters.ContainsKey("ChangedPath") -or $isPullRequest)
{
    [string[]]$buildRelevantPaths = @(
        $paths | Where-Object { !(Test-NonBuildPath -Path $_) }
    )
    $requiresFullValidation = $paths.Count -eq 0 -or $buildRelevantPaths.Count -gt 0
}

$result = [PSCustomObject]@{
    requires_full_validation = $requiresFullValidation.ToString().ToLowerInvariant()
}

if ($WriteGitHubOutput)
{
    if ([string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT))
    {
        throw "GITHUB_OUTPUT is required when -WriteGitHubOutput is specified."
    }

    Add-Content `
        -LiteralPath $env:GITHUB_OUTPUT `
        -Value "requires_full_validation=$($result.requires_full_validation)"
}

$result
