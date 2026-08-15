[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scopeScript = Join-Path $PSScriptRoot "Get-CiChangeScope.ps1"
$repositoryRoot = Split-Path -Parent $PSScriptRoot

function Assert-True
{
    param([bool]$Condition, [string]$Message)

    if (!$Condition)
    {
        throw $Message
    }
}

function Assert-ValidationScope
{
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ChangedPath,
        [Parameter(Mandatory)][string]$Expected
    )

    $result = & $scopeScript -ChangedPath $ChangedPath
    if ($result.requires_full_validation -ne $Expected)
    {
        throw "$Name expected requires_full_validation=$Expected, received $($result.requires_full_validation)."
    }
}

Assert-ValidationScope `
    -Name "Documentation and metadata changes" `
    -ChangedPath @(
        "README.md",
        "CHANGELOG.md",
        "docs\development-and-testing.md",
        "assets\logo.svg",
        "LICENSE",
        ".editorconfig",
        ".github\ISSUE_TEMPLATE\bug.md",
        ".github\dependabot.yml"
    ) `
    -Expected "false"
Assert-ValidationScope `
    -Name "Source changes" `
    -ChangedPath @("crates\broker\src\lib.rs") `
    -Expected "true"
Assert-ValidationScope `
    -Name "Dependency changes" `
    -ChangedPath @("Cargo.lock") `
    -Expected "true"
Assert-ValidationScope `
    -Name "Workflow changes" `
    -ChangedPath @(".github\workflows\ci.yml") `
    -Expected "true"
Assert-ValidationScope `
    -Name "Unrecognized files" `
    -ChangedPath @("new-file.txt") `
    -Expected "true"
Assert-ValidationScope `
    -Name "Empty change sets" `
    -ChangedPath ([string[]]@()) `
    -Expected "true"

$pushGroupFragment = 'github.event_name == ''push'' && github.sha || github.ref'
$pullRequestCancellation = 'cancel-in-progress: ${{ github.event_name == ''pull_request'' }}'
foreach ($workflowName in @("ci.yml", "codeql.yml"))
{
    $workflow = Get-Content `
        -LiteralPath (Join-Path $repositoryRoot ".github\workflows\$workflowName") `
        -Raw
    Assert-True `
        ($workflow.Contains($pushGroupFragment)) `
        "$workflowName does not use a commit-specific concurrency group for main pushes."
    Assert-True `
        ($workflow.Contains($pullRequestCancellation)) `
        "$workflowName does not limit cancellation to pull request updates."
    Assert-True `
        ($workflow.Contains(".\scripts\Test-WorkflowScripts.ps1")) `
        "$workflowName does not run tracked workflow script syntax validation."
    Assert-True `
        ($workflow.Contains(".\scripts\Test-ReleaseTag.ps1")) `
        "$workflowName does not validate the Git Data API release tag helper."
}

$codeqlWorkflow = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot ".github\workflows\codeql.yml") `
    -Raw
$codeqlAvailabilityJob = [regex]::Match(
    $codeqlWorkflow,
    '(?ms)^  availability:\r?\n(?<body>.*?)(?=^  \S|\z)'
)
Assert-True `
    $codeqlAvailabilityJob.Success `
    "CodeQL must retain its availability job."
$codeqlAvailabilityBody = $codeqlAvailabilityJob.Groups["body"].Value
Assert-True `
    ($codeqlAvailabilityBody.Contains("uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")) `
    "CodeQL availability must check out the tracked status-reporting script."
Assert-True `
    ($codeqlAvailabilityBody.Contains("bash scripts/ci/write-codeql-availability.sh")) `
    "CodeQL availability must run the tracked status-reporting script."

$releasePublisher = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot ".github\workflows\release-publish.yml") `
    -Raw
$releaseTagScript = Join-Path $repositoryRoot "scripts\release\New-ReleaseTag.ps1"
Assert-True `
    ($releasePublisher.Contains("id: app-token")) `
    "Release publishing does not mint the GitHub App token required to create protected tags."
Assert-True `
    ($releasePublisher.Contains("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1")) `
    "Release publishing does not use the pinned GitHub App token action."
Assert-True `
    ($releasePublisher.Contains("permission-contents: write")) `
    "Release publishing does not request the GitHub App Contents permission required to create tags."
Assert-True `
    (!$releasePublisher.Contains("permission-workflows: write")) `
    "Release publishing must not request GitHub App permission to modify workflow files for tag creation."
Assert-True `
    ($releasePublisher.Contains("GH_TOKEN: `${{ steps.app-token.outputs.token }}")) `
    "Release publishing does not scope the GitHub App token to annotated tag creation."
Assert-True `
    ($releasePublisher.Contains('.\scripts\release\New-ReleaseTag.ps1 -Repository $env:GITHUB_REPOSITORY -Tag $env:TAG -ReleaseSha $env:RELEASE_SHA')) `
    "Release publishing does not call the Git Data API tag helper."
Assert-True `
    (Test-Path -LiteralPath $releaseTagScript -PathType Leaf) `
    "Release publishing is missing the Git Data API tag helper."
Assert-True `
    (!(Test-Path -LiteralPath (Join-Path $repositoryRoot "scripts\New-ReleaseTag.ps1") -PathType Leaf)) `
    "Release publishing must keep a single Git Data API tag helper."
$releaseTagSource = Get-Content -LiteralPath $releaseTagScript -Raw
Assert-True `
    ($releaseTagSource.Contains("git/tags")) `
    "Release tag helper does not create an annotated Git tag object."
Assert-True `
    ($releaseTagSource.Contains("git/refs")) `
    "Release tag helper does not create the release tag reference."
Assert-True `
    ($releaseTagSource.Contains("matching-refs/tags")) `
    "Release tag helper does not safely inspect existing tag references."
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $releaseTagScript,
    [ref]$tokens,
    [ref]$parseErrors
) | Out-Null
Assert-True `
    ($parseErrors.Count -eq 0) `
    "Release tag helper contains PowerShell syntax errors: $((@($parseErrors | ForEach-Object { $_.Message }) -join '; '))."

$hostedWslE2eWorkflow = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot ".github\workflows\hosted-wsl-e2e.yml") `
    -Raw
Assert-True `
    ($hostedWslE2eWorkflow -match '(?m)^permissions:\r?\n  actions: write\r?\n  contents: read\r?$') `
    "Hosted WSL E2E must grant the cache action write access while retaining read-only repository contents."
Assert-True `
    ($hostedWslE2eWorkflow -notmatch '(?m)^  pull_request:\s*$') `
    "Hosted WSL E2E must not run for pull requests."
Assert-True `
    ($hostedWslE2eWorkflow.Contains("if: github.event.repository.fork == false")) `
    "Hosted WSL E2E must skip fork repositories."

$releasePublishWorkflow = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot ".github\workflows\release-publish.yml") `
    -Raw
$releaseHostedE2eJob = [regex]::Match(
    $releasePublishWorkflow,
    '(?ms)^  hosted-e2e:\r?\n(?<body>.*?)(?=^  \S|\z)'
)
Assert-True `
    $releaseHostedE2eJob.Success `
    "Release publish must retain its hosted WSL E2E reusable-workflow job."
$releaseHostedE2eBody = $releaseHostedE2eJob.Groups["body"].Value
Assert-True `
    ($releaseHostedE2eBody.Contains("uses: ./.github/workflows/hosted-wsl-e2e.yml")) `
    "Release publish must call the hosted WSL E2E workflow."
Assert-True `
    ($releaseHostedE2eBody.Contains("needs: wait-ci")) `
    "Release publish must wait for merge CI before running hosted WSL E2E."
Assert-True `
    ($releaseHostedE2eBody -match '(?m)^    permissions:\r?\n      actions: write\r?\n      contents: read\r?$') `
    "Release publish must not downgrade the hosted WSL E2E cache-save permission."
Assert-True `
    ($releasePublishWorkflow.Contains("github.event.pull_request.merged == true") -and `
        $releasePublishWorkflow.Contains("github.event.pull_request.base.ref == github.event.repository.default_branch") -and `
        $releasePublishWorkflow.Contains("github.event.pull_request.head.repo.full_name == github.repository") -and `
        $releasePublishWorkflow.Contains("startsWith(github.event.pull_request.head.ref, 'release/v')") -and `
        $releasePublishWorkflow.Contains("contains(github.event.pull_request.labels.*.name, 'release')")) `
    "Release publish must restrict hosted WSL E2E to merged same-repository release pull requests."

Write-Host "CI change-scope validation passed."
