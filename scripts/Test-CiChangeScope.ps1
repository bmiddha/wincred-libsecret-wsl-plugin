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
}

$releasePublisher = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot ".github\workflows\release-publish.yml") `
    -Raw
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
    ($releasePublisher.Contains("permission-workflows: write")) `
    "Release publishing does not request the GitHub App Workflows permission required to create tags."
Assert-True `
    ($releasePublisher.Contains("token: `${{ steps.app-token.outputs.token }}")) `
    "Release publishing does not authenticate checkout with the GitHub App token."

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
