[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scopeScript = Join-Path $PSScriptRoot "Get-CiChangeScope.ps1"

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

Write-Host "CI change-scope validation passed."
