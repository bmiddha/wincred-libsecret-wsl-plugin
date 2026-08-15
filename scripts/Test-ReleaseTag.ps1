[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$releaseTagScript = Join-Path $repositoryRoot "scripts\release\New-ReleaseTag.ps1"
$repository = "owner/repository"
$tag = "v0.1.0"
$releaseSha = "0123456789abcdef0123456789abcdef01234567"

function Assert-True
{
    param([bool]$Condition, [string]$Message)

    if (!$Condition)
    {
        throw $Message
    }
}

function gh
{
    param(
        [Parameter(ValueFromPipeline = $true, Position = -2147483648)]
        [AllowEmptyString()]
        [string]$InputObject,

        [Parameter(ValueFromRemainingArguments = $true, Position = 0)]
        [string[]]$Arguments
    )

    begin
    {
        $inputValues = [System.Collections.Generic.List[string]]::new()
    }

    process
    {
        [void]$inputValues.Add($InputObject)
    }

    end
    {
        $path = @($Arguments | Where-Object { $_ -like "repos/*" })[-1]
        $method = if ($Arguments -contains "POST") { "POST" } else { "GET" }
        [void]$global:WincredReleaseTagTestCalls.Add([pscustomobject]@{
                Command = "gh"
                Method = $method
                Path = $path
                Input = $inputValues -join "`n"
            })
        $global:LASTEXITCODE = 0

        $matchingReferencePath = "repos/$global:WincredReleaseTagTestRepository/git/matching-refs/tags/$global:WincredReleaseTagTestTag"
        $tagObjectPath = "repos/$global:WincredReleaseTagTestRepository/git/tags/tag-object"
        $tagCreationPath = "repos/$global:WincredReleaseTagTestRepository/git/tags"
        $referenceCreationPath = "repos/$global:WincredReleaseTagTestRepository/git/refs"

        switch ($global:WincredReleaseTagTestScenario)
        {
            "new"
            {
                if ($method -eq "GET" -and $path -eq $matchingReferencePath)
                {
                    "[]"
                    return
                }
                if ($method -eq "POST" -and $path -eq $tagCreationPath)
                {
                    '{"sha":"tag-object"}'
                    return
                }
                if ($method -eq "POST" -and $path -eq $referenceCreationPath)
                {
                    return
                }
            }
            "annotated"
            {
                if ($method -eq "GET" -and $path -eq $matchingReferencePath)
                {
                    "[{`"ref`":`"refs/tags/$global:WincredReleaseTagTestTag`",`"object`":{`"type`":`"tag`",`"sha`":`"tag-object`"}}]"
                    return
                }
                if ($method -eq "GET" -and $path -eq $tagObjectPath)
                {
                    "{`"object`":{`"type`":`"commit`",`"sha`":`"$global:WincredReleaseTagTestReleaseSha`"}}"
                    return
                }
            }
            "lightweight"
            {
                if ($method -eq "GET" -and $path -eq $matchingReferencePath)
                {
                    "[{`"ref`":`"refs/tags/$global:WincredReleaseTagTestTag`",`"object`":{`"type`":`"commit`",`"sha`":`"$global:WincredReleaseTagTestReleaseSha`"}}]"
                    return
                }
            }
            "mismatch"
            {
                if ($method -eq "GET" -and $path -eq $matchingReferencePath)
                {
                    '[{"ref":"refs/tags/v0.1.0","object":{"type":"commit","sha":"abcdefabcdefabcdefabcdefabcdefabcdefabcd"}}]'
                    return
                }
            }
        }

        throw "Unexpected gh invocation for $($global:WincredReleaseTagTestScenario): $method $path"
    }
}

function git
{
    param(
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$Arguments
    )

    [void]$global:WincredReleaseTagTestCalls.Add([pscustomobject]@{
            Command = "git"
            Method = $Arguments[0]
            Path = ""
            Input = $Arguments -join " "
        })
    $global:LASTEXITCODE = 0

    switch ($Arguments[0])
    {
        "fetch"
        {
            return
        }
        "rev-list"
        {
            $global:WincredReleaseTagTestReleaseSha
            return
        }
        default
        {
            throw "Unexpected git invocation: $($Arguments -join ' ')"
        }
    }
}

function Invoke-ReleaseTagScenario
{
    param(
        [Parameter(Mandatory)]
        [ValidateSet("new", "annotated", "lightweight")]
        [string]$Scenario
    )

    $global:WincredReleaseTagTestScenario = $Scenario
    $global:WincredReleaseTagTestCalls = [System.Collections.Generic.List[object]]::new()

    & $releaseTagScript -Repository $repository -Tag $tag -ReleaseSha $releaseSha

    $tagCreationCalls = @(
        $global:WincredReleaseTagTestCalls |
            Where-Object { $_.Command -eq "gh" -and $_.Method -eq "POST" -and $_.Path -eq "repos/$repository/git/tags" }
    )
    $referenceCreationCalls = @(
        $global:WincredReleaseTagTestCalls |
            Where-Object { $_.Command -eq "gh" -and $_.Method -eq "POST" -and $_.Path -eq "repos/$repository/git/refs" }
    )
    if ($Scenario -eq "new")
    {
        Assert-True ($tagCreationCalls.Count -eq 1) "New tags must create exactly one annotated tag object."
        Assert-True ($referenceCreationCalls.Count -eq 1) "New tags must create exactly one tag reference."
        Assert-True `
            ($tagCreationCalls[0].Input.Contains("`"object`":`"$releaseSha`"")) `
            "New tag objects must reference the release commit."
        Assert-True `
            ($referenceCreationCalls[0].Input.Contains('"ref":"refs/tags/v0.1.0"')) `
            "New tag references must use the release tag name."
    }
    else
    {
        Assert-True ($tagCreationCalls.Count -eq 0) "Existing tags must not create another tag object."
        Assert-True ($referenceCreationCalls.Count -eq 0) "Existing tags must not create another tag reference."
    }

    Assert-True `
        (@($global:WincredReleaseTagTestCalls | Where-Object { $_.Command -eq "git" -and $_.Method -eq "fetch" }).Count -eq 1) `
        "Release tag verification must fetch the resolved tag."
    Assert-True `
        (@($global:WincredReleaseTagTestCalls | Where-Object { $_.Command -eq "git" -and $_.Method -eq "rev-list" }).Count -eq 1) `
        "Release tag verification must resolve the tagged commit."
}

$previousToken = $env:GH_TOKEN
try
{
    $env:GH_TOKEN = "test-token"
    $global:WincredReleaseTagTestRepository = $repository
    $global:WincredReleaseTagTestTag = $tag
    $global:WincredReleaseTagTestReleaseSha = $releaseSha
    foreach ($scenario in @("new", "annotated", "lightweight"))
    {
        Invoke-ReleaseTagScenario -Scenario $scenario
    }

    $global:WincredReleaseTagTestScenario = "mismatch"
    $global:WincredReleaseTagTestCalls = [System.Collections.Generic.List[object]]::new()
    $threw = $false
    try
    {
        & $releaseTagScript -Repository $repository -Tag $tag -ReleaseSha $releaseSha
    }
    catch
    {
        $threw = $_.Exception.Message -like "*already points*"
    }
    Assert-True $threw "Tags that point to another commit must fail."
    Assert-True `
        (@($global:WincredReleaseTagTestCalls | Where-Object { $_.Method -eq "POST" }).Count -eq 0) `
        "Tags that point to another commit must not create Git objects."
}
finally
{
    if ($null -eq $previousToken)
    {
        Remove-Item Env:\GH_TOKEN -ErrorAction SilentlyContinue
    }
    else
    {
        $env:GH_TOKEN = $previousToken
    }
    Remove-Variable -Name WincredReleaseTagTestCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name WincredReleaseTagTestScenario -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name WincredReleaseTagTestRepository -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name WincredReleaseTagTestTag -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name WincredReleaseTagTestReleaseSha -Scope Global -ErrorAction SilentlyContinue
}

Write-Host "Release tag helper validation passed."
