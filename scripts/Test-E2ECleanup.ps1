[CmdletBinding()]
param(
    [string]$ResultDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ResultDirectory))
{
    $ResultDirectory = Join-Path $repoRoot "test-results\e2e"
}
if (!(Test-Path -LiteralPath $ResultDirectory -PathType Container))
{
    throw "E2E result directory '$ResultDirectory' does not exist."
}

$report = Get-ChildItem -LiteralPath $ResultDirectory -Filter "*.junit.xml" -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -eq $report)
{
    throw "No E2E JUnit report was produced."
}
if ($report.Length -gt 1MB)
{
    throw "E2E JUnit report '$($report.Name)' is unexpectedly large."
}

. (Join-Path $repoRoot "tests\e2e\E2E.Common.ps1")
$inventory = Get-E2EInventoryFromJUnitReport $report.FullName $ResultDirectory

$registered = @(
    & wsl.exe --list --quiet |
        ForEach-Object { $_.Trim([char]0, [char]32) } |
        Where-Object { $_ -like "wincred-e2e-$($inventory.RunId)-*" }
)
if ($LASTEXITCODE -ne 0)
{
    throw "Could not list WSL distributions during E2E cleanup verification."
}
if ($registered.Count -gt 0)
{
    throw "Disposable WSL distributions for this E2E run remain registered."
}
Write-Host "Verified E2E cleanup: JUnit, sanitized inventory, and this run's disposable distributions are clean."
