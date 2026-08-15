[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceDistribution,
    [Parameter(Mandatory)]
    [string]$SourceRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

& wsl.exe --shutdown
if ($LASTEXITCODE -ne 0)
{
    throw "wsl.exe --shutdown exited with $LASTEXITCODE."
}

$distributions = @(& wsl.exe --list --quiet 2>&1 | ForEach-Object {
    ([string]$_).Replace([string][char]0, "").Trim([char]0xFEFF, " ", "`t", "`r")
} | Where-Object { $_ })
if ($LASTEXITCODE -ne 0)
{
    throw "wsl.exe --list --quiet exited with $LASTEXITCODE."
}
if ($distributions -contains $SourceDistribution)
{
    & wsl.exe --unregister $SourceDistribution
    if ($LASTEXITCODE -ne 0)
    {
        throw "wsl.exe --unregister exited with $LASTEXITCODE."
    }
}
if (Test-Path -LiteralPath $SourceRoot)
{
    Remove-Item -LiteralPath $SourceRoot -Recurse -Force
}
