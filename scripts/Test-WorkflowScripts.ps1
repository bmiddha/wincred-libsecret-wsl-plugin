[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = $PSScriptRoot
$powerShellScripts = @(
    Get-ChildItem -LiteralPath $scriptRoot -Recurse -Filter "*.ps1" -File
)
$parseErrors = @()
foreach ($script in $powerShellScripts)
{
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null
    $parseErrors += $errors
}
if ($parseErrors.Count -gt 0)
{
    throw "PowerShell syntax errors:`n$($parseErrors | ForEach-Object Message | Out-String)"
}

$bashScripts = @(
    Get-ChildItem -LiteralPath $scriptRoot -Recurse -Filter "*.sh" -File
)
if ($bashScripts.Count -gt 0)
{
    $bashCommand = "bash"
    if ($IsWindows)
    {
        $gitBash = Join-Path $env:ProgramFiles "Git\bin\bash.exe"
        if (Test-Path -LiteralPath $gitBash -PathType Leaf)
        {
            $bashCommand = $gitBash
        }
    }
    $bashArguments = @("-n") + @($bashScripts.FullName)
    & $bashCommand @bashArguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "bash syntax validation failed with exit code $LASTEXITCODE."
    }
}

$pythonScripts = @(
    Get-ChildItem -LiteralPath $scriptRoot -Recurse -Filter "*.py" -File
)
if ($pythonScripts.Count -gt 0)
{
    $pythonCommand = if ($IsWindows) { "python" } else { "python3" }
    $pythonArguments = @("-B", "-m", "py_compile") + @($pythonScripts.FullName)
    & $pythonCommand @pythonArguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "Python syntax validation failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Tracked workflow script syntax validation passed."
