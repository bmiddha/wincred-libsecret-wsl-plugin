[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias("FullName")]
    [string[]]$Path
)

begin
{
    Set-StrictMode -Version Latest
    . (Join-Path $PSScriptRoot "Signing.Common.ps1")
}

process
{
    Get-SigningState -Path $Path
}
