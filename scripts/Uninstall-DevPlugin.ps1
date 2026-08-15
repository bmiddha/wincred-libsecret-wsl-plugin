[CmdletBinding(SupportsShouldProcess)]
param([switch]$RestartWslService)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

if ($WhatIfPreference)
{
    $PSCmdlet.ShouldProcess(
        $script:PluginRegistryPath,
        "Restore only the protected saved plugin registration if the current value is still tracked"
    ) | Out-Null
    return
}

Assert-Administrator
Initialize-DevPluginStateStore
$state = Read-DevPluginState
if ($null -eq $state)
{
    Write-Host "No protected developer plugin registration state exists at '$(Get-DevPluginStatePath)'."
    return
}

$tracked = [PSCustomObject]@{ Value = $state.trackedDllPath; Kind = "String" }
$restore = if ($state.hadExistingValue)
{
    [PSCustomObject]@{ Value = $state.originalValue; Kind = $state.originalKind }
}
else
{
    $null
}
$existing = Get-PluginRegistryValue
if (!(Test-RegistryValueMatches -Actual $existing -Expected $tracked))
{
    $current = if ($null -eq $existing) { "absent" } else { "'$($existing.Value)' ($($existing.Kind))" }
    Write-Warning "Preserved the current plugin registry value ($current) because it no longer matches the protected tracked DLL. State was retained."
    return
}

if ($PSCmdlet.ShouldProcess($script:PluginRegistryPath, "Remove development plugin and restore protected registry value"))
{
    if (!(Restore-PluginRegistryValueIfStillTracked -Tracked $tracked -Restore $restore))
    {
        Write-Warning "Preserved the plugin registry value because it changed while cleanup was running. State was retained."
        return
    }
    Remove-DevPluginState
    if ($null -ne $restore)
    {
        Write-Host "Restored the protected pre-existing plugin value: $($restore.Value)"
    }
    else
    {
        Write-Host "Removed the development plugin value."
    }
    Invoke-WslServiceRestart -RestartWslService:$RestartWslService
}
