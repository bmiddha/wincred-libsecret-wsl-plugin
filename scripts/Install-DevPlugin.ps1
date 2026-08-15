[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DllPath,
    [switch]$ReplaceConflict,
    [switch]$AllowUnsigned,
    [switch]$RestartWslService
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "Signing.Common.ps1")
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($DllPath))
{
    $DllPath = Join-Path $repoRoot "artifacts\Debug\windows\wincred-libsecret-wsl-plugin.dll"
}
$dll = Assert-ExistingPluginDll -Path $DllPath
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if ($signature.Status -ne "Valid" -and !$AllowUnsigned)
{
    throw "DLL signature is $($signature.Status). Sign it or pass -AllowUnsigned for an isolated local development install."
}

if ($WhatIfPreference)
{
    $PSCmdlet.ShouldProcess(
        $script:PluginRegistryPath,
        "Register development plugin '$dll' and create protected state at '$(Get-DevPluginStatePath)'"
    ) | Out-Null
    return
}

Assert-Administrator
Initialize-DevPluginStateStore
$state = Read-DevPluginState
$existing = Get-PluginRegistryValue
if ($null -ne $state)
{
    $tracked = [PSCustomObject]@{ Value = $state.trackedDllPath; Kind = "String" }
    if (!$tracked.Value.Equals($dll, [StringComparison]::OrdinalIgnoreCase))
    {
        throw "Protected developer plugin state tracks '$($tracked.Value)'. Clean it up before installing another DLL."
    }
    if ($null -ne $existing -and !(Test-RegistryValueMatches -Actual $existing -Expected $tracked))
    {
        throw "The plugin value changed after developer installation and was preserved. Clean it up only after reviewing '$($existing.Value)'."
    }
    if ($null -eq $existing)
    {
        $existing = $null
    }
}
elseif ($null -ne $existing -and $existing.Value.Equals($dll, [StringComparison]::OrdinalIgnoreCase))
{
    throw "The DLL is already registered without protected developer state; refusing to claim ownership."
}
elseif ($null -ne $existing -and !$ReplaceConflict)
{
    throw "The plugin value already names '$($existing.Value)'. It was not changed. Re-run with -ReplaceConflict only after reviewing it."
}

if ($null -ne $existing -and !($existing.Kind -eq "String"))
{
    throw "Refusing to replace registry value kind '$($existing.Kind)'; only REG_SZ plugin registrations can be restored safely."
}
if ($null -ne $existing)
{
    [void](Assert-TrustedRestorablePluginDll -Path $existing.Value)
}

$newState = if ($null -ne $state)
{
    $state
}
else
{
    [ordered]@{
        schemaVersion = $script:DevPluginStateSchemaVersion
        trackedDllPath = $dll
        hadExistingValue = $null -ne $existing
        originalValue = if ($null -eq $existing) { $null } else { $existing.Value }
        originalKind = if ($null -eq $existing) { $null } else { $existing.Kind }
    }
}

if ($PSCmdlet.ShouldProcess($script:PluginRegistryPath, "Register development plugin '$dll'"))
{
    $wroteState = $false
    try
    {
        if ($null -eq $state)
        {
            Write-DevPluginState -State $newState
            $wroteState = $true
        }
        if (!(Set-PluginRegistryValueIfUnchanged -Expected $existing -Value $dll))
        {
            throw "The plugin registry value changed while installing; it was preserved."
        }
    }
    catch
    {
        if ($wroteState)
        {
            Remove-DevPluginState
        }
        throw
    }
    Write-Host "Registered development plugin: $dll"
    Invoke-WslServiceRestart -RestartWslService:$RestartWslService
}
