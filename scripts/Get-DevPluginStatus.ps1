[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "Signing.Common.ps1")
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

$registration = Get-PluginRegistryValue
$statePath = Get-DevPluginStatePath
$state = $null
$stateStatus = "absent"
if (Test-Path -LiteralPath $statePath -PathType Leaf)
{
    if (Test-Administrator)
    {
        try
        {
            $state = Read-DevPluginState
            $stateStatus = "valid"
        }
        catch
        {
            $stateStatus = "invalid: $($_.Exception.Message)"
        }
    }
    else
    {
        $stateStatus = "protected (run elevated to inspect)"
    }
}
$signature = if ($null -ne $registration -and (Test-Path -LiteralPath $registration.Value -PathType Leaf))
{
    Get-SigningState -Path $registration.Value
}
else
{
    $null
}
[PSCustomObject]@{
    RegistryPath = $script:PluginRegistryPath
    ValueName = $script:PluginValueName
    RegisteredPath = if ($null -eq $registration) { $null } else { $registration.Value }
    RegistryValueKind = if ($null -eq $registration) { $null } else { $registration.Kind }
    ProtectedStatePath = $statePath
    ProtectedStateStatus = $stateStatus
    TrackedDevelopmentDll = if ($null -eq $state) { $null } else { $state.trackedDllPath }
    SignatureStatus = if ($null -eq $signature) { $null } else { $signature.Status }
    SignerThumbprint = if ($null -eq $signature) { $null } else { $signature.SignerThumbprint }
}
