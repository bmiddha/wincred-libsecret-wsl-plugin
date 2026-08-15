Set-StrictMode -Version Latest

$script:PluginRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins"
$script:PluginRegistrySubKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins"
$script:PluginValueName = "wincred-libsecret-wsl-plugin"
$script:DevPluginStateSchemaVersion = 1
$script:DevPluginStateFileName = "plugin-registration.json"

function Test-Administrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator
{
    if (!(Test-Administrator))
    {
        throw "This operation changes HKLM or protected machine state and must be run from an elevated PowerShell session."
    }
}

function Get-DevPluginStateDirectory
{
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($programData))
    {
        $programData = "C:\ProgramData"
    }
    Join-Path $programData "WinCredLibsecret\DevPlugin"
}

function Get-DevPluginStatePath
{
    Join-Path (Get-DevPluginStateDirectory) $script:DevPluginStateFileName
}

function Test-ReparsePoint
{
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Assert-NotReparsePoint
{
    param([Parameter(Mandatory)][string]$Path)

    if (Test-ReparsePoint -Path $Path)
    {
        throw "Refusing reparse-point path '$Path'."
    }
}

function Get-MachineStateSids
{
    @(
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )
}

function Set-MachineProtectedAcl
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    if ($Directory)
    {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($identity in @($system, $administrators))
        {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$security.AddAccessRule($rule)
        }
        $security.SetOwner($administrators)
        $security.SetAccessRuleProtection($true, $false)
        Set-Acl -LiteralPath $Path -AclObject $security
    }
    else
    {
        $security = [Security.AccessControl.FileSecurity]::new()
        foreach ($identity in @($system, $administrators))
        {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$security.AddAccessRule($rule)
        }
        $security.SetOwner($administrators)
        $security.SetAccessRuleProtection($true, $false)
        Set-Acl -LiteralPath $Path -AclObject $security
    }
}

function Test-MachineProtectedAcl
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    try
    {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($Directory -and !$item.PSIsContainer)
        {
            return $false
        }
        if (!$Directory -and $item.PSIsContainer)
        {
            return $false
        }
        if (Test-ReparsePoint -Path $Path)
        {
            return $false
        }

        $security = Get-Acl -LiteralPath $Path
        if (!$security.AreAccessRulesProtected)
        {
            return $false
        }
        $allowedSids = @(
            foreach ($machineStateSid in Get-MachineStateSids)
            {
                $machineStateSid.Value
            }
        )
        if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids)
        {
            return $false
        }

        $rules = $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        $found = @{}
        foreach ($rule in $rules)
        {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.IdentityReference.Value -notin $allowedSids)
            {
                return $false
            }
            if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl)
            {
                return $false
            }
            $found[$rule.IdentityReference.Value] = $true
        }
        foreach ($sid in $allowedSids)
        {
            if (!$found.ContainsKey($sid))
            {
                return $false
            }
        }
        return $true
    }
    catch
    {
        return $false
    }
}

function Assert-MachineProtectedPath
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    if (!(Test-MachineProtectedAcl -Path $Path -Directory:$Directory))
    {
        throw "Machine state path '$Path' is missing the required SYSTEM/Administrators-only ACL, owner, or no-reparse guarantee."
    }
}

function New-MachineProtectedDirectory
{
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path)
    {
        Assert-MachineProtectedPath -Path $Path -Directory
        return
    }

    $parent = Split-Path -Parent $Path
    if (!(Test-Path -LiteralPath $parent -PathType Container))
    {
        throw "State parent '$parent' does not exist."
    }
    Assert-NotReparsePoint -Path $parent
    New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    Assert-NotReparsePoint -Path $Path
    Set-MachineProtectedAcl -Path $Path -Directory
    Assert-MachineProtectedPath -Path $Path -Directory
}

function Initialize-DevPluginStateStore
{
    Assert-Administrator
    $stateDirectory = Get-DevPluginStateDirectory
    $productDirectory = Split-Path -Parent $stateDirectory
    New-MachineProtectedDirectory -Path $productDirectory
    New-MachineProtectedDirectory -Path $stateDirectory
}

function Assert-DevPluginStateStore
{
    $stateDirectory = Get-DevPluginStateDirectory
    Assert-MachineProtectedPath -Path (Split-Path -Parent $stateDirectory) -Directory
    Assert-MachineProtectedPath -Path $stateDirectory -Directory
}

function Get-PluginRegistryValue
{
    if (!(Test-Path -LiteralPath $script:PluginRegistryPath))
    {
        return $null
    }

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:PluginRegistrySubKey, $false)
    if ($null -eq $key)
    {
        return $null
    }
    try
    {
        $value = $key.GetValue(
            $script:PluginValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($null -eq $value)
        {
            return $null
        }
        [PSCustomObject]@{
            Value = [string]$value
            Kind = $key.GetValueKind($script:PluginValueName).ToString()
        }
    }
    finally
    {
        $key.Dispose()
    }
}

function Test-RegistryValueMatches
{
    param(
        $Actual,
        $Expected
    )

    if ($null -eq $Actual -or $null -eq $Expected)
    {
        return $null -eq $Actual -and $null -eq $Expected
    }
    $Actual.Kind -eq "String" -and
        $Expected.Kind -eq "String" -and
        $Actual.Value.Equals($Expected.Value, [StringComparison]::OrdinalIgnoreCase)
}

function Set-PluginRegistryValueIfUnchanged
{
    param(
        $Expected,
        [Parameter(Mandatory)][string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String
    )

    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($script:PluginRegistrySubKey, $true)
    if ($null -eq $key)
    {
        throw "Could not open '$script:PluginRegistryPath' for writing."
    }
    try
    {
        $currentValue = $key.GetValue(
            $script:PluginValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $current = if ($null -eq $currentValue)
        {
            $null
        }
        else
        {
            [PSCustomObject]@{
                Value = [string]$currentValue
                Kind = $key.GetValueKind($script:PluginValueName).ToString()
            }
        }
        if (!(Test-RegistryValueMatches -Actual $current -Expected $Expected))
        {
            return $false
        }
        $key.SetValue($script:PluginValueName, $Value, $Kind)
        return $true
    }
    finally
    {
        $key.Dispose()
    }
}

function Restore-PluginRegistryValueIfStillTracked
{
    param(
        [Parameter(Mandatory)]$Tracked,
        $Restore
    )

    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($script:PluginRegistrySubKey, $true)
    if ($null -eq $key)
    {
        throw "Could not open '$script:PluginRegistryPath' for writing."
    }
    try
    {
        $currentValue = $key.GetValue(
            $script:PluginValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $current = if ($null -eq $currentValue)
        {
            $null
        }
        else
        {
            [PSCustomObject]@{
                Value = [string]$currentValue
                Kind = $key.GetValueKind($script:PluginValueName).ToString()
            }
        }
        if (!(Test-RegistryValueMatches -Actual $current -Expected $Tracked))
        {
            return $false
        }
        if ($null -eq $Restore)
        {
            $key.DeleteValue($script:PluginValueName, $false)
        }
        else
        {
            $key.SetValue(
                $script:PluginValueName,
                $Restore.Value,
                [Microsoft.Win32.RegistryValueKind]::$Restore.Kind
            )
        }
        return $true
    }
    finally
    {
        $key.Dispose()
    }
}

function ConvertFrom-DevPluginState
{
    param([Parameter(Mandatory)][string]$Json)

    try
    {
        $state = $Json | ConvertFrom-Json -ErrorAction Stop
    }
    catch
    {
        throw "Developer plugin state is not valid JSON."
    }
    $expectedProperties = @(
        "schemaVersion",
        "trackedDllPath",
        "hadExistingValue",
        "originalValue",
        "originalKind"
    )
    $actualProperties = @($state.PSObject.Properties.Name)
    if ($actualProperties.Count -ne $expectedProperties.Count -or
        @($actualProperties | Where-Object { $_ -notin $expectedProperties }).Count -ne 0)
    {
        throw "Developer plugin state has an unsupported schema."
    }
    if ($state.schemaVersion -ne $script:DevPluginStateSchemaVersion -or
        $state.hadExistingValue -isnot [bool] -or
        $state.trackedDllPath -isnot [string] -or
        [string]::IsNullOrWhiteSpace($state.trackedDllPath) -or
        ![IO.Path]::IsPathFullyQualified($state.trackedDllPath) -or
        [IO.Path]::GetFileName($state.trackedDllPath) -ne "wincred-libsecret-wsl-plugin.dll")
    {
        throw "Developer plugin state failed schema validation."
    }
    if ($state.hadExistingValue)
    {
        if ($state.originalValue -isnot [string] -or
            [string]::IsNullOrWhiteSpace($state.originalValue) -or
            ![IO.Path]::IsPathFullyQualified($state.originalValue) -or
            $state.originalKind -ne "String")
        {
            throw "Developer plugin restoration state failed validation."
        }
    }
    elseif ($null -ne $state.originalValue -or $null -ne $state.originalKind)
    {
        throw "Developer plugin state has unexpected restoration data."
    }
    $state
}

function Assert-ExistingPluginDll
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$RequireTrustedSignature
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (Test-ReparsePoint -Path $item.FullName))
    {
        throw "Plugin DLL path '$Path' is not a regular file."
    }
    $resolved = $item.FullName
    if (![IO.Path]::IsPathFullyQualified($resolved) -or
        [IO.Path]::GetFileName($resolved) -ne "wincred-libsecret-wsl-plugin.dll")
    {
        throw "Plugin DLL must resolve to an absolute wincred-libsecret-wsl-plugin.dll path."
    }
    if ($RequireTrustedSignature)
    {
        $signature = Get-AuthenticodeSignature -LiteralPath $resolved
        if ($signature.Status -ne "Valid")
        {
            throw "Restored plugin DLL '$resolved' does not have a valid trusted Authenticode signature ($($signature.Status))."
        }
    }
    $resolved
}

function Assert-TrustedRestorablePluginDll
{
    param([Parameter(Mandatory)][string]$Path)

    $resolved = Assert-ExistingPluginDll -Path $Path
    Assert-NoUntrustedWriteAccess -Path (Split-Path -Parent $resolved)
    Assert-TrustedAuthenticodeFile -Path $resolved
}

function Assert-NoUntrustedWriteAccess
{
    param([Parameter(Mandatory)][string]$Path)

    $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteDac -bor
        [Security.AccessControl.FileSystemRights]::WriteOwner
    $allowedWriters = @("S-1-5-18", "S-1-5-32-544")
    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($true)
    {
        if (!$directory.PSIsContainer -or (Test-ReparsePoint -Path $directory.FullName))
        {
            throw "Trusted restore directory '$($directory.FullName)' is not a regular directory."
        }
        $rules = (Get-Acl -LiteralPath $directory.FullName).GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
        foreach ($rule in $rules)
        {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            {
                continue
            }
            $identity = $rule.IdentityReference.Value
            $trustedService = $identity.StartsWith("S-1-5-80-", [StringComparison]::OrdinalIgnoreCase)
            if (!$trustedService -and $identity -notin $allowedWriters -and
                ($rule.FileSystemRights -band $writeMask) -ne 0)
            {
                throw "Trusted restore directory '$($directory.FullName)' grants write access to '$identity'."
            }
        }
        $parent = $directory.Parent
        if ($null -eq $parent -or $parent.FullName.Equals($directory.FullName, [StringComparison]::OrdinalIgnoreCase))
        {
            return
        }
        $directory = $parent
    }
}

function Assert-TrustedAuthenticodeFile
{
    param([Parameter(Mandatory)][string]$Path)

    if (![IO.Path]::IsPathFullyQualified($Path))
    {
        throw "Trusted artifact path must be absolute."
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (Test-ReparsePoint -Path $item.FullName))
    {
        throw "Trusted artifact path '$Path' is not a regular file."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
    if ($signature.Status -ne "Valid")
    {
        throw "Restored artifact '$($item.FullName)' does not have a valid trusted Authenticode signature ($($signature.Status))."
    }
    $item.FullName
}

function Read-DevPluginState
{
    $statePath = Get-DevPluginStatePath
    if (!(Test-Path -LiteralPath $statePath -PathType Leaf))
    {
        return $null
    }
    Assert-DevPluginStateStore
    Assert-MachineProtectedPath -Path $statePath
    $stream = [IO.File]::Open($statePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try
    {
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
        try
        {
            $state = ConvertFrom-DevPluginState -Json $reader.ReadToEnd()
        }
        finally
        {
            $reader.Dispose()
        }
    }
    finally
    {
        $stream.Dispose()
    }

    $state.trackedDllPath = Assert-ExistingPluginDll -Path $state.trackedDllPath
    if ($state.hadExistingValue)
    {
        $state.originalValue = Assert-TrustedRestorablePluginDll -Path $state.originalValue
    }
    $state
}

function Write-DevPluginState
{
    param([Parameter(Mandatory)]$State)

    Initialize-DevPluginStateStore
    $statePath = Get-DevPluginStatePath
    if (Test-Path -LiteralPath $statePath)
    {
        Assert-MachineProtectedPath -Path $statePath
    }
    $json = $State | ConvertTo-Json -Depth 3
    [void](ConvertFrom-DevPluginState -Json $json)
    $temporaryPath = Join-Path (Get-DevPluginStateDirectory) ".$($script:DevPluginStateFileName).$([Guid]::NewGuid().ToString("N")).tmp"
    $stream = [IO.FileStream]::new(
        $temporaryPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::WriteThrough
    )
    try
    {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false), 4096, $true)
        try
        {
            $writer.Write($json)
            $writer.Flush()
            $stream.Flush($true)
        }
        finally
        {
            $writer.Dispose()
        }
    }
    finally
    {
        $stream.Dispose()
    }

    try
    {
        Assert-NotReparsePoint -Path $temporaryPath
        Set-MachineProtectedAcl -Path $temporaryPath
        if (Test-Path -LiteralPath $statePath)
        {
            [IO.File]::Replace($temporaryPath, $statePath, $null, $true)
        }
        else
        {
            [IO.File]::Move($temporaryPath, $statePath)
        }
        Assert-MachineProtectedPath -Path $statePath
    }
    finally
    {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Remove-DevPluginState
{
    $statePath = Get-DevPluginStatePath
    if (!(Test-Path -LiteralPath $statePath -PathType Leaf))
    {
        return
    }
    Assert-DevPluginStateStore
    Assert-MachineProtectedPath -Path $statePath
    Remove-Item -LiteralPath $statePath -Force -ErrorAction Stop
}

function Invoke-WslServiceRestart
{
    param([switch]$RestartWslService)

    if (!$RestartWslService)
    {
        Write-Warning "Registration changed. Restart wslservice from an elevated terminal, or reboot Windows, before starting a new WSL distribution."
        return
    }

    try
    {
        $service = Get-Service -Name wslservice -ErrorAction Stop
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped)
        {
            & wsl.exe --shutdown
            if ($LASTEXITCODE -ne 0)
            {
                throw "wsl.exe --shutdown exited with $LASTEXITCODE."
            }
            $service.Refresh()
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped)
            {
                if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::StopPending)
                {
                    $service.Stop()
                }
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(90))
            }
        }

        $deadline = (Get-Date).AddSeconds(30)
        $lastStartError = $null
        do
        {
            $service = Get-Service -Name wslservice -ErrorAction Stop
            $service.Refresh()
            if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Running)
            {
                break
            }

            try
            {
                Start-Service -Name wslservice -ErrorAction Stop
            }
            catch
            {
                $lastStartError = $_.Exception.Message
            }

            $service.Refresh()
            if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Running)
            {
                break
            }
            if ((Get-Date) -ge $deadline)
            {
                if ($null -ne $lastStartError)
                {
                    throw "wslservice did not start within 30 seconds. Last start error: $lastStartError"
                }
                throw "wslservice did not start within 30 seconds. Current status: $($service.Status)."
            }
            Start-Sleep -Milliseconds 500
        }
        while ($true)

        Write-Host "Restarted wslservice."
    }
    catch
    {
        Write-Warning "Plugin registration changed, but wslservice could not be restarted: $($_.Exception.Message). Restart wslservice manually from an elevated terminal or reboot Windows."
    }
}
