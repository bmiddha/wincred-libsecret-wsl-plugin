Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-E2EContext
{
    param([Parameter(Mandatory)][string]$RepositoryRoot)

    $runId = [guid]::NewGuid().ToString("N")
    $resultRoot = Join-Path $RepositoryRoot "test-results\e2e"
    $workRoot = Join-Path $resultRoot "work\$runId"
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    [PSCustomObject]@{
        RunId = $runId
        RepositoryRoot = $RepositoryRoot
        ResultRoot = $resultRoot
        WorkRoot = $workRoot
        LogPath = Join-Path $resultRoot "e2e-$runId.log"
        JUnitPath = Join-Path $resultRoot "e2e-$runId.junit.xml"
        InventoryPath = Join-Path $resultRoot "e2e-$runId.inventory.json"
        Results = [System.Collections.Generic.List[object]]::new()
        Resources = [ordered]@{
            distributions = [System.Collections.Generic.List[string]]::new()
            distributionRoots = [System.Collections.Generic.List[string]]::new()
            distributionResources = [System.Collections.Generic.List[object]]::new()
            initialCredentialInventory = @()
            finalCredentialInventory = @()
            preservedCredentialInventory = @()
            inventoryInitialized = $false
            inventoryFinalized = $false
            runOwnedCredentialTargets = [System.Collections.Generic.List[string]]::new()
            seededCredential = $null
            certificateState = $null
            pluginState = $null
            pluginStateExistedBefore = $false
            rootfsPath = $null
            ownsRootfs = $false
        }
    }
}

function ConvertTo-E2ESafeText
{
    param([AllowNull()][object]$Value)

    $text = [string]$Value
    # E2E clients intentionally never write secret material. Keep this final
    # redaction layer in case a platform tool includes a sensitive argument in
    # an unexpected diagnostic.
    $text = $text -replace '(?im)(password|secret|credential)(\s*[:=]\s*)\S+', '$1$2[redacted]'
    $text = $text -replace '(?im)(/pass:)\S+', '$1[redacted]'
    $text.Trim()
}

function Write-E2ELog
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Message
    )

    $line = "$(Get-Date -Format o) $(ConvertTo-E2ESafeText $Message)"
    Add-Content -LiteralPath $Context.LogPath -Value $line -Encoding utf8NoBOM
    Write-Host $line
}

function Add-E2EResult
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet("passed", "failed", "skipped")]
        [string]$Status,
        [string]$Detail = ""
    )

    $record = [PSCustomObject]@{
        Name = $Name
        Status = $Status
        Detail = ConvertTo-E2ESafeText $Detail
    }
    $Context.Results.Add($record)
    Write-E2ELog $Context "[$Status] $Name $($record.Detail)"
}

function Invoke-E2EAssertion
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$Skip,
        [string]$SkipReason
    )

    if ($Skip)
    {
        Add-E2EResult $Context $Name "skipped" $SkipReason
        return $null
    }
    try
    {
        $result = & $Action
        Add-E2EResult $Context $Name "passed"
        return $result
    }
    catch
    {
        Add-E2EResult $Context $Name "failed" $_.Exception.Message
        throw
    }
}

function Invoke-E2EProcess
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$AllowFailure
    )

    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object {
        ([string]$_).Replace([string][char]0, "")
    })
    $exitCode = $LASTEXITCODE
    if ($output.Count -gt 0)
    {
        foreach ($line in $output)
        {
            Write-E2ELog $Context "$([IO.Path]::GetFileName($FilePath)): $line"
        }
    }
    if (!$AllowFailure -and $exitCode -ne 0)
    {
        throw "'$FilePath' exited with $exitCode."
    }
    [PSCustomObject]@{
        ExitCode = $exitCode
        Output = ($output -join "`n")
    }
}

function Test-E2EAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-E2EPluginLoaded
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$PluginPath,
        [Parameter(Mandatory)][string]$StartupDistribution
    )

    # WSL starts its trigger-start service through a client request, not
    # reliably through the Service Control Manager on hosted Windows.
    Invoke-E2EProcess $Context "wsl.exe" @(
        "--distribution", $StartupDistribution,
        "--user", "root",
        "--",
        "/bin/true"
    ) | Out-Null

    $expectedPath = [IO.Path]::GetFullPath($PluginPath)
    $deadline = (Get-Date).AddSeconds(30)
    $lastObservation = "wslservice was not observed."
    do
    {
        $service = Get-CimInstance Win32_Service -Filter "Name='wslservice'" -ErrorAction Stop
        if ($service.ProcessId -le 0)
        {
            $lastObservation = "wslservice does not have a process ID."
        }
        else
        {
            $process = Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue
            if ($null -eq $process)
            {
                $lastObservation = "wslservice process $($service.ProcessId) exited before its modules could be inspected."
            }
            else
            {
                $loaded = @(
                    $process.Modules |
                        Where-Object {
                            ![string]::IsNullOrWhiteSpace($_.FileName) -and
                            $_.FileName.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)
                        }
                )
                if ($loaded.Count -eq 1)
                {
                    return
                }
                $lastObservation = "wslservice process $($service.ProcessId) did not load '$expectedPath'."
            }
        }

        if ((Get-Date) -lt $deadline)
        {
            Start-Sleep -Milliseconds 500
        }
    }
    while ((Get-Date) -lt $deadline)

    throw "wslservice did not load '$expectedPath' within 30 seconds. Last observation: $lastObservation"
}

function Get-E2EWslVersion
{
    param([Parameter(Mandatory)]$Context)

    $result = Invoke-E2EProcess $Context "wsl.exe" @("--version") -AllowFailure
    if ($result.ExitCode -ne 0)
    {
        return $null
    }
    $match = [regex]::Match($result.Output, '(?im)^\s*WSL\s+version\s*:\s*v?(\d+)\.(\d+)\.(\d+)')
    if (!$match.Success)
    {
        return $null
    }
    [version]::new([int]$match.Groups[1].Value, [int]$match.Groups[2].Value, [int]$match.Groups[3].Value)
}

function Get-E2EDistributions
{
    param([Parameter(Mandatory)]$Context)

    $result = Invoke-E2EProcess $Context "wsl.exe" @("--list", "--quiet") -AllowFailure
    if ($result.ExitCode -ne 0)
    {
        return @()
    }
    @($result.Output -split "`r?`n" | ForEach-Object { $_.Trim([char]0xFEFF, " ", "`t", "`r") } | Where-Object { $_ })
}

function Invoke-E2EWsl
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Distribution,
        [Parameter(Mandatory)][string[]]$Command,
        [string]$User = "root",
        [switch]$AllowFailure
    )

    Invoke-E2EProcess $Context "wsl.exe" (@("-d", $Distribution, "-u", $User, "--") + $Command) -AllowFailure:$AllowFailure
}

function Get-E2EWslPath
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Distribution,
        [Parameter(Mandatory)][string]$WindowsPath
    )

    $normalizedWindowsPath = $WindowsPath -replace "\\", "/"
    $result = Invoke-E2EWsl $Context $Distribution @("wslpath", "-a", $normalizedWindowsPath)
    $result.Output.Trim()
}

function Invoke-E2EBash
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Distribution,
        [Parameter(Mandatory)][string]$Script,
        [string]$User = "root",
        [switch]$AllowFailure
    )

    $normalizedScript = $Script.Replace("`r`n", "`n").Replace("`r", "`n")
    if ($normalizedScript.Contains("`n"))
    {
        $encodedScript = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($normalizedScript))
        $normalizedScript = "printf '%s' '$encodedScript' | base64 --decode | /bin/bash -l"
    }
    Invoke-E2EWsl $Context $Distribution @("/bin/bash", "-lc", $normalizedScript) $User -AllowFailure:$AllowFailure
}

function Get-E2ESourceDistribution
{
    param(
        [Parameter(Mandatory)]$Context,
        [string]$RequestedDistribution
    )

    if (![string]::IsNullOrWhiteSpace($RequestedDistribution))
    {
        if ((Get-E2EDistributions $Context) -notcontains $RequestedDistribution)
        {
            throw "Requested WSL source distribution '$RequestedDistribution' is not registered."
        }
        return $RequestedDistribution
    }

    foreach ($distribution in Get-E2EDistributions $Context)
    {
        $probe = Invoke-E2EBash $Context $distribution 'test -x /bin/bash && test -r /etc/os-release' -AllowFailure
        if ($probe.ExitCode -eq 0)
        {
            return $distribution
        }
    }
    throw "No suitable existing WSL distribution is available as an import source. Supply -RootfsPath or -WslSourceDistro."
}

function Assert-E2EPrerequisites
{
    param(
        [Parameter(Mandatory)]$Context,
        [string]$WslSourceDistro
    )

    $checks = [ordered]@{}
    $checks.x64Windows = [Environment]::Is64BitOperatingSystem -and
        ([Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") -notmatch "ARM")
    $version = Get-E2EWslVersion $Context
    $checks.wslVersion = $null -ne $version -and $version -ge [version]"2.5.1"
    $checks.wsl2 = $false
    $checks.administrator = Test-E2EAdministrator
    $checks.rust = $null -ne (Get-Command cargo -ErrorAction SilentlyContinue)
    $checks.visualStudio = Test-Path -LiteralPath (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe")
    $checks.source = $false
    $checks.systemd = $false
    $checks.dbus = $false
    $checks.interop = $false

    if ($checks.wslVersion)
    {
        try
        {
            $source = Get-E2ESourceDistribution $Context $WslSourceDistro
            $checks.source = $true
            $verbose = Invoke-E2EProcess $Context "wsl.exe" @("--list", "--verbose") -AllowFailure
            $sourcePattern = [regex]::Escape($source)
            $checks.wsl2 = $verbose.ExitCode -eq 0 -and
                [regex]::IsMatch($verbose.Output, "(?m)^\s*\*?\s*$sourcePattern\s+.*\s2\s*$")
            $checks.systemd = (Invoke-E2EBash $Context $source 'test -d /run/systemd/system && systemctl --version >/dev/null').ExitCode -eq 0
            $checks.dbus = (Invoke-E2EBash $Context $source 'command -v dbus-daemon >/dev/null || command -v dbus-broker >/dev/null').ExitCode -eq 0
            $checks.interop = (Invoke-E2EBash $Context $source 'command -v cmd.exe >/dev/null && cmd.exe /c exit 0').ExitCode -eq 0
        }
        catch
        {
            Write-E2ELog $Context "WSL source prerequisite probe failed: $($_.Exception.Message)"
        }
    }
    foreach ($entry in $checks.GetEnumerator())
    {
        if ($entry.Value)
        {
            Add-E2EResult $Context "prerequisite.$($entry.Key)" "passed"
        }
        else
        {
            Add-E2EResult $Context "prerequisite.$($entry.Key)" "skipped" "Unavailable; full plugin loading is not attempted."
        }
    }
    [PSCustomObject]@{
        Checks = $checks
        SourceDistribution = if ($checks.source) { Get-E2ESourceDistribution $Context $WslSourceDistro } else { $null }
        FullReady = @("x64Windows", "wslVersion", "wsl2", "administrator", "rust", "visualStudio", "source", "systemd", "dbus", "interop") |
            ForEach-Object { $checks[$_] } |
            Where-Object { !$_.Equals($true) } |
            Measure-Object |
            Select-Object -ExpandProperty Count |
            ForEach-Object { $_ -eq 0 }
    }
}

function New-E2EDistributions
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$SourceDistribution,
        [string]$RootfsPath
    )

    $rootfs = if ([string]::IsNullOrWhiteSpace($RootfsPath))
    {
        Join-Path $Context.WorkRoot "source-rootfs.tar"
    }
    else
    {
        (Resolve-Path -LiteralPath $RootfsPath -ErrorAction Stop).Path
    }
    if ([string]::IsNullOrWhiteSpace($RootfsPath))
    {
        Invoke-E2EProcess $Context "wsl.exe" @("--export", $SourceDistribution, $rootfs) | Out-Null
        $Context.Resources.rootfsPath = $rootfs
        $Context.Resources.ownsRootfs = $true
    }

    $names = @("wincred-e2e-$($Context.RunId)-a", "wincred-e2e-$($Context.RunId)-b")
    foreach ($name in $names)
    {
        $root = Join-Path $Context.WorkRoot "distros\$name"
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        # Record the deterministic name before importing. A failed import can
        # still register a distro and must be cleaned up by this run only.
        Add-E2EDistributionResource $Context $name $root
        Invoke-E2EProcess $Context "wsl.exe" @("--import", $name, $root, $rootfs, "--version", "2") | Out-Null
        Set-E2EDistributionIdentity $Context $name
        Invoke-E2EBash $Context $name "printf '[boot]`nsystemd=true`n' > /etc/wsl.conf" | Out-Null
        Invoke-E2EProcess $Context "wsl.exe" @("--terminate", $name) | Out-Null
        Invoke-E2EBash $Context $name 'test -d /run/systemd/system && systemctl is-system-running --wait >/dev/null 2>&1 || test -d /run/systemd/system' | Out-Null
        Invoke-E2EBash $Context $name @'
if ! command -v apt-get >/dev/null; then
  echo "No apt-get package manager; provide a Debian/Ubuntu rootfs with libsecret test prerequisites." >&2
  exit 1
fi

if ! command -v dbus-run-session >/dev/null ||
   ! command -v secret-tool >/dev/null ||
   ! command -v cc >/dev/null ||
   ! command -v pkg-config >/dev/null ||
   ! pkg-config --exists libsecret-1 ||
   ! test -f /usr/include/libsecret-1/libsecret/secret.h; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends dbus-user-session dbus libsecret-tools libsecret-1-dev build-essential pkg-config
fi

test -f /usr/include/libsecret-1/libsecret/secret.h
useradd -m -s /bin/bash e2eone
useradd -m -s /bin/bash e2etwo
install -d -o root -g root -m 1777 /opt/wincred-e2e
'@ | Out-Null
    }
    $names
}

function Add-E2EDistributionResource
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Root
    )

    if (!$Context.Resources.distributions.Contains($Name))
    {
        $Context.Resources.distributions.Add($Name)
    }
    if (!$Context.Resources.distributionRoots.Contains($Root))
    {
        $Context.Resources.distributionRoots.Add($Root)
    }
    if (@($Context.Resources.distributionResources | Where-Object Name -eq $Name).Count -eq 0)
    {
        $Context.Resources.distributionResources.Add([PSCustomObject]@{
            Name = $Name
            Root = $Root
            DistroGuid = $null
            DistroRegistryPath = $null
            EnablementKeyPath = $null
            EnablementEnabled = $false
            EnablementVerifiedAbsent = $false
            Unregistered = $false
            StorageDeleted = $false
        })
    }
}

function Get-E2EDistributionResource
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $matches = @($Context.Resources.distributionResources | Where-Object Name -eq $Name)
    if ($matches.Count -ne 1)
    {
        throw "E2E distribution resource '$Name' is not uniquely tracked."
    }
    $matches[0]
}

function Test-E2EDisposableDistributionName
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $Name -in @(
        "wincred-e2e-$($Context.RunId)-a",
        "wincred-e2e-$($Context.RunId)-b"
    )
}

function Get-E2EDistributionRegistration
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    if (!(Test-E2EDisposableDistributionName $Context $Name))
    {
        throw "Refused to inspect a non-disposable WSL distribution."
    }
    $lxss = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Lxss"
    $matches = [Collections.Generic.List[object]]::new()
    foreach ($candidate in @(Get-ChildItem -LiteralPath $lxss -ErrorAction Stop))
    {
        try
        {
            $guid = [guid]$candidate.PSChildName.Trim("{}")
        }
        catch
        {
            continue
        }
        try
        {
            $registeredName = [string]((Get-ItemProperty -LiteralPath $candidate.PSPath -Name DistributionName -ErrorAction Stop).DistributionName)
        }
        catch
        {
            continue
        }
        if ($registeredName.Equals($Name, [StringComparison]::Ordinal))
        {
            $matches.Add([PSCustomObject]@{
                Guid = $guid.ToString("D")
                RegistryPath = $candidate.PSPath
                DistributionName = $registeredName
            })
        }
    }
    if ($matches.Count -ne 1)
    {
        throw "Disposable distribution '$Name' did not resolve to exactly one HKCU Lxss registration."
    }
    $matches[0]
}

function Set-E2EDistributionIdentity
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $resource = Get-E2EDistributionResource $Context $Name
    $registration = Get-E2EDistributionRegistration $Context $Name
    $resource.DistroGuid = $registration.Guid
    $resource.DistroRegistryPath = $registration.RegistryPath
    $resource.EnablementKeyPath = "Registry::HKEY_CURRENT_USER\Software\wincred-libsecret\WSLPlugin\Distributions\{$($registration.Guid)}"
}

function Register-E2EDistributionEnablement
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $resource = Get-E2EDistributionResource $Context $Name
    if ([string]::IsNullOrWhiteSpace($resource.DistroGuid))
    {
        Set-E2EDistributionIdentity $Context $Name
    }
    if (!(Test-Path -LiteralPath $resource.EnablementKeyPath))
    {
        throw "Distro enable did not create the tracked HKCU enablement key for '$Name'."
    }
    $resource.EnablementEnabled = $true
    $resource.EnablementVerifiedAbsent = $false
}

function Assert-E2EDistributionEnablementAbsent
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $resource = Get-E2EDistributionResource $Context $Name
    if (![string]::IsNullOrWhiteSpace($resource.EnablementKeyPath) -and
        (Test-Path -LiteralPath $resource.EnablementKeyPath))
    {
        throw "Distro disable left the tracked HKCU enablement key for '$Name'."
    }
    $resource.EnablementEnabled = $false
    $resource.EnablementVerifiedAbsent = $true
}

function Invoke-E2ETrackedEnablementCleanup
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][scriptblock]$DisableAction,
        [Parameter(Mandatory)][scriptblock]$KeyExistsAction,
        [Parameter(Mandatory)][scriptblock]$RegisteredNameAction,
        [Parameter(Mandatory)][scriptblock]$RemoveKeyAction
    )

    $errors = [Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Resource.DistroGuid))
    {
        # A failed import cannot have enabled a key because enabling occurs
        # only after the registration identity was captured.
        $Resource.EnablementVerifiedAbsent = $true
        return [PSCustomObject]@{ SafeToRemoveStorage = $true; Errors = @($errors) }
    }
    if (!(Test-E2EDisposableDistributionName $Context $Resource.Name))
    {
        $errors.Add("refused to clean a non-disposable distribution enablement key")
        return [PSCustomObject]@{ SafeToRemoveStorage = $false; Errors = @($errors) }
    }

    if ($Resource.EnablementEnabled)
    {
        try
        {
            if (!(& $DisableAction $Resource))
            {
                $errors.Add("distro disable returned a nonzero result")
            }
        }
        catch
        {
            $errors.Add("distro disable failed: $($_.Exception.Message)")
        }
    }

    $keyExists = $false
    try { $keyExists = [bool](& $KeyExistsAction $Resource) }
    catch
    {
        $errors.Add("could not verify HKCU enablement absence: $($_.Exception.Message)")
        return [PSCustomObject]@{ SafeToRemoveStorage = $false; Errors = @($errors) }
    }
    if (!$keyExists)
    {
        $Resource.EnablementEnabled = $false
        $Resource.EnablementVerifiedAbsent = $true
        return [PSCustomObject]@{ SafeToRemoveStorage = $true; Errors = @($errors) }
    }

    $registeredName = $null
    try { $registeredName = [string](& $RegisteredNameAction $Resource) }
    catch { $errors.Add("could not verify the tracked distro identity: $($_.Exception.Message)") }
    if ([string]::IsNullOrWhiteSpace($registeredName) -or
        !$registeredName.Equals($Resource.Name, [StringComparison]::Ordinal))
    {
        $errors.Add("preserved a changed or foreign HKCU enablement key")
        return [PSCustomObject]@{ SafeToRemoveStorage = $false; Errors = @($errors) }
    }

    if ($Resource.EnablementEnabled)
    {
        $errors.Add("distro disable reported success but the tracked HKCU enablement key remained")
    }
    try
    {
        if (!(& $RemoveKeyAction $Resource))
        {
            $errors.Add("could not remove the tracked HKCU enablement key")
        }
    }
    catch
    {
        $errors.Add("could not remove the tracked HKCU enablement key: $($_.Exception.Message)")
    }

    try { $keyExists = [bool](& $KeyExistsAction $Resource) }
    catch
    {
        $errors.Add("could not verify HKCU enablement removal: $($_.Exception.Message)")
        $keyExists = $true
    }
    if ($keyExists)
    {
        $errors.Add("tracked HKCU enablement key remains")
    }
    if (!$keyExists)
    {
        $Resource.EnablementEnabled = $false
        $Resource.EnablementVerifiedAbsent = $true
    }
    [PSCustomObject]@{
        SafeToRemoveStorage = !$keyExists
        Errors = @($errors)
    }
}

function Clear-E2EDistributionEnablement
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Resource,
        [string]$CliPath
    )

    $processInvoker = ${function:Invoke-E2EProcess}
    if ($null -eq $processInvoker)
    {
        throw "Invoke-E2EProcess must be available before distribution enablement cleanup."
    }
    $disableAction = {
        param($TrackedResource)
        if ([string]::IsNullOrWhiteSpace($CliPath) -or !(Test-Path -LiteralPath $CliPath))
        {
            return $false
        }
        $result = & $processInvoker $Context $CliPath @("distro", "disable", $TrackedResource.Name) -AllowFailure
        $result.ExitCode -eq 0
    }.GetNewClosure()
    $keyExistsAction = {
        param($TrackedResource)
        Test-Path -LiteralPath $TrackedResource.EnablementKeyPath
    }
    $registeredNameAction = {
        param($TrackedResource)
        [string]((Get-ItemProperty -LiteralPath $TrackedResource.DistroRegistryPath -Name DistributionName -ErrorAction Stop).DistributionName)
    }
    $removeKeyAction = {
        param($TrackedResource)
        Remove-Item -LiteralPath $TrackedResource.EnablementKeyPath -Recurse -Force -ErrorAction Stop
        $true
    }
    Invoke-E2ETrackedEnablementCleanup `
        -Context $Context `
        -Resource $Resource `
        -DisableAction $disableAction `
        -KeyExistsAction $keyExistsAction `
        -RegisteredNameAction $registeredNameAction `
        -RemoveKeyAction $removeKeyAction
}

function Add-E2ENativeCredentialApi
{
    if ("WinCredE2E.NativeCredentials" -as [type])
    {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace WinCredE2E {
  public static class NativeCredentials {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    internal struct CREDENTIAL {
      public uint Flags; public uint Type; public string TargetName; public string Comment;
      public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
      public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist;
      public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
    }
    [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr credentials);
    [DllImport("Advapi32.dll", SetLastError=true)]
    static extern void CredFree(IntPtr buffer);
    [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredWrite(ref CREDENTIAL credential, uint flags);
    [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredDelete(string target, uint type, uint flags);
    static void Check(bool ok) { if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
    static void Wipe(IntPtr blob, uint size) {
      if (blob == IntPtr.Zero) return;
      for (int i = 0; i < size; i++) Marshal.WriteByte(blob, i, 0);
    }
    static void WipeCredential(IntPtr credential) {
      if (credential == IntPtr.Zero) return;
      var c = (CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL));
      Wipe(c.CredentialBlob, c.CredentialBlobSize);
    }
    static string Hash(IntPtr blob, uint size) {
      byte[] bytes = new byte[size]; if (size > 0) Marshal.Copy(blob, bytes, 0, (int)size);
      try {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
      } finally { Array.Clear(bytes, 0, bytes.Length); }
    }
    static byte[] ReadBlob(string target) {
      IntPtr pointer; Check(CredRead(target, 1, 0, out pointer));
      try {
        var c = (CREDENTIAL)Marshal.PtrToStructure(pointer, typeof(CREDENTIAL));
        byte[] bytes = new byte[c.CredentialBlobSize];
        if (bytes.Length > 0) Marshal.Copy(c.CredentialBlob, bytes, 0, bytes.Length);
        return bytes;
      } finally { WipeCredential(pointer); CredFree(pointer); }
    }
    public static string[] EnumerateTargets(string prefix) {
      uint count; IntPtr list;
      if (!CredEnumerate(prefix + "*", 0, out count, out list)) {
        int error = Marshal.GetLastWin32Error();
        if (error == 1168) return new string[0];
        throw new System.ComponentModel.Win32Exception(error);
      }
      try { var values = new List<string>(); for (int i = 0; i < count; i++) {
        var p = Marshal.ReadIntPtr(list, i * IntPtr.Size);
        var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
        values.Add(c.TargetName);
      } return values.ToArray(); } finally {
        for (int i = 0; i < count; i++) WipeCredential(Marshal.ReadIntPtr(list, i * IntPtr.Size));
        CredFree(list);
      }
    }
    public static void Write(string target, byte[] value) {
      IntPtr blob = Marshal.AllocCoTaskMem(value.Length);
      try { Marshal.Copy(value, 0, blob, value.Length); var c = new CREDENTIAL {
        Type=1, TargetName=target, UserName="wincred-e2e", CredentialBlobSize=(uint)value.Length,
        CredentialBlob=blob, Persist=1 }; Check(CredWrite(ref c, 0)); } finally { Marshal.FreeCoTaskMem(blob); }
    }
    public static string Fingerprint(string target) {
      byte[] bytes = ReadBlob(target);
      try {
        using (var sha = SHA256.Create())
          return bytes.Length + ":" + BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
      } finally { Array.Clear(bytes, 0, bytes.Length); }
    }
    public static void Delete(string target) { if (!CredDelete(target, 1, 0)) {
      int error = Marshal.GetLastWin32Error(); if (error != 1168) throw new System.ComponentModel.Win32Exception(error); } }

    sealed class CborValue {
      internal string Text;
      internal byte[] Bytes;
      internal Dictionary<string, CborValue> Map;
    }
    static void Need(byte[] data, int offset, int count) {
      if (offset < 0 || count < 0 || offset > data.Length - count) throw new FormatException("truncated CBOR metadata");
    }
    static long Length(byte[] data, ref int offset, int additional) {
      if (additional < 24) return additional;
      if (additional == 31) return -1;
      int count = additional == 24 ? 1 : additional == 25 ? 2 : additional == 26 ? 4 : additional == 27 ? 8 : -2;
      if (count < 0) throw new FormatException("invalid CBOR length");
      Need(data, offset, count);
      ulong result = 0;
      for (int i = 0; i < count; i++) result = (result << 8) | data[offset++];
      if (result > Int32.MaxValue) throw new FormatException("oversized CBOR metadata");
      return (long)result;
    }
    static void ConsumeBreak(byte[] data, ref int offset) {
      Need(data, offset, 1);
      if (data[offset++] != 0xff) throw new FormatException("unterminated CBOR metadata");
    }
    static CborValue ReadValue(byte[] data, ref int offset, int depth) {
      if (depth > 32) throw new FormatException("nested CBOR metadata");
      Need(data, offset, 1);
      int initial = data[offset++], major = initial >> 5, additional = initial & 31;
      var value = new CborValue();
      if (major == 7) {
        int simpleBytes = additional == 24 ? 1 : additional == 25 ? 2 : additional == 26 ? 4 : additional == 27 ? 8 : 0;
        if (additional == 31) throw new FormatException("unexpected CBOR break");
        Need(data, offset, simpleBytes);
        offset += simpleBytes;
        return value;
      }
      long length = Length(data, ref offset, additional);
      if (major == 0 || major == 1) return value;
      if (major == 2 || major == 3) {
        if (length < 0) throw new FormatException("indefinite CBOR strings are unsupported");
        Need(data, offset, (int)length);
        if (major == 2) {
          value.Bytes = new byte[(int)length];
          Buffer.BlockCopy(data, offset, value.Bytes, 0, (int)length);
        } else value.Text = Encoding.UTF8.GetString(data, offset, (int)length);
        offset += (int)length;
        return value;
      }
      if (major == 4) {
        if (length < 0) {
          while (true) { Need(data, offset, 1); if (data[offset] == 0xff) { offset++; break; } ReadValue(data, ref offset, depth + 1); }
        } else for (int i = 0; i < length; i++) ReadValue(data, ref offset, depth + 1);
        return value;
      }
      if (major == 5) {
        value.Map = new Dictionary<string, CborValue>(StringComparer.Ordinal);
        if (length < 0) {
          while (true) {
            Need(data, offset, 1); if (data[offset] == 0xff) { offset++; break; }
            CborValue key = ReadValue(data, ref offset, depth + 1);
            CborValue mapped = ReadValue(data, ref offset, depth + 1);
            if (key.Text != null) value.Map[key.Text] = mapped;
          }
        } else for (int i = 0; i < length; i++) {
          CborValue key = ReadValue(data, ref offset, depth + 1);
          CborValue mapped = ReadValue(data, ref offset, depth + 1);
          if (key.Text != null) value.Map[key.Text] = mapped;
        }
        return value;
      }
      if (major == 6) return ReadValue(data, ref offset, depth + 1);
      throw new FormatException("unknown CBOR metadata type");
    }
    static Dictionary<string, CborValue> RootMap(byte[] blob) {
      int offset = 0; CborValue root = ReadValue(blob, ref offset, 0);
      if (offset != blob.Length || root.Map == null) throw new FormatException("invalid CBOR metadata map");
      return root.Map;
    }
    static string Text(Dictionary<string, CborValue> map, string name) {
      CborValue value; return map != null && map.TryGetValue(name, out value) ? value.Text : null;
    }
    static string UuidText(Dictionary<string, CborValue> map, string name) {
      CborValue value;
      if (map == null || !map.TryGetValue(name, out value)) return null;
      if (value.Text != null) return value.Text.ToLowerInvariant();
      if (value.Bytes != null && value.Bytes.Length == 16) {
        string hex = BitConverter.ToString(value.Bytes).Replace("-", "").ToLowerInvariant();
        return hex.Substring(0, 8) + "-" + hex.Substring(8, 4) + "-" +
          hex.Substring(12, 4) + "-" + hex.Substring(16, 4) + "-" + hex.Substring(20, 12);
      }
      return null;
    }
    static byte[] MetadataBlob(string target, string pattern) {
      if (!Regex.IsMatch(target, pattern, RegexOptions.CultureInvariant))
        throw new ArgumentException("target is not project metadata", "target");
      return ReadBlob(target);
    }
    public static bool ItemMetadataBlobHasRunMarker(byte[] blob, string runId) {
      var root = RootMap(blob);
      CborValue attributes;
      return root.TryGetValue("attributes", out attributes) && attributes.Map != null &&
        String.Equals(Text(attributes.Map, "e2e-run"), runId, StringComparison.Ordinal);
    }
    public static bool ItemHasRunMarker(string target, string runId) {
      return ItemMetadataBlobHasRunMarker(
        MetadataBlob(target, @"^WinCredLibSecret/v1/item/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/meta$"),
        runId
      );
    }
    public static bool CollectionHasRunMarker(string target, string runId) {
      var root = RootMap(MetadataBlob(target, @"^WinCredLibSecret/v1/collection/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));
      return String.Equals(Text(root, "label"), "WinCred E2E " + runId, StringComparison.Ordinal);
    }
    public static string[] AliasMetadataBlob(byte[] blob) {
      var root = RootMap(blob);
      return new [] { Text(root, "name"), UuidText(root, "collection_id") };
    }
    public static string[] ReadAliasMetadata(string target) {
      return AliasMetadataBlob(MetadataBlob(target, @"^WinCredLibSecret/v1/alias/[A-Za-z0-9_-]+$"));
    }
  }
}
'@
}

function Get-E2EProjectCredentialTargets
{
    @(Get-E2EProjectCredentialInventory | ForEach-Object Target)
}

function Get-E2EProjectCredentialInventory
{
    Add-E2ENativeCredentialApi
    @(
        [WinCredE2E.NativeCredentials]::EnumerateTargets("WinCredLibSecret/v1/") |
            Sort-Object |
            ForEach-Object {
                [PSCustomObject]@{
                    Target = $_
                    Hash = [WinCredE2E.NativeCredentials]::Fingerprint($_)
                }
            }
    )
}

function ConvertTo-E2EInventoryMap
{
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Inventory,
        [Parameter(Mandatory)][string]$Name
    )

    $map = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    foreach ($entry in @($Inventory))
    {
        if ($null -eq $entry)
        {
            throw "$Name inventory contains an empty entry."
        }
        $targetProperty = $entry.PSObject.Properties["Target"]
        $hashProperty = $entry.PSObject.Properties["Hash"]
        if ($null -eq $targetProperty -or $null -eq $hashProperty)
        {
            throw "$Name inventory contains a record without target and hash."
        }
        $target = [string]$targetProperty.Value
        $hash = [string]$hashProperty.Value
        if (
            [string]::IsNullOrWhiteSpace($target) -or
            !$target.StartsWith("WinCredLibSecret/v1/", [StringComparison]::Ordinal) -or
            $hash -notmatch '^\d+:[0-9a-f]{64}$'
        )
        {
            throw "$Name inventory contains an invalid sanitized record."
        }
        if ($map.ContainsKey($target))
        {
            throw "$Name inventory contains duplicate target names."
        }
        $map.Add($target, $hash)
    }
    $map
}

function Get-E2EExpectedCredentialInventory
{
    param([Parameter(Mandatory)]$Context)

    $initial = ConvertTo-E2EInventoryMap -Inventory @($Context.Resources.initialCredentialInventory) -Name "initial"
    $preserved = ConvertTo-E2EInventoryMap -Inventory @($Context.Resources.preservedCredentialInventory) -Name "preserved"
    foreach ($entry in @($Context.Resources.preservedCredentialInventory))
    {
        $target = [string]$entry.Target
        $hash = [string]$entry.Hash
        if ($initial.ContainsKey($target) -and $initial[$target] -ne $hash)
        {
            throw "A preserved concurrent fixture conflicts with the initial inventory."
        }
        if (!$initial.ContainsKey($target))
        {
            $initial.Add($target, $hash)
        }
    }
    @(
        $initial.Keys |
            Sort-Object |
            ForEach-Object { [PSCustomObject]@{ Target = $_; Hash = $initial[$_] } }
    )
}

function Assert-E2EInventoryEquals
{
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actual,
        [string]$ExpectedName = "expected",
        [string]$ActualName = "actual"
    )

    $expectedMap = ConvertTo-E2EInventoryMap -Inventory @($Expected) -Name $ExpectedName
    $actualMap = ConvertTo-E2EInventoryMap -Inventory @($Actual) -Name $ActualName
    if ($expectedMap.Count -ne $actualMap.Count)
    {
        throw "Sanitized credential inventory count differs ($ExpectedName=$($expectedMap.Count), $ActualName=$($actualMap.Count))."
    }
    foreach ($target in $expectedMap.Keys)
    {
        if (!$actualMap.ContainsKey($target) -or $actualMap[$target] -ne $expectedMap[$target])
        {
            throw "Sanitized credential inventory differs from $ExpectedName."
        }
    }
}

function Write-E2EInventory
{
    param([Parameter(Mandatory)]$Context)

    if (!$Context.Resources.inventoryInitialized)
    {
        return
    }

    $document = [ordered]@{
        schemaVersion = 1
        runId = $Context.RunId
        initial = @($Context.Resources.initialCredentialInventory)
        preserved = @($Context.Resources.preservedCredentialInventory)
        final = $null
    }
    if ($Context.Resources.inventoryFinalized)
    {
        # An empty array emitted from an if expression is collapsed to $null.
        # Assigning it directly preserves the completed empty inventory as [].
        $document.final = @($Context.Resources.finalCredentialInventory)
    }
    $json = $document | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(
        $Context.InventoryPath,
        $json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
}

function Initialize-E2EInventory
{
    param([Parameter(Mandatory)]$Context)

    if ($Context.Resources.inventoryInitialized)
    {
        return
    }
    $Context.Resources.initialCredentialInventory = @(Get-E2EProjectCredentialInventory)
    $Context.Resources.inventoryInitialized = $true
    Write-E2EInventory $Context
}

function Complete-E2EInventory
{
    param([Parameter(Mandatory)]$Context)

    if (!$Context.Resources.inventoryInitialized)
    {
        return
    }
    $Context.Resources.finalCredentialInventory = @(Get-E2EProjectCredentialInventory)
    $Context.Resources.inventoryFinalized = $true
    Write-E2EInventory $Context
    $expectedInventory = @(Get-E2EExpectedCredentialInventory $Context)
    Assert-E2EInventoryEquals `
        -Expected $expectedInventory `
        -Actual @($Context.Resources.finalCredentialInventory) `
        -ExpectedName "initial plus preserved concurrent fixtures" `
        -ActualName "final"
}

function Read-E2EInventoryFile
{
    param([Parameter(Mandatory)][string]$Path)

    if (!(Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "E2E inventory file '$Path' does not exist."
    }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 1MB)
    {
        throw "E2E inventory file '$Path' is unexpectedly large."
    }
    try
    {
        $document = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch
    {
        throw "E2E inventory file '$Path' is corrupt."
    }
    if (
        $null -eq $document -or
        [int]$document.schemaVersion -ne 1 -or
        [string]$document.runId -notmatch '^[0-9a-f]{32}$' -or
        $null -eq $document.PSObject.Properties["initial"] -or
        $null -eq $document.PSObject.Properties["preserved"] -or
        $null -eq $document.PSObject.Properties["final"] -or
        $null -eq $document.final
    )
    {
        throw "E2E inventory file '$Path' has an invalid schema."
    }
    $initial = @($document.initial | ForEach-Object {
        [PSCustomObject]@{ Target = $_.target; Hash = $_.hash }
    })
    $preserved = @($document.preserved | ForEach-Object {
        [PSCustomObject]@{ Target = $_.target; Hash = $_.hash }
    })
    $final = @($document.final | ForEach-Object {
        [PSCustomObject]@{ Target = $_.target; Hash = $_.hash }
    })
    ConvertTo-E2EInventoryMap -Inventory $initial -Name "initial inventory file" | Out-Null
    ConvertTo-E2EInventoryMap -Inventory $preserved -Name "preserved inventory file" | Out-Null
    ConvertTo-E2EInventoryMap -Inventory $final -Name "final inventory file" | Out-Null
    [PSCustomObject]@{
        RunId = [string]$document.runId
        Initial = $initial
        Preserved = $preserved
        Final = $final
    }
}

function Get-E2EProjectMetadataInfo
{
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$RunId
    )

    try
    {
        if ($Target -match '^WinCredLibSecret/v1/item/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/meta$')
        {
            return [PSCustomObject]@{
                Kind = "item"
                RunOwned = [WinCredE2E.NativeCredentials]::ItemHasRunMarker($Target, $RunId)
                AliasName = $null
                CollectionId = $null
            }
        }
        if ($Target -match '^WinCredLibSecret/v1/collection/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        {
            return [PSCustomObject]@{
                Kind = "collection"
                RunOwned = [WinCredE2E.NativeCredentials]::CollectionHasRunMarker($Target, $RunId)
                AliasName = $null
                CollectionId = $null
            }
        }
        if ($Target -match '^WinCredLibSecret/v1/alias/[A-Za-z0-9_-]+$')
        {
            $alias = [WinCredE2E.NativeCredentials]::ReadAliasMetadata($Target)
            return [PSCustomObject]@{
                Kind = "alias"
                RunOwned = $false
                AliasName = $alias[0]
                CollectionId = $alias[1]
            }
        }
    }
    catch
    {
        # Corrupt metadata is never a cleanup authority. It is preserved for
        # the broker's recovery path. Do not log target blobs or their bytes.
    }
    $null
}

function New-E2ERunOwnedTargetPlan
{
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Inventory,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][scriptblock]$InspectMetadata
    )

    $itemPattern = '^WinCredLibSecret/v1/item/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/meta$'
    $secretPattern = '^WinCredLibSecret/v1/item/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/secret/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $collectionPattern = '^WinCredLibSecret/v1/collection/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
    $aliasPattern = '^WinCredLibSecret/v1/alias/[A-Za-z0-9_-]+$'
    $items = @{}
    $collections = @{}
    $aliases = [Collections.Generic.List[object]]::new()
    $knownTargets = @($Inventory | ForEach-Object Target)

    foreach ($target in $knownTargets)
    {
        if ($target -match $itemPattern)
        {
            $itemId = $Matches[1]
            $metadata = & $InspectMetadata $target
            if ($null -ne $metadata -and $metadata.Kind -eq "item" -and $metadata.RunOwned)
            {
                $items[$itemId] = [PSCustomObject]@{
                    Id = $itemId
                    MetadataTarget = $target
                    SecretTargets = [Collections.Generic.List[string]]::new()
                }
            }
        }
        elseif ($target -match $collectionPattern)
        {
            $collectionId = $Matches[1]
            $metadata = & $InspectMetadata $target
            if ($null -ne $metadata -and $metadata.Kind -eq "collection" -and $metadata.RunOwned)
            {
                $collections[$collectionId] = $target
            }
        }
    }
    foreach ($target in $knownTargets)
    {
        if ($target -match $secretPattern)
        {
            $itemId = $Matches[1]
            if ($items.ContainsKey($itemId))
            {
                $items[$itemId].SecretTargets.Add($target)
            }
        }
        elseif ($target -match $aliasPattern)
        {
            $metadata = & $InspectMetadata $target
            if (
                $null -ne $metadata -and
                $metadata.Kind -eq "alias" -and
                $collections.ContainsKey([string]$metadata.CollectionId)
            )
            {
                $aliases.Add([PSCustomObject]@{
                    Target = $target
                    CollectionId = [string]$metadata.CollectionId
                })
            }
        }
    }
    $targets = [Collections.Generic.List[string]]::new()
    foreach ($item in $items.Values)
    {
        foreach ($target in $item.SecretTargets) { $targets.Add($target) }
        $targets.Add($item.MetadataTarget)
    }
    foreach ($alias in $aliases) { $targets.Add($alias.Target) }
    foreach ($target in $collections.Values) { $targets.Add($target) }
    [PSCustomObject]@{
        Items = @($items.Values)
        Aliases = @($aliases)
        Collections = @(
            $collections.Keys |
                Sort-Object |
                ForEach-Object { [PSCustomObject]@{ Id = $_; Target = $collections[$_] } }
        )
        Targets = @($targets | Sort-Object -Unique)
    }
}

function Get-E2ERunOwnedTargetPlan
{
    param([Parameter(Mandatory)]$Context)

    $inventory = @(Get-E2EProjectCredentialInventory)
    New-E2ERunOwnedTargetPlan -Inventory $inventory -RunId $Context.RunId -InspectMetadata {
        param($Target)
        Get-E2EProjectMetadataInfo $Target $Context.RunId
    }
}

function Test-E2EItemMetadataOwnership
{
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$RunId
    )

    try
    {
        [WinCredE2E.NativeCredentials]::ItemHasRunMarker($Target, $RunId)
    }
    catch
    {
        $false
    }
}

function Test-E2ECollectionMetadataOwnership
{
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$RunId
    )

    try
    {
        [WinCredE2E.NativeCredentials]::CollectionHasRunMarker($Target, $RunId)
    }
    catch
    {
        $false
    }
}

function Test-E2EAliasOwnership
{
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$CollectionId
    )

    try
    {
        $alias = [WinCredE2E.NativeCredentials]::ReadAliasMetadata($Target)
        $alias[1] -eq $CollectionId
    }
    catch
    {
        $false
    }
}

function Remove-E2ERunOwnedCredentials
{
    param([Parameter(Mandatory)]$Context)

    $plan = Get-E2ERunOwnedTargetPlan $Context
    $Context.Resources.runOwnedCredentialTargets.Clear()
    foreach ($target in $plan.Targets)
    {
        $Context.Resources.runOwnedCredentialTargets.Add($target)
    }

    # Delete generation credentials while their marker-bearing item metadata
    # still exists, then revalidate immediately before removing the metadata.
    foreach ($item in $plan.Items)
    {
        if (Test-E2EItemMetadataOwnership $item.MetadataTarget $Context.RunId)
        {
            foreach ($target in $item.SecretTargets)
            {
                [WinCredE2E.NativeCredentials]::Delete($target)
            }
            if (Test-E2EItemMetadataOwnership $item.MetadataTarget $Context.RunId)
            {
                [WinCredE2E.NativeCredentials]::Delete($item.MetadataTarget)
            }
        }
    }
    foreach ($alias in $plan.Aliases)
    {
        if (Test-E2EAliasOwnership $alias.Target $alias.CollectionId)
        {
            [WinCredE2E.NativeCredentials]::Delete($alias.Target)
        }
    }
    foreach ($collection in $plan.Collections)
    {
        if (Test-E2ECollectionMetadataOwnership $collection.Target $Context.RunId)
        {
            [WinCredE2E.NativeCredentials]::Delete($collection.Target)
        }
    }
}

function New-E2EUnrelatedCredential
{
    param([Parameter(Mandatory)]$Context)

    Add-E2ENativeCredentialApi
    $target = "WinCredE2E-Unrelated/$($Context.RunId)"
    [WinCredE2E.NativeCredentials]::Write($target, [Text.Encoding]::UTF8.GetBytes("e2e-seed"))
    $Context.Resources.seededCredential = [PSCustomObject]@{
        Target = $target
        Fingerprint = [WinCredE2E.NativeCredentials]::Fingerprint($target)
    }
}

function Assert-E2EWinCredState
{
    param([Parameter(Mandatory)]$Context)

    $owned = Get-E2ERunOwnedTargetPlan $Context
    if ($owned.Items.Count -eq 0 -or
        @($owned.Items | ForEach-Object { $_.SecretTargets }).Count -eq 0)
    {
        throw "Credential Manager inventory did not contain run-marked metadata and generation credentials."
    }
    $seed = $Context.Resources.seededCredential
    if ($null -eq $seed -or [WinCredE2E.NativeCredentials]::Fingerprint($seed.Target) -ne $seed.Fingerprint)
    {
        throw "The unrelated seeded Windows credential changed."
    }
}

function Remove-E2EResources
{
    param([Parameter(Mandatory)]$Context)

    $errors = [System.Collections.Generic.List[string]]::new()
    $cli = Join-Path $Context.RepositoryRoot "artifacts\Release\windows\wincred-libsecret.exe"
    foreach ($resource in @($Context.Resources.distributionResources))
    {
        $distribution = $resource.Name
        try
        {
            $repoPath = Get-E2EWslPath $Context $distribution $Context.RepositoryRoot
            Invoke-E2EBash $Context $distribution "dbus-run-session -- bash '$repoPath/tests/e2e/run-linux-e2e.sh' --mode cleanup --run-id '$($Context.RunId)' --work-root /opt/wincred-e2e" -AllowFailure | Out-Null
        }
        catch
        {
            $errors.Add("distro Linux cleanup ${distribution}: $($_.Exception.Message)")
        }
        try
        {
            $enablement = Clear-E2EDistributionEnablement $Context $resource $cli
            foreach ($error in @($enablement.Errors))
            {
                $errors.Add("distro enablement ${distribution}: $error")
            }
        }
        catch
        {
            $resource.EnablementVerifiedAbsent = $false
            $errors.Add("distro enablement ${distribution}: $($_.Exception.Message)")
        }
    }
    if ($Context.Resources.inventoryInitialized)
    {
        try { Remove-E2ERunOwnedCredentials $Context }
        catch { $errors.Add("run-owned credential cleanup: $($_.Exception.Message)") }
    }
    if ($null -ne $Context.Resources.seededCredential)
    {
        try
        {
            if ([WinCredE2E.NativeCredentials]::Fingerprint($Context.Resources.seededCredential.Target) -eq $Context.Resources.seededCredential.Fingerprint)
            {
                [WinCredE2E.NativeCredentials]::Delete($Context.Resources.seededCredential.Target)
            }
        }
        catch { $errors.Add("seed cleanup: $($_.Exception.Message)") }
    }

    if (
        !$Context.Resources.pluginStateExistedBefore -and
        $null -ne $Context.Resources.pluginState -and
        (Test-Path -LiteralPath $Context.Resources.pluginState)
    )
    {
        try { & (Join-Path $Context.RepositoryRoot "scripts\Uninstall-DevPlugin.ps1") -RestartWslService }
        catch { $errors.Add("plugin cleanup: $($_.Exception.Message)") }
    }
    if ($null -ne $Context.Resources.certificateState -and (Test-Path -LiteralPath $Context.Resources.certificateState))
    {
        try { & (Join-Path $Context.RepositoryRoot "scripts\Remove-DevSigningCertificate.ps1") -StatePath $Context.Resources.certificateState }
        catch { $errors.Add("certificate cleanup: $($_.Exception.Message)") }
    }
    $certificateDirectory = Join-Path $Context.WorkRoot "dev-signing"
    if (Test-Path -LiteralPath $certificateDirectory)
    {
        try { Remove-Item -LiteralPath $certificateDirectory -Recurse -Force -ErrorAction Stop }
        catch { $errors.Add("remove certificate state: $($_.Exception.Message)") }
    }

    foreach ($resource in @($Context.Resources.distributionResources))
    {
        $distribution = $resource.Name
        if (!$resource.EnablementVerifiedAbsent)
        {
            $errors.Add("unregister ${distribution}: skipped because the tracked HKCU enablement key was not verified absent")
            continue
        }
        if (!$resource.Unregistered)
        {
            try
            {
                $result = Invoke-E2EProcess $Context "wsl.exe" @("--unregister", $distribution) -AllowFailure
                if ($result.ExitCode -ne 0 -and (Get-E2EDistributions $Context) -contains $distribution)
                {
                    throw "wsl.exe --unregister exited with $($result.ExitCode)."
                }
                $resource.Unregistered = $true
            }
            catch
            {
                $errors.Add("unregister ${distribution}: $($_.Exception.Message)")
            }
        }
        if ($resource.Unregistered -and !$resource.StorageDeleted)
        {
            try
            {
                if (Test-Path -LiteralPath $resource.Root)
                {
                    Remove-Item -LiteralPath $resource.Root -Recurse -Force -ErrorAction Stop
                }
                $resource.StorageDeleted = $true
            }
            catch
            {
                $errors.Add("remove distro storage ${distribution}: $($_.Exception.Message)")
            }
        }
    }
    if ($Context.Resources.ownsRootfs -and (Test-Path -LiteralPath $Context.Resources.rootfsPath))
    {
        try { Remove-Item -LiteralPath $Context.Resources.rootfsPath -Force -ErrorAction Stop }
        catch { $errors.Add("remove exported rootfs: $($_.Exception.Message)") }
    }
    if ($errors.Count -gt 0)
    {
        throw ($errors -join "; ")
    }
}

function Get-E2EInventoryFromJUnitReport
{
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$ResultDirectory
    )

    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = $null
    try
    {
        $reader = [Xml.XmlReader]::Create($ReportPath, $settings)
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
    }
    catch
    {
        throw "E2E JUnit report '$ReportPath' is invalid XML."
    }
    finally
    {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    $suite = $document.SelectSingleNode("/*[local-name()='testsuite']")
    if ($null -eq $suite)
    {
        throw "E2E JUnit report '$ReportPath' does not have a testsuite root."
    }
    $testCases = @($suite.SelectNodes("./*[local-name()='testcase']"))
    if ($testCases.Count -eq 0)
    {
        throw "E2E JUnit report '$ReportPath' contains no test cases."
    }
    $cleanup = @($testCases | Where-Object { $_.GetAttribute("name") -eq "e2e.cleanup" })
    if (
        $cleanup.Count -ne 1 -or
        $null -ne $cleanup[0].SelectSingleNode("./*[local-name()='failure']") -or
        $null -ne $cleanup[0].SelectSingleNode("./*[local-name()='skipped']")
    )
    {
        throw "E2E cleanup did not complete successfully according to '$([IO.Path]::GetFileName($ReportPath))'."
    }
    if (
        @(
            $testCases | Where-Object {
                $null -ne $_.SelectSingleNode("./*[local-name()='failure']") -or
                $null -ne $_.SelectSingleNode("./*[local-name()='skipped']")
            }
        ).Count -gt 0
    )
    {
        throw "The privileged E2E report contains failed or skipped test cases."
    }
    $property = $suite.SelectSingleNode("./*[local-name()='properties']/*[local-name()='property' and @name='e2e.inventory']")
    if ($null -eq $property)
    {
        throw "E2E JUnit report does not reference a sanitized inventory."
    }
    $inventoryName = $property.GetAttribute("value")
    $reportName = [IO.Path]::GetFileName($ReportPath)
    $inventoryMatch = [regex]::Match($inventoryName, '^e2e-([0-9a-f]{32})\.inventory\.json$')
    $reportMatch = [regex]::Match($reportName, '^e2e-([0-9a-f]{32})\.junit\.xml$')
    if (
        !$inventoryMatch.Success -or
        !$reportMatch.Success -or
        $reportMatch.Groups[1].Value -ne $inventoryMatch.Groups[1].Value -or
        [IO.Path]::IsPathRooted($inventoryName) -or
        [IO.Path]::GetFileName($inventoryName) -ne $inventoryName
    )
    {
        throw "E2E JUnit report references an unsafe inventory path."
    }
    $inventoryPath = Join-Path $ResultDirectory $inventoryName
    $inventory = Read-E2EInventoryFile $inventoryPath
    if ($inventory.RunId -ne $inventoryMatch.Groups[1].Value)
    {
        throw "E2E inventory run ID does not match its JUnit reference."
    }
    $context = [PSCustomObject]@{
        Resources = [ordered]@{
            initialCredentialInventory = $inventory.Initial
            preservedCredentialInventory = $inventory.Preserved
        }
    }
    $expectedInventory = @(Get-E2EExpectedCredentialInventory $context)
    Assert-E2EInventoryEquals `
        -Expected $expectedInventory `
        -Actual @($inventory.Final) `
        -ExpectedName "initial inventory plus preserved concurrent fixtures" `
        -ActualName "final inventory"
    $inventory
}

function Write-E2EJUnit
{
    param([Parameter(Mandatory)]$Context)

    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $writer = [Xml.XmlWriter]::Create($Context.JUnitPath, $settings)
    try
    {
        $writer.WriteStartDocument()
        $writer.WriteStartElement("testsuite")
        $writer.WriteAttributeString("name", "wincred-libsecret-wsl-e2e")
        $writer.WriteAttributeString("tests", [string]$Context.Results.Count)
        $writer.WriteAttributeString("failures", [string]@($Context.Results | Where-Object Status -eq "failed").Count)
        $writer.WriteAttributeString("skipped", [string]@($Context.Results | Where-Object Status -eq "skipped").Count)
        if ($Context.Resources.inventoryInitialized)
        {
            $writer.WriteStartElement("properties")
            $writer.WriteStartElement("property")
            $writer.WriteAttributeString("name", "e2e.inventory")
            $writer.WriteAttributeString("value", [IO.Path]::GetFileName($Context.InventoryPath))
            $writer.WriteEndElement()
            $writer.WriteEndElement()
        }
        foreach ($result in $Context.Results)
        {
            $writer.WriteStartElement("testcase")
            $writer.WriteAttributeString("name", $result.Name)
            if ($result.Status -eq "skipped")
            {
                $writer.WriteStartElement("skipped")
                $writer.WriteAttributeString("message", $result.Detail)
                $writer.WriteEndElement()
            }
            elseif ($result.Status -eq "failed")
            {
                $writer.WriteStartElement("failure")
                $writer.WriteAttributeString("message", $result.Detail)
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally
    {
        $writer.Dispose()
    }
}
