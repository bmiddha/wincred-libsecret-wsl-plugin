[CmdletBinding()]
param(
    [string[]]$Distro,
    [switch]$SkipBuild,
    [switch]$KeepExistingSecretService
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

Assert-Administrator

$configuration = "Release"
$windowsArtifacts = Join-Path $repoRoot "artifacts\$configuration\windows"
$pluginArtifact = Join-Path $windowsArtifacts "wincred-libsecret-wsl-plugin.dll"
$cliArtifact = Join-Path $windowsArtifacts "wincred-libsecret.exe"
$brokerArtifact = Join-Path $windowsArtifacts "wincred-libsecret-broker.exe"
$msi = Join-Path $repoRoot "packages\$configuration\wincred-libsecret-wsl-plugin.msi"
$installDirectory = Join-Path $env:ProgramFiles "WinCredLibsecret"
$installedCli = Join-Path $installDirectory "wincred-libsecret.exe"
$installedPlugin = Join-Path $installDirectory "wincred-libsecret-wsl-plugin.dll"

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$productState = Join-Path $programData "WinCredLibsecret"
$localInstallState = Join-Path $productState "LocalInstall"
$certificateState = Join-Path $localInstallState "certificate-state.json"

$plugins = Get-ItemProperty -LiteralPath $script:PluginRegistryPath -ErrorAction SilentlyContinue
$foreignPlugins = @(
    if ($null -ne $plugins)
    {
        $plugins.PSObject.Properties |
            Where-Object {
                $_.Name -notmatch "^PS" -and
                $_.Name -ne $script:PluginValueName
            }
    }
)
$skipPluginRegistration = $foreignPlugins.Count -gt 0
if ($skipPluginRegistration)
{
    Write-Warning "Existing WSL plugin(s) detected: $($foreignPlugins.Name -join ', '). The installer will preserve them and skip WinCred lifecycle-plugin registration."
}

if (!$SkipBuild)
{
    & (Join-Path $PSScriptRoot "build.ps1") -Configuration $configuration
    if ($LASTEXITCODE -ne 0)
    {
        throw "Release build failed."
    }
}

foreach ($artifact in @($pluginArtifact, $cliArtifact, $brokerArtifact))
{
    if (!(Test-Path -LiteralPath $artifact -PathType Leaf))
    {
        throw "Required Release artifact is missing: $artifact"
    }
}

New-MachineProtectedDirectory -Path $productState
New-MachineProtectedDirectory -Path $localInstallState

& wsl.exe --shutdown
if ($LASTEXITCODE -ne 0)
{
    throw "Could not stop WSL before signing and installing the Windows binaries."
}
Start-Sleep -Seconds 2

if (Test-Path -LiteralPath $certificateState)
{
    Assert-MachineProtectedPath -Path $certificateState
    & (Join-Path $PSScriptRoot "Remove-DevSigningCertificate.ps1") -StatePath $certificateState -Confirm:$false
}

& (Join-Path $PSScriptRoot "New-DevSigningCertificate.ps1") `
    -ValidityDays 365 `
    -StatePath $certificateState `
    -TrustForLocalMachine `
    -SignPath @($pluginArtifact, $cliArtifact, $brokerArtifact)
Set-MachineProtectedAcl -Path $certificateState
$certificateFile = Join-Path $localInstallState "wincred-libsecret-dev-signing.cer"
Set-MachineProtectedAcl -Path $certificateFile

& (Join-Path $PSScriptRoot "package.ps1") -Configuration $configuration -SkipBuild
if ($LASTEXITCODE -ne 0)
{
    throw "MSI creation failed."
}

$certificateInfo = Get-Content -LiteralPath $certificateState -Raw | ConvertFrom-Json
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($certificateInfo.thumbprint)" -ErrorAction Stop
$msiSignature = Set-AuthenticodeSignature -LiteralPath $msi -Certificate $certificate -HashAlgorithm SHA256
if ($null -eq $msiSignature.SignerCertificate)
{
    throw "The local MSI could not be signed."
}

$installLog = Join-Path $localInstallState "msi-install.log"
$msiArguments = @(
    "/i",
    "`"$msi`"",
    "/qn",
    "/norestart",
    "/l*v",
    "`"$installLog`""
)
if (Test-Path -LiteralPath $installedCli -PathType Leaf)
{
    $msiArguments += @("REINSTALL=ALL", "REINSTALLMODE=vomus")
}
if ($skipPluginRegistration)
{
    $msiArguments += "SKIPPLUGINREGISTRATION=1"
}
$installer = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList $msiArguments
if ($installer.ExitCode -notin 0, 3010)
{
    throw "MSI installation failed with exit code $($installer.ExitCode). See '$installLog'."
}

foreach ($path in @($installedCli, $installedPlugin))
{
    if (!(Test-Path -LiteralPath $path -PathType Leaf))
    {
        throw "Installed file is missing: $path"
    }
}
if ((Get-AuthenticodeSignature -LiteralPath $installedPlugin).Status -ne "Valid")
{
    throw "The installed WSL plugin signature is not trusted."
}

if (!$skipPluginRegistration)
{
    Invoke-WslServiceRestart -RestartWslService
    if ((Get-Service -Name wslservice -ErrorAction Stop).Status -ne "Running")
    {
        throw "wslservice is not running after installation."
    }
}

if (!$Distro)
{
    $Distro = @(
        & wsl.exe --list --quiet |
            ForEach-Object { $_.Trim([char]0, [char]32) } |
            Where-Object {
                $_ -and
                $_ -notmatch "^(docker-desktop|docker-desktop-data)$"
            }
    )
}
if ($Distro.Count -eq 0)
{
    throw "No compatible WSL distributions were found."
}

$failed = [System.Collections.Generic.List[string]]::new()
foreach ($name in $Distro)
{
    Write-Host "Enabling WinCred Secret Service in '$name'..."
    $arguments = @("distro", "enable", $name)
    if (!$KeepExistingSecretService)
    {
        $arguments += "--replace-conflicts"
    }
    & $installedCli @arguments
    if ($LASTEXITCODE -ne 0)
    {
        $failed.Add($name)
        continue
    }
    & $installedCli doctor --distro $name
    if ($LASTEXITCODE -ne 0)
    {
        $failed.Add($name)
    }
}

if ($failed.Count -gt 0)
{
    throw "Installation completed, but these distributions failed validation: $($failed -join ', ')."
}

if (!$skipPluginRegistration)
{
    & wsl.exe --shutdown
    Start-Sleep -Seconds 2
    & wsl.exe -d $Distro[0] -- /bin/true
    if ($LASTEXITCODE -ne 0)
    {
        throw "The first enabled distribution did not restart successfully."
    }

    $loaded = @(
        Get-Process -Name wslservice -Module -ErrorAction Stop |
            Where-Object {
                $_.FileName -and
                $_.FileName.Equals($installedPlugin, [StringComparison]::OrdinalIgnoreCase)
            }
    )
    if ($loaded.Count -eq 0)
    {
        throw "wslservice did not load '$installedPlugin'."
    }
}

$smokeId = [guid]::NewGuid().ToString("N")
$smokeScript = @'
set -e
if ! command -v secret-tool >/dev/null 2>&1; then
    exit 0
fi
printf '%s' 'wincred-local-install-ok' |
    secret-tool store --label='WinCred local install smoke test' wincred-local-install "$1"
test "$(secret-tool lookup wincred-local-install "$1")" = 'wincred-local-install-ok'
secret-tool clear wincred-local-install "$1"
'@
foreach ($name in $Distro)
{
    & wsl.exe -d $name -- dbus-run-session -- bash -c $smokeScript -- $smokeId
    if ($LASTEXITCODE -ne 0)
    {
        throw "libsecret smoke test failed in '$name'."
    }
}

Write-Host ""
Write-Host "Installed WinCred Libsecret and enabled: $($Distro -join ', ')"
if ($skipPluginRegistration)
{
    Write-Host "The WinCred lifecycle plugin was not registered because another WSL plugin is installed; distro providers remain fully usable."
}
Write-Host "Open a new WSL shell and use secret-tool or any libsecret application."
