[CmdletBinding()]
param([string[]]$Distro)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

Assert-Administrator

$installDirectory = Join-Path $env:ProgramFiles "WinCredLibsecret"
$installedCli = Join-Path $installDirectory "wincred-libsecret.exe"
$msi = Join-Path $repoRoot "packages\Release\wincred-libsecret-wsl-plugin.msi"
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$localInstallState = Join-Path $programData "WinCredLibsecret\LocalInstall"
$certificateState = Join-Path $localInstallState "certificate-state.json"

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

if (Test-Path -LiteralPath $installedCli -PathType Leaf)
{
    foreach ($name in $Distro)
    {
        & $installedCli distro disable $name
        if ($LASTEXITCODE -ne 0)
        {
            throw "Could not disable '$name'; MSI uninstall was not attempted."
        }
    }
}

if (Test-Path -LiteralPath $msi -PathType Leaf)
{
    $uninstallLog = Join-Path $env:TEMP "wincred-libsecret-msi-uninstall.log"
    $installer = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @(
        "/x",
        "`"$msi`"",
        "/qn",
        "/norestart",
        "/l*v",
        "`"$uninstallLog`""
    )
    if ($installer.ExitCode -notin 0, 1605, 3010)
    {
        throw "MSI uninstall failed with exit code $($installer.ExitCode). See '$uninstallLog'."
    }
}
else
{
    Write-Warning "The source MSI was not found. Remove the product through Windows Installed Apps."
}

Invoke-WslServiceRestart -RestartWslService

if (Test-Path -LiteralPath $certificateState)
{
    Assert-MachineProtectedPath -Path $certificateState
    & (Join-Path $PSScriptRoot "Remove-DevSigningCertificate.ps1") -StatePath $certificateState -Confirm:$false
}
if (Test-Path -LiteralPath $localInstallState)
{
    Assert-MachineProtectedPath -Path $localInstallState -Directory
    Remove-Item -LiteralPath $localInstallState -Recurse -Force
}

Write-Host "Uninstalled WinCred Libsecret. The WinCred vault was preserved."
