[CmdletBinding()]
param(
    [ValidatePattern("^[a-z0-9][a-z0-9-]*$")]
    [string]$SourceDistribution = "wincred-e2e-source",
    [ValidateSet("Ubuntu-24.04")]
    [string]$BootstrapDistribution = "Ubuntu-24.04",
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [string]$InstallRoot,
    [Parameter(Mandatory)]
    [string]$RootfsPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Administrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw "The hosted WSL E2E bootstrap requires an elevated Windows runner."
    }
}

function Invoke-WslCommand
{
    param([Parameter(Mandatory)][string[]]$Arguments)

    $normalizedArguments = @(
        $Arguments | ForEach-Object { $_.Replace("`r`n", "`n") }
    )
    $output = @(& wsl.exe @normalizedArguments 2>&1 | ForEach-Object {
        ([string]$_).Replace([string][char]0, "")
    })
    $exitCode = $LASTEXITCODE
    foreach ($line in $output)
    {
        Write-Host "wsl.exe: $line"
    }
    if ($exitCode -ne 0)
    {
        throw "wsl.exe $($normalizedArguments -join ' ') exited with $exitCode."
    }
}

function Get-WslDistributions
{
    $output = @(& wsl.exe --list --quiet 2>&1 | ForEach-Object {
        ([string]$_).Replace([string][char]0, "")
    })
    if ($LASTEXITCODE -ne 0)
    {
        throw "wsl.exe --list --quiet exited with $LASTEXITCODE."
    }
    @(
        $output |
            ForEach-Object { $_.Trim([char]0xFEFF, " ", "`t", "`r") } |
            Where-Object { $_ }
    )
}

function Assert-Wsl2Runtime
{
    $output = @(& wsl.exe --version 2>&1 | ForEach-Object {
        ([string]$_).Replace([string][char]0, "")
    })
    if ($LASTEXITCODE -ne 0)
    {
        throw "wsl.exe --version exited with $LASTEXITCODE."
    }
    $text = $output -join "`n"
    $match = [regex]::Match($text, '(?im)^\s*WSL\s+version\s*:\s*v?(\d+(?:\.\d+){2,3})')
    if (!$match.Success)
    {
        throw "Could not determine the installed WSL version. Output: $text"
    }
    $version = [version]$match.Groups[1].Value
    if ($version -lt [version]"2.5.1")
    {
        throw "WSL $version is too old; WSL 2.5.1 or newer is required."
    }
}

function Get-WslPath
{
    param(
        [Parameter(Mandatory)][string]$Distribution,
        [Parameter(Mandatory)][string]$WindowsPath
    )

    $normalizedWindowsPath = $WindowsPath -replace "\\", "/"
    $output = @(& wsl.exe --distribution $Distribution --user root -- wslpath -a $normalizedWindowsPath 2>&1 | ForEach-Object {
        ([string]$_).Replace([string][char]0, "")
    })
    if ($LASTEXITCODE -ne 0)
    {
        throw "wsl.exe could not translate '$WindowsPath' for '$Distribution': $($output -join "`n")"
    }
    $path = ($output -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($path))
    {
        throw "wsl.exe returned an empty path for '$WindowsPath'."
    }
    $path
}

function ConvertTo-BashLiteral
{
    param([Parameter(Mandatory)][string]$Value)

    "'" + $Value.Replace("'", "'`"`'`"'" ) + "'"
}

Assert-Administrator
Assert-Wsl2Runtime

$rootfsParent = Split-Path -Parent $RootfsPath
if ([string]::IsNullOrWhiteSpace($rootfsParent))
{
    throw "RootfsPath must include a parent directory."
}
New-Item -ItemType Directory -Path $rootfsParent -Force | Out-Null

$rootfsExists = Test-Path -LiteralPath $RootfsPath -PathType Leaf
if ($rootfsExists -and (Get-Item -LiteralPath $RootfsPath -Force).Length -eq 0)
{
    throw "Cached WSL rootfs '$RootfsPath' is empty; delete its Actions cache entry before retrying."
}
if (Test-Path -LiteralPath $InstallRoot)
{
    throw "WSL install root '$InstallRoot' already exists."
}
if ((Test-Path -LiteralPath $RootfsPath) -and !$rootfsExists)
{
    throw "Cached WSL rootfs path '$RootfsPath' is not a file."
}
if ((Get-WslDistributions) -contains $SourceDistribution)
{
    throw "WSL source distribution '$SourceDistribution' already exists."
}

if (!$rootfsExists)
{
    if ((Get-WslDistributions) -contains $BootstrapDistribution)
    {
        throw "Bootstrap distribution '$BootstrapDistribution' already exists."
    }

    Invoke-WslCommand @("--install", "--no-launch", "--web-download", "--distribution", $BootstrapDistribution)

    $bootstrap = @'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

cat >/etc/wsl.conf <<'EOF'
[boot]
systemd=true

[user]
default=root
EOF

apt-get update
apt-get install --yes --no-install-recommends \
  build-essential ca-certificates curl dbus dbus-user-session git \
  libsecret-1-dev libsecret-tools musl-tools pkg-config

if ! command -v rustup >/dev/null 2>&1; then
  curl --fail --location --proto '=https' --tlsv1.2 https://sh.rustup.rs |
    sh -s -- -y --profile minimal
fi

source /root/.cargo/env
rustup toolchain install 1.97.1 --profile minimal --component clippy,rustfmt
rustup default 1.97.1
rustup target add x86_64-unknown-linux-musl --toolchain 1.97.1
apt-get clean
rm -rf /var/lib/apt/lists/*
'@
    Invoke-WslCommand @(
        "--distribution", $BootstrapDistribution,
        "--user", "root",
        "--",
        "/bin/bash", "-lc", $bootstrap
    )
    $repositoryPath = Get-WslPath -Distribution $BootstrapDistribution -WindowsPath $RepositoryRoot
    $fetchDependencies = @"
set -euo pipefail
source /root/.cargo/env
cd -- $(ConvertTo-BashLiteral $repositoryPath)
cargo +1.97.1 fetch --locked
"@
    Invoke-WslCommand @(
        "--distribution", $BootstrapDistribution,
        "--user", "root",
        "--",
        "/bin/bash", "-lc", $fetchDependencies
    )
    Invoke-WslCommand @("--shutdown")
    Invoke-WslCommand @("--export", $BootstrapDistribution, $RootfsPath)
    Invoke-WslCommand @("--unregister", $BootstrapDistribution)
}
else
{
    Write-Host "Reusing cached WSL rootfs '$RootfsPath'."
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Invoke-WslCommand @("--import", $SourceDistribution, $InstallRoot, $RootfsPath, "--version", "2")
Invoke-WslCommand @("--shutdown")

$sourceValidation = @'
set -euo pipefail
test -d /run/systemd/system
command -v dbus-run-session >/dev/null
command -v secret-tool >/dev/null
command -v musl-gcc >/dev/null
pkg-config --exists libsecret-1
test -f /usr/include/libsecret-1/libsecret/secret.h
source /root/.cargo/env
rustc --version | grep -F '1.97.1'
'@
Invoke-WslCommand @(
    "--distribution", $SourceDistribution,
    "--user", "root",
    "--",
    "/bin/bash", "-lc", $sourceValidation
)

$verbose = @(& wsl.exe --list --verbose 2>&1 | ForEach-Object {
    ([string]$_).Replace([string][char]0, "")
}) -join "`n"
if ($LASTEXITCODE -ne 0)
{
    throw "wsl.exe --list --verbose exited with $LASTEXITCODE."
}
$sourcePattern = [regex]::Escape($SourceDistribution)
if (![regex]::IsMatch($verbose, "(?m)^\s*\*?\s*$sourcePattern\s+.*\s2\s*$"))
{
    throw "WSL source distribution '$SourceDistribution' is not running as WSL 2. Output: $verbose"
}

Write-Host "Hosted WSL source distribution '$SourceDistribution' is ready."
