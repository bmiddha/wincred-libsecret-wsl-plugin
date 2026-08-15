[CmdletBinding()]
param(
    [string]$StageDirectory,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$MsiPath,
    [string[]]$SigningPath,
    [switch]$RequireValidSignatures
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-True
{
    param([bool]$Condition, [string]$Message)
    if (!$Condition) { throw $Message }
}

function Assert-Throws
{
    param([scriptblock]$Action, [string]$Message)

    try
    {
        & $Action
    }
    catch
    {
        return
    }
    throw $Message
}

function Get-Sha256
{
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CleanupResult
{
    param([string]$Current, [string]$Tracked, [string]$Backup, [bool]$HadBackup)

    if ($null -eq $Current -or !$Current.Equals($Tracked, [StringComparison]::OrdinalIgnoreCase))
    {
        return "Preserve"
    }
    if ($HadBackup) { return "Restore:$Backup" }
    "Remove"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "Signing.Common.ps1")
. (Join-Path $PSScriptRoot "DevPlugin.Common.ps1")

$parseErrors = @()
$powerShellScripts = @(
    Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.ps1" -File
    Get-Item -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) "install.ps1")
)
$powerShellScripts | ForEach-Object {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    $parseErrors += $errors
}
if ($parseErrors.Count -gt 0)
{
    throw "PowerShell syntax errors:`n$($parseErrors | ForEach-Object Message | Out-String)"
}

$analyzer = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if ($null -ne $analyzer)
{
    $findings = @(Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -Severity Error)
    if ($findings.Count -gt 0)
    {
        throw "PSScriptAnalyzer errors:`n$($findings | Format-Table -AutoSize | Out-String)"
    }
}
else
{
    Write-Host "PSScriptAnalyzer is not installed; completed PowerShell parser validation."
}

$wixPath = Join-Path $repoRoot "packaging\wix\Product.wxs"
$wix = Get-Content -LiteralPath $wixPath -Raw
[xml]$wixXml = $wix
Assert-True ($wix -match 'UpgradeCode="\{A81A96E1-14E9-43F8-BAE1-7C88BE7A6B5C\}"') "WiX UpgradeCode changed unexpectedly."
foreach ($componentGuid in @(
    "86C3E780-770B-4775-8521-EC2B3A99E812",
    "6D0134A8-7BF4-4287-A147-DB907A6DB083",
    "4843FB32-C6CE-46B4-BE31-AF1A5D4E2F8A",
    "D0F7BA9B-8BF5-4163-B70B-58E0460B5AA2",
    "F462CF31-39FD-483A-820C-2A8B1264B905",
    "BF4D4A6A-66CA-4789-BFE0-E1B36AF2541F",
    "F5A5C3D2-9ACD-45E4-98A6-CFF878FC9199"
))
{
    Assert-True ($wix.Contains("Guid=`"{$componentGuid}`"")) "WiX component GUID $componentGuid changed unexpectedly."
}
Assert-True ($wix.Contains('SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins')) "WiX does not document the exact plugin registry key."
Assert-True ($wix -notmatch '<RegistryValue') "Registry must be managed through guarded CLI custom actions, not an unconditional WiX registry row."
Assert-True ($wix.Contains('plugin install --dll "[#PluginDll]"')) "WiX registration does not pass the installed plugin DLL path."
Assert-True ($wix.Contains('plugin uninstall --dll "[#PluginDll]"')) "WiX cleanup does not guard the installed plugin DLL path."
Assert-True ($wix.Contains('Execute="rollback"')) "WiX rollback action is missing."
Assert-True ($wix.Contains('REMOVE="ALL"')) "WiX uninstall action is missing."
Assert-True ($wix.Contains('SKIPPLUGINREGISTRATION')) "WiX cannot preserve an existing incompatible WSL security plugin."

$cliLibrary = Get-Content -LiteralPath (Join-Path $repoRoot "crates\cli\src\lib.rs") -Raw
$cliMain = Get-Content -LiteralPath (Join-Path $repoRoot "crates\cli\src\main.rs") -Raw
Assert-True ($cliLibrary.Contains('SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins')) "CLI registry path changed."
Assert-True ($cliLibrary.Contains('PLUGIN_VALUE_NAME: &str = "wincred-libsecret-wsl-plugin"')) "CLI plugin value name changed."
Assert-True ($cliMain.Contains('eq_ignore_ascii_case(expected)')) "CLI uninstall no longer guards against a changed registry value."

Assert-True ((Get-CleanupResult -Current "C:\other.dll" -Tracked "C:\dev.dll" -Backup "C:\saved.dll" -HadBackup $true) -eq "Preserve") "Conflict preservation model failed."
Assert-True ((Get-CleanupResult -Current "C:\dev.dll" -Tracked "C:\dev.dll" -Backup "C:\saved.dll" -HadBackup $true) -eq "Restore:C:\saved.dll") "Conflict restoration model failed."
Assert-True ((Get-CleanupResult -Current "C:\dev.dll" -Tracked "C:\dev.dll" -Backup "" -HadBackup $false) -eq "Remove") "Clean development unregister model failed."

$installDevPlugin = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Install-DevPlugin.ps1") -Raw
$uninstallDevPlugin = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Uninstall-DevPlugin.ps1") -Raw
$statusDevPlugin = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Get-DevPluginStatus.ps1") -Raw
$devPluginCommon = Get-Content -LiteralPath (Join-Path $PSScriptRoot "DevPlugin.Common.ps1") -Raw
Assert-True ($installDevPlugin -notmatch '(?s)param\s*\([^)]*\$StatePath') "Install-DevPlugin must not accept a caller-controlled state path."
Assert-True ($uninstallDevPlugin -notmatch '(?s)param\s*\([^)]*\$StatePath') "Uninstall-DevPlugin must not accept a caller-controlled state path."
Assert-True ($statusDevPlugin -notmatch '(?s)param\s*\([^)]*\$StatePath') "Get-DevPluginStatus must not accept a caller-controlled state path."
Assert-True ($devPluginCommon.Contains("CommonApplicationData")) "Developer state is not rooted under ProgramData."
Assert-True ($devPluginCommon.Contains("SetAccessRuleProtection(`$true, `$false)")) "Developer state ACL is not protected."
Assert-True ($devPluginCommon.Contains("[IO.FileMode]::CreateNew")) "Developer state write is not no-follow create-new."
Assert-True ($devPluginCommon.Contains("[IO.File]::Replace")) "Developer state write is not atomic replacement."
Assert-True ($devPluginCommon.Contains("Test-ReparsePoint")) "Developer state does not reject reparse points."
Assert-True ($devPluginCommon.Contains("Assert-TrustedRestorablePluginDll")) "Developer state does not revalidate restore targets."

$validDevState = @'
{"schemaVersion":1,"trackedDllPath":"C:\\Program Files\\WinCredLibsecret\\wincred-libsecret-wsl-plugin.dll","hadExistingValue":false,"originalValue":null,"originalKind":null}
'@
$parsedDevState = ConvertFrom-DevPluginState -Json $validDevState
Assert-True ($parsedDevState.schemaVersion -eq 1) "Valid protected developer state was rejected."
foreach ($tamperedState in @(
    '{"schemaVersion":2,"trackedDllPath":"C:\\Program Files\\WinCredLibsecret\\wincred-libsecret-wsl-plugin.dll","hadExistingValue":false,"originalValue":null,"originalKind":null}',
    '{"schemaVersion":1,"trackedDllPath":"C:\\Program Files\\WinCredLibsecret\\wincred-libsecret-wsl-plugin.dll","hadExistingValue":false,"originalValue":"C:\\attacker.dll","originalKind":"String"}',
    '{"schemaVersion":1,"trackedDllPath":"C:\\Program Files\\WinCredLibsecret\\wincred-libsecret-wsl-plugin.dll","hadExistingValue":true,"originalValue":"C:\\attacker.dll","originalKind":"ExpandString"}',
    '{"schemaVersion":1,"trackedDllPath":"C:\\Program Files\\WinCredLibsecret\\wincred-libsecret-wsl-plugin.dll","hadExistingValue":false,"originalValue":null,"originalKind":null,"attacker":"extra"}'
))
{
    Assert-Throws { ConvertFrom-DevPluginState -Json $tamperedState | Out-Null } "Tampered developer state was accepted."
}

$stateTestRoot = Join-Path $repoRoot "artifacts\state-security-validation"
Remove-Item -LiteralPath $stateTestRoot -Recurse -Force -ErrorAction SilentlyContinue
try
{
    New-Item -ItemType Directory -Path $stateTestRoot -Force | Out-Null
    Assert-True (!(Test-MachineProtectedAcl -Path $stateTestRoot -Directory)) "A user-writable state parent was accepted."
    Assert-Throws { Assert-MachineProtectedPath -Path $stateTestRoot -Directory } "User-writable state parent was not rejected."

    $reparseTarget = Join-Path $stateTestRoot "target"
    $reparsePath = Join-Path $stateTestRoot "junction"
    New-Item -ItemType Directory -Path $reparseTarget | Out-Null
    New-Item -ItemType Junction -Path $reparsePath -Target $reparseTarget | Out-Null
    Assert-True (Test-ReparsePoint -Path $reparsePath) "Junction test setup did not create a reparse point."
    Assert-Throws { Assert-NotReparsePoint -Path $reparsePath } "Reparse-point state path was accepted."
}
finally
{
    Remove-Item -LiteralPath $stateTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$unsignedPlugin = Join-Path $repoRoot "artifacts\Release\windows\wincred-libsecret-wsl-plugin.dll"
if (Test-Path -LiteralPath $unsignedPlugin -PathType Leaf)
{
    Assert-Throws { Assert-TrustedRestorablePluginDll -Path $unsignedPlugin | Out-Null } "Unsigned restore target was accepted."
}
$signedSystemDll = Join-Path $env:WINDIR "System32\kernel32.dll"
if (Test-Path -LiteralPath $signedSystemDll -PathType Leaf)
{
    [void](Assert-TrustedAuthenticodeFile -Path $signedSystemDll)
}
Assert-True ((Get-CleanupResult -Current "C:\changed.dll" -Tracked "C:\dev.dll" -Backup "C:\saved.dll" -HadBackup $true) -eq "Preserve") "Changed registration cleanup was not preserved."
Assert-True ($devPluginCommon.Contains("if (!(Test-Path -LiteralPath `$statePath -PathType Leaf))")) "Missing protected state is not handled idempotently."

Assert-True (!(Test-Path -LiteralPath (Join-Path $repoRoot "packaging\signing\publisher-certificate.json"))) "Public releases must not use a committed self-signed publisher certificate."
$releaseInstaller = Get-Content -LiteralPath (Join-Path $repoRoot "install.ps1") -Raw
Assert-True ($releaseInstaller.Contains("releases/latest")) "Release installer does not select the latest release by default."
Assert-True ($releaseInstaller.Contains("releases/tags/")) "Release installer cannot select a specific release tag."
Assert-True ($releaseInstaller.Contains("checksums.sha256")) "Release installer does not verify release checksums."
Assert-True ($releaseInstaller.Contains("wincred-libsecret-release-signing.txt")) "Release installer does not retrieve signer metadata."
Assert-True ($releaseInstaller.Contains("Get-ReleaseSigningMetadata")) "Release installer does not validate signer metadata."
Assert-True (!$releaseInstaller.Contains("wincred-libsecret-release.cer")) "Release installer must not require a self-signed release certificate."
Assert-True (!$releaseInstaller.Contains("Import-Certificate")) "Release installer must not modify certificate trust stores."
Assert-True ($releaseInstaller.Contains("Get-AuthenticodeSignature")) "Release installer does not validate the MSI signature."
Assert-True ($releaseInstaller.Contains("msiexec.exe")) "Release installer does not install the MSI."
$releasePublishWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\release-publish.yml") -Raw
Assert-True (!$releasePublishWorkflow.Contains("RELEASE_SIGNING_CERTIFICATE_")) "Release workflow must not use a persistent publisher PFX."
Assert-True (!$releasePublishWorkflow.Contains("publisher-certificate.json")) "Release workflow must not use a committed publisher certificate."
Assert-True (!$releasePublishWorkflow.Contains("New-DevSigningCertificate.ps1")) "Release workflow must not use a development signing certificate."
Assert-True ($releasePublishWorkflow.Contains("environment: release")) "Release workflow must use the protected release environment."
Assert-True ($releasePublishWorkflow.Contains("azure/login@f5d393ae46f8fde4be8b75f32e3fc50e654ad0ca")) "Release workflow does not pin Azure login."
Assert-True ($releasePublishWorkflow.Contains("Azure/artifact-signing-action@c7ab2a863ab5f9a846ddb8265964877ef296ee82")) "Release workflow does not pin Azure Artifact Signing."
Assert-True ($releasePublishWorkflow.Contains("AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME")) "Release workflow does not require an Azure certificate profile."
Assert-True ($releasePublishWorkflow.Contains("-PrepareOnly")) "Release workflow does not stage binaries before Azure signing."
Assert-True ($releasePublishWorkflow.Contains("-UsePreparedStage")) "Release workflow does not build the MSI from Azure-signed binaries."
Assert-True ($releasePublishWorkflow.Contains("wincred-libsecret-release-signing.txt")) "Release workflow does not publish signer metadata."
Assert-True ($releasePublishWorkflow.Contains('package["name"] == "wincred-libsecret"')) "Release workflow does not validate the root workspace package version."
Assert-True ($releasePublishWorkflow.Contains("attestations: write")) "Release workflow cannot publish GitHub artifact attestations."
Assert-True ($releasePublishWorkflow.Contains("artifact-metadata: write")) "Release workflow cannot create attestation artifact metadata."
Assert-True ($releasePublishWorkflow.Contains("id-token: write")) "Release workflow cannot obtain an artifact-attestation identity token."
Assert-True ($releasePublishWorkflow.Contains("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6")) "Release workflow does not pin the GitHub artifact-attestation action."
Assert-True ($releasePublishWorkflow.Contains('subject-path: "packages/Release/*"')) "Release workflow does not attest every release asset."
Assert-True ($releasePublishWorkflow.Contains("github.event.repository.visibility == 'public'")) "Release workflow does not safely gate attestations until the repository is public."
Assert-True ($releasePublishWorkflow.Contains("exclude-azure-cli-credential: false")) "Azure Artifact Signing cannot use the Azure CLI OIDC session."
$prepareIndex = $releasePublishWorkflow.IndexOf("Prepare unsigned package stage", [StringComparison]::Ordinal)
$payloadSigningIndex = $releasePublishWorkflow.IndexOf("Sign staged Windows payload with Azure Artifact Signing", [StringComparison]::Ordinal)
$buildMsiIndex = $releasePublishWorkflow.IndexOf("Build MSI from the Azure-signed package stage", [StringComparison]::Ordinal)
Assert-True (
    $prepareIndex -ge 0 -and
    $payloadSigningIndex -gt $prepareIndex -and
    $buildMsiIndex -gt $payloadSigningIndex
) "Release workflow does not prepare, sign, and package Windows payloads in that order."
$packageScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot "package.ps1") -Raw
Assert-True ($packageScript.Contains('[switch]$PrepareOnly')) "Packager cannot stage artifacts before Azure signing."
Assert-True ($packageScript.Contains('[switch]$UsePreparedStage')) "Packager cannot build an MSI from an externally signed stage."
Assert-Throws {
    & (Join-Path $PSScriptRoot "package.ps1") -PrepareOnly -UsePreparedStage
} "Packager accepted conflicting stage modes."
Assert-Throws {
    & (Join-Path $PSScriptRoot "package.ps1") -UsePreparedStage
} "Packager accepted a staged package while rebuilding inputs."
Assert-Throws {
    & (Join-Path $PSScriptRoot "package.ps1") -PrepareOnly -Sign `
        -CertificateThumbprint "0123456789abcdef0123456789abcdef01234567"
} "Packager accepted signing in prepare-only mode."

if (![string]::IsNullOrEmpty($StageDirectory))
{
    $stage = [IO.Path]::GetFullPath($StageDirectory)
    $manifestPath = Join-Path $stage "metadata\version-manifest.json"
    $checksumsPath = Join-Path $stage "metadata\checksums.sha256"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Assert-True ($manifest.PSObject.Properties.Name -notcontains "createdUtc") "Reproducible version manifest must not include timestamps."
    foreach ($file in $manifest.files)
    {
        $path = Join-Path $stage ($file.path.Replace("/", "\"))
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "Manifest file is absent: $($file.path)"
        Assert-True ((Get-Sha256 $path) -eq $file.sha256) "Manifest hash mismatch: $($file.path)"
    }
    foreach ($line in Get-Content -LiteralPath $checksumsPath)
    {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split ' \*', 2
        Assert-True ($parts.Count -eq 2) "Invalid checksum line: $line"
        $path = Join-Path $stage ($parts[1].Replace("/", "\"))
        Assert-True ((Get-Sha256 $path) -eq $parts[0]) "Checksum mismatch: $($parts[1])"
    }
    Write-Host "Validated package manifest hashes: $stage"
}

if ($SigningPath)
{
    $states = @(Get-SigningState -Path $SigningPath)
    $states | Format-Table -AutoSize
    if ($RequireValidSignatures)
    {
        $invalid = @($states | Where-Object Status -ne "Valid")
        Assert-True ($invalid.Count -eq 0) "One or more required release signatures are not Valid."
    }
}

if (![string]::IsNullOrEmpty($MsiPath))
{
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    $actions = $null
    try
    {
        $database = $installer.OpenDatabase(
            (Resolve-Path -LiteralPath $MsiPath -ErrorAction Stop).Path,
            0
        )
        $view = $database.OpenView("SELECT ``FileName`` FROM ``File``")
        $view.Execute()
        $fileNames = [System.Collections.Generic.List[string]]::new()
        while ($null -ne ($record = $view.Fetch()))
        {
            $fileName = $record.StringData(1)
            # MSI FileName can be stored as the 8.3 name followed by the
            # long name (short|long); validation must compare the payload name.
            $fileNames.Add(($fileName -split '\|')[-1])
        }
        foreach ($expected in @(
            "wincred-libsecret-wsl-plugin.dll",
            "wincred-libsecret.exe",
            "wincred-libsecret-broker.exe",
            "wincred-libsecret-provider",
            "wincred-libsecret-interop.service"
        ))
        {
            Assert-True ($fileNames -contains $expected) "MSI is missing expected payload '$expected'."
        }

        $actions = $database.OpenView("SELECT ``Action`` FROM ``CustomAction``")
        $actions.Execute()
        $customActions = [System.Collections.Generic.List[string]]::new()
        while ($null -ne ($record = $actions.Fetch()))
        {
            $customActions.Add($record.StringData(1))
        }
        foreach ($expected in @("RegisterPlugin", "UnregisterPlugin", "RollbackPluginRegistration"))
        {
            Assert-True ($customActions -contains $expected) "MSI is missing expected custom action '$expected'."
        }
    }
    finally
    {
        if ($null -ne $view) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
        if ($null -ne $actions) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($actions) }
        if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database) }
        if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
    }
    Write-Host "Validated MSI payload and guarded registration actions: $MsiPath"
}

Write-Host "Packaging source validation passed."
