[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "E2E.Common.ps1")

function Assert-E2ECondition
{
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (!$Condition)
    {
        throw $Message
    }
}

function Assert-E2EThrows
{
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Message
    )

    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    Assert-E2ECondition $threw $Message
}

function New-E2ETestEnablementResource
{
    param(
        [Parameter(Mandatory)]$Context,
        [switch]$PartialImport
    )

    [PSCustomObject]@{
        Name = "wincred-e2e-$($Context.RunId)-a"
        Root = "Q:\e2e-test-root"
        DistroGuid = if ($PartialImport) { $null } else { "88888888-8888-8888-8888-888888888888" }
        DistroRegistryPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Lxss\{88888888-8888-8888-8888-888888888888}"
        EnablementKeyPath = "Registry::HKEY_CURRENT_USER\Software\wincred-libsecret\WSLPlugin\Distributions\{88888888-8888-8888-8888-888888888888}"
        EnablementEnabled = !$PartialImport
        EnablementVerifiedAbsent = $false
        Unregistered = $false
        StorageDeleted = $false
    }
}

function Invoke-E2ETestEnablementCleanup
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)]$State
    )

    $disable = {
        param($TrackedResource)
        $State.DisableCalls++
        if ($State.DisableThrows)
        {
            throw "simulated disable failure"
        }
        if ($State.DisableSucceeds)
        {
            $State.KeyExists = $State.KeyAfterDisable
        }
        [bool]$State.DisableSucceeds
    }.GetNewClosure()
    $keyExists = {
        param($TrackedResource)
        [bool]$State.KeyExists
    }.GetNewClosure()
    $registeredName = {
        param($TrackedResource)
        [string]$State.RegisteredName
    }.GetNewClosure()
    $remove = {
        param($TrackedResource)
        $State.RemoveCalls++
        if ($State.RemoveSucceeds)
        {
            $State.KeyExists = $false
            return $true
        }
        $false
    }.GetNewClosure()
    Invoke-E2ETrackedEnablementCleanup `
        -Context $Context `
        -Resource $Resource `
        -DisableAction $disable `
        -KeyExistsAction $keyExists `
        -RegisteredNameAction $registeredName `
        -RemoveKeyAction $remove
}

$runId = "0123456789abcdef0123456789abcdef"
$collectionId = "11111111-1111-1111-1111-111111111111"
$itemId = "22222222-2222-2222-2222-222222222222"
$normalItemId = "33333333-3333-3333-3333-333333333333"
$orphanItemId = "44444444-4444-4444-4444-444444444444"
$generationId = "55555555-5555-5555-5555-555555555555"
$normalGenerationId = "66666666-6666-6666-6666-666666666666"
$orphanGenerationId = "77777777-7777-7777-7777-777777777777"
$hash = "0:" + (("a") * 64 -join "")

$enablementContext = [PSCustomObject]@{ RunId = $runId }
$successfulResource = New-E2ETestEnablementResource $enablementContext
$successfulState = [PSCustomObject]@{
    DisableCalls = 0
    RemoveCalls = 0
    DisableThrows = $false
    DisableSucceeds = $true
    KeyAfterDisable = $false
    KeyExists = $true
    RegisteredName = $successfulResource.Name
    RemoveSucceeds = $true
}
$successfulCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $successfulResource $successfulState
Assert-E2ECondition (
    $successfulCleanup.SafeToRemoveStorage -and
    $successfulCleanup.Errors.Count -eq 0 -and
    $successfulResource.EnablementVerifiedAbsent -and
    $successfulState.DisableCalls -eq 1 -and
    $successfulState.RemoveCalls -eq 0
) "Successful distro disable did not verify the tracked HKCU key is absent."

$disableFailureResource = New-E2ETestEnablementResource $enablementContext
$disableFailureState = [PSCustomObject]@{
    DisableCalls = 0
    RemoveCalls = 0
    DisableThrows = $false
    DisableSucceeds = $false
    KeyAfterDisable = $true
    KeyExists = $true
    RegisteredName = $disableFailureResource.Name
    RemoveSucceeds = $true
}
$disableFailureCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $disableFailureResource $disableFailureState
Assert-E2ECondition (
    $disableFailureCleanup.SafeToRemoveStorage -and
    $disableFailureCleanup.Errors.Count -gt 0 -and
    $disableFailureState.RemoveCalls -eq 1 -and
    !$disableFailureState.KeyExists
) "A nonzero distro disable was not recorded while its exact run-owned key was removed."

$removeFailureResource = New-E2ETestEnablementResource $enablementContext
$removeFailureState = [PSCustomObject]@{
    DisableCalls = 0
    RemoveCalls = 0
    DisableThrows = $false
    DisableSucceeds = $true
    KeyAfterDisable = $true
    KeyExists = $true
    RegisteredName = $removeFailureResource.Name
    RemoveSucceeds = $false
}
$removeFailureCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $removeFailureResource $removeFailureState
Assert-E2ECondition (
    !$removeFailureCleanup.SafeToRemoveStorage -and
    $removeFailureCleanup.Errors.Count -gt 0 -and
    $removeFailureState.RemoveCalls -eq 1 -and
    $removeFailureState.KeyExists
) "A failed exact-key removal was treated as safe for storage deletion."

$foreignResource = New-E2ETestEnablementResource $enablementContext
$foreignResource.EnablementEnabled = $false
$foreignState = [PSCustomObject]@{
    DisableCalls = 0
    RemoveCalls = 0
    DisableThrows = $false
    DisableSucceeds = $true
    KeyAfterDisable = $true
    KeyExists = $true
    RegisteredName = "foreign-distribution"
    RemoveSucceeds = $true
}
$foreignCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $foreignResource $foreignState
Assert-E2ECondition (
    !$foreignCleanup.SafeToRemoveStorage -and
    $foreignCleanup.Errors.Count -gt 0 -and
    $foreignState.DisableCalls -eq 0 -and
    $foreignState.RemoveCalls -eq 0 -and
    $foreignState.KeyExists
) "A changed or foreign registry key was not preserved."

$partialResource = New-E2ETestEnablementResource $enablementContext -PartialImport
$partialState = [PSCustomObject]@{
    DisableCalls = 0
    RemoveCalls = 0
    DisableThrows = $false
    DisableSucceeds = $true
    KeyAfterDisable = $false
    KeyExists = $false
    RegisteredName = $partialResource.Name
    RemoveSucceeds = $true
}
$partialCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $partialResource $partialState
Assert-E2ECondition (
    $partialCleanup.SafeToRemoveStorage -and
    $partialCleanup.Errors.Count -eq 0 -and
    $partialResource.EnablementVerifiedAbsent -and
    $partialState.DisableCalls -eq 0 -and
    $partialState.RemoveCalls -eq 0
) "A partial import without a tracked GUID was not safely handled."

$repeatedCleanup = Invoke-E2ETestEnablementCleanup $enablementContext $successfulResource $successfulState
Assert-E2ECondition (
    $repeatedCleanup.SafeToRemoveStorage -and
    $repeatedCleanup.Errors.Count -eq 0 -and
    $successfulState.DisableCalls -eq 1 -and
    $successfulState.RemoveCalls -eq 0
) "Repeated cleanup was not idempotent after absence verification."

$originalProcessInvoker = ${function:Invoke-E2EProcess}
$cleanupRegressionKey = "Registry::HKEY_CURRENT_USER\Software\wincred-libsecret\e2e-cleanup-$runId"
$cleanupRegressionCalls = 0
$cleanupRegressionArguments = @()
New-Item -Path $cleanupRegressionKey -Force | Out-Null
New-ItemProperty -Path $cleanupRegressionKey -Name DistributionName -Value $successfulResource.Name -PropertyType String -Force | Out-Null
function Invoke-E2EProcess
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$AllowFailure
    )

    $script:cleanupRegressionCalls++
    $script:cleanupRegressionArguments = @($ArgumentList)
    Remove-Item -LiteralPath $script:cleanupRegressionKey -Recurse -Force -ErrorAction Stop
    [PSCustomObject]@{ ExitCode = 0; Output = "" }
}
try
{
    $closureResource = New-E2ETestEnablementResource $enablementContext
    $closureResource.EnablementKeyPath = $cleanupRegressionKey
    $closureResource.DistroRegistryPath = $cleanupRegressionKey
    $closureCleanup = Clear-E2EDistributionEnablement $enablementContext $closureResource (Join-Path $PSHOME "pwsh.exe")
    Assert-E2ECondition (
        $closureCleanup.SafeToRemoveStorage -and
        $closureCleanup.Errors.Count -eq 0 -and
        $closureResource.EnablementVerifiedAbsent -and
        $script:cleanupRegressionCalls -eq 1 -and
        (($script:cleanupRegressionArguments -join "`0") -ceq (@("distro", "disable", $closureResource.Name) -join "`0"))
    ) "Distribution cleanup did not retain its process helper when executing the captured disable action."
}
finally
{
    Set-Item -LiteralPath Function:\Invoke-E2EProcess -Value $originalProcessInvoker
    Remove-Item -LiteralPath $cleanupRegressionKey -Recurse -Force -ErrorAction SilentlyContinue
}

$originalWslInvoker = ${function:Invoke-E2EWsl}
$capturedWslCommand = @()
$capturedWslUser = $null
$capturedWslAllowFailure = $false
function Invoke-E2EWsl
{
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Distribution,
        [Parameter(Mandatory)][string[]]$Command,
        [string]$User = "root",
        [switch]$AllowFailure
    )

    $script:capturedWslCommand = @($Command)
    $script:capturedWslUser = $User
    $script:capturedWslAllowFailure = [bool]$AllowFailure
    [PSCustomObject]@{ ExitCode = 0; Output = "" }
}
try
{
    $multiLineBash = "printf '%s' first`r`nprintf '%s' second`r`n"
    Invoke-E2EBash $enablementContext "test-distribution" $multiLineBash -AllowFailure | Out-Null
    $wrapper = [string]$script:capturedWslCommand[2]
    $encoded = [regex]::Match($wrapper, "^printf '%s' '([A-Za-z0-9+/=]+)' \| base64 --decode \| /bin/bash -l$")
    Assert-E2ECondition (
        $script:capturedWslCommand.Count -eq 3 -and
        $script:capturedWslCommand[0] -eq "/bin/bash" -and
        $script:capturedWslCommand[1] -eq "-lc" -and
        $script:capturedWslUser -eq "root" -and
        $script:capturedWslAllowFailure -and
        $encoded.Success -and
        [Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String($encoded.Groups[1].Value)) -eq $multiLineBash.Replace("`r`n", "`n")
    ) "Multiline Bash commands were not encoded as one lossless WSL argument."
}
finally
{
    Set-Item -LiteralPath Function:\Invoke-E2EWsl -Value $originalWslInvoker
}

Add-E2ENativeCredentialApi
$markerBlob = [Collections.Generic.List[byte]]::new()
foreach ($byte in @(0xa1, 0x6a))
{
    $markerBlob.Add($byte)
}
$markerBlob.AddRange([Text.Encoding]::UTF8.GetBytes("attributes"))
foreach ($byte in @(0xa1, 0x67))
{
    $markerBlob.Add($byte)
}
$markerBlob.AddRange([Text.Encoding]::UTF8.GetBytes("e2e-run"))
foreach ($byte in @(0x78, 0x20))
{
    $markerBlob.Add($byte)
}
$markerBlob.AddRange([Text.Encoding]::UTF8.GetBytes($runId))
Assert-E2ECondition (
    [WinCredE2E.NativeCredentials]::ItemMetadataBlobHasRunMarker($markerBlob.ToArray(), $runId)
) "CBOR metadata marker parsing did not identify this run."
Assert-E2ECondition (
    ![WinCredE2E.NativeCredentials]::ItemMetadataBlobHasRunMarker($markerBlob.ToArray(), ("f" * 32 -join ""))
) "CBOR metadata marker parsing accepted another run."
$aliasBlob = [Collections.Generic.List[byte]]::new()
foreach ($byte in @(0xa2, 0x64))
{
    $aliasBlob.Add($byte)
}
$aliasBlob.AddRange([Text.Encoding]::UTF8.GetBytes("name"))
$aliasName = "e2e_$($runId.Substring(0, 16))"
$aliasBlob.Add(0x60 + $aliasName.Length)
$aliasBlob.AddRange([Text.Encoding]::UTF8.GetBytes($aliasName))
foreach ($byte in @(0x6d))
{
    $aliasBlob.Add($byte)
}
$aliasBlob.AddRange([Text.Encoding]::UTF8.GetBytes("collection_id"))
$aliasBlob.Add(0x50)
$aliasBlob.AddRange([byte[]](1..16))
$decodedAlias = [WinCredE2E.NativeCredentials]::AliasMetadataBlob($aliasBlob.ToArray())
Assert-E2ECondition (
    $decodedAlias[0] -eq $aliasName -and
    $decodedAlias[1] -eq "01020304-0506-0708-090a-0b0c0d0e0f10"
) "CBOR alias metadata parsing did not preserve the collection UUID."

$preExisting = [PSCustomObject]@{
    Target = "WinCredLibSecret/v1/item/$normalItemId/meta"
    Hash = $hash
}
$concurrentFixture = [PSCustomObject]@{
    Target = "WinCredLibSecret/v1/item/$normalItemId/secret/$normalGenerationId"
    Hash = $hash
}
$ownedMetadata = "WinCredLibSecret/v1/item/$itemId/meta"
$ownedGeneration = "WinCredLibSecret/v1/item/$itemId/secret/$generationId"
$ownedCollection = "WinCredLibSecret/v1/collection/$collectionId"
$ownedAlias = "WinCredLibSecret/v1/alias/ZTJlXzAxMjM0NTY3ODlhYmNkZWY"
$ownedDefaultAlias = "WinCredLibSecret/v1/alias/ZGVmYXVsdA"
$interruptedGeneration = "WinCredLibSecret/v1/item/$orphanItemId/secret/$orphanGenerationId"
$foreignNamespace = "ForeignApplication/e2e-$runId"

$inventory = @(
    $preExisting,
    $concurrentFixture,
    [PSCustomObject]@{ Target = $ownedMetadata; Hash = $hash },
    [PSCustomObject]@{ Target = $ownedGeneration; Hash = $hash },
    [PSCustomObject]@{ Target = $ownedCollection; Hash = $hash },
    [PSCustomObject]@{ Target = $ownedAlias; Hash = $hash },
    [PSCustomObject]@{ Target = $ownedDefaultAlias; Hash = $hash },
    [PSCustomObject]@{ Target = $interruptedGeneration; Hash = $hash },
    [PSCustomObject]@{ Target = $foreignNamespace; Hash = $hash }
)
$probe = {
    param($target)
    if ($target -eq $ownedMetadata)
    {
        return [PSCustomObject]@{ Kind = "item"; RunOwned = $true; AliasName = $null; CollectionId = $null }
    }
    if ($target -eq $ownedCollection)
    {
        return [PSCustomObject]@{ Kind = "collection"; RunOwned = $true; AliasName = $null; CollectionId = $null }
    }
    if ($target -eq $ownedAlias -or $target -eq $ownedDefaultAlias)
    {
        return [PSCustomObject]@{
            Kind = "alias"
            RunOwned = $false
            AliasName = if ($target -eq $ownedDefaultAlias) { "default" } else { "e2e_$($runId.Substring(0, 16))" }
            CollectionId = $collectionId
        }
    }
    if ($target -eq $preExisting.Target)
    {
        return [PSCustomObject]@{ Kind = "item"; RunOwned = $false; AliasName = $null; CollectionId = $null }
    }
    $null
}

$plan = New-E2ERunOwnedTargetPlan -Inventory $inventory -RunId $runId -InspectMetadata $probe
$expectedOwned = @($ownedMetadata, $ownedGeneration, $ownedCollection, $ownedAlias, $ownedDefaultAlias)
Assert-E2ECondition ($plan.Targets.Count -eq $expectedOwned.Count) "Cleanup plan did not limit itself to exact run-owned targets."
foreach ($target in $expectedOwned)
{
    Assert-E2ECondition ($plan.Targets -contains $target) "Expected run-owned target is missing from cleanup plan."
}
foreach ($target in @($preExisting.Target, $concurrentFixture.Target, $interruptedGeneration, $foreignNamespace))
{
    Assert-E2ECondition (!($plan.Targets -contains $target)) "Cleanup plan selected a pre-existing, concurrent, interrupted, or foreign target."
}

$finalInventory = @($preExisting, $concurrentFixture)
Assert-E2EInventoryEquals -Expected $finalInventory -Actual $finalInventory `
    -ExpectedName "initial plus concurrent fixture" -ActualName "final"
$repeatedPlan = New-E2ERunOwnedTargetPlan -Inventory $finalInventory -RunId $runId -InspectMetadata $probe
Assert-E2ECondition ($repeatedPlan.Targets.Count -eq 0) "Repeated cleanup selected a target after the first cleanup."
Assert-E2ECondition (
    (New-E2ERunOwnedTargetPlan -Inventory @() -RunId $runId -InspectMetadata $probe).Targets.Count -eq 0
) "Cleanup selected targets when a run failed before IDs were known."

function Get-E2EProjectCredentialInventory
{
    @()
}

$emptyInventoryContext = New-E2EContext $repoRoot
try
{
    $emptyInventoryContext.Resources.inventoryInitialized = $true
    $emptyPlan = Get-E2ERunOwnedTargetPlan -Context $emptyInventoryContext
    Assert-E2ECondition ($emptyPlan.Targets.Count -eq 0) "Cleanup did not handle an empty credential inventory."
    Complete-E2EInventory -Context $emptyInventoryContext
    Assert-E2ECondition $emptyInventoryContext.Resources.inventoryFinalized "Empty credential inventory was not finalized."
    $writtenEmptyInventory = Read-E2EInventoryFile $emptyInventoryContext.InventoryPath
    Assert-E2ECondition ($writtenEmptyInventory.Final.Count -eq 0) "Completed empty credential inventory was not serialized as an empty array."
}
finally
{
    Remove-Item -LiteralPath $emptyInventoryContext.InventoryPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $emptyInventoryContext.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$partialImportContext = New-E2EContext $repoRoot
try
{
    $partialName = "wincred-e2e-$($partialImportContext.RunId)-a"
    $partialRoot = Join-Path $partialImportContext.WorkRoot "distros\$partialName"
    Add-E2EDistributionResource -Context $partialImportContext -Name $partialName -Root $partialRoot
    Assert-E2ECondition (
        $partialImportContext.Resources.distributions.Contains($partialName) -and
        $partialImportContext.Resources.distributionRoots.Contains($partialRoot)
    ) "A partially imported disposable distro would not be recorded for exact cleanup."
}
finally
{
    Remove-Item -LiteralPath $partialImportContext.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$testRoot = Join-Path $repoRoot "test-results\e2e\cleanup-selftest-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try
{
    $inventoryName = "e2e-$runId.inventory.json"
    $inventoryPath = Join-Path $testRoot $inventoryName
    [ordered]@{
        schemaVersion = 1
        runId = $runId
        initial = @($preExisting)
        preserved = @($concurrentFixture)
        final = $finalInventory
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inventoryPath -Encoding utf8NoBOM

    $reportPath = Join-Path $testRoot "e2e-$runId.junit.xml"
    @"
<?xml version="1.0" encoding="utf-8"?>
<testsuite>
  <properties><property name="e2e.inventory" value="$inventoryName" /></properties>
  <testcase name="e2e.cleanup" />
  <testcase name="e2e.inventory" />
</testsuite>
"@ | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
    $verified = Get-E2EInventoryFromJUnitReport -ReportPath $reportPath -ResultDirectory $testRoot
    Assert-E2ECondition ($verified.RunId -eq $runId) "JUnit inventory association was not verified."

    $emptyRunId = [guid]::NewGuid().ToString("N")
    $emptyInventoryName = "e2e-$emptyRunId.inventory.json"
    [ordered]@{
        schemaVersion = 1
        runId = $emptyRunId
        initial = @()
        preserved = @()
        final = @()
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot $emptyInventoryName) -Encoding utf8NoBOM
    $emptyReportPath = Join-Path $testRoot "e2e-$emptyRunId.junit.xml"
    @"
<?xml version="1.0" encoding="utf-8"?>
<testsuite>
  <properties><property name="e2e.inventory" value="$emptyInventoryName" /></properties>
  <testcase name="e2e.cleanup" />
  <testcase name="e2e.inventory" />
</testsuite>
"@ | Set-Content -LiteralPath $emptyReportPath -Encoding utf8NoBOM
    $verifiedEmpty = Get-E2EInventoryFromJUnitReport -ReportPath $emptyReportPath -ResultDirectory $testRoot
    Assert-E2ECondition ($verifiedEmpty.Final.Count -eq 0) "JUnit cleanup verification did not accept an empty completed inventory."

    Assert-E2EThrows { Read-E2EInventoryFile -Path (Join-Path $testRoot "missing.inventory.json") } `
        "Missing inventory file was accepted."
    Set-Content -LiteralPath (Join-Path $testRoot "corrupt.inventory.json") -Value "{" -Encoding utf8NoBOM
    Assert-E2EThrows { Read-E2EInventoryFile -Path (Join-Path $testRoot "corrupt.inventory.json") } `
        "Corrupt inventory file was accepted."

    @"
<?xml version="1.0" encoding="utf-8"?>
<testsuite>
  <properties><property name="e2e.inventory" value="../$inventoryName" /></properties>
  <testcase name="e2e.cleanup" />
</testsuite>
"@ | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
    Assert-E2EThrows { Get-E2EInventoryFromJUnitReport -ReportPath $reportPath -ResultDirectory $testRoot } `
        "Unsafe JUnit inventory path was accepted."
}
finally
{
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$pluginLoadState = [PSCustomObject]@{
    Invocation = $null
}
$pluginLoadPath = Join-Path $repoRoot "artifacts\Release\windows\wincred-libsecret-wsl-plugin.dll"

function Invoke-E2EProcess
{
    param(
        $Context,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [switch]$AllowFailure
    )

    $script:pluginLoadState.Invocation = [PSCustomObject]@{
        FilePath = $FilePath
        Arguments = $ArgumentList
    }
    [PSCustomObject]@{
        ExitCode = 0
        Output = ""
    }
}

function Get-CimInstance
{
    param(
        [string]$ClassName,
        [string]$Filter,
        $ErrorAction
    )

    [PSCustomObject]@{ ProcessId = 4321 }
}

function Get-Process
{
    param(
        [int]$Id,
        $ErrorAction
    )

    [PSCustomObject]@{
        Modules = @(
            [PSCustomObject]@{ FileName = [IO.Path]::GetFullPath($script:pluginLoadPath) }
        )
    }
}

Assert-E2EPluginLoaded `
    -Context ([PSCustomObject]@{}) `
    -PluginPath $pluginLoadPath `
    -StartupDistribution "wincred-e2e-source"
Assert-E2ECondition (
    $pluginLoadState.Invocation.FilePath -eq "wsl.exe" -and
    ($pluginLoadState.Invocation.Arguments -join "|") -eq
        "--distribution|wincred-e2e-source|--user|root|--|/bin/true"
) "Plugin load validation did not trigger the source distribution through wsl.exe."

Write-Host "E2E helper unit scenarios passed without accessing live credentials, WSL, certificates, or registry state."
