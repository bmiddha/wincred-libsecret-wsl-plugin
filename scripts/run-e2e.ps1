[CmdletBinding()]
param(
    [switch]$PrerequisiteOnly,
    [switch]$DryRun,
    [switch]$Full,
    [string]$WslSourceDistro,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$RootfsPath,
    [switch]$AllowReplacePluginConflict,
    [switch]$RequireFull
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot "tests\e2e\E2E.Common.ps1")

$context = New-E2EContext $repoRoot
$completed = $false
try
{
    $prerequisites = Assert-E2EPrerequisites $context $WslSourceDistro
    if ($PrerequisiteOnly -or $DryRun)
    {
        $modeDetail = if ($DryRun) { "Dry-run requested; no resources were changed." } else { "Prerequisite-only mode requested." }
        Add-E2EResult $context "e2e.execution" "skipped" $modeDetail
        if ($RequireFull)
        {
            throw "-RequireFull cannot be used with -PrerequisiteOnly or -DryRun."
        }
        $completed = $true
        return
    }
    if (!$Full)
    {
        throw "E2E is opt-in. Specify -Full after reviewing the disposable-resource policy, or use -PrerequisiteOnly/-DryRun."
    }
    $buildReady = @("x64Windows", "wslVersion", "wsl2", "rust", "visualStudio", "source") |
        ForEach-Object { $prerequisites.Checks[$_] } |
        Where-Object { !$_.Equals($true) } |
        Measure-Object |
        Select-Object -ExpandProperty Count |
        ForEach-Object { $_ -eq 0 }
    if (!$buildReady)
    {
        Add-E2EResult $context "e2e.nonprivileged-components" "skipped" "Build prerequisites are unavailable; no host resources were changed."
        if ($RequireFull)
        {
            throw "Full E2E prerequisites are unavailable; the privileged test must not be skipped."
        }
        $completed = $true
        return
    }

    $source = $prerequisites.SourceDistribution
    Invoke-E2EAssertion $context "component.release-build" {
        & (Join-Path $repoRoot "scripts\build.ps1") -Configuration Release -WslDistribution $source
        if ($LASTEXITCODE -ne 0) { throw "Release build failed." }
    } | Out-Null
    Invoke-E2EAssertion $context "component.test-runner" {
        & (Join-Path $repoRoot "test.ps1") -Configuration Release -WslDistribution $source -RunLinux
        if ($LASTEXITCODE -ne 0) { throw "Existing component test runner failed." }
    } | Out-Null

    if (!$prerequisites.FullReady)
    {
        $windows = Join-Path $repoRoot "artifacts\Release\windows"
        $plugin = Join-Path $windows "wincred-libsecret-wsl-plugin.dll"
        $cli = Join-Path $windows "wincred-libsecret.exe"
        $broker = Join-Path $windows "wincred-libsecret-broker.exe"
        $certificateState = Join-Path $context.WorkRoot "dev-signing\certificate-state.json"
        $context.Resources.certificateState = $certificateState
        try
        {
            & (Join-Path $repoRoot "scripts\New-DevSigningCertificate.ps1") -StatePath $certificateState -TrustForCurrentUser -SignPath @($plugin, $cli, $broker)
            . (Join-Path $repoRoot "scripts\Signing.Common.ps1")
            Assert-ReleaseSignature -Path @($plugin, $cli, $broker)
            Add-E2EResult $context "signing.nonprivileged-dev-path" "passed" "Artifacts were signed and verified with an isolated CurrentUser certificate."
        }
        catch
        {
            Add-E2EResult $context "signing.nonprivileged-dev-path" "skipped" "Host trust policy prevented the safe development signing path: $($_.Exception.Message)"
        }
        Add-E2EResult $context "e2e.plugin-load" "skipped" "Administrator or WSL runtime policy prevents registry/service plugin loading; Release, component, and safe signing coverage completed."
        if ($RequireFull)
        {
            throw "Full privileged E2E prerequisites are unavailable; plugin loading must not be skipped."
        }
        $completed = $true
        return
    }

    # Capture the pre-run project inventory before any E2E resource is
    # created. The persisted snapshot contains only target names and hashes.
    Initialize-E2EInventory $context

    $windows = Join-Path $repoRoot "artifacts\Release\windows"
    $plugin = Join-Path $windows "wincred-libsecret-wsl-plugin.dll"
    $cli = Join-Path $windows "wincred-libsecret.exe"
    $broker = Join-Path $windows "wincred-libsecret-broker.exe"
    $certificateState = Join-Path $context.WorkRoot "dev-signing\certificate-state.json"
    $context.Resources.certificateState = $certificateState
    Invoke-E2EAssertion $context "signing.isolated-dev-certificate" {
        & (Join-Path $repoRoot "scripts\New-DevSigningCertificate.ps1") -StatePath $certificateState -TrustForLocalMachine -SignPath @($plugin, $cli, $broker)
    } | Out-Null
    Invoke-E2EAssertion $context "signing.verify-artifacts" {
        . (Join-Path $repoRoot "scripts\Signing.Common.ps1")
        Assert-ReleaseSignature -Path @($plugin, $cli, $broker)
    } | Out-Null

    New-E2EUnrelatedCredential $context
    . (Join-Path $repoRoot "scripts\DevPlugin.Common.ps1")
    $pluginState = Get-DevPluginStatePath
    $context.Resources.pluginState = $pluginState
    $context.Resources.pluginStateExistedBefore = Test-Path -LiteralPath $pluginState
    if ($context.Resources.pluginStateExistedBefore)
    {
        throw "Protected developer plugin state already exists at '$pluginState'. Clean it up before running isolated E2E."
    }
    $existingPlugin = Get-PluginRegistryValue
    if ($null -ne $existingPlugin -and !$existingPlugin.Value.Equals($plugin, [StringComparison]::OrdinalIgnoreCase) -and !$AllowReplacePluginConflict)
    {
        Add-E2EResult $context "plugin.conflict-preflight" "passed" "Foreign plugin value was detected and preserved; use -AllowReplacePluginConflict only after reviewing it."
        Add-E2EResult $context "e2e.plugin-load" "skipped" "Plugin conflict was safely preserved. Release/component coverage completed."
        if ($RequireFull)
        {
            throw "A foreign plugin registration blocks the privileged E2E run; it must not be skipped."
        }
        $completed = $true
        return
    }
    Invoke-E2EAssertion $context "plugin.conflict-preflight" {
        & (Join-Path $repoRoot "scripts\Install-DevPlugin.ps1") -DllPath $plugin -WhatIf
    } | Out-Null
    Invoke-E2EAssertion $context "plugin.install-exact-hklm-value" {
        $arguments = @{ DllPath = $plugin; RestartWslService = $true }
        if ($AllowReplacePluginConflict) { $arguments.ReplaceConflict = $true }
        & (Join-Path $repoRoot "scripts\Install-DevPlugin.ps1") @arguments
    } | Out-Null
    Invoke-E2EAssertion $context "plugin.loaded-by-wslservice" {
        Assert-E2EPluginLoaded -Context $context -PluginPath $plugin -StartupDistribution $source
    } | Out-Null

    $distros = Invoke-E2EAssertion $context "distros.create-disposable-systemd-pairs" {
        @(New-E2EDistributions $context $source $RootfsPath)
    }
    $a, $b = $distros
    $payload = Join-Path $repoRoot "artifacts\Release\linux"
    Invoke-E2EAssertion $context "distro-a.enable" {
        Invoke-E2EProcess $context $cli @("distro", "enable", $a, "--payload-root", $payload, "--broker", $broker, "--replace-conflicts") | Out-Null
        Register-E2EDistributionEnablement $context $a
    } | Out-Null

    # A disposable foreign D-Bus definition proves refusal and reversible
    # replacement without touching a user's existing distribution.
    Invoke-E2EBash $context $b "printf '[D-BUS Service]`nName=org.freedesktop.secrets`nExec=/bin/false`n' > /usr/share/dbus-1/services/org.freedesktop.secrets.service" | Out-Null
    $conflictHash = (Invoke-E2EBash $context $b "sha256sum /usr/share/dbus-1/services/org.freedesktop.secrets.service | awk '{print `$1}'").Output.Trim()
    Invoke-E2EAssertion $context "distro-b.conflict-refusal" {
        $result = Invoke-E2EProcess $context $cli @("distro", "enable", $b, "--payload-root", $payload, "--broker", $broker) -AllowFailure
        if ($result.ExitCode -eq 0) { throw "Provider enable unexpectedly overwrote a foreign D-Bus service definition." }
        $after = (Invoke-E2EBash $context $b "sha256sum /usr/share/dbus-1/services/org.freedesktop.secrets.service | awk '{print `$1}'").Output.Trim()
        if ($after -ne $conflictHash) { throw "Foreign D-Bus service definition changed during refusal." }
    } | Out-Null
    Invoke-E2EAssertion $context "distro-b.reversible-conflict-replacement" {
        Invoke-E2EProcess $context $cli @("distro", "enable", $b, "--payload-root", $payload, "--broker", $broker, "--replace-conflicts") | Out-Null
        Register-E2EDistributionEnablement $context $b
        Invoke-E2EProcess $context $cli @("distro", "disable", $b) | Out-Null
        Assert-E2EDistributionEnablementAbsent $context $b
        $restored = (Invoke-E2EBash $context $b "sha256sum /usr/share/dbus-1/services/org.freedesktop.secrets.service | awk '{print `$1}'").Output.Trim()
        if ($restored -ne $conflictHash) { throw "Foreign D-Bus definition was not restored." }
        Invoke-E2EProcess $context $cli @("distro", "enable", $b, "--payload-root", $payload, "--broker", $broker, "--replace-conflicts") | Out-Null
        Register-E2EDistributionEnablement $context $b
    } | Out-Null

    foreach ($distro in $distros)
    {
        Invoke-E2EAssertion $context "distro.$distro.payload-and-refresh" {
            $doctor = Invoke-E2EBash $context $distro '/usr/libexec/wincred-libsecret/wincred-libsecret-refresh --doctor'
            if ($doctor.Output -notmatch 'CHECK payload-hashes ok' -or $doctor.Output -notmatch 'CHECK modes ok' -or $doctor.Output -notmatch 'CHECK activation ok') { throw "Payload doctor did not validate hashes, modes, and D-Bus activation." }
            Invoke-E2EBash $context $distro 'systemctl is-enabled --quiet wincred-libsecret-refresh.service' | Out-Null
            Invoke-E2EBash $context $distro 'systemctl start wincred-libsecret-refresh.service; systemctl is-active --quiet wincred-libsecret-refresh.service || test "$(systemctl show -p Result --value wincred-libsecret-refresh.service)" = success' | Out-Null
        } | Out-Null
    }
    Invoke-E2EAssertion $context "distro.refresh-all-upgrade-lifecycle" {
        Invoke-E2EProcess $context $cli @(
            "distro",
            "refresh",
            "--all",
            "--payload-root",
            $payload,
            "--broker",
            $broker
        ) | Out-Null
        foreach ($distro in $distros)
        {
            $doctor = Invoke-E2EBash $context $distro '/usr/libexec/wincred-libsecret/wincred-libsecret-refresh --doctor'
            if ($doctor.Output -notmatch 'CHECK payload-hashes ok' -or
                $doctor.Output -notmatch 'CHECK activation ok' -or
                $doctor.Output -notmatch 'CHECK modes ok')
            {
                throw "Refreshed payload validation failed in '$distro'."
            }
        }
    } | Out-Null
    Invoke-E2EAssertion $context "plugin.lifecycle-refresh-launch" {
        $traceName = "WinCredLibsecretE2E-$($context.RunId)"
        $tracePath = Join-Path $context.ResultRoot "e2e-$($context.RunId).plugin-lifecycle.etl"
        $traceStarted = $false
        try
        {
            & logman.exe start $traceName `
                -p "{88D50C75-62EB-43E0-9DAC-197745EA38E2}" 0xFFFFFFFF 0xFF `
                -o $tracePath -ets
            if ($LASTEXITCODE -ne 0)
            {
                throw "Could not start the plugin lifecycle ETW trace."
            }
            $traceStarted = $true
            Invoke-E2EBash $context $a 'systemctl stop wincred-libsecret-refresh.service || true; systemctl reset-failed wincred-libsecret-refresh.service || true' | Out-Null
            Invoke-E2EProcess $context "wsl.exe" @("--terminate", $a) | Out-Null
            Invoke-E2EBash $context $a 'true' | Out-Null
            $result = Invoke-E2EBash $context $a @'
for attempt in $(seq 1 20); do
  result="$(systemctl show -p Result --value wincred-libsecret-refresh.service)"
  if [[ "$result" == success ]]; then
    systemctl show -p Result -p ExecMainStartTimestampMonotonic wincred-libsecret-refresh.service
    exit 0
  fi
  sleep 1
done
systemctl show -p Result -p ExecMainStartTimestampMonotonic wincred-libsecret-refresh.service >&2
exit 1
'@
            if ($result.Output -notmatch 'Result=success' -or $result.Output -notmatch 'ExecMainStartTimestampMonotonic=[1-9][0-9]*')
            {
                throw "WSL plugin lifecycle did not launch the refresh service after the enabled distro restarted."
            }
        }
        finally
        {
            if ($traceStarted)
            {
                & logman.exe stop $traceName -ets | Out-Null
                if ($LASTEXITCODE -ne 0)
                {
                    Write-E2ELog $context "Could not stop plugin lifecycle ETW trace '$traceName'."
                }
                else
                {
                    Write-E2ELog $context "Plugin lifecycle ETW trace saved to '$([IO.Path]::GetFileName($tracePath))'."
                }
            }
        }
    } | Out-Null

    $repoInA = Get-E2EWslPath $context $a $repoRoot
    $repoInB = Get-E2EWslPath $context $b $repoRoot
    $linux = "bash '$repoInA/tests/e2e/run-linux-e2e.sh' --run-id '$($context.RunId)' --work-root /opt/wincred-e2e"
    Invoke-E2EAssertion $context "linux.secret-tool-libsecret-direct-dbus" {
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode write" "e2eone" | Out-Null
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode direct" "e2eone" | Out-Null
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode limits" "e2eone" | Out-Null
    } | Out-Null
    foreach ($entry in @(
        @{ distro = $a; user = "e2eone"; mode = "read"; repo = $repoInA },
        @{ distro = $a; user = "e2etwo"; mode = "read"; repo = $repoInA },
        @{ distro = $b; user = "e2eone"; mode = "read"; repo = $repoInB },
        @{ distro = $b; user = "e2etwo"; mode = "read"; repo = $repoInB }
    ))
    {
        Invoke-E2EAssertion $context "shared-vault.$($entry.distro).$($entry.user)" {
            $command = "dbus-run-session -- bash '$($entry.repo)/tests/e2e/run-linux-e2e.sh' --mode $($entry.mode) --run-id '$($context.RunId)' --work-root /opt/wincred-e2e"
            Invoke-E2EBash $context $entry.distro $command $entry.user | Out-Null
        } | Out-Null
    }
    Invoke-E2EAssertion $context "shared-vault.reverse-update-and-concurrency" {
        Invoke-E2EBash $context $b "dbus-run-session -- bash '$repoInB/tests/e2e/run-linux-e2e.sh' --mode reverse --run-id '$($context.RunId)' --work-root /opt/wincred-e2e" "e2etwo" | Out-Null
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode read-reverse" "e2eone" | Out-Null
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode concurrent" "e2eone" | Out-Null
    } | Out-Null
    Invoke-E2EAssertion $context "windows.broker-and-credential-generations" {
        $env:WINCRED_LIVE_TESTS = "1"
        & cargo test -p wincred-libsecret-broker --test wincred_integration -- --ignored --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw "Windows broker operation test failed." }
        Assert-E2EWinCredState $context
    } | Out-Null

    Invoke-E2EAssertion $context "restart.persistence-and-isolation" {
        Invoke-E2EProcess $context "wsl.exe" @("--terminate", $a) | Out-Null
        Invoke-E2EBash $context $a "dbus-run-session -- $linux --mode read-reverse" "e2eone" | Out-Null
        Invoke-E2EProcess $context "wsl.exe" @("--shutdown") | Out-Null
        Invoke-E2EBash $context $b "dbus-run-session -- bash '$repoInB/tests/e2e/run-linux-e2e.sh' --mode read-reverse --run-id '$($context.RunId)' --work-root /opt/wincred-e2e" "e2eone" | Out-Null
        Invoke-E2EBash $context $a 'mv /usr/libexec/wincred-libsecret/wincred-libsecret-provider /opt/wincred-e2e/provider.saved' | Out-Null
        try { Invoke-E2EBash $context $b 'true' | Out-Null }
        finally { Invoke-E2EBash $context $a 'mv /opt/wincred-e2e/provider.saved /usr/libexec/wincred-libsecret/wincred-libsecret-provider' | Out-Null }
        Invoke-E2EProcess $context $cli @("distro", "disable", $b) | Out-Null
        Assert-E2EDistributionEnablementAbsent $context $b
        Invoke-E2EBash $context $b '! grep -Fq "X-WinCred-Libsecret=1" /usr/share/dbus-1/services/org.freedesktop.secrets.service' | Out-Null
        Invoke-E2EProcess $context $cli @("distro", "enable", $b, "--payload-root", $payload, "--broker", $broker, "--replace-conflicts") | Out-Null
        Register-E2EDistributionEnablement $context $b
        Invoke-E2EBash $context $b "dbus-run-session -- bash '$repoInB/tests/e2e/run-linux-e2e.sh' --mode read-reverse --run-id '$($context.RunId)' --work-root /opt/wincred-e2e" "e2eone" | Out-Null
    } | Out-Null
    $completed = $true
}
finally
{
    try
    {
        Remove-E2EResources $context
        Add-E2EResult $context "e2e.cleanup" "passed" "Disposable distros, test credentials, registration, and development certificate were removed or restored."
    }
    catch
    {
        Add-E2EResult $context "e2e.cleanup" "failed" $_.Exception.Message
        $completed = $false
    }
    try
    {
        Complete-E2EInventory $context
        if ($context.Resources.inventoryInitialized)
        {
            Add-E2EResult $context "e2e.inventory" "passed" "Sanitized final inventory matches the initial inventory and preserved concurrent fixtures."
        }
    }
    catch
    {
        Add-E2EResult $context "e2e.inventory" "failed" $_.Exception.Message
        $completed = $false
    }
    Write-E2EJUnit $context
}

if (!$completed -or @($context.Results | Where-Object Status -eq "failed").Count -gt 0)
{
    exit 1
}
