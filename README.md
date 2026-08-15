<p align="center">
  <img src="assets/logo.svg" alt="WinCred Libsecret WSL Plugin logo" width="180">
</p>

# WinCred Libsecret WSL Plugin

`wincred-libsecret-wsl-plugin` provides a Freedesktop Secret Service in WSL
whose persistent data is stored in the current Windows user's Credential
Manager vault. Linux applications use the standard
`org.freedesktop.secrets` D-Bus name through libsecret or `secret-tool`; they
do not call a project-specific Linux API.

> **Security model in one sentence:** all enabled WSL distributions and Linux
> users that belong to one Windows user share one project-namespaced WinCred
> vault. Linux UID is not a vault boundary.

## Install

Open a non-elevated PowerShell session and run the public release installer:

```powershell
$installer = Join-Path $env:TEMP 'wincred-libsecret-install.ps1'
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/bmiddha/wincred-libsecret-wsl-plugin/main/install.ps1 `
  -OutFile $installer
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
```

It requests elevation only to install the MSI. The elevated installer downloads
the latest stable GitHub Release to protected staging, verifies GitHub's asset
digest and the release checksums, and validates the Azure Artifact Signing
metadata and MSI Authenticode signature. The original non-elevated session then
refreshes enabled WSL distributions.
To install a particular release, add `-Version`, for example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -Version v0.1.0
```

Pass `-IncludePrerelease` to select the newest published prerelease.

The installer uses unauthenticated GitHub endpoints, so the selected release
must be public. Azure Artifact Signing uses a standard Windows-trusted
Authenticode chain, so the installer does not import a release certificate or
download private signing material. Public releases also publish GitHub artifact
attestations; see
[Installation and operations](docs/installation-and-operations.md#release-trust-and-signing)
for optional provenance verification.

After the MSI is installed, enable each WSL distribution that should use the
provider:

```powershell
$cli = Join-Path $env:ProgramFiles 'WinCredLibsecret\wincred-libsecret.exe'
& $cli distro enable <distro-name>
& $cli doctor --distro <distro-name>
```

Existing `org.freedesktop.secrets` activation files are backed up and restored
by uninstall. To replace an existing Secret Service provider, review it first,
then add `--replace-conflicts` to `distro enable`.

If another machine-wide WSL plugin is already installed (for example the
Microsoft Defender for Endpoint WSL plugin), the installer preserves it and
skips WinCred lifecycle-plugin registration. The libsecret provider still
works normally in every enabled distro.

Open a new WSL shell and verify it:

```bash
printf 'hello' | secret-tool store --label='WinCred test' app wincred-test
secret-tool lookup app wincred-test
```

To fully remove the plugin and restore previous Secret Service definitions,
run this from a non-elevated PowerShell session:

```powershell
& $cli uninstall
```

The uninstall command removes project-owned WSL provisioning and this user's
enablement records before requesting elevation to remove the MSI. It preserves
secrets already stored in Windows Credential Manager.

## Documentation

- [Architecture](docs/architecture.md) — components, identities, lifecycle,
  D-Bus activation, and the CBOR bridge.
- [WinCred data model](docs/wincred-data-model.md) — target names, metadata,
  generations, limits, and recovery.
- [Installation and operations](docs/installation-and-operations.md) —
  signing, MSI and development installation, provisioning, diagnostics,
  recovery, and rollback.
- [Development and testing](docs/development-and-testing.md) — toolchains,
  component tests, live tests, E2E, CI expectations, and releases.
- [Troubleshooting](docs/troubleshooting.md) — common failures and complete
  removal.
- [Contributing](CONTRIBUTING.md).

## Architecture overview

```text
Linux application ──libsecret / D-Bus──> WSL provider
                                         │ persistent stdio bridge
                                         │ (length-prefixed CBOR)
                                         v
                                   Windows broker.exe
                                         │ project targets only
                                         v
                         current Windows user's Credential Manager

wslservice loads the signed x64 DLL. On a started, enabled distribution it
impersonates that session's Windows token to read the enablement flag, then
asks WSL to start the distro refresh unit. It never brokers secret requests.
```

The global D-Bus activation definition and user systemd service make the
provider available to each user's session bus in an enabled distribution.
Each provider starts the Windows broker through WSL interop. The broker
enumerates and mutates only `WinCredLibSecret/v1/` generic credentials; it
cannot read arbitrary Credential Manager entries. See
[Architecture](docs/architecture.md) and
[the schema](docs/wincred-data-model.md).

## Supported matrix

| Requirement | Supported configuration |
| --- | --- |
| Host architecture | Windows x64 only |
| WSL runtime | WSL **2.5.1 or newer** |
| Distribution | WSL 2, x86_64 |
| Init and bus | systemd active, session D-Bus implementation available |
| Windows interop | `cmd.exe` available and usable from the distribution |
| Secret API | Freedesktop Secret Service / `org.freedesktop.secrets` |
| Isolation | One shared vault per Windows user; no Linux-UID separation |

The bootstrap checks the x86_64 architecture, active systemd, D-Bus tools and
activation directory, usable Windows interop, broker reachability, payload
hashes, and file ownership/modes. It does not support WSL 1, non-x64 Linux
guests, a distro without systemd, or disabled Windows interop.

## Build prerequisites

For the complete Windows build, install:

- Windows x64, WSL 2.5.1+, and a systemd-enabled WSL distribution;
- Rust toolchain **1.97.1** (the Linux scripts select it explicitly);
- Visual Studio with the C++ toolchain, CMake, Ninja, and `vswhere`;
- CMake 3.28+ (the WSL Plugin API 2.9.3 is fetched with a pinned SHA-256);
- .NET SDK for the repository-local, pinned WiX tool when packaging.

The Linux build needs the Rust toolchain and an x86_64 WSL environment. The
full E2E runner also provisions disposable Debian/Ubuntu-style distributions;
it installs `dbus-user-session`, `dbus`, `libsecret-tools`,
`libsecret-1-dev`, a C compiler, and `pkg-config` when `apt-get` is present.

```powershell
scripts\build.ps1 -Configuration Debug -WslDistribution <distro>
test.ps1 -Configuration Debug -WslDistribution <distro> -RunLinux
```

Use an exact registered WSL distribution name for `<distro>`. See
[Development and testing](docs/development-and-testing.md) for narrower
commands and safe live-WinCred tests.

## Manual signed-MSI installation

1. Download the release MSI, `checksums.sha256`, and
   `wincred-libsecret-release-signing.txt`. Verify the published checksums and
   signer metadata:

   ```powershell
   Get-Content .\checksums.sha256 | ForEach-Object {
     $expected, $name = $_ -split ' \*', 2
     if ((Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
       throw "Checksum mismatch: $name"
     }
   }
   $signer = Get-AuthenticodeSignature -LiteralPath .\wincred-libsecret-wsl-plugin.msi
   if ($signer.Status -ne 'Valid') {
     throw "MSI Authenticode validation failed: $($signer.Status)"
   }
   $metadata = @{}
   Get-Content .\wincred-libsecret-release-signing.txt | ForEach-Object {
     $name, $value = $_ -split ': ', 2
     $metadata[$name] = $value
   }
   if ($signer.SignerCertificate.Subject -ne $metadata.Subject -or
       $signer.SignerCertificate.Issuer -ne $metadata.Issuer -or
       !$signer.SignerCertificate.Thumbprint.Equals(
         $metadata.Thumbprint,
         [StringComparison]::OrdinalIgnoreCase
       )) {
     throw 'MSI signer does not match release signing metadata.'
   }
   ```

   See [Installation and operations](docs/installation-and-operations.md#release-trust-and-signing)
   for optional GitHub artifact-attestation verification.

2. Install the MSI from an elevated PowerShell session:

   ```powershell
   msiexec.exe /i .\wincred-libsecret-wsl-plugin.msi
   ```

3. Restart `wslservice` (or reboot/restart WSL) so it reloads the plugin, then
   inspect the registration:

   ```powershell
   $cli = Join-Path $env:ProgramFiles 'WinCredLibsecret\wincred-libsecret.exe'
   & $cli plugin status
   ```

4. Enable one WSL 2 distribution. Enabling provisions its Linux files before
   it writes the per-user callback flag:

   ```powershell
   & $cli distro enable <distro-name>
   & $cli distro list
   & $cli doctor --distro <distro-name>
   ```

If another Secret Service activation file exists, enable refuses rather than
overwrite it. Review the existing provider, then use
`--replace-conflicts` only when it is appropriate to make a root-owned,
reversible backup:

```powershell
& $cli distro enable <distro-name> --replace-conflicts
```

The MSI registers the signed DLL using guarded custom actions. It does not
enable distributions automatically.

## Development installation

Development registration changes HKLM and therefore requires an elevated
PowerShell session. Build first, create a short-lived non-exportable
CurrentUser code-signing certificate, trust only its public certificate for
the intended scope, and sign the DLL/EXEs:

```powershell
scripts\build.ps1 -Configuration Debug -WslDistribution <distro>
$artifacts = '.\artifacts\Debug\windows'
$files = @(
  (Join-Path $artifacts 'wincred-libsecret-wsl-plugin.dll'),
  (Join-Path $artifacts 'wincred-libsecret.exe'),
  (Join-Path $artifacts 'wincred-libsecret-broker.exe')
)
scripts\New-DevSigningCertificate.ps1 -TrustForCurrentUser -SignPath $files
scripts\Install-DevPlugin.ps1 -DllPath $files[0] -RestartWslService
scripts\Get-DevPluginStatus.ps1
```

`Install-DevPlugin.ps1` records a replaced project value only in the fixed
machine-protected state store at
`%ProgramData%\WinCredLibsecret\DevPlugin\plugin-registration.json`.
The store is restricted to SYSTEM and Administrators; callers cannot supply a
state path. It rejects an existing different registration unless
`-ReplaceConflict` is explicit. `-AllowUnsigned` is only for isolated local
development; do not use it for a release or broadly trusted host.

After testing, disable any test distributions, restore the dev registration,
and remove the dev certificate:

```powershell
scripts\Uninstall-DevPlugin.ps1 -RestartWslService
scripts\Remove-DevSigningCertificate.ps1
```

Details, including production signing and MSI repair/upgrade behavior, are in
[Installation and operations](docs/installation-and-operations.md).

## Plugin and distribution commands

The management CLI is a Windows program. Its commands are:

```text
wincred-libsecret plugin install --dll <absolute-dll-path>
    [--allow-unsigned] [--restart-wslservice]
wincred-libsecret plugin uninstall [--dll <absolute-dll-path>]
    [--restart-wslservice]
wincred-libsecret plugin status
wincred-libsecret upgrade [--include-prerelease]
wincred-libsecret uninstall [--keep-distro-provisioning]

wincred-libsecret distro enable <distro-name>
    [--payload-root <directory>] [--broker <absolute-exe-path>]
    [--replace-conflicts]
wincred-libsecret distro disable <distro-name>
wincred-libsecret distro refresh [<distro-name> | --all]
    [--payload-root <directory>] [--broker <absolute-exe-path>]
wincred-libsecret distro list
wincred-libsecret doctor [--distro <distro-name>] [--include-prerelease]
```

`plugin install` requires elevation, a real absolute DLL, and a `Valid`
Authenticode signature unless the explicit development-only override is
given. `plugin uninstall --dll` removes the registry value only if it still
names that DLL. The per-distro operations use the exact distribution name and
support names with spaces.

Run `upgrade` and `uninstall` from a non-elevated terminal. Each starts a
packaged helper, then exits so Windows can replace or remove the running CLI;
the helper requests elevation only for MSI work. Upgrade refreshes and
validates enabled distro payloads after the MSI completes.

The registry locations are deliberately narrow:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins
  wincred-libsecret-wsl-plugin = <absolute signed DLL path>

HKCU\Software\wincred-libsecret\WSLPlugin\Distributions\{distro-guid}
  Enabled = DWORD 1
```

The DLL reads the latter under the distribution session user's impersonated
token; it does not use the LocalSystem user vault. `doctor` emits non-secret
readiness findings for WSL version, plugin registration/path/signature, WSL 2
state, enablement, systemd, D-Bus, interop, broker reachability, payload
hashes, activation definitions, and ownership/modes.
It also reports a newer public GitHub Release when one is available. A release
lookup failure is a warning and does not suppress local diagnostic results.

## Using the Secret Service

In an enabled distribution, run these in a user's graphical or terminal D-Bus
session. This example reads the value without putting a secret literal in
shell history or source:

```bash
read -r -s -p 'Secret: ' SECRET; printf '\n'
printf '%s' "$SECRET" |
  secret-tool store --label='Example credential' service example.test user example-user
unset SECRET

secret-tool lookup service example.test user example-user
secret-tool clear service example.test user example-user
```

The provider is compatible with libsecret. An application opens the normal
`org.freedesktop.Secret.Service` service; no project-only object path or
socket is required. Collections, aliases, item attributes, labels, binary
secrets, and Unicode metadata are persisted by the project schema.

## Limits and behavior

- A secret blob is at most **2,560 bytes**. Exactly 2,560 bytes is accepted;
  2,561 bytes is rejected.
- Secret bytes are binary-safe. Labels, aliases, content types, and
  attributes are UTF-8 and reject NUL. Their byte limits are documented in
  [the data model](docs/wincred-data-model.md).
- Collections report as always unlocked. `Lock`/`Unlock` are compatibility
  operations, not a separate Linux lock screen or additional encryption key.
- Updates use a new secret generation followed by metadata as the visibility
  commit point. Startup reconciliation removes abandoned generations and
  reports metadata that points to a missing generation.
- This is not a general Credential Manager browser: it cannot access targets
  outside `WinCredLibSecret/v1/`.

## Diagnostics, troubleshooting, and safe uninstall

Use the CLI doctor first:

```powershell
& $cli doctor --distro <distro-name>
```

On Linux, the per-distro diagnostic is:

```bash
sudo /usr/libexec/wincred-libsecret/wincred-libsecret-refresh --doctor
systemctl --user status wincred-libsecret.service
journalctl --user -u wincred-libsecret.service
```

The plugin logs failure operation/status pairs through ETW provider
`WinCredLibsecret.WslPlugin`; it does not log secret data. See
[Troubleshooting](docs/troubleshooting.md) for signing,
`TRUST_E_NOSIGNATURE`, service, systemd, D-Bus, interop, conflict, limit, and
corrupt-generation recovery.

To remove a release installation safely, run `wincred-libsecret uninstall`
from a non-elevated PowerShell session. It disables every registered project
distribution before MSI removal, restores backed-up Secret Service definitions,
removes only project-owned enablement records, and preserves the WinCred vault.
Use `--keep-distro-provisioning` only for a deliberate migration; otherwise it
would leave Linux payloads that should be disabled before MSI removal. For a
development registration, unregister the tracked development DLL, restart
`wslservice`, and remove the development certificate/state if used. Back up or
delete only the explicitly named project targets if complete credential-data
removal is intended; see the complete-removal procedure in
[Troubleshooting](docs/troubleshooting.md).

## Current local execution evidence

The canonical full cross-boundary validation runs in the `Hosted WSL E2E`
GitHub Actions workflow on an ephemeral Windows 2025 VM. It creates
disposable resources with `finally` cleanup, so local plugin-load observations
are never represented as a completed cross-distro E2E run.
