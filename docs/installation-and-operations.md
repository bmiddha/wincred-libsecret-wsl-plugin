# Installation and operations

## Release trust and signing

Public GitHub Releases use Azure Artifact Signing for the DLL, CLI, broker,
and MSI. The release workflow authenticates to Azure with GitHub OIDC in its
protected `release` environment; no long-lived signing PFX or self-signed root
certificate is stored in the repository or release workflow.

Before manually installing a GitHub Release, download the MSI,
`checksums.sha256`, and `wincred-libsecret-release-signing.txt`. Verify the
checksums, then validate the Windows Authenticode chain and signer metadata:

```powershell
Get-Content .\checksums.sha256 | ForEach-Object {
  $expected, $name = $_ -split ' \*', 2
  $actual = (Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "Checksum mismatch: $name" }
}
$signature = Get-AuthenticodeSignature -LiteralPath .\wincred-libsecret-wsl-plugin.msi
if ($signature.Status -ne 'Valid') {
  throw "MSI Authenticode validation failed: $($signature.Status)"
}
$metadata = @{}
Get-Content .\wincred-libsecret-release-signing.txt | ForEach-Object {
  $name, $value = $_ -split ': ', 2
  $metadata[$name] = $value
}
if ($signature.SignerCertificate.Subject -ne $metadata.Subject -or
    $signature.SignerCertificate.Issuer -ne $metadata.Issuer -or
    !$signature.SignerCertificate.Thumbprint.Equals(
      $metadata.Thumbprint,
      [StringComparison]::OrdinalIgnoreCase
    )) {
  throw 'MSI signer does not match release signing metadata.'
}
```

Azure Artifact Signing certificates chain to standard Windows trust anchors,
so no certificate is imported into `LocalMachine\TrustedPublisher` or
`LocalMachine\Root`. The release installer performs the same checksum,
signature, and signer-metadata checks before it invokes `msiexec`.

Public releases also include GitHub artifact attestations for every release
asset. After downloading an asset, optionally verify its GitHub Actions
provenance with the GitHub CLI:

```powershell
gh attestation verify .\wincred-libsecret-wsl-plugin.msi `
  --repo bmiddha/wincred-libsecret-wsl-plugin
```

Artifact attestations complement, rather than replace, checksum and
Authenticode verification. Azure Artifact Signing may issue a renewed signing
certificate over time; the per-release signing metadata binds the MSI to the
certificate that signed that release.

For local or private-distribution testing, build all Windows and Linux payloads
and use the existing packager with a locally trusted code-signing identity:

```powershell
scripts\build.ps1 -Configuration Release -WslDistribution <build-distro>
scripts\package.ps1 -Configuration Release -Sign `
  -CertificateThumbprint <40-hex-thumbprint> `
  -TimestampUrl <https-timestamp-url>
```

Alternatively supply `-CertificatePath <pfx-path>` and
`-CertificatePassword <secure-string>`; the packager accepts a
certificate password from its supported secret source rather than source
control. This local path is not the public release-signing flow. The packager
uses SHA-256 Authenticode, verifies every signed file, and signs the MSI after
WiX builds it. Verify signatures and the generated `checksums.sha256` before
distribution. Do not distribute or register an unsigned release DLL.

The package stage includes the signed Windows binaries, Linux provider,
bootstrap, D-Bus and systemd templates, payload manifest, symbols, licenses,
dependency metadata, version manifest, and checksums. WiX is restored through
the repository-local tool manifest; it is not globally installed.

## MSI install, upgrade, repair, and uninstall

Run the public installer from a non-elevated PowerShell session. It requests
elevation only for MSI installation; the elevated helper downloads and verifies
release checksums, GitHub asset digests, and the Authenticode signer in
protected staging before invoking `msiexec`:

```powershell
.\install.ps1
```

To install a particular release, pass `-Version vX.Y.Z`. By default `latest`
means the newest stable release; pass `-IncludePrerelease` to allow the newest
published prerelease instead.

Manual MSI installation also remains supported from an elevated session:

```powershell
msiexec.exe /i .\wincred-libsecret-wsl-plugin.msi
```

The per-machine MSI installs its payload below the Program Files product
directory and invokes the CLI as deferred non-impersonating custom actions.
It appends that product directory to the machine `PATH`, preserving existing
entries, so a new terminal can invoke `wincred-libsecret.exe` directly.
The install/repair path registers only this value:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins
  wincred-libsecret-wsl-plugin = <installed DLL>
```

The CLI requires an absolute existing DLL and `Valid` Authenticode result.
The MSI deliberately does not use an unconditional WiX Registry table row:
on rollback or uninstall it calls guarded `plugin uninstall --dll ...`, which
preserves the value if an administrator changed it to another DLL after
installation.

The MSI uses a stable UpgradeCode and a major-upgrade rule. Install a newer
release with `msiexec.exe /i <new-msi>`; it upgrades the product and reruns
the guarded registration. The installed CLI provides the preferred
self-upgrade path:

```powershell
wincred-libsecret upgrade
wincred-libsecret upgrade --include-prerelease
```

Run `upgrade` from a non-elevated terminal. It starts the packaged, verified
release installer, then exits so Windows can replace the running CLI. The
installer waits for the CLI to exit, prompts for MSI elevation, and refreshes
every enabled distribution from the new Windows payload, validating the Linux
provider after each refresh. A manually installed newer MSI is also safe: the
plugin refreshes each enabled distribution the next time it starts. Run
`wincred-libsecret distro refresh --all` from a non-elevated terminal to
perform and validate that refresh immediately. Repair with the normal Windows
Installer repair flow or
`msiexec.exe /fa <msi>`; repair invokes the registration action. After an
install, repair, upgrade, or removal, restart `wslservice` or restart WSL
before starting a new distribution. Use `plugin status` and `doctor` to confirm
status.

MSI removal unregisters only the matching DLL and removes its installed files.
It also removes only the MSI's product-directory `PATH` entry.
For a full current-user cleanup, use the CLI from a non-elevated terminal
instead of removing the product through Installed Apps:

```powershell
wincred-libsecret uninstall
```

The command disables every registered project distribution before it starts MSI
removal, restores any project-backed foreign Secret Service definitions, removes
only this project's HKCU enablement records, shuts down WSL, unregisters the
matching plugin DLL, and removes the product `PATH` entry. It never deletes
Windows Credential Manager data. `--keep-distro-provisioning` leaves enabled
distribution payloads and registry records in place only for a deliberate
manual migration; disable those distributions before later MSI removal.
The command exits before MSI removal so Windows can release the running CLI;
the packaged helper then requests elevation and reports the final result.
The Windows Installed Apps uninstaller cannot safely operate on another
user's HKCU and WSL state, so use the CLI cleanup path for every Windows user
who enabled a distribution.

## Development signing lifecycle

The development certificate script creates a 7-day, RSA-3072, SHA-256,
non-exportable code-signing key in `Cert:\CurrentUser\My`. It exports only the
public certificate to ignored state under `artifacts\dev-signing`. With
`-TrustForCurrentUser` it imports that public certificate to the current
user's TrustedPublisher store only; that is a development convenience and is
not the machine-wide release-installation path. `-TrustForLocalMachine`
additionally needs elevation and imports the public certificate into both
`LocalMachine\TrustedPublisher` and `LocalMachine\Root` for the local machine
E2E scenario. The saved development state records each store so
`Remove-DevSigningCertificate.ps1` removes only the entries it created.

```powershell
$binaries = @(
  '.\artifacts\Debug\windows\wincred-libsecret-wsl-plugin.dll',
  '.\artifacts\Debug\windows\wincred-libsecret.exe',
  '.\artifacts\Debug\windows\wincred-libsecret-broker.exe'
)
scripts\New-DevSigningCertificate.ps1 -TrustForCurrentUser -SignPath $binaries
scripts\Remove-DevSigningCertificate.ps1
```

The removal script verifies that its state identifies the project-created
certificate before removing trusted-store entries, the private key, public
certificate, and state. Never export, commit, or reuse this development key.
Do not enable Windows test signing or alter Secure Boot.

## Development plugin registration

Use the development scripts from an elevated terminal:

```powershell
scripts\Install-DevPlugin.ps1 `
  -DllPath .\artifacts\Debug\windows\wincred-libsecret-wsl-plugin.dll `
  -RestartWslService
scripts\Get-DevPluginStatus.ps1
scripts\Uninstall-DevPlugin.ps1 -RestartWslService
```

Installation records the original value before replacement only in the fixed
`%ProgramData%\WinCredLibsecret\DevPlugin\plugin-registration.json` machine
store. Its directory and state file are owner/ACL protected for SYSTEM and
Administrators, reject reparse points, and use atomic writes; `-StatePath` is
intentionally unsupported. It refuses a different current value unless
`-ReplaceConflict` is explicit. Uninstall restores a saved value only when the
registry still names the tracked development DLL and the saved target remains
an absolute, regular, non-user-writable, trusted-signed
`wincred-libsecret-wsl-plugin.dll` stored as REG_SZ. Otherwise it preserves
the newer value and retains state for investigation. `-AllowUnsigned` is an
isolated development escape hatch, not an acceptable production configuration.

## Distro provisioning and lifecycle

The MSI CLI defaults to its installed `linux` payload and broker. Development
can pass the build outputs explicitly:

```powershell
$cli = '.\artifacts\Debug\windows\wincred-libsecret.exe'
& $cli distro enable <distro-name> `
  --payload-root .\artifacts\Debug\linux `
  --broker .\artifacts\Debug\windows\wincred-libsecret-broker.exe
& $cli distro list
& $cli doctor --distro <distro-name>
& $cli distro refresh --all `
  --payload-root .\artifacts\Debug\linux `
  --broker .\artifacts\Debug\windows\wincred-libsecret-broker.exe
& $cli distro disable <distro-name>
```

Enable checks WSL 2.5.1+, finds an exact WSL 2 distro, translates the payload
and broker paths with `wslpath`, verifies the Linux manifest, and runs the
bootstrap as Linux root. Only after successful provisioning does it write:

```text
HKCU\Software\wincred-libsecret\WSLPlugin\Distributions\{distro-guid}
  Enabled = DWORD 1
```

Disable performs the inverse ordering: it first invokes the Linux helper to
remove project-owned files, then removes that exact per-user registry key. It
is idempotent and does not modify Credential Manager data.

The bootstrap creates root-owned files with these expected modes:

| Path | Owner and mode |
| --- | --- |
| Provider, bootstrap helper, refresh launcher | `root:root`, `0755` |
| D-Bus service, user unit, refresh unit, config | `root:root`, `0644` |
| Release directories | `root:root`, `0755` |
| Conflict backups and backup manifest | `root:root`, `0700` directory / `0600` files |

It installs immutable versioned release contents under
`/usr/libexec/wincred-libsecret/releases`, updates a `current` symlink
atomically, stores configuration in `/etc/wincred-libsecret/config`, and
reloads systemd. The refresh unit is enabled at `multi-user.target` so it
refreshes after every systemd-enabled distribution boot; the WSL plugin's
lifecycle request remains an early fast path. The D-Bus activation file is
`/usr/share/dbus-1/services/org.freedesktop.secrets.service`; the session
unit is `/usr/lib/systemd/user/wincred-libsecret.service`; the refresh unit is
`/etc/systemd/system/wincred-libsecret-refresh.service`.

## Conflicts, backup, restore, and rollback

Before installing, bootstrap inspects common global and user service-file
locations for an existing `org.freedesktop.secrets.service`. A non-project
definition causes a refusal. With `--replace-conflicts`, it copies each
foreign file and original UID/GID/mode into protected state before removing
the conflict. Disabling verifies that no newer non-project file occupies the
target; it then restores the backed-up file and original ownership/mode. If a
new provider owns a target, restoration stops rather than overwriting it.

For a failed provisioning run, the helper removes newly installed
project-owned service definitions when appropriate, restores conflict backups,
and reloads systemd. For operational rollback, disable affected distros,
restore a previous trusted MSI/DLL with the normal guarded registration path,
restart `wslservice`, then enable the distro again using the desired payload.

## Diagnostics and recovery

Run:

```powershell
& $cli plugin status
& $cli distro list
& $cli doctor --distro <distro-name>
& $cli doctor --include-prerelease
```

The Linux helper supports `--status`, `--doctor`, `--refresh`, and `--disable`
when run as root. It checks provisioning state, foreign conflicts,
architecture, systemd, user D-Bus availability, Windows interop, broker
reachability, payload hashes, activation files, and exact modes.

`doctor` also compares the installed CLI version with the newest public GitHub
Release. It reports an available update with the matching `upgrade` command;
a release API timeout or unavailable network is a warning and does not hide
local diagnostic failures.

Use `journalctl --user -u wincred-libsecret.service` for provider logs and
`journalctl -u wincred-libsecret-refresh.service` for refresh logs. The DLL
uses ETW provider `WinCredLibsecret.WslPlugin` with failure operation and
HRESULT status fields; this supports tracing without putting secret values in
logs. Broker startup attempts generation reconciliation; a reported missing
committed generation is data corruption, so preserve diagnostic context and
restore from a backup or remove the affected project item intentionally.
