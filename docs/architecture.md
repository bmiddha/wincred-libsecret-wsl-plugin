# Architecture

## Components and identities

```text
 Windows host (one interactive Windows user)
 ┌───────────────────────────────────────────────────────────────────────┐
 │ HKLM plugin registration ──> signed x64 WSL plugin DLL in wslservice  │
 │                                  │ callback; impersonates session token│
 │ HKCU per-distro Enabled flag <────┘                                    │
 │                                  │ ExecuteBinaryInDistribution         │
 │                                  v                                     │
 │ Windows broker.exe <── WSL interop ── provider (one per Linux session) │
 │      │ CredRead/Write/Enumerate only WinCredLibSecret/v1/*             │
 │      v                                                                  │
 │ Current Windows user's Credential Manager                              │
 └───────────────────────────────────────────────────────────────────────┘
                   ▲                         ▲
  Distro A, UID 1000│                         │Distro B, UID 2000
  D-Bus session ────┘                         └──── D-Bus session
             Both intentionally reach the same Windows-user vault.
```

The Windows user is the persistence and authorization scope. Linux UIDs,
Linux distributions, and D-Bus sessions are consumers of the same vault when
they are enabled under that user; they do not get separate WinCred namespaces.
The plugin DLL is not a secret service and never handles Secret Service
requests. It is a narrowly scoped lifecycle trigger inside `wslservice`.

## Startup lifecycle

1. The administrator installs a signed DLL registration at
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins` with value
   name `wincred-libsecret-wsl-plugin`.
2. `wslservice` loads the x64 DLL. The entrypoint validates the Plugin API
   version (WSL 2.5.1+), configures the `OnDistributionStarted` hook, and
   records the WSL `ExecuteBinaryInDistribution` callback.
3. On a distribution start, the hook validates callback arguments and
   impersonates the supplied WSL session token only long enough to query
   `HKCU\Software\wincred-libsecret\WSLPlugin\Distributions\{GUID}\Enabled`.
   This avoids selecting a LocalSystem user profile/vault.
4. If enabled, the plugin asks WSL to execute
   `/usr/bin/systemctl --no-block start wincred-libsecret-refresh.service`
   in that distribution. It returns `S_OK` even for an enablement or launch
   failure, and emits a non-secret ETW operation/status diagnostic. The
   request is a fast path only because the callback can precede systemd
   readiness.
5. The root-owned refresh unit is also enabled at `multi-user.target`, so
   systemd reliably starts it during boot after the plugin callback. It
   validates the payload, updates the root-owned current release symlink and
   D-Bus/service definitions, then reloads systemd.
6. A user's session bus activates `org.freedesktop.secrets` from the
   system-wide D-Bus service file. The corresponding user systemd service
   starts `wincred-libsecret-provider`.
7. The provider launches `wincred-libsecret-broker.exe` through WSL interop,
   negotiates the protocol, and serves Secret Service requests. The broker
   persists project targets to the current Windows user's Credential Manager.

The plugin’s constraints matter: it is loaded into a privileged, long-lived
host process. Its hook performs no secret transport, uses no arbitrary shell
launch, uses the WSL supplied command-execution API, handles failures without
throwing across the ABI, and records only ETW operation/status values.

## Linux activation and multi-user behavior

Provisioning installs these project-owned definitions:

| Location | Role |
| --- | --- |
| `/usr/share/dbus-1/services/org.freedesktop.secrets.service` | Global D-Bus activation definition |
| `/usr/lib/systemd/user/wincred-libsecret.service` | Per-user session-bus service (`Type=dbus`, `BusName=org.freedesktop.secrets`) |
| `/etc/systemd/system/wincred-libsecret-refresh.service` | System refresh oneshot |
| `/usr/libexec/wincred-libsecret/` | Launcher, helper, versioned releases, `current` link |
| `/etc/wincred-libsecret/config` | Payload, broker, protocol and version configuration |
| `/var/lib/wincred-libsecret/backups` | Reversible foreign-provider backups |

The D-Bus service file is installed system-wide so it can activate for any
Linux user with a session bus. The provider is therefore multi-user at the
Linux service layer, while persistence is shared at the Windows-user layer.
It is not an authorization system between Linux users. The bootstrap requires
systemd, a D-Bus implementation, a D-Bus activation directory, x86_64,
functional `cmd.exe`, and a launchable broker.

## Provider-to-broker bridge

The provider keeps one broker child process and communicates **only** through
stdin/stdout. Each message is a big-endian unsigned 32-bit length followed by
one CBOR payload. Empty frames, trailing bytes, malformed CBOR, and frames
over 1 MiB are rejected. The initial `Hello`/`HelloAck` selects protocol
version 1 and the intersection of capabilities:

- binary secrets;
- collections;
- aliases;
- generation commits; and
- reconciliation.

Requests have correlation IDs. A 10-second transport timeout or child failure
causes one broker restart and retry. Broker stderr is not forwarded to
journald: the provider logs only its byte count because a Windows error could
otherwise contain sensitive text.

The broker is a Windows process launched by the WSL user through interop. It
is not a network listener and does not accept caller-selected WinCred target
names. Its API accepts collections, aliases, item metadata, item IDs, and
secret bytes; typed target construction happens inside the broker.

## Persistence and failure behavior

Metadata is CBOR stored in named generic credentials. Updating a secret writes
a new generation, writes item metadata pointing to it (the visibility commit
point), then deletes the old generation. The broker serializes operations
with `Local\WinCredLibSecret-v1-broker` and reconciles at startup:
unreferenced stored generations are removed; a metadata record referencing a
missing generation is reported as corrupt and is not silently deleted.

The full target grammar, limits, and recovery details are in
[WinCred data model](wincred-data-model.md).
