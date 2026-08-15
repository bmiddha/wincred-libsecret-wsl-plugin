# Contributing

Thanks for improving the project. Contributions are licensed under the MIT
License.

## Before changing code

Read the [architecture](docs/architecture.md),
[data model](docs/wincred-data-model.md).
Keep the DLL loaded by `wslservice` small, non-throwing across its ABI, and
free of secret handling. The Windows broker must operate only on typed
`WinCredLibSecret/v1/` targets; do not add a path for arbitrary WinCred
enumeration or access.

Never place secret material in source, command lines, environment variables,
logs, crash text, test names, or artifacts. Tests use randomized identifiers
and hashes rather than secret output.

## Development loop

Windows work needs Rust 1.97.1, Visual Studio's C++ toolchain/CMake/Ninja, and
CMake 3.28+. Linux provider work needs a systemd-enabled x86_64 WSL
distribution with Rust 1.97.1. Build and test using existing scripts:

```powershell
scripts\build.ps1 -Configuration Debug -WslDistribution <distro>
test.ps1 -Configuration Debug -WslDistribution <distro> -RunLinux
```

Use targeted Cargo, CTest, or Linux script commands when they cover the
change. Run `cargo fmt --all -- --check`, relevant tests, and Clippy without
new warnings. Details are in [Development and testing](docs/development-and-testing.md).

## Privileged and live testing

Live WinCred tests are opt-in and use the current Windows user's vault:

```powershell
$env:WINCRED_LIVE_TESTS = '1'
cargo test -p wincred-libsecret-broker --test wincred_integration -- --ignored --test-threads=1
```

They must create randomized project IDs and clean up. For DLL registration,
use the tracked development-signing and development-plugin scripts; do not
enable test signing or change Secure Boot. The full cross-boundary E2E command
is the `Hosted WSL E2E` GitHub Actions workflow, which runs on an ephemeral
Windows 2025 VM. It imports disposable distributions and restores
registration, credentials, and its development certificate in cleanup.

## Documentation and review

Update the linked documentation whenever the CLI, registry paths, service
files, package payload, security boundary, schema, limits, test commands, or
operational behavior changes. Commands must be copyable with placeholders,
not machine-specific paths or secret values.

Keep changes focused. Explain privilege, trust, persistence, rollback, and
secret-handling effects in the pull request.
