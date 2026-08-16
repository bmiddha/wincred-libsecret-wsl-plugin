# Hosted WSL E2E runner

`hosted-wsl-e2e.yml` runs on GitHub-hosted `windows-2025`, whose image includes
WSL 2. It uses the runner's elevated, ephemeral Windows VM to register the
test plugin, restart `wslservice`, and import disposable distributions. No
self-hosted runner, runner labels, persistent user profile, or repository
environment is required.

The workflow runs weekly at 04:17 UTC on Sunday and can be dispatched
manually. It can also be called by the release publisher for the immutable
release commit. It deliberately does not run on ordinary pull requests,
keeping the high-cost full E2E path out of the normal component CI matrix.

The workflow caches two safe, reproducible inputs:

- Windows Cargo dependencies and Rust dependency build outputs through
  `Swatinem/rust-cache`, isolated by the Windows image, Rust toolchain, host
  target, and Cargo environment;
- a WSL source-rootfs tarball keyed by its bootstrap script, lockfile, and
  Rust toolchain.

Weekly and manually dispatched runs populate these caches. The release
publisher calls the workflow from a closed pull-request event, whose
default-branch cache token is intentionally read-only; that call restores
available entries but does not save new ones.

The rootfs cache is exported before the E2E begins and contains only Ubuntu
packages and the pinned Rust toolchain. It never contains repository build
outputs, test credentials, plugin registration, certificates, or disposable
distribution state. Every run imports a fresh source distribution from it,
passes that same immutable tarball to the child-distro imports, and unregisters
the source distribution during cleanup.

Each run imports two additional disposable distributions, uses a short-lived
isolated development certificate, restores plugin registration, and verifies
cleanup. The job fails on every skipped privileged test and uploads sanitized
JUnit/log output even after a failure.
