# Development and testing

## Toolchains and builds

Windows builds require Rust, Visual Studio's C++ toolchain, CMake/Ninja, and
CMake 3.28+. The native plugin uses C++23, targets x64 only, and obtains WSL
Plugin API 2.9.3 through CMake `FetchContent` with a pinned SHA-256. The Rust
workspace declares Rust 1.97; Linux scripts select `+1.97.1`.

Build Windows broker/CLI/plugin and Linux provider together:

```powershell
scripts\build.ps1 -Configuration Debug -WslDistribution <distro>
scripts\build.ps1 -Configuration Release -WslDistribution <distro>
```

The Windows build excludes the Linux provider, builds Rust CLI/broker, runs
the `windows-x64` CMake preset, and stages artifacts. The Linux build invokes
`scripts\build-linux.sh` in the selected WSL distro, cross-builds
`x86_64-unknown-linux-musl`, copies the provider/templates, and emits
`manifest.sha256`.

For component-only Windows work, use the existing runner:

```powershell
test.ps1 -Configuration Debug
```

It runs Rust formatting, workspace tests, Clippy with warnings denied, CMake
configure/build, and CTest. Add `-RunLinux` with a WSL distro to execute the
Linux component suite as well.

## Linux and D-Bus tests

From a suitable WSL working tree:

```bash
scripts/test-linux.sh
```

This runs Rust formatting, protocol/broker/provider tests, Clippy, a musl
provider build, and provider D-Bus integration under `dbus-run-session` when
available. It prints a skip only when the session-bus launcher is unavailable.
Provider integration tests use an in-memory broker; they do not modify
Credential Manager.

## Safe live Credential Manager test

The ignored integration test is the narrowest test that accesses real WinCred.
It requires opt-in, serial execution, randomized project UUIDs, and cleanup:

```powershell
$env:WINCRED_LIVE_TESTS = '1'
cargo test -p wincred-libsecret-broker --test wincred_integration -- --ignored --test-threads=1
Remove-Item Env:\WINCRED_LIVE_TESTS
```

It exercises collection, alias, binary item creation/read, and collection
deletion through the broker. It does not enumerate or touch credentials
outside the project namespace. Do not run it against an account whose
Credential Manager state you cannot safely test.

## Full privileged E2E

The E2E runner is intentionally opt-in:

```powershell
scripts\run-e2e.ps1 -PrerequisiteOnly
scripts\run-e2e.ps1 -DryRun
scripts\run-e2e.ps1 -Full -WslSourceDistro <distro>
```

The canonical full run is the `Hosted WSL E2E` GitHub Actions workflow. It
uses an ephemeral GitHub-hosted `windows-2025` VM, provisions a systemd-enabled
WSL 2 source distribution, and runs the command with `-RequireFull`. It builds
Release artifacts; creates a short-lived, isolated development certificate
trusted for the local machine; registers and verifies the signed DLL in HKLM;
verifies module loading by `wslservice`; and imports two disposable
systemd-enabled WSL2 distributions. It never enables test signing or changes
Secure Boot.

The runner tests:

- signed plugin registration, guarded conflict handling, and module load;
- bootstrap hashes, modes, refresh lifecycle, D-Bus activation, and
  reversible foreign Secret Service conflicts;
- `secret-tool`, libsecret C client, direct D-Bus collection/alias/signals,
  Unicode, binary secret, exactly-2560-byte and rejected-2561-byte behavior;
- cross-distro and cross-Linux-user shared-vault reads, reverse update,
  concurrency, restart persistence, and provider isolation;
- real broker/WinCred generation inspection.

E2E uses generated IDs and records hashes, not secret values. Cleanup never
uses a before/after namespace difference as deletion authority. It parses only
project metadata for the current run marker (`e2e-run` item attributes and
the generated collection label), derives the deterministic direct-D-Bus alias,
and deletes only those exact item metadata, generation, collection, and alias
targets. An unmarked concurrent write, a pre-existing project credential, a
foreign namespace credential, or an interrupted generation without committed
run metadata is preserved rather than guessed at.

Each full run writes `e2e-<run-id>.inventory.json` alongside its JUnit report.
It contains only project target names and blob hashes: initial, intentionally
preserved concurrent fixtures, and final inventories. The JUnit
`e2e.inventory` property links the matching file. Verify a completed
privileged run with:

```powershell
scripts\Test-E2ECleanup.ps1
```

The verifier safely parses XML, checks that final inventory equals initial
inventory plus preserved fixtures, and checks only that run's deterministic
WSL distro names. It does not require the entire project namespace to be
empty. Plugin registration state is isolated per E2E run beneath ProgramData
so the secure-state location remains cleanup-compatible. The `finally`
cleanup disables disposable distros, removes only this run's storage,
registration state, and development certificate, and writes JUnit/log output
under `test-results\e2e`. If cleanup reports a failure, investigate before
rerunning.

The nonprivileged cleanup scenarios can be run without WSL, certificates,
registry changes, or live credentials:

```powershell
tests\e2e\Test-E2ECleanup.ps1
```

### Current local status

The GitHub-hosted workflow is the source of record for full cross-boundary
validation. Do not interpret a local plugin-load observation as a complete
cross-distro E2E pass.

## CI and release expectations

CI covers Windows formatting/tests/Clippy/CMake/CTest, Linux
formatting/tests/Clippy/musl provider build, and D-Bus integration where a
session bus exists. The full privileged E2E uses the weekly or manually
dispatched GitHub-hosted Windows 2025 workflow rather than consuming Windows
minutes on every pull request. It uses an isolated Windows Cargo and Rust
dependency-compilation cache plus a pre-test WSL rootfs; see
[the hosted E2E runner](../.github/HOSTED_WSL_E2E.md).
Pull requests limited to documentation, branding assets, legal/community
files, or approved repository metadata run only the lightweight change-scope
validation; they skip the build matrix and CodeQL analysis. Source,
dependencies, packaging, build-system, workflow, and unrecognized file
changes remain on the complete validation path. Pushes to `main` and manual
CI runs always use the complete path. Each `main` commit has an independent
CI and CodeQL concurrency group, so a later merge cannot cancel its full
validation run.
CodeQL runs automatically when the repository is public. Before publication,
enable GitHub Code Security and set the `CODEQL_ENABLED` repository variable
to `true` on a supported plan; until then the workflow records a successful
availability notice rather than attempting an unsupported code-scanning upload.
Successful pushes to `main` upload an unsigned `release-layout-unsigned`
artifact containing the MSI, checksum, and deterministic package stage. It is
for installation testing only.

## Automated releases

Run the `Release preparation` workflow from `main` and choose either an
explicit `MAJOR.MINOR.PATCH` version or a bump. Its `auto` bump uses
Conventional Commit markers when present (`feat` is minor; a breaking marker
is major) and otherwise uses a patch bump. It creates a `release/vX.Y.Z` pull
request containing the workspace version, updated `Cargo.lock`, and generated
`CHANGELOG.md`. Review that pull request and merge it after its normal CI
checks pass.

The publisher regenerates the changelog from the merge commit before signing.
If `main` changed while a release PR was open, this comparison fails rather
than publishing stale notes. Close and delete the stale release branch, then
run `Release preparation` again from current `main`.

For the first release, select `initial_release`. It preserves the current
workspace version, requires that no SemVer release tag exists, and creates a
changelog-only `release/vX.Y.Z` PR. This is the supported bootstrap path for
the initial `v0.1.0` release. For a clean public launch, create the repository
without inherited SemVer release tags; `initial_release` deliberately refuses
to run when one already exists.

The `Conventional Commits` workflow validates human pull request titles and
commits. Dependabot is excluded from that gate, but its generated commits use
the `chore(deps)` prefix. `git-cliff` uses `.config/cliff.toml` to generate
the committed changelog and the GitHub Release notes, retaining older
non-conventional history under an "Other changes" section for the initial
release. Add both Conventional Commits checks to the required checks for
`main`; defining the workflow alone does not prevent an invalid PR merge.

The repository needs a GitHub App installed with Contents, Pull requests,
Issues, and Workflows read/write permission, plus `RELEASE_APP_ID` and
`RELEASE_APP_PRIVATE_KEY` repository secrets. Create an Azure Artifact Signing
account and code-signing certificate profile in its supported region. Create a
protected GitHub `release` environment and configure these GitHub environment
variables:

| Variable | Purpose |
| --- | --- |
| `AZURE_CLIENT_ID` | Microsoft Entra application (client) ID |
| `AZURE_TENANT_ID` | Microsoft Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription containing the Artifact Signing account |
| `AZURE_ARTIFACT_SIGNING_ENDPOINT` | Regional Artifact Signing endpoint |
| `AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME` | Artifact Signing account name |
| `AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME` | Code-signing certificate profile name |

This repository's shared release identity is provisioned by the homelab
Artifact Signing stack. Its federated credential uses issuer
`https://token.actions.githubusercontent.com`, audience
`api://AzureADTokenExchange`, and the exact default GitHub OIDC subject:

```text
repo:bmiddha@5100938/wincred-libsecret-wsl-plugin@1334818618:environment:release
```

Keep GitHub's default OIDC subject template and use an exact immutable subject
for every approved repository/environment; Microsoft Entra does not support
wildcard federated-credential subjects. The shared identity has the
**Artifact Signing Certificate Profile Signer** role at the certificate
profile scope. The release workflow exchanges its GitHub OIDC token through
`azure/login`, then Azure Artifact Signing signs the staged DLL/EXEs before
WiX builds the MSI and signs the completed MSI afterward. No long-lived
signing PFX or Azure client secret is stored in GitHub.

When the repository is public, the publisher also creates GitHub artifact
attestations for every release asset. Checksums and Authenticode signatures
remain required verification controls. Before creating signing material, the
publisher accepts only a merged same-repo `release/vX.Y.Z` PR with the expected
version, lockfile, and generated changelog changes. The initial-release label
is the sole exception: it allows only the generated changelog while requiring
the current version and no unrelated release tag.

After the release PR merges, `Release publish` waits for the successful CI
run for that exact merge commit and reuses its `windows-release` and
`linux-release` artifacts rather than rebuilding them. It then runs the
GitHub-hosted WSL E2E suite on the same immutable commit, signs and validates
the DLLs, executables, and MSI, generates SBOM/checksum metadata, uploads
signed artifacts, creates the annotated `vX.Y.Z` tag, generates
conventional release notes, and publishes the GitHub Release. A failed CI or
E2E gate creates neither a tag nor a release. CI build inputs remain available
for 30 days so a transient production-signing or publishing
failure can be rerun. A rerun safely accepts an existing tag only when it
names the same merge commit.

For a prerelease, select the workflow's prerelease option. It marks the
GitHub Release as a prerelease while preserving a numeric MSI-compatible
workspace version.

Use `scripts\Test-Packaging.ps1` after staging or packaging to validate
package structure, manifest hashes, registration guards, and release
signatures when present. Its optional stage/MSI/signing-path arguments select
the artifacts to validate.
