#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="+1.97.1"

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
fi

cd "${repo_root}"
bash "${repo_root}/tests/linux/test-bootstrap-no-backup.sh"
bash "${repo_root}/tests/linux/test-refresh-unit-contract.sh"
bash "${repo_root}/tests/linux/test-interop-unit-contract.sh"
bash "${repo_root}/tests/linux/test-libsecret-client-compile.sh"
cargo "${toolchain}" fmt --all -- --check
cargo "${toolchain}" test --locked \
    -p wincred-libsecret-protocol \
    -p wincred-libsecret-broker \
    -p wincred-libsecret-provider \
    --lib \
    --bins
cargo "${toolchain}" clippy --locked -p wincred-libsecret-protocol -p wincred-libsecret-broker -p wincred-libsecret-provider --all-targets -- -D warnings
cargo "${toolchain}" build --locked -p wincred-libsecret-provider --target x86_64-unknown-linux-musl

if command -v dbus-run-session >/dev/null 2>&1; then
    dbus-run-session -- env WINCRED_REQUIRE_DBUS_TESTS=1 \
        cargo "${toolchain}" test --locked -p wincred-libsecret-provider --test integration -- --test-threads=1
else
    if [[ "${WINCRED_REQUIRE_DBUS_TESTS:-0}" == "1" ]]; then
        printf '%s\n' "D-Bus integration is required but dbus-run-session is unavailable." >&2
        exit 1
    fi
    printf '%s\n' "Skipping D-Bus integration: dbus-run-session is unavailable."
fi
