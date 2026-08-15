#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
unit="${repo_root}/packaging/linux/wincred-libsecret-interop.service"

fail() {
    printf '%s\n' "Interop-unit contract test failed: $1" >&2
    exit 1
}

grep -Fxq 'ConditionFileIsExecutable=/init' "$unit" ||
    fail "the interop unit does not use the supported executable-file condition"
if grep -Fq 'ConditionPathIsExecutable=' "$unit"; then
    fail "the interop unit uses the unsupported ConditionPathIsExecutable directive"
fi

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
installed_unit="${test_root}/wincred-libsecret-interop.service"
install -m 0644 "$unit" "$installed_unit"
verify_output="$(systemd-analyze verify "$installed_unit" 2>&1)" ||
    fail "systemd rejected the interop unit: $verify_output"
if [[ "$verify_output" == *"Unknown key name"* ]]; then
    fail "systemd reported an unknown interop-unit directive: $verify_output"
fi

printf '%s\n' "Interop-unit contract test passed."
