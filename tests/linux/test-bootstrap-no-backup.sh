#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bootstrap="${repo_root}/packaging/linux/wincred-libsecret-bootstrap.sh"

fail() {
    printf '%s\n' "Bootstrap no-backup regression test failed: $1" >&2
    exit 1
}

extract_function() {
    local name="$1"
    awk -v name="$name" '
        $0 == name "() {" { capture = 1 }
        capture { print }
        capture && $0 == "}" { exit }
    ' "$bootstrap"
}

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
STATE="${test_root}/state"
mkdir -p -- "$STATE"

source <(extract_function verify_backups_can_restore)
source <(extract_function restore_backups)
declare -F verify_backups_can_restore >/dev/null ||
    fail "could not load verify_backups_can_restore"
declare -F restore_backups >/dev/null ||
    fail "could not load restore_backups"

if ! verify_backups_can_restore; then
    fail "verification treated a missing backup manifest as an error"
fi
if ! restore_backups; then
    fail "restore treated a missing backup manifest as an error"
fi

printf '%s\n' "Bootstrap no-backup regression test passed."
