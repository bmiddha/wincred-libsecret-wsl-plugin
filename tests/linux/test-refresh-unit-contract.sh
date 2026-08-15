#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
unit="${repo_root}/packaging/linux/wincred-libsecret-refresh.service"
bootstrap="${repo_root}/packaging/linux/wincred-libsecret-bootstrap.sh"

fail() {
    printf '%s\n' "Refresh-unit contract test failed: $1" >&2
    exit 1
}

grep -Fxq '[Install]' "$unit" ||
    fail "the refresh unit has no install section"
grep -Fxq 'WantedBy=multi-user.target' "$unit" ||
    fail "the refresh unit is not scheduled for normal systemd boot"
grep -Fxq '    systemctl enable wincred-libsecret-refresh.service' "$bootstrap" ||
    fail "provisioning does not enable the refresh unit"
grep -Fxq '    systemctl disable --now wincred-libsecret-refresh.service >/dev/null 2>&1 || true' "$bootstrap" ||
    fail "disable does not remove the refresh boot scheduling"

printf '%s\n' "Refresh-unit contract test passed."
