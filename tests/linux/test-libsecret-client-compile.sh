#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${repo_root}/tests/e2e/run-linux-e2e.sh"

fail() {
    printf '%s\n' "Libsecret client compile regression test failed: $1" >&2
    exit 1
}

extract_function() {
    local name="$1"
    awk -v name="$name" '
        $0 == name "() {" { capture = 1 }
        capture { print }
        capture && $0 == "}" { exit }
    ' "$runner"
}

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
fake_bin="${test_root}/bin"
args_file="${test_root}/cc.args"
work_root="${test_root}/work"
mkdir -p -- "$fake_bin" "$work_root"

cat >"${fake_bin}/pkg-config" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$1" == "--exists" && "$2" == "libsecret-1" ]]; then
    exit 0
fi
if [[ "$1" == "--cflags" && "$2" == "--libs" && "$3" == "libsecret-1" ]]; then
    printf '%s\n' '-I/mock/include -DTEST_BUILD=1 -lmocksecret'
    exit 0
fi
exit 64
EOF

cat >"${fake_bin}/cc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${E2E_CC_ARGS_FILE:?}"
printf '%s\n' "$@" >"${E2E_CC_ARGS_FILE}"

while (($#)); do
    if [[ "$1" == "-o" ]]; then
        printf '%s\n' '#!/usr/bin/env sh' 'exit 0' >"$2"
        exit 0
    fi
    shift
done
exit 64
EOF

chmod +x "${fake_bin}/pkg-config" "${fake_bin}/cc"
source <(extract_function compile_client)
declare -F compile_client >/dev/null || fail "could not load compile_client"

client="${work_root}/libsecret-client"
source_root="${repo_root}/tests/e2e"
export E2E_CC_ARGS_FILE="${args_file}"
PATH="${fake_bin}:${PATH}"
compile_client

mapfile -t actual <"${args_file}"
expected=(
    "-Werror"
    "-O2"
    "${repo_root}/tests/e2e/libsecret-client.c"
    "-o"
    "${work_root}/libsecret-client"
    "-I/mock/include"
    "-DTEST_BUILD=1"
    "-lmocksecret"
)
[[ "${actual[*]}" == "${expected[*]}" ]] ||
    fail "pkg-config output was not passed as distinct compiler arguments"

printf '%s\n' "Libsecret client compile regression test passed."
