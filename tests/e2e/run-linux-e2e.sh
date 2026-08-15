#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

mode=""
run_id=""
work_root=""

usage() {
    echo "usage: run-linux-e2e.sh --mode MODE --run-id ID --work-root DIRECTORY" >&2
    exit 2
}

while (($#)); do
    case "$1" in
        --mode) mode="${2:-}"; shift ;;
        --run-id) run_id="${2:-}"; shift ;;
        --work-root) work_root="${2:-}"; shift ;;
        *) usage ;;
    esac
    shift
done
[[ -n "$mode" && "$run_id" =~ ^[a-f0-9]{32}$ && "$work_root" == /opt/* ]] || usage

readonly run_id work_root
readonly schema="wincred-e2e"
readonly shared_kind="shared"
readonly reverse_kind="reverse"
readonly unicode_attribute="属性-🔐"
readonly label="WinCred E2E ${run_id}"
readonly client="$work_root/libsecret-client"
readonly source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly default_collection_marker="$work_root/libsecret-default-collection-${run_id}"

fail() {
    echo "E2E assertion failed: $1" >&2
    exit 1
}

hash_stdin() {
    sha256sum | awk '{print $1}'
}

secret_for() {
    # Values are intentionally never written to stdout or test artifacts.
    printf 'run:%s:kind:%s:unicode:✓' "$run_id" "$1"
}

expected_hash() {
    secret_for "$1" | hash_stdin
}

store_text() {
    local kind="$1"
    secret_for "$kind" | secret-tool store --label="$label" e2e-run "$run_id" e2e-kind "$kind" e2e-unicode "$unicode_attribute" >/dev/null
}

assert_text() {
    local kind="$1"
    local actual expected
    actual="$(secret-tool lookup e2e-run "$run_id" e2e-kind "$kind" e2e-unicode "$unicode_attribute" | hash_stdin)"
    expected="$(expected_hash "$kind")"
    [[ "$actual" == "$expected" ]] || fail "secret-tool retrieval hash mismatch"
}

compile_client() {
    [[ -x "$client" ]] && return
    command -v cc >/dev/null || fail "C compiler unavailable"
    pkg-config --exists libsecret-1 || fail "libsecret development headers unavailable"
    local -a libsecret_flags
    local IFS=$' \t\n'
    read -r -a libsecret_flags <<< "$(pkg-config --cflags --libs libsecret-1)"
    ((${#libsecret_flags[@]})) || fail "libsecret compiler flags unavailable"
    cc -Werror -O2 "$source_root/libsecret-client.c" -o "$client" \
        "${libsecret_flags[@]}"
    chmod 0755 "$client"
}

ensure_test_default_collection() {
    local existing created collection
    existing="$(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
        --method org.freedesktop.Secret.Service.ReadAlias default)"
    if [[ "$existing" =~ /org/freedesktop/secrets/collection/c[0-9a-f]{32} ]]; then
        return
    fi
    grep -Fq "'/'" <<<"$existing" || fail "default collection alias is invalid"

    created="$(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
        --method org.freedesktop.Secret.Service.CreateCollection "{'Label': <'$label'>}" default)"
    collection="$(printf '%s' "$created" | grep -oE '/org/freedesktop/secrets/collection/c[0-9a-f]{32}' | head -n1)"
    [[ -n "$collection" ]] || fail "test default collection creation"
    printf '%s\n' "$collection" >"$default_collection_marker"
}

cleanup_test_default_collection() {
    [[ -f "$default_collection_marker" ]] || return

    local collection collection_label default_alias
    collection="$(<"$default_collection_marker")"
    [[ "$collection" =~ ^/org/freedesktop/secrets/collection/c[0-9a-f]{32}$ ]] ||
        fail "test default collection marker is invalid"
    collection_label="$(gdbus call --session --dest org.freedesktop.secrets --object-path "$collection" \
        --method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Collection Label)"
    grep -Fq "$label" <<<"$collection_label" || fail "test default collection ownership"
    default_alias="$(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
        --method org.freedesktop.Secret.Service.ReadAlias default)"
    grep -Fq "$collection" <<<"$default_alias" || fail "test default collection alias ownership"
    gdbus call --session --dest org.freedesktop.secrets --object-path "$collection" \
        --method org.freedesktop.Secret.Collection.Delete >/dev/null
    rm -f -- "$default_collection_marker"
}

exercise_direct_dbus() {
    local service=/org/freedesktop/secrets
    local alias="e2e_${run_id:0:16}"
    local created collection signal_log monitor_pid
    signal_log="$work_root/direct-dbus-signals-${run_id}.log"
    rm -f -- "$signal_log"
    dbus-monitor --session "type='signal',path='$service'" >"$signal_log" 2>&1 &
    monitor_pid=$!
    trap 'kill "$monitor_pid" 2>/dev/null || true; wait "$monitor_pid" 2>/dev/null || true' RETURN
    gdbus introspect --session --dest org.freedesktop.secrets --object-path "$service" |
        grep -Fq "org.freedesktop.Secret.Service" || fail "service introspection"
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.OpenSession plain "<''>" >/dev/null
    created="$(gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.CreateCollection "{'Label': <'$label'>}" "$alias")"
    collection="$(printf '%s' "$created" | grep -oE '/org/freedesktop/secrets/collection/c[0-9a-f]{32}' | head -n1)"
    [[ -n "$collection" ]] || fail "direct D-Bus collection creation"
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.ReadAlias "$alias" |
        grep -Fq "$collection" || fail "direct D-Bus alias read"
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.SetAlias "$alias" "$collection" >/dev/null
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.SearchItems "{'e2e-run': '$run_id'}" >/dev/null
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.Lock "[objectpath '$collection']" >/dev/null
    gdbus call --session --dest org.freedesktop.secrets --object-path "$service" \
        --method org.freedesktop.Secret.Service.Unlock "[objectpath '$collection']" >/dev/null
    gdbus call --session --dest org.freedesktop.secrets --object-path "$collection" \
        --method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Collection Locked |
        grep -Eq '(false|False)' || fail "collections must remain unlocked"
    gdbus call --session --dest org.freedesktop.secrets --object-path "$collection" \
        --method org.freedesktop.Secret.Collection.Delete >/dev/null
    sleep 1
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    trap - RETURN
    grep -Eq 'Collection(Created|Deleted)' "$signal_log" || fail "collection signals were not observed"
    # The compatibility prompt has no secret response and verifies the
    # always-unlocked Prompt object is callable.
    gdbus call --session --dest org.freedesktop.secrets \
        --object-path /org/freedesktop/secrets/prompt/compatibility \
        --method org.freedesktop.Secret.Prompt.Prompt "" >/dev/null
}

exercise_limits() {
    local maximum_hash
    maximum_hash="$(head -c 2560 </dev/zero | tr '\0' A | hash_stdin)"
    head -c 2560 </dev/zero | tr '\0' A |
        secret-tool store --label="$label" e2e-run "$run_id" e2e-kind limit-2560 >/dev/null
    local actual
    actual="$(secret-tool lookup e2e-run "$run_id" e2e-kind limit-2560 | hash_stdin)"
    [[ "$actual" == "$maximum_hash" ]] || fail "2560-byte secret did not round-trip"
    if head -c 2561 </dev/zero | tr '\0' A |
        secret-tool store --label="$label" e2e-run "$run_id" e2e-kind limit-2561 >/dev/null 2>&1; then
        fail "2561-byte secret unexpectedly succeeded"
    fi
}

case "$mode" in
    write)
        command -v secret-tool >/dev/null || fail "secret-tool unavailable"
        ensure_test_default_collection
        compile_client
        store_text "$shared_kind"
        assert_text "$shared_kind"
        printf '\000\377\200\001' |
            secret-tool store --label="$label" e2e-run "$run_id" e2e-kind binary e2e-unicode "$unicode_attribute" >/dev/null
        binary_expected="$(printf '\000\377\200\001' | hash_stdin)"
        binary_actual="$(secret-tool lookup e2e-run "$run_id" e2e-kind binary e2e-unicode "$unicode_attribute" | hash_stdin)"
        [[ "$binary_actual" == "$binary_expected" ]] || fail "binary content hash mismatch"
        "$client" write "$run_id" "$work_root" >/dev/null
        "$client" read "$run_id" "$work_root" >/dev/null
        ;;
    read)
        compile_client
        assert_text "$shared_kind"
        "$client" read "$run_id" "$work_root" >/dev/null
        ;;
    reverse)
        compile_client
        store_text "$reverse_kind"
        "$client" replace "$run_id" "$work_root" >/dev/null
        ;;
    read-reverse)
        compile_client
        assert_text "$reverse_kind"
        "$client" read-replacement "$run_id" "$work_root" >/dev/null
        ;;
    direct)
        exercise_direct_dbus
        ;;
    limits)
        exercise_limits
        ;;
    concurrent)
        pids=()
        for number in 1 2 3 4; do
            (store_text "concurrent-$number"; assert_text "concurrent-$number") &
            pids+=("$!")
        done
        for pid in "${pids[@]}"; do wait "$pid"; done
        ;;
    cleanup)
        secret-tool clear e2e-run "$run_id" >/dev/null 2>&1 || true
        [[ -x "$client" ]] && "$client" clear "$run_id" "$work_root" >/dev/null 2>&1 || true
        cleanup_test_default_collection
        rm -f -- "$work_root"/direct-dbus-signals-"$run_id".log "$client"
        ;;
    *) usage ;;
esac

printf 'E2E Linux mode %s passed without emitting secret values.\n' "$mode"
