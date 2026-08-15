#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly ROOT="/usr/libexec/wincred-libsecret"
readonly CONFIG="/etc/wincred-libsecret/config"
readonly STATE="/var/lib/wincred-libsecret"
readonly MARKER="X-WinCred-Libsecret=1"
readonly DBUS_SERVICE="org.freedesktop.secrets.service"
readonly DBUS_TARGET="/usr/share/dbus-1/services/${DBUS_SERVICE}"
readonly USER_UNIT="/usr/lib/systemd/user/wincred-libsecret.service"
readonly REFRESH_UNIT="/etc/systemd/system/wincred-libsecret-refresh.service"
readonly INTEROP_UNIT="/etc/systemd/system/wincred-libsecret-interop.service"

action=""
source_root=""
broker_path=""
protocol_version=""
payload_version=""
replace_conflicts=0
install_started=0
previous_project_install=0

usage() {
    cat >&2 <<'EOF'
Usage: wincred-libsecret-bootstrap.sh --check|--install|--refresh|--disable|--status|--doctor
       [--source DIRECTORY --broker PATH --protocol VERSION --version VERSION]
       [--replace-conflicts]
EOF
    exit 2
}

die() {
    printf '%s\n' "wincred-libsecret: $*" >&2
    exit 1
}

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "this operation must run as root"
}

is_project_owned() {
    [[ -f "$1" ]] && grep -Fq "$MARKER" -- "$1"
}

check_safe_field() {
    [[ "$1" != *$'\n'* && "$1" != *$'\r'* && "$1" != *$'\t'* ]] ||
        die "unsafe character in $2"
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            --check|--install|--refresh|--disable|--status|--doctor)
                [[ -z "$action" ]] || usage
                action="$1"
                ;;
            --source)
                (($# >= 2)) || usage
                source_root="$2"
                shift
                ;;
            --broker)
                (($# >= 2)) || usage
                broker_path="$2"
                shift
                ;;
            --protocol)
                (($# >= 2)) || usage
                protocol_version="$2"
                shift
                ;;
            --version)
                (($# >= 2)) || usage
                payload_version="$2"
                shift
                ;;
            --replace-conflicts)
                replace_conflicts=1
                ;;
            *)
                usage
                ;;
        esac
        shift
    done
    [[ -n "$action" ]] || usage
}

read_config() {
    [[ -r "$CONFIG" ]] || die "provider configuration is absent"
    source_root=""
    broker_path=""
    protocol_version=""
    payload_version=""
    while IFS='=' read -r key value; do
        case "$key" in
            payload_root) source_root="$value" ;;
            broker_path) broker_path="$value" ;;
            protocol_version) protocol_version="$value" ;;
            payload_version) payload_version="$value" ;;
            project_marker) [[ "$value" == "$MARKER" ]] || die "configuration ownership marker is invalid" ;;
            "") ;;
            *) die "unrecognized configuration key" ;;
        esac
    done < "$CONFIG"
    [[ -n "$source_root" && -n "$broker_path" && -n "$protocol_version" && -n "$payload_version" ]] ||
        die "provider configuration is incomplete"
}

validate_arguments() {
    [[ -d "$source_root" ]] || die "payload source is not a directory"
    [[ -f "$source_root/manifest.sha256" ]] || die "payload manifest is missing"
    [[ -f "$source_root/wincred-libsecret-provider" ]] || die "provider payload is missing"
    [[ -f "$source_root/wincred-libsecret-bootstrap.sh" ]] || die "bootstrap payload is missing"
    [[ -f "$broker_path" ]] || die "Windows broker executable is not reachable from this distribution"
    [[ "$protocol_version" =~ ^[0-9]+$ ]] || die "protocol version must be numeric"
    [[ "$payload_version" =~ ^[A-Za-z0-9._-]+$ ]] || die "payload version contains unsupported characters"
    check_safe_field "$source_root" "payload source"
    check_safe_field "$broker_path" "broker path"
}

verify_payload() {
    local root="$1"
    payload_hashes_valid "$root" || die "payload hash verification failed"
}

payload_hashes_valid() {
    local root="$1"
    (
        cd -- "$root"
        sha256sum --check --status manifest.sha256
    )
}

check_runtime() {
    [[ "$(uname -m)" == "x86_64" ]] || die "only x86_64 WSL distributions are supported"
    [[ -d /run/systemd/system ]] || die "systemd is not active; enable it in /etc/wsl.conf and restart WSL"
    command -v systemctl >/dev/null || die "systemctl is unavailable"
    if ! command -v dbus-daemon >/dev/null && ! command -v dbus-broker >/dev/null; then
        die "a D-Bus user service implementation is required"
    fi
    [[ -d /usr/share/dbus-1/services ]] || die "D-Bus activation directory is unavailable"
    if command -v cmd.exe >/dev/null && cmd.exe /c exit 0 >/dev/null 2>&1; then
        :
    elif [[ -x /init ]] && /init /mnt/c/Windows/System32/cmd.exe /c exit 0 >/dev/null 2>&1; then
        :
    else
        die "Windows interop is not usable"
    fi
}

declare -a conflict_paths=()

collect_conflicts() {
    conflict_paths=()
    local candidate
    local -a candidates=(
        "$DBUS_TARGET"
        "/etc/xdg/dbus-1/services/${DBUS_SERVICE}"
        "/usr/local/share/dbus-1/services/${DBUS_SERVICE}"
    )
    local home
    for home in /root /home/*; do
        [[ -d "$home" ]] || continue
        candidates+=("$home/.local/share/dbus-1/services/${DBUS_SERVICE}")
    done
    for candidate in "${candidates[@]}"; do
        [[ -e "$candidate" ]] || continue
        if ! is_project_owned "$candidate"; then
            check_safe_field "$candidate" "conflicting service path"
            conflict_paths+=("$candidate")
        fi
    done
}

require_conflict_resolution() {
    collect_conflicts
    ((${#conflict_paths[@]} == 0)) && return
    if ((replace_conflicts == 0)); then
        printf '%s\n' "existing org.freedesktop.secrets definitions were found:" >&2
        printf '  %s\n' "${conflict_paths[@]}" >&2
        die "refusing to replace another Secret Service provider; retry with --replace-conflicts to create reversible backups"
    fi
}

backup_conflicts() {
    ((${#conflict_paths[@]} == 0)) && return
    install -d -o root -g root -m 0700 "$STATE/backups"
    local backup_dir="$STATE/backups/$(date +%s)-$$"
    local manifest="$STATE/active-backups.tsv"
    install -d -o root -g root -m 0700 "$backup_dir"
    touch "$manifest"
    chmod 0600 "$manifest"
    chown root:root "$manifest"
    local target index=0 uid gid mode
    for target in "${conflict_paths[@]}"; do
        uid="$(stat -c '%u' -- "$target")"
        gid="$(stat -c '%g' -- "$target")"
        mode="$(stat -c '%a' -- "$target")"
        cp --preserve=mode,timestamps -- "$target" "$backup_dir/$index"
        chown root:root "$backup_dir/$index"
        chmod 0600 "$backup_dir/$index"
        printf '%s\t%s\t%s\t%s\t%s\n' "$backup_dir/$index" "$target" "$uid" "$gid" "$mode" >> "$manifest"
        index=$((index + 1))
    done
    for target in "${conflict_paths[@]}"; do
        rm -f -- "$target"
    done
}

verify_backups_can_restore() {
    local manifest="$STATE/active-backups.tsv"
    [[ -f "$manifest" ]] || return 0
    local backup target uid gid mode
    while IFS=$'\t' read -r backup target uid gid mode; do
        [[ -n "$backup" && -n "$target" && -n "$uid" && -n "$gid" && -n "$mode" ]] ||
            die "backup manifest is malformed"
        if [[ -e "$target" ]] && ! is_project_owned "$target"; then
            die "cannot restore backup because a new provider owns $target"
        fi
    done < "$manifest"
}

restore_backups() {
    local manifest="$STATE/active-backups.tsv"
    [[ -f "$manifest" ]] || return 0
    verify_backups_can_restore
    local backup target uid gid mode
    while IFS=$'\t' read -r backup target uid gid mode; do
        [[ -f "$backup" ]] || die "backup payload is missing for $target"
        install -D -o root -g root -m "$mode" -- "$backup" "$target"
        chown "$uid:$gid" -- "$target"
    done < "$manifest"
    while IFS=$'\t' read -r backup _; do
        rm -f -- "$backup"
        rmdir -- "$(dirname -- "$backup")" 2>/dev/null || true
    done < "$manifest"
    rm -f -- "$manifest"
}

install_release() {
    local digest release temp
    digest="$(sha256sum "$source_root/manifest.sha256" | awk '{print $1}')"
    release="${payload_version}-${digest:0:16}"
    install -d -o root -g root -m 0755 "$ROOT/releases"
    if [[ ! -d "$ROOT/releases/$release" ]]; then
        temp="$ROOT/releases/.${release}.new.$$"
        rm -rf -- "$temp"
        install -d -o root -g root -m 0755 "$temp"
        local file
        for file in \
            manifest.sha256 \
            wincred-libsecret-provider \
            wincred-libsecret-bootstrap.sh \
            org.freedesktop.secrets.service \
            wincred-libsecret.service \
            wincred-libsecret-refresh.service \
            wincred-libsecret-interop.service; do
            install -o root -g root -m 0644 -- "$source_root/$file" "$temp/$file"
        done
        chmod 0755 "$temp/wincred-libsecret-provider" "$temp/wincred-libsecret-bootstrap.sh"
        verify_payload "$temp"
        mv -- "$temp" "$ROOT/releases/$release"
    fi
    ln -sfn "releases/$release" "$ROOT/.current.new"
    mv -Tf -- "$ROOT/.current.new" "$ROOT/current"
}

write_configuration() {
    install -d -o root -g root -m 0755 /etc/wincred-libsecret
    local temporary="$CONFIG.new.$$"
    umask 022
    {
        printf '%s\n' "project_marker=$MARKER"
        printf '%s\n' "payload_root=$source_root"
        printf '%s\n' "broker_path=$broker_path"
        printf '%s\n' "protocol_version=$protocol_version"
        printf '%s\n' "payload_version=$payload_version"
    } > "$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    mv -f -- "$temporary" "$CONFIG"
}

write_helpers_and_services() {
    install -d -o root -g root -m 0755 "$ROOT"
    install -o root -g root -m 0755 \
        "$ROOT/current/wincred-libsecret-bootstrap.sh" \
        "$ROOT/wincred-libsecret-refresh"
    cat > "$ROOT/wincred-libsecret-provider" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
readonly ROOT="/usr/libexec/wincred-libsecret"
readonly CONFIG="/etc/wincred-libsecret/config"
broker_path=""
while IFS='=' read -r key value; do
    case "$key" in
        broker_path) broker_path="$value" ;;
        "") ;;
    esac
done < "$CONFIG"
[[ -n "$broker_path" ]] || { echo "wincred-libsecret: missing broker path" >&2; exit 1; }
exec "$ROOT/current/wincred-libsecret-provider" --broker "$broker_path"
EOF
    chown root:root "$ROOT/wincred-libsecret-provider"
    chmod 0755 "$ROOT/wincred-libsecret-provider"
    install -d -o root -g root -m 0755 "$(dirname -- "$DBUS_TARGET")" "$(dirname -- "$USER_UNIT")" "$(dirname -- "$REFRESH_UNIT")" "$(dirname -- "$INTEROP_UNIT")"
    install -o root -g root -m 0644 "$ROOT/current/org.freedesktop.secrets.service" "$DBUS_TARGET"
    install -o root -g root -m 0644 "$ROOT/current/wincred-libsecret.service" "$USER_UNIT"
    install -o root -g root -m 0644 "$ROOT/current/wincred-libsecret-refresh.service" "$REFRESH_UNIT"
    install -o root -g root -m 0644 "$ROOT/current/wincred-libsecret-interop.service" "$INTEROP_UNIT"
}

reload_systemd() {
    systemctl daemon-reload
    systemctl enable --now wincred-libsecret-interop.service
    systemctl enable wincred-libsecret-refresh.service
}

install_payload() {
    [[ -d "$ROOT" ]] && previous_project_install=1
    validate_arguments
    verify_payload "$source_root"
    check_runtime
    require_conflict_resolution
    backup_conflicts
    install_started=1
    install_release
    write_configuration
    write_helpers_and_services
    reload_systemd
    install_started=0
    printf '%s\n' "WinCred Secret Service payload installed"
}

remove_project_file() {
    local path="$1"
    if is_project_owned "$path"; then
        rm -f -- "$path"
    fi
}

disable_payload() {
    verify_backups_can_restore
    systemctl disable --now wincred-libsecret-refresh.service >/dev/null 2>&1 || true
    systemctl disable --now wincred-libsecret-interop.service >/dev/null 2>&1 || true
    remove_project_file "$DBUS_TARGET"
    remove_project_file "$USER_UNIT"
    remove_project_file "$REFRESH_UNIT"
    remove_project_file "$INTEROP_UNIT"
    if is_project_owned "$CONFIG"; then
        rm -f -- "$CONFIG"
    fi
    rm -rf -- "$ROOT"
    restore_backups
    systemctl daemon-reload
    printf '%s\n' "WinCred project-owned files removed; the credential vault was not modified"
}

status() {
    local provisioned=false conflict=false
    [[ -x "$ROOT/wincred-libsecret-refresh" && -f "$CONFIG" ]] && provisioned=true
    collect_conflicts
    ((${#conflict_paths[@]} == 0)) || conflict=true
    printf '%s\n' "provisioned=$provisioned"
    printf '%s\n' "conflict=$conflict"
}

doctor() {
    status
    if [[ "$(uname -m)" == "x86_64" ]]; then
        printf '%s\n' "CHECK architecture ok x86_64"
    else
        printf '%s\n' "CHECK architecture failed $(uname -m)"
    fi
    if [[ -d /run/systemd/system ]]; then
        printf '%s\n' "CHECK systemd ok active"
    else
        printf '%s\n' "CHECK systemd failed inactive"
    fi
    if command -v dbus-daemon >/dev/null || command -v dbus-broker >/dev/null; then
        printf '%s\n' "CHECK dbus-user ok available"
    else
        printf '%s\n' "CHECK dbus-user failed unavailable"
    fi
    if command -v cmd.exe >/dev/null && cmd.exe /c exit 0 >/dev/null 2>&1; then
        printf '%s\n' "CHECK interop ok available"
    elif [[ -x /init ]] && /init /mnt/c/Windows/System32/cmd.exe /c exit 0 >/dev/null 2>&1; then
        printf '%s\n' "CHECK interop ok available"
    else
        printf '%s\n' "CHECK interop failed unavailable"
    fi
    if [[ -f "$CONFIG" ]]; then
        if read_config && [[ -f "$broker_path" ]]; then
            printf '%s\n' "CHECK broker ok reachable"
        else
            printf '%s\n' "CHECK broker failed unreachable"
        fi
    else
        printf '%s\n' "CHECK broker failed configuration-absent"
    fi
    if [[ -L "$ROOT/current" ]] && payload_hashes_valid "$ROOT/current"; then
        printf '%s\n' "CHECK payload-hashes ok verified"
    else
        printf '%s\n' "CHECK payload-hashes failed invalid"
    fi
    if is_project_owned "$DBUS_TARGET" && is_project_owned "$USER_UNIT" && is_project_owned "$REFRESH_UNIT" && is_project_owned "$INTEROP_UNIT"; then
        printf '%s\n' "CHECK activation ok definitions-present"
    else
        printf '%s\n' "CHECK activation failed definitions-absent"
    fi
    if [[ "$(stat -c '%U:%G:%a' "$ROOT/current/wincred-libsecret-provider" 2>/dev/null || true)" == "root:root:755" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$ROOT/wincred-libsecret-refresh" 2>/dev/null || true)" == "root:root:755" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$DBUS_TARGET" 2>/dev/null || true)" == "root:root:644" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$USER_UNIT" 2>/dev/null || true)" == "root:root:644" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$REFRESH_UNIT" 2>/dev/null || true)" == "root:root:644" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$INTEROP_UNIT" 2>/dev/null || true)" == "root:root:644" ]] &&
        [[ "$(stat -c '%U:%G:%a' "$CONFIG" 2>/dev/null || true)" == "root:root:644" ]]; then
        printf '%s\n' "CHECK modes ok root-owned-modes-verified"
    else
        printf '%s\n' "CHECK modes failed helper-missing-or-not-executable"
    fi
}

cleanup_after_failure() {
    local status_code=$?
    if ((status_code != 0 && install_started == 1)); then
        if ((previous_project_install == 0)); then
            remove_project_file "$DBUS_TARGET"
            remove_project_file "$USER_UNIT"
            remove_project_file "$REFRESH_UNIT"
            remove_project_file "$INTEROP_UNIT"
        fi
        restore_backups || true
        systemctl daemon-reload || true
    fi
    exit "$status_code"
}

parse_arguments "$@"
require_root

case "$action" in
    --check)
        validate_arguments
        verify_payload "$source_root"
        check_runtime
        require_conflict_resolution
        printf '%s\n' "prerequisites satisfied"
        ;;
    --install)
        trap cleanup_after_failure EXIT
        install_payload
        ;;
    --refresh)
        trap cleanup_after_failure EXIT
        read_config
        install_payload
        ;;
    --disable)
        disable_payload
        ;;
    --status)
        status
        ;;
    --doctor)
        doctor
        ;;
esac
