#!/usr/bin/env bash
set -euo pipefail

configuration="${1:-Debug}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="x86_64-unknown-linux-musl"

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
fi

case "${configuration}" in
    Debug)
        cargo_args=()
        cargo_profile="debug"
        ;;
    Release)
        cargo_args=(--release)
        cargo_profile="release"
        ;;
    *)
        echo "Unsupported configuration: ${configuration}" >&2
        exit 2
        ;;
esac

cd "${repo_root}"
cargo +1.97.1 build \
    --locked \
    -p wincred-libsecret-provider \
    --target "${target}" \
    "${cargo_args[@]}"

artifact_dir="${repo_root}/artifacts/${configuration}/linux"
install -d -m 0755 "${artifact_dir}"
install -m 0755 \
    "${repo_root}/target/${target}/${cargo_profile}/wincred-libsecret-provider" \
    "${artifact_dir}/wincred-libsecret-provider"

for payload_file in \
    org.freedesktop.secrets.service \
    wincred-libsecret.service \
    wincred-libsecret-refresh.service \
    wincred-libsecret-interop.service \
    wincred-libsecret-bootstrap.sh; do
    install -m 0644 \
        "${repo_root}/packaging/linux/${payload_file}" \
        "${artifact_dir}/${payload_file}"
done
chmod 0755 "${artifact_dir}/wincred-libsecret-bootstrap.sh"

(
    cd "${artifact_dir}"
    sha256sum \
        org.freedesktop.secrets.service \
        wincred-libsecret.service \
        wincred-libsecret-refresh.service \
        wincred-libsecret-interop.service \
        wincred-libsecret-bootstrap.sh \
        wincred-libsecret-provider > manifest.sha256
)
