#!/usr/bin/env bash
set -euo pipefail

git fetch --tags --force
current="$(
    awk '
        /^\[workspace\.package\]$/ { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && /^version[[:space:]]*=/ {
            value = $0
            sub(/^[^"]*"/, "", value)
            sub(/".*$/, "", value)
            print value
            exit
        }
    ' Cargo.toml
)"
if [[ ! "$current" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "::error::Cargo.toml does not contain a three-part [workspace.package] version."
    exit 1
fi

initial_release="${INITIAL_RELEASE:-false}"
if [[ "$initial_release" != "true" && "$initial_release" != "false" ]]; then
    echo "::error::initial_release must be true or false."
    exit 1
fi
requested="${REQUESTED_VERSION:-}"
requested="${requested#v}"
if [[ "$initial_release" == "true" ]]; then
    if [[ -n "$requested" && "$requested" != "$current" ]]; then
        echo "::error::The initial release must use the current workspace version '$current'."
        exit 1
    fi
    if git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | grep -q .; then
        echo "::error::An initial release is only allowed when no SemVer release tag exists."
        exit 1
    fi
    next="$current"
else
    IFS=. read -r major minor patch <<<"$current"
    if [[ -n "$requested" ]]; then
        next="$requested"
    else
        bump="${REQUESTED_BUMP:-auto}"
        if [[ "$bump" == "auto" ]]; then
            last_tag="$(git tag --merged HEAD --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname | head -n 1)"
            range="HEAD"
            if [[ -n "$last_tag" ]]; then
                range="$last_tag..HEAD"
            fi
            messages="$(git log --format='%s%n%b' "$range")"
            if grep -Eiq '(^|[[:space:]])BREAKING[ -]CHANGE:|^[[:alnum:]]+(\([^)]+\))?!:' <<<"$messages"; then
                bump="major"
            elif git log --format='%s' "$range" | grep -Eq '^feat(\([^)]+\))?:'; then
                bump="minor"
            else
                bump="patch"
            fi
        fi

        case "$bump" in
            major) next="$((major + 1)).0.0" ;;
            minor) next="$major.$((minor + 1)).0" ;;
            patch) next="$major.$minor.$((patch + 1))" ;;
            *)
                echo "::error::Unsupported version bump '$bump'."
                exit 1
                ;;
        esac
    fi
fi

if [[ ! "$next" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "::error::Release version '$next' must use MAJOR.MINOR.PATCH."
    exit 1
fi
if [[ "$initial_release" != "true" ]]; then
    IFS=. read -r next_major next_minor next_patch <<<"$next"
    if (( next_major < major ||
          (next_major == major && next_minor < minor) ||
          (next_major == major && next_minor == minor && next_patch <= patch) )); then
        echo "::error::Release version '$next' must be greater than the current version '$current'."
        exit 1
    fi
fi
tag="v$next"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "::error::Tag '$tag' already exists."
    exit 1
fi
echo "version=$next" >> "$GITHUB_OUTPUT"
echo "tag=$tag" >> "$GITHUB_OUTPUT"
echo "initial_release=$initial_release" >> "$GITHUB_OUTPUT"
