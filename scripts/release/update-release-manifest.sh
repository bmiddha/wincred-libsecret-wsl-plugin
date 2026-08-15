#!/usr/bin/env bash
set -euo pipefail

if [[ "$INITIAL_RELEASE" != "true" ]]; then
    python3 scripts/release/update-workspace-version.py
    cargo update --workspace
    if git diff --quiet -- Cargo.lock; then
        echo "::error::Updating the workspace version did not refresh Cargo.lock."
        exit 1
    fi
    cargo metadata --locked --format-version 1 --no-deps >/dev/null
elif ! git diff --quiet -- Cargo.toml Cargo.lock; then
    echo "::error::The initial release must not change Cargo.toml or Cargo.lock."
    exit 1
fi
git cliff --config .config/cliff.toml --tag "$TAG" -o CHANGELOG.md
notes_path="${RUNNER_TEMP}/release-notes.md"
git cliff --config .config/cliff.toml --tag "$TAG" --latest --strip all -o "$notes_path"
if [[ ! -s CHANGELOG.md || ! -s "$notes_path" ]]; then
    echo "::error::git-cliff did not generate release changelog output."
    exit 1
fi
git add -N CHANGELOG.md
git diff --check
