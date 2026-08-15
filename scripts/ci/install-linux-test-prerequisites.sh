#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
    build-essential dbus dbus-user-session libsecret-1-dev libsecret-tools \
    musl-tools pkg-config
command -v dbus-run-session
command -v secret-tool
pkg-config --exists libsecret-1
