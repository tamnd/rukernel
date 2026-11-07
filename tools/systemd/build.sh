#!/bin/sh
# Builds the root file system of the `systemd` and `udevd` boot tests: Debian 13 with the systemd,
# kmod, systemd-sysv, dbus and udev packages, in a Debian container.
#
# Usage: tools/systemd/build.sh OUT_FILE [ARCH]
#
# The script needs docker. It writes a gzip tarball of the tree to OUT_FILE. ARCH is the Debian
# architecture, `amd64` (the default) or `arm64`. An arm64 tree on an x86-64 host needs
# qemu-user-static with binfmt_misc. Set RK_SYSTEMD to OUT_FILE, and
# `cargo xtask boot-test systemd` boots the tree with systemd as PID 1.
set -eu

out=${1:?usage: tools/systemd/build.sh OUT_FILE [ARCH]}
arch=${2:-amd64}
name=rk-systemd-build-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run --platform "linux/$arch" --name "$name" debian:trixie sh -euc '
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends systemd kmod \
	systemd-sysv dbus udev >/dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*
'
docker export "$name" | gzip > "$out"
echo "systemd: the tree is in $out"
