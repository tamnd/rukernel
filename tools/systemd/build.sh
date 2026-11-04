#!/bin/sh
# Builds the root file system of the `systemd` boot test: Debian 13 with the systemd, kmod,
# systemd-sysv and dbus packages, in a Debian container.
#
# Usage: tools/systemd/build.sh OUT_FILE
#
# The script needs docker. It writes a gzip tarball of the tree to OUT_FILE. Set RK_SYSTEMD to
# OUT_FILE, and `cargo xtask boot-test systemd` boots the tree with systemd as PID 1.
set -eu

out=${1:?usage: tools/systemd/build.sh OUT_FILE}
name=rk-systemd-build-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run --platform linux/amd64 --name "$name" debian:trixie sh -euc '
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends systemd kmod \
	systemd-sysv dbus >/dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*
'
docker export "$name" | gzip > "$out"
echo "systemd: the tree is in $out"
