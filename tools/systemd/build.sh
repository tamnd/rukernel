#!/bin/sh
# Builds the root file system of the `systemd`, `udevd`, `networkd` and `cryptenroll` boot tests: a
# distribution with systemd, udev, systemd-resolved, dbus and kmod, in a container of the
# distribution. The trees of Debian and Ubuntu also have cryptsetup, systemd-cryptenroll and
# tpm2-tools.
#
# Usage: tools/systemd/build.sh OUT_FILE [ARCH [IMAGE]]
#
# The script needs docker. It writes a gzip tarball of the tree to OUT_FILE. ARCH is the
# architecture of the image, `amd64` (the default) or `arm64`. An arm64 tree on an x86-64 host
# needs qemu-user-static with binfmt_misc. IMAGE is the docker image of the distribution:
# `debian:trixie` (the default, Debian 13), `ubuntu:26.04`, `ubuntu:26.10`, `fedora:44` or
# `archlinux:latest` (amd64 only). Set RK_SYSTEMD to OUT_FILE, and
# `cargo xtask boot-test systemd` boots the tree with systemd as PID 1. With
# `RK_CMDLINE=rk.missing=1` and `RK_BOOT_LOG=1`, tools/missing/report.py makes the report of the
# missing files of the image from the boot log. RK_SYSTEMD_PACKAGES adds more packages of the
# distribution to the tree. The `sdbpf` boot test needs a Debian tree with
# `RK_SYSTEMD_PACKAGES="systemd-tests iputils-ping"`.
set -eu

usage='usage: tools/systemd/build.sh OUT_FILE [ARCH [IMAGE]]'
out=${1:?$usage}
arch=${2:-amd64}
image=${3:-debian:trixie}
RK_SYSTEMD_PACKAGES=${RK_SYSTEMD_PACKAGES:-}
name=rk-systemd-build-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

case $image in
debian:* | ubuntu:*)
	install='
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends systemd kmod \
	systemd-sysv dbus udev systemd-resolved cryptsetup-bin systemd-cryptsetup tpm2-tools \
	libtss2-tcti-device0t64 $RK_SYSTEMD_PACKAGES >/dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*
'
	;;
fedora:*)
	install='
dnf -q -y install --setopt=install_weak_deps=False systemd systemd-udev systemd-resolved \
	dbus-broker kmod gawk $RK_SYSTEMD_PACKAGES >/dev/null
dnf -q clean all
'
	;;
archlinux:*)
	install='
pacman -Syu --noconfirm --needed systemd dbus kmod gawk $RK_SYSTEMD_PACKAGES >/dev/null
pacman -Scc --noconfirm >/dev/null
'
	;;
*)
	echo "systemd: no packages for the image $image" >&2
	exit 1
	;;
esac

docker run -e "RK_SYSTEMD_PACKAGES=$RK_SYSTEMD_PACKAGES" --platform "linux/$arch" --name "$name" \
	"$image" sh -euc "$install"
docker export "$name" | gzip > "$out"
echo "systemd: the tree of $image is in $out"
