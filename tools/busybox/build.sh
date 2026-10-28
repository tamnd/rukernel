#!/bin/sh
# Builds a static arm64 BusyBox with musl, in an arm64 Alpine container.
#
# Usage: tools/busybox/build.sh OUT_DIR
#
# The script needs docker, and qemu-user with binfmt_misc to run the arm64 container on another
# host. It takes the BusyBox release in VERSION, checks its SHA-256 and builds the default
# configuration as a static program. The program goes to OUT_DIR/busybox. `cargo xtask boot-test
# aarch64` puts it in the initramfs of the arm64 `busybox` test when RK_BUSYBOX_AARCH64 gives its
# path.
set -eu

ALPINE=3.22
VERSION=1.37.0
SHA256=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4

out=${1:?usage: tools/busybox/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/arm64 -v "$out:/out" -e VERSION="$VERSION" -e SHA256="$SHA256" \
	alpine:$ALPINE sh -euc '
apk add --no-cache build-base linux-headers >/dev/null
cd /tmp
wget -q "https://busybox.net/downloads/busybox-$VERSION.tar.bz2"
echo "$SHA256  busybox-$VERSION.tar.bz2" | sha256sum -c -s
tar -xjf "busybox-$VERSION.tar.bz2"
cd "busybox-$VERSION"
make defconfig >/dev/null
# A static program runs without a dynamic loader in the initramfs. The tc applet does not build
# with the headers of Linux 6.8 and later, and the tests do not use it. The SHA hardware code of
# BusyBox 1.37 is for x86 only, and it does not build on arm64.
sed -i -e "s/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/" -e "s/^CONFIG_TC=y/# CONFIG_TC is not set/" \
	-e "s/^CONFIG_SHA1_HWACCEL=y/# CONFIG_SHA1_HWACCEL is not set/" \
	-e "s/^CONFIG_SHA256_HWACCEL=y/# CONFIG_SHA256_HWACCEL is not set/" .config
make -j"$(nproc)" busybox >/dev/null
strip busybox
cp busybox /out/busybox
echo "$VERSION" > /out/VERSION
'
echo "busybox: the program is in $out/busybox"
