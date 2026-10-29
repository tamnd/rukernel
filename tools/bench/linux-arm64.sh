#!/bin/sh
# Builds a Linux arm64 `Image` for the Linux column of `tools/bench/run.py --arch aarch64`.
#
# Usage: tools/bench/linux-arm64.sh DIR
#
# The script downloads the Linux release that tools/rk-abigen uses, checks its SHA-256, and builds
# the `Image` of `defconfig` in DIR/build. The `Image` is DIR/build/arch/arm64/boot/Image. A second
# run uses the tarball and the build directory again. CROSS_COMPILE gives the cross compiler, and
# the default is aarch64-linux-gnu-. Without that compiler, the script uses clang and ld.lld with
# LLVM=1. JOBS gives the number of jobs of make, and the default is 3. The build runs with
# `nice -n 19`, because it takes a long time on a shared host.
set -eu

# The same release as LINUX_VERSION, TARBALL_URL and TARBALL_SHA256 of tools/rk-abigen.
version=7.3
url=https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$version.tar.xz
sha256=87363c24f10e06321eb362765521094e94471f6bff8bce2d6b3e40f39f004953

if [ $# -ne 1 ]; then
	echo "usage: $0 DIR" >&2
	exit 2
fi
dir=$(mkdir -p "$1" && cd "$1" && pwd)
mkdir -p "$dir/src" "$dir/build"
tarball=$dir/src/linux-$version.tar.xz
if [ ! -f "$tarball" ] || ! echo "$sha256  $tarball" | sha256sum -c --status; then
	curl --fail --location --silent --show-error --retry 3 -o "$tarball.part" "$url"
	echo "$sha256  $tarball.part" | sha256sum -c --status || {
		echo "$url: the SHA-256 is not $sha256" >&2
		exit 1
	}
	mv "$tarball.part" "$tarball"
	rm -rf "$dir/src/linux-$version"
fi
if [ ! -f "$dir/src/linux-$version/Makefile" ]; then
	tar -xJf "$tarball" -C "$dir/src"
fi

cross=${CROSS_COMPILE-aarch64-linux-gnu-}
if command -v "${cross}gcc" >/dev/null 2>&1; then
	set -- CROSS_COMPILE="$cross"
elif command -v clang >/dev/null 2>&1 && command -v ld.lld >/dev/null 2>&1; then
	set -- LLVM=1
else
	echo "no ${cross}gcc and no clang with ld.lld" >&2
	exit 1
fi
build() {
	nice -n 19 make -C "$dir/src/linux-$version" O="$dir/build" ARCH=arm64 "$@"
}
if [ ! -f "$dir/build/.config" ]; then
	build "$@" defconfig
fi
build "$@" -j"${JOBS:-3}" Image
ls -l "$dir/build/arch/arm64/boot/Image"
