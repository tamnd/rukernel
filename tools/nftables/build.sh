#!/bin/sh
# Builds the root file system that runs tests/shell of the nftables project, in an Alpine
# container.
#
# Usage: tools/nftables/build.sh [--arch aarch64] OUT_DIR
#
# The script needs docker. The container installs `nft` of the nftables package of Alpine and the
# programs that the tests use, and then copies its root file system to OUT_DIR/root. Next it
# downloads the release of nftables with the same version as the package, checks its SHA-256, and
# puts tests/shell of the release in OUT_DIR/root/nftables/tests/shell. Thus the tests and `nft`
# come from the same version. `run.py --root OUT_DIR/root` makes the initramfs from that
# directory.
#
# With --arch aarch64 the container is an arm64 Alpine. The host must run arm64 programs through
# qemu-user-static with binfmt.
set -eu

ALPINE=alpine:3.20
NFTABLES=1.0.9
SHA256=a3c304cd9ba061239ee0474f9afb938a9bb99d89b960246f66f0c3a0a85e14cd
URL=https://www.netfilter.org/projects/nftables/files
# bash, coreutils, findutils, diffutils, grep, sed and gawk run run-tests.sh and the tests.
# util-linux-misc has unshare, iproute2 has ip, tc and bridge, and kmod loads the modules of the
# reference kernel.
PACKAGES="bash coreutils findutils diffutils grep sed gawk util-linux-misc iproute2 iputils-ping
netcat-openbsd socat procps-ng kmod nftables=$NFTABLES-r2"

platform=linux/amd64
if [ "${1:-}" = --arch ]; then
	case ${2:-} in
	aarch64) platform=linux/arm64 ;;
	x86_64) ;;
	*) echo "build.sh: unknown arch ${2:-}" >&2; exit 2 ;;
	esac
	shift 2
fi
out=${1:?usage: tools/nftables/build.sh [--arch aarch64] OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -rf "$out/root"

docker run --rm --platform "$platform" -v "$out:/out" -e PACKAGES="$PACKAGES" \
	-e NFTABLES="$NFTABLES" -e SHA256="$SHA256" -e URL="$URL" "$ALPINE" sh -euc '
apk add -q --no-cache $PACKAGES
cd /tmp
wget -q "$URL/nftables-$NFTABLES.tar.xz"
echo "$SHA256  nftables-$NFTABLES.tar.xz" | sha256sum -c >/dev/null
unxz -c "nftables-$NFTABLES.tar.xz" | tar -xf - "nftables-$NFTABLES/tests/shell"
mkdir -p /out/root
tar -C / --exclude=./out --exclude=./proc --exclude=./sys --exclude=./dev --exclude=./tmp \
	--exclude=./var/cache/apk -cf - . | tar -C /out/root -xf -
mkdir -p /out/root/nftables/tests /out/root/proc /out/root/sys /out/root/dev /out/root/tmp
# The release has old logs of runs next to run-tests.sh. They are not tests.
rm -f nftables-$NFTABLES/tests/shell/log*
mv "nftables-$NFTABLES/tests/shell" /out/root/nftables/tests/
chown -R 0:0 /out/root
'
du -sh "$out/root"
