#!/bin/sh
# Builds the root file system that loads the AppArmor profiles of Ubuntu and runs the AppArmor
# regression tests, in an Ubuntu 26.04 container.
#
# Usage: tools/apparmor/build.sh [--arch aarch64] OUT_DIR
#
# The script needs docker. The container installs the package apparmor of Ubuntu, with
# apparmor_parser, aa-status, aa-exec and the profiles in /etc/apparmor.d. Next it gets the source
# package of apparmor with apt-get source, so the tests and the parser come from the same
# version, and builds tests/regression/apparmor against the libapparmor of the system. Then it
# removes the compiler and copies its root file system to OUT_DIR/root. The tests are in
# OUT_DIR/root/apparmor/tests/regression/apparmor, and OUT_DIR/root/apparmor/TESTS has the tests
# that `make tests` runs on that system. `run.py --root OUT_DIR/root` makes the initramfs
# from that directory.
#
# With --arch aarch64 the container is an arm64 Ubuntu. The host must run arm64 programs through
# qemu-user-static with binfmt.
set -eu

IMAGE=ubuntu:26.04
# The programs that the tests use: bash, perl for mkprofile.pl, the tools of coreutils,
# util-linux, procps and iproute2, attr for the extended attributes, and the network tests.
PACKAGES="apparmor libapparmor-dev gcc libc6-dev make pkg-config dpkg-dev perl bash coreutils
util-linux procps iproute2 attr kmod netcat-openbsd libcap2-bin"
# The packages that only the build needs.
BUILD="libapparmor-dev gcc libc6-dev make pkg-config dpkg-dev"

platform=linux/amd64
if [ "${1:-}" = --arch ]; then
	case ${2:-} in
	aarch64) platform=linux/arm64 ;;
	x86_64) ;;
	*) echo "build.sh: unknown arch ${2:-}" >&2; exit 2 ;;
	esac
	shift 2
fi
out=${1:?usage: tools/apparmor/build.sh [--arch aarch64] OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -rf "$out/root"

docker run --rm --platform "$platform" -v "$out:/out" -e PACKAGES="$PACKAGES" -e BUILD="$BUILD" \
	"$IMAGE" bash -euc '
export DEBIAN_FRONTEND=noninteractive
sed -i "s/^Types: deb$/Types: deb deb-src/" /etc/apt/sources.list.d/ubuntu.sources
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends $PACKAGES >/dev/null
mkdir /src
cd /src
apt-get source -qq apparmor >/tmp/source.log 2>&1 || { cat /tmp/source.log; exit 1; }
version=$(dpkg-query -W -f "\${Version}" apparmor)
mkdir -p /apparmor/tests/regression
mv apparmor-*/tests/regression/apparmor /apparmor/tests/regression/
mv apparmor-*/common /apparmor/
cd /apparmor/tests/regression/apparmor
# The compiler gives many warnings for the tests. Show them only when the build fails.
make -s USE_SYSTEM=1 >/tmp/make.log 2>&1 || { cat /tmp/make.log; exit 1; }
# The tests of "make tests" on this system, in their order.
make -s USE_SYSTEM=1 --eval "print-tests: ; @echo \$(TESTS)" print-tests 2>/dev/null | tr " " "\n" |
	grep . > /apparmor/TESTS
echo "$version" > /apparmor/VERSION
apt-get purge -qq -y --autoremove $BUILD >/dev/null
apt-get clean
mkdir -p /out/root
tar -C / --exclude=./out --exclude=./proc --exclude=./sys --exclude=./dev --exclude=./tmp \
	--exclude=./src --exclude=./var/lib/apt/lists --exclude=./var/cache/apt \
	--exclude=./usr/share/doc --exclude=./usr/share/man --exclude=./usr/share/locale \
	-cf - . | tar -C /out/root -xf -
mkdir -p /out/root/proc /out/root/sys /out/root/dev /out/root/tmp
chown -R 0:0 /out/root
'
echo "apparmor: version $(cat "$out/root/apparmor/VERSION")"
du -sh "$out/root"
