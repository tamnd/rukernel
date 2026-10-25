#!/bin/sh
# Builds fstests and a Debian root file system that runs it, in a Debian container.
#
# Usage: tools/fstests/build.sh OUT_DIR
#
# The script needs docker. It builds the fstests release in FSTESTS_TAG, and installs it in
# /var/lib/xfstests of the container. Then it removes the compilers and the documents, and writes
# the root file system of the container to OUT_DIR/rootfs.tar.gz. `cargo xtask boot-test fstests`
# finds the file in target/fstests, or in the directory that RK_FSTESTS gives.
#
# The root file system is large. The boot test keeps it in memory, so the virtual machine of the
# test has more memory than the other boot tests.
set -eu

FSTESTS_TAG=v2026.10.15
URL=https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/snapshot

# The packages that fstests uses when it runs.
RUN="acl attr bc bsdextrautils e2fsprogs fio gawk kmod libaio1t64 libgdbm6t64 libgdbm-compat4t64
liburing2 perl procps psmisc sed util-linux uuid-runtime xfsprogs"
# The packages that only the build uses.
BUILD="autoconf automake ca-certificates curl gcc libacl1-dev libaio-dev libattr1-dev libcap-dev
libgdbm-compat-dev libgdbm-dev libtool libtool-bin liburing-dev make pkg-config uuid-dev
xfslibs-dev"

out=${1:?usage: tools/fstests/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e FSTESTS_TAG="$FSTESTS_TAG" -e URL="$URL" \
	-e RUN="$RUN" -e BUILD="$BUILD" debian:trixie sh -euc '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends $RUN >/dev/null
apt-get install -qq -y --no-install-recommends $BUILD >/dev/null
curl -fsSL "$URL/xfstests-dev-$FSTESTS_TAG.tar.gz" | tar -xz -C /tmp
cd /tmp/xfstests-dev-$FSTESTS_TAG
make -j"$(nproc)" >/dev/null 2>&1 || make
make install >/dev/null
cd /
rm -rf /tmp/xfstests-dev-$FSTESTS_TAG
# Some tests run commands as these users.
useradd -m fsgqa
useradd -m fsgqa2
useradd 123456-fsgqa
apt-mark manual $RUN >/dev/null
apt-get purge -qq -y $BUILD >/dev/null
apt-get autoremove -qq -y --purge >/dev/null
apt-get clean
rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale \
	/var/log/* /var/cache/debconf/*-old
mkdir -p /test /scratch
tar -czf /out/rootfs.tar.gz --one-file-system --exclude=./out -C / .
echo "$FSTESTS_TAG" > /out/VERSION
'
echo "fstests: the root file system is in $out/rootfs.tar.gz"
