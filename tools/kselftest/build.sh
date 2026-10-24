#!/bin/sh
# Builds the kselftest programs of rukernel as static glibc programs, in a Debian container.
#
# Usage: tools/kselftest/build.sh OUT_DIR
#
# The script needs docker. It takes the selftests of the Linux release in LINUX_TAG, and builds
# only the tests in TESTS. The test programs go to OUT_DIR. `cargo xtask boot-test` finds them in
# target/kselftest, or in the directory that RK_KSELFTEST gives.
set -eu

LINUX_TAG=v6.17
TESTS="seccomp/seccomp_bpf"

out=${1:?usage: tools/kselftest/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e LINUX_TAG="$LINUX_TAG" -e TESTS="$TESTS" \
	debian:trixie sh -euc '
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends gcc libc6-dev libcap-dev linux-libc-dev git \
	ca-certificates >/dev/null
git clone --quiet --depth 1 --branch "$LINUX_TAG" --filter=blob:none --sparse \
	https://github.com/torvalds/linux /linux
cd /linux
git sparse-checkout set --no-cone /tools/testing/selftests/ >/dev/null
cd tools/testing/selftests
for t in $TESTS; do
	gcc -static -O2 -Wall -D_GNU_SOURCE -I. -o "/out/${t##*/}" "$t.c" \
		-lcap -lpthread
	strip "/out/${t##*/}"
done
echo "$LINUX_TAG" > /out/VERSION
'
echo "kselftest: the tests are in $out"
