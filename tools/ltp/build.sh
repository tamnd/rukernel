#!/bin/sh
# Builds the LTP tests of rukernel as static musl programs, in an Alpine container.
#
# Usage: tools/ltp/build.sh OUT_DIR
#
# The script needs docker. It builds the LTP release in LTP_TAG, and only the test directories in
# LTP_DIRS. The test programs go to OUT_DIR. `cargo xtask boot-test` finds them in target/ltp, or
# in the directory that RK_LTP gives.
set -eu

LTP_TAG=20260930
LTP_DIRS="fork clone exit exit_group wait wait4 waitpid getpid getppid gettid brk mmap munmap mprotect mremap"

out=${1:?usage: tools/ltp/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e LTP_TAG="$LTP_TAG" -e LTP_DIRS="$LTP_DIRS" \
	alpine:3.20 sh -euc '
apk add --no-cache build-base autoconf automake linux-headers pkgconf bash git >/dev/null
git clone --quiet --depth 1 --branch "$LTP_TAG" https://github.com/linux-test-project/ltp /ltp
cd /ltp
make autotools >/dev/null
./configure LDFLAGS=-static >/dev/null
# The compiler can crash under x86-64 emulation on an arm64 host. A second serial run continues
# the build.
make -C lib -j"$(nproc)" >/dev/null 2>&1 || make -C lib >/dev/null
make -C libs -j"$(nproc)" >/dev/null 2>&1 || make -C libs >/dev/null
for d in $LTP_DIRS; do
	make -C "testcases/kernel/syscalls/$d" -j"$(nproc)" -k >/dev/null 2>&1 ||
		make -C "testcases/kernel/syscalls/$d" -k >/dev/null 2>&1 || echo "ltp: some tests in $d did not build"
	find "testcases/kernel/syscalls/$d" -maxdepth 1 -type f -perm -u+x ! -name "*.sh" -exec cp {} /out/ \;
done
echo "$LTP_TAG" > /out/VERSION
'
echo "ltp: the tests are in $out"
