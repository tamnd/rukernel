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
TESTS="seccomp/seccomp_bpf net/af_unix/scm_pidfd timens/timens timens/timerfd timens/timer
	timens/clock_nanosleep timens/procfs timens/exec timens/futex timens/vfork_exec
	lsm/lsm_get_self_attr_test lsm/lsm_set_self_attr_test lsm/lsm_list_modules_test
	pidfd/pidfd_fdinfo_test pidfd/pidfd_file_handle_test pidfd/pidfd_info_test
	pidfd/pidfd_exec_helper pidfd/pidfd_setns_test
	cgroup/test_core cgroup/test_cpuset cgroup/test_freezer cgroup/test_kill"

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
	# The tests of lsm also need lsm/common.c, as their Makefile.
	# The tests of cgroup need cgroup/lib/cgroup_util.c and its header.
	extra=
	case $t in
	lsm/*) extra=lsm/common.c ;;
	cgroup/*) extra="cgroup/lib/cgroup_util.c -Icgroup/lib/include" ;;
	esac
	gcc -static -O2 -Wall -D_GNU_SOURCE -I. -o "/out/${t##*/}" "$t.c" $extra \
		-lcap -lpthread
	strip "/out/${t##*/}"
done
echo "$LINUX_TAG" > /out/VERSION
'
echo "kselftest: the tests are in $out"
