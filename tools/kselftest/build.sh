#!/bin/sh
# Builds the kselftest programs of rukernel as static glibc programs, in a Debian container.
#
# Usage: tools/kselftest/build.sh OUT_DIR
#
# The script needs docker. It takes the selftests of the Linux release in LINUX_TAG, and builds
# only the tests in TESTS, and bpf/test_verifier with a static libbpf. The test programs go to
# OUT_DIR. `cargo xtask boot-test` finds them in target/kselftest, or in the directory that
# RK_KSELFTEST gives.
#
# The Python tests of tpm2 go to OUT_DIR/tpm2. The `kselftest` boot test does not run them: the
# `tpm` boot test runs them with the python3 of tools/tpm/build.sh, on x86-64 and on arm64.
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
	ca-certificates make python3 libelf-dev zlib1g-dev libzstd-dev >/dev/null
git clone --quiet --depth 1 --branch "$LINUX_TAG" --filter=blob:none --sparse \
	https://github.com/torvalds/linux /linux
cd /linux
git sparse-checkout set --no-cone /tools/ /kernel/bpf/disasm.c /kernel/bpf/disasm.h >/dev/null
cd tools/testing/selftests
for t in $TESTS; do
	# The tests of lsm also need lsm/common.c, as their Makefile.
	# The tests of cgroup need cgroup/lib/cgroup_util.c and its header.
	# The tests of cgroup build without optimization, as their Makefile: at -O2, gcc removes
	# the malloc, the writes and the free of alloc_anon of test_memcontrol, so the test does
	# not use the memory that it must use.
	extra=
	opt=-O2
	case $t in
	lsm/*) extra=lsm/common.c ;;
	cgroup/*) extra="cgroup/lib/cgroup_util.c -Icgroup/lib/include" opt= ;;
	esac
	gcc -static $opt -Wall -D_GNU_SOURCE -I. -o "/out/${t##*/}" "$t.c" $extra \
		-lcap -lpthread
	strip "/out/${t##*/}"
done
mkdir -p /out/tpm2
cp tpm2/test_smoke.sh tpm2/test_space.sh tpm2/test_async.sh tpm2/tpm2.py tpm2/tpm2_tests.py \
	/out/tpm2/
# bpf/test_verifier, as its rule in the Makefile of selftests/bpf, with a static libbpf.
mkdir -p /b/libbpf
make -s -C /linux/tools/lib/bpf -j"$(nproc)" OUTPUT=/b/libbpf/ BUILD_STATIC_ONLY=1 \
	DESTDIR=/b/inst prefix=/usr install >/dev/null
cd bpf
# rukernel cannot load bpf_testmod.ko, the module of the tests. Without the module, only the
# tests of its kernel functions fail, so the test runs on.
sed -i "/if (load_bpf_testmod(verbose))/{N;s/.*\n.*/\tload_bpf_testmod(verbose);/}" test_verifier.c
# The verifier of rukernel is for the program types of issue #537 only, so the other tests do not
# apply. tools/kselftest/bpf.md gives the result.
sed -i "/^\tfixup_skips = skips;/i\\
\tif (prog_type != BPF_PROG_TYPE_SOCKET_FILTER \&\& prog_type != BPF_PROG_TYPE_CGROUP_SKB \&\&\\
\t    prog_type != BPF_PROG_TYPE_CGROUP_SOCK \&\&\\
\t    prog_type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR \&\&\\
\t    prog_type != BPF_PROG_TYPE_CGROUP_DEVICE) {\\
\t\tprintf(\"SKIP (program type %d)\\\\n\", prog_type);\\
\t\tskips++;\\
\t\treturn;\\
\t}" test_verifier.c
(cd verifier && echo "#ifdef FILL_ARRAY" && ls *.c | sed "s/.*/#include \"&\"/" &&
	echo "#endif") > verifier/tests.h
# The libelf.a of Debian trixie does not have the search tree of elfutils.
printf "%s\n" "#include <search.h>" "struct t { void *root; };" \
	"void eu_search_tree_init(struct t *t) { t->root = 0; }" \
	"void eu_search_tree_fini(struct t *t, void (*f)(void *))" \
	"{ if (t->root) tdestroy(t->root, f); t->root = 0; }" > /b/eu-search.c
gcc -static -O2 -std=gnu11 -D_GNU_SOURCE -I. -I/b/inst/usr/include -I/linux/tools/include \
	-I/linux/tools/arch/x86/include -I/linux/tools/include/uapi -o /out/test_verifier \
	test_verifier.c testing_helpers.c cap_helpers.c unpriv_helpers.c disasm.c /b/eu-search.c \
	/b/inst/usr/lib64/libbpf.a -lelf -lz -lzstd -lrt -lpthread
strip /out/test_verifier
echo "$LINUX_TAG" > /out/VERSION
'
echo "kselftest: the tests are in $out"
