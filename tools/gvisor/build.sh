#!/bin/sh
# Builds the gVisor Unix socket syscall tests as static glibc programs, in a Debian container.
#
# Usage: tools/gvisor/build.sh OUT_DIR
#
# The script needs docker. It takes the gVisor source at GVISOR_COMMIT and builds only the tests in
# TESTS. It does not use bazel. It compiles the test/util files once into an archive, and links each
# test against that archive, abseil, gtest and gmock. The test programs go to OUT_DIR, with the
# names of the cc_binary targets in test/syscalls/linux/BUILD.
#
# The gVisor code needs absl::string_view to be std::string_view. The abseil of Debian does not
# have this property, so the script builds the static abseil libraries from ABSL_TAG. The gtest
# and gmock libraries come from Debian.
#
# The script replaces two bazel-only files. test_util_runfiles.cc needs the bazel runfiles library,
# so RunfilePath returns its argument. test_util_impl.cc needs google benchmark, so the replacement
# only runs the gtest tests.
#
# On an arm64 host, docker runs the amd64 compiler in an emulator. The emulated compiler can crash
# at random, so the script tries each compile and link step up to five times.
set -eu

GVISOR_COMMIT=3f738cc1a994ef418f19e7937cbe257c2f855fb5
ABSL_TAG=20260817.0

# Each line is a test name, then its source files in test/syscalls/linux. A backslash continues a
# line.
TESTS="
socket_unix_pair_test socket_unix_pair.cc socket_unix.cc socket_unix_cmsg.cc socket_unix_peercred.cc
socket_unix_stream_test socket_unix_stream.cc
socket_unix_stream_listener_close_test socket_unix_stream_listener_close.cc
socket_unix_dgram_local_test socket_unix_dgram_local.cc socket_unix_dgram.cc \
	socket_unix_non_stream.cc socket_non_stream.cc
socket_unix_dgram_non_blocking_test socket_unix_dgram_non_blocking.cc
socket_unix_seqpacket_local_test socket_unix_seqpacket_local.cc socket_unix_seqpacket.cc \
	socket_unix_non_stream.cc socket_non_stream.cc
socket_unix_unbound_abstract_test socket_unix_unbound_abstract.cc
socket_unix_unbound_dgram_test socket_unix_unbound_dgram.cc
socket_unix_unbound_filesystem_test socket_unix_unbound_filesystem.cc
socket_unix_unbound_seqpacket_test socket_unix_unbound_seqpacket.cc
socket_unix_unbound_stream_test socket_unix_unbound_stream.cc
socket_domain_test socket_unix_domain.cc socket_generic_test_cases.cc
socket_domain_non_blocking_test socket_unix_pair_nonblock.cc socket_non_blocking.cc
socket_abstract_non_blocking_test socket_unix_abstract_nonblock.cc socket_non_blocking.cc
socket_filesystem_non_blocking_test socket_unix_filesystem_nonblock.cc socket_non_blocking.cc
socket_stream_local_test socket_unix_stream_local.cc socket_stream.cc
socket_stream_blocking_local_test socket_unix_stream_blocking_local.cc socket_stream_blocking.cc
socket_stream_nonblock_local_test socket_unix_stream_nonblock_local.cc socket_stream_nonblock.cc
socket_blocking_local_test socket_unix_blocking_local.cc socket_blocking.cc
socket_non_stream_blocking_local_test socket_unix_non_stream_blocking_local.cc \
	socket_non_stream_blocking.cc
"

out=${1:?usage: tools/gvisor/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e GVISOR_COMMIT="$GVISOR_COMMIT" \
	-e ABSL_TAG="$ABSL_TAG" -e TESTS="$TESTS" debian:trixie sh -euc '
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends g++ libc6-dev linux-libc-dev libgtest-dev \
	libgmock-dev cmake make git ca-certificates >/dev/null
cat > /usr/local/bin/retry <<EOF
#!/bin/sh
for i in 1 2 3 4 5; do "\$@" && exit 0; done
exit 1
EOF
chmod +x /usr/local/bin/retry
git clone --quiet --depth 1 --branch "$ABSL_TAG" -c advice.detachedHead=false \
	https://github.com/abseil/abseil-cpp /absl
cmake -S /absl -B /absl/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_STANDARD=17 \
	-DABSL_PROPAGATE_CXX_STD=ON -DABSL_BUILD_TESTING=OFF >/dev/null
absl_targets="flags_parse strings str_format_internal time synchronization hash raw_hash_set \
	status statusor"
retry cmake --build /absl/build -j "$(nproc)" --target $absl_targets >/dev/null

git init --quiet /gvisor
cd /gvisor
git remote add origin https://github.com/google/gvisor
git sparse-checkout set test/util test/syscalls/linux
git fetch --quiet --depth 1 --filter=blob:none origin "$GVISOR_COMMIT"
git checkout --quiet FETCH_HEAD

# Replace the bazel-only files.
cat > test/util/test_util_runfiles.cc <<EOF
#include <string>
#include "test/util/test_util.h"
namespace gvisor {
namespace testing {
std::string RunfilePath(std::string path) { return path; }
}  // namespace testing
}  // namespace gvisor
EOF
cat > test/util/test_util_impl.cc <<EOF
#include <signal.h>
#include "gtest/gtest.h"
#include "absl/flags/parse.h"
#include "test/util/logging.h"
namespace gvisor {
namespace testing {
void SetupGvisorDeathTest() {}
void TestInit(int* argc, char*** argv) {
  ::testing::InitGoogleTest(argc, *argv);
  ::absl::ParseCommandLine(*argc, *argv);
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  TEST_CHECK(sigaction(SIGPIPE, &sa, nullptr) == 0);
}
int RunAllTests() { return RUN_ALL_TESTS(); }
}  // namespace testing
}  // namespace gvisor
EOF

CXX="g++ -std=c++17 -O2 -w -pthread -I/gvisor -I/absl"
export CXX
mkdir -p /obj
cd /gvisor/test/util
ls *.cc | grep -v -E "_test\.cc$|^(fuse_util|io_uring_util|errno_safe_allocator)\.cc$" |
	sed "s|^|test/util/|" > /obj/util.list
echo test/syscalls/linux/unix_domain_socket_test_util.cc >> /obj/util.list
echo test/syscalls/linux/ip_socket_test_util.cc >> /obj/util.list
cd /gvisor
echo "$TESTS" | awk "NF { for (i = 2; i <= NF; i++) print \"test/syscalls/linux/\" \$i }" |
	sort -u > /obj/linux.list
echo test/util/errno_safe_allocator.cc | cat /obj/util.list /obj/linux.list - |
	xargs -P "$(nproc)" -I{} sh -c "o=/obj/\$(basename {} .cc).o
		retry \$CXX -c -o \$o {}"
ar rcs /obj/libgvisor_util.a $(sed "s|.*/\(.*\)\.cc$|/obj/\1.o|" /obj/util.list)

absl=$(find /absl/build -name "libabsl_*.a")
echo "$TESTS" | while read -r name srcs; do
	[ -n "$name" ] || continue
	objs=$(for s in $srcs; do echo "/obj/${s%.cc}.o"; done)
	retry $CXX -static -o "/out/$name" $objs /obj/errno_safe_allocator.o /obj/libgvisor_util.a \
		-lgmock -lgtest -Wl,--start-group $absl -Wl,--end-group
	strip "/out/$name"
done
echo "gvisor $GVISOR_COMMIT abseil $ABSL_TAG" > /out/VERSION
'
echo "gvisor: the tests are in $out"
