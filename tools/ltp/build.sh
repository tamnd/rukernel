#!/bin/sh
# Builds the LTP tests of rukernel as static musl programs, in an Alpine container.
#
# Usage: tools/ltp/build.sh [--arch aarch64] OUT_DIR
#        tools/ltp/build.sh --full [--arch aarch64] OUT_DIR
#
# The script needs docker. It builds the LTP release in LTP_TAG.
#
# --arch aarch64 builds the arm64 programs in an arm64 Alpine container. On an x86-64 host, docker
# runs the container under qemu-user, so the host needs qemu-user-static with binfmt. The build is
# then approximately 10 times slower.
#
# Without --full, it builds only the test directories in LTP_DIRS, and the test programs go to
# OUT_DIR. `cargo xtask boot-test` finds them in target/ltp, or in the directory that RK_LTP gives.
#
# With --full, it builds all of LTP and installs it in OUT_DIR/ltp, as LTP installs itself in
# /opt/ltp. tools/ltp/run.py runs the runtest files of this tree. OUT_DIR/notbuilt.txt has the
# tests of the syscalls, mm, sched, net and pty groups that have no program, because the program
# did not build with musl. OUT_DIR/src.tar.gz has the C and shell sources of the tests for
# report.py.
# LTP_TESTDIRS gives the directories of the tests that --full builds, with a space between them.
# The default is all of testcases. For example, LTP_TESTDIRS=testcases/kernel/syscalls builds only
# the syscalls group, which is faster under qemu-user.
set -eu

LTP_TAG=20260930
LTP_DIRS="fork clone exit exit_group wait wait4 waitpid getpid getppid gettid brk mmap munmap mprotect mremap
msync madvise mlock munlock mincore getrlimit setrlimit execve kill signal sigaction rt_sigaction
sigprocmask rt_sigprocmask sigaltstack pipe pipe2 poll select futex read write open close dup dup2
dup3 lseek pread pwrite readv writev getdents mkdir unlink rename stat fstat chdir getcwd uname
nanosleep clock_gettime gettimeofday sched_yield set_tid_address arch_prctl fcntl umask access
clone3 set_robust_list get_robust_list epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait
eventfd eventfd2 timerfd signalfd signalfd4 socketpair socket bind connect listen accept accept4
sendmsg recvmsg send recv sendto recvfrom getsockname getpeername setsockopt getsockopt ptrace
prctl seccomp sched_setaffinity sched_getaffinity sched_getparam sched_setparam sched_getscheduler
sched_setscheduler sched_get_priority_max sched_get_priority_min sched_rr_get_interval
sched_setattr sched_getattr getcpu rt_sigsuspend sigsuspend rt_sigtimedwait sigpending
rt_sigqueueinfo tgkill sigwaitinfo sigtimedwait sigwait pause alarm timer_create timer_settime
timer_gettime timer_delete setitimer getitimer waitid getpriority setpriority nice fsopen fsconfig
fsmount fspick move_mount open_tree setxattr getxattr listxattr removexattr fsetxattr fgetxattr
flistxattr fremovexattr lgetxattr llistxattr lremovexattr sendfile splice copy_file_range fadvise"

# The runtest files of the groups that notbuilt.txt lists. net.* is each runtest/net.* file.
LTP_GROUPS="syscalls mm sched controllers net.* pty"

full=0
platform=linux/amd64
while [ $# -gt 1 ]; do
	case $1 in
	--full) full=1 ;;
	--arch)
		case ${2:-} in
		x86_64) platform=linux/amd64 ;;
		aarch64) platform=linux/arm64 ;;
		*) echo "ltp: the architecture is x86_64 or aarch64" >&2 && exit 2 ;;
		esac
		shift
		;;
	*) break ;;
	esac
	shift
done
out=${1:?usage: tools/ltp/build.sh [--full] [--arch aarch64] OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform "$platform" -v "$out:/out" -e LTP_TAG="$LTP_TAG" -e LTP_DIRS="$LTP_DIRS" \
	-e LTP_GROUPS="$LTP_GROUPS" -e FULL="$full" -e LTP_TESTDIRS="${LTP_TESTDIRS:-testcases}" \
	alpine:3.20 sh -euc '
# The libraries are for the tests that use them. configure links with -static, so it uses a
# library only if the library has a static archive. Without it, the test only reports TCONF.
apk add --no-cache build-base autoconf automake linux-headers pkgconf bash git >/dev/null
if [ "$FULL" = 1 ]; then
	apk add --no-cache libaio-dev libcap-dev libcap-static numactl-dev keyutils-dev acl-dev \
		acl-static libtirpc-dev libtirpc-static libmnl-dev libmnl-static >/dev/null 2>&1 ||
		echo "ltp: some libraries are not there"
fi
git clone --quiet --depth 1 --branch "$LTP_TAG" https://github.com/linux-test-project/ltp /ltp
cd /ltp
make autotools >/dev/null
./configure --prefix=/opt/ltp LDFLAGS=-static >/dev/null
if [ "$FULL" = 1 ]; then
	# A test that does not build does not stop the build. notbuilt.txt below records it. The
	# Makefile of a directory with subdirectories stops at the first subdirectory that fails, also
	# with -k, so the script runs make in each directory of tests.
	{
		make -C lib -j"$(nproc)" && make -C libs -k -j"$(nproc)"
		make -C testcases/lib -k -j"$(nproc)"
		dirs=$(find $LTP_TESTDIRS -name Makefile -exec grep -l generic_leaf_target {} + |
			xargs -n1 dirname)
		echo "$dirs" | xargs -P"$(nproc)" -I{} make -C {} -k
		# A directory with subdirectories can also have its own tests and scripts, as
		# controllers/memcg (memcontrol01 to memcontrol04) and controllers (cgroup_lib.sh). The
		# target trunk-all builds them without the subdirectories. The install of these files
		# needs the goal install, because env_post.mk sets INSTALL_FILES only for it.
		trunks=$(find $LTP_TESTDIRS -name Makefile -exec grep -l generic_trunk_target {} + |
			xargs -n1 dirname)
		echo "$trunks" | xargs -I{} make -C {} -k trunk-all
		if [ "$LTP_TESTDIRS" = testcases ]; then
			make -k
		fi
		echo "$dirs" | xargs -I{} make -C {} -k install
		echo "$trunks" | xargs -I{} make -C {} -k install
		# testcases/lib has the shell library (tst_test.sh, tst_net.sh) and its helper programs.
		make -C testcases/lib -k install
		if [ "$LTP_TESTDIRS" = testcases ]; then
			make -k install
		else
			# The runtest files, and the Version file that run.py compares with its image.
			make -C runtest -k install
			echo "$LTP_TAG" > /opt/ltp/Version
		fi
	} >/out/build.log 2>&1 || true
	# The symbols make the tree 5 times larger, so the script strips the tree before it copies it
	# to the host. strip fails on a script, and that is correct.
	find /opt/ltp -type f -perm -u+x -exec strip {} + 2>/dev/null || true
	rm -rf /out/ltp
	mv /opt/ltp /out/ltp
	# report.py reads the description of each test from its source.
	git ls-files "testcases/*.c" "testcases/*.sh" | tar -czf /out/src.tar.gz -T -
	cd /out/ltp
	for g in $LTP_GROUPS; do
		for f in runtest/$g; do
			grep -v "^#" "$f" | while read -r tag cmd _; do
				# A command that starts with a variable is a shell command.
				case $cmd in "" | *=*) continue ;; esac
				[ -e "testcases/bin/$cmd" ] || echo "${f#runtest/} $tag $cmd"
			done
		done
	done > /out/notbuilt.txt
	echo "$LTP_TAG" > /out/VERSION
	exit 0
fi
# The compiler can crash under x86-64 emulation on an arm64 host. More runs continue the build.
# A crash can leave an archive without some objects, so each run makes the archives again.
build() {
	for try in 1 2 3; do
		make -C "$1" -j"$(nproc)" >/dev/null 2>&1 && return
		find "$1" -name "*.a" -delete
	done
	make -C "$1" >/dev/null
}
build lib
build libs
for d in $LTP_DIRS; do
	dir="testcases/kernel/syscalls/$d"
	make -C "$dir" -j"$(nproc)" -k >/dev/null 2>&1 || make -C "$dir" -k >/dev/null 2>&1 ||
		make -C "$dir" -k >/dev/null 2>&1 || make -C "$dir" -k >/dev/null 2>&1 ||
		echo "ltp: some tests in $d did not build"
	# The symbols make each test 5 times larger, and the ltp boot test keeps each test in memory.
	for f in $(find "$dir" -maxdepth 1 -type f -perm -u+x ! -name "*.sh"); do
		strip -o "/out/${f##*/}" "$f"
	done
done
echo "$LTP_TAG" > /out/VERSION
'
echo "ltp: the tests are in $out"
