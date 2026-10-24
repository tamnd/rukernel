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
timer_gettime timer_delete setitimer getitimer waitid"

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
# The compiler can crash under x86-64 emulation on an arm64 host. More serial runs continue the
# build.
build() {
	make -C "$1" -j"$(nproc)" >/dev/null 2>&1 || make -C "$1" >/dev/null 2>&1 ||
		make -C "$1" >/dev/null 2>&1 || make -C "$1" >/dev/null
}
build lib
build libs
for d in $LTP_DIRS; do
	dir="testcases/kernel/syscalls/$d"
	make -C "$dir" -j"$(nproc)" -k >/dev/null 2>&1 || make -C "$dir" -k >/dev/null 2>&1 ||
		make -C "$dir" -k >/dev/null 2>&1 || make -C "$dir" -k >/dev/null 2>&1 ||
		echo "ltp: some tests in $d did not build"
	# The symbols make each test 5 times larger, and the ltp boot test keeps each test in memory.
	find "$dir" -maxdepth 1 -type f -perm -u+x ! -name "*.sh" \
		-exec sh -c 'strip -o "/out/${1##*/}" "$1"' sh {} \;
done
echo "$LTP_TAG" > /out/VERSION
'
echo "ltp: the tests are in $out"
