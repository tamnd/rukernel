/*
 * The init program of the rk.test=init boot test. It is a static ELF file. Each check prints
 * one line. init exits with 0 if each check passes, and with 1 if a check fails. With the
 * argument "tty", init also reads a line from the console and waits for ^C, which the boot test
 * types. With the argument "smp", init also checks the CPU count and runs a hackbench load.
 * With the first argument "only", init runs only the checks of the next argument.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/epoll.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/klog.h>
#include <sys/file.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/aio_abi.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <mqueue.h>
#include <termios.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <unistd.h>

/* The names of the machine for uname and seccomp. */
#if defined(__aarch64__)
#define UNAME_MACHINE "aarch64"
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_AARCH64
#else
#define UNAME_MACHINE "x86_64"
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_X86_64
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

static int failed;

static void check(const char *name, int ok)
{
	printf("init: %s: %s\n", name, ok ? "ok" : "FAIL");
	if (!ok)
		failed = 1;
}

static void test_ids(void)
{
	check("getpid gives 1", getpid() == 1);
	check("getppid gives 0", getppid() == 0);
}

/* The credentials change in a child, so init stays root. */
static void test_creds(void)
{
	check("getuid and getegid give 0", getuid() == 0 && getegid() == 0);
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	pid_t pid = fork();
	if (pid == 0) {
		failed = 0;
		unsigned int header[2] = {0x20080522, 0};
		unsigned int data[6];
		gid_t groups[2] = {20, 10};
		gid_t got[4] = {0};
		check("setgroups as root", syscall(SYS_setgroups, 2, groups) == 0);
		check("getgroups gives the sorted groups",
		      syscall(SYS_getgroups, 0, NULL) == 2 && syscall(SYS_getgroups, 4, got) == 2 &&
			      got[0] == 10 && got[1] == 20);
		check("getgroups with a small size gives EINVAL",
		      syscall(SYS_getgroups, 1, got) == -1 && errno == EINVAL);
		check("PR_CAPBSET_DROP removes CAP_SYS_ADMIN",
		      prctl(PR_CAPBSET_READ, 21) == 1 && prctl(PR_CAPBSET_DROP, 21) == 0 &&
			      prctl(PR_CAPBSET_READ, 21) == 0);
		check("setresgid", syscall(SYS_setresgid, 100, 100, 100) == 0 && getgid() == 100);
		check("setresuid keeps root in the saved ID",
		      syscall(SYS_setresuid, 1000, 1000, 0) == 0 && geteuid() == 1000);
		check("capget gives no effective capabilities after the change",
		      syscall(SYS_capget, header, data) == 0 && data[0] == 0 && data[1] != 0);
		check("the saved ID gives root back",
		      syscall(SYS_setresuid, -1, 0, -1) == 0 && geteuid() == 0 &&
			      syscall(SYS_capget, header, data) == 0 && data[0] != 0);
		check("setuid as root sets all the IDs", syscall(SYS_setuid, 1000) == 0);
		uid_t r, e, sv;
		check("getresuid gives the new IDs",
		      syscall(SYS_getresuid, &r, &e, &sv) == 0 && r == 1000 && e == 1000 && sv == 1000);
		check("setuid back to root gives EPERM", syscall(SYS_setuid, 0) == -1 && errno == EPERM);
		check("setgroups as a user gives EPERM",
		      syscall(SYS_setgroups, 0, NULL) == -1 && errno == EPERM);
		check("capget gives no permitted capabilities",
		      syscall(SYS_capget, header, data) == 0 && data[0] == 0 && data[1] == 0);
		check("setfsuid to a strange ID changes nothing",
		      syscall(SYS_setfsuid, 5) == 1000 && syscall(SYS_setfsuid, -1) == 1000);
		char buf[2048];
		int fd = open("/proc/self/status", O_RDONLY);
		ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
		buf[n < 0 ? 0 : n] = 0;
		check("/proc/self/status shows the IDs",
		      strstr(buf, "\nUid:\t1000\t1000\t1000\t1000\n") &&
			      strstr(buf, "\nGid:\t100\t100\t100\t100\n") && strstr(buf, "\nGroups:\t10 20\n"));
		close(fd);
		_exit(failed);
	}
	int status;
	check("the credentials child passes",
	      waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	umount("/proc");
	check("init is root after the child", getuid() == 0 && geteuid() == 0);
}

/* An ACL in the format of the system.posix_acl_* attributes. */
struct acl_entry {
	unsigned short tag, perm;
	unsigned int id;
};

struct acl {
	unsigned int version;
	struct acl_entry e[5];
};

static void test_acls(void)
{
	/* Root reads and writes, user 1000 reads, the others get nothing. */
	struct acl access = {2,
			     {{1, 6, -1}, {2, 4, 1000}, {4, 0, -1}, {0x10, 4, -1}, {0x20, 0, -1}}};
	struct acl def = {2, {{1, 7, -1}, {4, 5, -1}, {0x20, 0, -1}}};
	struct stat st;
	int fd = open("/tmp/perm.acl", O_WRONLY | O_CREAT, 0600);
	close(fd);
	check("setxattr of an access ACL sets the group bits to the mask",
	      setxattr("/tmp/perm.acl", "system.posix_acl_access", &access, sizeof(access), 0) == 0 &&
		      stat("/tmp/perm.acl", &st) == 0 && (st.st_mode & 0777) == 0640);
	struct acl got;
	check("getxattr gives the ACL back",
	      getxattr("/tmp/perm.acl", "system.posix_acl_access", &got, sizeof(got)) ==
			      sizeof(access) &&
		      memcmp(&got, &access, sizeof(access)) == 0);
	check("a default ACL on a file gives EACCES",
	      setxattr("/tmp/perm.acl", "system.posix_acl_default", &def, 4 + 3 * 8, 0) == -1 &&
		      errno == EACCES);
	mkdir("/tmp/perm.dacl", 0777);
	check("a new file gets the bits of the default ACL and not the umask",
	      setxattr("/tmp/perm.dacl", "system.posix_acl_default", &def, 4 + 3 * 8, 0) == 0 &&
		      (fd = open("/tmp/perm.dacl/f", O_WRONLY | O_CREAT, 0666)) >= 0 &&
		      fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0640);
	close(fd);
	check("a new directory gets the default ACL",
	      mkdir("/tmp/perm.dacl/d", 0777) == 0 &&
		      getxattr("/tmp/perm.dacl/d", "system.posix_acl_default", &got, sizeof(got)) ==
			      4 + 3 * 8);
}

static void test_perms(void)
{
	int fd = open("/tmp/perm.secret", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	close(fd);
	check("mkdir for the permission test",
	      mkdir("/tmp/perm.priv", 0700) == 0 && mkdir("/tmp/perm.sticky", 0777) == 0 &&
		      chmod("/tmp/perm.sticky", 01777) == 0 && mkdir("/tmp/perm.sg", 0777) == 0 &&
		      chmod("/tmp/perm.sg", 02777) == 0 && chown("/tmp/perm.sg", 0, 50) == 0);
	fd = open("/tmp/perm.sticky/root", O_WRONLY | O_CREAT, 0666);
	close(fd);
	chmod("/tmp/perm.sticky/root", 0666);
	fd = open("/tmp/perm.suid", O_WRONLY | O_CREAT, 0755);
	close(fd);
	struct stat sst;
	check("chown by root clears the set-user-ID bit",
	      chmod("/tmp/perm.suid", 04755) == 0 && chown("/tmp/perm.suid", 1000, 100) == 0 &&
		      stat("/tmp/perm.suid", &sst) == 0 && (sst.st_mode & 07777) == 0755);
	check("chmod by root keeps the set-user-ID bit",
	      chmod("/tmp/perm.suid", 06755) == 0 && stat("/tmp/perm.suid", &sst) == 0 &&
		      (sst.st_mode & 07777) == 06755);
	test_acls();
	pid_t pid = fork();
	if (pid == 0) {
		gid_t groups[1] = {50};
		failed = 0;
		struct stat st;
		check("the permission child becomes a user",
		      syscall(SYS_setgroups, 1, groups) == 0 &&
			      syscall(SYS_setresgid, 100, 100, 100) == 0 &&
			      syscall(SYS_setresuid, 1000, 1000, 1000) == 0);
		check("open of a file of root with the mode 0600 gives EACCES",
		      open("/tmp/perm.secret", O_RDONLY) == -1 && errno == EACCES);
		check("access gives EACCES",
		      access("/tmp/perm.secret", R_OK) == -1 && errno == EACCES &&
			      access("/tmp/perm.secret", F_OK) == 0);
		check("create in a directory of root gives EACCES",
		      open("/tmp/perm.new", O_WRONLY | O_CREAT, 0644) == -1 && errno == EACCES);
		check("chdir to a directory without search permission gives EACCES",
		      chdir("/tmp/perm.priv") == -1 && errno == EACCES);
		check("a walk through a directory without search permission gives EACCES",
		      stat("/tmp/perm.priv/x", &st) == -1 && errno == EACCES);
		fd = open("/tmp/perm.sticky/mine", O_RDWR | O_CREAT, 0);
		check("open with O_CREAT and the mode 0 can write", fd >= 0 && write(fd, "x", 1) == 1);
		close(fd);
		check("a new file has the owner and the group of the process",
		      stat("/tmp/perm.sticky/mine", &st) == 0 && st.st_uid == 1000 && st.st_gid == 100);
		check("unlink of a file of root in a sticky directory gives EPERM",
		      unlink("/tmp/perm.sticky/root") == -1 && errno == EPERM);
		check("unlink of an own file in a sticky directory", unlink("/tmp/perm.sticky/mine") == 0);
		check("mknod of a device without CAP_MKNOD gives EPERM",
		      mknod("/tmp/perm.sticky/null", S_IFCHR | 0666, makedev(1, 3)) == -1 &&
			      errno == EPERM);
		check("a directory in a set-group-ID directory gets its group and the bit",
		      mkdir("/tmp/perm.sg/d", 0755) == 0 && stat("/tmp/perm.sg/d", &st) == 0 &&
			      st.st_gid == 50 && (st.st_mode & S_ISGID));
		check("chmod of a file of root gives EPERM",
		      chmod("/tmp/perm.sticky/root", 0777) == -1 && errno == EPERM);
		check("chown to another user gives EPERM",
		      chown("/tmp/perm.suid", 2000, -1) == -1 && errno == EPERM);
		check("chown to a group of the process", chown("/tmp/perm.sg/d", -1, 100) == 0);
		check("chown to a group outside the process gives EPERM",
		      chown("/tmp/perm.sg/d", -1, 7) == -1 && errno == EPERM);
		struct timespec ts[2] = {{1, 0}, {1, 0}};
		check("utimensat with a time on a file of root gives EPERM",
		      utimensat(AT_FDCWD, "/tmp/perm.sticky/root", ts, 0) == -1 && errno == EPERM);
		check("utimensat to now on a file that the process can write",
		      utimensat(AT_FDCWD, "/tmp/perm.sticky/root", NULL, 0) == 0);
		fd = open("/tmp/perm.suid", O_WRONLY);
		check("a write clears the set-user-ID and set-group-ID bits",
		      fd >= 0 && write(fd, "x", 1) == 1 && stat("/tmp/perm.suid", &st) == 0 &&
			      (st.st_mode & 07777) == 0755);
		close(fd);
		check("setxattr of a trusted attribute gives EPERM",
		      syscall(SYS_setxattr, "/tmp/perm.suid", "trusted.a", "v", 1, 0) == -1 &&
			      errno == EPERM);
		check("setxattr of a user attribute on a file of root gives EACCES",
		      syscall(SYS_setxattr, "/tmp/perm.secret", "user.a", "v", 1, 0) == -1 &&
			      errno == EACCES);
		check("kill of init as a user gives EPERM", kill(1, 0) == -1 && errno == EPERM);
		check("kill of the process itself", kill(getpid(), 0) == 0);
		check("ptrace attach to init gives EPERM",
		      ptrace(PTRACE_ATTACH, 1, 0, 0) == -1 && errno == EPERM);
		check("a lower nice value without CAP_SYS_NICE gives EACCES",
		      setpriority(PRIO_PROCESS, 0, -5) == -1 && errno == EACCES &&
			      setpriority(PRIO_PROCESS, 0, 5) == 0);
		struct rlimit rl;
		getrlimit(RLIMIT_NOFILE, &rl);
		rl.rlim_max--;
		check("a lower hard limit", setrlimit(RLIMIT_NOFILE, &rl) == 0);
		rl.rlim_max++;
		check("a higher hard limit without CAP_SYS_RESOURCE gives EPERM",
		      setrlimit(RLIMIT_NOFILE, &rl) == -1 && errno == EPERM);
		rl.rlim_max--;
		rl.rlim_cur = 2048;
		fd = setrlimit(RLIMIT_NOFILE, &rl) == 0 ? fcntl(1, F_DUPFD, 1500) : -1;
		check("a higher soft limit lets the process use a descriptor above 1024", fd >= 1500);
		close(fd);
		check("mount without CAP_SYS_ADMIN gives EPERM",
		      mount("none", "/tmp", "tmpfs", 0, NULL) == -1 && errno == EPERM);
		fd = open("/tmp/perm.acl", O_RDONLY);
		check("a named user entry of an ACL gives read access", fd >= 0);
		close(fd);
		check("the ACL refuses a write to the named user",
		      open("/tmp/perm.acl", O_WRONLY) == -1 && errno == EACCES);
		check("setxattr of an ACL on a file of root gives EPERM",
		      setxattr("/tmp/perm.acl", "system.posix_acl_access", "", 0, 0) == -1 &&
			      errno == EPERM);
		_exit(failed);
	}
	int status;
	check("the permission child passes",
	      waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_uname(void)
{
	struct utsname u;
	check("uname", uname(&u) == 0 && strcmp(u.sysname, "Linux") == 0 &&
			       strcmp(u.machine, UNAME_MACHINE) == 0);
}

static void test_memory(void)
{
	char *p = malloc(1 << 20);
	check("malloc of 1 MiB", p != NULL);
	if (p) {
		memset(p, 0x5a, 1 << 20);
		check("the memory keeps its value", p[12345] == 0x5a);
		free(p);
	}
	char *m = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	check("mmap of anonymous memory", m != MAP_FAILED && m[4096] == 0);
	if (m != MAP_FAILED) {
		m[8191] = 1;
		check("munmap", munmap(m, 3 * 4096) == 0);
	}
	/* musl gives ENOMEM for sbrk with an increment, so the test uses the system call. */
	long cur = syscall(SYS_brk, 0);
	check("brk", cur > 0 && syscall(SYS_brk, cur + 8192) == cur + 8192);
	((volatile char *)cur)[8191] = 1;
	check("brk again with the old end", syscall(SYS_brk, cur) == cur);
	/* MADV_GUARD_INSTALL (102) and MADV_WIPEONFORK (18), as mm/madvise.c of Linux (#385). */
	m = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m != MAP_FAILED) {
		m[4096] = 7;
		check("madvise MADV_WIPEONFORK", madvise(m + 4096, 4096, 18) == 0);
		check("madvise MADV_GUARD_INSTALL", madvise(m, 4096, 102) == 0);
		int status = 0;
		pid_t pid = fork();
		if (pid == 0)
			_exit(m[4096] == 0 ? 0 : 1);
		check("the child of fork has zero pages in a MADV_WIPEONFORK area",
		      waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		pid = fork();
		if (pid == 0) {
			*(volatile char *)m = 1;
			_exit(0);
		}
		check("an access to a guard page gives SIGSEGV",
		      waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
		check("the parent keeps the data of a MADV_WIPEONFORK area", m[4096] == 7);
		munmap(m, 2 * 4096);
	}
}

/* Gives the value of the line `name` of /proc/meminfo, or -1. */
static long meminfo(const char *name)
{
	char buf[4096];
	int fd = open("/proc/meminfo", O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	char *at = strstr(buf, name);
	return at ? strtol(at + strlen(name) + 1, NULL, 10) : -1;
}

/* Writes `text` to the file `path`. Gives 0, or -1 for an error. */
static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* Touches the bytes at `p` and gives the signal that stopped the child, or 0. */
static int touch_in_child(volatile char *p)
{
	int status = 0;
	pid_t pid = fork();
	if (pid == 0) {
		*p = 1;
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return WIFSIGNALED(status) ? WTERMSIG(status) : 0;
}

static unsigned long long pagemap_entry(const void *addr);
static unsigned long long kpageflags_pfn(unsigned long long pfn);

/* `size=` and `min_size=` of hugetlbfs, as the subpool of mm/hugetlb.c of Linux (#392). */
static void test_hugetlbfs(void)
{
	const long huge = 2 << 20;
	mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/huge", 0755);
	if (write_text("/proc/sys/vm/nr_hugepages", "4") != 0 || meminfo("HugePages_Total:") != 4 ||
	    mount("none", "/huge", "hugetlbfs", 0, "size=4M,min_size=2M") != 0) {
		check("hugetlbfs with 4 huge pages", 0);
		umount("/proc");
		return;
	}
	check("min_size= reserves its page", meminfo("HugePages_Rsvd:") == 1);
	int fd = open("/huge/f", O_CREAT | O_RDWR, 0600);
	char *m = mmap(NULL, huge, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	check("a mapping of hugetlbfs uses the reservation of min_size=",
	      m != MAP_FAILED && meminfo("HugePages_Rsvd:") == 1);
	if (m != MAP_FAILED)
		munmap(m, huge);
	m = mmap(NULL, 3 * huge, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE, fd, 0);
	check("mmap of hugetlbfs with MAP_NORESERVE", m != MAP_FAILED);
	if (m != MAP_FAILED) {
		check("faults of hugetlbfs within size= work",
		      touch_in_child(m) == 0 && touch_in_child(m + huge) == 0);
		check("a fault of hugetlbfs past size= gives SIGBUS",
		      touch_in_child(m + 2 * huge) == SIGBUS);
		munmap(m, 3 * huge);
	}
	/* KPF_MMAP (11) only while a process maps the page, as folio_mapped in fs/proc/page.c (#444). */
	m = mmap(NULL, huge, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m != MAP_FAILED) {
		const unsigned long long kmmap = 1ULL << 11, khuge = 1ULL << 17;
		m[0] = 1;
		unsigned long long pfn = pagemap_entry(m) & ((1ULL << 55) - 1);
		check("kpageflags: a mapped page of hugetlbfs has KPF_MMAP",
		      pfn != 0 && (kpageflags_pfn(pfn) & (kmmap | khuge)) == (kmmap | khuge));
		munmap(m, huge);
		check("kpageflags: a page of hugetlbfs that no process maps has no KPF_MMAP",
		      (kpageflags_pfn(pfn) & (kmmap | khuge)) == khuge);
	}
	close(fd);
	unlink("/huge/f");
	check("the pages of a file of hugetlbfs go back to the reservation of min_size=",
	      meminfo("HugePages_Rsvd:") == 1 && meminfo("HugePages_Free:") == 4);

	/* A private mapping of a file takes the pages of the mount too (#415). */
	fd = open("/huge/p", O_CREAT | O_RDWR, 0600);
	m = mmap(NULL, 3 * huge, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	check("a private mapping of hugetlbfs past size= gives ENOMEM", m == MAP_FAILED && errno == ENOMEM);
	m = mmap(NULL, 2 * huge, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	check("a private mapping of hugetlbfs reserves its pages in the mount",
	      m != MAP_FAILED && meminfo("HugePages_Rsvd:") == 2 &&
		      mmap(NULL, huge, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED);
	if (m != MAP_FAILED) {
		/* KPF_HUGE (17), KPF_ANON (12), KPF_COMPOUND_HEAD (15) and KPF_COMPOUND_TAIL (16) (#430). */
		const unsigned long long khuge = 1ULL << 17, kanon = 1ULL << 12, khead = 1ULL << 15, ktail = 1ULL << 16;
		m[0] = 1;
		unsigned long long pfn = pagemap_entry(m) & ((1ULL << 55) - 1);
		unsigned long long head = kpageflags_pfn(pfn), tail = kpageflags_pfn(pfn + 1);
		check("kpageflags: a private hugetlb page is anonymous and huge",
		      pfn != 0 && (head & (khuge | kanon | khead | ktail)) == (khuge | kanon | khead) &&
			      (tail & (khuge | kanon | khead | ktail)) == (khuge | kanon | ktail));
		munmap(m, 2 * huge);
		check("kpageflags: a free page of the hugetlb pool is huge only", kpageflags_pfn(pfn) == (khuge | khead));
	}
	check("the private pages go back to the mount",
	      meminfo("HugePages_Rsvd:") == 1 && meminfo("HugePages_Free:") == 4);
	m = mmap(NULL, 3 * huge, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
	if (m != MAP_FAILED) {
		int status = 0;
		pid_t pid = fork();
		if (pid == 0) {
			m[0] = 1;
			m[huge] = 1;
			m[2 * huge] = 1;
			_exit(0);
		}
		check("a private fault of hugetlbfs past size= gives SIGBUS",
		      waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
		munmap(m, 3 * huge);
	}
	close(fd);
	unlink("/huge/p");
	check("the pages of a private fault go back to the mount",
	      meminfo("HugePages_Rsvd:") == 1 && meminfo("HugePages_Free:") == 4);
	umount("/huge");
	check("the reservation of min_size= goes with the mount", meminfo("HugePages_Rsvd:") == 0);
	write_text("/proc/sys/vm/nr_hugepages", "0");
	umount("/proc");
}

static void test_files(void)
{
	static const char data[] = "rukernel tmpfs data\n";
	char buf[64];
	check("mkdir", mkdir("/tmp", 0755) == 0 || errno == EEXIST);
	int fd = open("/tmp/a", O_RDWR | O_CREAT | O_TRUNC, 0644);
	check("open with O_CREAT", fd >= 0);
	check("write", write(fd, data, sizeof(data) - 1) == (ssize_t)sizeof(data) - 1);
	check("lseek", lseek(fd, 0, SEEK_SET) == 0);
	memset(buf, 0, sizeof(buf));
	check("read gives the data", read(fd, buf, sizeof(buf)) == (ssize_t)sizeof(data) - 1 &&
					     strcmp(buf, data) == 0);
	struct stat st;
	check("fstat", fstat(fd, &st) == 0 && st.st_size == sizeof(data) - 1 && S_ISREG(st.st_mode));
	check("close", close(fd) == 0);
	check("swapon of a file without a swap header gives EINVAL",
	      syscall(SYS_swapon, "/tmp/a", 0) == -1 && errno == EINVAL);
	check("swapoff of a file that is not a swap area gives EINVAL",
	      syscall(SYS_swapoff, "/tmp/a") == -1 && errno == EINVAL);
	check("rename", rename("/tmp/a", "/tmp/b") == 0 && access("/tmp/a", F_OK) != 0);
	mkdir("/tmp/x", 0755);
	check("renameat2 with RENAME_EXCHANGE swaps a file and a directory",
	      syscall(SYS_renameat2, AT_FDCWD, "/tmp/b", AT_FDCWD, "/tmp/x", RENAME_EXCHANGE) == 0 &&
		      stat("/tmp/b", &st) == 0 && S_ISDIR(st.st_mode) && rmdir("/tmp/b") == 0 &&
		      rename("/tmp/x", "/tmp/b") == 0);
	check("unlink", unlink("/tmp/b") == 0 && stat("/tmp/b", &st) != 0 && errno == ENOENT);
	char *map;
	fd = open("/etc/motd", O_RDONLY);
	map = fd < 0 ? MAP_FAILED : mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	check("mmap of a file", map != MAP_FAILED && memcmp(map, "rukernel initramfs\n", 19) == 0);
	if (fd >= 0)
		close(fd);
	check("chdir and getcwd", chdir("/etc") == 0 && getcwd(buf, sizeof(buf)) && strcmp(buf, "/etc") == 0);
	chdir("/");
}

static void test_devices(void)
{
	char buf[16];
	int fd = open("/dev/zero", O_RDONLY);
	memset(buf, 1, sizeof(buf));
	check("/dev/zero", fd >= 0 && read(fd, buf, sizeof(buf)) == sizeof(buf) && buf[0] == 0 && buf[15] == 0);
	close(fd);
	fd = open("/dev/null", O_WRONLY);
	check("/dev/null", fd >= 0 && write(fd, buf, sizeof(buf)) == sizeof(buf));
	close(fd);
	check("isatty of the console", isatty(1));
	/* RNDGETENTCNT, as random_ioctl in drivers/char/random.c of Linux (#385). */
	int bits = -1;
	fd = open("/dev/urandom", O_RDONLY);
	check("RNDGETENTCNT on /dev/urandom", fd >= 0 && ioctl(fd, 0x80045200, &bits) == 0 && bits > 0);
	close(fd);
	/* O_ASYNC on a pipe sends SIGIO to the owner, as kill_fasync of Linux (#385). */
	int pfd[2];
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGIO);
	sigprocmask(SIG_BLOCK, &set, &old);
	if (pipe(pfd) == 0) {
		struct timespec zero = { 0, 0 };
		check("fcntl F_SETFL O_ASYNC on a pipe",
		      fcntl(pfd[0], F_SETOWN, getpid()) == 0 && fcntl(pfd[0], F_SETFL, O_ASYNC) == 0 &&
			      (fcntl(pfd[0], F_GETFL) & O_ASYNC));
		check("a write to a pipe with O_ASYNC sends SIGIO",
		      write(pfd[1], "x", 1) == 1 && sigtimedwait(&set, NULL, &zero) == SIGIO);
		close(pfd[0]);
		close(pfd[1]);
	}
	sigprocmask(SIG_SETMASK, &old, NULL);
}

static volatile sig_atomic_t pty_hups, pty_conts, pty_ttous;

static void pty_on_ttou(int sig)
{
	(void)sig;
	pty_ttous++;
}

static void pty_on_signal(int sig)
{
	if (sig == SIGHUP)
		pty_hups++;
	else
		pty_conts++;
}

/* Opens a new pty pair: gives the master, and the path of the slave in name. */
static int pty_open_pair(char *name, size_t size)
{
	int lock = 0, n = -1;
	int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (m < 0 || ioctl(m, TIOCSPTLCK, &lock) != 0 || ioctl(m, TIOCGPTN, &n) != 0)
		return -1;
	snprintf(name, size, "/dev/pts/%d", n);
	return m;
}

/*
 * The session checks of #433, in a new session with the slave name as its controlling terminal.
 * Gives 0, or the number of the check that failed.
 */
static int pty_session_child(const char *name)
{
	pid_t sid = 0, pgrp;
	if (setsid() != getpid())
		return 1;
	/* /dev/tty gives ENXIO without a controlling terminal, as tty_open_current_tty. */
	if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO)
		return 2;
	int t = open(name, O_RDWR);
	if (t < 0 || ioctl(t, TIOCGSID, &sid) != 0 || sid != getpid())
		return 3;
	/* TIOCSPGRP checks the group, as tiocspgrp: EPERM for another session, ESRCH for no group. */
	pgrp = getpid();
	if (ioctl(t, TIOCSPGRP, &pgrp) != 0)
		return 4;
	pgrp = 1;
	if (ioctl(t, TIOCSPGRP, &pgrp) != -1 || errno != EPERM)
		return 5;
	pgrp = 0x3fffff;
	if (ioctl(t, TIOCSPGRP, &pgrp) != -1 || errno != ESRCH)
		return 6;
	/* TIOCNOTTY of a process that is not the leader drops its controlling terminal only. */
	pid_t pid = fork();
	if (pid == 0) {
		if (ioctl(t, TIOCNOTTY) != 0)
			_exit(1);
		if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO)
			_exit(2);
		pgrp = getpgrp();
		if (ioctl(t, TIOCSPGRP, &pgrp) != -1 || errno != ENOTTY)
			_exit(3);
		_exit(0);
	}
	int status = -1;
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 10 + (WIFEXITED(status) ? WEXITSTATUS(status) : 9);
	if (ioctl(t, TIOCGSID, &sid) != 0 || sid != getpid())
		return 7;
	/*
	 * TIOCSPGRP from a background group sends SIGTTOU to the group, as tty_check_change.
	 * Without SA_RESTART the call gives EINTR after the handler. A blocked SIGTTOU lets it set
	 * the group.
	 */
	pid = fork();
	if (pid == 0) {
		struct sigaction sa = { .sa_handler = pty_on_ttou };
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGTTOU);
		if (setpgid(0, 0) != 0 || sigaction(SIGTTOU, &sa, NULL) != 0)
			_exit(1);
		pgrp = getpgrp();
		if (ioctl(t, TIOCSPGRP, &pgrp) != -1 || errno != EINTR || pty_ttous != 1)
			_exit(2);
		if (sigprocmask(SIG_BLOCK, &set, NULL) != 0 || ioctl(t, TIOCSPGRP, &pgrp) != 0 || pty_ttous != 1)
			_exit(3);
		_exit(0);
	}
	status = -1;
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 30 + (WIFEXITED(status) ? WEXITSTATUS(status) : 9);
	/* The group of the leader is in the background now. Its parent is init, so the group is
	 * orphaned and gets ENOTTY. With SIGTTOU ignored, it sets the group. */
	pgrp = getpid();
	if (getppid() == 1 && (ioctl(t, TIOCSPGRP, &pgrp) != -1 || errno != ENOTTY))
		return 40;
	signal(SIGTTOU, SIG_IGN);
	if (ioctl(t, TIOCSPGRP, &pgrp) != 0)
		return 41;
	signal(SIGTTOU, SIG_DFL);
	/* A hang up of the slave sends SIGHUP and SIGCONT to the session leader. */
	signal(SIGHUP, pty_on_signal);
	signal(SIGCONT, pty_on_signal);
	if (ioctl(t, TIOCVHANGUP, 0) != 0 || pty_hups != 1 || pty_conts != 1)
		return 20;
	if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO)
		return 21;
	/* The close of the master hangs up the slave too, as pty_close. */
	char other[32];
	int m = pty_open_pair(other, sizeof(other));
	int u = m < 0 ? -1 : open(other, O_RDWR);
	if (u < 0 || ioctl(u, TIOCGSID, &sid) != 0 || sid != getpid())
		return 22;
	close(m);
	if (pty_hups != 2 || pty_conts != 2)
		return 23;
	if (read(u, &sid, 1) != 0)
		return 24;
	return 0;
}

/* The pseudo terminals: /dev/ptmx and devpts, as musl openpty does it (#403). */
static void test_pty(void)
{
	mkdir("/dev/pts", 0755);
	check("mount devpts", mount("devpts", "/dev/pts", "devpts", 0, NULL) == 0);
	int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	int n = -1, lock = 0;
	check("open /dev/ptmx", m >= 0);
	if (m < 0)
		return;
	check("TIOCSPTLCK and TIOCGPTN", ioctl(m, TIOCSPTLCK, &lock) == 0 && ioctl(m, TIOCGPTN, &n) == 0 && n >= 0);
	char c;
	check("pty master read before the slave opens gives EIO", read(m, &c, 1) == -1 && errno == EIO);
	char name[32];
	snprintf(name, sizeof(name), "/dev/pts/%d", n);
	int s = open(name, O_RDWR | O_NOCTTY);
	check("open the pty slave", s >= 0 && isatty(s));
	check("TCGETA with a bad pointer gives EFAULT", ioctl(m, TCGETA, (void *)8) == -1 && errno == EFAULT);
	struct termios t;
	check("tcgetattr on the pty master", tcgetattr(m, &t) == 0 && (t.c_lflag & ICANON));
	char buf[16] = { 0 };
	check("pty master to slave", write(m, "hi\n", 3) == 3 && read(s, buf, sizeof(buf)) == 3 && memcmp(buf, "hi\n", 3) == 0);
	check("pty echo", read(m, buf, sizeof(buf)) == 4 && memcmp(buf, "hi\r\n", 4) == 0);
	check("pty slave to master", write(s, "ok", 2) == 2 && read(m, buf, sizeof(buf)) == 2 && memcmp(buf, "ok", 2) == 0);
	/* TIOCGPTPEER opens the slave of the master, and gives EIO on another tty (#413). */
	int p = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY);
	struct stat ps, ss;
	check("TIOCGPTPEER opens the slave", p >= 0 && fstat(p, &ps) == 0 && fstat(s, &ss) == 0 && ps.st_rdev == ss.st_rdev);
	check("TIOCGPTPEER on the slave gives EIO", ioctl(s, TIOCGPTPEER, O_RDWR) == -1 && errno == EIO);
	close(p);
	/* A session leader without a controlling terminal gets the slave as its controlling terminal (#413). */
	pid_t pid = fork();
	if (pid == 0) {
		pid_t sid = 0;
		if (setsid() != getpid())
			_exit(1);
		int t = open(name, O_RDWR);
		if (t < 0 || ioctl(t, TIOCGSID, &sid) != 0 || sid != getpid())
			_exit(2);
		int tty = open("/dev/tty", O_RDWR);
		if (tty < 0 || ioctl(tty, TIOCGSID, &sid) != 0 || sid != getpid())
			_exit(3);
		/* TIOCNOTTY of a session leader sends SIGHUP to the foreground group, as Linux. */
		signal(SIGHUP, SIG_IGN);
		if (ioctl(t, TIOCNOTTY) != 0 || ioctl(t, TIOCGSID, &sid) != -1 || errno != ENOTTY)
			_exit(4);
		if (ioctl(t, TIOCSCTTY, 0) != 0 || ioctl(t, TIOCGSID, &sid) != 0 || sid != getpid())
			_exit(5);
		/* The SIGHUP at the exit of the leader does not change its exit status. */
		signal(SIGHUP, SIG_DFL);
		_exit(0);
	}
	int status = -1;
	check("open of a pty slave sets the controlling terminal", pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* The session rules of #433: ENXIO, TIOCSPGRP, TIOCNOTTY and the hang up signals. */
	pid = fork();
	if (pid == 0)
		_exit(pty_session_child(name));
	status = -1;
	if (pid > 0)
		waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		printf("pty session child: status %#x\n", status);
	check("pty session: ENXIO, TIOCSPGRP, TIOCNOTTY, SIGHUP and SIGCONT", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* devpts has its own magic, and mknod in it fails, as Linux (#433). */
	struct statfs sfs;
	check("statfs of devpts gives DEVPTS_SUPER_MAGIC", statfs("/dev/pts", &sfs) == 0 && sfs.f_type == 0x1cd1);
	check("mknod in devpts gives EPERM", mknod("/dev/pts/x", S_IFCHR | 0600, makedev(1, 3)) == -1 && errno == EPERM);
	check("mkdir in devpts gives EPERM", mkdir("/dev/pts/d", 0755) == -1 && errno == EPERM);
	check("unlink in devpts gives EPERM", unlink("/dev/pts/ptmx") == -1 && errno == EPERM);
	/* A bind mount of /dev/pts/ptmx on /dev/ptmx finds devpts for TIOCGPTPEER, as devpts_mntget (#433). */
	check("bind mount /dev/pts/ptmx on /dev/ptmx", mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL) == 0);
	char bname[32];
	int bm = pty_open_pair(bname, sizeof(bname));
	struct stat pts;
	p = bm < 0 ? -1 : ioctl(bm, TIOCGPTPEER, O_RDWR | O_NOCTTY);
	check("TIOCGPTPEER through a bind mount of ptmx", p >= 0 && fstat(p, &ps) == 0 && stat(bname, &ss) == 0 && stat("/dev/pts", &pts) == 0 && ps.st_rdev == ss.st_rdev && ps.st_dev == pts.st_dev);
	close(p);
	close(bm);
	umount("/dev/ptmx");
	/* The console: /dev/console never sets the controlling terminal, and TIOCNOTTY of a
	 * process that is not the leader drops it (#433). */
	pid = fork();
	if (pid == 0) {
		int con = open("/dev/console", O_RDWR | O_NOCTTY);
		if (con < 0 || ioctl(con, TIOCSCTTY, 0) != -1 || errno != EPERM)
			_exit(1);
		if (ioctl(con, TIOCNOTTY) != 0 || open("/dev/tty", O_RDWR) != -1 || errno != ENXIO)
			_exit(2);
		if (ioctl(con, TIOCGPGRP, &n) != -1 || errno != ENOTTY)
			_exit(3);
		if (setsid() != getpid())
			_exit(4);
		int c2 = open("/dev/console", O_RDWR);
		if (c2 < 0 || open("/dev/tty", O_RDWR) != -1 || errno != ENXIO)
			_exit(5);
		if (ioctl(c2, TIOCSCTTY, 0) != -1 || errno != EPERM)
			_exit(6);
		_exit(0);
	}
	status = -1;
	if (pid > 0)
		waitpid(pid, &status, 0);
	check("console: TIOCSCTTY, TIOCNOTTY and /dev/tty", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* TIOCVHANGUP hangs up the open files of the slave (#413). */
	int h = open(name, O_RDWR | O_NOCTTY);
	check("TIOCVHANGUP on the pty slave", h >= 0 && ioctl(h, TIOCVHANGUP, 0) == 0);
	check("read after TIOCVHANGUP gives 0", read(h, buf, 1) == 0 && read(s, buf, 1) == 0);
	check("write after TIOCVHANGUP gives EIO", write(s, "x", 1) == -1 && errno == EIO);
	close(h);
	close(s);
	check("pty master read after the slave closes gives EIO", read(m, buf, 1) == -1 && errno == EIO);
	close(m);
	check("pty slave goes away with the master", access(name, F_OK) == -1);
	umount("/dev/pts");
}

static void test_fork(void)
{
	int status = 0;
	pid_t pid = fork();
	if (pid == 0)
		_exit(42);
	check("fork", pid > 1);
	check("wait4 gives the child", waitpid(pid, &status, 0) == pid);
	check("the exit status of the child", WIFEXITED(status) && WEXITSTATUS(status) == 42);
	check("wait4 with no child", waitpid(-1, &status, 0) == -1 && errno == ECHILD);
}

static void test_exec(void)
{
	int status = 0;
	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = { "/bin/hello", "arg", NULL };
		char *envp[] = { NULL };
		execve(argv[0], argv, envp);
		_exit(99);
	}
	check("execve of a static pie", waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
						WEXITSTATUS(status) == 7);
	check("execve of a missing file", execve("/missing", NULL, NULL) == -1 && errno == ENOENT);
	/* A program that runs cannot be opened for write, as deny_write_access of Linux (#385). */
	int tfd = open("/init", O_WRONLY);
	check("open for write of the running program gives ETXTBSY", tfd == -1 && errno == ETXTBSY);
}

static void test_time(void)
{
	struct timespec a, b, d = { 0, 20 * 1000 * 1000 };
	clock_gettime(CLOCK_MONOTONIC, &a);
	check("nanosleep", nanosleep(&d, NULL) == 0);
	clock_gettime(CLOCK_MONOTONIC, &b);
	long ns = (b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec);
	check("the clock goes forward in the sleep", ns >= 10 * 1000 * 1000);
}

/* Finds a function of the vDSO by its name in the dynamic symbols, as parse_vdso.c of Linux
 * does. It does not look at the versions. */
static void *vdso_sym(const char *name)
{
	char *base = (char *)getauxval(AT_SYSINFO_EHDR);
	if (!base)
		return NULL;
	Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
	Elf64_Phdr *ph = (Elf64_Phdr *)(base + eh->e_phoff);
	Elf64_Dyn *dyn = NULL;
	long load = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type == PT_LOAD)
			load = (long)base + ph[i].p_offset - ph[i].p_vaddr;
		else if (ph[i].p_type == PT_DYNAMIC)
			dyn = (Elf64_Dyn *)(base + ph[i].p_offset);
	}
	if (!dyn)
		return NULL;
	Elf64_Sym *sym = NULL;
	char *str = NULL;
	Elf64_Word *hash = NULL;
	for (; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_SYMTAB)
			sym = (Elf64_Sym *)(load + dyn->d_un.d_ptr);
		else if (dyn->d_tag == DT_STRTAB)
			str = (char *)(load + dyn->d_un.d_ptr);
		else if (dyn->d_tag == DT_HASH)
			hash = (Elf64_Word *)(load + dyn->d_un.d_ptr);
	}
	if (!sym || !str || !hash)
		return NULL;
	for (Elf64_Word i = 0; i < hash[1]; i++)
		if (sym[i].st_shndx != SHN_UNDEF && !strcmp(str + sym[i].st_name, name))
			return (void *)(load + sym[i].st_value);
	return NULL;
}

static long timespec_ns(const struct timespec *t)
{
	return t->tv_sec * 1000000000L + t->tv_nsec;
}

#if defined(__aarch64__)
static volatile int vdso_signal_seen;

static void vdso_signal_handler(int sig)
{
	vdso_signal_seen = sig;
}

/* A signal handler without SA_RESTORER returns through __kernel_rt_sigreturn of the vDSO, as on
 * Linux. musl always gives SA_RESTORER, so the test calls rt_sigaction directly. */
static void test_vdso_sigreturn(void)
{
	struct {
		void (*handler)(int);
		unsigned long flags;
		void (*restorer)(void);
		unsigned long mask;
	} act = { vdso_signal_handler, 0, NULL, 0 }, old;
	check("rt_sigaction without SA_RESTORER", syscall(SYS_rt_sigaction, SIGUSR2, &act, &old, 8) == 0);
	vdso_signal_seen = 0;
	kill(getpid(), SIGUSR2);
	check("a handler returns through __kernel_rt_sigreturn", vdso_signal_seen == SIGUSR2);
	syscall(SYS_rt_sigaction, SIGUSR2, &old, NULL, 8);
}
#endif

static void test_vdso(void)
{
	/* arm64 has the time functions under the names __kernel_*, and no time or getcpu, as on
	 * Linux. */
#if defined(__aarch64__)
	int (*vgettime)(clockid_t, struct timespec *) = vdso_sym("__kernel_clock_gettime");
	int (*vgettimeofday)(struct timeval *, void *) = vdso_sym("__kernel_gettimeofday");
	check("the vDSO has its functions", vgettime && vgettimeofday && vdso_sym("__kernel_clock_getres") &&
					    vdso_sym("__kernel_rt_sigreturn"));
	if (!vgettime || !vgettimeofday)
		return;
	test_vdso_sigreturn();
#else
	int (*vgettime)(clockid_t, struct timespec *) = vdso_sym("__vdso_clock_gettime");
	int (*vgettimeofday)(struct timeval *, void *) = vdso_sym("__vdso_gettimeofday");
	long (*vtime)(long *) = vdso_sym("__vdso_time");
	int (*vgetcpu)(unsigned *, unsigned *) = vdso_sym("__vdso_getcpu");
	check("the vDSO has its functions", vgettime && vgettimeofday && vtime && vgetcpu &&
					    vdso_sym("__vdso_clock_getres"));
	if (!vgettime || !vgettimeofday || !vtime || !vgetcpu)
		return;
#endif
	struct timespec a, s, b;
	check("__vdso_clock_gettime", vgettime(CLOCK_MONOTONIC, &a) == 0);
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &s);
	vgettime(CLOCK_MONOTONIC, &b);
	check("the vDSO time agrees with the system call", timespec_ns(&a) <= timespec_ns(&s) &&
							   timespec_ns(&s) <= timespec_ns(&b));
	struct timespec d = { 0, 20 * 1000 * 1000 };
	nanosleep(&d, NULL);
	vgettime(CLOCK_MONOTONIC, &b);
	check("the vDSO time goes forward in a sleep", timespec_ns(&b) - timespec_ns(&s) >= 10 * 1000 * 1000);
	check("__vdso_clock_gettime of a CPU clock", vgettime(CLOCK_PROCESS_CPUTIME_ID, &a) == 0);
	check("__vdso_clock_gettime of a bad clock", vgettime(1000, &a) == -EINVAL);
	struct timeval tv;
	syscall(SYS_clock_gettime, CLOCK_REALTIME, &s);
	check("__vdso_gettimeofday", vgettimeofday(&tv, NULL) == 0 && tv.tv_sec >= s.tv_sec);
#if !defined(__aarch64__)
	long t = 0;
	check("__vdso_time", vtime(&t) == t && t >= s.tv_sec);
	unsigned cpu = 7, node = 7;
	check("__vdso_getcpu", vgetcpu(&cpu, &node) == 0 && cpu < (unsigned)sysconf(_SC_NPROCESSORS_ONLN) && node == 0);
#endif
	struct timespec m;
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &s);
	check("clock_gettime of libc", clock_gettime(CLOCK_MONOTONIC, &m) == 0 && timespec_ns(&m) >= timespec_ns(&s));
	syscall(SYS_clock_gettime, CLOCK_REALTIME, &s);
	check("CLOCK_REALTIME is the time of the real time clock", s.tv_sec > 1700000000);
}

static volatile sig_atomic_t got_sig, got_code, got_pid, chld_count, on_altstack;
static volatile void *got_addr;
static char altstack[16384];
static sigjmp_buf segv_env;

static void on_signal(int sig, siginfo_t *info, void *uc)
{
	(void)uc;
	got_sig = sig;
	got_code = info->si_code;
	got_pid = info->si_pid;
}

static void on_chld(int sig, siginfo_t *info, void *uc)
{
	(void)sig;
	(void)uc;
	chld_count++;
	got_pid = info->si_pid;
}

static void on_segv(int sig, siginfo_t *info, void *uc)
{
	(void)sig;
	(void)uc;
	got_addr = info->si_addr;
	siglongjmp(segv_env, 1);
}

static void on_alt(int sig)
{
	char here;
	(void)sig;
	on_altstack = &here >= altstack && &here < altstack + sizeof(altstack);
}

static void set_handler(int sig, void (*fn)(int, siginfo_t *, void *), int flags)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = fn;
	sa.sa_flags = SA_SIGINFO | flags;
	sigaction(sig, &sa, NULL);
}

static void test_sigwait(void)
{
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &set, &old);

	siginfo_t si;
	raise(SIGUSR1);
	check("sigwaitinfo takes a pending signal", sigwaitinfo(&set, &si) == SIGUSR1 &&
	      si.si_signo == SIGUSR1 && si.si_code == SI_TKILL);

	struct timespec zero = {0, 0};
	check("sigtimedwait with no time gives EAGAIN", sigtimedwait(&set, &si, &zero) == -1 && errno == EAGAIN);
	struct timespec short_time = {0, 30 * 1000 * 1000};
	check("sigtimedwait gives EAGAIN at the end of the time",
	      sigtimedwait(&set, &si, &short_time) == -1 && errno == EAGAIN);

	union sigval v = {.sival_int = 42};
	check("sigqueue", sigqueue(getpid(), SIGUSR2, v) == 0);
	check("sigwaitinfo gives the value of sigqueue", sigwaitinfo(&set, &si) == SIGUSR2 &&
	      si.si_code == SI_QUEUE && si.si_value.sival_int == 42 && si.si_pid == getpid());

	for (int i = 0; i < 3; i++) {
		v.sival_int = i;
		sigqueue(getpid(), SIGRTMIN, v);
	}
	int order = 1;
	for (int i = 0; i < 3; i++)
		order &= sigwaitinfo(&set, &si) == SIGRTMIN && si.si_value.sival_int == i;
	check("real time signals queue in order", order);

	pid_t pid = fork();
	if (pid == 0) {
		struct timespec d = {0, 20 * 1000 * 1000};
		nanosleep(&d, NULL);
		kill(getppid(), SIGTERM);
		_exit(0);
	}
	struct timespec long_time = {5, 0};
	int sig = sigtimedwait(&set, &si, &long_time);
	check("sigtimedwait takes a blocked fatal signal from a child", sig == SIGTERM && si.si_pid == pid);
	int status;
	waitpid(pid, &status, 0);

	siginfo_t fake;
	memset(&fake, 0, sizeof(fake));
	fake.si_code = SI_USER;
	check("rt_sigqueueinfo with SI_USER to another process gives EPERM",
	      syscall(SYS_rt_sigqueueinfo, 1000000, SIGUSR1, &fake) == -1 && (errno == EPERM || errno == ESRCH));
	fake.si_code = SI_QUEUE;
	fake.si_value.sival_int = 7;
	check("rt_tgsigqueueinfo", syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &fake) == 0 &&
	      sigwaitinfo(&set, &si) == SIGUSR1 && si.si_value.sival_int == 7);
	sigprocmask(SIG_SETMASK, &old, NULL);
}

static void test_timers(void)
{
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &set, &old);
	siginfo_t si;

	check("alarm with no alarm gives 0", alarm(10) == 0);
	check("alarm gives the rest of the last alarm", alarm(0) == 10);

	struct itimerval it = {{0, 0}, {1, 0}}, got;
	check("setitimer", setitimer(ITIMER_REAL, &it, NULL) == 0);
	check("getitimer gives the rest", getitimer(ITIMER_REAL, &got) == 0 && got.it_value.tv_sec <= 1 &&
	      (got.it_value.tv_sec > 0 || got.it_value.tv_usec > 0));
	struct itimerval bad = {{0, 0}, {0, 1000000}};
	check("setitimer with a bad time gives EINVAL", setitimer(ITIMER_REAL, &bad, NULL) == -1 && errno == EINVAL);
	check("getitimer with a bad timer gives EINVAL", getitimer(5, &got) == -1 && errno == EINVAL);
	struct itimerval tick = {{0, 10000}, {0, 10000}};
	setitimer(ITIMER_REAL, &tick, NULL);
	int n = 0;
	for (int i = 0; i < 3; i++)
		n += sigwaitinfo(&set, &si) == SIGALRM && si.si_code == SI_KERNEL;
	struct itimerval off = {{0, 0}, {0, 0}};
	setitimer(ITIMER_REAL, &off, &got);
	/* The timer can send one more SIGALRM before it stops. */
	sigset_t alrm;
	sigemptyset(&alrm);
	sigaddset(&alrm, SIGALRM);
	sigtimedwait(&alrm, NULL, &(struct timespec){0, 0});
	check("ITIMER_REAL with an interval sends SIGALRM again", n == 3 && got.it_interval.tv_usec == 10000);

	pid_t pid = fork();
	if (pid == 0) {
		sigprocmask(SIG_SETMASK, &old, NULL);
		struct itimerval once = {{0, 0}, {0, 20000}};
		setitimer(ITIMER_REAL, &once, NULL);
		for (;;)
			pause();
	}
	int status;
	check("SIGALRM of setitimer ends a child", waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGALRM);

	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_int = 77;
	timer_t t;
	check("timer_create", timer_create(CLOCK_MONOTONIC, &sev, &t) == 0);
	/* A long timer, so that it does not fire before timer_gettime on a busy host. */
	struct itimerspec ts = {{0, 0}, {10, 0}}, cur;
	check("timer_settime", timer_settime(t, 0, &ts, NULL) == 0);
	check("timer_gettime gives the rest", timer_gettime(t, &cur) == 0 && cur.it_value.tv_sec <= 10 &&
	      (cur.it_value.tv_sec > 0 || cur.it_value.tv_nsec > 0));
	ts.it_value = (struct timespec){0, 20 * 1000 * 1000};
	timer_settime(t, 0, &ts, NULL);
	check("a timer sends its signal", sigwaitinfo(&set, &si) == SIGRTMIN && si.si_code == SI_TIMER &&
	      si.si_value.sival_int == 77);
	check("timer_gettime of a timer that fired gives 0", timer_gettime(t, &cur) == 0 &&
	      cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0);

	struct itimerspec fast = {{0, 4 * 1000 * 1000}, {0, 4 * 1000 * 1000}};
	timer_settime(t, 0, &fast, NULL);
	struct timespec d = {0, 100 * 1000 * 1000};
	nanosleep(&d, NULL);
	int sig = sigwaitinfo(&set, &si);
	check("a timer counts the signals that it did not send", sig == SIGRTMIN && si.si_overrun > 0 &&
	      timer_getoverrun(t) > 0);
	struct itimerspec stop = {{0, 0}, {0, 0}};
	timer_settime(t, 0, &stop, NULL);
	check("timer_delete", timer_delete(t) == 0);
	check("timer_delete of a deleted timer gives EINVAL", syscall(SYS_timer_delete, 0) == -1 && errno == EINVAL);
	check("timer_create with a bad clock gives EINVAL", timer_create(100, &sev, &t) == -1 && errno == EINVAL);

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_THREAD_ID;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_notify_thread_id = gettid();
	check("timer_create with SIGEV_THREAD_ID", timer_create(CLOCK_REALTIME, &sev, &t) == 0);
	struct itimerspec soon = {{0, 0}, {0, 1000 * 1000}};
	timer_settime(t, 0, &soon, NULL);
	sigset_t pend;
	sigemptyset(&pend);
	for (int i = 0; i < 100 && !sigismember(&pend, SIGRTMIN); i++) {
		nanosleep(&(struct timespec){0, 2 * 1000 * 1000}, NULL);
		sigpending(&pend);
	}
	check("a timer sends its signal to the thread", sigwaitinfo(&set, &si) == SIGRTMIN && si.si_code == SI_TIMER);
	timer_delete(t);
	sigprocmask(SIG_SETMASK, &old, NULL);
}

static volatile long *stop_counter;

static void *stop_spin(void *arg)
{
	(void)arg;
	for (;;)
		__atomic_fetch_add(stop_counter, 1, __ATOMIC_RELAXED);
	return NULL;
}

static char proc_state(pid_t pid)
{
	char path[64], buf[256];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	char *p = strrchr(buf, ')');
	return p && p[1] == ' ' ? p[2] : 0;
}

static void test_stop(void)
{
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &old);
	struct timespec wait_time = {2, 0};
	siginfo_t si;
	int st;

	stop_counter = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pid_t pid = fork();
	if (pid == 0) {
		pthread_t t;
		pthread_create(&t, NULL, stop_spin, NULL);
		for (;;)
			pause();
	}
	while (*stop_counter == 0)
		sched_yield();

	check("SIGSTOP stops a child", kill(pid, SIGSTOP) == 0 && waitpid(pid, &st, WUNTRACED) == pid &&
	      WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
	check("the parent gets SIGCHLD with CLD_STOPPED", sigtimedwait(&set, &si, &wait_time) == SIGCHLD &&
	      si.si_code == CLD_STOPPED && si.si_pid == pid && si.si_status == SIGSTOP);
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	check("/proc gives the state T", proc_state(pid) == 'T');
	umount("/proc");
	long count = *stop_counter;
	usleep(50 * 1000);
	check("each thread of a stopped process stops", *stop_counter == count);
	check("waitpid takes the stop only one time", waitpid(pid, &st, WUNTRACED | WNOHANG) == 0);

	check("SIGCONT continues the child", kill(pid, SIGCONT) == 0 && waitpid(pid, &st, WCONTINUED) == pid &&
	      WIFCONTINUED(st));
	check("the parent gets SIGCHLD with CLD_CONTINUED", sigtimedwait(&set, &si, &wait_time) == SIGCHLD &&
	      si.si_code == CLD_CONTINUED && si.si_status == SIGCONT);
	/* The thread of the child runs again at once. A fixed sleep is not a good test: on a busy
	 * host, the host can stop the virtual CPU for longer than the sleep, and then the timer of
	 * the sleep is due before the thread runs one instruction. Thus the parent waits up to 2 s for
	 * a change, and tells the time when it is long. */
	struct timespec cont, now;
	clock_gettime(CLOCK_MONOTONIC, &cont);
	long cont_ms = 0;
	while (*stop_counter == count && cont_ms < 2000) {
		usleep(1000);
		clock_gettime(CLOCK_MONOTONIC, &now);
		cont_ms = (timespec_ns(&now) - timespec_ns(&cont)) / 1000000;
	}
	if (cont_ms >= 50)
		printf("init: the threads ran again after %ld ms\n", cont_ms);
	check("the threads run again", *stop_counter != count);

	memset(&si, 0xff, sizeof(si));
	check("waitid with WNOHANG and no change gives si_pid 0",
	      waitid(P_PID, pid, &si, WSTOPPED | WNOHANG) == 0 && si.si_pid == 0 && si.si_signo == 0);
	check("waitid without a type of change gives EINVAL", waitid(P_ALL, 0, &si, WNOHANG) == -1 && errno == EINVAL);

	kill(pid, SIGTSTP);
	check("waitid with WNOWAIT keeps the stop", waitid(P_PID, pid, &si, WSTOPPED | WNOWAIT) == 0 &&
	      si.si_signo == SIGCHLD && si.si_code == CLD_STOPPED && si.si_status == SIGTSTP && si.si_pid == pid);
	check("waitid takes the stop", waitid(P_PID, pid, &si, WSTOPPED) == 0 && si.si_code == CLD_STOPPED);
	si.si_pid = 1;
	check("the stop is gone after waitid", waitid(P_PID, pid, &si, WSTOPPED | WNOHANG) == 0 && si.si_pid == 0);

	check("SIGKILL ends a stopped child", kill(pid, SIGKILL) == 0 && waitid(P_PID, pid, &si, WEXITED) == 0 &&
	      si.si_code == CLD_KILLED && si.si_status == SIGKILL);
	sigtimedwait(&set, &si, &(struct timespec){0, 0});
	sigtimedwait(&set, &si, &(struct timespec){0, 0});

	/* A stop and SIGCONT do not end a sleep early, because the kernel continues it with
	 * restart_syscall. */
	pid = fork();
	if (pid == 0) {
		struct timespec a, b;
		clock_gettime(CLOCK_MONOTONIC, &a);
		int r = nanosleep(&(struct timespec){0, 300 * 1000 * 1000}, NULL);
		clock_gettime(CLOCK_MONOTONIC, &b);
		long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
		_exit(r == 0 && ms >= 290 ? 0 : 1);
	}
	usleep(50 * 1000);
	kill(pid, SIGSTOP);
	waitpid(pid, &st, WUNTRACED);
	kill(pid, SIGCONT);
	check("nanosleep continues after a stop", waitpid(pid, &st, 0) == pid && WIFEXITED(st) &&
	      WEXITSTATUS(st) == 0);

	pid = fork();
	if (pid == 0) {
		sigset_t tstp;
		sigemptyset(&tstp);
		sigaddset(&tstp, SIGTSTP);
		sigprocmask(SIG_BLOCK, &tstp, NULL);
		kill(getpid(), SIGTSTP);
		kill(getpid(), SIGCONT);
		sigprocmask(SIG_UNBLOCK, &tstp, NULL);
		_exit(0);
	}
	check("SIGCONT discards a pending stop signal", waitpid(pid, &st, WUNTRACED) == pid && WIFEXITED(st));
	sigtimedwait(&set, &si, &(struct timespec){0, 0});
	sigtimedwait(&set, &si, &(struct timespec){0, 0});
	sigprocmask(SIG_SETMASK, &old, NULL);
	munmap((void *)stop_counter, 4096);
}

static long long clock_ms(clockid_t clock)
{
	struct timespec ts;
	clock_gettime(clock, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

/* Runs user code until the CPU clock of the process shows ms milliseconds more. On a busy host,
 * QEMU gives the guest little CPU time, so the limit of wall time is large. */
static void spin_cpu(long long ms)
{
	long long end = clock_ms(CLOCK_PROCESS_CPUTIME_ID) + ms;
	long long limit = clock_ms(CLOCK_MONOTONIC) + 20000;
	while (clock_ms(CLOCK_PROCESS_CPUTIME_ID) < end && clock_ms(CLOCK_MONOTONIC) < limit)
		;
}

/* Gives the field n (from 1) of /proc/PID/stat, or -1. */
static long proc_stat_field(pid_t pid, int n)
{
	char path[64], buf[512];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = 0;
	char *p = strrchr(buf, ')');
	for (int i = 2; p && i < n; i++)
		p = strchr(p + 1, ' ');
	return p ? strtol(p + 1, NULL, 10) : -1;
}

static void test_cputime(void)
{
	spin_cpu(100);
	long long cpu = clock_ms(CLOCK_PROCESS_CPUTIME_ID);
	check("the CPU clock of the process counts user time", cpu >= 100);
	check("the CPU clock of the thread counts user time",
	      clock_ms(CLOCK_THREAD_CPUTIME_ID) > 0 && clock_ms(CLOCK_THREAD_CPUTIME_ID) <= clock_ms(CLOCK_PROCESS_CPUTIME_ID));
	usleep(100 * 1000);
	check("a sleep adds no CPU time", clock_ms(CLOCK_PROCESS_CPUTIME_ID) - cpu < 50);

	struct rusage ru;
	struct tms tms;
	check("getrusage gives the user time", getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000 >= 100);
	check("times gives the user time", times(&tms) != (clock_t)-1 && tms.tms_utime >= 10);
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	check("/proc/self/stat gives the user time", proc_stat_field(getpid(), 14) >= 10);

	sigset_t vt, oldset, pend;
	sigemptyset(&vt);
	sigaddset(&vt, SIGVTALRM);
	sigprocmask(SIG_BLOCK, &vt, &oldset);
	struct itimerval itv = {{0, 0}, {0, 50 * 1000}};
	setitimer(ITIMER_VIRTUAL, &itv, NULL);
	usleep(200 * 1000);
	sigpending(&pend);
	check("ITIMER_VIRTUAL does not count a sleep", !sigismember(&pend, SIGVTALRM));
	long long start = clock_ms(CLOCK_PROCESS_CPUTIME_ID);
	long long limit = clock_ms(CLOCK_MONOTONIC) + 20000;
	do
		sigpending(&pend);
	while (!sigismember(&pend, SIGVTALRM) && clock_ms(CLOCK_MONOTONIC) < limit);
	check("ITIMER_VIRTUAL fires after the CPU time", sigismember(&pend, SIGVTALRM) && clock_ms(CLOCK_PROCESS_CPUTIME_ID) - start >= 40);
	sigtimedwait(&vt, NULL, &(struct timespec){0, 0});
	sigprocmask(SIG_SETMASK, &oldset, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		spin_cpu(100);
		_exit(0);
	}
	int st;
	check("wait4 gives the user time of the child",
	      wait4(pid, &st, 0, &ru) == pid && ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000 >= 100);
	check("getrusage gives the user time of the children",
	      getrusage(RUSAGE_CHILDREN, &ru) == 0 && ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000 >= 100);
	check("times and /proc give the user time of the children",
	      times(&tms) != (clock_t)-1 && tms.tms_cutime >= 10 && proc_stat_field(getpid(), 16) >= 10);
	umount("/proc");
}

static void test_signals(void)
{
	volatile double x = 1.5;
	set_handler(SIGUSR1, on_signal, 0);
	raise(SIGUSR1);
	check("a handler runs and returns", got_sig == SIGUSR1 && got_code == SI_TKILL && x * 2 == 3.0);

	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &old);
	got_sig = 0;
	kill(getpid(), SIGUSR1);
	sigset_t pend;
	sigpending(&pend);
	check("a blocked signal stays pending", got_sig == 0 && sigismember(&pend, SIGUSR1));
	sigprocmask(SIG_SETMASK, &old, NULL);
	check("the signal comes when it is unblocked", got_sig == SIGUSR1 && got_code == SI_USER && got_pid == 1);

	signal(SIGUSR2, SIG_IGN);
	check("an ignored signal has no effect", kill(getpid(), SIGUSR2) == 0);
	signal(SIGUSR2, SIG_DFL);

	set_handler(SIGCHLD, on_chld, SA_RESTART);
	int status;
	pid_t pid = fork();
	if (pid == 0)
		_exit(0);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
	check("SIGCHLD comes when a child ends", chld_count >= 1 && got_pid == pid);
	signal(SIGCHLD, SIG_DFL);

	pid = fork();
	if (pid == 0) {
		for (;;)
			pause();
	}
	kill(pid, SIGTERM);
	check("SIGTERM ends a child", waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGTERM);

	sigprocmask(SIG_BLOCK, &set, &old);
	got_sig = 0;
	pid = fork();
	if (pid == 0) {
		kill(getppid(), SIGUSR1);
		_exit(0);
	}
	sigset_t none;
	sigemptyset(&none);
	int r = sigsuspend(&none);
	check("sigsuspend waits for a signal", r == -1 && errno == EINTR && got_sig == SIGUSR1);
	sigprocmask(SIG_SETMASK, &old, NULL);
	waitpid(pid, &status, 0);

	got_sig = 0;
	pid = fork();
	if (pid == 0) {
		/* The parent can start its nanosleep after the first signal, so send it again. */
		for (;;) {
			struct timespec d = {0, 20 * 1000 * 1000};
			nanosleep(&d, NULL);
			kill(getppid(), SIGUSR1);
		}
	}
	struct timespec d = {5, 0};
	r = nanosleep(&d, NULL);
	int nerr = errno;
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	check("a signal stops nanosleep", r == -1 && nerr == EINTR && got_sig == SIGUSR1);

	set_handler(SIGSEGV, on_segv, 0);
	if (sigsetjmp(segv_env, 1) == 0)
		*(volatile int *)8 = 1;
	check("SIGSEGV gives the fault address", got_addr == (void *)8);
	signal(SIGSEGV, SIG_DFL);

	stack_t ss = {.ss_sp = altstack, .ss_size = sizeof(altstack), .ss_flags = 0};
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_alt;
	sa.sa_flags = SA_ONSTACK;
	check("sigaltstack", sigaltstack(&ss, NULL) == 0);
	sigaction(SIGUSR2, &sa, NULL);
	raise(SIGUSR2);
	check("a handler runs on the alternate stack", on_altstack);
	signal(SIGUSR2, SIG_DFL);
}

static volatile sig_atomic_t got_pipe;

static void on_pipe(int sig)
{
	got_pipe = sig;
}

static void test_pipes(void)
{
	int p[2];
	char buf[64];
	check("pipe", pipe(p) == 0);
	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = { "/bin/hello", "arg", NULL };
		char *envp[] = { NULL };
		dup2(p[1], 1);
		close(p[0]);
		close(p[1]);
		execve(argv[0], argv, envp);
		_exit(99);
	}
	close(p[1]);
	size_t got = 0;
	ssize_t n;
	while ((n = read(p[0], buf + got, sizeof(buf) - 1 - got)) > 0)
		got += n;
	buf[got] = 0;
	check("a pipe takes the output of a child", strcmp(buf, "hello: static pie runs\n") == 0);
	check("read gives end of file when the writer exits", n == 0);
	int status = 0;
	waitpid(pid, &status, 0);
	close(p[0]);

	check("pipe for RWF_NOWAIT", pipe(p) == 0);
	struct iovec nv = { buf, sizeof(buf) };
	check("preadv2 with RWF_NOWAIT of an empty pipe gives EAGAIN",
	      syscall(SYS_preadv2, p[0], &nv, 1, -1L, -1L, RWF_NOWAIT) == -1 && errno == EAGAIN);
	write(p[1], "abc", 3);
	check("preadv2 with RWF_NOWAIT reads the data of a pipe",
	      syscall(SYS_preadv2, p[0], &nv, 1, -1L, -1L, RWF_NOWAIT) == 3);
	close(p[0]);
	close(p[1]);
	int nf = open("/tmp/nowait", O_RDWR | O_CREAT | O_TRUNC, 0644);
	check("preadv2 with RWF_NOWAIT of a tmpfs file gives EOPNOTSUPP",
	      nf >= 0 && syscall(SYS_preadv2, nf, &nv, 1, 0L, 0L, RWF_NOWAIT) == -1 && errno == EOPNOTSUPP);
	check("pwritev2 with RWF_NOWAIT of a tmpfs file gives EOPNOTSUPP",
	      syscall(SYS_pwritev2, nf, &nv, 1, 0L, 0L, RWF_NOWAIT) == -1 && errno == EOPNOTSUPP);
	close(nf);
	unlink("/tmp/nowait");

	check("pipe2 with O_NONBLOCK", pipe2(p, O_NONBLOCK | O_CLOEXEC) == 0);
	check("an empty pipe gives EAGAIN", read(p[0], buf, 1) == -1 && errno == EAGAIN);
	struct pollfd fds[2] = { { p[0], POLLIN, 0 }, { p[1], POLLOUT, 0 } };
	check("poll of an empty pipe", poll(fds, 2, 0) == 1 && fds[0].revents == 0 &&
					   fds[1].revents == POLLOUT);
	write(p[1], "x", 1);
	check("poll sees the data", poll(fds, 1, 0) == 1 && fds[0].revents == POLLIN);
	fd_set rd;
	FD_ZERO(&rd);
	FD_SET(p[0], &rd);
	struct timeval tv = { 0, 0 };
	check("select sees the data", select(p[0] + 1, &rd, NULL, NULL, &tv) == 1 &&
					  FD_ISSET(p[0], &rd));
	read(p[0], buf, 1);
	FD_SET(p[0], &rd);
	tv.tv_usec = 20000;
	check("select waits for the timeout", select(p[0] + 1, &rd, NULL, NULL, &tv) == 0 &&
						  !FD_ISSET(p[0], &rd));

	pid = fork();
	if (pid == 0) {
		struct timespec d = { 0, 20 * 1000 * 1000 };
		nanosleep(&d, NULL);
		write(p[1], "y", 1);
		_exit(0);
	}
	fds[0].revents = 0;
	check("poll waits for a writer", poll(fds, 1, 5000) == 1 && fds[0].revents == POLLIN);
	waitpid(pid, &status, 0);
	read(p[0], buf, 1);

	close(p[0]);
	signal(SIGPIPE, on_pipe);
	check("a write with no reader gives EPIPE", write(p[1], "z", 1) == -1 && errno == EPIPE);
	check("a write with no reader sends SIGPIPE", got_pipe == SIGPIPE);
	signal(SIGPIPE, SIG_DFL);
	close(p[1]);
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static long counter, ready;
static volatile sig_atomic_t usr1_tid;

static void *add_many(void *arg)
{
	for (int i = 0; i < 2000; i++) {
		pthread_mutex_lock(&lock);
		long v = counter;
		if (i % 100 == 0)
			sched_yield();
		counter = v + 1;
		pthread_mutex_unlock(&lock);
	}
	return arg;
}

static void *wait_ready(void *arg)
{
	pthread_mutex_lock(&lock);
	while (!ready)
		pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);
	return (void *)(long)gettid();
}

static void on_usr1(int sig)
{
	usr1_tid = gettid();
}

static void *wait_signal(void *arg)
{
	while (!usr1_tid)
		sched_yield();
	return NULL;
}

static void *spin(void *arg)
{
	for (;;)
		sched_yield();
	return NULL;
}

/* struct futex_waitv of <linux/futex.h>, for futex_waitv (449). */
struct rk_futex_waitv {
	unsigned long long val;
	unsigned long long uaddr;
	unsigned int flags;
	unsigned int reserved;
};

static int waitv_words[2];

static void *waitv_waker(void *arg)
{
	(void)arg;
	/* Wake the second word until the waiter is in its queue. */
	for (int i = 0; i < 1000; i++) {
		if (syscall(SYS_futex, &waitv_words[1], FUTEX_WAKE_PRIVATE, 1) == 1)
			return NULL;
		usleep(1000);
	}
	return NULL;
}

/* futex_waitv, as kernel/futex/syscalls.c of Linux (futex_waitv01 to 03 of LTP, #475). */
static void test_futex_waitv(void)
{
	struct rk_futex_waitv w[2];
	struct timespec to;
	pthread_t t;

	for (int i = 0; i < 2; i++) {
		w[i].val = 0;
		w[i].uaddr = (unsigned long)&waitv_words[i];
		w[i].flags = 2 | 128; /* FUTEX2_SIZE_U32 | FUTEX2_PRIVATE */
		w[i].reserved = 0;
	}
	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_nsec += 20 * 1000 * 1000;
	if (to.tv_nsec >= 1000000000) {
		to.tv_sec++;
		to.tv_nsec -= 1000000000;
	}
	check("futex_waitv with a timeout gives ETIMEDOUT",
	      syscall(449, w, 2, 0, &to, CLOCK_MONOTONIC) == -1 && errno == ETIMEDOUT);
	w[0].val = 1;
	check("futex_waitv with a different value gives EAGAIN", syscall(449, w, 2, 0, NULL, 0) == -1 && errno == EAGAIN);
	w[0].val = 0;
	w[0].flags = 128;
	check("futex_waitv without FUTEX2_SIZE_U32 gives EINVAL",
	      syscall(449, w, 2, 0, NULL, 0) == -1 && errno == EINVAL);
	w[0].flags = 2 | 128;
	check("futex_waitv of 0 futexes gives EINVAL", syscall(449, w, 0, 0, NULL, 0) == -1 && errno == EINVAL);
	check("futex_waitv with CLOCK_TAI gives EINVAL", syscall(449, w, 2, 0, &to, CLOCK_TAI) == -1 && errno == EINVAL);
	pthread_create(&t, NULL, waitv_waker, NULL);
	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += 5;
	check("futex_waitv gives the index of the woken futex", syscall(449, w, 2, 0, &to, CLOCK_MONOTONIC) == 1);
	pthread_join(t, NULL);
}

static void test_threads(void)
{
	pthread_t t[4];
	void *ret;
	for (long i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, add_many, (void *)i);
	int joined = 1;
	for (long i = 0; i < 4; i++)
		joined &= pthread_join(t[i], &ret) == 0 && ret == (void *)i;
	check("pthread_join gives the value of each thread", joined);
	check("a mutex keeps the counter right", counter == 8000);

	pthread_create(&t[0], NULL, wait_ready, NULL);
	sched_yield();
	pthread_mutex_lock(&lock);
	ready = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
	pthread_join(t[0], &ret);
	check("a condition variable wakes a thread", ret != NULL && (long)ret != getpid());

	signal(SIGUSR1, on_usr1);
	pthread_create(&t[0], NULL, wait_signal, NULL);
	pid_t tid = 0;
	pthread_kill(t[0], SIGUSR1);
	pthread_join(t[0], NULL);
	tid = usr1_tid;
	check("pthread_kill runs the handler in the thread", tid != 0 && tid != getpid());
	signal(SIGUSR1, SIG_DFL);

	int word = 1;
	struct timespec ts = { 0, 20 * 1000 * 1000 };
	check("futex wait with a different value", syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0,
							   NULL) == -1 && errno == EAGAIN);
	check("futex wait with a timeout", syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 1, &ts) ==
						   -1 && errno == ETIMEDOUT);
	check("futex wake with no waiter", syscall(SYS_futex, &word, FUTEX_WAKE_PRIVATE, 1) == 0);
	test_futex_waitv();

	pid_t pid = fork();
	if (pid == 0) {
		pthread_create(&t[0], NULL, spin, NULL);
		sched_yield();
		exit(3);
	}
	int status = 0;
	check("exit ends each thread of the process", waitpid(pid, &status, 0) == pid &&
							   WIFEXITED(status) && WEXITSTATUS(status) == 3);

	pid = fork();
	if (pid == 0) {
		char *argv[] = { "/bin/hello", "arg", NULL };
		char *envp[] = { NULL };
		int out = open("/dev/null", O_WRONLY);
		dup2(out, 1);
		pthread_create(&t[0], NULL, spin, NULL);
		sched_yield();
		execve(argv[0], argv, envp);
		_exit(99);
	}
	check("execve ends the other threads", waitpid(pid, &status, 0) == pid &&
						     WIFEXITED(status) && WEXITSTATUS(status) == 7);
}

static pthread_mutex_t robust, pi;

static void *lock_and_exit(void *arg)
{
	pthread_mutex_lock(arg);
	return NULL;
}

static void *add_many_pi(void *arg)
{
	for (int i = 0; i < 500; i++) {
		pthread_mutex_lock(&pi);
		long v = counter;
		if (i % 50 == 0)
			sched_yield();
		counter = v + 1;
		pthread_mutex_unlock(&pi);
	}
	return arg;
}

static void *trylock_pi(void *arg)
{
	return (void *)(long)pthread_mutex_trylock(&pi);
}

static void init_mutex(pthread_mutex_t *m, int robust_attr, int protocol, int shared)
{
	pthread_mutexattr_t a;
	pthread_mutexattr_init(&a);
	pthread_mutexattr_setrobust(&a, robust_attr);
	pthread_mutexattr_setprotocol(&a, protocol);
	pthread_mutexattr_setpshared(&a, shared);
	pthread_mutex_init(m, &a);
	pthread_mutexattr_destroy(&a);
}

static void test_locks(void)
{
	pthread_t t[4];
	void *ret;

	init_mutex(&robust, PTHREAD_MUTEX_ROBUST, PTHREAD_PRIO_NONE, PTHREAD_PROCESS_PRIVATE);
	pthread_create(&t[0], NULL, lock_and_exit, &robust);
	pthread_join(t[0], NULL);
	int r = pthread_mutex_lock(&robust);
	check("a robust mutex of a dead thread gives EOWNERDEAD", r == EOWNERDEAD);
	pthread_mutex_consistent(&robust);
	pthread_mutex_unlock(&robust);
	check("a robust mutex works after pthread_mutex_consistent",
	      pthread_mutex_lock(&robust) == 0 && pthread_mutex_unlock(&robust) == 0);

	pthread_mutex_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	init_mutex(shared, PTHREAD_MUTEX_ROBUST, PTHREAD_PRIO_NONE, PTHREAD_PROCESS_SHARED);
	pid_t pid = fork();
	if (pid == 0) {
		pthread_mutex_lock(shared);
		_exit(0);
	}
	waitpid(pid, NULL, 0);
	r = pthread_mutex_lock(shared);
	check("a robust mutex of a dead process gives EOWNERDEAD", r == EOWNERDEAD);
	pthread_mutex_consistent(shared);
	pthread_mutex_unlock(shared);
	munmap(shared, 4096);

	/* musl gives the kernel its robust list when it locks a shared robust mutex. */
	struct robust_list_head *head = NULL;
	size_t len = 0;
	check("get_robust_list gives the list of the thread",
	      syscall(SYS_get_robust_list, 0, &head, &len) == 0 && head != NULL &&
		      len == sizeof(*head));
	check("set_robust_list checks the length",
	      syscall(SYS_set_robust_list, head, 1) == -1 && errno == EINVAL);

	init_mutex(&pi, PTHREAD_MUTEX_STALLED, PTHREAD_PRIO_INHERIT, PTHREAD_PROCESS_PRIVATE);
	counter = 0;
	for (long i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, add_many_pi, (void *)i);
	for (long i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	check("a priority inheritance mutex keeps the counter right", counter == 2000);

	pthread_mutex_lock(&pi);
	pthread_create(&t[0], NULL, trylock_pi, NULL);
	pthread_join(t[0], &ret);
	check("trylock of a priority inheritance mutex gives EBUSY", ret == (void *)EBUSY);
	pthread_mutex_unlock(&pi);

	pthread_mutex_destroy(&pi);
	init_mutex(&pi, PTHREAD_MUTEX_ROBUST, PTHREAD_PRIO_INHERIT, PTHREAD_PROCESS_PRIVATE);
	pthread_create(&t[0], NULL, lock_and_exit, &pi);
	pthread_join(t[0], NULL);
	r = pthread_mutex_lock(&pi);
	check("a robust priority inheritance mutex of a dead thread gives EOWNERDEAD",
	      r == EOWNERDEAD);
	pthread_mutex_consistent(&pi);
	pthread_mutex_unlock(&pi);
}

#define MANY 1000

static pthread_barrier_t many_barrier;

static void *many(void *arg)
{
	pthread_barrier_wait(&many_barrier);
	return arg;
}

static void test_clone3(void)
{
	struct clone_args args;
	char big[128];

	memset(&args, 0, sizeof(args));
	args.exit_signal = SIGCHLD;
	long pid = syscall(SYS_clone3, &args, sizeof(args));
	if (pid == 0)
		_exit(5);
	int status = 0;
	check("clone3 makes a child process", pid > 0 && waitpid(pid, &status, 0) == pid &&
						     WIFEXITED(status) && WEXITSTATUS(status) == 5);
	check("clone3 with a short struct gives EINVAL",
	      syscall(SYS_clone3, &args, 32) == -1 && errno == EINVAL);
	memset(big, 0, sizeof(big));
	memcpy(big, &args, sizeof(args));
	big[sizeof(big) - 1] = 1;
	check("clone3 with an unknown field gives E2BIG",
	      syscall(SYS_clone3, big, sizeof(big)) == -1 && errno == E2BIG);
	args.stack_size = 4096;
	check("clone3 with a stack size and no stack gives EINVAL",
	      syscall(SYS_clone3, &args, sizeof(args)) == -1 && errno == EINVAL);
	args.stack_size = 0;
	args.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
	check("clone3 of a thread with an exit signal gives EINVAL",
	      syscall(SYS_clone3, &args, sizeof(args)) == -1 && errno == EINVAL);

	pthread_t t[MANY];
	pthread_attr_t a;
	int ok = 1;
	pthread_attr_init(&a);
	pthread_attr_setstacksize(&a, 16384);
	pthread_barrier_init(&many_barrier, NULL, MANY + 1);
	for (long i = 0; i < MANY; i++)
		ok &= pthread_create(&t[i], &a, many, (void *)i) == 0;
	check("1000 threads start", ok);
	pthread_barrier_wait(&many_barrier);
	for (long i = 0; i < MANY; i++) {
		void *ret;
		ok &= pthread_join(t[i], &ret) == 0 && ret == (void *)i;
	}
	check("1000 threads stop and each gives its value", ok);
	pthread_attr_destroy(&a);
}

/* A signal to the process wakes a poll of its signal file. */
static void test_signalfd_poll(void)
{
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	sigprocmask(SIG_BLOCK, &set, &old);
	int sfd = syscall(SYS_signalfd4, -1, &set, 8, 0);
	check("signalfd4", sfd >= 0);
	struct pollfd p = { .fd = sfd, .events = POLLIN };
	check("poll of a signal file with no signal gives 0", poll(&p, 1, 0) == 0);
	pid_t pid = fork();
	if (pid == 0) {
		nanosleep(&(struct timespec){0, 20 * 1000 * 1000}, NULL);
		kill(getppid(), SIGUSR2);
		_exit(0);
	}
	check("a signal wakes a poll of a signal file", poll(&p, 1, 5000) == 1 && (p.revents & POLLIN));
	char info[128];
	check("read of a signal file after poll", read(sfd, info, sizeof(info)) == sizeof(info) &&
						    *(unsigned *)info == SIGUSR2);
	waitpid(pid, NULL, 0);
	close(sfd);
	sigprocmask(SIG_SETMASK, &old, NULL);
}

static void test_pidfd(void)
{
	int fds[2];
	char c = 0;

	if (pipe(fds) != 0) {
		check("pipe for pidfd", 0);
		return;
	}
	pid_t pid = fork();
	if (pid == 0) {
		read(fds[0], &c, 1);
		_exit(7);
	}
	int pidfd = syscall(SYS_pidfd_open, pid, 0);
	check("pidfd_open", pidfd >= 0 && (fcntl(pidfd, F_GETFD) & FD_CLOEXEC));
	struct pollfd p = {.fd = pidfd, .events = POLLIN};
	check("poll of a pidfd of a running process gives 0", poll(&p, 1, 0) == 0);
	write(fds[1], &c, 1);
	check("poll of a pidfd gives POLLIN at the exit",
	      poll(&p, 1, 5000) == 1 && (p.revents & POLLIN));
	siginfo_t info;
	memset(&info, 0, sizeof(info));
	check("waitid with P_PIDFD", waitid(P_PIDFD, pidfd, &info, WEXITED) == 0 &&
					     info.si_pid == pid && info.si_status == 7);
	close(pidfd);
	check("pidfd_open of no process gives ESRCH",
	      syscall(SYS_pidfd_open, 99999, 0) == -1 && errno == ESRCH);

	struct clone_args args;
	memset(&args, 0, sizeof(args));
	args.flags = CLONE_PIDFD;
	args.pidfd = (unsigned long)&pidfd;
	args.exit_signal = SIGCHLD;
	pidfd = -1;
	pid = syscall(SYS_clone3, &args, sizeof(args));
	if (pid == 0) {
		read(fds[0], &c, 1);
		_exit(0);
	}
	int status = 0;
	check("clone3 with CLONE_PIDFD", pid > 0 && pidfd >= 0);
	check("pidfd_send_signal",
	      syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) == 0 &&
		      waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
		      WTERMSIG(status) == SIGKILL);
	close(pidfd);
	close(fds[0]);
	close(fds[1]);

	int dup1 = dup(1);
	int null = open("/dev/null", O_RDONLY);
	long other = syscall(SYS_kcmp, getpid(), getpid(), 0, 1, null);
	check("kcmp of two descriptors of one file gives 0",
	      syscall(SYS_kcmp, getpid(), getpid(), 0, 1, dup1) == 0);
	check("kcmp of two files gives 1 or 2", other == 1 || other == 2);
	check("kcmp of a bad descriptor gives EBADF",
	      syscall(SYS_kcmp, getpid(), getpid(), 0, 1, 999) == -1 && errno == EBADF);
	close(dup1);
	close(null);

	unsigned int header[2] = {0x20080522, 0};
	unsigned int data[6];
	memset(data, 0, sizeof(data));
	check("capget gives CAP_SYS_ADMIN",
	      syscall(SYS_capget, header, data) == 0 && (data[0] & (1u << 21)) &&
		      (data[1] & (1u << 21)) && data[2] == 0);
	header[0] = 1;
	check("capget of an unknown version gives EINVAL and version 3",
	      syscall(SYS_capget, header, data) == -1 && errno == EINVAL &&
		      header[0] == 0x20080522);
}

static volatile int sigsys_nr;

static void on_sigsys(int sig, siginfo_t *info, void *uc)
{
	(void)sig;
	(void)uc;
	if (info->si_code == SYS_SECCOMP && info->si_arch == AUDIT_ARCH_NATIVE)
		sigsys_nr = info->si_syscall;
}

/* Installs a filter that gives `action` for the system call `nr` and allows the others. */
static int seccomp_filter(int nr, unsigned int action)
{
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, action),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {.len = 4, .filter = insns};
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

/* Runs `fn` in a child, and gives the status of the child. */
static int seccomp_child(int (*fn)(void))
{
	int status = 0;
	pid_t pid = fork();
	if (pid == 0)
		_exit(fn());
	waitpid(pid, &status, 0);
	return status;
}

static int seccomp_errno_child(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		return 1;
	if (seccomp_filter(SYS_getppid, SECCOMP_RET_ERRNO | E2BIG) != 0)
		return 2;
	if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2)
		return 3;
	if (syscall(SYS_getppid) != -1 || errno != E2BIG)
		return 4;
	/* The filters stay in a child of fork. */
	int status = 0;
	pid_t pid = fork();
	if (pid == 0)
		_exit(syscall(SYS_getppid) == -1 && errno == E2BIG ? 0 : 1);
	if (waitpid(pid, &status, 0) != pid || status != 0)
		return 5;
	/* The filter mode cannot change to the strict mode. */
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != -1 || errno != EINVAL)
		return 6;
	return getpid() > 0 ? 0 : 7;
}

static int seccomp_trap_child(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_sigsys;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSYS, &sa, NULL);
	if (seccomp_filter(SYS_getppid, SECCOMP_RET_TRAP) != 0)
		return 1;
	syscall(SYS_getppid);
	return sigsys_nr == SYS_getppid ? 0 : 2;
}

static int seccomp_kill_child(void)
{
	seccomp_filter(SYS_getppid, SECCOMP_RET_KILL_PROCESS);
	syscall(SYS_getppid);
	return 0;
}

static int seccomp_strict_child(void)
{
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0)
		return 1;
	write(1, "", 0);
	syscall(SYS_getppid);
	return 0;
}

static void test_seccomp(void)
{
	int status = seccomp_child(seccomp_errno_child);
	check("seccomp SECCOMP_RET_ERRNO", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	status = seccomp_child(seccomp_trap_child);
	check("seccomp SECCOMP_RET_TRAP", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	status = seccomp_child(seccomp_kill_child);
	check("seccomp SECCOMP_RET_KILL_PROCESS", WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
	status = seccomp_child(seccomp_strict_child);
	check("seccomp strict mode", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	unsigned int action = SECCOMP_RET_LOG;
	check("SECCOMP_GET_ACTION_AVAIL",
	      syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0);
	action = 0x12345678;
	check("SECCOMP_GET_ACTION_AVAIL of an unknown action",
	      syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == -1 && errno == EOPNOTSUPP);
}

/* Checks the shared memory of System V. */
/* The semaphores of System V. */
static void test_sem(void)
{
	unsigned short vals[2] = {2, 0};
	struct sembuf op = {.sem_num = 0, .sem_op = -1, .sem_flg = 0};
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 20000000};
	struct semid_ds ds;
	int id = semget(IPC_PRIVATE, 2, IPC_CREAT | 0600);

	check("semget", id >= 0);
	check("SETALL and GETALL", semctl(id, 0, SETALL, vals) == 0 && semctl(id, 0, GETVAL) == 2 &&
	      semctl(id, 1, GETVAL) == 0);
	check("IPC_STAT gives the number of semaphores",
	      semctl(id, 0, IPC_STAT, &ds) == 0 && ds.sem_nsems == 2 && ds.sem_otime == 0);
	check("semop takes one", semop(id, &op, 1) == 0 && semctl(id, 0, GETVAL) == 1 &&
	      semctl(id, 0, GETPID) == getpid());
	struct sembuf two[2] = {{0, -1, 0}, {1, -1, IPC_NOWAIT}};
	errno = 0;
	check("semop does all the operations or none of them",
	      semop(id, two, 2) == -1 && errno == EAGAIN && semctl(id, 0, GETVAL) == 1);
	struct sembuf zero = {.sem_num = 0, .sem_op = 0, .sem_flg = 0};
	errno = 0;
	check("semtimedop gives EAGAIN at the end of the timeout",
	      semtimedop(id, &zero, 1, &ts) == -1 && errno == EAGAIN);
	pid_t child = fork();
	if (child == 0) {
		struct sembuf up = {.sem_num = 1, .sem_op = 3, .sem_flg = SEM_UNDO};
		semop(id, &up, 1);
		struct sembuf wait = {.sem_num = 0, .sem_op = 0, .sem_flg = 0};
		_exit(semop(id, &wait, 1) == 0 ? 0 : 1);
	}
	struct sembuf take = {.sem_num = 1, .sem_op = -1, .sem_flg = 0};
	check("semop waits for another process", semop(id, &take, 1) == 0);
	while (semctl(id, 0, GETZCNT) != 1)
		sched_yield();
	check("semop that waits for 0 counts in GETZCNT", semctl(id, 0, GETZCNT) == 1);
	int status = 0;
	check("semop wakes the process that waits for 0",
	      semop(id, &op, 1) == 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 0);
	check("the exit of a process undoes its SEM_UNDO changes", semctl(id, 1, GETVAL) == 0);
	check("semctl IPC_RMID", semctl(id, 0, IPC_RMID) == 0);
	errno = 0;
	check("semop on a removed set gives EINVAL", semop(id, &op, 1) == -1 && errno == EINVAL);
}

static void test_msg(void)
{
	struct {
		long mtype;
		char text[16];
	} m;
	struct msqid_ds ds;
	int id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);

	check("msgget", id >= 0);
	m.mtype = 2;
	strcpy(m.text, "two");
	check("msgsnd type 2", msgsnd(id, &m, 4, 0) == 0);
	m.mtype = 1;
	strcpy(m.text, "one");
	check("msgsnd type 1", msgsnd(id, &m, 4, 0) == 0);
	check("IPC_STAT counts the messages and the bytes",
	      msgctl(id, IPC_STAT, &ds) == 0 && ds.msg_qnum == 2 && ds.msg_cbytes == 8 &&
		      ds.msg_lspid == getpid());
	memset(&m, 0, sizeof(m));
	check("msgrcv selects the type", msgrcv(id, &m, sizeof(m.text), 1, 0) == 4 &&
						 m.mtype == 1 && strcmp(m.text, "one") == 0);
	errno = 0;
	check("msgrcv MSG_NOERROR is off: E2BIG", msgrcv(id, &m, 2, 0, 0) == -1 && errno == E2BIG);
	check("msgrcv MSG_NOERROR cuts the message",
	      msgrcv(id, &m, 2, 0, MSG_NOERROR) == 2 && m.mtype == 2);
	errno = 0;
	check("msgrcv IPC_NOWAIT on an empty queue gives ENOMSG",
	      msgrcv(id, &m, sizeof(m.text), 0, IPC_NOWAIT) == -1 && errno == ENOMSG);
	pid_t child = fork();
	if (child == 0) {
		m.mtype = 7;
		_exit(msgsnd(id, &m, 1, 0) == 0 ? 0 : 1);
	}
	int status = 0;
	check("msgrcv waits for a message from another process",
	      msgrcv(id, &m, sizeof(m.text), 7, 0) == 1 && waitpid(child, &status, 0) == child &&
		      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("msgctl IPC_RMID", msgctl(id, IPC_RMID, NULL) == 0);
	errno = 0;
	check("msgsnd on a removed queue gives EINVAL", msgsnd(id, &m, 1, 0) == -1 && errno == EINVAL);
	char buf[64] = {0};
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	int fd = open("/proc/sys/kernel/msgmnb", O_RDONLY);
	check("/proc/sys/kernel/msgmnb", fd >= 0 && read(fd, buf, sizeof(buf)) > 0 &&
						 strcmp(buf, "16384\n") == 0);
	close(fd);
	fd = open("/proc/sysvipc/msg", O_RDONLY);
	check("/proc/sysvipc/msg", fd >= 0 && read(fd, buf, sizeof(buf)) > 0 &&
					   strncmp(buf, "       key", 10) == 0);
	close(fd);
	umount("/proc");
}

static volatile int mq_signals;

static void mq_signal(int sig, siginfo_t *info, void *ctx)
{
	(void)ctx;
	if (sig == SIGUSR1 && info->si_code == SI_MESGQ && info->si_value.sival_int == 42)
		mq_signals++;
}

static volatile int mq_thread_calls;

static void mq_thread(union sigval v)
{
	if (v.sival_int == 43)
		mq_thread_calls++;
}

static void test_mqueue(void)
{
	struct mq_attr attr = {.mq_maxmsg = 2, .mq_msgsize = 16};
	char buf[16];
	unsigned prio = 0;

	mq_unlink("/rk-test");
	mqd_t q = mq_open("/rk-test", O_RDWR | O_CREAT | O_EXCL, 0600, &attr);
	check("mq_open", q >= 0);
	errno = 0;
	check("mq_open O_EXCL gives EEXIST",
	      mq_open("/rk-test", O_RDWR | O_CREAT | O_EXCL, 0600, &attr) == -1 && errno == EEXIST);
	check("mq_send low", mq_send(q, "low", 3, 1) == 0);
	check("mq_send high", mq_send(q, "high", 4, 9) == 0);
	struct pollfd p = {.fd = q, .events = POLLIN | POLLOUT};
	check("poll on a full queue", poll(&p, 1, 0) == 1 && p.revents == POLLIN);
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += 20000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	errno = 0;
	check("mq_timedsend on a full queue gives ETIMEDOUT",
	      mq_timedsend(q, "x", 1, 0, &ts) == -1 && errno == ETIMEDOUT);
	errno = 0;
	check("mq_receive with a small buffer gives EMSGSIZE",
	      mq_receive(q, buf, 8, NULL) == -1 && errno == EMSGSIZE);
	check("mq_receive gives the highest priority first",
	      mq_receive(q, buf, sizeof(buf), &prio) == 4 && prio == 9 && memcmp(buf, "high", 4) == 0);
	check("mq_receive low", mq_receive(q, buf, sizeof(buf), &prio) == 3 && prio == 1);
	struct mq_attr got;
	struct mq_attr nb = {.mq_flags = O_NONBLOCK};
	check("mq_setattr O_NONBLOCK", mq_setattr(q, &nb, &got) == 0 && got.mq_flags == 0 &&
					       got.mq_maxmsg == 2 && got.mq_msgsize == 16);
	errno = 0;
	check("mq_receive O_NONBLOCK gives EAGAIN",
	      mq_receive(q, buf, sizeof(buf), NULL) == -1 && errno == EAGAIN);

	struct sigaction sa = {.sa_sigaction = mq_signal, .sa_flags = SA_SIGINFO};
	struct sigaction old;
	sigaction(SIGUSR1, &sa, &old);
	struct sigevent ev = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1};
	ev.sigev_value.sival_int = 42;
	check("mq_notify SIGEV_SIGNAL", mq_notify(q, &ev) == 0);
	errno = 0;
	check("a second mq_notify gives EBUSY", mq_notify(q, &ev) == -1 && errno == EBUSY);
	char status[80] = {0};
	check("a read of the queue gives the status",
	      read(q, status, sizeof(status) - 1) == 60 && strstr(status, "SIGNO:10") != NULL);
	mq_send(q, "s", 1, 0);
	check("mq_notify sends the signal", mq_signals == 1);
	mq_receive(q, buf, sizeof(buf), NULL);
	mq_send(q, "s", 1, 0);
	check("the notification is for one message only", mq_signals == 1);
	mq_receive(q, buf, sizeof(buf), NULL);
	sigaction(SIGUSR1, &old, NULL);

	struct sigevent tev = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = mq_thread};
	tev.sigev_value.sival_int = 43;
	check("mq_notify SIGEV_THREAD", mq_notify(q, &tev) == 0);
	mq_send(q, "t", 1, 0);
	/* musl starts a new thread for the call, so wait by time and not by a count of yields. */
	for (int i = 0; i < 2000 && mq_thread_calls == 0; i++)
		usleep(1000);
	check("mq_notify SIGEV_THREAD calls the function", mq_thread_calls == 1);
	mq_close(q);
	check("mq_unlink", mq_unlink("/rk-test") == 0);
	errno = 0;
	check("mq_unlink of a removed queue gives ENOENT", mq_unlink("/rk-test") == -1 && errno == ENOENT);
	mkdir("/dev/mqueue", 0755);
	struct stat st;
	check("mount mqueue", mount("mqueue", "/dev/mqueue", "mqueue", 0, NULL) == 0 &&
				      stat("/dev/mqueue", &st) == 0 && (st.st_mode & 07777) == 01777);
	q = mq_open("/rk-vis", O_RDWR | O_CREAT, 0600, NULL);
	check("a queue is a file of the mount",
	      stat("/dev/mqueue/rk-vis", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 80);
	mq_close(q);
	mq_unlink("/rk-vis");
	umount("/dev/mqueue");
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	int fd = open("/proc/sys/fs/mqueue/msg_max", O_RDONLY);
	memset(buf, 0, sizeof(buf));
	check("/proc/sys/fs/mqueue/msg_max",
	      fd >= 0 && read(fd, buf, sizeof(buf)) > 0 && strcmp(buf, "10\n") == 0);
	close(fd);
	umount("/proc");
}

static void test_shm(void)
{
	struct shmid_ds ds;
	int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
	char *a = id >= 0 ? shmat(id, NULL, 0) : (char *)-1;
	char *b = id >= 0 ? shmat(id, NULL, SHM_RDONLY) : (char *)-1;
	pid_t pid;
	int status = -1;

	check("shmget and shmat", id >= 0 && a != (char *)-1 && b != (char *)-1 && a != b);
	if (a == (char *)-1 || b == (char *)-1)
		return;
	strcpy(a + 4100, "shared");
	check("two attaches of a segment share the pages", !strcmp(b + 4100, "shared"));
	check("IPC_STAT gives the size and the attaches",
	      shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_segsz == 8192 && ds.shm_nattch == 2 &&
	      ds.shm_perm.mode == 0600);
	pid = fork();
	if (pid == 0) {
		strcpy(a, "child");
		_exit(0);
	}
	waitpid(pid, &status, 0);
	check("a child writes to a segment of its parent", status == 0 && !strcmp(b, "child"));
	errno = 0;
	check("shmdt of an address in the middle gives EINVAL", shmdt(a + 4096) == -1 && errno == EINVAL);
	check("shmdt", shmdt(b) == 0 && shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
	check("IPC_RMID keeps an attached segment", shmctl(id, IPC_RMID, NULL) == 0 && !strcmp(a, "child"));
	check("shmdt of the last attach", shmdt(a) == 0);
	errno = 0;
	check("a removed segment is gone", shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
	id = shmget(0x726b, 4096, IPC_CREAT | 0600);
	errno = 0;
	check("IPC_EXCL with a used key gives EEXIST",
	      id >= 0 && shmget(0x726b, 4096, IPC_CREAT | IPC_EXCL) == -1 && errno == EEXIST);
	check("shmget finds a key", shmget(0x726b, 0, 0) == id && shmctl(id, IPC_RMID, NULL) == 0);
	errno = 0;
	check("shmget of a missing key gives ENOENT", shmget(0x726b, 4096, 0) == -1 && errno == ENOENT);
}

static void test_memfd(void)
{
	char buf[64] = {0};
	char path[32];
	int fd = (int)syscall(SYS_memfd_create, "rk", MFD_CLOEXEC);

	check("memfd_create", fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
	check("a memfd keeps its data", write(fd, "data", 4) == 4 && lseek(fd, 0, SEEK_SET) == 0 &&
	      read(fd, buf, 4) == 4 && !strcmp(buf, "data"));
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	memset(buf, 0, sizeof(buf));
	mount("proc", "/proc", "proc", 0, NULL);
	check("/proc/self/fd shows the name of a memfd",
	      readlink(path, buf, sizeof(buf) - 1) > 0 && !strncmp(buf, "/memfd:rk", 9));
	int again = open(path, O_RDONLY);
	memset(buf, 0, sizeof(buf));
	check("an open through /proc/self/fd gives the memfd",
	      again >= 0 && read(again, buf, 4) == 4 && !strcmp(buf, "data"));
	close(again);
	int p[2];
	check("pipe for /proc/self/fd", pipe(p) == 0);
	snprintf(path, sizeof(path), "/proc/self/fd/%d", p[0]);
	again = open(path, O_RDONLY | O_NONBLOCK);
	memset(buf, 0, sizeof(buf));
	check("an open through /proc/self/fd gives the same pipe",
	      again >= 0 && write(p[1], "pipe", 4) == 4 && read(again, buf, 4) == 4 && !strcmp(buf, "pipe"));
	close(again);
	close(p[0]);
	close(p[1]);
	umount("/proc");
	close(fd);
	errno = 0;
	check("memfd_create with an unknown flag gives EINVAL",
	      syscall(SYS_memfd_create, "rk", 0x100) == -1 && errno == EINVAL);
	errno = 0;
	check("unshare of the PID name space gives EINVAL", unshare(CLONE_NEWPID) == -1 && errno == EINVAL);
	check("unshare of the file table", unshare(CLONE_FILES | CLONE_FS) == 0);
}

/* Sends the descriptor fd on the socket s with SCM_RIGHTS. */
static int send_fd(int s, int fd)
{
	char data = 'f';
	struct iovec iov = {.iov_base = &data, .iov_len = 1};
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.buf, .msg_controllen = sizeof(u.buf)};
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &fd, sizeof(int));
	return (int)sendmsg(s, &msg, 0);
}

/* Receives a descriptor from the socket s. Gives -1 if the message has none. */
static int recv_fd(int s)
{
	char data;
	int fd = -1;
	struct iovec iov = {.iov_base = &data, .iov_len = 1};
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.buf, .msg_controllen = sizeof(u.buf)};
	struct cmsghdr *c;

	if (recvmsg(s, &msg, MSG_CMSG_CLOEXEC) != 1)
		return -1;
	c = CMSG_FIRSTHDR(&msg);
	if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
		memcpy(&fd, CMSG_DATA(c), sizeof(int));
	return fd;
}

static void test_unix(void)
{
	int sv[2], fds[2], srv, cli, con, fd;
	char buf[32] = {0};
	struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = "/tmp-rk.sock"};
	struct sockaddr_un got;
	socklen_t len = sizeof(got);
	struct ucred cred;
	struct stat st;

	check("socketpair of SOCK_STREAM", socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
	check("a stream socket moves bytes", write(sv[0], "hello", 5) == 5 && read(sv[1], buf, sizeof(buf)) == 5 &&
	      !strcmp(buf, "hello"));
	len = sizeof(cred);
	check("SO_PEERCRED gives the pid", getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 &&
	      len == sizeof(cred) && cred.pid == getpid());
	check("fstat of a socket gives S_IFSOCK", fstat(sv[0], &st) == 0 && S_ISSOCK(st.st_mode));
	check("pipe for SCM_RIGHTS", pipe(fds) == 0);
	check("sendmsg with SCM_RIGHTS", send_fd(sv[0], fds[1]) == 1);
	close(fds[1]);
	fd = recv_fd(sv[1]);
	check("recvmsg gives the descriptor", fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
	check("the descriptor works", write(fd, "x", 1) == 1 && read(fds[0], buf, 1) == 1 && buf[0] == 'x');
	close(fd);
	close(fds[0]);
	close(sv[1]);
	errno = 0;
	check("a write to a closed peer gives EPIPE", send(sv[0], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
	close(sv[0]);

	check("socketpair of SOCK_SEQPACKET", socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	memset(buf, 0, sizeof(buf));
	check("seqpacket keeps the boundaries", write(sv[0], "one", 3) == 3 && write(sv[0], "two", 3) == 3 &&
	      recv(sv[1], buf, 2, 0) == 2 && recv(sv[1], buf, sizeof(buf), 0) == 3 && !strcmp(buf, "two"));
	close(sv[0]);
	close(sv[1]);

	srv = socket(AF_UNIX, SOCK_STREAM, 0);
	check("bind to a path", srv >= 0 && bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	check("bind makes a socket file", stat(addr.sun_path, &st) == 0 && S_ISSOCK(st.st_mode));
	check("listen", listen(srv, 4) == 0);
	cli = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	check("connect to the path", connect(cli, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	len = sizeof(got);
	con = accept4(srv, (struct sockaddr *)&got, &len, SOCK_CLOEXEC);
	check("accept4", con >= 0 && len == sizeof(sa_family_t));
	len = sizeof(got);
	check("getpeername gives the path", getpeername(cli, (struct sockaddr *)&got, &len) == 0 &&
	      !strcmp(got.sun_path, addr.sun_path));
	memset(buf, 0, sizeof(buf));
	check("data on the accepted socket", send(cli, "ping", 4, 0) == 4 && recv(con, buf, sizeof(buf), 0) == 4 &&
	      !strcmp(buf, "ping"));
	errno = 0;
	check("an empty nonblocking socket gives EAGAIN", recv(cli, buf, sizeof(buf), 0) == -1 && errno == EAGAIN);
	errno = 0;
	cli = socket(AF_UNIX, SOCK_STREAM, 0);
	check("bind to a used path gives EADDRINUSE",
	      bind(cli, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno == EADDRINUSE);
	close(cli);
	close(con);
	close(srv);
	unlink(addr.sun_path);
	errno = 0;
	/* Linux removed DECnet in 6.1, so the family is unknown. */
	cli = socket(AF_DECnet, SOCK_STREAM, 0);
	check("an unknown family gives EAFNOSUPPORT", cli == -1 && errno == EAFNOSUPPORT);
}

static void test_mount(void)
{
	struct statfs st;
	char buf[8] = {0};
	int fd;

	mkdir("/mnt", 0755);
	mkdir("/mnt2", 0755);
	check("mount tmpfs", mount("none", "/mnt", "tmpfs", 0, "mode=700") == 0);
	check("statfs gives TMPFS_MAGIC", statfs("/mnt", &st) == 0 && st.f_type == 0x01021994);
	fd = open("/mnt/f", O_CREAT | O_RDWR, 0644);
	check("a file in the new tmpfs", fd >= 0 && write(fd, "data", 4) == 4);
	close(fd);
	check("mount --bind", mount("/mnt", "/mnt2", NULL, MS_BIND, NULL) == 0);
	fd = open("/mnt2/f", O_RDONLY);
	check("the bind mount shows the file", fd >= 0 && read(fd, buf, 4) == 4 && !strcmp(buf, "data"));
	close(fd);
	check("mount --make-private", mount(NULL, "/mnt", NULL, MS_PRIVATE, NULL) == 0);
	check("mount -o remount,ro", mount(NULL, "/mnt", NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0);
	errno = 0;
	check("an unknown type gives ENODEV", mount("none", "/mnt", "nofs", 0, NULL) == -1 && errno == ENODEV);
	check("umount the bind mount", umount("/mnt2") == 0);
	check("umount2 with MNT_DETACH", umount2("/mnt", MNT_DETACH) == 0);
	errno = 0;
	check("umount of a directory gives EINVAL", umount("/mnt") == -1 && errno == EINVAL);
	check("the file is gone with the mount", access("/mnt/f", F_OK) == -1 && errno == ENOENT);
	rmdir("/mnt");
	rmdir("/mnt2");
}

/*
 * unshare(CLONE_NEWNS) gives the process a copy of the mounts. A mount under a shared mount shows
 * in the old name space too, and a mount under a private mount does not.
 */
static void test_mount_ns(void)
{
	int status = -1;
	pid_t pid;

	mkdir("/mnt", 0755);
	check("mount tmpfs for the name spaces", mount("none", "/mnt", "tmpfs", 0, NULL) == 0);
	mkdir("/mnt/a", 0755);
	mkdir("/mnt/b", 0755);
	check("mount --make-shared", mount(NULL, "/mnt", NULL, MS_SHARED, NULL) == 0);
	pid = fork();
	if (pid == 0) {
		int ok = unshare(CLONE_NEWNS) == 0;
		ok = ok && mount("none", "/mnt/a", "tmpfs", 0, NULL) == 0;
		ok = ok && mount(NULL, "/mnt", NULL, MS_PRIVATE, NULL) == 0;
		ok = ok && mount("none", "/mnt/b", "tmpfs", 0, NULL) == 0;
		ok = ok && close(open("/mnt/a/g", O_CREAT | O_RDWR, 0644)) == 0;
		ok = ok && close(open("/mnt/b/f", O_CREAT | O_RDWR, 0644)) == 0;
		_exit(ok ? 0 : 1);
	}
	waitpid(pid, &status, 0);
	check("unshare(CLONE_NEWNS) and mounts in the new name space",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("a mount under a shared mount shows in the old name space", access("/mnt/a/g", F_OK) == 0);
	errno = 0;
	check("a mount under a private mount stays in the new name space",
	      access("/mnt/b/f", F_OK) == -1 && errno == ENOENT);
	check("umount the copy of the mount", umount("/mnt/a") == 0);
	check("umount the tmpfs of the name spaces", umount("/mnt") == 0);
	rmdir("/mnt");
}

/* A child in a new UTS namespace has its own host name, and a child in a new IPC namespace does
 * not see the shared memory of the parent. setns with the file of the namespace of the parent
 * puts each one back, as kernel/utsname.c and ipc/namespace.c of Linux. setns02 of LTP does the
 * same (#481). */
static void test_uts_ipc_ns(void)
{
	struct utsname u;
	char old[sizeof(u.nodename)];
	int status = -1, shmid, uts_fd, ipc_fd;
	pid_t pid;

	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	uname(&u);
	strcpy(old, u.nodename);
	uts_fd = open("/proc/self/ns/uts", O_RDONLY);
	ipc_fd = open("/proc/self/ns/ipc", O_RDONLY);
	shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	check("open the files of the UTS and IPC namespaces", uts_fd >= 0 && ipc_fd >= 0 && shmid >= 0);
	pid = fork();
	if (pid == 0) {
		struct utsname c;
		int ok = unshare(CLONE_NEWUTS) == 0;
		ok = ok && sethostname("uts-child", 9) == 0 && uname(&c) == 0;
		ok = ok && strcmp(c.nodename, "uts-child") == 0;
		ok = ok && setns(uts_fd, CLONE_NEWUTS) == 0 && uname(&c) == 0;
		ok = ok && strcmp(c.nodename, old) == 0;
		_exit(ok ? 0 : 1);
	}
	waitpid(pid, &status, 0);
	check("unshare(CLONE_NEWUTS) gives a host name of its own and setns goes back",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	uname(&u);
	check("the host name of the parent does not change", strcmp(u.nodename, old) == 0);
	pid = fork();
	if (pid == 0) {
		int ok = unshare(CLONE_NEWIPC) == 0;
		void *a;
		errno = 0;
		ok = ok && shmat(shmid, NULL, 0) == (void *)-1 && errno == EINVAL;
		ok = ok && shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600) >= 0;
		ok = ok && setns(ipc_fd, 0) == 0;
		a = shmat(shmid, NULL, 0);
		ok = ok && a != (void *)-1 && shmdt(a) == 0;
		_exit(ok ? 0 : 1);
	}
	waitpid(pid, &status, 0);
	check("unshare(CLONE_NEWIPC) hides the shared memory and setns shows it again",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	errno = 0;
	check("clone with CLONE_NEWIPC and CLONE_SYSVSEM gives EINVAL",
	      syscall(SYS_clone, CLONE_NEWIPC | CLONE_SYSVSEM | SIGCHLD, 0, 0, 0, 0) == -1 &&
		      errno == EINVAL);
	shmctl(shmid, IPC_RMID, NULL);
	close(uts_fd);
	close(ipc_fd);
	umount("/proc");
}

/* A walk follows 40 symbolic links and gives ELOOP at the next one, as Linux. */
static void test_symlink_chain(void)
{
	char name[32], target[32];
	int fd, i, ok = 1;

	mkdir("/tmp", 0755);
	fd = open("/tmp/chain", O_CREAT | O_RDWR, 0644);
	close(fd);
	for (i = 0; i <= 40; i++) {
		snprintf(name, sizeof(name), "/tmp/l%d", i);
		if (i == 0)
			snprintf(target, sizeof(target), "chain");
		else
			snprintf(target, sizeof(target), "l%d", i - 1);
		ok &= symlink(target, name) == 0;
	}
	check("symlink of a chain of 41 links", ok);
	fd = open("/tmp/l39", O_RDONLY);
	check("a walk follows 40 links", fd >= 0);
	close(fd);
	errno = 0;
	check("a walk gives ELOOP at the 41st link", open("/tmp/l40", O_RDONLY) == -1 && errno == ELOOP);
	errno = 0;
	check("a directory component gives ELOOP at the 41st link",
	      open("/tmp/l40/x", O_RDONLY) == -1 && errno == ELOOP);
	for (i = 0; i <= 40; i++) {
		snprintf(name, sizeof(name), "/tmp/l%d", i);
		unlink(name);
	}
	unlink("/tmp/chain");
}

/* sendfile, splice and copy_file_range copy data in the kernel. fadvise64 checks its advice. */
static void test_splice(void)
{
	char buf[16] = {0};
	int in, out, null, p[2];
	long long off = 2;

	mkdir("/tmp", 0755);
	in = open("/tmp/sp_in", O_CREAT | O_RDWR | O_TRUNC, 0644);
	out = open("/tmp/sp_out", O_CREAT | O_RDWR | O_TRUNC, 0644);
	check("write the source of the copies", write(in, "abcdefgh", 8) == 8);
	check("sendfile at an offset copies 4 bytes",
	      syscall(SYS_sendfile, out, in, &off, 4) == 4 && off == 6);
	check("sendfile at an offset keeps the position", lseek(in, 0, SEEK_CUR) == 8);
	check("sendfile writes at the position of the output",
	      pread(out, buf, sizeof(buf), 0) == 4 && memcmp(buf, "cdef", 4) == 0);
	check("pipe for splice", pipe(p) == 0);
	off = 0;
	check("splice from a file to a pipe",
	      syscall(SYS_splice, in, &off, p[1], NULL, 8, 0) == 8 && off == 8);
	errno = 0;
	check("splice with an offset for a pipe gives ESPIPE",
	      syscall(SYS_splice, p[0], &off, out, NULL, 8, 0) == -1 && errno == ESPIPE);
	off = 0;
	check("splice from a pipe to a file",
	      syscall(SYS_splice, p[0], NULL, out, &off, 8, 0) == 8 && off == 8);
	memset(buf, 0, sizeof(buf));
	check("splice writes the data of the pipe",
	      pread(out, buf, sizeof(buf), 0) == 8 && memcmp(buf, "abcdefgh", 8) == 0);
	errno = 0;
	check("splice without a pipe gives EINVAL",
	      syscall(SYS_splice, in, NULL, out, NULL, 8, 0) == -1 && errno == EINVAL);
	check("write to the pipe", write(p[1], "xyz", 3) == 3);
	close(p[1]);
	null = open("/dev/null", O_WRONLY);
	check("splice to /dev/null drains the pipe",
	      syscall(SYS_splice, p[0], NULL, null, NULL, 4096, 0) == 3);
	close(null);
	close(p[0]);
	check("pipe for a large splice", pipe(p) == 0);
	ftruncate(in, 100000);
	off = 0;
	check("splice to a pipe writes only what fits and does not wait",
	      syscall(SYS_splice, in, &off, p[1], NULL, 100000, 0) == 65536 && off == 65536);
	close(p[0]);
	close(p[1]);
	/* An eventfd has no splice operations, so a splice gives EINVAL and does not wait for the
	 * empty pipe, as fs/splice.c of Linux. splice07 of LTP waited here (#481). */
	check("pipe for a splice to an eventfd", pipe(p) == 0);
	int efd = syscall(SYS_eventfd2, 0, 0);
	errno = 0;
	check("splice from an empty pipe to an eventfd gives EINVAL",
	      syscall(SYS_splice, p[0], NULL, efd, NULL, 1, 0) == -1 && errno == EINVAL);
	errno = 0;
	check("splice from an eventfd to a pipe gives EINVAL",
	      syscall(SYS_splice, efd, NULL, p[1], NULL, 1, 0) == -1 && errno == EINVAL);
	close(efd);
	int dfd = open("/tmp", O_RDONLY | O_DIRECTORY);
	errno = 0;
	check("splice from a directory to a pipe gives EINVAL",
	      syscall(SYS_splice, dfd, NULL, p[1], NULL, 1, 0) == -1 && errno == EINVAL);
	close(dfd);
	close(p[0]);
	close(p[1]);
	ftruncate(in, 8);
	lseek(in, 1, SEEK_SET);
	lseek(out, 0, SEEK_SET);
	check("copy_file_range at the positions copies 3 bytes",
	      syscall(SYS_copy_file_range, in, NULL, out, NULL, 3, 0) == 3);
	check("copy_file_range moves the positions",
	      lseek(in, 0, SEEK_CUR) == 4 && lseek(out, 0, SEEK_CUR) == 3);
	memset(buf, 0, sizeof(buf));
	check("copy_file_range writes the data",
	      pread(out, buf, sizeof(buf), 0) == 8 && memcmp(buf, "bcddefgh", 8) == 0);
	off = 0;
	errno = 0;
	check("copy_file_range of ranges that overlap gives EINVAL",
	      syscall(SYS_copy_file_range, in, &off, in, NULL, 8, 0) == -1 && errno == EINVAL);
	errno = 0;
	check("copy_file_range with flags gives EINVAL",
	      syscall(SYS_copy_file_range, in, NULL, out, NULL, 1, 1) == -1 && errno == EINVAL);
	int dev = open("/dev/null", O_WRONLY | O_APPEND);
	errno = 0;
	check("copy_file_range to an append-only device gives EINVAL",
	      syscall(SYS_copy_file_range, in, NULL, dev, NULL, 1, 0) == -1 && errno == EINVAL);
	close(dev);
	check("fadvise64 with a valid advice", syscall(SYS_fadvise64, in, 0, 0, 2) == 0);
	errno = 0;
	check("fadvise64 with a bad advice gives EINVAL",
	      syscall(SYS_fadvise64, in, 0, 0, 99) == -1 && errno == EINVAL);
	close(in);
	close(out);
	unlink("/tmp/sp_in");
	unlink("/tmp/sp_out");
}

/* A read updates the access time with the relatime rules. A noatime mount keeps it. */
static void test_atime(void)
{
	struct timespec old[2] = {{1000, 0}, {2000, 0}};
	struct stat st1, st2;
	char buf[4];
	int fd;

	mkdir("/tmp", 0755);
	fd = open("/tmp/at", O_CREAT | O_RDWR | O_TRUNC, 0644);
	check("write a file for atime", write(fd, "abc", 3) == 3);
	check("utimensat sets an old atime", futimens(fd, old) == 0);
	/* futimens sets the ctime. The clock must move past it, else the atime of the read is the
	 * same as the ctime and the next read updates it again. */
	nanosleep(&(struct timespec){0, 10 * 1000 * 1000}, NULL);
	check("read for atime", pread(fd, buf, 3, 0) == 3);
	fstat(fd, &st1);
	check("a read updates an atime that is before the mtime", st1.st_atime > 2000);
	check("pread of the file again", pread(fd, buf, 3, 0) == 3);
	fstat(fd, &st2);
	check("relatime keeps an atime that is after the mtime and the ctime",
	      st2.st_atim.tv_sec == st1.st_atim.tv_sec && st2.st_atim.tv_nsec == st1.st_atim.tv_nsec);
	close(fd);
	unlink("/tmp/at");

	mkdir("/mnt", 0755);
	check("mount tmpfs noatime", mount("none", "/mnt", "tmpfs", MS_NOATIME, NULL) == 0);
	fd = open("/mnt/at", O_CREAT | O_RDWR | O_TRUNC, 0644);
	check("write a file on a noatime mount", write(fd, "abc", 3) == 3);
	check("utimensat on a noatime mount", futimens(fd, old) == 0);
	check("read on a noatime mount", pread(fd, buf, 3, 0) == 3);
	fstat(fd, &st1);
	check("a noatime mount keeps the atime", st1.st_atime == 1000);
	close(fd);
	unlink("/mnt/at");
	umount("/mnt");
	rmdir("/mnt");
}

static void test_xattr(void)
{
	char buf[64];
	int fd;

	mkdir("/tmp", 0755);
	fd = open("/tmp/xa", O_CREAT | O_RDWR | O_TRUNC, 0644);
	check("setxattr makes a user attribute", setxattr("/tmp/xa", "user.color", "blue", 4, 0) == 0);
	check("getxattr gives the size for a size of 0", getxattr("/tmp/xa", "user.color", NULL, 0) == 4);
	check("getxattr gives the value",
	      getxattr("/tmp/xa", "user.color", buf, sizeof(buf)) == 4 && memcmp(buf, "blue", 4) == 0);
	check("getxattr with a small buffer gives ERANGE",
	      getxattr("/tmp/xa", "user.color", buf, 2) < 0 && errno == ERANGE);
	check("XATTR_CREATE of an attribute that exists gives EEXIST",
	      setxattr("/tmp/xa", "user.color", "red", 3, XATTR_CREATE) < 0 && errno == EEXIST);
	check("XATTR_REPLACE of a new attribute gives ENODATA",
	      fsetxattr(fd, "user.size", "1", 1, XATTR_REPLACE) < 0 && errno == ENODATA);
	check("fsetxattr makes a trusted attribute", fsetxattr(fd, "trusted.t", "", 0, 0) == 0);
	check("listxattr gives the names",
	      listxattr("/tmp/xa", buf, sizeof(buf)) == 21 && memcmp(buf, "trusted.t\0user.color\0", 21) == 0);
	check("flistxattr gives the size for a size of 0", flistxattr(fd, NULL, 0) == 21);
	check("a name without a namespace gives EOPNOTSUPP",
	      setxattr("/tmp/xa", "color", "x", 1, 0) < 0 && errno == EOPNOTSUPP);
	check("an empty name gives ERANGE", getxattr("/tmp/xa", "", buf, sizeof(buf)) < 0 && errno == ERANGE);
	check("a bad flag gives EINVAL", setxattr("/tmp/xa", "user.a", "x", 1, 4) < 0 && errno == EINVAL);
	check("removexattr removes the attribute", removexattr("/tmp/xa", "user.color") == 0);
	check("getxattr of a removed attribute gives ENODATA",
	      fgetxattr(fd, "user.color", buf, sizeof(buf)) < 0 && errno == ENODATA);
	symlink("/tmp/xa", "/tmp/xl");
	check("lsetxattr of a user attribute on a link gives EPERM",
	      lsetxattr("/tmp/xl", "user.a", "x", 1, 0) < 0 && errno == EPERM);
	check("getxattr follows the link", getxattr("/tmp/xl", "trusted.t", buf, sizeof(buf)) == 0);
	close(fd);
	unlink("/tmp/xl");
	unlink("/tmp/xa");
}

static void test_syslog(void)
{
	static char buf[65536];
	int n;

	check("syslog gives the size of the kernel log", klogctl(10, NULL, 0) == 65536);
	n = klogctl(3, buf, sizeof(buf) - 1);
	buf[n > 0 ? n : 0] = 0;
	check("syslog reads the boot log with the level and the time", n > 0 && strncmp(buf, "<6>[", 4) == 0 && strstr(buf, "rukernel") != NULL);
#if defined(__x86_64__)
	{
		/* CPUID leaf 1, ECX bit 21: the CPU has the x2APIC. The kernel then logs
		 * "x2apic enabled", as x2apic_enable of arch/x86/kernel/apic/apic.c in Linux. */
		unsigned int eax = 1, ebx, ecx = 0, edx;

		__asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
		check("the kernel uses the x2APIC if and only if the CPU has it",
		      (strstr(buf, "x2apic enabled") != NULL) == ((ecx >> 21) & 1));
		printf("init: the CPU %s the x2APIC\n", (ecx >> 21) & 1 ? "has" : "does not have");
	}
#endif
	check("syslog with a bad action gives EINVAL", klogctl(99, NULL, 0) < 0 && errno == EINVAL);
	check("syslog read with no buffer gives EINVAL", klogctl(3, NULL, 10) < 0 && errno == EINVAL);
	check("syslog clears the kernel log", klogctl(5, NULL, 0) == 0 && klogctl(3, buf, sizeof(buf)) == 0);
}

static void test_membarrier(void)
{
	long mask = syscall(SYS_membarrier, 0, 0, 0);

	check("membarrier query gives the commands", mask == 0x27f);
	check("membarrier global", syscall(SYS_membarrier, 1, 0, 0) == 0);
	check("membarrier private before the registration gives EPERM",
	      syscall(SYS_membarrier, 8, 0, 0) < 0 && errno == EPERM);
	check("membarrier registers the private command", syscall(SYS_membarrier, 16, 0, 0) == 0);
	check("membarrier private", syscall(SYS_membarrier, 8, 0, 0) == 0);
	check("membarrier gives the registrations", syscall(SYS_membarrier, 512, 0, 0) == 16);
	check("membarrier with flags gives EINVAL", syscall(SYS_membarrier, 1, 1, 0) < 0 && errno == EINVAL);
	check("membarrier with a bad command gives EINVAL", syscall(SYS_membarrier, 3, 0, 0) < 0 && errno == EINVAL);
}

/* Sets a lock of type on the bytes start..start+len-1 of fd with cmd. */
static int set_lock(int fd, int cmd, short type, off_t start, off_t len)
{
	struct flock fl = { .l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len };

	return fcntl(fd, cmd, &fl);
}

static void test_file_locks(void)
{
	struct flock fl;
	pid_t pid;
	int fd, fd2, status;

	mkdir("/tmp", 0755);
	fd = open("/tmp/lk", O_RDWR | O_CREAT | O_TRUNC, 0644);
	check("a write lock", set_lock(fd, F_SETLK, F_WRLCK, 0, 10) == 0);
	/* The child tells the parent through the pipe when it found the conflict. A fixed sleep of
	 * the parent is not enough: on a busy host the child can start after the close. */
	int ready[2];
	if (pipe(ready) != 0)
		ready[0] = ready[1] = -1;
	pid = fork();
	if (pid == 0) {
		int c = open("/tmp/lk", O_RDWR);
		struct flock g = { .l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 1 };

		if (set_lock(c, F_SETLK, F_RDLCK, 5, 1) == 0 || errno != EAGAIN)
			_exit(1);
		if (fcntl(c, F_GETLK, &g) != 0 || g.l_type != F_WRLCK || g.l_pid != getppid() ||
		    g.l_start != 0 || g.l_len != 10)
			_exit(2);
		if (set_lock(c, F_SETLK, F_WRLCK, 10, 0) != 0)
			_exit(3);
		write(ready[1], "r", 1);
		/* The parent closes another descriptor of the file, and that releases its lock. */
		if (set_lock(c, F_SETLKW, F_WRLCK, 0, 10) != 0)
			_exit(4);
		_exit(0);
	}
	fd2 = open("/tmp/lk", O_RDONLY);
	/* The read also returns when the child exits early. */
	close(ready[1]);
	char r;
	read(ready[0], &r, 1);
	close(ready[0]);
	usleep(100000);
	close(fd2);
	waitpid(pid, &status, 0);
	check("a lock of another process conflicts, F_GETLK finds it, and a close releases it",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	check("F_GETLK gives F_UNLCK when the locks of the child went with it",
	      fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type == F_UNLCK);
	check("a write lock on a file open only for reading gives EBADF",
	      (fd2 = open("/tmp/lk", O_RDONLY)) >= 0 && set_lock(fd2, F_SETLK, F_WRLCK, 0, 1) < 0 &&
		      errno == EBADF);
	close(fd2);

	fd2 = open("/tmp/lk", O_RDWR);
	check("an OFD lock", set_lock(fd2, F_OFD_SETLK, F_WRLCK, 100, 1) == 0);
	check("an OFD lock conflicts with a POSIX lock of the same process",
	      set_lock(fd, F_SETLK, F_WRLCK, 100, 1) < 0 && errno == EAGAIN);
	close(fd2);
	check("the OFD lock goes with its file", set_lock(fd, F_SETLK, F_WRLCK, 100, 1) == 0);

	fd2 = open("/tmp/lk", O_RDWR);
	check("flock LOCK_EX", flock(fd, LOCK_EX) == 0);
	check("flock of another open file gives EWOULDBLOCK",
	      flock(fd2, LOCK_SH | LOCK_NB) < 0 && errno == EWOULDBLOCK);
	check("flock LOCK_UN", flock(fd, LOCK_UN) == 0 && flock(fd2, LOCK_SH | LOCK_NB) == 0);
	check("flock with a bad operation gives EINVAL", flock(fd, 0) < 0 && errno == EINVAL);
	close(fd2);
	close(fd);
	unlink("/tmp/lk");
}

static void test_iflags(void)
{
	struct fsxattr fsx;
	int flags = 0, fd, ap;

	mkdir("/tmp", 0755);
	fd = open("/tmp/fl", O_CREAT | O_RDWR | O_TRUNC, 0644);
	check("FS_IOC_GETFLAGS gives no flags for a new file", ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && flags == 0);
	flags = FS_IMMUTABLE_FL;
	check("FS_IOC_SETFLAGS sets the immutable flag", ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0);
	flags = 0;
	check("FS_IOC_GETFLAGS gives the immutable flag",
	      ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && flags == FS_IMMUTABLE_FL);
	memset(&fsx, 0, sizeof(fsx));
	check("FS_IOC_FSGETXATTR gives the immutable flag",
	      ioctl(fd, FS_IOC_FSGETXATTR, &fsx) == 0 && fsx.fsx_xflags == FS_XFLAG_IMMUTABLE);
	fsx.fsx_xflags = FS_XFLAG_IMMUTABLE | FS_XFLAG_NODUMP;
	check("FS_IOC_FSSETXATTR sets the nodump flag", ioctl(fd, FS_IOC_FSSETXATTR, &fsx) == 0 &&
	      ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && flags == (FS_IMMUTABLE_FL | FS_NODUMP_FL));
	{
		/* STATX_ATTR_IMMUTABLE, STATX_ATTR_APPEND and STATX_ATTR_NODUMP. musl does not have them. */
		const unsigned long long imm = 0x10, app = 0x20, nodump = 0x40;
		struct statx stx;
		check("statx gives the immutable and nodump attributes",
		      statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) == 0 &&
		      (stx.stx_attributes & (imm | nodump | app)) == (imm | nodump) && (stx.stx_attributes_mask & app));
		/* STATX_ATTR_COMPRESSED: tmpfs does not keep it, as shmem_getattr of Linux. */
		check("statx on tmpfs has no compressed attribute in the mask",
		      statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) == 0 && !(stx.stx_attributes_mask & 0x4));
	}
	fsx.fsx_projid = 1;
	check("FS_IOC_FSSETXATTR with a project id gives EOPNOTSUPP",
	      ioctl(fd, FS_IOC_FSSETXATTR, &fsx) < 0 && errno == EOPNOTSUPP);
	check("a write to an immutable file gives EPERM", write(fd, "x", 1) < 0 && errno == EPERM);
	check("an open for writing of an immutable file gives EPERM",
	      open("/tmp/fl", O_WRONLY) < 0 && errno == EPERM);
	check("unlink of an immutable file gives EPERM", unlink("/tmp/fl") < 0 && errno == EPERM);
	check("chmod of an immutable file gives EPERM", chmod("/tmp/fl", 0600) < 0 && errno == EPERM);
	check("setxattr on an immutable file gives EPERM",
	      setxattr("/tmp/fl", "user.a", "x", 1, 0) < 0 && errno == EPERM);
	flags = FS_APPEND_FL;
	check("FS_IOC_SETFLAGS sets the append-only flag", ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0);
	check("an open of an append-only file without O_APPEND gives EPERM",
	      open("/tmp/fl", O_WRONLY) < 0 && errno == EPERM);
	ap = open("/tmp/fl", O_WRONLY | O_APPEND);
	check("an append-only file accepts an append", ap >= 0 && write(ap, "ab", 2) == 2);
	check("clearing O_APPEND on an append-only file gives EPERM",
	      fcntl(ap, F_SETFL, 0) < 0 && errno == EPERM);
	check("ftruncate of an append-only file gives EPERM", ftruncate(ap, 0) < 0 && errno == EPERM);
	check("utimensat to the time now works on an append-only file", utimensat(AT_FDCWD, "/tmp/fl", NULL, 0) == 0);
	{
		struct timespec ts[2] = { { 1, 0 }, { 1, 0 } };
		check("utimensat with a time on an append-only file gives EPERM",
		      utimensat(AT_FDCWD, "/tmp/fl", ts, 0) < 0 && errno == EPERM);
	}
	close(ap);
	flags = 0;
	check("FS_IOC_SETFLAGS clears the flags", ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0);
	flags = 0;
	check("FIGETBSZ gives the block size", ioctl(fd, FIGETBSZ, &flags) == 0 && flags == 4096);
	flags = 0;
	check("FIBMAP on tmpfs gives EINVAL", ioctl(fd, FIBMAP, &flags) < 0 && errno == EINVAL);
	close(fd);
	check("unlink works when the flags are clear", unlink("/tmp/fl") == 0);
}

static void test_fallocate(void)
{
	struct stat st;
	char buf[4];
	int fd = open("/tmp/fa", O_RDWR | O_CREAT | O_TRUNC, 0644);

	check("fallocate makes the file larger", fallocate(fd, 0, 0, 8192) == 0 &&
	      fstat(fd, &st) == 0 && st.st_size == 8192);
	check("fallocate with FALLOC_FL_KEEP_SIZE keeps the size",
	      fallocate(fd, FALLOC_FL_KEEP_SIZE, 8192, 4096) == 0 && fstat(fd, &st) == 0 &&
		      st.st_size == 8192);
	pwrite(fd, "abcd", 4, 100);
	check("FALLOC_FL_PUNCH_HOLE makes zeros",
	      fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 101, 2) == 0 &&
		      pread(fd, buf, 4, 100) == 4 && memcmp(buf, "a\0\0d", 4) == 0);
	check("FALLOC_FL_PUNCH_HOLE without FALLOC_FL_KEEP_SIZE gives EOPNOTSUPP",
	      fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, 1) < 0 && errno == EOPNOTSUPP);
	check("fallocate with a length of 0 gives EINVAL", fallocate(fd, 0, 0, 0) < 0 && errno == EINVAL);
	close(fd);
	fd = open("/tmp/fa", O_RDONLY);
	check("fallocate of a file open only for reading gives EBADF",
	      fallocate(fd, 0, 0, 1) < 0 && errno == EBADF);
	close(fd);
	unlink("/tmp/fa");
}

static volatile sig_atomic_t got_xfsz;

static void on_xfsz(int sig)
{
	got_xfsz = sig;
}

static void test_tmpfile(void)
{
	char path[64], buf[8] = { 0 };
	struct stat st;
	int fd, ex;

	check("O_TMPFILE without write access gives EINVAL",
	      open("/tmp", O_TMPFILE | O_RDONLY, 0600) == -1 && errno == EINVAL);
	check("O_TMPFILE on a file gives ENOTDIR",
	      open("/init", O_TMPFILE | O_RDWR, 0600) == -1 && errno == ENOTDIR);
	fd = open("/tmp", O_TMPFILE | O_RDWR, 0600);
	check("O_TMPFILE makes a file without a link",
	      fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 0);
	check("a file of O_TMPFILE keeps its data", write(fd, "tmp", 3) == 3);
	check("linkat with AT_EMPTY_PATH gives the file a name",
	      linkat(fd, "", AT_FDCWD, "/tmp/tmpf", AT_EMPTY_PATH) == 0 &&
	      fstat(fd, &st) == 0 && st.st_nlink == 1);
	close(fd);
	fd = open("/tmp/tmpf", O_RDONLY);
	check("the linked file has the data", fd >= 0 && read(fd, buf, sizeof(buf)) == 3 &&
	      memcmp(buf, "tmp", 3) == 0);
	close(fd);
	unlink("/tmp/tmpf");
	ex = open("/tmp", O_TMPFILE | O_EXCL | O_WRONLY, 0600);
	snprintf(path, sizeof(path), "/proc/self/fd/%d", ex);
	check("a file of O_TMPFILE with O_EXCL gets no link",
	      ex >= 0 && linkat(AT_FDCWD, path, AT_FDCWD, "/tmp/tmpx", AT_SYMLINK_FOLLOW) == -1 &&
	      errno == ENOENT);
	close(ex);
}

static void test_fsize(void)
{
	struct rlimit rl = { 8192, RLIM_INFINITY };
	struct stat st;
	char buf[4096] = { 0 };
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		int fd = open("/tmp/fsz", O_RDWR | O_CREAT | O_TRUNC, 0644);

		failed = 0;
		signal(SIGXFSZ, on_xfsz);
		setrlimit(RLIMIT_FSIZE, &rl);
		check("a write that crosses RLIMIT_FSIZE is short",
		      pwrite(fd, buf, 4096, 6144) == 2048 && got_xfsz == 0);
		check("a write at RLIMIT_FSIZE gives EFBIG and sends SIGXFSZ",
		      pwrite(fd, buf, 1, 8192) == -1 && errno == EFBIG && got_xfsz == SIGXFSZ);
		got_xfsz = 0;
		check("ftruncate above RLIMIT_FSIZE gives EFBIG",
		      ftruncate(fd, 8193) == -1 && errno == EFBIG && got_xfsz == SIGXFSZ);
		check("ftruncate to a smaller size ignores RLIMIT_FSIZE",
		      ftruncate(fd, 100) == 0 && fstat(fd, &st) == 0 && st.st_size == 100);
		got_xfsz = 0;
		check("fallocate above RLIMIT_FSIZE gives EFBIG",
		      fallocate(fd, 0, 0, 8193) == -1 && errno == EFBIG && got_xfsz == SIGXFSZ);
		check("fallocate with FALLOC_FL_KEEP_SIZE ignores RLIMIT_FSIZE",
		      fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 16384) == 0);
		close(fd);
		unlink("/tmp/fsz");
		_exit(failed);
	}
	waitpid(pid, &status, 0);
	check("the RLIMIT_FSIZE checks of the child pass", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_fifo(void)
{
	struct stat st1, st2;
	char buf[8];
	pid_t pid;
	int fd, status;

	mkdir("/tmp", 0755);
	unlink("/tmp/ff");
	check("mkfifo", mkfifo("/tmp/ff", 0644) == 0);
	check("a nonblocking open for writing of a FIFO with no reader gives ENXIO",
	      open("/tmp/ff", O_WRONLY | O_NONBLOCK) < 0 && errno == ENXIO);
	pid = fork();
	if (pid == 0) {
		fd = open("/tmp/ff", O_WRONLY);
		_exit(fd >= 0 && write(fd, "hi", 2) == 2 ? 0 : 1);
	}
	fd = open("/tmp/ff", O_RDONLY);
	check("an open for reading of a FIFO waits for the writer", fd >= 0);
	check("a read of a FIFO gives the data of the writer", read(fd, buf, sizeof(buf)) == 2 && memcmp(buf, "hi", 2) == 0);
	waitpid(pid, &status, 0);
	check("the writer of the FIFO exits with 0", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("a read of a FIFO with no writer gives the end of the file", read(fd, buf, sizeof(buf)) == 0);
	fstat(fd, &st1);
	stat("/tmp/ff", &st2);
	check("fstat of a FIFO gives the inode of the file", S_ISFIFO(st1.st_mode) && st1.st_ino == st2.st_ino && st1.st_dev == st2.st_dev);
	close(fd);
	fd = open("/tmp/ff", O_RDWR);
	check("an open of a FIFO with O_RDWR does not wait", fd >= 0 && write(fd, "x", 1) == 1 && read(fd, buf, 1) == 1);
	close(fd);
	unlink("/tmp/ff");
}

/* Reads the file at path into buf, and gives the count of bytes, or -1. */
static int read_small(const char *path, char *buf, int size)
{
	int fd = open(path, O_RDONLY);
	int n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n >= 0)
		buf[n] = 0;
	return n;
}

/* Writes the string data to a new file at path. */
static int put_file(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	int ok;

	if (fd < 0)
		return -1;
	ok = write(fd, data, strlen(data)) == (ssize_t)strlen(data);
	close(fd);
	return ok ? 0 : -1;
}

/* The leases of F_SETLEASE and their breaks, as fs/locks.c of Linux (#481). */
static void test_file_leases(void)
{
	struct timespec wait_time = { 5, 0 }, zero = { 0, 0 }, t0, t1;
	sigset_t set, old;
	siginfo_t si;
	int fd, fd2, status;
	long ms;
	pid_t pid;

	mkdir("/tmp", 0755);
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	close(open("/tmp/ls", O_RDWR | O_CREAT | O_TRUNC, 0644));
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &old);
	fd = open("/tmp/ls", O_RDONLY);
	check("F_SETLEASE F_UNLCK without a lease gives EAGAIN",
	      fcntl(fd, F_SETLEASE, F_UNLCK) < 0 && errno == EAGAIN);
	fd2 = open("/tmp/ls", O_RDONLY);
	check("a write lease while another file is open gives EAGAIN",
	      fcntl(fd, F_SETLEASE, F_WRLCK) < 0 && errno == EAGAIN);
	close(fd2);
	check("a write lease on a file open only for reading",
	      fcntl(fd, F_SETSIG, SIGUSR1) == 0 && fcntl(fd, F_SETLEASE, F_WRLCK) == 0 &&
		      fcntl(fd, F_GETLEASE) == F_WRLCK);
	check("an open with O_NONBLOCK that breaks a lease gives EWOULDBLOCK",
	      open("/tmp/ls", O_RDONLY | O_NONBLOCK) < 0 && errno == EWOULDBLOCK);
	check("the lease holder gets the signal of F_SETSIG with its descriptor",
	      sigtimedwait(&set, &si, &wait_time) == SIGUSR1 && si.si_fd == fd && si.si_code == POLL_MSG);
	check("F_GETLEASE gives F_RDLCK while a read open breaks a write lease",
	      fcntl(fd, F_GETLEASE) == F_RDLCK);
	check("the holder downgrades its lease to a read lease",
	      fcntl(fd, F_SETLEASE, F_RDLCK) == 0 && fcntl(fd, F_GETLEASE) == F_RDLCK);
	fd2 = open("/tmp/ls", O_RDONLY | O_NONBLOCK);
	check("a read open does not break a read lease", fd2 >= 0);
	close(fd2);
	pid = fork();
	if (pid == 0) {
		/* The open waits until the holder removes the lease. */
		int c = open("/tmp/ls", O_WRONLY);

		_exit(c >= 0 ? 0 : 1);
	}
	check("a write open breaks a read lease, and F_GETLEASE gives F_UNLCK",
	      sigtimedwait(&set, &si, &wait_time) == SIGUSR1 && fcntl(fd, F_GETLEASE) == F_UNLCK);
	check("no read lease while the file is open for a write",
	      fcntl(fd, F_SETLEASE, F_RDLCK) < 0 && errno == EAGAIN);
	check("the removal of the lease lets the open of the breaker go on",
	      fcntl(fd, F_SETLEASE, F_UNLCK) == 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 0);
	close(fd);

	/* A holder that does nothing loses its lease after fs.lease-break-time seconds. */
	check("fs.lease-break-time takes a new value", put_file("/proc/sys/fs/lease-break-time", "1") == 0);
	fd = open("/tmp/ls", O_RDONLY);
	fcntl(fd, F_SETSIG, SIGUSR1);
	check("a read lease", fcntl(fd, F_SETLEASE, F_RDLCK) == 0);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	check("truncate breaks a read lease", truncate("/tmp/ls", 0) == 0);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
	check("the breaker waits for the break time, and the lease goes away",
	      ms >= 900 && ms < 4000 && fcntl(fd, F_GETLEASE) == F_UNLCK);
	sigtimedwait(&set, &si, &zero);
	put_file("/proc/sys/fs/lease-break-time", "45");
	check("fs.leases-enable 0 makes F_SETLEASE give EINVAL",
	      put_file("/proc/sys/fs/leases-enable", "0") == 0 && fcntl(fd, F_SETLEASE, F_RDLCK) < 0 &&
		      errno == EINVAL);
	put_file("/proc/sys/fs/leases-enable", "1");
	close(fd);
	unlink("/tmp/ls");
	sigprocmask(SIG_SETMASK, &old, NULL);
	umount("/proc");
}

/* Counts the entries of the directory at path, without . and .., or gives -1. */
static int count_entries(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			n++;
	closedir(d);
	return n;
}

static void test_overlay(void)
{
	struct statfs sfs;
	struct stat st;
	char buf[32];

	mkdir("/ov", 0755);
	check("mount a tmpfs for overlayfs", mount("tmpfs", "/ov", "tmpfs", 0, NULL) == 0);
	mkdir("/ov/lower", 0755);
	mkdir("/ov/upper", 0755);
	mkdir("/ov/work", 0755);
	mkdir("/ov/merged", 0755);
	mkdir("/ov/lower/d", 0755);
	put_file("/ov/lower/a", "lower");
	put_file("/ov/lower/d/x", "x");
	put_file("/ov/upper/b", "upper");
	check("mount overlayfs", mount("overlay", "/ov/merged", "overlay", 0,
				       "lowerdir=/ov/lower,upperdir=/ov/upper,workdir=/ov/work") == 0);
	check("statfs of overlayfs gives OVERLAYFS_SUPER_MAGIC",
	      statfs("/ov/merged", &sfs) == 0 && sfs.f_type == 0x794c7630);
	check("overlayfs joins the layers", count_entries("/ov/merged") == 3);
	check("overlayfs shows a lower file", read_small("/ov/merged/a", buf, sizeof(buf)) == 5 && strcmp(buf, "lower") == 0);
	check("a write through overlayfs copies the file up", put_file("/ov/merged/a", "new") == 0 &&
	      read_small("/ov/upper/a", buf, sizeof(buf)) == 3 && strcmp(buf, "new") == 0 &&
	      read_small("/ov/lower/a", buf, sizeof(buf)) == 5);
	check("an unlink through overlayfs makes a whiteout", unlink("/ov/merged/d/x") == 0 &&
	      stat("/ov/upper/d/x", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == 0 &&
	      access("/ov/merged/d/x", F_OK) < 0 && access("/ov/lower/d/x", F_OK) == 0);
	check("rmdir of an empty joined directory", rmdir("/ov/merged/d") == 0 && access("/ov/merged/d", F_OK) < 0);
	check("a rename of a lower directory gives EXDEV", mkdir("/ov/lower/e", 0755) == 0 &&
	      rename("/ov/merged/e", "/ov/merged/f") < 0 && errno == EXDEV);
	check("umount overlayfs", umount("/ov/merged") == 0);
	check("an overlay mount without an upper directory is read only",
	      mount("overlay", "/ov/merged", "overlay", 0, "lowerdir=/ov/upper:/ov/lower") == 0 &&
	      open("/ov/merged/n", O_WRONLY | O_CREAT, 0644) < 0 && errno == EROFS &&
	      access("/ov/merged/d", F_OK) < 0 && access("/ov/merged/e", F_OK) == 0);
	umount("/ov/merged");
	umount("/ov");
}

static void test_sysfs(void)
{
	struct statfs sfs;
	struct stat st;
	char buf[128];
	ssize_t n;
	int fd;

	mkdir("/sys", 0755);
	check("mount sysfs", mount("sysfs", "/sys", "sysfs", 0, NULL) == 0);
	check("statfs of sysfs gives SYSFS_MAGIC", statfs("/sys", &sfs) == 0 && sfs.f_type == 0x62656572);
	check("sysfs has /sys/class/mem/null/dev",
	      read_small("/sys/class/mem/null/dev", buf, sizeof(buf)) > 0 && strcmp(buf, "1:3\n") == 0);
	n = readlink("/sys/dev/char/1:3", buf, sizeof(buf) - 1);
	check("/sys/dev/char/1:3 links to the device",
	      n > 0 && (buf[n] = 0, strcmp(buf, "../../devices/virtual/mem/null") == 0));
	fd = open("/sys/class/mem/null/dev", O_WRONLY);
	check("a sysfs file does not take a write", write(fd, "1", 1) < 0 && errno == EACCES);
	close(fd);
	check("sysfs does not take a new file", mkdir("/sys/new", 0755) < 0 && errno == EPERM);
	if (stat("/sys/block/vda", &st) == 0) {
		check("sysfs has the uevent of vda",
		      read_small("/sys/block/vda/uevent", buf, sizeof(buf)) > 0 &&
			      strstr(buf, "DEVNAME=vda\nDEVTYPE=disk\n") != NULL);
		check("sysfs has the size of vda",
		      read_small("/sys/class/block/vda/size", buf, sizeof(buf)) > 0 && atol(buf) > 0);
	}
	umount("/sys");

	mkdir("/mnt", 0755);
	check("mount devtmpfs", mount("devtmpfs", "/mnt", "devtmpfs", 0, NULL) == 0);
	check("devtmpfs has /dev/null",
	      stat("/mnt/null", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3));
	umount("/mnt");
	rmdir("/mnt");
}

/* A loop device over a file of 4 KiB: its size, its data, its status and its device file. */
static void test_loop(void)
{
	struct loop_info64 info;
	char data[4096], buf[512], path[32];
	unsigned long long size = 0;
	int ctl, file, dev, n;

	for (n = 0; n < (int)sizeof(data); n++)
		data[n] = (char)(n % 251);
	file = open("/loopfile", O_RDWR | O_CREAT | O_TRUNC, 0644);
	check("make the file of the loop device", file >= 0 && write(file, data, sizeof(data)) == sizeof(data));
	ctl = open("/dev/loop-control", O_RDWR);
	n = ctl >= 0 ? ioctl(ctl, LOOP_CTL_GET_FREE) : -1;
	check("LOOP_CTL_GET_FREE gives a device", n >= 0);
	snprintf(path, sizeof(path), "/dev/loop%d", n);
	dev = open(path, O_RDWR);
	check("LOOP_SET_FD", dev >= 0 && ioctl(dev, LOOP_SET_FD, file) == 0);
	check("the loop device has the size of the file",
	      ioctl(dev, BLKGETSIZE64, &size) == 0 && size == sizeof(data));
	check("the loop device reads the file",
	      pread(dev, buf, sizeof(buf), 512) == sizeof(buf) && memcmp(buf, data + 512, sizeof(buf)) == 0);
	check("LOOP_GET_STATUS64", ioctl(dev, LOOP_GET_STATUS64, &info) == 0 && (int)info.lo_number == n);
	check("LOOP_SET_FD on a used device gives EBUSY", ioctl(dev, LOOP_SET_FD, file) < 0 && errno == EBUSY);
	check("LOOP_CLR_FD", ioctl(dev, LOOP_CLR_FD, 0) == 0);
	close(dev);
	close(file);
	unlink("/loopfile");
	check("LOOP_CTL_ADD makes /dev/loop200",
	      ioctl(ctl, LOOP_CTL_ADD, 200) == 200 && access("/dev/loop200", F_OK) == 0);
	check("LOOP_CTL_REMOVE removes /dev/loop200",
	      ioctl(ctl, LOOP_CTL_REMOVE, 200) == 0 && access("/dev/loop200", F_OK) < 0);
	close(ctl);
}

/* The calls and the flags of the new mount API, from <linux/mount.h>. */
#ifndef SYS_fsopen
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#endif
#define RK_FSCONFIG_SET_FLAG 0
#define RK_FSCONFIG_SET_STRING 1
#define RK_FSCONFIG_CMD_CREATE 6
#define RK_FSCONFIG_CMD_RECONFIGURE 7
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#define RK_MOUNT_ATTR_RDONLY 1
#define RK_MOUNT_ATTR_NOSUID 2
#define RK_MOUNT_ATTR_NODEV 4
#define RK_MOUNT_ATTR_NOATIME 0x10
#define RK_ST_RDONLY 1
#define RK_ST_NOSUID 2
#define RK_MOVE_MOUNT_F_EMPTY_PATH 4
#define RK_OPEN_TREE_CLONE 1

/* The struct mount_attr of mount_setattr. */
struct rk_mount_attr {
	unsigned long long attr_set, attr_clr, propagation, userns_fd;
};

static void test_mount_api(void)
{
	int fd, mfd, tfd, pfd, f;
	struct rk_mount_attr attr = { RK_MOUNT_ATTR_RDONLY | RK_MOUNT_ATTR_NOSUID, 0, 0, 0 };
	struct statfs sfs;

	mkdir("/mnt", 0755);
	mkdir("/mnt2", 0755);
	errno = 0;
	check("fsopen of an unknown type gives ENODEV", syscall(SYS_fsopen, "nofs", 0) == -1 && errno == ENODEV);
	fd = syscall(SYS_fsopen, "tmpfs", 1);
	check("fsopen", fd >= 0);
	check("fsconfig FSCONFIG_SET_STRING", syscall(SYS_fsconfig, fd, RK_FSCONFIG_SET_STRING, "mode", "755", 0) == 0);
	errno = 0;
	check("fsconfig FSCONFIG_SET_FLAG with a value gives EINVAL",
	      syscall(SYS_fsconfig, fd, RK_FSCONFIG_SET_FLAG, "ro", "x", 0) == -1 && errno == EINVAL);
	errno = 0;
	check("fsconfig with an unknown command gives EOPNOTSUPP",
	      syscall(SYS_fsconfig, fd, 99, NULL, NULL, 0) == -1 && errno == EOPNOTSUPP);
	errno = 0;
	check("fsmount before FSCONFIG_CMD_CREATE gives EINVAL", syscall(SYS_fsmount, fd, 0, 0) == -1 && errno == EINVAL);
	check("fsconfig FSCONFIG_CMD_CREATE", syscall(SYS_fsconfig, fd, RK_FSCONFIG_CMD_CREATE, NULL, NULL, 0) == 0);
	errno = 0;
	check("a second FSCONFIG_CMD_CREATE gives EBUSY",
	      syscall(SYS_fsconfig, fd, RK_FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1 && errno == EBUSY);
	mfd = syscall(SYS_fsmount, fd, 1, RK_MOUNT_ATTR_NODEV);
	check("fsmount", mfd >= 0);
	f = openat(mfd, "f", O_CREAT | O_RDWR, 0644);
	check("a file in a mount that is not attached", f >= 0);
	close(f);
	check("move_mount attaches the mount of fsmount",
	      syscall(SYS_move_mount, mfd, "", AT_FDCWD, "/mnt", RK_MOVE_MOUNT_F_EMPTY_PATH) == 0 &&
		      access("/mnt/f", F_OK) == 0);
	check("move_mount moves an attached mount",
	      syscall(SYS_move_mount, AT_FDCWD, "/mnt", AT_FDCWD, "/mnt2", 0) == 0 && access("/mnt/f", F_OK) == -1 &&
		      access("/mnt2/f", F_OK) == 0);
	check("mount with MS_MOVE", mount("/mnt2", "/mnt", NULL, MS_MOVE, NULL) == 0 && access("/mnt/f", F_OK) == 0 &&
					    access("/mnt2/f", F_OK) == -1);
	mkdir("/mnt/d", 0755);
	errno = 0;
	check("move_mount into the same mount gives ELOOP",
	      syscall(SYS_move_mount, AT_FDCWD, "/mnt", AT_FDCWD, "/mnt/d", 0) == -1 && errno == ELOOP);
	tfd = syscall(SYS_open_tree, AT_FDCWD, "/mnt", RK_OPEN_TREE_CLONE | O_CLOEXEC);
	check("open_tree with OPEN_TREE_CLONE", tfd >= 0);
	check("move_mount attaches the clone of open_tree",
	      syscall(SYS_move_mount, tfd, "", AT_FDCWD, "/mnt2", RK_MOVE_MOUNT_F_EMPTY_PATH) == 0 &&
		      access("/mnt2/f", F_OK) == 0);
	errno = 0;
	check("fspick of a directory that is not a mount gives EINVAL",
	      syscall(SYS_fspick, AT_FDCWD, "/mnt/d", 0) == -1 && errno == EINVAL);
	pfd = syscall(SYS_fspick, AT_FDCWD, "/mnt", 1);
	check("fspick", pfd >= 0);
	check("fsconfig FSCONFIG_CMD_RECONFIGURE of fspick",
	      syscall(SYS_fsconfig, pfd, RK_FSCONFIG_SET_FLAG, "ro", NULL, 0) == 0 &&
		      syscall(SYS_fsconfig, pfd, RK_FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0) == 0);
	check("mount_setattr sets MOUNT_ATTR_RDONLY and MOUNT_ATTR_NOSUID",
	      syscall(SYS_mount_setattr, AT_FDCWD, "/mnt2", 0, &attr, sizeof(attr)) == 0 && statfs("/mnt2", &sfs) == 0 &&
		      (sfs.f_flags & RK_ST_RDONLY) && (sfs.f_flags & RK_ST_NOSUID));
	attr.attr_set = 0;
	attr.attr_clr = RK_MOUNT_ATTR_RDONLY;
	check("mount_setattr clears MOUNT_ATTR_RDONLY",
	      syscall(SYS_mount_setattr, AT_FDCWD, "/mnt2", 0, &attr, sizeof(attr)) == 0 && statfs("/mnt2", &sfs) == 0 &&
		      !(sfs.f_flags & RK_ST_RDONLY) && (sfs.f_flags & RK_ST_NOSUID));
	attr.attr_set = RK_MOUNT_ATTR_NOATIME;
	attr.attr_clr = 0;
	errno = 0;
	check("mount_setattr of an atime value without MOUNT_ATTR__ATIME gives EINVAL",
	      syscall(SYS_mount_setattr, AT_FDCWD, "/mnt2", 0, &attr, sizeof(attr)) == -1 && errno == EINVAL);
	/* A descriptor of a mount keeps the mount busy, as on Linux. */
	close(pfd);
	close(tfd);
	close(mfd);
	close(fd);
	check("umount the clone", umount("/mnt2") == 0);
	check("umount the mount of fsmount", umount("/mnt") == 0 && access("/mnt/f", F_OK) == -1);
	rmdir("/mnt");
	rmdir("/mnt2");
}

/* Reads the file `path` into `buf` and gives the byte count, or -1. */
static ssize_t read_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n >= 0)
		buf[n] = 0;
	return n;
}

/* The ptrace checks change these words in the child. */
static volatile long ptrace_word = 1;
static const volatile long ptrace_ro_word = 5;

/* Waits for the traced `pid` and gives the status, or -1. */
static int trace_wait(pid_t pid)
{
	int status;

	return waitpid(pid, &status, __WALL) == pid ? status : -1;
}

#if defined(__aarch64__)
/* arm64 has no PTRACE_GETREGS, so the test uses the register sets, as strace does. */
static long get_regs(pid_t pid, struct user_regs_struct *regs)
{
	struct iovec iov = { regs, sizeof(*regs) };
	return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}
static int syscall_nr(pid_t pid)
{
	int nr = -1;
	struct iovec iov = { &nr, sizeof(nr) };
	ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &iov);
	return nr;
}
static void set_syscall_nr(pid_t pid, int nr)
{
	struct iovec iov = { &nr, sizeof(nr) };
	ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &iov);
}
/* The op of struct ptrace_syscall_info: 1 at the entry to a system call. */
static int at_syscall_entry(pid_t pid)
{
	unsigned char info[88] = { 0 };
	return ptrace(0x420e, pid, (void *)sizeof(info), info) > 0 && info[0] == 1;
}
#define REG_PC(r) ((r).pc)
#define REG_RET(r) ((r).regs[0])
#define STEP_FLAG (1UL << 21)
#define REG_FLAGS(r) ((r).pstate)
#define USER_MODE(r) (((r).pstate & 0xf) == 0)
#else
static long get_regs(pid_t pid, struct user_regs_struct *regs)
{
	return ptrace(PTRACE_GETREGS, pid, 0, regs);
}
static int syscall_nr(pid_t pid)
{
	struct user_regs_struct regs;
	get_regs(pid, &regs);
	return (int)regs.orig_rax;
}
static void set_syscall_nr(pid_t pid, int nr)
{
	struct user_regs_struct regs;
	get_regs(pid, &regs);
	regs.orig_rax = nr;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
}
static int at_syscall_entry(pid_t pid)
{
	struct user_regs_struct regs;
	get_regs(pid, &regs);
	return regs.rax == (unsigned long)-ENOSYS;
}
#define REG_PC(r) ((r).rip)
#define REG_RET(r) ((r).rax)
#define STEP_FLAG 0x100UL
#define REG_FLAGS(r) ((r).eflags)
#define USER_MODE(r) ((r).cs == 0x33)
#endif

static void test_ptrace(void)
{
	struct user_regs_struct regs, before;
	siginfo_t si;
	unsigned long msg;
	pid_t pid, child, me = getpid();
	int status, i, found = 0;
	long word = 0;

	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		pid_t p = getpid();
		_exit(p == getppid() ? (int)(ptrace_word + ptrace_ro_word) : 1);
	}
	status = trace_wait(pid);
	check("PTRACE_TRACEME stops the child at SIGSTOP", WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	check("PTRACE_GETSIGINFO", ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0 && si.si_signo == SIGSTOP);
	errno = 0;
	word = ptrace(PTRACE_PEEKDATA, pid, &ptrace_word, 0);
	check("PTRACE_PEEKDATA", word == 1 && errno == 0);
	check("PTRACE_POKEDATA", ptrace(PTRACE_POKEDATA, pid, &ptrace_word, 40) == 0);
	check("PTRACE_POKETEXT to a read only page", ptrace(PTRACE_POKETEXT, pid, &ptrace_ro_word, 2) == 0 &&
	      ptrace_ro_word == 5);
	check("PTRACE_GETREGS", get_regs(pid, &before) == 0 && USER_MODE(before));
	check("PTRACE_SINGLESTEP", ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == 0);
	status = trace_wait(pid);
	get_regs(pid, &regs);
	ptrace(PTRACE_GETSIGINFO, pid, 0, &si);
	check("a single step stops with SIGTRAP", WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
	      si.si_code == TRAP_TRACE && REG_PC(regs) != REG_PC(before) && !(REG_FLAGS(regs) & STEP_FLAG));
	check("PTRACE_SETOPTIONS", ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT) == 0);
	for (i = 0; i < 20 && !found; i++) {
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		status = trace_wait(pid);
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80))
			break;
		if (syscall_nr(pid) == SYS_getpid && at_syscall_entry(pid)) {
			found = 1;
			set_syscall_nr(pid, SYS_getppid);
		}
	}
	check("PTRACE_SYSCALL stops at the entry to getpid", found);
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	status = trace_wait(pid);
	get_regs(pid, &regs);
	check("the tracer changes the system call", WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80) &&
	      syscall_nr(pid) == SYS_getppid && REG_RET(regs) == (unsigned long)me);
	ptrace(PTRACE_CONT, pid, 0, 0);
	status = trace_wait(pid);
	check("PTRACE_EVENT_EXIT", WIFSTOPPED(status) && status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)) &&
	      ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) == 0 && msg == (42 << 8));
	ptrace(PTRACE_CONT, pid, 0, 0);
	status = trace_wait(pid);
	check("the traced child exits", WIFEXITED(status) && WEXITSTATUS(status) == 42);

	/* PTRACE_O_TRACEFORK traces the child of the tracee too. */
	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		child = fork();
		if (child == 0)
			_exit(3);
		_exit(waitpid(child, &status, 0) == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}
	trace_wait(pid);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK);
	ptrace(PTRACE_CONT, pid, 0, 0);
	status = trace_wait(pid);
	msg = 0;
	ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
	check("PTRACE_EVENT_FORK", WIFSTOPPED(status) && status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) && msg > 0);
	child = msg;
	status = trace_wait(child);
	check("the new child stops at SIGSTOP", WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	ptrace(PTRACE_CONT, child, 0, 0);
	status = trace_wait(child);
	check("the tracer sees the exit of the new child", WIFEXITED(status) && WEXITSTATUS(status) == 3);
	/* The tracee stops for its SIGCHLD before it exits. */
	for (i = 0; i < 5; i++) {
		ptrace(PTRACE_CONT, pid, 0, 0);
		status = trace_wait(pid);
		if (!WIFSTOPPED(status))
			break;
	}
	check("the parent of the new child reaps it", WIFEXITED(status) && WEXITSTATUS(status) == 3);

	/* PTRACE_ATTACH, PTRACE_SEIZE and PTRACE_INTERRUPT on a child that sleeps. */
	pid = fork();
	if (pid == 0) {
		for (;;)
			pause();
	}
	check("PTRACE_ATTACH", ptrace(PTRACE_ATTACH, pid, 0, 0) == 0);
	status = trace_wait(pid);
	check("the attached child stops", WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	check("PTRACE_ATTACH twice gives EPERM", ptrace(PTRACE_ATTACH, pid, 0, 0) == -1 && errno == EPERM);
	check("PTRACE_DETACH", ptrace(PTRACE_DETACH, pid, 0, 0) == 0);
	check("PTRACE_SEIZE", ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL) == 0);
	check("PTRACE_INTERRUPT", ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0);
	status = trace_wait(pid);
	check("PTRACE_EVENT_STOP", WIFSTOPPED(status) && status >> 16 == PTRACE_EVENT_STOP);
	{
		long remote = 0;
		struct iovec local_iov = {&remote, sizeof(remote)};
		struct iovec remote_iov = {(void *)&ptrace_word, sizeof(remote)};

		check("process_vm_readv", syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0) == 8 &&
		      remote == 1);
	}
	ptrace(PTRACE_DETACH, pid, 0, 0);
	kill(pid, SIGKILL);
	status = trace_wait(pid);
	check("the detached child dies", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	check("PTRACE_CONT of a process that is not traced gives ESRCH",
	      ptrace(PTRACE_CONT, getppid(), 0, 0) == -1 && errno == ESRCH);
}

/* The files of procfs for ptrace and debuggers. */
static void test_proc_ptrace(void)
{
	char buf[4096], path[64];
	unsigned long aux[64], pagesz = 0;
	long word = 0, value = 77;
	ssize_t n;
	pid_t pid;
	int fd, i, status;

	mount("proc", "/proc", "proc", 0, NULL);
	n = read_file("/proc/self/auxv", (char *)aux, sizeof(aux));
	for (i = 0; i + 1 < n / 8; i += 2)
		if (aux[i] == AT_PAGESZ)
			pagesz = aux[i + 1];
	check("/proc/self/auxv", n > 0 && n % 16 == 0 && pagesz == getauxval(AT_PAGESZ) && aux[n / 8 - 2] == AT_NULL);
	fd = open("/proc/self/mem", O_RDWR);
	check("/proc/self/mem reads", fd >= 0 && pread(fd, &word, sizeof(word), (off_t)&ptrace_word) == 8 &&
	      word == ptrace_word);
	check("/proc/self/mem writes", pwrite(fd, &value, sizeof(value), (off_t)&ptrace_word) == 8 && ptrace_word == 77);
	check("/proc/self/mem gives EIO for no mapping", pread(fd, &word, sizeof(word), 0) == -1 && errno == EIO);
	close(fd);

	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		_exit(0);
	}
	trace_wait(pid);
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	n = read_file(path, buf, sizeof(buf));
	snprintf(path, sizeof(path), "\nTracerPid:\t%d\n", getpid());
	check("/proc/PID/status of a tracee", n > 0 && strstr(buf, "\nState:\tt (tracing stop)\n") && strstr(buf, path));
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	umount("/proc");
}

/* Gives the entry of /proc/self/pagemap for `addr`, or 0. */
static unsigned long long pagemap_entry(const void *addr)
{
	unsigned long long entry = 0;
	int fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return 0;
	if (pread(fd, &entry, sizeof(entry), (unsigned long)addr / 4096 * sizeof(entry)) != sizeof(entry))
		entry = 0;
	close(fd);
	return entry;
}

/* Gives the entry of /proc/kpageflags for the page frame `pfn`, or 0. */
static unsigned long long kpageflags_pfn(unsigned long long pfn)
{
	unsigned long long flags = 0;
	int fd = open("/proc/kpageflags", O_RDONLY);
	if (fd < 0)
		return 0;
	if (pread(fd, &flags, sizeof(flags), pfn * sizeof(flags)) != sizeof(flags))
		flags = 0;
	close(fd);
	return flags;
}

/* Gives the entry of /proc/kpageflags for the page at `addr`, or 0. */
static unsigned long long kpageflags_entry(const void *addr)
{
	return kpageflags_pfn(pagemap_entry(addr) & ((1ULL << 55) - 1));
}

/*
 * PM_SOFT_DIRTY (55) and PM_MMAP_EXCLUSIVE (56) of /proc/PID/pagemap, the clear of soft-dirty
 * with a write of 4 to /proc/PID/clear_refs, and the THP flags of /proc/kpageflags (#430).
 */
static void test_soft_dirty(void)
{
	const unsigned long long soft = 1ULL << 55, excl = 1ULL << 56;
	char *m = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		check("mmap for soft-dirty", 0);
		return;
	}
	m[0] = 1;
	check("pagemap: a new page is soft-dirty and exclusive", (pagemap_entry(m) & (soft | excl)) == (soft | excl));
	check("clear_refs: 9 gives EINVAL", write_text("/proc/self/clear_refs", "9") != 0);
	check("clear_refs: 4 clears soft-dirty",
	      write_text("/proc/self/clear_refs", "4") == 0 && (pagemap_entry(m) & soft) == 0 &&
		      (pagemap_entry(m + 4096) & soft) == 0);
	check("pagemap: a read keeps the page clean", m[0] == 1 && m[4096] == 0 && (pagemap_entry(m + 4096) & soft) == 0);
	m[0] = 2;
	m[4096] = 2;
	check("pagemap: a write after the clear makes the page soft-dirty",
	      (pagemap_entry(m) & soft) != 0 && (pagemap_entry(m + 4096) & soft) != 0);
	write_text("/proc/self/clear_refs", "4");
	char *n = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	check("pagemap: a new mapping is soft-dirty", n != MAP_FAILED && (pagemap_entry(n) & soft) != 0);
	if (n != MAP_FAILED)
		munmap(n, 4096);
	int status = 0;
	pid_t pid = fork();
	if (pid == 0)
		_exit((pagemap_entry(m) & excl) == 0 && (pagemap_entry(m) & soft) == 0 ? 0 : 1);
	check("pagemap: a page that fork shares is not exclusive",
	      pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("pagemap: the page is exclusive again after the child", (pagemap_entry(m) & excl) != 0);

	/* An unmap clears the soft-dirty bit of the page, as zap_pte_range of Linux (#444). */
	write_text("/proc/self/clear_refs", "4");
	m[0] = 3;
	check("pagemap: MADV_DONTNEED clears the soft-dirty bit of a page",
	      (pagemap_entry(m) & soft) != 0 && madvise(m, 4096, MADV_DONTNEED) == 0 && m[0] == 0 &&
		      (pagemap_entry(m) & soft) == 0);
	munmap(m, 2 * 4096);

	/* The pages of stack growth keep the soft-dirty state of the area, as expand_downwards (#444). */
	char *hole = mmap(NULL, 2 << 20, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char *g = MAP_FAILED;
	if (hole != MAP_FAILED) {
		munmap(hole, 2 << 20);
		g = mmap(hole + (2 << 20) - 4096, 4096, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
	}
	if (g != MAP_FAILED) {
		write_text("/proc/self/clear_refs", "4");
		g[-3 * 4096] = 1;
		check("pagemap: a write below a MAP_GROWSDOWN area marks only the written page",
		      (pagemap_entry(g - 3 * 4096) & soft) != 0 && (pagemap_entry(g - 2 * 4096) & soft) == 0 &&
			      (pagemap_entry(g - 4096) & soft) == 0 && (pagemap_entry(g) & soft) == 0);
		munmap(g - 3 * 4096, 4 * 4096);
	}

	/* PM_GUARD_REGION (58) and PM_SWAP (62) for a guard page of MADV_GUARD_INSTALL (#444). */
	const unsigned long long guard = 1ULL << 58, swap = 1ULL << 62;
	m = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m != MAP_FAILED) {
		m[0] = 1;
		m[4096] = 1;
		check("pagemap: a guard page has PM_GUARD_REGION",
		      madvise(m, 4096, 102) == 0 && (pagemap_entry(m) & (guard | swap | (1ULL << 63))) == (guard | swap) &&
			      (pagemap_entry(m + 4096) & guard) == 0);
		check("pagemap: MADV_GUARD_REMOVE clears PM_GUARD_REGION",
		      madvise(m, 4096, 103) == 0 && (pagemap_entry(m) & (guard | swap)) == 0);
		munmap(m, 2 * 4096);
	}

	/* PM_MMAP_EXCLUSIVE counts the mappings of the page, not the page cache (#444). */
	int fd = open("/tmp/excl", O_CREAT | O_RDWR | O_TRUNC, 0600);
	char *a = MAP_FAILED, *b = MAP_FAILED;
	if (fd >= 0 && ftruncate(fd, 4096) == 0) {
		a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	}
	if (a != MAP_FAILED && b != MAP_FAILED) {
		a[0] = 1;
		check("pagemap: a page of a file with one mapping is exclusive", (pagemap_entry(a) & excl) != 0);
		check("pagemap: a page of a file with two mappings is not exclusive",
		      b[0] == 1 && (pagemap_entry(a) & excl) == 0 && (pagemap_entry(b) & excl) == 0);
		munmap(b, 4096);
		check("pagemap: the page is exclusive again after the munmap", (pagemap_entry(a) & excl) != 0);
		munmap(a, 4096);
	} else {
		check("mmap of /tmp/excl", 0);
	}
	if (fd >= 0)
		close(fd);
	unlink("/tmp/excl");

	/* A transparent huge page: KPF_THP (22), KPF_COMPOUND_HEAD (15) and KPF_COMPOUND_TAIL (16). */
	const unsigned long long thp = 1ULL << 22, head = 1ULL << 15, tail = 1ULL << 16;
	char *r = mmap(NULL, 4 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r == MAP_FAILED)
		return;
	char *h = (char *)(((unsigned long)r + (2 << 20) - 1) & ~((2UL << 20) - 1));
	madvise(h, 2 << 20, MADV_HUGEPAGE);
	h[0] = 1;
	unsigned long long f0 = kpageflags_entry(h), f1 = kpageflags_entry(h + 4096);
	check("kpageflags: a transparent huge page has KPF_THP and the compound flags",
	      (f0 & (thp | head | tail)) == (thp | head) && (f1 & (thp | head | tail)) == (thp | tail));
	munmap(r, 4 << 20);
}

/*
 * A write back makes the page read only in each process that wrote it, as folio_mkclean of
 * Linux, so the next write of any process marks the page dirty again (#430).
 */
static void test_mkclean(void)
{
	const unsigned long long dirty = 1ULL << 4;
	int fd = open("/tmp/mkclean", O_CREAT | O_RDWR | O_TRUNC, 0600);
	char *s = MAP_FAILED, c = 0;
	int go[2], done[2];
	if (fd >= 0 && ftruncate(fd, 4096) == 0)
		s = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (s == MAP_FAILED || pipe(go) != 0 || pipe(done) != 0) {
		check("mmap for mkclean", 0);
		return;
	}
	pid_t pid = fork();
	if (pid == 0) {
		/* The child writes after the parent, and its msync writes back the page of both. */
		read(go[0], &c, 1);
		s[1] = 'b';
		int ok = msync(s, 4096, MS_SYNC) == 0;
		write(done[1], &c, 1);
		_exit(ok ? 0 : 1);
	}
	s[0] = 'a';
	write(go[1], &c, 1);
	read(done[0], &c, 1);
	int status = 0;
	check("msync of another process", waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("kpageflags: the msync of another process makes the page clean", (kpageflags_entry(s) & dirty) == 0);
	s[2] = 'c';
	check("kpageflags: a write after the msync of another process makes the page dirty",
	      (kpageflags_entry(s) & dirty) != 0);
	char buf[4] = {0};
	check("msync writes the page", msync(s, 4096, MS_SYNC) == 0 && pread(fd, buf, 3, 0) == 3 && memcmp(buf, "abc", 3) == 0);
	munmap(s, 4096);
	close(fd);
	close(go[0]);
	close(go[1]);
	close(done[0]);
	close(done[1]);
	unlink("/tmp/mkclean");
}

/*
 * The file bit (61) of /proc/PID/pagemap comes from the page, and /proc/kpageflags gives KPF_ANON
 * (12) for an anonymous page, as fs/proc/task_mmu.c and fs/proc/page.c of Linux (#421).
 */
static void test_pagemap(void)
{
	const unsigned long long file = 1ULL << 61, anon = 1ULL << 12, dirty = 1ULL << 4;
	char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m != MAP_FAILED) {
		m[0] = 1;
		check("pagemap: an anonymous page has no file bit", (pagemap_entry(m) & ((1ULL << 63) | file)) == 1ULL << 63);
		check("kpageflags: an anonymous page has KPF_ANON", (kpageflags_entry(m) & anon) != 0);
		munmap(m, 4096);
	}
	int fd = open("/init", O_RDONLY);
	char *f = fd < 0 ? MAP_FAILED : mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (fd >= 0)
		close(fd);
	check("mmap of /init that can be written", f != MAP_FAILED);
	if (f != MAP_FAILED) {
		check("pagemap: a page of a private file mapping has the file bit", f[0] == 0x7f && (pagemap_entry(f) & file) != 0);
		check("kpageflags: a page of a file has no KPF_ANON", (kpageflags_entry(f) & anon) == 0);
		f[1] = 'X';
		check("pagemap: the copy of a written page has no file bit", (pagemap_entry(f) & file) == 0);
		check("kpageflags: the copy of a written page has KPF_ANON", (kpageflags_entry(f) & anon) != 0);
		munmap(f, 4096);
	}
	fd = open("/tmp/pagemap", O_CREAT | O_RDWR | O_TRUNC, 0600);
	char *s = MAP_FAILED;
	if (fd >= 0 && ftruncate(fd, 4096) == 0)
		s = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (s != MAP_FAILED) {
		s[0] = 1;
		check("kpageflags: a written page of a shared mapping is dirty", (kpageflags_entry(s) & (dirty | anon)) == dirty);
		check("msync of a shared mapping", msync(s, 4096, MS_SYNC) == 0);
		check("kpageflags: msync makes the page clean", (kpageflags_entry(s) & dirty) == 0);
		munmap(s, 4096);
	}
	if (fd >= 0)
		close(fd);
	unlink("/tmp/pagemap");
	test_soft_dirty();
	test_mkclean();
}

/* Gives the end of the area of /proc/self/maps that holds `addr`, or 0. */
static unsigned long maps_area_end(unsigned long addr)
{
	static char maps[65536];
	unsigned long a, b;

	if (read_file("/proc/self/maps", maps, sizeof(maps)) <= 0)
		return 0;
	for (char *line = maps; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL)
		if (sscanf(line, "%lx-%lx", &a, &b) == 2 && a <= addr && addr < b)
			return b;
	return 0;
}

/*
 * vma01 of LTP (#475): an area that a child of fork got with its pages does not join a new area
 * next to it, because its anon_vma chain is not singular (mm/vma.c of Linux). In the parent the
 * same two areas join.
 */
static void test_fork_area_merge(void)
{
	const unsigned long ps = 4096;
	char *t = mmap(NULL, 6 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (t == MAP_FAILED) {
		check("mmap for the area merge after fork", 0);
		return;
	}
	munmap(t + 3 * ps, 3 * ps);
	memset(t, 1, ps);
	int status = 0;
	pid_t pid = fork();
	if (pid == 0) {
		memset(t, 2, ps);
		char *u = mmap(t + 3 * ps, 3 * ps, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (u != t + 3 * ps)
			_exit(2);
		u[0] = 2;
		_exit(maps_area_end((unsigned long)t) == (unsigned long)u ? 0 : 1);
	}
	check("an area from fork does not join a new area next to it",
	      waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	char *u = mmap(t + 3 * ps, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	check("an area that is not from fork joins a new area next to it",
	      u == t + 3 * ps && maps_area_end((unsigned long)t) >= (unsigned long)(t + 6 * ps));
	munmap(t, 6 * ps);
}

/* A child that sets RLIMIT_CORE to `limit`, sets the dumpable flag and calls abort(). */
static int core_child(rlim_t limit, int dumpable)
{
	pid_t pid = fork();
	int status = 0;

	if (pid == 0) {
		struct rlimit rl = { limit, limit };

		setrlimit(RLIMIT_CORE, &rl);
		prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
		abort();
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid)
		return -1;
	return status;
}

/* Finds the note of type `type` with the name "CORE" in the notes at buf. */
static const unsigned char *core_note(const unsigned char *buf, size_t len, unsigned type, size_t *size)
{
	size_t off = 0;

	while (off + sizeof(Elf64_Nhdr) <= len) {
		const Elf64_Nhdr *n = (const Elf64_Nhdr *)(buf + off);
		size_t name = (n->n_namesz + 3) & ~3u, desc = (n->n_descsz + 3) & ~3u;
		const unsigned char *p = buf + off + sizeof(*n);

		if (off + sizeof(*n) + name + desc > len)
			return 0;
		if (n->n_type == type && n->n_namesz == 5 && !memcmp(p, "CORE", 5)) {
			*size = n->n_descsz;
			return p + name;
		}
		off += sizeof(*n) + name + desc;
	}
	return 0;
}

/* The ELF core dump of fs/coredump.c and fs/binfmt_elf.c of Linux (#475). */
static void test_core_dump(void)
{
	static unsigned char notes[65536];
	char buf[256], name[300];
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	const unsigned char *d;
	size_t size = 0, notes_len = 0;
	int status, fd, i, loads = 0;
	pid_t pid;

	check("core_pattern is core by default",
	      read_file("/proc/sys/kernel/core_pattern", buf, sizeof(buf)) == 5 && !strcmp(buf, "core\n"));
	check("prctl PR_GET_DUMPABLE gives 1", prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
	check("prctl PR_SET_DUMPABLE 2 gives EINVAL", prctl(PR_SET_DUMPABLE, 2, 0, 0, 0) == -1 && errno == EINVAL);
	check("fs.suid_dumpable above 2 gives EINVAL", put_file("/proc/sys/fs/suid_dumpable", "3") == -1 && errno == EINVAL);
	check("write core_pattern", put_file("/proc/sys/kernel/core_pattern", "/tmp/core.%e.%p") == 0);
	check("read core_pattern",
	      read_file("/proc/sys/kernel/core_pattern", buf, sizeof(buf)) > 0 && !strcmp(buf, "/tmp/core.%e.%p\n"));

	/* RLIMIT_CORE of 0 and a process that is not dumpable give no dump. */
	status = core_child(0, 1);
	check("RLIMIT_CORE 0 gives SIGABRT without WCOREDUMP",
	      WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT && !WCOREDUMP(status));
	status = core_child(RLIM_INFINITY, 0);
	check("PR_SET_DUMPABLE 0 gives no core dump", WIFSIGNALED(status) && !WCOREDUMP(status));

	pid = fork();
	if (pid == 0) {
		struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

		setrlimit(RLIMIT_CORE, &rl);
		abort();
	}
	status = 0;
	check("abort with RLIMIT_CORE gives WCOREDUMP",
	      waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT &&
		      WCOREDUMP(status));
	snprintf(name, sizeof(name), "/tmp/core.init.%d", pid);
	fd = open(name, O_RDONLY);
	check("the core file has the name of core_pattern", fd >= 0);
	memset(&eh, 0, sizeof(eh));
	check("the core file has an ELF header of ET_CORE",
	      pread(fd, &eh, sizeof(eh), 0) == sizeof(eh) && !memcmp(eh.e_ident, ELFMAG, SELFMAG) &&
		      eh.e_ident[EI_CLASS] == ELFCLASS64 && eh.e_type == ET_CORE &&
#if defined(__aarch64__)
		      eh.e_machine == EM_AARCH64 &&
#else
		      eh.e_machine == EM_X86_64 &&
#endif
		      eh.e_phentsize == sizeof(Elf64_Phdr) && eh.e_phnum > 1);
	for (i = 0; fd >= 0 && i < eh.e_phnum && i < 4096; i++) {
		if (pread(fd, &ph, sizeof(ph), eh.e_phoff + i * sizeof(ph)) != sizeof(ph))
			break;
		if (ph.p_type == PT_NOTE && i == 0 && ph.p_filesz <= sizeof(notes))
			notes_len = pread(fd, notes, ph.p_filesz, ph.p_offset) == (ssize_t)ph.p_filesz ? ph.p_filesz : 0;
		if (ph.p_type == PT_LOAD)
			loads++;
	}
	check("the core file has a PT_NOTE first and a PT_LOAD for each area", notes_len > 0 && loads == eh.e_phnum - 1);
	d = core_note(notes, notes_len, NT_PRSTATUS, &size);
	/* struct elf_prstatus: pr_info.si_signo at 0, pr_pid at 32. */
	check("NT_PRSTATUS has the signal and the pid",
	      d && size >= 112 && *(const int *)d == SIGABRT && *(const short *)(d + 12) == SIGABRT &&
		      *(const int *)(d + 32) == pid);
	d = core_note(notes, notes_len, NT_PRPSINFO, &size);
	/* struct elf_prpsinfo: pr_pid at 24, pr_fname at 40. */
	check("NT_PRPSINFO has the pid and the name",
	      d && size == 136 && *(const int *)(d + 24) == pid && !strcmp((const char *)d + 40, "init"));
	d = core_note(notes, notes_len, 0x53494749, &size);
	check("NT_SIGINFO has SIGABRT", d && size == 128 && *(const int *)d == SIGABRT);
	d = core_note(notes, notes_len, NT_AUXV, &size);
	check("NT_AUXV ends with AT_NULL", d && size >= 16 && size % 16 == 0 && *(const long *)(d + size - 16) == AT_NULL);
	check("the core file has NT_FILE and NT_PRFPREG",
	      core_note(notes, notes_len, 0x46494c45, &size) && core_note(notes, notes_len, NT_PRFPREG, &size));
	if (fd >= 0)
		close(fd);
	unlink(name);

	/* core_uses_pid adds ".PID" to a pattern without %p. */
	put_file("/proc/sys/kernel/core_pattern", "/tmp/core");
	check("write core_uses_pid", put_file("/proc/sys/kernel/core_uses_pid", "1") == 0);
	status = core_child(RLIM_INFINITY, 1);
	check("abort with core_uses_pid gives WCOREDUMP", WIFSIGNALED(status) && WCOREDUMP(status));
	{
		DIR *dir = opendir("/tmp");
		struct dirent *e;
		int found = 0;

		while (dir && (e = readdir(dir)))
			if (!strncmp(e->d_name, "core.", 5) && e->d_name[5] >= '1' && e->d_name[5] <= '9') {
				snprintf(name, sizeof(name), "/tmp/%s", e->d_name);
				unlink(name);
				found++;
			}
		if (dir)
			closedir(dir);
		check("core_uses_pid gives the name core.PID", found == 1);
	}
	put_file("/proc/sys/kernel/core_uses_pid", "0");
	put_file("/proc/sys/kernel/core_pattern", "core");
}

static void test_proc(void)
{
	char buf[4096], want[64], link[256];
	struct statfs st;
	ssize_t n;
	int fd;

	mkdir("/proc", 0555);
	check("mount proc", mount("proc", "/proc", "proc", 0, NULL) == 0);
	check("statfs gives PROC_SUPER_MAGIC", statfs("/proc", &st) == 0 && st.f_type == 0x9fa0);
	check("/proc/meminfo", read_file("/proc/meminfo", buf, sizeof(buf)) > 0 && !strncmp(buf, "MemTotal:", 9));
	snprintf(want, sizeof(want), "%d (init) R 0 ", getpid());
	check("/proc/self/stat", read_file("/proc/self/stat", buf, sizeof(buf)) > 0 && !strncmp(buf, want, strlen(want)));
	check("/proc/self/status", read_file("/proc/self/status", buf, sizeof(buf)) > 0 && strstr(buf, "\nState:\tR (running)\n"));
	check("/proc/self/cmdline", read_file("/proc/self/cmdline", buf, sizeof(buf)) > 0 && !strcmp(buf, "/init"));
	check("/proc/self/maps names the stack", read_file("/proc/self/maps", buf, sizeof(buf)) > 0 && strstr(buf, "[stack]\n") &&
						   strstr(buf, "[vvar]\n") && strstr(buf, "[vdso]\n"));
	check("/proc/mounts", read_file("/proc/mounts", buf, sizeof(buf)) > 0 && strstr(buf, "proc /proc proc rw,relatime 0 0\n"));
	n = readlink("/proc/self/exe", link, sizeof(link) - 1);
	check("/proc/self/exe", n == 5 && !strncmp(link, "/init", 5));
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	check("/proc/sys/kernel/pid_max", fd >= 0 && read(fd, buf, sizeof(buf)) == 8 && !strncmp(buf, "4194304\n", 8));
	close(fd);
	mkdir("/tmp/sticky", 0777);
	chmod("/tmp/sticky", 01777);
	symlink("/proc/self/exe", "/tmp/sticky/link");
	lchown("/tmp/sticky/link", 1000, 1000);
	check("fs.protected_symlinks above 1 gives EINVAL",
	      put_file("/proc/sys/fs/protected_symlinks", "2") == -1 && errno == EINVAL);
	check("fs.protected_symlinks refuses a link of another user in a sticky directory",
	      put_file("/proc/sys/fs/protected_symlinks", "1") == 0 &&
		      access("/tmp/sticky/link", F_OK) == -1 && errno == EACCES);
	check("fs.protected_symlinks of 0 follows the link",
	      put_file("/proc/sys/fs/protected_symlinks", "0") == 0 &&
		      access("/tmp/sticky/link", F_OK) == 0);
	unlink("/tmp/sticky/link");
	rmdir("/tmp/sticky");
	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	check("write /proc/self/oom_score_adj", fd >= 0 && write(fd, "-500\n", 5) == 5);
	close(fd);
	check("read /proc/self/oom_score_adj", read_file("/proc/self/oom_score_adj", buf, sizeof(buf)) == 5 && !strcmp(buf, "-500\n"));
	/* madvise08 of LTP (#475): the default of Linux is 0x33, and a child of fork keeps the value. */
	check("read /proc/self/coredump_filter",
	      read_file("/proc/self/coredump_filter", buf, sizeof(buf)) == 9 && !strcmp(buf, "00000033\n"));
	check("write /proc/self/coredump_filter", put_file("/proc/self/coredump_filter", "0x7f") == 0);
	pid_t cpid = fork();
	if (cpid == 0)
		_exit(read_file("/proc/self/coredump_filter", buf, sizeof(buf)) == 9 && !strcmp(buf, "0000007f\n") ? 0 : 1);
	int cstatus = 0;
	check("a child of fork keeps the coredump_filter",
	      waitpid(cpid, &cstatus, 0) == cpid && WIFEXITED(cstatus) && WEXITSTATUS(cstatus) == 0);
	check("coredump_filter keeps only the 9 bits of the filter",
	      put_file("/proc/self/coredump_filter", "0xffff") == 0 &&
		      read_file("/proc/self/coredump_filter", buf, sizeof(buf)) == 9 && !strcmp(buf, "000001ff\n"));
	check("coredump_filter refuses a text that is not a number",
	      put_file("/proc/self/coredump_filter", "x") == -1 && errno == EINVAL);
	put_file("/proc/self/coredump_filter", "0x33");
	test_core_dump();
	errno = 0;
	check("/proc/self/nothing gives ENOENT", open("/proc/self/nothing", O_RDONLY) == -1 && errno == ENOENT);
	test_pagemap();
	test_fork_area_merge();
	check("umount proc", umount("/proc") == 0);
}

static void test_tty(void)
{
	char buf[64];
	memset(buf, 0, sizeof(buf));
	printf("init: type a line\n");
	ssize_t n = read(0, buf, sizeof(buf));
	check("read of a line from the console", n == 6 && strcmp(buf, "hello\n") == 0);

	pid_t pid = fork();
	if (pid == 0) {
		setpgid(0, 0);
		for (;;)
			;
	}
	setpgid(pid, pid);
	check("tcsetpgrp to the child", tcsetpgrp(0, pid) == 0 && tcgetpgrp(0) == pid);
	printf("init: press ^C\n");
	int status = 0;
	check("^C stops the foreground job", waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
						    WTERMSIG(status) == SIGINT);
	/* init is in the background now. A shell ignores SIGTTOU to take the terminal back, as
	 * tty_check_change in drivers/tty/tty_jobctrl.c of Linux sends SIGTTOU otherwise. */
	signal(SIGTTOU, SIG_IGN);
	check("tcsetpgrp back to init", tcsetpgrp(0, getpgrp()) == 0);
	signal(SIGTTOU, SIG_DFL);
}

/* The load of hackbench in its process mode: each group has HB_FDS senders and HB_FDS receivers,
 * and each sender writes HB_LOOPS messages of HB_SIZE bytes to each receiver of its group through
 * a socket pair. */
#define HB_GROUPS 4
#define HB_FDS 10
#define HB_LOOPS 100
#define HB_SIZE 100

static void hb_receiver(int fd)
{
	char buf[HB_SIZE];
	size_t want = (size_t)HB_FDS * HB_LOOPS * HB_SIZE;
	while (want > 0) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0)
			_exit(1);
		want -= (size_t)n;
	}
	_exit(0);
}

static void hb_sender(const int *fds, int start)
{
	char buf[HB_SIZE] = {0}, go;
	if (read(start, &go, 1) != 1)
		_exit(1);
	for (int i = 0; i < HB_LOOPS; i++)
		for (int j = 0; j < HB_FDS; j++)
			for (size_t done = 0; done < sizeof(buf);) {
				ssize_t n = write(fds[j], buf + done, sizeof(buf) - done);
				if (n <= 0)
					_exit(1);
				done += (size_t)n;
			}
	_exit(0);
}

/* The byte at offset k of the disk of the blk boot test. xtask writes the same pattern. */
static unsigned char disk_byte(long k)
{
	return (unsigned char)(k / 512 * 7 + k % 251);
}

#define DISK_SIZE (1024 * 1024)
#define DISK_NOTE_AT (512 * 9 + 100)
#define DISK_NOTE "rukernel wrote this sector"

/* Reads 8 blocks of 4 KiB with one io_submit, in a mixed order, and writes one block with
 * IOCB_CMD_PWRITEV. The block layer merges the near reads. */
static void test_aio(int fd)
{
	aio_context_t ctx = 0;
	check("io_setup makes a context", syscall(SYS_io_setup, 16, &ctx) == 0 && ctx != 0);
	aio_context_t again = ctx;
	check("io_setup with a used context ID gives EINVAL",
	      syscall(SYS_io_setup, 16, &again) == -1 && errno == EINVAL);
	static unsigned char bufs[8][4096];
	struct iocb cbs[8], *list[8];
	static const int order[8] = { 3, 1, 2, 0, 7, 5, 6, 4 };
	for (int i = 0; i < 8; i++) {
		int b = order[i];
		memset(&cbs[i], 0, sizeof(cbs[i]));
		cbs[i].aio_data = b;
		cbs[i].aio_lio_opcode = IOCB_CMD_PREAD;
		cbs[i].aio_fildes = fd;
		cbs[i].aio_buf = (unsigned long)bufs[b];
		cbs[i].aio_nbytes = 4096;
		cbs[i].aio_offset = 65536 + b * 4096;
		list[i] = &cbs[i];
	}
	check("io_submit takes 8 reads", syscall(SYS_io_submit, ctx, 8, list) == 8);
	struct io_event ev[8];
	struct timespec ts = { 5, 0 };
	int n = syscall(SYS_io_getevents, ctx, 8, 8, ev, &ts);
	int ok = n == 8;
	for (int i = 0; ok && i < 8; i++)
		ok = ev[i].res == 4096 && ev[i].obj == (unsigned long)&cbs[i] && ev[i].data == (unsigned)order[i];
	for (int b = 0; ok && b < 8; b++)
		for (int k = 0; ok && k < 4096; k++)
			ok = bufs[b][k] == disk_byte(65536 + b * 4096 + k);
	check("io_getevents gives 8 events with the disk data", ok);
	check("io_getevents with no event and a time out of 0 gives 0",
	      syscall(SYS_io_getevents, ctx, 0, 8, ev, &(struct timespec){ 0, 0 }) == 0);

	memset(bufs[0], 0x5a, 512);
	memset(bufs[1], 0xa5, 512);
	struct iovec iov[2] = { { bufs[0], 512 }, { bufs[1], 512 } };
	struct iocb w = { .aio_lio_opcode = IOCB_CMD_PWRITEV, .aio_fildes = fd,
			  .aio_buf = (unsigned long)iov, .aio_nbytes = 2, .aio_offset = 512 * 100 };
	struct iocb s = { .aio_lio_opcode = IOCB_CMD_FSYNC, .aio_fildes = fd };
	struct iocb *wl[2] = { &w, &s };
	ok = syscall(SYS_io_submit, ctx, 2, wl) == 2 && syscall(SYS_io_getevents, ctx, 2, 2, ev, NULL) == 2 &&
	     ev[0].res == 1024 && ev[1].res == 0;
	check("io_submit of a pwritev and an fsync", ok);
	unsigned char back[1024];
	ok = pread(fd, back, 1024, 512 * 100) == 1024;
	for (int k = 0; ok && k < 1024; k++)
		ok = back[k] == (k < 512 ? 0x5a : 0xa5);
	check("pread gives the data of the pwritev", ok);
	memset(bufs[2], 0x3c, 512);
	struct iovec wv[2] = { { bufs[2], 256 }, { bufs[2] + 256, 256 } };
	check("pwritev2 with RWF_DSYNC", syscall(SYS_pwritev2, fd, wv, 2, 512 * 100, 0, RWF_DSYNC) == 512);
	memset(back, 0, sizeof(back));
	struct iovec rv[2] = { { back, 100 }, { back + 100, 924 } };
	ok = syscall(SYS_preadv, fd, rv, 2, 512 * 100, 0) == 1024;
	for (int k = 0; ok && k < 1024; k++)
		ok = back[k] == (k < 512 ? 0x3c : 0xa5);
	check("preadv gives the data of the pwritev2", ok);
	check("preadv with an offset of -1 gives EINVAL",
	      syscall(SYS_preadv, fd, rv, 2, -1L, 0) == -1 && errno == EINVAL);
	check("preadv2 with an unknown flag gives EOPNOTSUPP",
	      syscall(SYS_preadv2, fd, rv, 2, 0, 0, 0x10000) == -1 && errno == EOPNOTSUPP);
	struct iocb bad = { .aio_lio_opcode = 99, .aio_fildes = fd };
	struct iocb *bl[1] = { &bad };
	check("io_submit of an unknown command gives EINVAL",
	      syscall(SYS_io_submit, ctx, 1, bl) == -1 && errno == EINVAL);
	check("io_destroy", syscall(SYS_io_destroy, ctx) == 0);
	check("io_submit after io_destroy gives EINVAL",
	      syscall(SYS_io_submit, ctx, 1, list) == -1 && errno == EINVAL);
}

/* The range that test_cache writes, and the byte at offset k of it. xtask has the same values. */
#define CACHED_AT (512 * 1024)
#define CACHED_LEN (512 * 1024)
static unsigned char cached_byte(long k)
{
	return (unsigned char)(k * 13 + k / 4096);
}

/* Writes 512 KiB through the page cache, and then calls sync. xtask checks the data on the disk. */
static void test_cache(int fd)
{
	static unsigned char buf[CACHED_LEN];
	int ok;

	for (long k = 0; k < CACHED_LEN; k++)
		buf[k] = cached_byte(CACHED_AT + k);
	/* A write of part of a page first, so that the cache reads the other bytes of the page. */
	ok = pwrite(fd, buf + 1000, 3000, CACHED_AT + 1000) == 3000;
	ok = ok && pwrite(fd, buf, 1000, CACHED_AT) == 1000;
	ok = ok && pwrite(fd, buf + 4000, CACHED_LEN - 4000, CACHED_AT + 4000) == CACHED_LEN - 4000;
	check("pwrite of 512 KiB through the page cache", ok);
	memset(buf, 0, sizeof(buf));
	ok = pread(fd, buf, CACHED_LEN, CACHED_AT) == CACHED_LEN;
	for (long k = 0; ok && k < CACHED_LEN; k++)
		ok = buf[k] == cached_byte(CACHED_AT + k);
	check("pread gives the data in the page cache", ok);
	sync();
	check("BLKFLSBUF drops the page cache", ioctl(fd, BLKFLSBUF, 0) == 0);
	memset(buf, 0, sizeof(buf));
	ok = pread(fd, buf, CACHED_LEN, CACHED_AT) == CACHED_LEN;
	for (long k = 0; ok && k < CACHED_LEN; k++)
		ok = buf[k] == cached_byte(CACHED_AT + k);
	check("pread after sync gives the data from the disk", ok);
	errno = 0;
	check("syncfs of a bad descriptor gives EBADF", syncfs(-1) == -1 && errno == EBADF);
}

/* The size of the file that test_ext2 writes in chunks of 1 MiB, as the page cache of
 * memcontrol03 of LTP. */
#define EXT2_FILE_SIZE (50 << 20)

/* The size of the file that test_ext2 writes in chunks of 1 KiB. The debug kernel takes about
 * 150 s for 50 MB in chunks of 1 KiB, so the boot test writes less. */
#define EXT2_SMALL_SIZE (4 << 20)

/* Writes size bytes to the new file path in chunks of chunk bytes, and calls fsync. The first 8
 * bytes of each 1 MiB have the number of the MiB. Gives the time in ms, or -1. */
static long long ext2_write(const char *path, long size, size_t chunk)
{
	static unsigned char buf[1 << 20];
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0)
		return -1;
	long long start = clock_ms(CLOCK_MONOTONIC);
	int ok = 1;
	for (long at = 0; ok && at < size; at += chunk) {
		if (at % sizeof(buf) == 0) {
			memset(buf, (int)(at >> 20), sizeof(buf));
			memcpy(buf, &at, sizeof(at));
		}
		ok = write(fd, buf + at % sizeof(buf), chunk) == (ssize_t)chunk;
	}
	ok = ok && fsync(fd) == 0;
	long long ms = clock_ms(CLOCK_MONOTONIC) - start;
	return close(fd) == 0 && ok ? ms : -1;
}

/* Tells if the file path has the size bytes of ext2_write. */
static int ext2_data_ok(const char *path, long size)
{
	struct stat st;
	int fd = open(path, O_RDONLY);
	int ok = fd >= 0 && fstat(fd, &st) == 0 && st.st_size == size && st.st_blocks >= size / 512;
	for (long at = 0; ok && at < size; at += 1 << 20) {
		unsigned char got[16];
		long first;
		ok = pread(fd, got, sizeof(got), at) == sizeof(got);
		memcpy(&first, got, sizeof(first));
		ok = ok && first == at && got[8] == (unsigned char)(at >> 20) &&
		     pread(fd, got, 1, at + (1 << 20) - 1) == 1 && got[0] == (unsigned char)(at >> 20);
	}
	if (fd >= 0)
		close(fd);
	return ok;
}

static int cg_write(const char *path, const char *s);

/* Runs ext2_write of EXT2_SMALL_SIZE bytes in chunks of 1 KiB in a child in the memory cgroup cg, as the
 * children of memcontrol03. Gives the time in ms, or -1. */
static long long ext2_write_in_cgroup(const char *cg)
{
	int p[2];
	long long ms = -1;
	if (pipe(p) != 0)
		return -1;
	pid_t pid = fork();
	if (pid == 0) {
		char path[64];
		snprintf(path, sizeof(path), "%s/cgroup.procs", cg);
		ms = cg_write(path, "0") == 0 ? ext2_write("/ext2/small", EXT2_SMALL_SIZE, 1024) : -1;
		_exit(write(p[1], &ms, sizeof(ms)) == sizeof(ms) ? 0 : 1);
	}
	close(p[1]);
	if (pid < 0 || read(p[0], &ms, sizeof(ms)) != sizeof(ms))
		ms = -1;
	close(p[0]);
	int status;
	if (pid > 0 && (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0))
		ms = -1;
	return ms;
}

/* Writes 50 MB to a file on the ext2 disk /dev/vdb of the blk boot test, and calls fsync, as
 * memcontrol03 and memcontrol04 of LTP. xtask makes the disk with mkfs.ext2, as LTP does. The
 * test writes in chunks of 1 MiB. Then it writes 4 MB in chunks of 1 KiB, the BUFSIZ of musl that
 * LTP uses, in a child in a memory cgroup with a memory.max of 200 MB, as the children of
 * memcontrol03. Under QEMU without KVM, LTP waits 10 s for the write, so the times show if it
 * can pass. */
static void test_ext2(void)
{
	if (access("/dev/vdb", F_OK) != 0) {
		printf("init: the blk boot test has no ext2 disk\n");
		return;
	}
	mkdir("/ext2", 0755);
	int mounted = mount("/dev/vdb", "/ext2", "ext2", 0, NULL) == 0;
	check("mount of the ext2 disk", mounted);
	if (!mounted)
		return;
	long long big = ext2_write("/ext2/big", EXT2_FILE_SIZE, 1 << 20);
	check("write of 50 MB to ext2 in chunks of 1 MiB and fsync", big >= 0 && ext2_data_ok("/ext2/big", EXT2_FILE_SIZE));
	mkdir("/ext2cg", 0755);
	int cg = mount("none", "/ext2cg", "cgroup2", 0, NULL) == 0 &&
		 cg_write("/ext2cg/cgroup.subtree_control", "+memory") == 0 && mkdir("/ext2cg/ext2w", 0755) == 0 &&
		 cg_write("/ext2cg/ext2w/memory.max", "200M") == 0;
	check("a memory cgroup for the ext2 write", cg);
	long long small = cg ? ext2_write_in_cgroup("/ext2cg/ext2w") : -1;
	check("write of 4 MB to ext2 in chunks of 1 KiB and fsync in a memory cgroup",
	      small >= 0 && ext2_data_ok("/ext2/small", EXT2_SMALL_SIZE));
	printf("init: ext2 write takes %lld ms for 50 MB in chunks of 1 MiB, %lld ms for 4 MB in chunks of 1 KiB\n",
	       big, small);
	check("unlink of the ext2 files", unlink("/ext2/big") == 0 && unlink("/ext2/small") == 0);
	check("rmdir of the memory cgroup", rmdir("/ext2cg/ext2w") == 0 && umount("/ext2cg") == 0);
	rmdir("/ext2cg");
	check("umount of the ext2 disk", umount("/ext2") == 0);
}

static void test_blk(void)
{
	test_ext2();
	int fd = open("/dev/vda", O_RDWR);
	check("/dev/vda opens", fd >= 0);
	if (fd < 0)
		return;
	struct stat st;
	check("/dev/vda is a block device with the major 254",
	      fstat(fd, &st) == 0 && S_ISBLK(st.st_mode) && major(st.st_rdev) == 254 &&
		      minor(st.st_rdev) == 0);
	unsigned long long size = 0;
	check("BLKGETSIZE64 gives the disk size",
	      ioctl(fd, BLKGETSIZE64, &size) == 0 && size == DISK_SIZE);
	int ssz = 0;
	check("BLKSSZGET gives 512", ioctl(fd, BLKSSZGET, &ssz) == 0 && ssz == 512);
	check("lseek to the end gives the disk size", lseek(fd, 0, SEEK_END) == DISK_SIZE);

	static unsigned char buf[200 * 1024];
	int ok = pread(fd, buf, 1000, 3000) == 1000;
	for (int i = 0; ok && i < 1000; i++)
		ok = buf[i] == disk_byte(3000 + i);
	check("pread of part of some sectors gives the disk data", ok);
	ok = pread(fd, buf, sizeof(buf), 4096) == sizeof(buf);
	for (long i = 0; ok && i < (long)sizeof(buf); i++)
		ok = buf[i] == disk_byte(4096 + i);
	check("pread of 200 KiB gives the disk data", ok);
	check("pread at the end gives 0", pread(fd, buf, 10, DISK_SIZE) == 0);

	ok = pwrite(fd, DISK_NOTE, strlen(DISK_NOTE), DISK_NOTE_AT) == (ssize_t)strlen(DISK_NOTE);
	check("pwrite to the disk", ok);
	check("fsync of the disk", fsync(fd) == 0);
	memset(buf, 0, 1024);
	ok = pread(fd, buf, 1024, 512 * 9) == 1024 && memcmp(buf + 100, DISK_NOTE, strlen(DISK_NOTE)) == 0;
	for (int i = 0; ok && i < 100; i++)
		ok = buf[i] == disk_byte(512 * 9 + i);
	for (int i = 100 + (int)strlen(DISK_NOTE); ok && i < 1024; i++)
		ok = buf[i] == disk_byte(512 * 9 + i);
	check("pread after pwrite gives the new data and keeps the other bytes", ok);
	test_aio(fd);
	test_cache(fd);
	close(fd);
}

/* The rounds of each check of system calls on several CPUs at the same time (#405). */
#define PAR_ROUNDS 2000

/* Pins the calling thread to the CPU `c`. */
static void pin_cpu(int c)
{
	cpu_set_t one;
	CPU_ZERO(&one);
	CPU_SET(c, &one);
	sched_setaffinity(0, sizeof(one), &one);
}

/* The word of a futex ping-pong, and the waits that timed out. */
static volatile int par_word;
static int par_timeouts;

/* One side of a futex ping-pong on the CPU `arg`: it waits for its turn, then gives the turn to
 * the other side. A lost wake gives a timeout. */
static void *par_futex(void *arg)
{
	int cpu = (int)(long)arg, me = cpu & 1;
	pin_cpu(cpu);
	for (int i = 0; i < PAR_ROUNDS; i++) {
		int w;
		while ((w = __atomic_load_n(&par_word, __ATOMIC_ACQUIRE)) != me) {
			struct timespec ts = { 1, 0 };
			if (syscall(SYS_futex, &par_word, FUTEX_WAIT_PRIVATE, w, &ts) == -1 &&
			    errno == ETIMEDOUT)
				__atomic_fetch_add(&par_timeouts, 1, __ATOMIC_RELAXED);
		}
		__atomic_store_n(&par_word, !me, __ATOMIC_RELEASE);
		syscall(SYS_futex, &par_word, FUTEX_WAKE_PRIVATE, 1);
	}
	return NULL;
}

/* The sockets of the datagram check, and the result of each side. */
static int par_fds[2], par_ok[2];

/* Sends a datagram to the other socket of the pair and takes one from it, while the other side
 * does the same on another CPU. Both sockets have SO_PASSCRED. */
static void *par_dgram(void *arg)
{
	int side = (int)(long)arg;
	pin_cpu(side);
	char buf[64];
	int ok = 1;
	for (int i = 0; i < PAR_ROUNDS && ok; i++)
		ok = send(par_fds[side], "ping", 4, 0) == 4 &&
		     recv(par_fds[side], buf, sizeof(buf), 0) == 4;
	par_ok[side] = ok;
	return NULL;
}

/* The reads that gave EFAULT, and the end of the forks. */
static int par_efault, par_done;

/* Reads into new pages while the main thread forks on another CPU. A fork makes the private pages
 * read only, so the read must fault the page in again and not give EFAULT. */
static void *par_read(void *arg)
{
	pin_cpu((int)(long)arg);
	int fd = open("/dev/zero", O_RDONLY);
	while (fd >= 0 && !__atomic_load_n(&par_done, __ATOMIC_ACQUIRE)) {
		char *m = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED)
			break;
		for (int j = 0; j < 16; j++) {
			m[j * 4096] = 1;
			if (read(fd, m + j * 4096, 4096) < 0 && errno == EFAULT)
				__atomic_fetch_add(&par_efault, 1, __ATOMIC_RELAXED);
		}
		munmap(m, 16 * 4096);
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

/* Calls getpid on the CPU `arg`, and gives 1 if each call gives the same value. */
static void *par_getpid(void *arg)
{
	pin_cpu((int)(long)arg);
	pid_t pid = getpid();
	long same = 1;
	for (int i = 0; i < 20 * PAR_ROUNDS; i++)
		same &= getpid() == pid;
	return (void *)same;
}

/* The area of par_fault, its size in pages and the number of threads. */
static volatile char *par_area;
#define PAR_PAGES 2048
static int par_threads;

/* Writes the byte `arg` of each page of par_area, from a different start on each CPU. The threads
 * fault the same pages and different 2 MiB blocks at the same time. Each fault must map the page
 * once, and no write may be lost, as with the split page table locks of Linux (mm/memory.c). */
static void *par_fault(void *arg)
{
	long i = (long)arg;
	pin_cpu((int)i);
	for (int k = 0; k < PAR_PAGES; k++) {
		int p = (k + (int)i * PAR_PAGES / par_threads) % PAR_PAGES;
		par_area[p * 4096 + i] = (char)(i + 1);
	}
	return NULL;
}

/* The file of par_file, its size in pages, and the pages that par_file read with a wrong byte. */
#define PAR_FILE "/tmp/smp-map"
#define PAR_FILE_PAGES 256
static int par_file_bad;

/* The byte of the page `p` of PAR_FILE. */
static char par_file_byte(int p)
{
	return (char)(p % 127 + 1);
}

/* Maps PAR_FILE on the CPU `arg` and reads each page from a different start, while the other CPUs
 * fault the same pages. A thread with an odd number also writes the same bytes back through a
 * shared mapping, and msync and munmap write the pages back to the file. The page faults read the
 * file without the lock of the address space, as filemap_fault of Linux (mm/filemap.c), and the
 * first read of a page wins. */
static void *par_file(void *arg)
{
	long i = (long)arg;
	pin_cpu((int)i);
	int fd = open(PAR_FILE, O_RDWR);
	for (int round = 0; fd >= 0 && round < 8; round++) {
		int shared = (i & 1) != 0;
		char *m = mmap(NULL, PAR_FILE_PAGES * 4096, shared ? PROT_READ | PROT_WRITE : PROT_READ,
			       shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
		if (m == MAP_FAILED) {
			__atomic_fetch_add(&par_file_bad, 1, __ATOMIC_RELAXED);
			break;
		}
		for (int k = 0; k < PAR_FILE_PAGES; k++) {
			int p = (k + (int)i * PAR_FILE_PAGES / par_threads + round * 7) % PAR_FILE_PAGES;
			if (m[p * 4096 + 100] != par_file_byte(p))
				__atomic_fetch_add(&par_file_bad, 1, __ATOMIC_RELAXED);
			if (shared)
				m[p * 4096 + 100] = par_file_byte(p);
		}
		if (shared)
			msync(m, PAR_FILE_PAGES * 4096, MS_SYNC);
		munmap(m, PAR_FILE_PAGES * 4096);
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

/* Makes PAR_FILE and runs par_file on `n` CPUs. Gives 1 if each read gave the right byte. */
static int par_file_run(int n)
{
	static char page[4096];
	pthread_t t[4];
	int fd = open(PAR_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
	int ok = fd >= 0;
	for (int p = 0; p < PAR_FILE_PAGES && ok; p++) {
		memset(page, par_file_byte(p), sizeof(page));
		ok = write(fd, page, sizeof(page)) == sizeof(page);
	}
	if (fd >= 0)
		close(fd);
	if (!ok)
		return 0;
	par_file_bad = 0;
	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_file, (void *)(long)i);
	for (int i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	char c = 0;
	fd = open(PAR_FILE, O_RDONLY);
	ok = fd >= 0 && pread(fd, &c, 1, 5 * 4096 + 100) == 1 && c == par_file_byte(5);
	if (fd >= 0)
		close(fd);
	unlink(PAR_FILE);
	return ok && par_file_bad == 0;
}

/* The mappings of par_mm that had a wrong byte or failed, and the brk calls that failed. */
static int par_mm_bad;

/* Maps, writes, checks and unmaps areas on the CPU `arg`, while the other CPUs do the same. Each
 * thread writes its number to each page of its area, so two areas that overlap give a wrong byte.
 * The thread 0 also moves the end of the heap, and the thread 1 makes the pages clean in the
 * soft-dirty state. These calls do not share a lock of the heap or of the reserved ranges (#405),
 * as Linux keeps brk under mmap_lock and searches for a free range in vm_unmapped_area. */
static void *par_mm(void *arg)
{
	long i = (long)arg;
	pin_cpu((int)i);
	long heap = i == 0 ? syscall(SYS_brk, 0) : 0;
	for (int k = 0; k < 200; k++) {
		int pages = 1 + (k + (int)i) % 5;
		char *m = mmap(NULL, pages * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			       -1, 0);
		if (m == MAP_FAILED) {
			__atomic_fetch_add(&par_mm_bad, 1, __ATOMIC_RELAXED);
			break;
		}
		for (int p = 0; p < pages; p++)
			m[p * 4096 + 7] = (char)(i + 1);
		sched_yield();
		for (int p = 0; p < pages; p++)
			if (m[p * 4096 + 7] != (char)(i + 1))
				__atomic_fetch_add(&par_mm_bad, 1, __ATOMIC_RELAXED);
		munmap(m, pages * 4096);
		if (i == 0 && heap > 0) {
			long top = heap + 4096 * (1 + k % 4);
			if (syscall(SYS_brk, top) != top) {
				__atomic_fetch_add(&par_mm_bad, 1, __ATOMIC_RELAXED);
			} else {
				((char *)heap)[k % 4096] = 1;
				if (syscall(SYS_brk, heap) != heap)
					__atomic_fetch_add(&par_mm_bad, 1, __ATOMIC_RELAXED);
			}
		}
		if (i == 1 && k % 20 == 0)
			write_text("/proc/self/clear_refs", "4");
	}
	return NULL;
}

/* Runs par_mm on `n` CPUs. Gives 1 if each area kept its bytes and each brk call worked. */
static int par_mm_run(int n)
{
	pthread_t t[4];
	par_mm_bad = 0;
	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_mm, (void *)(long)i);
	for (int i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	return par_mm_bad == 0;
}

static long cg_value(const char *path, const char *key);
static int wait_status(pid_t pid);

/* The forks of par_cg that failed. */
static int par_cg_failed;

/* Forks and reaps children and maps new pages on the CPU `arg`, in the cgroup of the process. The
 * charges of the pids and the memory change on each CPU at the same time, without one lock for
 * all the cgroups, as page_counter_try_charge (mm/page_counter.c) and pids_try_charge
 * (kernel/cgroup/pids.c) of Linux. */
static void *par_cg(void *arg)
{
	pin_cpu((int)(long)arg);
	for (int k = 0; k < 40; k++) {
		pid_t pid = fork();
		if (pid == 0)
			_exit(0);
		int status;
		if (pid < 0 || waitpid(pid, &status, 0) != pid)
			__atomic_fetch_add(&par_cg_failed, 1, __ATOMIC_RELAXED);
		char *m = mmap(NULL, 8 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m != MAP_FAILED) {
			for (int j = 0; j < 8; j++)
				m[j * 4096] = 1;
			munmap(m, 8 * 4096);
		}
	}
	return NULL;
}

/* Runs par_cg on `n` CPUs in a new cgroup with a pids.max that the threads and their children
 * reach but do not pass. Gives 1 if no fork failed and the cgroup counts no task at the end. */
static int par_cg_run(int n)
{
	char max[16];
	mkdir("/cgs", 0755);
	if (mount("none", "/cgs", "cgroup2", 0, NULL) != 0)
		return 0;
	cg_write("/cgs/cgroup.subtree_control", "+memory +pids");
	rmdir("/cgs/smp");
	int ok = mkdir("/cgs/smp", 0755) == 0;
	/* The main thread, n threads, and one child of each thread. */
	snprintf(max, sizeof(max), "%d", 2 * n + 1);
	ok = ok && cg_write("/cgs/smp/pids.max", max) == 0;
	pid_t pid = ok ? fork() : -1;
	if (pid == 0) {
		pthread_t t[4];
		if (cg_write("/cgs/smp/cgroup.procs", "0") != 0)
			_exit(1);
		for (int i = 0; i < n; i++)
			pthread_create(&t[i], NULL, par_cg, (void *)(long)i);
		for (int i = 0; i < n; i++)
			pthread_join(t[i], NULL);
		_exit(par_cg_failed == 0 ? 0 : 2);
	}
	int status = wait_status(pid);
	ok = ok && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
	     cg_value("/cgs/smp/pids.current", "") == 0 &&
	     cg_value("/cgs/smp/pids.events", "max ") == 0 &&
	     cg_value("/cgs/smp/cgroup.events", "populated ") == 0 && rmdir("/cgs/smp") == 0;
	umount("/cgs");
	return ok;
}

/* The queue of par_mq, its messages, and the calls that gave a wrong result. */
#define PAR_MQ "/rk-smp"
#define PAR_MQ_RACE "/rk-smp-race"
#define PAR_MQ_ROUNDS 30
static mqd_t par_mqd;
static int par_mq_sent, par_mq_got, par_mq_bad, par_mq_unlinked;
static pthread_barrier_t par_mq_barrier;

/* An absolute CLOCK_REALTIME time `ms` milliseconds from now, for mq_timedsend. */
static struct timespec par_after_ms(int ms)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += ms * 1000000L;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000L;
	}
	return ts;
}

/* Sends (an even `arg`) or receives (an odd `arg`) messages on par_mqd on the CPU `arg`, while the
 * main thread unlinks the queue and makes new queues with the same name. The descriptor keeps its
 * queue after the unlink, as in ipc/mqueue.c of Linux. */
static void *par_mq(void *arg)
{
	int i = (int)(long)arg;
	pin_cpu(i);
	for (int k = 0; k < 100; k++) {
		struct timespec ts = par_after_ms(10);
		char msg[16];
		if (i % 2 == 0) {
			memset(msg, 'a' + k % 26, sizeof(msg));
			if (mq_timedsend(par_mqd, msg, sizeof(msg), k % 4, &ts) == 0)
				__atomic_fetch_add(&par_mq_sent, 1, __ATOMIC_RELAXED);
			else if (errno != ETIMEDOUT)
				__atomic_fetch_add(&par_mq_bad, 1, __ATOMIC_RELAXED);
			continue;
		}
		unsigned prio = 99;
		ssize_t n = mq_timedreceive(par_mqd, msg, sizeof(msg), &prio, &ts);
		int ok = n == sizeof(msg) && prio < 4;
		for (int j = 1; ok && j < (int)sizeof(msg); j++)
			ok = msg[j] == msg[0];
		if (ok)
			__atomic_fetch_add(&par_mq_got, 1, __ATOMIC_RELAXED);
		else if (n != -1 || errno != ETIMEDOUT)
			__atomic_fetch_add(&par_mq_bad, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

/* Opens PAR_MQ_RACE with O_CREAT on the CPU `arg` at the same time as the other threads, and then
 * unlinks it at the same time as them. Each open must work, and one unlink of each round must
 * work, as with the lock of the root inode in ipc/mqueue.c of Linux. */
static void *par_mq_race(void *arg)
{
	struct mq_attr attr = { .mq_maxmsg = 4, .mq_msgsize = 16 };
	pin_cpu((int)(long)arg);
	for (int k = 0; k < PAR_MQ_ROUNDS; k++) {
		pthread_barrier_wait(&par_mq_barrier);
		mqd_t q = mq_open(PAR_MQ_RACE, O_RDWR | O_CREAT, 0600, &attr);
		if (q == (mqd_t)-1)
			__atomic_fetch_add(&par_mq_bad, 1, __ATOMIC_RELAXED);
		else
			mq_close(q);
		pthread_barrier_wait(&par_mq_barrier);
		if (mq_unlink(PAR_MQ_RACE) == 0)
			__atomic_fetch_add(&par_mq_unlinked, 1, __ATOMIC_RELAXED);
		else if (errno != ENOENT)
			__atomic_fetch_add(&par_mq_bad, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

/* Runs the POSIX message queues on `n` CPUs: sends and receives on one queue while another thread
 * unlinks it, and opens and unlinks of one name at the same time. */
static void par_mq_run(int n)
{
	pthread_t t[4];
	struct mq_attr attr = { .mq_maxmsg = 8, .mq_msgsize = 16 };
	mq_unlink(PAR_MQ);
	par_mqd = mq_open(PAR_MQ, O_RDWR | O_CREAT | O_EXCL, 0600, &attr);
	int ok = par_mqd != (mqd_t)-1 && n >= 2;
	if (ok) {
		for (int i = 0; i < n; i++)
			pthread_create(&t[i], NULL, par_mq, (void *)(long)i);
		for (int k = 0; k < 50; k++) {
			if (mq_unlink(PAR_MQ) != 0 && errno != ENOENT)
				ok = 0;
			mqd_t q = mq_open(PAR_MQ, O_RDWR | O_CREAT, 0600, &attr);
			ok &= q != (mqd_t)-1;
			if (q != (mqd_t)-1)
				mq_close(q);
		}
		for (int i = 0; i < n; i++)
			pthread_join(t[i], NULL);
		struct mq_attr now;
		ok = ok && mq_getattr(par_mqd, &now) == 0 &&
		     par_mq_sent == par_mq_got + now.mq_curmsgs && par_mq_bad == 0;
		mq_close(par_mqd);
		mq_unlink(PAR_MQ);
	}
	check("mq send and receive on each CPU while another thread unlinks the queue", ok);

	mq_unlink(PAR_MQ_RACE);
	pthread_barrier_init(&par_mq_barrier, NULL, n);
	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_mq_race, (void *)(long)i);
	for (int i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	pthread_barrier_destroy(&par_mq_barrier);
	check("mq_open with O_CREAT and mq_unlink of one name on each CPU",
	      par_mq_bad == 0 && par_mq_unlinked == PAR_MQ_ROUNDS);
}

/* The context of par_aio, its events, and the calls that gave a wrong result. */
#define PAR_AIO_FILE "/tmp/smp-aio"
static aio_context_t par_aio_ctx;
static int par_aio_fd, par_aio_bad, par_aio_destroyed;
static long par_aio_sent, par_aio_got;
/* The result of the io_getevents that waits for io_destroy, and the time of its end. */
static long par_aio_wait_r = -2;
static struct timespec par_aio_wait_end;

/* Submits writes to PAR_AIO_FILE and reaps the events on the CPU `arg` until io_destroy removes
 * the context. Then io_submit and io_getevents give EINVAL, as lookup_ioctx in fs/aio.c of Linux. */
static void *par_aio(void *arg)
{
	static char bufs[4][64];
	int i = (int)(long)arg;
	pin_cpu(i);
	memset(bufs[i], 'a' + i, sizeof(bufs[i]));
	for (int k = 0; k < 5000; k++) {
		struct iocb cb[4], *list[4];
		for (int j = 0; j < 4; j++) {
			memset(&cb[j], 0, sizeof(cb[j]));
			cb[j].aio_lio_opcode = IOCB_CMD_PWRITE;
			cb[j].aio_fildes = par_aio_fd;
			cb[j].aio_buf = (unsigned long)bufs[i];
			cb[j].aio_nbytes = sizeof(bufs[i]);
			cb[j].aio_offset = (i * 4 + j) * 64;
			list[j] = &cb[j];
		}
		long r = syscall(SYS_io_submit, par_aio_ctx, 4, list);
		if (r > 0)
			__atomic_fetch_add(&par_aio_sent, r, __ATOMIC_RELAXED);
		else if (errno == EINVAL)
			break;
		else if (errno != EAGAIN)
			__atomic_fetch_add(&par_aio_bad, 1, __ATOMIC_RELAXED);
		struct io_event ev[8];
		r = syscall(SYS_io_getevents, par_aio_ctx, 0, 8, ev, &(struct timespec){ 0, 0 });
		if (r < 0 && errno == EINVAL)
			break;
		if (r < 0)
			__atomic_fetch_add(&par_aio_bad, 1, __ATOMIC_RELAXED);
		for (long e = 0; e < r; e++)
			if (ev[e].res != 64)
				__atomic_fetch_add(&par_aio_bad, 1, __ATOMIC_RELAXED);
		if (r > 0)
			__atomic_fetch_add(&par_aio_got, r, __ATOMIC_RELAXED);
	}
	return NULL;
}

/* Waits in io_getevents for more events than the other threads let stay in the context. Only
 * io_destroy ends the wait, as kill_ioctx in fs/aio.c of Linux wakes ctx->wait. */
static void *par_aio_wait(void *arg)
{
	struct io_event ev[64];
	pin_cpu((int)(long)arg);
	long r = syscall(SYS_io_getevents, par_aio_ctx, 64, 64, ev, &(struct timespec){ 5, 0 });
	clock_gettime(CLOCK_MONOTONIC, &par_aio_wait_end);
	par_aio_wait_r = r < 0 ? -errno : r;
	if (r > 0)
		__atomic_fetch_add(&par_aio_got, r, __ATOMIC_RELAXED);
	return NULL;
}

/* Calls io_destroy at the same time as the main thread. */
static void *par_aio_destroy(void *arg)
{
	(void)arg;
	if (syscall(SYS_io_destroy, par_aio_ctx) == 0)
		__atomic_fetch_add(&par_aio_destroyed, 1, __ATOMIC_RELAXED);
	return NULL;
}

/* Runs aio on `n` CPUs: threads submit and reap on one context, one thread waits in io_getevents,
 * and two threads destroy the context at the same time. */
static void par_aio_run(int n)
{
	pthread_t t[4], w, d;
	par_aio_fd = open(PAR_AIO_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
	int ok = par_aio_fd >= 0 && n >= 2 && syscall(SYS_io_setup, 64, &par_aio_ctx) == 0;
	if (!ok) {
		check("aio on each CPU while two threads destroy the context", 0);
		return;
	}
	pthread_create(&w, NULL, par_aio_wait, (void *)0L);
	for (int i = 1; i < n; i++)
		pthread_create(&t[i], NULL, par_aio, (void *)(long)i);
	struct timespec t0, now;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		sched_yield();
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (__atomic_load_n(&par_aio_sent, __ATOMIC_RELAXED) < 200 && now.tv_sec - t0.tv_sec < 2);
	pthread_create(&d, NULL, par_aio_destroy, NULL);
	struct timespec gone;
	clock_gettime(CLOCK_MONOTONIC, &gone);
	if (syscall(SYS_io_destroy, par_aio_ctx) == 0)
		__atomic_fetch_add(&par_aio_destroyed, 1, __ATOMIC_RELAXED);
	pthread_join(d, NULL);
	for (int i = 1; i < n; i++)
		pthread_join(t[i], NULL);
	pthread_join(w, NULL);
	struct iocb cb = { .aio_lio_opcode = IOCB_CMD_FSYNC, .aio_fildes = par_aio_fd };
	struct iocb *list[1] = { &cb };
	long waited = (par_aio_wait_end.tv_sec - gone.tv_sec) * 1000 +
		      (par_aio_wait_end.tv_nsec - gone.tv_nsec) / 1000000;
	ok = par_aio_destroyed == 1 && par_aio_bad == 0 && par_aio_sent > 0 &&
	     par_aio_got <= par_aio_sent &&
	     syscall(SYS_io_submit, par_aio_ctx, 1, list) == -1 && errno == EINVAL;
	check("aio on each CPU while two threads destroy the context", ok);
	check("io_destroy ends a wait in io_getevents on another CPU",
	      (par_aio_wait_r == -EINVAL || par_aio_wait_r >= 0) && waited < 2000);
	close(par_aio_fd);
	unlink(PAR_AIO_FILE);
}

/* The pages of par_ksm, and the reads that did not give the last write. */
#define PAR_KSM_PAGES 64
#define PAR_KSM_FILL 0x5a
static unsigned char *par_ksm_area;
static int par_ksm_bad, par_ksm_stop;

/* Writes the pages of the CPU `arg` while ksmd merges them, with stores and with read() into the
 * pages, and then writes the pages back to the contents that merge. Each read must give the last
 * write. write_protect_page in mm/ksm.c of Linux checks the count of references after the
 * protect, so a write that started before it does not go to a page that a KSM page replaces. */
static void *par_ksm(void *arg)
{
	int i = (int)(long)arg, pfd[2];
	pin_cpu(i);
	if (pipe(pfd) != 0) {
		__atomic_fetch_add(&par_ksm_bad, 1, __ATOMIC_RELAXED);
		return NULL;
	}
	long fill;
	memset(&fill, PAR_KSM_FILL, sizeof(fill));
	for (int round = 0; round < 20 || !__atomic_load_n(&par_ksm_stop, __ATOMIC_ACQUIRE); round++) {
		for (int p = i; p < PAR_KSM_PAGES; p += par_threads) {
			unsigned char *page = par_ksm_area + p * 4096;
			long *a = (long *)(page + (round % 256) * 8);
			long *b = (long *)(page + 2048 + (round % 256) * 8);
			long v = ((long)i << 32) | ((long)round << 16) | p;
			*a = v;
			long w = ~v;
			int ok = write(pfd[1], &w, sizeof(w)) == sizeof(w) &&
				 read(pfd[0], b, sizeof(w)) == sizeof(w);
			ok = ok && *a == v && *b == w;
			*a = fill;
			*b = fill;
			ok = ok && *a == fill && *b == fill;
			if (!ok)
				__atomic_fetch_add(&par_ksm_bad, 1, __ATOMIC_RELAXED);
		}
		sched_yield();
	}
	close(pfd[0]);
	close(pfd[1]);
	return NULL;
}

static int ksm_set(const char *name, const char *value)
{
	char path[64];
	snprintf(path, sizeof(path), "/sys/kernel/mm/ksm/%s", name);
	return cg_write(path, value);
}

static long ksm_get(const char *name)
{
	char path[64];
	snprintf(path, sizeof(path), "/sys/kernel/mm/ksm/%s", name);
	return cg_value(path, "");
}

/* Runs KSM on `n` CPUs: ksmd merges equal pages while threads write them. */
static void par_ksm_run(int n)
{
	pthread_t t[4];
	mkdir("/sys", 0755);
	int mounted = mount("sysfs", "/sys", "sysfs", 0, NULL) == 0;
	unsigned char *m = mmap(NULL, PAR_KSM_PAGES * 4096, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int ok = mounted && m != MAP_FAILED;
	if (ok) {
		memset(m, PAR_KSM_FILL, PAR_KSM_PAGES * 4096);
		ok = madvise(m, PAR_KSM_PAGES * 4096, MADV_MERGEABLE) == 0 &&
		     ksm_set("sleep_millisecs", "0") == 0 && ksm_set("pages_to_scan", "1000") == 0 &&
		     ksm_set("run", "1") == 0;
	}
	/* Two full scans merge the pages: the first puts them in the unstable tree. */
	for (int k = 0; ok && k < 300 && ksm_get("pages_sharing") <= 0; k++)
		usleep(10000);
	long sharing = ok ? ksm_get("pages_sharing") : 0;
	check("ksmd merges equal pages on an SMP system", ok && sharing > 0);
	if (ok && sharing > 0) {
		long scans = ksm_get("full_scans");
		par_threads = n;
		par_ksm_area = m;
		for (int i = 0; i < n; i++)
			pthread_create(&t[i], NULL, par_ksm, (void *)(long)i);
		/* The writes go on until ksmd did 3 full scans, or for at most 2 s. */
		long now = scans;
		for (int k = 0; k < 200 && now < scans + 3; k++) {
			usleep(10000);
			now = ksm_get("full_scans");
		}
		__atomic_store_n(&par_ksm_stop, 1, __ATOMIC_RELEASE);
		for (int i = 0; i < n; i++)
			pthread_join(t[i], NULL);
		int same = 1;
		for (int k = 0; same && k < PAR_KSM_PAGES * 4096; k++)
			same = m[k] == PAR_KSM_FILL;
		check("writes on each CPU to pages that ksmd merges are not lost",
		      par_ksm_bad == 0 && same && now > scans);
	}
	if (mounted) {
		check("KSM unmerges the pages after the writes", ksm_set("run", "2") == 0 &&
			      ksm_get("pages_sharing") == 0);
		ksm_set("run", "0");
		ksm_set("sleep_millisecs", "20");
		ksm_set("pages_to_scan", "100");
	}
	if (m != MAP_FAILED)
		munmap(m, PAR_KSM_PAGES * 4096);
	if (mounted)
		umount("/sys");
}

/* Gives the ms since *t and sets *t to now. */
static long par_lap(struct timespec *t)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	long ms = (now.tv_sec - t->tv_sec) * 1000 + (now.tv_nsec - t->tv_nsec) / 1000000;
	*t = now;
	return ms;
}

/* Lets the calling process run on each CPU again, after pin_cpu in its parent. */
static void par_unpin(void)
{
	cpu_set_t all;
	CPU_ZERO(&all);
	for (int c = 0; c < 4; c++)
		CPU_SET(c, &all);
	sched_setaffinity(0, sizeof(all), &all);
}

/* The process group of par_reap_run, and the processes of it that par_reap_wait took. */
#define PAR_REAP_ROUNDS 8
#define PAR_REAP_KIDS 8
static pid_t par_reap_group;
static int par_reap_got;

/* Waits for the processes of par_reap_group until the leader `arg` ends. */
static void *par_reap_wait(void *arg)
{
	pid_t leader = (pid_t)(long)arg;
	pin_cpu(1);
	for (;;) {
		pid_t p = waitpid(-par_reap_group, NULL, 0);
		if (p > 0)
			__atomic_fetch_add(&par_reap_got, 1, __ATOMIC_RELAXED);
		if (p == leader || (p < 0 && errno != EINTR))
			break;
	}
	return NULL;
}

/* Ends processes on each CPU while their children end, and waits for all of them in a thread of
 * init, which gets the children. No wake is lost: forget_original_parent and do_notify_parent in
 * kernel/exit.c of Linux run under tasklist_lock. */
static void par_reap_run(void)
{
	pid_t leader = fork();
	if (leader == 0) {
		setpgid(0, 0);
		for (;;)
			pause();
	}
	int ok = leader > 0;
	if (!ok) {
		check("wait and exit of many children on each CPU lose no wake", 0);
		return;
	}
	setpgid(leader, leader);
	par_reap_group = leader;
	pthread_t w;
	pthread_create(&w, NULL, par_reap_wait, (void *)(long)leader);
	int want = 0;
	for (int r = 0; r < PAR_REAP_ROUNDS; r++) {
		pid_t c = fork();
		if (c == 0) {
			setpgid(0, leader);
			par_unpin();
			for (int k = 0; k < PAR_REAP_KIDS; k++) {
				pid_t g = fork();
				if (g == 0) {
					for (int y = 0; y < k; y++)
						sched_yield();
					_exit(0);
				}
				if (g < 0)
					_exit(1);
			}
			_exit(0);
		}
		if (c > 0) {
			setpgid(c, leader);
			want += 1 + PAR_REAP_KIDS;
		}
	}
	/* Each process ends at once, so 3 s is enough. A lost wake leaves a zombie. */
	for (int k = 0; k < 1500 && __atomic_load_n(&par_reap_got, __ATOMIC_RELAXED) < want; k++)
		usleep(2000);
	ok = __atomic_load_n(&par_reap_got, __ATOMIC_RELAXED) == want;
	kill(leader, SIGKILL);
	pthread_join(w, NULL);
	while (waitpid(-leader, NULL, WNOHANG) > 0)
		;
	check("wait and exit of many children on each CPU lose no wake", ok);
}

/* Forks children that wait for a signal, while the main thread kills the process group. */
static void par_kill_member(int *forks)
{
	for (int k = 0; k < 16; k++) {
		pid_t c = fork();
		if (c == 0)
			for (;;)
				pause();
		if (c > 0)
			__atomic_fetch_add(forks, 1, __ATOMIC_RELAXED);
	}
	for (;;)
		pause();
}

#define PAR_KILL_ROUNDS 4

/* Kills a process group whose `n` members fork on each CPU. A child that a fork makes during the
 * kill must get the signal too, as copy_process in kernel/fork.c of Linux makes the fork restart
 * if a signal came, under tasklist_lock, which __kill_pgrp_info holds. */
static int par_kill_run(int n)
{
	int *forks = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (forks == MAP_FAILED)
		return 0;
	int ok = 1;
	for (int r = 0; r < PAR_KILL_ROUNDS; r++) {
		__atomic_store_n(forks, 0, __ATOMIC_RELAXED);
		pid_t leader = 0;
		for (int i = 0; i < n; i++) {
			pid_t p = fork();
			if (p == 0) {
				setpgid(0, leader);
				par_unpin();
				par_kill_member(forks);
			}
			if (p < 0) {
				ok = 0;
				break;
			}
			if (i == 0)
				leader = p;
			setpgid(p, leader);
		}
		if (leader <= 0)
			break;
		for (int k = 0; k < 1000 && __atomic_load_n(forks, __ATOMIC_RELAXED) < 4 * n; k++)
			usleep(1000);
		if (kill(-leader, SIGKILL) != 0)
			ok = 0;
		struct timespec t0, now;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (;;) {
			pid_t p = waitpid(-leader, NULL, WNOHANG);
			if (p > 0)
				continue;
			if (p < 0)
				break;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - t0.tv_sec >= 2) {
				/* A child got away from the kill. */
				ok = 0;
				kill(-leader, SIGKILL);
				while (waitpid(-leader, NULL, 0) > 0)
					;
				break;
			}
			usleep(1000);
		}
	}
	munmap(forks, 4096);
	return ok;
}

#define PAR_STOP_ROUNDS 800

/* Sends SIGSTOP and SIGCONT to a child that runs on another CPU. After the last SIGCONT the child
 * must run: SIGCONT clears JOBCTL_STOP_DEQUEUED in prepare_signal of kernel/signal.c of Linux, so
 * a stop signal that the child took before the SIGCONT does not stop it after. */
static int par_stop_run(int n)
{
	volatile long *count = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (count == MAP_FAILED)
		return 0;
	pid_t c = fork();
	if (c == 0) {
		pin_cpu(n - 1);
		for (;;)
			(*count)++;
	}
	int ok = c > 0;
	for (int k = 0; ok && k < PAR_STOP_ROUNDS; k++) {
		ok = kill(c, SIGSTOP) == 0;
		for (volatile int s = 0; s < k % 500; s++)
			;
		ok = ok && kill(c, SIGCONT) == 0;
	}
	int moved = 0;
	for (int k = 0; ok && k < 100 && !moved; k++) {
		long v = *count;
		usleep(10000);
		moved = *count != v;
	}
	if (c > 0) {
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
	}
	munmap((void *)count, 4096);
	return ok && moved;
}

/* The descriptors of par_fd, and the calls that gave a wrong result. */
static int par_fd_pipe[2], par_fd_bad;

/* Opens and closes descriptors on the CPU `arg`, while the thread on CPU 0 puts a pipe on the
 * descriptors 200 to 207 with dup2 and the others close them. */
static void *par_fd(void *arg)
{
	int i = (int)(long)arg;
	pin_cpu(i);
	for (int k = 0; k < 200; k++) {
		int target = 200 + (k + i) % 8;
		if (i == 0) {
			if (dup2(par_fd_pipe[0], target) != target)
				__atomic_fetch_add(&par_fd_bad, 1, __ATOMIC_RELAXED);
			continue;
		}
		struct stat st;
		int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		int ok = fd >= 0 && fd < 200 && fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) &&
			 close(fd) == 0;
		if (fstat(target, &st) == 0)
			ok = ok && S_ISFIFO(st.st_mode);
		if (close(target) != 0 && errno != EBADF)
			ok = 0;
		if (!ok)
			__atomic_fetch_add(&par_fd_bad, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

static int par_fd_run(int n)
{
	pthread_t t[4];
	if (pipe(par_fd_pipe) != 0)
		return 0;
	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_fd, (void *)(long)i);
	for (int i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	for (int fd = 200; fd < 208; fd++)
		close(fd);
	close(par_fd_pipe[0]);
	close(par_fd_pipe[1]);
	return par_fd_bad == 0;
}

/* The directory of the checks of the file systems, the inode of par_fs_links, and the calls that
 * gave a wrong result. */
#define PAR_FS_DIR "/tmp/smp-fs"
#define PAR_FS_NAMES 6
static ino_t par_fs_ino;
static int par_fs_bad, par_fs_both, par_fs_r[2], par_fs_why;
static pthread_barrier_t par_fs_barrier;

/* Links one file to the names s0 to s5, renames and unlinks these names, and looks them up, on
 * the CPU `arg`. vfs_link, vfs_rename and vfs_unlink in fs/namei.c of Linux hold the lock of the
 * directory, so each call sees the names of the other calls before or after it. */
static void *par_fs_links(void *arg)
{
	int i = (int)(long)arg;
	unsigned seed = i + 1;
	pin_cpu(i);
	for (int k = 0; k < 250; k++) {
		char a[64], b[64];
		struct stat st;
		int ok;
		seed = seed * 1103515245 + 12345;
		snprintf(a, sizeof(a), PAR_FS_DIR "/s%u", (seed >> 8) % PAR_FS_NAMES);
		snprintf(b, sizeof(b), PAR_FS_DIR "/s%u", (seed >> 16) % PAR_FS_NAMES);
		switch ((seed >> 24) % 4) {
		case 0:
			ok = link(PAR_FS_DIR "/base", a) == 0 || errno == EEXIST;
			break;
		case 1:
			ok = rename(a, b) == 0 || errno == ENOENT;
			break;
		case 2:
			ok = unlink(a) == 0 || errno == ENOENT;
			break;
		default:
			ok = stat(a, &st) == 0 ? st.st_ino == par_fs_ino : errno == ENOENT;
		}
		if (!ok) {
			__atomic_fetch_add(&par_fs_bad, 1, __ATOMIC_RELAXED);
			par_fs_why = (int)((seed >> 24) % 4) * 1000 + errno;
		}
	}
	return NULL;
}

/* Moves the directory a into b on CPU 0 while CPU 1 moves b into a. Only one of them can work:
 * lock_rename in fs/namei.c of Linux takes s_vfs_rename_mutex, so the check that a directory
 * does not go below itself sees the other rename. */
static void *par_fs_loop(void *arg)
{
	int i = (int)(long)arg;
	pin_cpu(i);
	for (int k = 0; k < 30; k++) {
		pthread_barrier_wait(&par_fs_barrier);
		int r = i == 0 ? rename(PAR_FS_DIR "/a", PAR_FS_DIR "/b/x")
			       : rename(PAR_FS_DIR "/b", PAR_FS_DIR "/a/y");
		par_fs_r[i] = r == 0 ? 0 : errno;
		pthread_barrier_wait(&par_fs_barrier);
		if (i == 0) {
			for (int j = 0; j < 2; j++)
				if (par_fs_r[j] != 0 && par_fs_r[j] != ENOENT && par_fs_r[j] != EINVAL)
					par_fs_bad++;
			if (par_fs_r[0] == 0 && par_fs_r[1] == 0)
				par_fs_both++;
			else if (par_fs_r[0] == 0)
				rename(PAR_FS_DIR "/b/x", PAR_FS_DIR "/a");
			else if (par_fs_r[1] == 0)
				rename(PAR_FS_DIR "/a/y", PAR_FS_DIR "/b");
		}
		pthread_barrier_wait(&par_fs_barrier);
	}
	return NULL;
}

/* Makes and removes the directory d on CPU 0, while the other CPUs make and remove a file in it.
 * A file that open made can always be removed: vfs_rmdir in fs/namei.c of Linux locks the
 * directory that it removes and marks it dead, so no file goes in it after the check that it is
 * empty. */
static void *par_fs_rmdir(void *arg)
{
	int i = (int)(long)arg;
	char f[64];
	snprintf(f, sizeof(f), PAR_FS_DIR "/d/f%d", i);
	pin_cpu(i);
	for (int k = 0; k < 150; k++) {
		int ok = 1;
		if (i == 0) {
			ok = mkdir(PAR_FS_DIR "/d", 0755) == 0 || errno == EEXIST;
			ok = (rmdir(PAR_FS_DIR "/d") == 0 || errno == ENOTEMPTY) && ok;
		} else {
			int fd = open(f, O_WRONLY | O_CREAT, 0600);
			if (fd >= 0) {
				close(fd);
				ok = unlink(f) == 0;
			} else {
				ok = errno == ENOENT;
			}
		}
		if (!ok)
			__atomic_fetch_add(&par_fs_bad, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

/* Runs link, rename, unlink, mkdir and rmdir of the same names on `n` CPUs in a tmpfs. */
static void par_fs_run(int n)
{
	pthread_t t[4];
	struct stat st;
	mkdir("/tmp", 0755);
	mkdir(PAR_FS_DIR, 0755);
	int fd = open(PAR_FS_DIR "/base", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	int ok = fd >= 0 && fstat(fd, &st) == 0;
	if (fd >= 0)
		close(fd);
	par_fs_ino = st.st_ino;
	par_fs_bad = 0;
	for (int i = 0; ok && i < n; i++)
		pthread_create(&t[i], NULL, par_fs_links, (void *)(long)i);
	for (int i = 0; ok && i < n; i++)
		pthread_join(t[i], NULL);
	/* readdir gives the names that the directory has. A lookup must give the same names. */
	int names = 0;
	DIR *dir = opendir(PAR_FS_DIR);
	ok = ok && dir;
	for (struct dirent *e; dir && (e = readdir(dir));) {
		if (e->d_name[0] != 's')
			continue;
		char p[300];
		snprintf(p, sizeof(p), PAR_FS_DIR "/%s", e->d_name);
		ok = ok && stat(p, &st) == 0 && st.st_ino == par_fs_ino;
		names++;
	}
	if (dir)
		closedir(dir);
	int links = stat(PAR_FS_DIR "/base", &st) == 0 ? (int)st.st_nlink : -1;
	ok = ok && links == 1 + names;
	int found = 0;
	for (int j = 0; j < PAR_FS_NAMES; j++) {
		char p[64];
		snprintf(p, sizeof(p), PAR_FS_DIR "/s%d", j);
		if (stat(p, &st) == 0)
			found++;
		unlink(p);
	}
	if (!ok || par_fs_bad || found != names)
		printf("init: smp-fs: %d bad calls (last %d), %d names in readdir, %d names in "
		       "lookups, %d links\n",
		       par_fs_bad, par_fs_why, names, found, links);
	check("link, rename and unlink of the same names on each CPU keep the names and the link "
	      "count", ok && par_fs_bad == 0 && found == names);
	unlink(PAR_FS_DIR "/base");

	par_fs_bad = 0;
	ok = mkdir(PAR_FS_DIR "/a", 0755) == 0 && mkdir(PAR_FS_DIR "/b", 0755) == 0;
	pthread_barrier_init(&par_fs_barrier, NULL, 2);
	for (int i = 0; ok && i < 2; i++)
		pthread_create(&t[i], NULL, par_fs_loop, (void *)(long)i);
	for (int i = 0; ok && i < 2; i++)
		pthread_join(t[i], NULL);
	pthread_barrier_destroy(&par_fs_barrier);
	ok = ok && rmdir(PAR_FS_DIR "/a") == 0 && rmdir(PAR_FS_DIR "/b") == 0;
	check("rename of a into b and of b into a on two CPUs makes no loop",
	      ok && par_fs_bad == 0 && par_fs_both == 0);

	par_fs_bad = 0;
	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_fs_rmdir, (void *)(long)i);
	for (int i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	ok = rmdir(PAR_FS_DIR "/d") == 0 || errno == ENOENT;
	check("rmdir of a directory on one CPU while files are made in it on the others",
	      ok && par_fs_bad == 0);
	rmdir(PAR_FS_DIR);
}

/* Runs futexes, sockets, faults and system calls on several CPUs at the same time. Before #405,
 * only one CPU at a time ran kernel code, so these races could not occur. */
static void test_smp_parallel(int cpus)
{
	pthread_t t[4];
	int n = cpus < 4 ? cpus : 4;

	pthread_create(&t[0], NULL, par_futex, (void *)0L);
	pthread_create(&t[1], NULL, par_futex, (void *)1L);
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	check("a futex ping-pong on two CPUs loses no wake", par_timeouts == 0);

	int on = 1;
	int ok = socketpair(AF_UNIX, SOCK_DGRAM, 0, par_fds) == 0 &&
		 setsockopt(par_fds[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == 0 &&
		 setsockopt(par_fds[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == 0;
	if (ok) {
		pthread_create(&t[0], NULL, par_dgram, (void *)0L);
		pthread_create(&t[1], NULL, par_dgram, (void *)1L);
		pthread_join(t[0], NULL);
		pthread_join(t[1], NULL);
		close(par_fds[0]);
		close(par_fds[1]);
	}
	check("two CPUs send datagrams with SO_PASSCRED to each other",
	      ok && par_ok[0] && par_ok[1]);

	pthread_create(&t[0], NULL, par_read, (void *)1L);
	pin_cpu(0);
	int forks = 1;
	for (int i = 0; i < 50 && forks; i++) {
		pid_t pid = fork();
		if (pid == 0)
			_exit(0);
		int status;
		forks = pid > 0 && waitpid(pid, &status, 0) == pid;
	}
	__atomic_store_n(&par_done, 1, __ATOMIC_RELEASE);
	pthread_join(t[0], NULL);
	check("a read on one CPU during a fork on another CPU gives no EFAULT",
	      forks && par_efault == 0);

	for (int i = 0; i < n; i++)
		pthread_create(&t[i], NULL, par_getpid, (void *)(long)i);
	long same = 1;
	for (int i = 0; i < n; i++) {
		void *r;
		pthread_join(t[i], &r);
		same &= (long)r;
	}
	check("getpid on each CPU at the same time", same);

	par_threads = n;
	char *area = mmap(NULL, PAR_PAGES * 4096, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int mapped = area != MAP_FAILED;
	if (mapped) {
		/* 4 KiB pages, so each write of the first pass is a page fault. */
		madvise(area, PAR_PAGES * 4096, MADV_NOHUGEPAGE);
		par_area = area;
		for (int i = 0; i < n; i++)
			pthread_create(&t[i], NULL, par_fault, (void *)(long)i);
		for (int i = 0; i < n; i++)
			pthread_join(t[i], NULL);
		for (int p = 0; p < PAR_PAGES && mapped; p++)
			for (int i = 0; i < n; i++)
				mapped &= area[p * 4096 + i] == (char)(i + 1);
		munmap(area, PAR_PAGES * 4096);
	}
	check("page faults on each CPU in one address space lose no write", mapped);

	check("mmap, munmap, brk and faults on each CPU keep the areas apart", par_mm_run(n));
	check("page faults of one file on each CPU read the right data", par_file_run(n));
	check("forks and pages on each CPU in one cgroup keep pids.max and the counts",
	      par_cg_run(n));
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	par_mq_run(n);
	par_aio_run(n);
	par_ksm_run(n);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	printf("init: mq, aio and KSM on %d CPUs take %ld ms\n", n,
	       (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	long part[5];
	struct timespec tp = t0;
	par_reap_run();
	part[0] = par_lap(&tp);
	check("kill of a process group while its members fork on each CPU", par_kill_run(n));
	part[1] = par_lap(&tp);
	check("SIGSTOP and SIGCONT to a process on another CPU leave it running",
	      par_stop_run(n));
	part[2] = par_lap(&tp);
	check("open and close of descriptors on each CPU while another CPU does dup2",
	      par_fd_run(n));
	part[3] = par_lap(&tp);
	par_fs_run(n);
	part[4] = par_lap(&tp);
	printf("init: wait, kill, stop, fd and fs parts take %ld, %ld, %ld, %ld and %ld ms\n",
	       part[0], part[1], part[2], part[3], part[4]);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	printf("init: processes and file systems on %d CPUs take %ld ms\n", n,
	       (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
}

static void test_smp(void)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	int cpus = sched_getaffinity(0, sizeof(set), &set) == 0 ? CPU_COUNT(&set) : 0;
	check("sched_getaffinity gives more than one CPU", cpus > 1);
	check("sysconf gives the CPU count", sysconf(_SC_NPROCESSORS_ONLN) == cpus);
	unsigned cpu = 99;
	check("getcpu gives a CPU of the set", syscall(SYS_getcpu, &cpu, NULL, NULL) == 0 &&
						     (int)cpu < cpus);
	int vcpu = sched_getcpu();
	check("sched_getcpu of the vDSO gives a CPU of the set", vcpu >= 0 && vcpu < cpus);

	/* sched_setaffinity moves the thread to the CPU of the new mask, and a child of fork gets
	 * the mask of its parent. */
	int moved = cpus > 1;
	for (int c = 0; c < cpus && moved; c++) {
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(c, &one);
		moved = sched_setaffinity(0, sizeof(one), &one) == 0 && sched_getcpu() == c &&
			syscall(SYS_getcpu, &cpu, NULL, NULL) == 0 && (int)cpu == c;
	}
	check("sched_setaffinity moves the thread to the CPU of the mask", moved);
	pid_t pinned = fork();
	if (pinned == 0)
		_exit(sched_getcpu() == cpus - 1 ? 0 : 1);
	int pstatus = 0;
	check("a child of fork runs on the CPU of the mask of its parent",
	      pinned > 0 && waitpid(pinned, &pstatus, 0) == pinned && WIFEXITED(pstatus) &&
		      WEXITSTATUS(pstatus) == 0);
	sched_setaffinity(0, sizeof(set), &set);
	test_smp_parallel(cpus);
	sched_setaffinity(0, sizeof(set), &set);

	int start[2];
	if (pipe(start) != 0) {
		check("hackbench makes its pipe", 0);
		return;
	}
	int children = 0, ok = 1;
	for (int g = 0; g < HB_GROUPS && ok; g++) {
		int wr[HB_FDS];
		for (int r = 0; r < HB_FDS; r++) {
			int sv[2];
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
				ok = 0;
				break;
			}
			pid_t pid = fork();
			if (pid == 0) {
				close(sv[1]);
				hb_receiver(sv[0]);
			}
			close(sv[0]);
			wr[r] = sv[1];
			children += pid > 0;
			ok &= pid > 0;
		}
		for (int s = 0; s < HB_FDS && ok; s++) {
			pid_t pid = fork();
			if (pid == 0)
				hb_sender(wr, start[0]);
			children += pid > 0;
			ok &= pid > 0;
		}
		for (int r = 0; r < HB_FDS; r++)
			close(wr[r]);
	}
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (int i = 0; i < HB_GROUPS * HB_FDS; i++)
		ok &= write(start[1], "g", 1) == 1;
	close(start[0]);
	close(start[1]);
	int status;
	for (int i = 0; i < children; i++)
		ok &= wait(&status) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
	printf("init: hackbench with %d groups on %d CPUs takes %ld ms\n", HB_GROUPS, cpus, ms);
	check("hackbench completes", ok && children == 2 * HB_GROUPS * HB_FDS);
}

/* The Internet checksum of RFC 1071. */
static unsigned short inet_sum(const void *data, int len)
{
	const unsigned char *p = data;
	unsigned long sum = 0;
	for (int i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (len & 1)
		sum += p[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum & 0xffff);
}

static struct sockaddr_in inet_addr4(unsigned long addr, int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	a.sin_addr.s_addr = htonl(addr);
	return a;
}

/* Waits at most ms milliseconds for a datagram on fd. */
static long recv_wait(int fd, void *buf, int len, struct sockaddr_in *from, int ms)
{
	struct pollfd p = { .fd = fd, .events = POLLIN };
	if (poll(&p, 1, ms) != 1)
		return -1;
	socklen_t fl = sizeof(*from);
	return recvfrom(fd, buf, len, 0, (struct sockaddr *)from, &fl);
}

static long elapsed_us(const struct timespec *t0)
{
	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (t1.tv_sec - t0->tv_sec) * 1000000 + (t1.tv_nsec - t0->tv_nsec) / 1000;
}

/* Sends three echo requests to 10.0.2.2 on the raw socket fd, as ping, and gives the count of
 * replies. A raw socket gets each ICMP packet with its IP header. */
static int ping_raw(int fd)
{
	struct sockaddr_in gw = inet_addr4(0x0a000202, 0);
	int replies = 0;
	for (int seq = 1; seq <= 3; seq++) {
		unsigned char req[64] = { 8, 0, 0, 0, 0x12, 0x34, 0, seq };
		for (int i = 8; i < 64; i++)
			req[i] = i;
		unsigned short sum = inet_sum(req, sizeof(req));
		memcpy(req + 2, &sum, 2);
		struct timespec t0;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		if (sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&gw, sizeof(gw)) != sizeof(req))
			continue;
		for (;;) {
			unsigned char buf[256];
			struct sockaddr_in from;
			long n = recv_wait(fd, buf, sizeof(buf), &from, 2000);
			if (n < 0)
				break;
			int hl = (buf[0] & 0xf) * 4;
			if (n < hl + 8 || buf[hl] != 0 || buf[hl + 4] != 0x12 || buf[hl + 5] != 0x34 ||
			    buf[hl + 7] != seq)
				continue;
			printf("init: inet: %ld bytes from %s: icmp_seq=%d ttl=%d time=%ld us\n", n - hl,
			       inet_ntoa(from.sin_addr), seq, buf[8], elapsed_us(&t0));
			replies++;
			break;
		}
	}
	return replies;
}

static void test_inet_ping(void)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	check("a raw ICMP socket opens", fd >= 0);
	if (fd >= 0) {
		check("ping 10.0.2.2 on a raw socket gets replies", ping_raw(fd) >= 2);
		close(fd);
	}

	errno = 0;
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	check("an ICMP echo socket needs a group in ping_group_range", fd == -1 && errno == EACCES);
	/* With the argument "only", the general checks did not make /proc. */
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	const char *range = "/proc/sys/net/ipv4/ping_group_range";
	char text[64] = { 0 };
	int rfd = open(range, O_RDONLY);
	check("ping_group_range is 1 0", rfd >= 0 && read(rfd, text, sizeof(text) - 1) > 0 &&
						 strcmp(text, "1\t0\n") == 0);
	close(rfd);
	check("ping_group_range takes 0 2147483647", write_text(range, "0 2147483647\n") == 0);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	check("an ICMP echo socket opens", fd >= 0);
	if (fd >= 0) {
		struct sockaddr_in gw = inet_addr4(0x0a000202, 0), from, me;
		unsigned char req[16] = { 8, 0, 0, 0, 0, 0, 0, 7, 'r', 'u', 'k', 'e', 'r', 'n', 'e', 'l' };
		long n = -1;
		for (int i = 0; i < 3 && n < 0; i++) {
			sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&gw, sizeof(gw));
			n = recv_wait(fd, text, sizeof(text), &from, 2000);
		}
		socklen_t ml = sizeof(me);
		getsockname(fd, (struct sockaddr *)&me, &ml);
		unsigned char *r = (unsigned char *)text;
		printf("init: inet: echo socket: %ld bytes from %s, type %d, id %d\n", n,
		       inet_ntoa(from.sin_addr), n > 0 ? r[0] : -1, ntohs(me.sin_port));
		check("ping 10.0.2.2 on an echo socket gets a reply with the socket id",
		      n == 16 && r[0] == 0 && memcmp(r + 4, &me.sin_port, 2) == 0 &&
			      memcmp(r + 8, "rukernel", 8) == 0);
		close(fd);
	}
	write_text(range, "1 0");
	umount("/proc");
}

static void test_inet_dns(void)
{
	/* A query for the A record of example.com, with recursion. */
	static const unsigned char query[] = { 0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7,
					       'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
					       0, 1, 0, 1 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	check("a UDP socket opens", fd >= 0);
	struct sockaddr_in dns = inet_addr4(0x0a000203, 53), from, me;
	check("connect to 10.0.2.3:53", connect(fd, (struct sockaddr *)&dns, sizeof(dns)) == 0);
	socklen_t ml = sizeof(me);
	check("getsockname gives 10.0.2.15 and an ephemeral port",
	      getsockname(fd, (struct sockaddr *)&me, &ml) == 0 &&
		      me.sin_addr.s_addr == htonl(0x0a00020f) && ntohs(me.sin_port) >= 32768);
	unsigned char buf[512];
	long n = -1;
	for (int i = 0; i < 3 && n < 0; i++) {
		if (send(fd, query, sizeof(query), 0) != sizeof(query))
			break;
		n = recv_wait(fd, buf, sizeof(buf), &from, 3000);
	}
	int ok = n >= 12 && buf[0] == 0xbe && buf[1] == 0xef && (buf[2] & 0x80);
	if (ok)
		printf("init: inet: DNS reply from %s:%d, %ld bytes, rcode %d, %d answers\n",
		       inet_ntoa(from.sin_addr), ntohs(from.sin_port), n, buf[3] & 0xf,
		       (buf[6] << 8) | buf[7]);
	check("a DNS query to 10.0.2.3:53 gets a reply", ok);
	close(fd);
}

static void test_inet_lo(void)
{
	int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	struct sockaddr_in lo = inet_addr4(INADDR_LOOPBACK, 0), an, from;
	socklen_t len = sizeof(an);
	check("bind to 127.0.0.1 port 0 gives an ephemeral port",
	      bind(a, (struct sockaddr *)&lo, sizeof(lo)) == 0 &&
		      getsockname(a, (struct sockaddr *)&an, &len) == 0 && ntohs(an.sin_port) >= 32768);
	errno = 0;
	check("a second bind to the port gives EADDRINUSE",
	      bind(b, (struct sockaddr *)&an, sizeof(an)) == -1 && errno == EADDRINUSE);

	int ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = a };
	epoll_ctl(ep, EPOLL_CTL_ADD, a, &ev);
	check("sendto over lo", sendto(b, "ping", 4, 0, (struct sockaddr *)&an, sizeof(an)) == 4);
	check("epoll sees the datagram", epoll_wait(ep, &ev, 1, 1000) == 1 && ev.data.fd == a);
	char buf[64];
	len = sizeof(from);
	struct sockaddr_in bn;
	socklen_t bl = sizeof(bn);
	getsockname(b, (struct sockaddr *)&bn, &bl);
	long n = recvfrom(a, buf, sizeof(buf), 0, (struct sockaddr *)&from, &len);
	printf("init: inet: lo: %ld bytes from %s:%d\n", n, inet_ntoa(from.sin_addr),
	       ntohs(from.sin_port));
	check("recvfrom gives the data and the sender", n == 4 && memcmp(buf, "ping", 4) == 0 &&
								 from.sin_port == bn.sin_port &&
								 from.sin_addr.s_addr == lo.sin_addr.s_addr);

	struct iovec iov[2] = { { "pi", 2 }, { "ng!", 3 } };
	struct msghdr mh = { .msg_name = &an, .msg_namelen = sizeof(an), .msg_iov = iov, .msg_iovlen = 2 };
	check("sendmsg over lo", sendmsg(b, &mh, 0) == 5);
	char small[3];
	struct iovec riov = { small, sizeof(small) };
	struct msghdr rh = { .msg_name = &from, .msg_namelen = sizeof(from), .msg_iov = &riov, .msg_iovlen = 1 };
	n = recvmsg(a, &rh, 0);
	check("recvmsg truncates with MSG_TRUNC", n == 3 && (rh.msg_flags & MSG_TRUNC) &&
							  rh.msg_namelen == sizeof(from) &&
							  memcmp(small, "pin", 3) == 0);
	errno = 0;
	check("recv on an empty socket gives EAGAIN", recv(b, buf, sizeof(buf), 0) == -1 && errno == EAGAIN);

	/* A connected socket gets ECONNREFUSED from the ICMP error for a port without a socket. */
	int c = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in closed = inet_addr4(INADDR_LOOPBACK, 9), peer;
	check("connect to 127.0.0.1:9", connect(c, (struct sockaddr *)&closed, sizeof(closed)) == 0);
	len = sizeof(peer);
	check("getpeername gives the peer", getpeername(c, (struct sockaddr *)&peer, &len) == 0 &&
						     peer.sin_port == htons(9));
	send(c, "x", 1, 0);
	errno = 0;
	check("a datagram to a closed port gives ECONNREFUSED",
	      recv(c, buf, sizeof(buf), MSG_DONTWAIT) == -1 && errno == ECONNREFUSED);
	close(c);

	int one = 1, r1 = socket(AF_INET, SOCK_DGRAM, 0), r2 = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in fixed = inet_addr4(INADDR_ANY, 5353);
	setsockopt(r1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(r2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("SO_REUSEADDR shares a port",
	      bind(r1, (struct sockaddr *)&fixed, sizeof(fixed)) == 0 &&
		      bind(r2, (struct sockaddr *)&fixed, sizeof(fixed)) == 0);
	close(r1);
	close(r2);

	int size = 4096;
	socklen_t sl = sizeof(size);
	setsockopt(a, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	check("SO_RCVBUF doubles the value", getsockopt(a, SOL_SOCKET, SO_RCVBUF, &size, &sl) == 0 &&
						   size == 8192);
	struct sockaddr_in bcast = inet_addr4(0x0a0002ff, 9);
	errno = 0;
	check("a broadcast without SO_BROADCAST gives EACCES",
	      sendto(b, "x", 1, 0, (struct sockaddr *)&bcast, sizeof(bcast)) == -1 && errno == EACCES);
	close(ep);
	close(a);
	close(b);
}

/* The TCP test moves 1 MiB each way. The client sends pattern A and then shuts down its side.
 * The server answers with the FNV-1a hash of the bytes that it got, then 1 MiB of pattern B.
 * xtask runs the same server on the host. */
#define TCP_BYTES (1 << 20)

static unsigned char tcp_pattern(unsigned long i, int b)
{
	return b ? (unsigned char)(i * 13 + (i >> 8) + 5) : (unsigned char)(i * 7 + (i >> 10));
}

static unsigned long long fnv(unsigned long long h, const unsigned char *p, long n)
{
	for (long i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ULL;
	return h;
}

#define FNV_INIT 0xcbf29ce484222325ULL

/* The hash of the first n bytes of a pattern. */
static unsigned long long pattern_fnv(int b, unsigned long n)
{
	unsigned long long h = FNV_INIT;
	for (unsigned long i = 0; i < n; i++) {
		unsigned char c = tcp_pattern(i, b);
		h = fnv(h, &c, 1);
	}
	return h;
}

/* Writes n bytes of a pattern in blocks of different sizes. */
static int tcp_write_pattern(int fd, int b, unsigned long n)
{
	static unsigned char buf[65536];
	unsigned long off = 0;
	for (int k = 0; off < n; k++) {
		unsigned long len = 1000 + (k * 7919) % 60000;
		if (len > n - off)
			len = n - off;
		for (unsigned long i = 0; i < len; i++)
			buf[i] = tcp_pattern(off + i, b);
		long w = write(fd, buf, len);
		if (w <= 0)
			return -1;
		off += w;
	}
	return 0;
}

/* Reads to the end of the stream, or n bytes, and gives the count. h gets the hash. */
static long tcp_read_all(int fd, long n, unsigned long long *h)
{
	static unsigned char buf[50000];
	long total = 0;
	*h = FNV_INIT;
	while (total < n) {
		long want = n - total < (long)sizeof(buf) ? n - total : (long)sizeof(buf);
		long r = read(fd, buf, want);
		if (r <= 0)
			return r < 0 ? -1 : total;
		*h = fnv(*h, buf, r);
		total += r;
	}
	return total;
}

/* Reads exactly n bytes. */
static int read_exact(int fd, void *p, long n)
{
	long got = 0;
	while (got < n) {
		long r = read(fd, (char *)p + got, n - got);
		if (r <= 0)
			return -1;
		got += r;
	}
	return 0;
}

/* The client side: gives 0 if the peer got the data and the reply is right. */
static int tcp_client(int fd, const char *who)
{
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (tcp_write_pattern(fd, 0, TCP_BYTES) < 0)
		return 1;
	if (shutdown(fd, SHUT_WR) < 0)
		return 2;
	unsigned long long sum, h;
	if (read_exact(fd, &sum, sizeof(sum)) < 0)
		return 3;
	long n = tcp_read_all(fd, TCP_BYTES + 1, &h);
	long us = elapsed_us(&t0);
	printf("init: inet: tcp %s: sent 1 MiB, got %ld bytes in %ld us\n", who, n, us);
	if (sum != pattern_fnv(0, TCP_BYTES))
		return 4;
	if (n != TCP_BYTES || h != pattern_fnv(1, TCP_BYTES))
		return 5;
	return 0;
}

/* The server side, for one connection. */
static int tcp_server(int fd)
{
	unsigned long long h;
	long n = tcp_read_all(fd, TCP_BYTES + 1, &h);
	if (n != TCP_BYTES)
		return 1;
	if (write(fd, &h, sizeof(h)) != sizeof(h))
		return 2;
	if (tcp_write_pattern(fd, 1, TCP_BYTES) < 0)
		return 3;
	return 0;
}

static void test_tcp_lo(void)
{
	int l = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in lo = inet_addr4(INADDR_LOOPBACK, 0), an;
	socklen_t len = sizeof(an);
	setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("tcp: bind and listen on 127.0.0.1",
	      bind(l, (struct sockaddr *)&lo, sizeof(lo)) == 0 && listen(l, 8) == 0 &&
		      getsockname(l, (struct sockaddr *)&an, &len) == 0 && an.sin_port != 0);
	int val = 0;
	len = sizeof(val);
	check("tcp: SO_ACCEPTCONN", getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 1);

	/* A nonblocking connect gives EINPROGRESS, then the socket is writable and SO_ERROR is 0. */
	int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	errno = 0;
	check("tcp: nonblocking connect gives EINPROGRESS",
	      connect(c, (struct sockaddr *)&an, sizeof(an)) == -1 && errno == EINPROGRESS);
	struct pollfd p = { .fd = c, .events = POLLOUT };
	val = -1;
	len = sizeof(val);
	check("tcp: the socket becomes writable with SO_ERROR 0",
	      poll(&p, 1, 2000) == 1 && (p.revents & POLLOUT) &&
		      getsockopt(c, SOL_SOCKET, SO_ERROR, &val, &len) == 0 && val == 0);
	int ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = l };
	epoll_ctl(ep, EPOLL_CTL_ADD, l, &ev);
	check("tcp: epoll sees the connection on the listener", epoll_wait(ep, &ev, 1, 1000) == 1);
	struct sockaddr_in peer;
	len = sizeof(peer);
	int a = accept4(l, (struct sockaddr *)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	struct sockaddr_in cn;
	socklen_t cl = sizeof(cn);
	getsockname(c, (struct sockaddr *)&cn, &cl);
	check("tcp: accept4 gives the address of the peer", a >= 0 && peer.sin_port == cn.sin_port &&
							       (fcntl(a, F_GETFL) & O_NONBLOCK));
	errno = 0;
	char buf[16];
	check("tcp: recv on an empty connection gives EAGAIN",
	      recv(a, buf, sizeof(buf), 0) == -1 && errno == EAGAIN);
	val = 1;
	setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 0;
	len = sizeof(val);
	check("tcp: TCP_NODELAY", getsockopt(c, IPPROTO_TCP, TCP_NODELAY, &val, &len) == 0 && val == 1);
	char cc[16] = "";
	len = sizeof(cc);
	check("tcp: TCP_CONGESTION is cubic",
	      getsockopt(c, IPPROTO_TCP, TCP_CONGESTION, cc, &len) == 0 && strcmp(cc, "cubic") == 0);
	send(c, "hello", 5, 0);
	p.fd = a;
	p.events = POLLIN;
	poll(&p, 1, 1000);
	check("tcp: MSG_PEEK leaves the data", recv(a, buf, 3, MSG_PEEK) == 3 && recv(a, buf, 16, 0) == 5 &&
						     memcmp(buf, "hello", 5) == 0);
	/* A half close: the peer reads the end of the data and can still send. */
	shutdown(c, SHUT_WR);
	p.events = POLLIN | POLLRDHUP;
	poll(&p, 1, 1000);
	check("tcp: the peer reads the end after SHUT_WR",
	      (p.revents & POLLRDHUP) && recv(a, buf, sizeof(buf), 0) == 0);
	errno = 0;
	check("tcp: send after SHUT_WR gives EPIPE",
	      send(c, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
	check("tcp: the half closed peer still sends", send(a, "bye", 3, 0) == 3);
	p.fd = c;
	poll(&p, 1, 1000);
	check("tcp: and the data arrives", recv(c, buf, sizeof(buf), 0) == 3);
	close(c);
	close(a);

	/* A close with unread data sends an RST. */
	c = socket(AF_INET, SOCK_STREAM, 0);
	connect(c, (struct sockaddr *)&an, sizeof(an));
	a = accept(l, NULL, NULL);
	send(a, "unread", 6, 0);
	p.fd = c;
	p.events = POLLIN;
	poll(&p, 1, 1000);
	close(c);
	p.fd = a;
	poll(&p, 1, 1000);
	errno = 0;
	check("tcp: a close with unread data resets the peer",
	      recv(a, buf, sizeof(buf), 0) == -1 && errno == ECONNRESET);
	close(a);

	/* No listener: ECONNREFUSED. */
	int d = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in closed = inet_addr4(INADDR_LOOPBACK, 9);
	errno = 0;
	check("tcp: connect to a closed port gives ECONNREFUSED",
	      connect(d, (struct sockaddr *)&closed, sizeof(closed)) == -1 && errno == ECONNREFUSED);
	close(d);

	/* 1 MiB each way between two processes. */
	pid_t pid = fork();
	if (pid == 0) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(s, (struct sockaddr *)&an, sizeof(an)) < 0)
			_exit(10);
		_exit(tcp_client(s, "lo"));
	}
	int s = accept(l, NULL, NULL);
	int r = s >= 0 ? tcp_server(s) : 9;
	close(s);
	int status = -1;
	waitpid(pid, &status, 0);
	printf("init: inet: tcp lo: server %d, client status %d\n", r, status);
	check("tcp: 1 MiB each way over lo", r == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* A poll on the listener in another process wakes when the connection comes, and does not
	 * wait for its timeout. The socket adds its queue to the poll, as sock_poll_wait in
	 * include/net/sock.h of Linux. recvmsg01 of LTP waits so with select (#470). */
	pid = fork();
	if (pid == 0) {
		struct pollfd w = { .fd = l, .events = POLLIN };
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		int n = poll(&w, 1, 5000);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
		_exit(n == 1 && ms < 3000 ? 0 : 1);
	}
	usleep(200000);
	c = socket(AF_INET, SOCK_STREAM, 0);
	connect(c, (struct sockaddr *)&an, sizeof(an));
	status = -1;
	waitpid(pid, &status, 0);
	check("tcp: a poll on the listener wakes at a connection",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	a = accept(l, NULL, NULL);
	close(a);
	close(c);
	close(ep);
	close(l);
}

/* Connects to the server of xtask on the host, at 10.0.2.2 and the port of the command line. */
static void test_tcp_host(int port)
{
	if (port <= 0) {
		printf("init: inet: tcp host: no port\n");
		return;
	}
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in host = inet_addr4(0x0a000202, port);
	int c = connect(s, (struct sockaddr *)&host, sizeof(host));
	int r = c == 0 ? tcp_client(s, "host") : -errno;
	printf("init: inet: tcp host: connect %d, result %d\n", c, r);
	check("tcp: 1 MiB each way with the host", r == 0);
	close(s);
}

#define RK_ETH_P_ALL 0x0003
#define RK_TUNSETIFF _IOW('T', 202, int)
#define RK_IFF_TUN 0x0001
#define RK_IFF_NO_PI 0x1000
#define RK_IFF_MULTI_QUEUE 0x0100
#define RK_IFF_ATTACH_QUEUE 0x0200
#define RK_IFF_DETACH_QUEUE 0x0400
#define RK_TUNSETQUEUE _IOW('T', 217, int)
#define RK_TUNSETIFINDEX _IOW('T', 218, unsigned int)
#define RK_N_SLIP 1
#define RK_N_SLCAN 17
#define RK_ETH_P_IP 0x0800
#define RK_ETH_P_CAN 0x000c

/* Opens a pty pair and sets the line discipline ldisc on the slave. Gives the master, the slave
 * in *slave and the name of the network device in name, or -1. */
static int line_open(int ldisc, int *slave, char *name)
{
	char path[32];
	if (access("/dev/pts/ptmx", F_OK) != 0) {
		mkdir("/dev/pts", 0755);
		mount("devpts", "/dev/pts", "devpts", 0, NULL);
	}
	int m = pty_open_pair(path, sizeof(path));
	*slave = m < 0 ? -1 : open(path, O_RDWR | O_NOCTTY);
	if (*slave < 0 || ioctl(*slave, TIOCSETD, &ldisc) != 0 || ioctl(*slave, SIOCGIFNAME, name) != 0) {
		close(m);
		return -1;
	}
	return m;
}

/* Sets the device name up with the MTU mtu, and binds a new packet socket to it for the
 * protocol proto. Gives the socket, or -1. */
static int line_socket(const char *name, int mtu, int proto)
{
	int p = socket(AF_PACKET, SOCK_RAW, 0);
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, name);
	ifr.ifr_mtu = mtu;
	int r = ioctl(p, SIOCSIFMTU, &ifr);
	r |= ioctl(p, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r |= ioctl(p, SIOCSIFFLAGS, &ifr);
	r |= ioctl(p, SIOCGIFINDEX, &ifr);
	struct sockaddr_ll ll = { .sll_family = AF_PACKET, .sll_protocol = htons(proto),
				  .sll_ifindex = ifr.ifr_ifindex };
	r |= bind(p, (struct sockaddr *)&ll, sizeof(ll));
	if (p < 0 || r != 0) {
		close(p);
		return -1;
	}
	return p;
}

/* Reads at most size bytes from fd after a poll of one second. */
static long line_read(int fd, void *buf, size_t size)
{
	struct pollfd pf = { .fd = fd, .events = POLLIN };
	return poll(&pf, 1, 1000) == 1 ? read(fd, buf, size) : -1;
}

/* The line disciplines N_SLIP and N_SLCAN on a pty slave, as LTP pty04 (#433). */
static void test_slip(void)
{
	char name[IFNAMSIZ] = { 0 };
	int s = -1, d = -1;
	int m = line_open(RK_N_SLIP, &s, name);
	check("TIOCSETD N_SLIP makes a SLIP device", m >= 0 && strncmp(name, "sl", 2) == 0 &&
						       ioctl(s, TIOCGETD, &d) == 0 && d == RK_N_SLIP);
	if (m < 0)
		return;
	check("a read of a slave with N_SLIP gives EIO", read(s, &d, 1) == -1 && errno == EIO);
	int p = line_socket(name, 1000, RK_ETH_P_IP);
	check("a packet socket binds to the SLIP device", p >= 0);
	/* A SLIP frame from the master. ESC ESC_END is END, and ESC ESC_ESC is ESC. */
	unsigned char in[] = { 'a', 0xdb, 0xdc, 'b', 0xdb, 0xdd, 'c', 0xc0 }, buf[64];
	struct sockaddr_ll from = { 0 };
	socklen_t fl = sizeof(from);
	struct pollfd pf = { .fd = p, .events = POLLIN };
	long n = -1;
	if (write(m, in, sizeof(in)) == sizeof(in) && poll(&pf, 1, 1000) == 1)
		n = recvfrom(p, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
	check("a packet socket gets the SLIP frame of the master",
	      n == 5 && memcmp(buf, "a\xc0" "b\xdb" "c", 5) == 0 && from.sll_hatype == 256 &&
		      from.sll_protocol == htons(RK_ETH_P_IP));
	/* A frame that the socket sends goes to the master with END at both ends. */
	n = send(p, "x\xc0y", 3, 0) == 3 ? line_read(m, buf, sizeof(buf)) : -1;
	check("the master reads the SLIP frame of the packet socket",
	      n == 6 && memcmp(buf, "\xc0x\xdb\xdcy\xc0", 6) == 0);
	/* A hang up of the slave removes the device. The socket gets ENETDOWN, as packet_notifier. */
	check("a hang up of the slave removes the SLIP device",
	      ioctl(s, TIOCVHANGUP, 0) == 0 && if_nametoindex(name) == 0);
	check("a packet socket of a removed device gets ENETDOWN and then ENXIO",
	      recv(p, buf, sizeof(buf), MSG_DONTWAIT) == -1 && errno == ENETDOWN &&
		      send(p, "x", 1, 0) == -1 && errno == ENXIO);
	close(p);
	close(s);
	close(m);

	/* N_SLCAN: a CAN frame is a line of text. */
	m = line_open(RK_N_SLCAN, &s, name);
	check("TIOCSETD N_SLCAN makes a serial line CAN device", m >= 0 && strncmp(name, "slcan", 5) == 0);
	if (m < 0)
		return;
	p = line_socket(name, 16, RK_ETH_P_CAN);
	check("a packet socket binds to the serial line CAN device", p >= 0);
	const char *line = "t00185f5f5f5f5f5f5f5f\r";
	pf.fd = p;
	n = -1;
	if (write(m, line, strlen(line)) == (long)strlen(line) && poll(&pf, 1, 1000) == 1)
		n = recv(p, buf, sizeof(buf), 0);
	check("a packet socket gets the CAN frame of the master",
	      n == 16 && memcmp(buf, "\x01\0\0\0\x08\0\0\0________", 16) == 0);
	n = n == 16 && send(p, buf, 16, 0) == 16 ? line_read(m, buf, sizeof(buf)) : -1;
	check("the master reads the CAN frame of the packet socket",
	      n == 22 && memcmp(buf, "t00185F5F5F5F5F5F5F5F\r", 22) == 0);
	close(m);
	check("the close of the master removes the serial line CAN device", if_nametoindex(name) == 0);
	close(p);
	close(s);
}

/* An AF_PACKET socket on lo gets the frames of a datagram over lo. */
static void test_packet_lo(void)
{
	int p = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(RK_ETH_P_ALL));
	check("an AF_PACKET socket opens", p >= 0);
	if (p < 0)
		return;
	struct sockaddr_ll ll = { .sll_family = AF_PACKET, .sll_protocol = htons(RK_ETH_P_ALL),
				  .sll_ifindex = if_nametoindex("lo") };
	check("an AF_PACKET socket binds to lo", bind(p, (struct sockaddr *)&ll, sizeof(ll)) == 0);
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in to = inet_addr4(INADDR_LOOPBACK, 9);
	sendto(u, "rkpkt", 5, 0, (struct sockaddr *)&to, sizeof(to));
	int found = 0, frames = 0;
	for (;;) {
		struct pollfd pf = { .fd = p, .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			break;
		unsigned char buf[256];
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		long n = recvfrom(p, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
		if (n < 0)
			break;
		frames++;
		/* An Ethernet header, an IPv4 header of 20 bytes and a UDP header come first. */
		if (n == 14 + 20 + 8 + 5 && buf[12] == 8 && buf[13] == 0 && from.sll_family == AF_PACKET &&
		    memcmp(buf + 42, "rkpkt", 5) == 0)
			found++;
		if (found == 2)
			break;
	}
	printf("init: inet: packet: %d frames on lo, %d with the datagram\n", frames, found);
	check("an AF_PACKET socket gets the datagram out and in on lo", found == 2);
	close(u);
	close(p);
}

/* The mapped rings of <linux/if_packet.h>. The musl headers do not have them. */
#define RK_PACKET_RX_RING 5
#define RK_PACKET_STATISTICS 6
#define RK_PACKET_VERSION 10
#define RK_PACKET_HDRLEN 11
#define RK_TPACKET_V2 1
#define RK_TPACKET_V3 2
#define RK_TP_STATUS_USER 1

struct rk_tpacket_req3 {
	unsigned int block_size, block_nr, frame_size, frame_nr;
	unsigned int retire_blk_tov, sizeof_priv, feature_req_word;
};

/* Sends "rkring" to the discard port on lo. */
static void packet_ring_send(void)
{
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in to = inet_addr4(INADDR_LOOPBACK, 9);
	sendto(u, "rkring", 6, 0, (struct sockaddr *)&to, sizeof(to));
	close(u);
}

/* Tells if the frame at mac has the datagram of packet_ring_send after an Ethernet, an IPv4
 * and a UDP header. */
static int packet_ring_has(const unsigned char *mac, unsigned int snaplen)
{
	return snaplen == 14 + 20 + 8 + 6 && memcmp(mac + 42, "rkring", 6) == 0;
}

/* Opens a packet socket on lo with a receive ring of version, as af_packet.c of Linux. */
static int packet_ring_open(int version, struct rk_tpacket_req3 *req, unsigned char **ring)
{
	int p = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(RK_ETH_P_ALL));
	if (p < 0)
		return -1;
	int ok = setsockopt(p, SOL_PACKET, RK_PACKET_VERSION, &version, sizeof(version)) == 0;
	socklen_t rl = version == RK_TPACKET_V3 ? sizeof(*req) : 16;
	ok = ok && setsockopt(p, SOL_PACKET, RK_PACKET_RX_RING, req, rl) == 0;
	struct sockaddr_ll ll = { .sll_family = AF_PACKET, .sll_protocol = htons(RK_ETH_P_ALL),
				  .sll_ifindex = if_nametoindex("lo") };
	ok = ok && bind(p, (struct sockaddr *)&ll, sizeof(ll)) == 0;
	size_t size = (size_t)req->block_size * req->block_nr;
	*ring = ok ? mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, p, 0) : MAP_FAILED;
	if (*ring == MAP_FAILED) {
		close(p);
		return -1;
	}
	return p;
}

/* A TPACKET_V2 and a TPACKET_V3 receive ring on lo get a datagram through the mapping. */
static void test_packet_ring(void)
{
	int v = RK_TPACKET_V3;
	socklen_t vl = sizeof(v);
	int s = socket(AF_PACKET, SOCK_RAW, 0);
	check("PACKET_HDRLEN gives 48 for TPACKET_V3",
	      getsockopt(s, SOL_PACKET, RK_PACKET_HDRLEN, &v, &vl) == 0 && v == 48);
	close(s);

	struct rk_tpacket_req3 req = { 4096, 1, 2048, 2, 0, 0, 0 };
	unsigned char *ring;
	int p = packet_ring_open(RK_TPACKET_V2, &req, &ring);
	check("a TPACKET_V2 receive ring maps", p >= 0);
	if (p >= 0) {
		packet_ring_send();
		int found = 0;
		for (int i = 0; i < 4 && !found; i++) {
			struct pollfd pf = { .fd = p, .events = POLLIN };
			if (poll(&pf, 1, 1000) != 1)
				break;
			for (int f = 0; f < 2; f++) {
				unsigned char *h = ring + f * 2048;
				unsigned int status, snaplen;
				unsigned short mac;
				memcpy(&status, h, 4);
				memcpy(&snaplen, h + 8, 4);
				memcpy(&mac, h + 12, 2);
				if (!(status & RK_TP_STATUS_USER))
					continue;
				found |= packet_ring_has(h + mac, snaplen);
				/* Gives the frame back to the kernel. */
				__atomic_store_n((unsigned int *)h, 0, __ATOMIC_RELEASE);
			}
		}
		check("a TPACKET_V2 ring gets the datagram on lo", found);
		struct { unsigned int packets, drops; } st;
		socklen_t sl = sizeof(st);
		check("PACKET_STATISTICS counts the frames of the ring",
		      getsockopt(p, SOL_PACKET, RK_PACKET_STATISTICS, &st, &sl) == 0 && sl == 8 &&
			      st.packets >= 1);
		munmap(ring, 4096);
		close(p);
	}

	struct rk_tpacket_req3 req3 = { 4096, 2, 2048, 4, 10, 0, 0 };
	p = packet_ring_open(RK_TPACKET_V3, &req3, &ring);
	check("a TPACKET_V3 receive ring maps", p >= 0);
	if (p < 0)
		return;
	packet_ring_send();
	int found = 0, blocks = 0;
	for (int i = 0; i < 4 && !found; i++) {
		struct pollfd pf = { .fd = p, .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			break;
		for (int b = 0; b < 2; b++) {
			unsigned char *blk = ring + b * 4096;
			unsigned int status, count, first;
			memcpy(&status, blk + 8, 4);
			memcpy(&count, blk + 12, 4);
			memcpy(&first, blk + 16, 4);
			if (!(status & RK_TP_STATUS_USER))
				continue;
			blocks++;
			unsigned char *h = blk + first;
			for (unsigned int k = 0; k < count; k++) {
				unsigned int next, snaplen;
				unsigned short mac;
				memcpy(&next, h, 4);
				memcpy(&snaplen, h + 12, 4);
				memcpy(&mac, h + 24, 2);
				found |= packet_ring_has(h + mac, snaplen);
				h += next;
			}
			__atomic_store_n((unsigned int *)(blk + 8), 0, __ATOMIC_RELEASE);
		}
	}
	printf("init: inet: packet ring: %d blocks of TPACKET_V3\n", blocks);
	check("a TPACKET_V3 block on lo gets the datagram after the timeout", found);
	munmap(ring, 8192);
	close(p);
}

/* Makes a TUN device, sends a datagram through it, and writes an echo request into it. The
 * stack must send the echo reply back to the TUN file. */
static void test_tun(void)
{
	int t = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	check("/dev/net/tun opens", t >= 0);
	if (t < 0)
		return;
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, "rktun%d");
	ifr.ifr_flags = RK_IFF_TUN | RK_IFF_NO_PI;
	check("TUNSETIFF makes rktun0", ioctl(t, RK_TUNSETIFF, &ifr) == 0 &&
						strcmp(ifr.ifr_name, "rktun0") == 0);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = inet_addr4(0x0a090901, 0);
	memcpy(&ifr.ifr_addr, &a, sizeof(a));
	int r = ioctl(s, SIOCSIFADDR, &ifr);
	a = inet_addr4(0xffffff00, 0);
	memcpy(&ifr.ifr_netmask, &a, sizeof(a));
	r |= ioctl(s, SIOCSIFNETMASK, &ifr);
	r |= ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r |= ioctl(s, SIOCSIFFLAGS, &ifr);
	check("rktun0 gets 10.9.9.1/24 and goes up", r == 0);

	struct sockaddr_in peer = inet_addr4(0x0a090902, 9);
	sendto(s, "rktun", 5, 0, (struct sockaddr *)&peer, sizeof(peer));
	unsigned char buf[256];
	long n = -1;
	for (int i = 0; i < 10; i++) {
		struct pollfd pf = { .fd = t, .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			break;
		n = read(t, buf, sizeof(buf));
		if (n == 20 + 8 + 5 && buf[0] == 0x45)
			break;
	}
	printf("init: inet: tun: read %ld bytes\n", n);
	check("a TUN file reads the datagram as an IPv4 packet",
	      n == 33 && buf[9] == IPPROTO_UDP && memcmp(buf + 28, "rktun", 5) == 0);

	/* An echo request from 10.9.9.2 to 10.9.9.1. */
	unsigned char req[28] = { 0x45, 0, 0, 28, 0, 1, 0, 0, 64, IPPROTO_ICMP, 0, 0,
				  10, 9, 9, 2, 10, 9, 9, 1, 8, 0, 0, 0, 0x56, 0x78, 0, 1 };
	unsigned short sum = inet_sum(req, 20);
	memcpy(req + 10, &sum, 2);
	sum = inet_sum(req + 20, 8);
	memcpy(req + 22, &sum, 2);
	check("a TUN file takes a packet", write(t, req, sizeof(req)) == sizeof(req));
	int reply = 0;
	for (int i = 0; i < 10 && !reply; i++) {
		struct pollfd pf = { .fd = t, .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			break;
		n = read(t, buf, sizeof(buf));
		reply = n == 28 && buf[9] == IPPROTO_ICMP && buf[20] == 0 && buf[24] == 0x56 &&
			memcmp(buf + 16, req + 12, 4) == 0;
	}
	check("the stack replies to an echo request through the TUN device", reply);
	close(s);
	close(t);
	check("rktun0 goes away when the file closes", if_nametoindex("rktun0") == 0);
}

/* Reads the frames of the TUN file t until there is no frame. Gives the number of UDP datagrams
 * of 4 bytes over IPv4. The device sends IPv6 frames too, for example MLD reports. */
static int tun_udp_frames(int t, unsigned char *buf, int size)
{
	int got = 0;
	long n;
	while ((n = read(t, buf, size)) > 0)
		got += n == 32 && buf[0] == 0x45 && buf[9] == IPPROTO_UDP;
	return got;
}

/* Reads the frames of the TUN file t for up to five seconds. Gives 1 when an MLD message of the
 * type `type` names the group `group`. A message of MLD comes after the IPv6 header and the
 * hop-by-hop header of 8 bytes. A report of MLDv2 has records of 20 bytes after 8 bytes, with
 * the record type `rec` at the offset 0 and the group at the offset 4. A message of MLDv1 has
 * the group at the offset 8. */
static int tun_mld(int t, int type, int rec, const struct in6_addr *group)
{
	unsigned char buf[1500];
	for (int i = 0; i < 5; i++) {
		struct pollfd pf = { .fd = t, .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			continue;
		long n;
		while ((n = read(t, buf, sizeof(buf))) > 0) {
			if (n < 40 + 8 + 24 || (buf[0] >> 4) != 6 || buf[6] != 0 || buf[7] != 1 ||
			    buf[40] != IPPROTO_ICMPV6 || buf[48] != type)
				continue;
			if (type != 143 && memcmp(buf + 56, group, 16) == 0)
				return 1;
			int records = (buf[54] << 8) | buf[55];
			for (int k = 0; type == 143 && k < records && 56 + 20 * k + 20 <= n; k++)
				if (buf[56 + 20 * k] == rec && !memcmp(buf + 56 + 20 * k + 4, group, 16))
					return 1;
		}
	}
	return 0;
}

/* Writes an MLD query of `len` bytes from fe80::2 to ff02::1 into the TUN file t. A query of 24
 * bytes is MLDv1, and a query of 28 bytes is MLDv2. The maximum delay is 10 ms. */
static int tun_mld_query(int t, int len)
{
	unsigned char p[40 + 28] = { 0x60, 0, 0, 0, 0, len, IPPROTO_ICMPV6, 1 };
	p[8] = 0xfe;
	p[9] = 0x80;
	p[23] = 2;
	p[24] = 0xff;
	p[25] = 0x02;
	p[39] = 1;
	unsigned char *m = p + 40;
	m[0] = 130;
	m[5] = 10;
	/* The checksum covers the pseudo header: the addresses, the length and the next header. */
	unsigned char sum[40 + 28] = { 0 };
	memcpy(sum, p + 8, 32);
	sum[35] = len;
	sum[39] = IPPROTO_ICMPV6;
	memcpy(sum + 40, m, len);
	unsigned short c = inet_sum(sum, 40 + len);
	memcpy(m + 2, &c, 2);
	return write(t, p, 40 + len) == 40 + len;
}

/* Reads /proc/net/if_inet6. Gives 1 when the device `name` has a link local address that is
 * not tentative. */
static int tun_has_link_local(const char *name)
{
	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	FILE *f = fopen("/proc/net/if_inet6", "r");
	if (!f)
		return 0;
	char addr[40], dev[32];
	unsigned int ifindex, prefix, scope, flags;
	int found = 0;
	while (fscanf(f, "%39s %x %x %x %x %31s", addr, &ifindex, &prefix, &scope, &flags, dev) == 6) {
		if (strcmp(dev, name) == 0)
			printf("init: inet: %s has %s, flags %x\n", name, addr, flags);
		found |= strcmp(dev, name) == 0 && strncmp(addr, "fe80", 4) == 0 && prefix == 64 &&
			 !(flags & 0x40);
	}
	fclose(f);
	return found;
}

/* Makes the TUN device rktun6 and brings it up. The device must get a link local address
 * without duplicate address detection. A socket joins a group: the device must send an MLDv2
 * report, and answer a general query of MLDv2 and of MLDv1. After the MLDv1 query, the leave of
 * the group must send an MLDv1 done message (#429). */
static void test_tun6(void)
{
	int t = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, "rktun6");
	ifr.ifr_flags = RK_IFF_TUN | RK_IFF_NO_PI;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	int r = ioctl(t, RK_TUNSETIFF, &ifr);
	r |= ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r |= ioctl(s, SIOCSIFFLAGS, &ifr);
	check("rktun6 goes up", t >= 0 && r == 0);
	close(s);
	if (t < 0 || r != 0)
		return;
	check("rktun6 gets a link local address at once", tun_has_link_local("rktun6"));

	struct ipv6_mreq m = { .ipv6mr_interface = if_nametoindex("rktun6") };
	inet_pton(AF_INET6, "ff02::4242", &m.ipv6mr_multiaddr);
	int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
	r = setsockopt(s6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &m, sizeof(m));
	check("IPV6_JOIN_GROUP joins ff02::4242 on rktun6", r == 0);
	check("the join sends an MLDv2 report", tun_mld(t, 143, 4, &m.ipv6mr_multiaddr));
	errno = 0;
	check("a second join gives EADDRINUSE",
	      setsockopt(s6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &m, sizeof(m)) == -1 &&
		      errno == EADDRINUSE);
	check("a general query of MLDv2 gets a report",
	      tun_mld_query(t, 28) && tun_mld(t, 143, 2, &m.ipv6mr_multiaddr));
	check("a general query of MLDv1 gets a report of MLDv1",
	      tun_mld_query(t, 24) && tun_mld(t, 131, 0, &m.ipv6mr_multiaddr));
	r = setsockopt(s6, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &m, sizeof(m));
	check("the leave sends an MLDv1 done", r == 0 && tun_mld(t, 132, 0, &m.ipv6mr_multiaddr));
	close(s6);
	close(t);
}

/* Makes a TUN device with two queues and the interface index 77, and sends datagrams of 16
 * flows through it. Each queue must get some of them. Then takes a queue off and puts it back. */
static void test_tun_mq(void)
{
	int q[2];
	q[0] = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	q[1] = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (q[0] < 0 || q[1] < 0) {
		check("/dev/net/tun opens two times", 0);
		return;
	}
	unsigned int index = 77;
	check("TUNSETIFINDEX takes an index", ioctl(q[0], RK_TUNSETIFINDEX, &index) == 0);
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, "rkmq0");
	ifr.ifr_flags = RK_IFF_TUN | RK_IFF_NO_PI | RK_IFF_MULTI_QUEUE;
	int r0 = ioctl(q[0], RK_TUNSETIFF, &ifr);
	int r1 = ioctl(q[1], RK_TUNSETIFF, &ifr);
	check("two files attach to the multi-queue device rkmq0", r0 == 0 && r1 == 0);
	check("rkmq0 has the index of TUNSETIFINDEX", if_nametoindex("rkmq0") == 77);
	errno = 0;
	check("TUNSETIFINDEX on an attached file gives EPERM",
	      ioctl(q[1], RK_TUNSETIFINDEX, &index) == -1 && errno == EPERM);
	int single = open("/dev/net/tun", O_RDWR);
	struct ifreq one = { 0 };
	strcpy(one.ifr_name, "rkmq0");
	one.ifr_flags = RK_IFF_TUN | RK_IFF_NO_PI;
	errno = 0;
	check("a file without IFF_MULTI_QUEUE cannot attach to rkmq0",
	      ioctl(single, RK_TUNSETIFF, &one) == -1 && errno == EINVAL);
	close(single);

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = inet_addr4(0x0a090801, 0);
	memcpy(&ifr.ifr_addr, &a, sizeof(a));
	int r = ioctl(s, SIOCSIFADDR, &ifr);
	a = inet_addr4(0xffffff00, 0);
	memcpy(&ifr.ifr_netmask, &a, sizeof(a));
	r |= ioctl(s, SIOCSIFNETMASK, &ifr);
	r |= ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r |= ioctl(s, SIOCSIFFLAGS, &ifr);
	check("rkmq0 gets 10.9.8.1/24 and goes up", r == 0);

	/* Each datagram has its own source port, so it is its own flow. */
	int got[2] = { 0, 0 };
	unsigned char buf[256];
	for (int i = 0; i < 16; i++) {
		int c = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in me = inet_addr4(0x0a090801, 40000 + i);
		bind(c, (struct sockaddr *)&me, sizeof(me));
		struct sockaddr_in peer = inet_addr4(0x0a090802, 9);
		sendto(c, "rkmq", 4, 0, (struct sockaddr *)&peer, sizeof(peer));
		close(c);
	}
	for (int i = 0; i < 10 && got[0] + got[1] < 16; i++) {
		struct pollfd pf[2] = { { .fd = q[0], .events = POLLIN },
					{ .fd = q[1], .events = POLLIN } };
		if (poll(pf, 2, 1000) < 1)
			break;
		for (int k = 0; k < 2; k++)
			got[k] += tun_udp_frames(q[k], buf, sizeof(buf));
	}
	printf("init: inet: tun mq: queue 0 got %d, queue 1 got %d\n", got[0], got[1]);
	check("the flows go to the two queues", got[0] > 0 && got[1] > 0 && got[0] + got[1] == 16);

	struct ifreq qr = { 0 };
	qr.ifr_flags = RK_IFF_DETACH_QUEUE;
	check("TUNSETQUEUE takes a queue off", ioctl(q[1], RK_TUNSETQUEUE, &qr) == 0);
	errno = 0;
	long n = read(q[1], buf, sizeof(buf));
	struct pollfd pf = { .fd = q[1], .events = POLLIN };
	int pr = poll(&pf, 1, 0);
	check("a detached queue gives EBADFD and POLLERR",
	      n == -1 && errno == EBADFD && pr == 1 && (pf.revents & POLLERR));
	got[0] = got[1] = 0;
	for (int i = 0; i < 8; i++) {
		int c = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in me = inet_addr4(0x0a090801, 41000 + i);
		bind(c, (struct sockaddr *)&me, sizeof(me));
		struct sockaddr_in peer = inet_addr4(0x0a090802, 9);
		sendto(c, "rkmq", 4, 0, (struct sockaddr *)&peer, sizeof(peer));
		close(c);
	}
	for (int i = 0; i < 10 && got[0] < 8; i++) {
		pf = (struct pollfd){ .fd = q[0], .events = POLLIN };
		if (poll(&pf, 1, 1000) != 1)
			break;
		got[0] += tun_udp_frames(q[0], buf, sizeof(buf));
	}
	check("the queue that is left gets all of the flows", got[0] == 8);
	qr.ifr_flags = RK_IFF_ATTACH_QUEUE;
	r = ioctl(q[1], RK_TUNSETQUEUE, &qr);
	/* The queue can get an MLD report of the device, so it reads until there is no frame. */
	do {
		errno = 0;
		n = read(q[1], buf, sizeof(buf));
	} while (n > 0);
	check("TUNSETQUEUE puts the queue back", r == 0 && n == -1 && errno == EAGAIN);
	close(s);
	close(q[0]);
	check("rkmq0 stays while a queue is open", if_nametoindex("rkmq0") == 77);
	close(q[1]);
	check("rkmq0 goes away when its last file closes", if_nametoindex("rkmq0") == 0);
}

/* The netlink attribute of the other end of a veth pair, VETH_INFO_PEER of <linux/veth.h>. */
#define RK_VETH_INFO_PEER 1

/* Adds the attribute `type` with `len` bytes of `data` to the netlink message m. A null `data`
 * gives zeros. Gives the attribute, so that the caller can end a nest with nl_end. */
static struct rtattr *nl_put(struct nlmsghdr *m, int type, const void *data, int len)
{
	struct rtattr *a = (struct rtattr *)((char *)m + NLMSG_ALIGN(m->nlmsg_len));
	a->rta_type = type;
	a->rta_len = RTA_LENGTH(len);
	if (data)
		memcpy(RTA_DATA(a), data, len);
	else
		memset(RTA_DATA(a), 0, len);
	m->nlmsg_len = NLMSG_ALIGN(m->nlmsg_len) + RTA_ALIGN(a->rta_len);
	return a;
}

/* Sets the length of the nest `a` to the end of the message m. */
static void nl_end(struct nlmsghdr *m, struct rtattr *a)
{
	a->rta_len = (char *)m + m->nlmsg_len - (char *)a;
}

/* Sends the request m on the rtnetlink socket fd and reads the first reply into buf. Gives the
 * length of the reply, or -1. */
static long nl_ask(int fd, struct nlmsghdr *m, void *buf, int size)
{
	m->nlmsg_flags |= NLM_F_REQUEST;
	if (send(fd, m, m->nlmsg_len, 0) != (long)m->nlmsg_len)
		return -1;
	return recv(fd, buf, size, 0);
}

/* Sends the request m with NLM_F_ACK. Gives the error of the ack: 0, or a negative errno. */
static int nl_talk(int fd, struct nlmsghdr *m)
{
	char buf[1024];
	m->nlmsg_flags |= NLM_F_ACK;
	long n = nl_ask(fd, m, buf, sizeof(buf));
	struct nlmsghdr *r = (struct nlmsghdr *)buf;
	if (n < (long)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || r->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	return ((struct nlmsgerr *)NLMSG_DATA(r))->error;
}

/* Gives the u32 attribute `type` of the link message r, or -1 if it is not there. */
static long link_u32(struct nlmsghdr *r, int type)
{
	struct ifinfomsg *ifi = NLMSG_DATA(r);
	int len = r->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, len); a = RTA_NEXT(a, len))
		if (a->rta_type == type)
			return *(unsigned int *)RTA_DATA(a);
	return -1;
}

/* Gives the interface `name` the IPv4 address `addr`/24 and sets it up. Gives 0 or -1. */
static int if_up_addr(const char *name, unsigned long addr)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, name);
	struct sockaddr_in a = inet_addr4(addr, 0);
	memcpy(&ifr.ifr_addr, &a, sizeof(a));
	int r = ioctl(s, SIOCSIFADDR, &ifr);
	a = inet_addr4(0xffffff00, 0);
	memcpy(&ifr.ifr_netmask, &a, sizeof(a));
	r |= ioctl(s, SIOCSIFNETMASK, &ifr);
	r |= ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r |= ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);
	return r ? -1 : 0;
}

/* Gives the flags of the interface `name`, or -1. */
static int if_flags(const char *name)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, name);
	int r = ioctl(s, SIOCGIFFLAGS, &ifr);
	close(s);
	return r ? -1 : (unsigned short)ifr.ifr_flags;
}

/* Reads the first line of the file `path` into buf. Gives buf, or "" on an error. */
static char *read_line(const char *path, char *buf, int size)
{
	int fd = open(path, O_RDONLY);
	long n = fd < 0 ? -1 : read(fd, buf, size - 1);
	if (fd >= 0)
		close(fd);
	buf[n < 0 ? 0 : n] = 0;
	buf[strcspn(buf, "\n")] = 0;
	return buf;
}

/* The other end of the pair in test_veth. It runs in its own network namespace. It tells the
 * first end its state with one byte on `out`, and waits for a byte on `in` for each step. */
static void veth_peer(int in, int out)
{
	char c = unshare(CLONE_NEWNET) == 0;
	write(out, &c, 1);
	if (read(in, &c, 1) != 1)
		_exit(1);
	c = if_nametoindex("rkvb") > 0 && if_up_addr("rkvb", 0x0a4d0002) == 0;
	/* Answer a ping to a multicast group, as net.ipv4.icmp_echo_ignore_broadcasts. */
	int sysctl = open("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", O_WRONLY);
	c &= sysctl >= 0 && write(sysctl, "0\n", 2) == 2;
	close(sysctl);
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in me = inet_addr4(0, 7777);
	c &= bind(u, (struct sockaddr *)&me, sizeof(me)) == 0;
	write(out, &c, 1);
	char buf[16];
	struct sockaddr_in from;
	c = 0;
	for (int i = 0; i < 10 && !c; i++) {
		long n = recv_wait(u, buf, sizeof(buf), &from, 1000);
		c = n == 6 && memcmp(buf, "rkveth", 6) == 0 &&
		    from.sin_addr.s_addr == htonl(0x0a4d0001);
	}
	if (c)
		sendto(u, "rkback", 6, 0, (struct sockaddr *)&from, sizeof(from));
	write(out, &c, 1);
	if (read(in, &c, 1) != 1)
		_exit(1);
	c = if_nametoindex("rkvb") == 0;
	write(out, &c, 1);
	_exit(0);
}

#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif

/* Sends an echo request with `size` bytes of data and the sequence `seq` to dst on the raw
 * ICMP socket fd, and waits at most ms milliseconds for the reply. Gives 0 if the reply came
 * with all of the data, 1 if no reply came, or the error of sendto as a negative errno. */
static int ping_size(int fd, unsigned long dst, int size, int seq, int ms)
{
	static unsigned char req[8 + 8192], buf[60 + 8 + 8192];
	memset(req, 0, 8);
	req[0] = 8;
	req[4] = 0x45;
	req[5] = 0x67;
	req[6] = seq >> 8;
	req[7] = seq;
	for (int i = 0; i < size; i++)
		req[8 + i] = i * 7;
	unsigned short sum = inet_sum(req, 8 + size);
	memcpy(req + 2, &sum, 2);
	struct sockaddr_in to = inet_addr4(dst, 0), from;
	if (sendto(fd, req, 8 + size, 0, (struct sockaddr *)&to, sizeof(to)) != 8 + size)
		return -errno;
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (elapsed_us(&t0) < ms * 1000L) {
		long n = recv_wait(fd, buf, sizeof(buf), &from, 100);
		if (n < 20)
			continue;
		int hl = (buf[0] & 0xf) * 4;
		if (n == hl + 8 + size && buf[hl] == 0 && memcmp(buf + hl + 4, req + 4, 4) == 0 &&
		    memcmp(buf + hl + 8, req + 8, size) == 0)
			return 0;
	}
	return 1;
}

/* Gives 1 if /proc/net/arp has a line for the address `ip` with the flags `flags` and the
 * hardware address `mac`, as arp_seq_show in net/ipv4/arp.c of Linux. */
static int arp_has(const char *ip, const char *flags, const char *mac)
{
	static char text[4096];
	if (read_file("/proc/net/arp", text, sizeof(text)) < 0)
		return 0;
	int len = strlen(ip);
	for (char *l = text; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
		char line[256];
		snprintf(line, sizeof(line), "%.*s", (int)strcspn(l, "\n"), l);
		if (strncmp(line, ip, len) == 0 && line[len] == ' ')
			return strstr(line, flags) && strstr(line, mac);
	}
	return 0;
}

/* Sends RTM_NEWNEIGH or RTM_DELNEIGH for the IPv4 address `addr` on the interface `index` on
 * the rtnetlink socket fd, as `ip neigh`. A null mac sends no NDA_LLADDR. Gives the error of
 * the ack. */
static int nl_neigh(int fd, int type, int flags, int index, unsigned long addr,
		    const unsigned char *mac)
{
	union {
		struct nlmsghdr h;
		char buf[256];
	} m = { 0 };
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	m.h.nlmsg_type = type;
	m.h.nlmsg_flags = flags;
	struct ndmsg *nd = NLMSG_DATA(&m.h);
	nd->ndm_family = AF_INET;
	nd->ndm_ifindex = index;
	nd->ndm_state = NUD_PERMANENT;
	unsigned int a = htonl(addr);
	nl_put(&m.h, NDA_DST, &a, 4);
	if (mac)
		nl_put(&m.h, NDA_LLADDR, mac, 6);
	return nl_talk(fd, &m.h);
}

/* Sends RTM_NEWNEIGH or RTM_DELNEIGH with NTF_PROXY for the IPv4 address `addr` on the
 * interface `index` on the rtnetlink socket fd, as `ip neigh add proxy`. Gives the error of the
 * ack. */
static int nl_pneigh(int fd, int type, int index, unsigned long addr)
{
	union {
		struct nlmsghdr h;
		char buf[256];
	} m = { 0 };
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	m.h.nlmsg_type = type;
	m.h.nlmsg_flags = type == RTM_NEWNEIGH ? NLM_F_CREATE : 0;
	struct ndmsg *nd = NLMSG_DATA(&m.h);
	nd->ndm_family = AF_INET;
	nd->ndm_ifindex = index;
	nd->ndm_flags = NTF_PROXY;
	unsigned int a = htonl(addr);
	nl_put(&m.h, NDA_DST, &a, 4);
	return nl_talk(fd, &m.h);
}

/* Dumps the proxy entries with RTM_GETNEIGH and NTF_PROXY on the rtnetlink socket fd, as
 * pneigh_dump_table in net/core/neighbour.c. Gives 1 if the dump has the IPv4 address `addr` on
 * the interface `index` with NTF_PROXY and NUD_NONE. */
static int nl_pneigh_dumped(int fd, int index, unsigned long addr)
{
	union {
		struct nlmsghdr h;
		char buf[64];
	} m = { 0 };
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	m.h.nlmsg_type = RTM_GETNEIGH;
	m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	struct ndmsg *q = NLMSG_DATA(&m.h);
	q->ndm_family = AF_INET;
	q->ndm_flags = NTF_PROXY;
	if (send(fd, &m, m.h.nlmsg_len, 0) != (long)m.h.nlmsg_len)
		return 0;
	static char buf[8192];
	unsigned int a = htonl(addr);
	int found = 0;
	for (;;) {
		long n = recv(fd, buf, sizeof(buf), 0);
		if (n <= 0)
			return 0;
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, n);
		     h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
				return found;
			struct ndmsg *nd = NLMSG_DATA(h);
			if (!(nd->ndm_flags & NTF_PROXY) || nd->ndm_state != NUD_NONE ||
			    nd->ndm_ifindex != index)
				continue;
			int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*nd));
			for (struct rtattr *r = (struct rtattr *)((char *)nd + NLMSG_ALIGN(sizeof(*nd)));
			     RTA_OK(r, len); r = RTA_NEXT(r, len))
				if (r->rta_type == NDA_DST && RTA_PAYLOAD(r) == 4 &&
				    memcmp(RTA_DATA(r), &a, 4) == 0)
					found = 1;
		}
	}
}

/* Gives 1 if the file `path` has the text `want`. */
static int file_has(const char *path, const char *want)
{
	static char text[8192];
	return read_file(path, text, sizeof(text)) >= 0 && strstr(text, want) != NULL;
}

/* Waits at most one second for a message of the type `type` for the IPv4 address `addr` on the
 * rtnetlink socket fd, which is in the group RTNLGRP_NEIGH. Gives the state of the entry, or -1. */
static int nl_neigh_event(int fd, int type, unsigned long addr)
{
	static char buf[8192];
	unsigned int a = htonl(addr);
	for (int i = 0; i < 20; i++) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		if (poll(&p, 1, 1000) != 1)
			return -1;
		long n = recv(fd, buf, sizeof(buf), 0);
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; n > 0 && NLMSG_OK(h, n);
		     h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_type != type)
				continue;
			struct ndmsg *nd = NLMSG_DATA(h);
			int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*nd));
			for (struct rtattr *r = (struct rtattr *)((char *)nd + NLMSG_ALIGN(sizeof(*nd)));
			     RTA_OK(r, len); r = RTA_NEXT(r, len))
				if (r->rta_type == NDA_DST && RTA_PAYLOAD(r) == 4 &&
				    memcmp(RTA_DATA(r), &a, 4) == 0)
					return nd->ndm_state;
		}
	}
	return -1;
}

/* The IPv4 multicast options over rkva, as net/ipv4/ip_sockglue.c and net/ipv4/igmp.c of
 * Linux, and IP_BIND_ADDRESS_NO_PORT, as __inet_bind in net/ipv4/af_inet.c. */
static void mcast4_checks(int index)
{
	int tx = socket(AF_INET, SOCK_DGRAM, 0), rx = socket(AF_INET, SOCK_DGRAM, 0);
	unsigned char c = 0;
	int v = 0;
	socklen_t len = 1;
	check("getsockopt of IP_MULTICAST_TTL with one byte gives 1",
	      getsockopt(tx, IPPROTO_IP, IP_MULTICAST_TTL, &c, &len) == 0 && len == 1 && c == 1);
	c = 10;
	len = sizeof(v);
	check("setsockopt of IP_MULTICAST_TTL takes one byte",
	      setsockopt(tx, IPPROTO_IP, IP_MULTICAST_TTL, &c, 1) == 0 &&
		      getsockopt(tx, IPPROTO_IP, IP_MULTICAST_TTL, &v, &len) == 0 && v == 10);
	c = 0;
	len = sizeof(v);
	check("setsockopt of IP_MULTICAST_LOOP takes one byte",
	      setsockopt(tx, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1) == 0 &&
		      getsockopt(tx, IPPROTO_IP, IP_MULTICAST_LOOP, &v, &len) == 0 && v == 0);
	struct in_addr ifa = { htonl(0x0a4d0001) }, got = { 0 };
	len = sizeof(got);
	check("IP_MULTICAST_IF takes the address of rkva and gives it back",
	      setsockopt(tx, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa)) == 0 &&
		      getsockopt(tx, IPPROTO_IP, IP_MULTICAST_IF, &got, &len) == 0 &&
		      got.s_addr == ifa.s_addr);
	struct in_addr none = { htonl(0x0a4d0063) };
	check("IP_MULTICAST_IF of an address that is not local gives EADDRNOTAVAIL",
	      setsockopt(tx, IPPROTO_IP, IP_MULTICAST_IF, &none, sizeof(none)) == -1 &&
		      errno == EADDRNOTAVAIL);

	int one = 1;
	struct sockaddr_in me = inet_addr4(0, 7790), grp = inet_addr4(0xef010203, 7790);
	setsockopt(rx, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	bind(rx, (struct sockaddr *)&me, sizeof(me));
	struct ip_mreqn mr = { .imr_multiaddr = { htonl(0xef010203) }, .imr_ifindex = index };
	check("IP_ADD_MEMBERSHIP joins 239.1.2.3 on rkva",
	      setsockopt(rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) == 0);
	check("a second IP_ADD_MEMBERSHIP of the group gives EADDRINUSE",
	      setsockopt(rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1 &&
		      errno == EADDRINUSE);
	struct ip_mreq uni = { { htonl(0x0a4d0002) }, { htonl(0x0a4d0001) } };
	check("IP_ADD_MEMBERSHIP of an address that is not multicast gives EINVAL",
	      setsockopt(rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, &uni, sizeof(uni)) == -1 &&
		      errno == EINVAL);
	check("/proc/net/igmp shows 239.1.2.3", file_has("/proc/net/igmp", "030201EF"));
	char buf[16];
	struct sockaddr_in from;
	check("without IP_MULTICAST_LOOP the sender does not get its datagram",
	      sendto(tx, "rkmc", 4, 0, (struct sockaddr *)&grp, sizeof(grp)) == 4 &&
		      recv_wait(rx, buf, sizeof(buf), &from, 300) < 0);
	c = 1;
	setsockopt(tx, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1);
	check("with IP_MULTICAST_LOOP a member of the group gets the datagram from rkva",
	      sendto(tx, "rkmc", 4, 0, (struct sockaddr *)&grp, sizeof(grp)) == 4 &&
		      recv_wait(rx, buf, sizeof(buf), &from, 2000) == 4 &&
		      memcmp(buf, "rkmc", 4) == 0 && from.sin_addr.s_addr == htonl(0x0a4d0001));
	check("IP_DROP_MEMBERSHIP leaves the group",
	      setsockopt(rx, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) == 0 &&
		      !file_has("/proc/net/igmp", "030201EF"));
	check("a second IP_DROP_MEMBERSHIP gives EADDRNOTAVAIL",
	      setsockopt(rx, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) == -1 &&
		      errno == EADDRNOTAVAIL);
	close(tx);
	close(rx);

	/* bind_noport01 of LTP: the port is 0 after bind, and connect gives one. */
	int types[2] = { SOCK_DGRAM, SOCK_STREAM };
	for (int i = 0; i < 2; i++) {
		int fd = socket(AF_INET, types[i], 0);
		struct sockaddr_in a = inet_addr4(0x0a4d0001, 0), b;
		socklen_t bl = sizeof(b);
		check(i ? "TCP: IP_BIND_ADDRESS_NO_PORT keeps the port 0 after bind"
			: "UDP: IP_BIND_ADDRESS_NO_PORT keeps the port 0 after bind",
		      setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one)) == 0 &&
			      bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0 &&
			      getsockname(fd, (struct sockaddr *)&b, &bl) == 0 && b.sin_port == 0 &&
			      b.sin_addr.s_addr == htonl(0x0a4d0001));
		if (i == 0) {
			struct sockaddr_in peer = inet_addr4(0x0a4d0002, 7777);
			bl = sizeof(b);
			check("UDP: connect after IP_BIND_ADDRESS_NO_PORT gives a port",
			      connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0 &&
				      getsockname(fd, (struct sockaddr *)&b, &bl) == 0 &&
				      b.sin_port != 0 && b.sin_addr.s_addr == htonl(0x0a4d0001));
		}
		close(fd);
	}
}

/* The checks of SO_BINDTODEVICE, large pings, multicast and the neighbour table over the veth
 * pair. rkva has 10.77.0.1/24 and the peer has 10.77.0.2/24. */
static void veth_checks(int nl, int index)
{
	/* ping -s 2048 and ping -s 4064: the packets go in fragments, as ip_do_fragment in
	 * net/ipv4/ip_output.c of Linux, and the other end puts them together again, as
	 * net/ipv4/ip_fragment.c. */
	int icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	check("ping -s 2048 crosses the pair in fragments",
	      ping_size(icmp, 0x0a4d0002, 2048, 1, 3000) == 0);
	check("ping -s 4064 crosses the pair in fragments",
	      ping_size(icmp, 0x0a4d0002, 4064, 2, 3000) == 0);
	int pmtu = IP_PMTUDISC_DO;
	check("with IP_PMTUDISC_DO a packet larger than the MTU gives EMSGSIZE",
	      setsockopt(icmp, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu)) == 0 &&
		      ping_size(icmp, 0x0a4d0002, 2048, 3, 100) == -EMSGSIZE);
	pmtu = IP_PMTUDISC_DONT;
	setsockopt(icmp, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));

	/* SO_BINDTODEVICE and SO_BINDTOIFINDEX, as sock_bindtoindex in net/core/sock.c. */
	int bound = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	char name[IFNAMSIZ];
	socklen_t len = sizeof(name);
	check("a socket without a device gives an empty name for SO_BINDTODEVICE",
	      getsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, name, &len) == 0 && len == 0);
	check("SO_BINDTODEVICE of a device that is not there gives ENODEV",
	      setsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, "rkno", 5) == -1 && errno == ENODEV);
	check("SO_BINDTODEVICE binds a socket to lo",
	      setsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0);
	len = sizeof(name);
	check("getsockopt of SO_BINDTODEVICE gives lo",
	      getsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, name, &len) == 0 && len == 3 &&
		      strcmp(name, "lo") == 0);
	int ifi = 0;
	len = sizeof(ifi);
	check("getsockopt of SO_BINDTOIFINDEX gives the index of lo",
	      getsockopt(bound, SOL_SOCKET, SO_BINDTOIFINDEX, &ifi, &len) == 0 &&
		      ifi == (int)if_nametoindex("lo"));
	unsigned char buf[256];
	struct sockaddr_in from;
	while (recv_wait(bound, buf, sizeof(buf), &from, 0) >= 0)
		;
	check("a socket bound to lo does not get the reply that came in on rkva",
	      ping_size(icmp, 0x0a4d0002, 56, 4, 2000) == 0 &&
		      recv_wait(bound, buf, sizeof(buf), &from, 300) < 0);
	check("SO_BINDTOIFINDEX binds the socket to rkva",
	      setsockopt(bound, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof(index)) == 0);
	check("a socket bound to rkva sends on rkva and gets the reply",
	      ping_size(bound, 0x0a4d0002, 56, 5, 2000) == 0);
	pid_t p = fork();
	if (p == 0) {
		int ok = syscall(SYS_setresuid, 1000, 1000, 1000) == 0;
		int u = socket(AF_INET, SOCK_DGRAM, 0);
		ok &= setsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0;
		ok &= setsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, "rkva", 5) == -1 && errno == EPERM;
		ok &= setsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, "", 0) == -1 && errno == EPERM;
		_exit(ok ? 0 : 1);
	}
	int status;
	check("without CAP_NET_RAW a socket binds once, and a change gives EPERM",
	      waitpid(p, &status, 0) == p && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* The devices that are up are in 224.0.0.1, as ip_mc_up in net/ipv4/igmp.c, and the peer
	 * answers a ping to the group when icmp_echo_ignore_broadcasts is 0. */
	check("a ping to 224.0.0.1 on rkva gets a reply from the peer",
	      ping_size(bound, 0xe0000001, 56, 6, 2000) == 0);
	len = sizeof(name);
	check("an empty name for SO_BINDTODEVICE removes the device",
	      setsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, "", 0) == 0 &&
		      getsockopt(bound, SOL_SOCKET, SO_BINDTODEVICE, name, &len) == 0 && len == 0);
	close(bound);
	close(icmp);
	check("/proc/net/igmp shows 224.0.0.1 on rkva",
	      file_has("/proc/net/igmp", "rkva") && file_has("/proc/net/igmp", "010000E0"));
	check("/proc/net/igmp6 shows ff02::1 on rkva",
	      file_has("/proc/net/igmp6", "rkva") &&
		      file_has("/proc/net/igmp6", "ff020000000000000000000000000001"));
	check("/proc/net/dev_mcast shows 01:00:5e:00:00:01 on rkva",
	      file_has("/proc/net/dev_mcast", "01005e000001"));

	/* ip maddr add and del, as dev_mc_add_global in net/core/dev_addr_lists.c. */
	int ms = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq mr = { 0 };
	strcpy(mr.ifr_name, "rkva");
	memcpy(mr.ifr_hwaddr.sa_data, "\x66\x66\0\0\0\x66", 6);
	check("SIOCADDMULTI adds a static link address that /proc/net/dev_mcast shows",
	      ioctl(ms, SIOCADDMULTI, &mr) == 0 && file_has("/proc/net/dev_mcast", "666600000066"));
	check("SIOCDELMULTI removes the address",
	      ioctl(ms, SIOCDELMULTI, &mr) == 0 && !file_has("/proc/net/dev_mcast", "666600000066"));
	check("SIOCDELMULTI of an address that is not there gives ENOENT",
	      ioctl(ms, SIOCDELMULTI, &mr) == -1 && errno == ENOENT);
	close(ms);

	mcast4_checks(index);

	/* ip neigh add, replace and del, as neigh_add and neigh_delete in net/core/neighbour.c. A
	 * socket in RTNLGRP_NEIGH gets the changes, as neigh_update_notify and __neigh_notify. */
	int mon = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_NEIGH };
	bind(mon, (struct sockaddr *)&snl, sizeof(snl));
	unsigned char mac9[6] = { 2, 0, 0, 0, 0, 9 }, mac10[6] = { 2, 0, 0, 0, 0, 0x10 };
	check("RTM_NEWNEIGH adds a permanent entry",
	      nl_neigh(nl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, index, 0x0a4d0009, mac9) == 0 &&
		      arp_has("10.77.0.9", "0x6", "02:00:00:00:00:09"));
	check("RTNLGRP_NEIGH gets RTM_NEWNEIGH of the permanent entry",
	      nl_neigh_event(mon, RTM_NEWNEIGH, 0x0a4d0009) == NUD_PERMANENT);
	check("RTM_NEWNEIGH with NLM_F_EXCL of an entry that is there gives EEXIST",
	      nl_neigh(nl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, index, 0x0a4d0009, mac9) ==
		      -EEXIST);
	check("RTM_NEWNEIGH with NLM_F_REPLACE changes the address",
	      nl_neigh(nl, RTM_NEWNEIGH, NLM_F_REPLACE, index, 0x0a4d0009, mac10) == 0 &&
		      arp_has("10.77.0.9", "0x6", "02:00:00:00:00:10"));
	check("RTM_DELNEIGH removes the entry",
	      nl_neigh(nl, RTM_DELNEIGH, 0, index, 0x0a4d0009, NULL) == 0 &&
		      !arp_has("10.77.0.9", "0x", ":"));
	check("RTNLGRP_NEIGH gets RTM_DELNEIGH of the entry",
	      nl_neigh_event(mon, RTM_DELNEIGH, 0x0a4d0009) == NUD_PERMANENT);
	close(mon);
	check("RTM_DELNEIGH of an entry that is not there gives ENOENT",
	      nl_neigh(nl, RTM_DELNEIGH, 0, index, 0x0a4d0009, NULL) == -ENOENT);
	check("RTM_NEWNEIGH without NLM_F_CREATE of a new entry gives ENOENT",
	      nl_neigh(nl, RTM_NEWNEIGH, NLM_F_REPLACE, index, 0x0a4d0009, mac9) == -ENOENT);

	/* ip neigh add proxy and del proxy, as pneigh_create and pneigh_delete in
	 * net/core/neighbour.c. */
	check("RTM_NEWNEIGH with NTF_PROXY adds a proxy entry that the NTF_PROXY dump shows",
	      nl_pneigh(nl, RTM_NEWNEIGH, index, 0x0a4d0021) == 0 &&
		      nl_pneigh_dumped(nl, index, 0x0a4d0021));
	check("RTM_NEWNEIGH with NTF_PROXY of an entry that is there gives 0",
	      nl_pneigh(nl, RTM_NEWNEIGH, index, 0x0a4d0021) == 0);
	check("/proc/net/arp shows the proxy entry with ATF_PUBL and ATF_PERM",
	      arp_has("10.77.0.33", "0xc", "00:00:00:00:00:00"));
	check("RTM_DELNEIGH with NTF_PROXY removes the proxy entry",
	      nl_pneigh(nl, RTM_DELNEIGH, index, 0x0a4d0021) == 0 &&
		      !nl_pneigh_dumped(nl, index, 0x0a4d0021));
	check("RTM_DELNEIGH with NTF_PROXY of an entry that is not there gives ENOENT",
	      nl_pneigh(nl, RTM_DELNEIGH, index, 0x0a4d0021) == -ENOENT);

	/* arp -s and arp -d, as arp_ioctl in net/ipv4/arp.c. */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct arpreq r = { 0 };
	struct sockaddr_in pa = inet_addr4(0x0a4d000b, 0);
	memcpy(&r.arp_pa, &pa, sizeof(pa));
	r.arp_ha.sa_family = ARPHRD_ETHER;
	memcpy(r.arp_ha.sa_data, "\x02\0\0\0\0\x0b", 6);
	r.arp_flags = ATF_PERM | ATF_COM;
	strcpy(r.arp_dev, "rkva");
	check("SIOCSARP adds a permanent entry",
	      ioctl(s, SIOCSARP, &r) == 0 && arp_has("10.77.0.11", "0x6", "02:00:00:00:00:0b"));
	memset(&r.arp_ha, 0, sizeof(r.arp_ha));
	r.arp_flags = 0;
	check("SIOCGARP gives the address and the flags of the entry",
	      ioctl(s, SIOCGARP, &r) == 0 && (r.arp_flags & ATF_PERM) &&
		      memcmp(r.arp_ha.sa_data, "\x02\0\0\0\0\x0b", 6) == 0);
	check("SIOCDARP removes the entry", ioctl(s, SIOCDARP, &r) == 0 &&
	      !arp_has("10.77.0.11", "0x", ":"));
	check("SIOCGARP and SIOCDARP of an entry that is not there give ENXIO",
	      ioctl(s, SIOCGARP, &r) == -1 && errno == ENXIO && ioctl(s, SIOCDARP, &r) == -1 &&
		      errno == ENXIO);
	close(s);
}

/* The checks of test_veth, in a child with its own network and mount namespaces. */
static int veth_child(void)
{
	failed = 0;
	check("unshare of the network and mount namespaces for the first end",
	      unshare(CLONE_NEWNET | CLONE_NEWNS) == 0);
	int go[2], done[2];
	if (pipe(go) || pipe(done))
		return 1;
	pid_t b = fork();
	if (b == 0)
		veth_peer(go[0], done[1]);
	char c = 0;
	check("the second end is in a new network namespace", read(done[0], &c, 1) == 1 && c);

	/* ip link add rkva type veth peer name rkvb netns PID */
	int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	union {
		struct nlmsghdr h;
		char buf[512];
	} m = { 0 };
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	m.h.nlmsg_type = RTM_NEWLINK;
	m.h.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	nl_put(&m.h, IFLA_IFNAME, "rkva", 5);
	struct rtattr *info = nl_put(&m.h, IFLA_LINKINFO, NULL, 0);
	nl_put(&m.h, IFLA_INFO_KIND, "veth", 4);
	struct rtattr *data = nl_put(&m.h, IFLA_INFO_DATA, NULL, 0);
	struct rtattr *peer = nl_put(&m.h, RK_VETH_INFO_PEER, NULL, sizeof(struct ifinfomsg));
	nl_put(&m.h, IFLA_IFNAME, "rkvb", 5);
	unsigned int pid = b;
	nl_put(&m.h, IFLA_NET_NS_PID, &pid, 4);
	nl_end(&m.h, peer);
	nl_end(&m.h, data);
	nl_end(&m.h, info);
	check("RTM_NEWLINK makes a veth pair with the peer in another namespace",
	      nl_talk(nl, &m.h) == 0);
	int index = if_nametoindex("rkva");
	check("the first end is in this namespace and the peer is not",
	      index > 0 && if_nametoindex("rkvb") == 0);

	/* ip link show rkva */
	memset(&m, 0, sizeof(m));
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	m.h.nlmsg_type = RTM_GETLINK;
	((struct ifinfomsg *)NLMSG_DATA(&m.h))->ifi_index = index;
	char reply[4096];
	long n = nl_ask(nl, &m.h, reply, sizeof(reply));
	struct nlmsghdr *r = (struct nlmsghdr *)reply;
	long link = n > 0 && r->nlmsg_type == RTM_NEWLINK ? link_u32(r, IFLA_LINK) : -1;
	printf("init: inet: veth: rkva is %d, its peer is %ld\n", index, link);
	check("IFLA_LINK gives the index of the peer", link > 0);
	check("IFLA_LINK_NETNSID tells that the peer is in another namespace",
	      n > 0 && link_u32(r, IFLA_LINK_NETNSID) != -1);

	check("rkva gets 10.77.0.1/24 and goes up", if_up_addr("rkva", 0x0a4d0001) == 0);
	int flags = if_flags("rkva");
	check("rkva has no carrier while the peer is down",
	      (flags & IFF_UP) && !(flags & IFF_RUNNING));
	c = 1;
	write(go[1], &c, 1);
	check("the peer gets 10.77.0.2/24 and goes up", read(done[0], &c, 1) == 1 && c);
	check("rkva has the carrier when the peer is up", if_flags("rkva") & IFF_RUNNING);

	/* A datagram goes to the other namespace, and the reply comes back. */
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in to = inet_addr4(0x0a4d0002, 7777), from;
	char buf[16];
	n = -1;
	for (int i = 0; i < 5 && n != 6; i++) {
		sendto(u, "rkveth", 6, 0, (struct sockaddr *)&to, sizeof(to));
		n = recv_wait(u, buf, sizeof(buf), &from, 1000);
	}
	check("a UDP datagram crosses the pair and the reply comes back",
	      n == 6 && memcmp(buf, "rkback", 6) == 0);
	check("the peer got the datagram from 10.77.0.1", read(done[0], &c, 1) == 1 && c);
	close(u);
	veth_checks(nl, index);

	char text[4096];
	int fd = open("/proc/net/dev", O_RDONLY);
	n = fd < 0 ? -1 : read(fd, text, sizeof(text) - 1);
	text[n < 0 ? 0 : n] = 0;
	close(fd);
	check("/proc/net/dev shows rkva", strstr(text, "rkva:") != NULL && !strstr(text, "rkvb:"));
	mkdir("/sys", 0755);
	check("mount sysfs in the new namespace", mount("sysfs", "/sys", "sysfs", 0, NULL) == 0);
	char line[64], want[16];
	struct ifreq ifr = { 0 };
	strcpy(ifr.ifr_name, "rkva");
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	char hw[32] = "";
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
		snprintf(hw, sizeof(hw), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
			 mac[3], mac[4], mac[5]);
	close(s);
	check("/sys/class/net/rkva/address gives the hardware address",
	      hw[0] && strcmp(read_line("/sys/class/net/rkva/address", line, sizeof(line)), hw) == 0);
	snprintf(want, sizeof(want), "%ld", link);
	check("/sys/class/net/rkva/iflink gives the index of the peer",
	      strcmp(read_line("/sys/class/net/rkva/iflink", line, sizeof(line)), want) == 0);
	check("/sys/class/net/rkvb is not in this namespace",
	      access("/sys/class/net/rkvb", F_OK) != 0);
	umount("/sys");

	/* ip link del rkva */
	memset(&m, 0, sizeof(m));
	m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	m.h.nlmsg_type = RTM_DELLINK;
	nl_put(&m.h, IFLA_IFNAME, "rkva", 5);
	check("RTM_DELLINK removes rkva", nl_talk(nl, &m.h) == 0 && if_nametoindex("rkva") == 0);
	c = 1;
	write(go[1], &c, 1);
	check("the peer goes away with rkva", read(done[0], &c, 1) == 1 && c);
	close(nl);
	int status;
	check("the peer process ends", waitpid(b, &status, 0) == b && status == 0);
	return failed;
}

/* A veth pair, as drivers/net/veth.c of Linux, with its ends in two network namespaces. */
static void test_veth(void)
{
	pid_t pid = fork();
	if (pid == 0)
		_exit(veth_child());
	int status;
	check("the checks of the veth pair pass",
	      waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* The errors of socket for protocols that rukernel does not have, as inet_create in
 * net/ipv4/af_inet.c of Linux without the modules, and IPV6_CHECKSUM of a raw ICMPv6 socket, as
 * do_rawv6_setsockopt in net/ipv6/raw.c. */
static void test_inet_protos(void)
{
#ifndef SOCK_DCCP
#define SOCK_DCCP 6
#endif
	errno = 0;
	check("socket of SOCK_DCCP gives ESOCKTNOSUPPORT",
	      socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP) == -1 && errno == ESOCKTNOSUPPORT);
	errno = 0;
	check("socket of SOCK_STREAM and IPPROTO_SCTP gives EPROTONOSUPPORT",
	      socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP) == -1 && errno == EPROTONOSUPPORT);
	errno = 0;
	check("socket of SOCK_SEQPACKET and IPPROTO_SCTP gives ESOCKTNOSUPPORT",
	      socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP) == -1 && errno == ESOCKTNOSUPPORT);

	int s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	int v = -1;
	socklen_t len = sizeof(v);
	check("a raw ICMPv6 socket has its checksum at the offset 2",
	      getsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &v, &len) == 0 && v == 2);
	v = 2;
	errno = 0;
	check("IPV6_CHECKSUM of the level IPPROTO_IPV6 on ICMPv6 gives EINVAL",
	      setsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &v, sizeof(v)) == -1 && errno == EINVAL);
	check("IPV6_CHECKSUM of the level SOL_RAW on ICMPv6 is allowed",
	      setsockopt(s, SOL_RAW, IPV6_CHECKSUM, &v, sizeof(v)) == 0);
	close(s);
}

static void test_inet(int port)
{
	test_inet_protos();
	test_inet_ping();
	test_inet_dns();
	test_inet_lo();
	test_packet_lo();
	test_packet_ring();
	test_tun();
	test_tun_mq();
	test_tun6();
	test_veth();
	test_slip();
	test_tcp_lo();
	test_tcp_host(port);
}


/* Writes the text `s` to the file `path`. Gives 0, or -1 with errno set. */
static int cg_write(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;
	int e;

	if (fd < 0)
		return -1;
	n = write(fd, s, strlen(s));
	e = errno;
	close(fd);
	errno = e;
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

/* Makes a child that moves to the cgroup `cg` and calls `fn`. The child exits with the value of
 * `fn`, or 100 if the move fails. Gives the pid of the child. */
static pid_t cgroup_child(const char *cg, int (*fn)(void))
{
	char path[64];
	pid_t pid = fork();

	if (pid == 0) {
		snprintf(path, sizeof(path), "%s/cgroup.procs", cg);
		_exit(cg_write(path, "0") == 0 ? fn() : 100);
	}
	return pid;
}

/* Gives the exit status of the child `pid`, or -1. */
static int wait_status(pid_t pid)
{
	int status;

	if (pid < 0 || waitpid(pid, &status, 0) != pid)
		return -1;
	return status;
}

static int cg_fork_twice(void)
{
	pid_t pid = fork();

	if (pid == 0)
		_exit(0);
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		return 1;
	}
	return errno == EAGAIN ? 0 : 2;
}

static int cg_busy(void)
{
	struct timespec a, b;

	clock_gettime(CLOCK_MONOTONIC, &a);
	do
		clock_gettime(CLOCK_MONOTONIC, &b);
	while ((b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec) < 1000000000L);
	return 0;
}

static int cg_eat(void)
{
	size_t len = 32 << 20;
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return 2;
	for (size_t i = 0; i < len; i += 4096)
		p[i] = 1;
	return 0;
}

static int cg_sleep(void)
{
	for (;;)
		pause();
	return 0;
}

static int cg_spin(void)
{
	for (;;)
		;
	return 0;
}

static int cg_unshare(void)
{
	char buf[64];

	if (unshare(CLONE_NEWCGROUP) != 0)
		return 2;
	return read_file("/proc/self/cgroup", buf, sizeof(buf)) > 0 && strcmp(buf, "0::/\n") == 0 ? 0 : 3;
}

/* Reads the number after `key` in the file `path`, or -1. */
static long cg_value(const char *path, const char *key)
{
	char buf[1024];
	char *p;

	if (read_file(path, buf, sizeof(buf)) <= 0 || (p = strstr(buf, key)) == NULL)
		return -1;
	return atol(p + strlen(key));
}

/* Gives the events of `poll` on `fd` for `events` after at most `ms` milliseconds, or 0. */
static int poll_events(int fd, short events, int ms)
{
	struct pollfd p = { .fd = fd, .events = events };

	return poll(&p, 1, ms) == 1 ? p.revents : 0;
}

/* The file of the cgroup namespace of init, for cg_setns. */
static int cg_ns_fd = -1;

/* Leaves the cgroup namespace and joins it again with setns, with a namespace file and with a
 * process file descriptor of the parent. */
static int cg_setns(void)
{
	char buf[64], mine[64], parent[64];
	ssize_t n;
	int pidfd;

	if (unshare(CLONE_NEWCGROUP) != 0)
		return 2;
	if (read_file("/proc/self/cgroup", buf, sizeof(buf)) <= 0 || strcmp(buf, "0::/\n") != 0)
		return 3;
	if (setns(cg_ns_fd, CLONE_NEWNET) != -1 || errno != EINVAL)
		return 4;
	if (setns(cg_ns_fd, CLONE_NEWCGROUP) != 0)
		return 5;
	if (read_file("/proc/self/cgroup", buf, sizeof(buf)) <= 0 || strcmp(buf, "0::/t/a\n") != 0)
		return 6;
	if (unshare(CLONE_NEWCGROUP) != 0)
		return 7;
	pidfd = syscall(SYS_pidfd_open, getppid(), 0);
	if (pidfd < 0 || setns(pidfd, CLONE_NEWCGROUP) != 0)
		return 8;
	snprintf(buf, sizeof(buf), "/proc/%d/ns/cgroup", getppid());
	n = readlink(buf, parent, sizeof(parent) - 1);
	if (n <= 0)
		return 9;
	parent[n] = 0;
	n = readlink("/proc/self/ns/cgroup", mine, sizeof(mine) - 1);
	if (n <= 0)
		return 10;
	mine[n] = 0;
	return strcmp(mine, parent) == 0 ? 0 : 11;
}

/* Reads the last 64 KiB of /dev/vda and writes the same bytes back, so the disk does not
 * change. */
static int cg_io(void)
{
	static char b[65536];
	int fd = open("/dev/vda", O_RDWR);
	off_t at = fd < 0 ? -1 : lseek(fd, 0, SEEK_END) - (off_t)sizeof(b);

	if (at < 0)
		return 2;
	if (pread(fd, b, sizeof(b), at) != (ssize_t)sizeof(b))
		return 3;
	if (pwrite(fd, b, sizeof(b), at) != (ssize_t)sizeof(b) || fsync(fd) != 0)
		return 4;
	close(fd);
	return 0;
}

/* Reads 64 KiB of /dev/vda before the blocks of cg_io, so that the page cache of the read is new
 * and the cgroup of the caller gets its charge. */
static int cg_cache(void)
{
	static char b[65536];
	int fd = open("/dev/vda", O_RDONLY);
	off_t at = fd < 0 ? -1 : lseek(fd, 0, SEEK_END) - 2 * (off_t)sizeof(b);

	if (at < 0 || pread(fd, b, sizeof(b), at) != (ssize_t)sizeof(b))
		return 2;
	close(fd);
	return 0;
}

/* Gives the value of `key` in the line of the device 254:0 in io.stat of the cgroup `cg`, or
 * -1. */
static long cg_io_value(const char *cg, const char *key)
{
	char path[64], buf[1024];
	char *line, *p;

	snprintf(path, sizeof(path), "%s/io.stat", cg);
	if (read_file(path, buf, sizeof(buf)) <= 0 || (line = strstr(buf, "254:0 ")) == NULL ||
	    (p = strstr(line, key)) == NULL)
		return -1;
	return atol(p + strlen(key));
}

/* Moves the caller to the threaded cgroup /cg/th/x with cgroup.threads. */
static int cg_thread_move(void)
{
	char buf[64];

	if (cg_write("/cg/th/x/cgroup.threads", "0") != 0)
		return 1;
	if (read_file("/proc/self/cgroup", buf, sizeof(buf)) <= 0 || strcmp(buf, "0::/th/x\n") != 0)
		return 2;
	return 0;
}

/* Checks the thread mode: cgroup.type, cgroup.threads and cgroup.procs of a threaded cgroup. */
static void test_cgroup_threaded(void)
{
	char buf[64];
	int status;

	mkdir("/cg/th", 0755);
	mkdir("/cg/th/x", 0755);
	check("cgroup.type of a new cgroup is domain",
	      read_file("/cg/th/x/cgroup.type", buf, sizeof(buf)) > 0 && strcmp(buf, "domain\n") == 0);
	check("cgroup.type takes threaded", cg_write("/cg/th/x/cgroup.type", "threaded") == 0);
	check("cgroup.type tells threaded",
	      read_file("/cg/th/x/cgroup.type", buf, sizeof(buf)) > 0 && strcmp(buf, "threaded\n") == 0);
	check("the parent of a threaded cgroup is a thread root",
	      read_file("/cg/th/cgroup.type", buf, sizeof(buf)) > 0 &&
		      strcmp(buf, "domain threaded\n") == 0);
	check("cgroup.type refuses domain",
	      cg_write("/cg/th/x/cgroup.type", "domain") == -1 && errno == EINVAL);
	check("cgroup.procs of a threaded cgroup gives EOPNOTSUPP",
	      read_file("/cg/th/x/cgroup.procs", buf, sizeof(buf)) < 0 && errno == EOPNOTSUPP);
	status = wait_status(cgroup_child("/cg/th", cg_thread_move));
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		printf("cg_thread_move: status %#x\n", status);
	check("cgroup.threads moves a thread in a threaded subtree",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("rmdir removes a threaded cgroup", rmdir("/cg/th/x") == 0 && rmdir("/cg/th") == 0);
}

/* The tree of test_cgroup_stop, as cgroup_fj_stress memory 10 3 each of LTP: 1110 cgroups below
 * /cg/s. A process goes in each STOP_STEP-th leaf, so that the boot test stays short. */
#define STOP_FAN 10
#define STOP_LEAVES (STOP_FAN * STOP_FAN * STOP_FAN)
#define STOP_STEP 10
#define STOP_PROCS (STOP_LEAVES / STOP_STEP)

/* Makes a tree of 1110 cgroups with processes in its leaves, then kills and waits for each process
 * one after the other, as cgroup_fj_stress of LTP. Each exit empties a leaf, so cgroup.events of
 * the leaf changes. The kernel must not go over each cgroup at each exit. */
static void test_cgroup_stop(void)
{
	static pid_t pids[STOP_PROCS];
	char path[64], want[16];
	long long start, stop_ms;
	int i, made = 0, moved = 0, waited = 0, removed = 0;

	if (mkdir("/cg/s", 0755) != 0 || cg_write("/cg/s/cgroup.subtree_control", "+memory") != 0) {
		check("cgroup stop: make /cg/s", 0);
		return;
	}
	for (i = 0; i < STOP_FAN; i++) {
		snprintf(path, sizeof(path), "/cg/s/%d", i);
		made += mkdir(path, 0755) == 0;
		snprintf(path, sizeof(path), "/cg/s/%d/cgroup.subtree_control", i);
		cg_write(path, "+memory");
		for (int j = 0; j < STOP_FAN; j++) {
			snprintf(path, sizeof(path), "/cg/s/%d/%d", i, j);
			made += mkdir(path, 0755) == 0;
			snprintf(path, sizeof(path), "/cg/s/%d/%d/cgroup.subtree_control", i, j);
			cg_write(path, "+memory");
			for (int k = 0; k < STOP_FAN; k++) {
				snprintf(path, sizeof(path), "/cg/s/%d/%d/%d", i, j, k);
				made += mkdir(path, 0755) == 0;
			}
		}
	}
	check("cgroup stop: mkdir makes 1110 cgroups", made == STOP_FAN + STOP_FAN * STOP_FAN + STOP_LEAVES);
	for (i = 0; i < STOP_PROCS; i++) {
		int leaf = i * STOP_STEP;

		pids[i] = fork();
		if (pids[i] == 0) {
			for (;;)
				pause();
		}
		if (pids[i] < 0)
			break;
		snprintf(path, sizeof(path), "/cg/s/%d/%d/%d/cgroup.procs", leaf / 100, leaf / 10 % 10, leaf % 10);
		snprintf(want, sizeof(want), "%d", pids[i]);
		moved += cg_write(path, want) == 0;
	}
	check("cgroup stop: the processes move to the leaves", moved == STOP_PROCS);
	check("cgroup stop: /cg/s is populated", cg_value("/cg/s/cgroup.events", "populated ") == 1);
	start = clock_ms(CLOCK_MONOTONIC);
	for (i = 0; i < STOP_PROCS && pids[i] > 0; i++) {
		kill(pids[i], SIGKILL);
		waited += wait_status(pids[i]) != -1;
	}
	stop_ms = clock_ms(CLOCK_MONOTONIC) - start;
	printf("init: cgroup stop: %d processes in %lld ms\n", waited, stop_ms);
	check("cgroup stop: each process ends", waited == STOP_PROCS);
	check("cgroup stop: /cg/s is empty", cg_value("/cg/s/cgroup.events", "populated ") == 0 &&
						     cg_value("/cg/s/0/0/0/cgroup.events", "populated ") == 0);
	for (i = STOP_LEAVES - 1; i >= 0; i--) {
		snprintf(path, sizeof(path), "/cg/s/%d/%d/%d", i / 100, i / 10 % 10, i % 10);
		removed += rmdir(path) == 0;
		if (i % 10 == 0) {
			snprintf(path, sizeof(path), "/cg/s/%d/%d", i / 100, i / 10 % 10);
			removed += rmdir(path) == 0;
		}
		if (i % 100 == 0) {
			snprintf(path, sizeof(path), "/cg/s/%d", i / 100);
			removed += rmdir(path) == 0;
		}
	}
	check("cgroup stop: rmdir removes the cgroups", removed == made && rmdir("/cg/s") == 0);
}

/* Checks the io controller: io.stat, io.max and io.weight. */
static void test_cgroup_io(void)
{
	char buf[256];
	long long start;
	int status;

	check("cgroup.subtree_control enables io", cg_write("/cg/cgroup.subtree_control", "+io") == 0 &&
							   access("/cg/t/io.max", F_OK) == 0);
	check("io.max of a device that does not exist gives ENODEV",
	      cg_write("/cg/t/io.max", "1:99 wbps=1") == -1 && errno == ENODEV);
	check("io.weight takes a weight", cg_write("/cg/t/io.weight", "default 50") == 0 &&
						  read_file("/cg/t/io.weight", buf, sizeof(buf)) > 0 &&
						  strcmp(buf, "default 50\n") == 0);
	check("io.weight refuses 0", cg_write("/cg/t/io.weight", "0") == -1 && errno == EINVAL);
	/* The disk is only in the boot test blk. */
	if (access("/dev/vda", F_OK) != 0)
		return;
	long before = cg_io_value("/cg/t", "wbytes=");
	status = wait_status(cgroup_child("/cg/t/a", cg_io));
	check("io.stat counts the writes of the cgroup", WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
								 cg_io_value("/cg/t", "wbytes=") >= before + 65536 &&
								 cg_io_value("/cg/t", "wios=") > 0 &&
								 cg_io_value("/cg", "wbytes=") >= 65536);
	/* The exit of the last task lets rmdir remove the cgroup, also with charges of page cache, as
	 * the offline of a memory cgroup in mm/memcontrol.c of Linux. */
	check("rmdir removes a cgroup with charges of page cache",
	      mkdir("/cg/t/pc", 0755) == 0 && (status = wait_status(cgroup_child("/cg/t/pc", cg_cache)), WIFEXITED(status)) &&
		      WEXITSTATUS(status) == 0 && cg_value("/cg/t/pc/memory.current", "") > 0 && rmdir("/cg/t/pc") == 0);
	check("io.max takes a limit", cg_write("/cg/t/io.max", "254:0 wbps=65536") == 0 &&
					      read_file("/cg/t/io.max", buf, sizeof(buf)) > 0 &&
					      strcmp(buf, "254:0 rbps=max wbps=65536 riops=max wiops=max\n") == 0);
	start = clock_ms(CLOCK_MONOTONIC);
	status = wait_status(cgroup_child("/cg/t/a", cg_io));
	check("io.max slows the writes of the cgroup", WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
							       clock_ms(CLOCK_MONOTONIC) - start >= 900 &&
							       cg_value("/cg/t/io.pressure", "total=") > 0);
	check("io.max takes max", cg_write("/cg/t/io.max", "254:0 wbps=max") == 0 &&
					  read_file("/cg/t/io.max", buf, sizeof(buf)) == 0);
}

/* The errno that the write of cg_lesser_euid must give: 0 for a write that works. */
static int cg_lesser_want;

/* Opens cgroup.procs of /cg/t/d/y as the user nobody and writes it as root, as cgroup_core01 of
 * LTP. The check uses the credentials of the open, so the write needs a nobody that can write
 * cgroup.procs of the common parent /cg/t/d. */
static int cg_lesser_euid(void)
{
	int fd;

	if (seteuid(65534) != 0)
		return 2;
	fd = open("/cg/t/d/y/cgroup.procs", O_RDWR);
	if (seteuid(0) != 0 || fd < 0)
		return 3;
	if (cg_lesser_want == 0)
		return write(fd, "0", 1) == 1 ? 0 : 4;
	return write(fd, "0", 1) == -1 && errno == cg_lesser_want ? 0 : 5;
}

/* Opens cgroup.procs of /cg/t/d/y in a new cgroup namespace at /cg/t/d/x, as cgroup_core02 of
 * LTP. With nsdelegate, y is outside the namespace, so a write gives ENOENT. The namespace can
 * write cgroup.procs of its root, but not the other files of its root. */
static int cg_lesser_ns(void)
{
	int fd;

	if (unshare(CLONE_NEWCGROUP) != 0)
		return 2;
	fd = open("/cg/t/d/y/cgroup.procs", O_RDWR);
	if (fd < 0)
		return 3;
	if (write(fd, "0", 1) != -1 || errno != ENOENT)
		return 4;
	if (cg_write("/cg/t/d/x/cgroup.max.depth", "5") != -1 || errno != EPERM)
		return 5;
	return cg_write("/cg/t/d/x/cgroup.procs", "0") == 0 ? 0 : 6;
}

/* Makes the cgroup /cg/t/d/z as the user nobody. */
static int cg_mkdir_nobody(void)
{
	return seteuid(65534) == 0 && mkdir("/cg/t/d/z", 0755) == 0 ? 0 : 2;
}

/* Checks the delegation of cgroups: chown, the credentials of the open of cgroup.procs, a cgroup
 * that a user makes, and the mount option nsdelegate. */
static void test_cgroup_delegation(void)
{
	struct stat st;
	char buf[4096];
	int status;

	check("mkdir makes the cgroups of a delegation", mkdir("/cg/t/d", 0755) == 0 && mkdir("/cg/t/d/x", 0755) == 0 &&
								mkdir("/cg/t/d/y", 0755) == 0);
	check("chown changes the owner of a cgroup file",
	      chown("/cg/t/d/x/cgroup.procs", 65534, -1) == 0 && chown("/cg/t/d/y/cgroup.procs", 65534, -1) == 0 &&
		      stat("/cg/t/d/y/cgroup.procs", &st) == 0 && st.st_uid == 65534 &&
		      stat("/cg/t/d/y/cgroup.threads", &st) == 0 && st.st_uid == 0);
	cg_lesser_want = EACCES;
	status = wait_status(cgroup_child("/cg/t/d/x", cg_lesser_euid));
	check("a write of cgroup.procs uses the credentials of the open", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	cg_lesser_want = 0;
	check("the owner of cgroup.procs of the common parent can move a process",
	      chown("/cg/t/d/cgroup.procs", 65534, -1) == 0 &&
		      (status = wait_status(cgroup_child("/cg/t/d/x", cg_lesser_euid)), WIFEXITED(status)) &&
		      WEXITSTATUS(status) == 0);
	check("a cgroup belongs to the user that makes it",
	      chown("/cg/t/d", 65534, -1) == 0 &&
		      (status = wait_status(cgroup_child("/cg/t/d/x", cg_mkdir_nobody)), WIFEXITED(status)) &&
		      WEXITSTATUS(status) == 0 && stat("/cg/t/d/z", &st) == 0 && st.st_uid == 65534 &&
		      stat("/cg/t/d/z/cgroup.procs", &st) == 0 && st.st_uid == 65534);

	mkdir("/cgd", 0755);
	check("cgroup2 takes nsdelegate", mount("none", "/cgd", "cgroup2", 0, "nsdelegate") == 0 &&
						  read_file("/proc/self/mounts", buf, sizeof(buf)) > 0 &&
						  strstr(buf, ",nsdelegate") != NULL);
	status = wait_status(cgroup_child("/cg/t/d/x", cg_lesser_ns));
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		printf("cg_lesser_ns: status %#x\n", status);
	check("nsdelegate makes a cgroup namespace a boundary", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	umount("/cgd");
	check("a mount without nsdelegate clears it", mount("none", "/cgd", "cgroup2", 0, NULL) == 0 &&
							   (status = wait_status(cgroup_child("/cg/t/d/x", cg_lesser_ns)),
							    WIFEXITED(status)) &&
							   WEXITSTATUS(status) == 4);
	umount("/cgd");
	rmdir("/cgd");
	check("rmdir removes the cgroups of a delegation", rmdir("/cg/t/d/z") == 0 && rmdir("/cg/t/d/y") == 0 &&
								  rmdir("/cg/t/d/x") == 0 && rmdir("/cg/t/d") == 0);
}

static void test_cgroup(void)
{
	struct statfs sfs;
	struct clone_args args;
	char buf[512], want[64];
	pid_t pid;
	ssize_t n;
	int status, fd;

	mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/cg", 0755);
	check("mount cgroup2", mount("none", "/cg", "cgroup2", 0, NULL) == 0);
	check("statfs of cgroup2 gives CGROUP2_SUPER_MAGIC", statfs("/cg", &sfs) == 0 && sfs.f_type == 0x63677270);
	check("the root has the controllers", read_file("/cg/cgroup.controllers", buf, sizeof(buf)) > 0 &&
						      strcmp(buf, "cpuset cpu io memory pids\n") == 0);
	check("/proc/self/cgroup is the root", read_file("/proc/self/cgroup", buf, sizeof(buf)) > 0 &&
						       strcmp(buf, "0::/\n") == 0);
	check("/proc/cgroups has memory", read_file("/proc/cgroups", buf, sizeof(buf)) > 0 &&
						  strstr(buf, "\nmemory\t0\t") != NULL);
	check("/proc/pressure/cpu has the averages",
	      read_file("/proc/pressure/cpu", buf, sizeof(buf)) > 0 && strncmp(buf, "some avg10=", 11) == 0 &&
		      strstr(buf, "\nfull avg10=") != NULL);
	check("cgroup.subtree_control enables controllers",
	      cg_write("/cg/cgroup.subtree_control", "+cpu +memory +pids") == 0);
	check("mkdir makes a cgroup", mkdir("/cg/t", 0755) == 0 && mkdir("/cg/t/a", 0755) == 0);
	check("a child cgroup has memory.max", access("/cg/t/memory.max", F_OK) == 0);
	check("cpu.weight takes a value", cg_write("/cg/t/cpu.weight", "200") == 0 &&
						  read_file("/cg/t/cpu.weight", buf, sizeof(buf)) > 0 &&
						  strcmp(buf, "200\n") == 0);

	pid = fork();
	if (pid == 0)
		for (;;)
			pause();
	snprintf(want, sizeof(want), "%d", pid);
	check("cgroup.procs moves a process", cg_write("/cg/t/cgroup.procs", want) == 0);
	strcat(want, "\n");
	check("cgroup.procs lists the process", read_file("/cg/t/cgroup.procs", buf, sizeof(buf)) > 0 &&
							strcmp(buf, want) == 0);
	snprintf(want, sizeof(want), "/proc/%d/cgroup", pid);
	check("/proc/PID/cgroup gives the path", read_file(want, buf, sizeof(buf)) > 0 && strcmp(buf, "0::/t\n") == 0);
	check("cgroup.events tells populated", cg_value("/cg/t/cgroup.events", "populated ") == 1);
	check("rmdir of a cgroup with a process gives EBUSY", rmdir("/cg/t/a") == 0 && rmdir("/cg/t") == -1 &&
								      errno == EBUSY);
	mkdir("/cg/t/a", 0755);
	/* Only a domain controller is under the rule. pids is a threaded controller, as in Linux. */
	check("no internal processes: subtree_control gives EBUSY",
	      cg_write("/cg/t/cgroup.subtree_control", "+memory") == -1 && errno == EBUSY);
	kill(pid, SIGKILL);
	wait_status(pid);
	check("cgroup.events tells empty", cg_value("/cg/t/cgroup.events", "populated ") == 0);
	check("cgroup.subtree_control of an empty cgroup",
	      cg_write("/cg/t/cgroup.subtree_control", "+cpu +memory +pids") == 0);
	check("no internal processes: cgroup.procs gives EBUSY",
	      cg_write("/cg/t/cgroup.procs", "1") == -1 && errno == EBUSY);

	cg_write("/cg/t/a/pids.max", "1");
	status = wait_status(cgroup_child("/cg/t/a", cg_fork_twice));
	check("pids.max gives EAGAIN", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check("pids.events counts the limit", cg_value("/cg/t/a/pids.events", "max ") >= 1);
	cg_write("/cg/t/a/pids.max", "max");

	cg_write("/cg/t/a/cpu.max", "10000 100000");
	status = wait_status(cgroup_child("/cg/t/a", cg_busy));
	long usage = cg_value("/cg/t/a/cpu.stat", "usage_usec ");
	check("cpu.max limits a busy loop", WIFEXITED(status) && WEXITSTATUS(status) == 0 && usage > 0 &&
						    usage < 500000 &&
						    cg_value("/cg/t/a/cpu.stat", "nr_throttled ") > 0);
	check("cpu.pressure counts the throttle", cg_value("/cg/t/a/cpu.pressure", "total=") > 0);
	cg_write("/cg/t/a/cpu.max", "max");

	check("memory.max takes a size", cg_write("/cg/t/a/memory.max", "4M") == 0);
	status = wait_status(cgroup_child("/cg/t/a", cg_eat));
	check("memory.max gives an OOM kill", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
						      cg_value("/cg/t/a/memory.events", "oom_kill ") >= 1);
	status = wait_status(cgroup_child("/cg/t/a", cg_eat));
	check("memory.events counts the OOM kill of the process", cg_value("/cg/t/a/memory.events.local", "oom_kill ") >= 2);
	check("memory.oom.group takes 1", cg_write("/cg/t/a/memory.oom.group", "1") == 0);
	pid = cgroup_child("/cg/t/a", cg_sleep);
	usleep(50000);
	status = wait_status(cgroup_child("/cg/t/a", cg_eat));
	check("memory.oom.group kills the whole cgroup", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
								 (status = wait_status(pid), WIFSIGNALED(status)) &&
								 WTERMSIG(status) == SIGKILL &&
								 cg_value("/cg/t/a/memory.events", "oom_group_kill ") >= 1);
	cg_write("/cg/t/a/memory.oom.group", "0");
	cg_write("/cg/t/a/memory.max", "max");

	check("memory.high takes a size", cg_write("/cg/t/a/memory.high", "4M") == 0);
	pid = cgroup_child("/cg/t/a", cg_eat);
	for (int i = 0; i < 100; i++) {
		if (cg_value("/cg/t/a/memory.events", "high ") > 0 && cg_value("/cg/t/a/memory.pressure", "total=") > 0)
			break;
		usleep(100000);
	}
	check("memory.high slows a process over the limit",
	      waitpid(pid, &status, WNOHANG) == 0 && cg_value("/cg/t/a/memory.events", "high ") > 0 &&
		      cg_value("/cg/t/a/memory.pressure", "total=") > 0);
	cg_write("/cg/t/a/memory.high", "max");
	status = wait_status(pid);
	check("the process goes on after memory.high goes up", WIFEXITED(status) && WEXITSTATUS(status) == 0);

	fd = open("/cg/t/a/cpu.pressure", O_RDWR);
	check("a pressure file without a trigger polls POLLERR",
	      (poll_events(fd, POLLPRI, 0) & (POLLERR | POLLPRI)) == (POLLERR | POLLPRI));
	check("a write of a pressure file makes a trigger", write(fd, "some 50000 1000000", 18) == 18);
	check("a second trigger on the file gives EBUSY", write(fd, "some 50000 1000000", 18) == -1 && errno == EBUSY);
	check("a trigger needs a valid window", cg_write("/cg/t/a/memory.pressure", "some 50000 100") == -1 &&
							errno == EINVAL);
	check("a trigger without an event does not poll POLLPRI", !(poll_events(fd, POLLPRI, 0) & POLLPRI));
	cg_write("/cg/t/a/cpu.max", "10000 100000");
	pid = cgroup_child("/cg/t/a", cg_busy);
	check("a stall polls POLLPRI on the trigger", poll_events(fd, POLLPRI, 3000) & POLLPRI);
	wait_status(pid);
	cg_write("/cg/t/a/cpu.max", "max");
	close(fd);
	fd = open("/proc/pressure/memory", O_RDWR);
	check("/proc/pressure takes a trigger", fd >= 0 && write(fd, "full 100000 2000000", 19) == 19 &&
							!(poll_events(fd, POLLPRI, 0) & POLLERR));
	close(fd);

	pid = cgroup_child("/cg/t/a", cg_spin);
	usleep(100000);
	fd = open("/cg/t/a/cgroup.events", O_RDONLY);
	check("poll of cgroup.events before a read sees an event", poll_events(fd, POLLPRI, 0) & POLLPRI);
	read(fd, buf, sizeof(buf));
	check("poll of cgroup.events after a read waits", !(poll_events(fd, POLLPRI, 0) & POLLPRI));
	check("cgroup.freeze takes 1", cg_write("/cg/t/a/cgroup.freeze", "1") == 0);
	check("poll of cgroup.events sees the freeze", poll_events(fd, POLLPRI, 3000) & POLLPRI);
	check("cgroup.events tells frozen", cg_value("/cg/t/a/cgroup.events", "frozen ") == 1);
	check("a new cgroup in a frozen cgroup is frozen",
	      mkdir("/cg/t/a/b", 0755) == 0 && cg_value("/cg/t/a/b/cgroup.events", "frozen ") == 1 &&
		      cg_value("/cg/t/a/b/cgroup.freeze", "") == 0 && rmdir("/cg/t/a/b") == 0);
	snprintf(want, sizeof(want), "/proc/%d/stat", pid);
	{
		long before = 0, after = 0;
		char *p;

		if (read_file(want, buf, sizeof(buf)) > 0 && (p = strrchr(buf, ')')) != NULL)
			sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld", &before);
		usleep(200000);
		if (read_file(want, buf, sizeof(buf)) > 0 && (p = strrchr(buf, ')')) != NULL)
			sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld", &after);
		check("a frozen process does not run", before > 0 && after == before);
	}
	read(fd, buf, sizeof(buf));
	cg_write("/cg/t/a/cgroup.freeze", "0");
	check("cgroup.events tells thawed", cg_value("/cg/t/a/cgroup.events", "frozen ") == 0 &&
						    poll_events(fd, POLLPRI, 0) & POLLPRI);
	close(fd);
	check("cgroup.kill kills the processes", cg_write("/cg/t/a/cgroup.kill", "1") == 0 &&
							 (status = wait_status(pid), WIFSIGNALED(status)) &&
							 WTERMSIG(status) == SIGKILL);

	fd = open("/cg/t/a", O_RDONLY | O_DIRECTORY);
	memset(&args, 0, sizeof(args));
	args.flags = CLONE_INTO_CGROUP;
	args.exit_signal = SIGCHLD;
	args.cgroup = fd;
	pid = syscall(SYS_clone3, &args, sizeof(args));
	if (pid == 0)
		_exit(read_file("/proc/self/cgroup", buf, sizeof(buf)) > 0 && strcmp(buf, "0::/t/a\n") == 0 ? 0 : 1);
	status = wait_status(pid);
	check("clone3 with CLONE_INTO_CGROUP", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd);
	status = wait_status(cgroup_child("/cg/t/a", cg_unshare));
	check("CLONE_NEWCGROUP makes the cgroup the root", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	n = readlink("/proc/self/ns/cgroup", buf, sizeof(buf) - 1);
	check("/proc/self/ns/cgroup links to the namespace", n > 0 && (buf[n] = 0, strcmp(buf, "cgroup:[4026531835]") == 0));
	cg_ns_fd = open("/proc/self/ns/cgroup", O_RDONLY);
	check("setns takes a file of a namespace", cg_ns_fd >= 0 && setns(cg_ns_fd, CLONE_NEWCGROUP) == 0);
	check("setns of a file that is not a namespace gives EINVAL",
	      (fd = open("/proc/self/cgroup", O_RDONLY)) >= 0 && setns(fd, 0) == -1 && errno == EINVAL);
	close(fd);
	status = wait_status(cgroup_child("/cg/t/a", cg_setns));
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		printf("cg_setns: status %#x\n", status);
	check("setns joins a cgroup namespace", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* No user namespaces, as Linux without CONFIG_USER_NS (getxattr05 of LTP, #475). */
	check("/proc/self/ns/user does not exist", access("/proc/self/ns/user", F_OK) == -1 && errno == ENOENT);
	check("unshare of CLONE_NEWUSER gives EINVAL", unshare(CLONE_NEWUSER) == -1 && errno == EINVAL);
	check("NS_GET_USERNS gives EPERM", ioctl(cg_ns_fd, 0xb701) == -1 && errno == EPERM);
	close(cg_ns_fd);

	test_cgroup_io();
	test_cgroup_threaded();
	test_cgroup_delegation();
	test_cgroup_stop();
	check("rmdir removes the cgroups", rmdir("/cg/t/a") == 0 && rmdir("/cg/t") == 0);
	umount("/cg");
	rmdir("/cg");
	umount("/proc");
}

/* Runs the general checks, which each boot of init runs without the argument "only". */
static void test_all(void)
{
	test_ids();
	test_creds();
	test_uname();
	test_memory();
	test_hugetlbfs();
	test_files();
	test_perms();
	test_devices();
	test_pty();
	test_fork();
	test_exec();
	test_time();
	test_vdso();
	test_signals();
	test_sigwait();
	test_timers();
	test_stop();
	test_cputime();
	test_pipes();
	test_threads();
	test_locks();
	test_clone3();
	test_pidfd();
	test_signalfd_poll();
	test_seccomp();
	test_ptrace();
	test_mount();
	test_mount_ns();
	test_uts_ipc_ns();
	test_mount_api();
	test_symlink_chain();
	test_splice();
	test_atime();
	test_sysfs();
	test_loop();
	test_xattr();
	test_fifo();
	test_file_locks();
	test_file_leases();
	test_fallocate();
	test_fsize();
	test_tmpfile();
	test_iflags();
	test_syslog();
	test_membarrier();
	test_overlay();
	test_proc();
	test_memfd();
	test_shm();
	test_sem();
	test_msg();
	test_mqueue();
	test_unix();
	test_proc_ptrace();
	test_cgroup();
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	/*
	 * With the first argument "only", init does not run the general checks. It runs only the
	 * checks of the next argument. The arm64 boot tests use this, because QEMU emulates each
	 * arm64 instruction and the general checks take a long time.
	 */
	if (argc > 1 && strcmp(argv[1], "only") == 0) {
		argc--;
		argv++;
	} else {
		test_all();
	}
	if (argc > 1 && strcmp(argv[1], "tty") == 0)
		test_tty();
	if (argc > 1 && strcmp(argv[1], "smp") == 0)
		test_smp();
	if (argc > 1 && strcmp(argv[1], "blk") == 0)
		test_blk();
	if (argc > 1 && strcmp(argv[1], "inet") == 0)
		test_inet(argc > 2 ? atoi(argv[2]) : 0);
	printf("init: %s\n", failed ? "a check failed" : "each check passed");
	return failed;
}
