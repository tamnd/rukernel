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
	close(fd);
	unlink("/huge/f");
	check("the pages of a file of hugetlbfs go back to the reservation of min_size=",
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
	usleep(50 * 1000);
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
	for (int i = 0; i < 1000 && mq_thread_calls == 0; i++)
		sched_yield();
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
	errno = 0;
	check("/proc/self/nothing gives ENOENT", open("/proc/self/nothing", O_RDONLY) == -1 && errno == ENOENT);
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
	check("tcsetpgrp back to init", tcsetpgrp(0, getpgrp()) == 0);
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

static void test_blk(void)
{
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

static void test_inet(int port)
{
	test_inet_ping();
	test_inet_dns();
	test_inet_lo();
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
	check("no internal processes: subtree_control gives EBUSY",
	      cg_write("/cg/t/cgroup.subtree_control", "+pids") == -1 && errno == EBUSY);
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
	close(cg_ns_fd);

	test_cgroup_io();
	test_cgroup_delegation();
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
	test_mount_api();
	test_symlink_chain();
	test_splice();
	test_atime();
	test_sysfs();
	test_loop();
	test_xattr();
	test_fifo();
	test_file_locks();
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
