/* Prints /proc/PID/maps and /proc/PID/smaps of programs for the maps and smaps diff of run.py.
 *
 * mapsdump NAME PROGRAM [ARG...] runs PROGRAM with ptrace and PTRACE_O_TRACEEXIT, and prints the
 * two files when the program stops before its exit, while its address space is still there.
 * mapsdump --setup mounts /proc, /dev and /tmp for the /init of run.py.
 * mapsdump --cases makes a set of address spaces with mmap, mprotect, mremap, madvise, mlock and
 * brk, each in a child that stops itself with SIGSTOP, and prints the two files of each child.
 *
 * The program turns off the random placement (ADDR_NO_RANDOMIZE), so that two kernels with the
 * same placement give the same addresses. Each line of the files has the prefix "M " or "S ".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PS 4096UL

static pid_t child;

static void on_alarm(int sig)
{
	(void)sig;
	if (child > 0)
		kill(child, SIGKILL);
}

static void print_file(pid_t pid, const char *file, const char *prefix)
{
	static char buf[1 << 20];
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, file);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("mapsdiff: error %s %s\n", path, strerror(errno));
		return;
	}
	size_t len = 0;
	ssize_t n;
	while (len < sizeof(buf) - 1 && (n = read(fd, buf + len, sizeof(buf) - 1 - len)) > 0)
		len += n;
	close(fd);
	buf[len] = 0;
	for (char *line = buf; *line;) {
		char *end = strchr(line, '\n');
		if (end)
			*end = 0;
		printf("%s%s\n", prefix, line);
		if (!end)
			break;
		line = end + 1;
	}
}

static void dump(pid_t pid, const char *name)
{
	printf("mapsdiff: begin %s\n", name);
	print_file(pid, "maps", "M ");
	print_file(pid, "smaps", "S ");
	printf("mapsdiff: end %s\n", name);
	fflush(stdout);
}

/* Runs the program and prints its files at the exit stop. */
static int run(const char *name, char **argv)
{
	fflush(stdout);
	child = fork();
	if (child < 0)
		return 1;
	if (child == 0) {
		personality(ADDR_NO_RANDOMIZE);
		int fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execv(argv[0], argv);
		_exit(127);
	}
	signal(SIGALRM, on_alarm);
	alarm(60);
	int st, dumped = 0;
	if (waitpid(child, &st, 0) != child || !WIFSTOPPED(st)) {
		printf("mapsdiff: noexec %s\n", name);
		return 1;
	}
	ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL);
	ptrace(PTRACE_CONT, child, 0, 0);
	for (;;) {
		if (waitpid(child, &st, 0) != child)
			break;
		if (WIFEXITED(st) || WIFSIGNALED(st))
			break;
		if (st >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
			if (!dumped)
				dump(child, name);
			dumped = 1;
			ptrace(PTRACE_CONT, child, 0, 0);
			continue;
		}
		int sig = WSTOPSIG(st);
		ptrace(PTRACE_CONT, child, 0, sig == SIGTRAP ? 0 : sig);
	}
	alarm(0);
	if (!dumped)
		printf("mapsdiff: nodump %s\n", name);
	child = 0;
	return 0;
}

static char *reserve(size_t pages)
{
	char *p = mmap(NULL, pages * PS, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED)
		_exit(2);
	return p;
}

static char *anon(char *at, size_t pages, int prot, int flags)
{
	return mmap(at, pages * PS, prot, flags | MAP_ANONYMOUS | (at ? MAP_FIXED : 0), -1, 0);
}

static void touch(char *p, size_t pages)
{
	for (size_t i = 0; i < pages; i++)
		p[i * PS] = 1;
}

static int make_file(const char *path, size_t pages)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	static char page[PS];
	for (size_t i = 0; i < pages; i++) {
		memset(page, 'a' + (int)i, sizeof(page));
		if (write(fd, page, PS) != (ssize_t)PS)
			_exit(3);
	}
	return fd;
}

/* The cases. Each makes its areas in a fresh child, after a PROT_NONE area of 64 pages that
 * keeps the areas away from the areas of the program. */
static void case_anon_adjacent(void)
{
	char *r = reserve(64);
	anon(r + 8 * PS, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	anon(r + 12 * PS, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	anon(r + 16 * PS, 4, PROT_READ, MAP_PRIVATE);
	touch(r + 8 * PS, 6);
}

static void case_mprotect_back(void)
{
	char *p = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 8);
	mprotect(p + 3 * PS, 2 * PS, PROT_READ);
	mprotect(p + 3 * PS, 2 * PS, PROT_READ | PROT_WRITE);
}

static void case_mprotect_split(void)
{
	char *p = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 4);
	mprotect(p + 3 * PS, 2 * PS, PROT_READ);
	mprotect(p + 6 * PS, 2 * PS, PROT_NONE);
	mprotect(p, PS, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void case_shared_hole(void)
{
	char *p = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_SHARED);
	touch(p, 8);
	munmap(p + 3 * PS, 2 * PS);
}

static void case_file_adjacent(void)
{
	int fd = make_file("/tmp/mapsdiff-a", 16);
	char *r = reserve(64);
	mmap(r + 8 * PS, 4 * PS, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);
	mmap(r + 12 * PS, 4 * PS, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 4 * PS);
	/* Offsets that do not follow: two areas. */
	mmap(r + 20 * PS, 2 * PS, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);
	mmap(r + 22 * PS, 2 * PS, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 8 * PS);
	volatile char c = r[8 * PS] + r[13 * PS] + r[22 * PS];
	(void)c;
	close(fd);
}

static void case_file_shared_write(void)
{
	int fd = make_file("/tmp/mapsdiff-b", 8);
	char *p = mmap(NULL, 8 * PS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	touch(p, 3);
	char *q = mmap(NULL, 8 * PS, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	touch(q + 2 * PS, 2);
	volatile char c = q[6 * PS];
	(void)c;
	close(fd);
	unlink("/tmp/mapsdiff-b");
}

/* musl has no sbrk with an increment, thus the cases call brk directly. */
static char *brk_add(long bytes)
{
	char *b = (char *)syscall(SYS_brk, 0);
	syscall(SYS_brk, b + bytes);
	return b;
}

static void case_brk(void)
{
	char *b = brk_add(5 * PS);
	touch(b, 4);
	brk_add(-(long)PS);
}

static void case_mremap(void)
{
	char *r = reserve(64);
	char *p = anon(r + 8 * PS, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 4);
	munmap(r + 12 * PS, 8 * PS);
	mremap(p, 4 * PS, 8 * PS, 0);
	char *q = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(q, 4);
	mremap(q, 4 * PS, 2 * PS, 0);
	char *s = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(s, 2);
	mremap(s, 4 * PS, 4 * PS, MREMAP_MAYMOVE | MREMAP_FIXED, r + 40 * PS);
	char *t = anon(NULL, 2, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(t, 2);
	mremap(t, 2 * PS, 2 * PS, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, r + 50 * PS);
}

static void case_munmap_middle(void)
{
	char *p = anon(NULL, 10, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 10);
	munmap(p + 4 * PS, 2 * PS);
	anon(p + 4 * PS, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	anon(p + 8 * PS, 1, PROT_READ, MAP_PRIVATE);
}

static void case_madvise(void)
{
	char *p = anon(NULL, 16, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 16);
	madvise(p, 2 * PS, MADV_DONTNEED);
	madvise(p + 4 * PS, 2 * PS, MADV_DONTFORK);
	madvise(p + 8 * PS, 2 * PS, MADV_DONTDUMP);
	madvise(p + 10 * PS, 2 * PS, MADV_RANDOM);
	madvise(p + 12 * PS, 2 * PS, MADV_SEQUENTIAL);
	madvise(p + 14 * PS, 2 * PS, MADV_WIPEONFORK);
	char *h = anon(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	madvise(h + 512 * PS, 512 * PS, MADV_NOHUGEPAGE);
	char *f = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(f, 8);
	madvise(f + 2 * PS, 2 * PS, MADV_FREE);
}

static void case_mlock(void)
{
	char *p = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	mlock(p + 2 * PS, 3 * PS);
	char *q = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED);
	(void)q;
	char *s = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	mlock2(s, 4 * PS, MLOCK_ONFAULT);
	touch(s, 1);
	munlock(p + 3 * PS, PS);
}

static void case_flags(void)
{
	char *p = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_NORESERVE);
	touch(p, 1);
	char *q = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE);
	(void)q;
	char *g = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_GROWSDOWN);
	touch(g + 3 * PS, 1);
	char *n = anon(NULL, 4, PROT_NONE, MAP_PRIVATE);
	(void)n;
	char *x = anon(NULL, 2, PROT_READ | PROT_EXEC, MAP_PRIVATE);
	(void)x;
	char *w = anon(NULL, 2, PROT_WRITE, MAP_PRIVATE);
	(void)w;
	char *s = anon(NULL, 4, PROT_READ, MAP_SHARED);
	(void)s;
}

static void case_memfd_shm(void)
{
	int fd = memfd_create("mapsdiff", 0);
	if (ftruncate(fd, 8 * PS) == 0) {
		char *p = mmap(NULL, 8 * PS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		touch(p, 5);
		char *q = mmap(NULL, 4 * PS, PROT_READ, MAP_PRIVATE, fd, 4 * PS);
		volatile char c = q[0];
		(void)c;
	}
	int id = shmget(IPC_PRIVATE, 4 * PS, IPC_CREAT | 0600);
	if (id >= 0) {
		char *s = shmat(id, NULL, 0);
		if (s != (char *)-1)
			touch(s, 2);
		char *t = shmat(id, NULL, SHM_RDONLY);
		(void)t;
		shmctl(id, IPC_RMID, NULL);
	}
	char *z = mmap(NULL, 4 * PS, PROT_READ | PROT_WRITE, MAP_PRIVATE, open("/dev/zero", O_RDWR), 0);
	touch(z, 2);
}

static void case_map_fixed_over(void)
{
	char *p = anon(NULL, 12, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 12);
	anon(p + 4 * PS, 2, PROT_READ, MAP_PRIVATE);
	anon(p + 6 * PS, 2, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	int fd = make_file("/tmp/mapsdiff-c", 4);
	mmap(p + 10 * PS, 2 * PS, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);
	close(fd);
	if (mmap(p + 2 * PS, PS, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) ==
	    MAP_FAILED)
		anon(p + 11 * PS, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE);
}

static void case_cow_fork(void)
{
	char *p = anon(NULL, 8, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	touch(p, 8);
	char *s = anon(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED);
	touch(s, 4);
	mprotect(p + 2 * PS, 2 * PS, PROT_READ);
	madvise(p + 6 * PS, 2 * PS, MADV_DONTFORK);
	char *b = brk_add(3 * PS);
	touch(b, 3);
	pid_t pid = fork();
	if (pid == 0) {
		p[0] = 2;
		raise(SIGSTOP);
		_exit(0);
	}
	int st;
	waitpid(pid, &st, WUNTRACED);
	dump(pid, "case-cow-fork-child");
	kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
}

static const struct {
	const char *name;
	void (*fn)(void);
} cases[] = {
	{"anon-adjacent", case_anon_adjacent},
	{"mprotect-back", case_mprotect_back},
	{"mprotect-split", case_mprotect_split},
	{"shared-hole", case_shared_hole},
	{"file-adjacent", case_file_adjacent},
	{"file-shared-write", case_file_shared_write},
	{"brk", case_brk},
	{"mremap", case_mremap},
	{"munmap-middle", case_munmap_middle},
	{"madvise", case_madvise},
	{"mlock", case_mlock},
	{"flags", case_flags},
	{"memfd-shm", case_memfd_shm},
	{"map-fixed-over", case_map_fixed_over},
	{"cow-fork", case_cow_fork},
};

static void run_cases(void)
{
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		fflush(stdout);
		pid_t pid = fork();
		if (pid == 0) {
			cases[i].fn();
			raise(SIGSTOP);
			_exit(0);
		}
		int st;
		if (waitpid(pid, &st, WUNTRACED) != pid || !WIFSTOPPED(st)) {
			printf("mapsdiff: nodump case-%s\n", cases[i].name);
			continue;
		}
		char name[64];
		snprintf(name, sizeof(name), "case-%s", cases[i].name);
		dump(pid, name);
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
	}
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOFBF, 1 << 16);
	if (argc == 2 && !strcmp(argv[1], "--setup")) {
		mount("proc", "/proc", "proc", 0, NULL);
		if (mount("dev", "/dev", "devtmpfs", 0, NULL) != 0) {
			mount("dev", "/dev", "tmpfs", 0, NULL);
			mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
			mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
		}
		mount("tmp", "/tmp", "tmpfs", 0, NULL);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--cases")) {
		/* The cases run with the placement of the program, so that each kernel places them in
		 * the same way. A re-exec gives the program the fixed placement. */
		if (personality(0xffffffff) & ADDR_NO_RANDOMIZE) {
			run_cases();
			return 0;
		}
		personality(ADDR_NO_RANDOMIZE);
		execv("/proc/self/exe", argv);
		run_cases();
		return 0;
	}
	if (argc < 3) {
		fprintf(stderr, "usage: mapsdump NAME PROGRAM [ARG...] | mapsdump --cases\n");
		return 2;
	}
	return run(argv[1], argv + 2);
}
