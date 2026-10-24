/*
 * The init program of the rk.test=init boot test. It is a static ELF file. Each check prints
 * one line. init exits with 0 if each check passes, and with 1 if a check fails. With the
 * argument "tty", init also reads a line from the console and waits for ^C, which the boot test
 * types.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

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

static void test_uname(void)
{
	struct utsname u;
	check("uname", uname(&u) == 0 && strcmp(u.sysname, "Linux") == 0 &&
			       strcmp(u.machine, "x86_64") == 0);
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
	check("rename", rename("/tmp/a", "/tmp/b") == 0 && access("/tmp/a", F_OK) != 0);
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

static void test_vdso(void)
{
	int (*vgettime)(clockid_t, struct timespec *) = vdso_sym("__vdso_clock_gettime");
	int (*vgettimeofday)(struct timeval *, void *) = vdso_sym("__vdso_gettimeofday");
	long (*vtime)(long *) = vdso_sym("__vdso_time");
	int (*vgetcpu)(unsigned *, unsigned *) = vdso_sym("__vdso_getcpu");
	check("the vDSO has its functions", vgettime && vgettimeofday && vtime && vgetcpu &&
					    vdso_sym("__vdso_clock_getres"));
	if (!vgettime || !vgettimeofday || !vtime || !vgetcpu)
		return;
	struct timespec a, s, b;
	check("__vdso_clock_gettime", vgettime(CLOCK_MONOTONIC, &a) == 0);
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &s);
	vgettime(CLOCK_MONOTONIC, &b);
	check("the vDSO time agrees with the system call", timespec_ns(&a) <= timespec_ns(&s) &&
							   timespec_ns(&s) <= timespec_ns(&b));
	struct timespec d = { 0, 20 * 1000 * 1000 };
	nanosleep(&d, NULL);
	vgettime(CLOCK_REALTIME, &b);
	check("the vDSO time goes forward in a sleep", timespec_ns(&b) - timespec_ns(&s) >= 10 * 1000 * 1000);
	check("__vdso_clock_gettime of a CPU clock", vgettime(CLOCK_PROCESS_CPUTIME_ID, &a) == 0);
	check("__vdso_clock_gettime of a bad clock", vgettime(1000, &a) == -EINVAL);
	struct timeval tv;
	syscall(SYS_clock_gettime, CLOCK_REALTIME, &s);
	check("__vdso_gettimeofday", vgettimeofday(&tv, NULL) == 0 && tv.tv_sec >= s.tv_sec);
	long t = 0;
	check("__vdso_time", vtime(&t) == t && t >= s.tv_sec);
	unsigned cpu = 7, node = 7;
	check("__vdso_getcpu", vgetcpu(&cpu, &node) == 0 && cpu == 0 && node == 0);
	struct timespec m;
	check("clock_gettime of libc", clock_gettime(CLOCK_MONOTONIC, &m) == 0 && timespec_ns(&m) >= timespec_ns(&s));
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
		struct timespec d = {0, 20 * 1000 * 1000};
		nanosleep(&d, NULL);
		kill(getppid(), SIGUSR1);
		_exit(0);
	}
	struct timespec d = {5, 0};
	r = nanosleep(&d, NULL);
	check("a signal stops nanosleep", r == -1 && errno == EINTR && got_sig == SIGUSR1);
	waitpid(pid, &status, 0);

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
	check("/proc/mounts", read_file("/proc/mounts", buf, sizeof(buf)) > 0 && strstr(buf, "proc /proc proc rw 0 0\n"));
	n = readlink("/proc/self/exe", link, sizeof(link) - 1);
	check("/proc/self/exe", n == 5 && !strncmp(link, "/init", 5));
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	check("/proc/sys/kernel/pid_max", fd >= 0 && read(fd, buf, sizeof(buf)) == 8 && !strncmp(buf, "4194304\n", 8));
	close(fd);
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

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	test_ids();
	test_uname();
	test_memory();
	test_files();
	test_devices();
	test_fork();
	test_exec();
	test_time();
	test_vdso();
	test_signals();
	test_pipes();
	test_threads();
	test_locks();
	test_clone3();
	test_mount();
	test_proc();
	if (argc > 1 && strcmp(argv[1], "tty") == 0)
		test_tty();
	printf("init: %s\n", failed ? "a check failed" : "each check passed");
	return failed;
}
