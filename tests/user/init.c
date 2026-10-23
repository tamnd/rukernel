/*
 * The init program of the rk.test=init boot test. It is a static ELF file. Each check prints
 * one line. init exits with 0 if each check passes, and with 1 if a check fails. With the
 * argument "tty", init also reads a line from the console and waits for ^C, which the boot test
 * types.
 */
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
	test_signals();
	if (argc > 1 && strcmp(argv[1], "tty") == 0)
		test_tty();
	printf("init: %s\n", failed ? "a check failed" : "each check passed");
	return failed;
}
