/*
 * The workloads of the first rukernel-bench table. One static program has all the benchmarks.
 *
 * Usage: bench [RUNS [SCALE [NAME...]]]
 *
 * The program runs each benchmark one time as a warm-up, then RUNS times. Each run prints the
 * line "bench: NAME VALUE". VALUE is the time of one operation, or a throughput for the stream
 * benchmarks. SCALE multiplies the number of operations of a run (100 is the default count). With
 * NAME, only these benchmarks run. As init (PID 1), the program first gets a console, mounts
 * /proc and /dev and brings up lo. At the end it prints "bench-done". run.py reads these lines.
 *
 * The same binary runs on rukernel and on Linux, so the two kernels run the same instructions in
 * user mode.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define FAULT_BYTES (16L << 20)
#define BIG_BYTES (128L << 20)
#define COW_BYTES (16L << 20)
#define MT_BYTES (4L << 20)
#define STREAM_CHUNK 65536
#define UDP_SIZE 1024

static long scale = 100;
static int port = 20000;

static long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static void die(const char *what)
{
	printf("bench-error: %s: %s\n", what, strerror(errno));
	fflush(stdout);
	exit(1);
}

/* The count of operations of a run: the base count times SCALE / 100. */
static long count(long base)
{
	long n = base * scale / 100;
	return n > 0 ? n : 1;
}

static void full_read(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len > 0) {
		ssize_t r = read(fd, p, len);
		if (r <= 0)
			die("read");
		p += r;
		len -= r;
	}
}

/* entry: getpid through syscall(2), so that the C library does not keep the value. */
static double b_getpid(void)
{
	long n = count(20000), t = now_ns();
	for (long i = 0; i < n; i++)
		syscall(SYS_getpid);
	return (double)(now_ns() - t) / n;
}

/* entry: the null system call of LMbench, getppid. */
static double b_null(void)
{
	long n = count(20000), t = now_ns();
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	return (double)(now_ns() - t) / n;
}

/* entry: a read of 1 byte from /dev/zero. */
static double b_read_zero(void)
{
	char c;
	int fd = open("/dev/zero", O_RDONLY);
	if (fd < 0)
		die("open /dev/zero");
	long n = count(20000), t = now_ns();
	for (long i = 0; i < n; i++)
		if (read(fd, &c, 1) != 1)
			die("read /dev/zero");
	t = now_ns() - t;
	close(fd);
	return (double)t / n;
}

/* entry: a write of 1 byte to a pipe and a read of it in the same process, with no switch. */
static double b_pipe_rw(void)
{
	int p[2];
	char c = 'x';
	if (pipe(p) < 0)
		die("pipe");
	long n = count(10000), t = now_ns();
	for (long i = 0; i < n; i++) {
		if (write(p[1], &c, 1) != 1 || read(p[0], &c, 1) != 1)
			die("pipe");
	}
	t = now_ns() - t;
	close(p[0]);
	close(p[1]);
	return (double)t / n;
}

/* sched: a round trip of 1 byte between two processes over two pipes (two context switches). */
static double b_ctxsw(void)
{
	int a[2], b[2];
	char c = 'x';
	if (pipe(a) < 0 || pipe(b) < 0)
		die("pipe");
	long n = count(5000);
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		for (long i = 0; i < n; i++) {
			full_read(a[0], &c, 1);
			if (write(b[1], &c, 1) != 1)
				_exit(1);
		}
		_exit(0);
	}
	long t = now_ns();
	for (long i = 0; i < n; i++) {
		if (write(a[1], &c, 1) != 1)
			die("write");
		full_read(b[0], &c, 1);
	}
	t = now_ns() - t;
	waitpid(pid, NULL, 0);
	close(a[0]);
	close(a[1]);
	close(b[0]);
	close(b[1]);
	return (double)t / n;
}

/* sched: sched_yield with no other task to run. */
static double b_yield(void)
{
	long n = count(20000), t = now_ns();
	for (long i = 0; i < n; i++)
		sched_yield();
	return (double)(now_ns() - t) / n;
}

static void *thread_fn(void *arg)
{
	return arg;
}

/* sched: pthread_create and pthread_join of a thread that returns at once. */
static double b_thread(void)
{
	long n = count(1000), t = now_ns();
	for (long i = 0; i < n; i++) {
		pthread_t th;
		if (pthread_create(&th, NULL, thread_fn, NULL) != 0)
			die("pthread_create");
		pthread_join(th, NULL);
	}
	return (double)(now_ns() - t) / n / 1000.0;
}

/* mem: the write fault on a new anonymous page. Only the writes are in the time. */
static double b_fault(void)
{
	long rounds = count(400) / 100 + 1, pages = FAULT_BYTES / PAGE, total = 0;
	for (long r = 0; r < rounds; r++) {
		char *m = mmap(NULL, FAULT_BYTES, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED)
			die("mmap");
		long t = now_ns();
		for (long i = 0; i < pages; i++)
			m[i * PAGE] = 1;
		total += now_ns() - t;
		munmap(m, FAULT_BYTES);
	}
	return (double)total / (rounds * pages);
}

/*
 * mem: the write fault that copies a private page of 4 KiB, which a child of fork also maps. The
 * area has no transparent huge pages, so each fault copies one page. Only the writes are in the
 * time.
 */
static double b_cow(void)
{
	long rounds = count(400) / 100 + 1, pages = COW_BYTES / PAGE, total = 0;
	for (long r = 0; r < rounds; r++) {
		char *m = mmap(NULL, COW_BYTES, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED)
			die("mmap");
		madvise(m, COW_BYTES, MADV_NOHUGEPAGE);
		for (long i = 0; i < pages; i++)
			m[i * PAGE] = 1;
		int p[2];
		if (pipe(p) != 0)
			die("pipe");
		pid_t pid = fork();
		if (pid < 0)
			die("fork");
		if (pid == 0) {
			/* The child keeps the pages until the parent closes the pipe. */
			char c;
			close(p[1]);
			read(p[0], &c, 1);
			_exit(0);
		}
		close(p[0]);
		long t = now_ns();
		for (long i = 0; i < pages; i++)
			m[i * PAGE] = 2;
		total += now_ns() - t;
		close(p[1]);
		waitpid(pid, NULL, 0);
		munmap(m, COW_BYTES);
	}
	return (double)total / (rounds * pages);
}

/* mem: mmap and munmap of 64 KiB of anonymous memory, with no access. */
static double b_mmap(void)
{
	long n = count(10000), t = now_ns();
	for (long i = 0; i < n; i++) {
		void *m = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			       -1, 0);
		if (m == MAP_FAILED)
			die("mmap");
		munmap(m, 65536);
	}
	return (double)(now_ns() - t) / n;
}

static double fork_loop(long n)
{
	long t = now_ns();
	for (long i = 0; i < n; i++) {
		pid_t pid = fork();
		if (pid < 0)
			die("fork");
		if (pid == 0)
			_exit(0);
		waitpid(pid, NULL, 0);
	}
	return (double)(now_ns() - t) / n / 1000.0;
}

/* mem: fork of a small process, exit of the child and wait. */
static double b_fork(void)
{
	return fork_loop(count(500));
}

/* mem: the same with 128 MiB of private anonymous memory that the parent wrote. */
static double b_fork_big(void)
{
	char *m = mmap(NULL, BIG_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED)
		die("mmap");
	for (long i = 0; i < BIG_BYTES; i += PAGE)
		m[i] = 1;
	double v = fork_loop(count(50));
	munmap(m, BIG_BYTES);
	return v;
}

/* The number of threads of the multithreaded benchmarks: one for each CPU of the process. */
static int nthreads(void)
{
	cpu_set_t set;
	if (sched_getaffinity(0, sizeof(set), &set) != 0)
		return 1;
	int n = CPU_COUNT(&set);
	return n > 0 ? n : 1;
}

struct mt_arg {
	pthread_barrier_t *start;
	long rounds;
	int fault;
};

/* One thread of fault_mt or mmap_mt. Each thread maps its own range, as will-it-scale does. */
static void *mt_fn(void *p)
{
	struct mt_arg *a = p;
	pthread_barrier_wait(a->start);
	for (long r = 0; r < a->rounds; r++) {
		long len = a->fault ? MT_BYTES : 65536;
		char *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED)
			die("mmap");
		if (a->fault)
			for (long i = 0; i < len; i += PAGE)
				m[i] = 1;
		munmap(m, len);
	}
	return NULL;
}

/* Runs `rounds` rounds in each of the threads, and gives the wall time in ns of one operation of
 * all the threads: the time of the run over the operations of all threads. */
static double mt_run(long rounds, int fault, long ops_per_round)
{
	int n = nthreads();
	pthread_t th[64];
	struct mt_arg arg[64];
	pthread_barrier_t start;
	if (n > 64)
		n = 64;
	pthread_barrier_init(&start, NULL, n + 1);
	for (int i = 0; i < n; i++) {
		arg[i] = (struct mt_arg){&start, rounds, fault};
		if (pthread_create(&th[i], NULL, mt_fn, &arg[i]) != 0)
			die("pthread_create");
	}
	pthread_barrier_wait(&start);
	long t = now_ns();
	for (int i = 0; i < n; i++)
		pthread_join(th[i], NULL);
	long total = now_ns() - t;
	pthread_barrier_destroy(&start);
	return (double)total / (n * rounds * ops_per_round);
}

/* mem: the write fault on a new anonymous page in each thread at the same time, as page_fault1 of
 * will-it-scale. Each round of a thread maps 4 MiB, writes each page and unmaps it. The time is
 * the wall time of one fault: the time of the run over the faults of all threads. */
static double b_fault_mt(void)
{
	return mt_run(count(400) / 100 + 1, 1, MT_BYTES / PAGE);
}

/* mem: mmap and munmap of 64 KiB in each thread at the same time, as mmap1 of will-it-scale. The
 * time is the wall time of one pair over the pairs of all threads. */
static double b_mmap_mt(void)
{
	return mt_run(count(2000), 0, 1);
}

static struct sockaddr_in loopback(int p)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(p);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return a;
}

/* Makes a listening TCP socket on 127.0.0.1 and gives its port. */
static int tcp_listen(int *p)
{
	int one = 1, s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		die("socket");
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in a = loopback(*p = port++);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(s, 1) < 0)
		die("bind tcp");
	return s;
}

static int tcp_connect(int p)
{
	int one = 1, s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = loopback(p);
	if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) < 0)
		die("connect");
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return s;
}

static int tcp_accept(int l)
{
	int one = 1, s = accept(l, NULL, NULL);
	if (s < 0)
		_exit(1);
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	close(l);
	return s;
}

/* net: a round trip of 1 byte over a TCP connection on loopback, between two processes. */
static double b_tcp_rr(void)
{
	int p, l = tcp_listen(&p);
	char c = 'x';
	long n = count(2000);
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		int s = tcp_accept(l);
		for (long i = 0; i < n; i++) {
			full_read(s, &c, 1);
			if (write(s, &c, 1) != 1)
				_exit(1);
		}
		_exit(0);
	}
	close(l);
	int s = tcp_connect(p);
	long t = now_ns();
	for (long i = 0; i < n; i++) {
		if (write(s, &c, 1) != 1)
			die("write");
		full_read(s, &c, 1);
	}
	t = now_ns() - t;
	close(s);
	waitpid(pid, NULL, 0);
	return (double)t / n / 1000.0;
}

/* net: the throughput of one TCP connection on loopback, in writes of 64 KiB. */
static double b_tcp_stream(void)
{
	static char buf[STREAM_CHUNK];
	int p, l = tcp_listen(&p);
	long n = count(500);
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		int s = tcp_accept(l);
		long got = 0;
		ssize_t r;
		while ((r = read(s, buf, sizeof(buf))) > 0)
			got += r;
		char c = got == n * STREAM_CHUNK ? 'y' : 'n';
		_exit(write(s, &c, 1) == 1 && c == 'y' ? 0 : 1);
	}
	close(l);
	int s = tcp_connect(p);
	char c;
	long t = now_ns();
	for (long i = 0; i < n; i++) {
		size_t off = 0;
		while (off < sizeof(buf)) {
			ssize_t w = write(s, buf + off, sizeof(buf) - off);
			if (w <= 0)
				die("write");
			off += w;
		}
	}
	shutdown(s, SHUT_WR);
	full_read(s, &c, 1);
	t = now_ns() - t;
	close(s);
	waitpid(pid, NULL, 0);
	if (c != 'y')
		die("tcp stream lost data");
	return (double)n * STREAM_CHUNK / 1e6 / (t / 1e9);
}

static int udp_bind(int p)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = loopback(p);
	if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) < 0)
		die("bind udp");
	return s;
}

static int udp_connect(int p)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = loopback(p);
	if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) < 0)
		die("connect udp");
	return s;
}

/* net: a round trip of a 1 byte datagram over UDP on loopback, between two processes. */
static double b_udp_rr(void)
{
	int p = port++, srv = udp_bind(p);
	char c = 'x';
	long n = count(2000);
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		struct sockaddr_in from;
		for (long i = 0; i < n; i++) {
			socklen_t len = sizeof(from);
			if (recvfrom(srv, &c, 1, 0, (struct sockaddr *)&from, &len) != 1)
				_exit(1);
			sendto(srv, &c, 1, 0, (struct sockaddr *)&from, len);
		}
		_exit(0);
	}
	close(srv);
	int s = udp_connect(p);
	long t = now_ns();
	for (long i = 0; i < n; i++) {
		if (send(s, &c, 1, 0) != 1)
			die("send");
		if (recv(s, &c, 1, 0) != 1)
			die("recv");
	}
	t = now_ns() - t;
	close(s);
	waitpid(pid, NULL, 0);
	return (double)t / n / 1000.0;
}

/*
 * net: the throughput of UDP datagrams of 1 KiB on loopback. The receiver counts the bytes that
 * arrive and the time of the last one, so a lost datagram counts as no data. A datagram of 1 byte
 * marks the end.
 */
static double b_udp_stream(void)
{
	static char buf[UDP_SIZE];
	int p = port++, srv = udp_bind(p), rep[2], big = 4 << 20;
	long n = count(20000);
	setsockopt(srv, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	if (pipe(rep) < 0)
		die("pipe");
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		struct timeval tv = {2, 0};
		long r[2] = {0, 0};
		ssize_t got;
		setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		while ((got = recv(srv, buf, sizeof(buf), 0)) > 1) {
			r[0] += got;
			r[1] = now_ns();
		}
		_exit(write(rep[1], r, sizeof(r)) == sizeof(r) ? 0 : 1);
	}
	close(srv);
	int s = udp_connect(p);
	long t = now_ns();
	for (long i = 0; i < n; i++)
		send(s, buf, sizeof(buf), 0);
	for (int i = 0; i < 10; i++)
		send(s, buf, 1, 0);
	long r[2];
	full_read(rep[0], r, sizeof(r));
	close(s);
	close(rep[0]);
	close(rep[1]);
	waitpid(pid, NULL, 0);
	if (r[0] == 0)
		die("udp stream got no data");
	return (double)r[0] / 1e6 / ((r[1] - t) / 1e9);
}

static const struct {
	const char *name;
	double (*fn)(void);
} benches[] = {
	{"getpid", b_getpid},	   {"null", b_null},		{"read_zero", b_read_zero},
	{"pipe_rw", b_pipe_rw},	   {"ctxsw", b_ctxsw},		{"yield", b_yield},
	{"thread", b_thread},	   {"fault", b_fault},		{"mmap", b_mmap},
	{"fork", b_fork},	   {"fork_big", b_fork_big},	{"tcp_rr", b_tcp_rr},
	{"tcp_stream", b_tcp_stream}, {"udp_rr", b_udp_rr},	{"udp_stream", b_udp_stream},
	{"fault_mt", b_fault_mt},  {"mmap_mt", b_mmap_mt},	{"cow", b_cow},
};

/* As init: get a console, mount /proc and /dev, and bring up lo. Errors do not stop the run. */
static void setup(void)
{
	mkdir("/dev", 0755);
	mkdir("/proc", 0555);
	mount("proc", "/proc", "proc", 0, NULL);
	if (access("/dev/zero", F_OK) != 0)
		mount("dev", "/dev", "devtmpfs", 0, NULL);
	if (access("/dev/zero", F_OK) != 0)
		mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
	if (fcntl(1, F_GETFD) < 0) {
		int fd = open("/dev/console", O_RDWR);
		if (fd < 0)
			fd = open("/dev/ttyS0", O_RDWR);
		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
		}
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");
	if (s >= 0 && ioctl(s, SIOCGIFFLAGS, &ifr) == 0 && !(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	if (s >= 0)
		close(s);
}

int main(int argc, char **argv)
{
	int runs = 10;
	if (getpid() == 1)
		setup();
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);
	if (argc > 1)
		runs = atoi(argv[1]);
	if (argc > 2)
		scale = atol(argv[2]);
	for (size_t b = 0; b < sizeof(benches) / sizeof(benches[0]); b++) {
		int want = argc <= 3;
		for (int i = 3; i < argc; i++)
			want |= strcmp(argv[i], benches[b].name) == 0;
		if (!want)
			continue;
		printf("bench-start: %s\n", benches[b].name);
		benches[b].fn();
		for (int r = 0; r < runs; r++)
			printf("bench: %s %.3f\n", benches[b].name, benches[b].fn());
	}
	printf("bench-done\n");
	return 0;
}
