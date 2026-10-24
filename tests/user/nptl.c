/*
 * The pthread test of the debian boot test. It is a dynamic glibc program. The checks follow the
 * nptl tests of glibc for mutexes, condition variables, robust mutexes and priority inheritance
 * mutexes. Each check prints one line. The program exits with 0 if each check passes, and with 1
 * if a check fails.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failed;

static void check(const char *name, int ok)
{
	printf("nptl: %s: %s\n", name, ok ? "ok" : "FAIL");
	fflush(stdout);
	if (!ok)
		failed = 1;
}

static void init_mutex(pthread_mutex_t *m, int type, int robust, int protocol, int shared)
{
	pthread_mutexattr_t a;
	pthread_mutexattr_init(&a);
	pthread_mutexattr_settype(&a, type);
	pthread_mutexattr_setrobust(&a, robust);
	pthread_mutexattr_setprotocol(&a, protocol);
	pthread_mutexattr_setpshared(&a, shared);
	pthread_mutex_init(m, &a);
	pthread_mutexattr_destroy(&a);
}

/* Gives the time on `clock` after `ms` milliseconds. */
static struct timespec after_ms(clockid_t clock, long ms)
{
	struct timespec ts;
	clock_gettime(clock, &ts);
	ts.tv_nsec += ms * 1000000;
	ts.tv_sec += ts.tv_nsec / 1000000000;
	ts.tv_nsec %= 1000000000;
	return ts;
}

static pthread_mutex_t m;
static long counter;

static void *add_many(void *arg)
{
	for (int i = 0; i < 1000; i++) {
		pthread_mutex_lock(&m);
		long v = counter;
		if (i % 64 == 0)
			sched_yield();
		counter = v + 1;
		pthread_mutex_unlock(&m);
	}
	return arg;
}

static int count_with(int protocol)
{
	pthread_t t[4];
	init_mutex(&m, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_STALLED, protocol,
		   PTHREAD_PROCESS_PRIVATE);
	counter = 0;
	for (int i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, add_many, NULL);
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	pthread_mutex_destroy(&m);
	return counter == 4000;
}

static void *lock_and_exit(void *arg)
{
	pthread_mutex_lock(arg);
	return NULL;
}

static void *trylock(void *arg)
{
	return (void *)(long)pthread_mutex_trylock(arg);
}

static void *timedlock(void *arg)
{
	struct timespec ts = after_ms(CLOCK_REALTIME, 50);
	return (void *)(long)pthread_mutex_timedlock(arg, &ts);
}

static void test_mutexes(void)
{
	pthread_t t;
	void *ret;

	check("a normal mutex keeps the counter right", count_with(PTHREAD_PRIO_NONE));
	check("a priority inheritance mutex keeps the counter right",
	      count_with(PTHREAD_PRIO_INHERIT));

	for (int pi = 0; pi < 2; pi++) {
		int protocol = pi ? PTHREAD_PRIO_INHERIT : PTHREAD_PRIO_NONE;
		const char *kind = pi ? "priority inheritance" : "normal";
		char name[128];

		init_mutex(&m, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_STALLED, protocol,
			   PTHREAD_PROCESS_PRIVATE);
		pthread_mutex_lock(&m);
		snprintf(name, sizeof(name), "an error check %s mutex gives EDEADLK", kind);
		check(name, pthread_mutex_lock(&m) == EDEADLK);
		pthread_create(&t, NULL, trylock, &m);
		pthread_join(t, &ret);
		snprintf(name, sizeof(name), "trylock of a %s mutex gives EBUSY", kind);
		check(name, ret == (void *)EBUSY);
		pthread_create(&t, NULL, timedlock, &m);
		pthread_join(t, &ret);
		snprintf(name, sizeof(name), "timedlock of a %s mutex gives ETIMEDOUT", kind);
		check(name, ret == (void *)ETIMEDOUT);
		pthread_mutex_unlock(&m);
		snprintf(name, sizeof(name), "unlock of a free %s mutex gives EPERM", kind);
		check(name, pthread_mutex_unlock(&m) == EPERM);
		pthread_mutex_destroy(&m);

		init_mutex(&m, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_STALLED, protocol,
			   PTHREAD_PROCESS_PRIVATE);
		snprintf(name, sizeof(name), "a recursive %s mutex locks two times", kind);
		check(name, pthread_mutex_lock(&m) == 0 && pthread_mutex_lock(&m) == 0 &&
				    pthread_mutex_unlock(&m) == 0 && pthread_mutex_unlock(&m) == 0);
		pthread_mutex_destroy(&m);
	}
}

static void test_robust(void)
{
	pthread_t t;

	for (int pi = 0; pi < 2; pi++) {
		int protocol = pi ? PTHREAD_PRIO_INHERIT : PTHREAD_PRIO_NONE;
		const char *kind = pi ? "robust priority inheritance" : "robust";
		char name[128];

		init_mutex(&m, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_ROBUST, protocol,
			   PTHREAD_PROCESS_PRIVATE);
		pthread_create(&t, NULL, lock_and_exit, &m);
		pthread_join(t, NULL);
		snprintf(name, sizeof(name), "a %s mutex of a dead thread gives EOWNERDEAD", kind);
		check(name, pthread_mutex_lock(&m) == EOWNERDEAD);
		pthread_mutex_unlock(&m);
		snprintf(name, sizeof(name),
			 "a %s mutex that is not consistent gives ENOTRECOVERABLE", kind);
		check(name, pthread_mutex_lock(&m) == ENOTRECOVERABLE);
		pthread_mutex_destroy(&m);

		pthread_mutex_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
					       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		init_mutex(shared, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_ROBUST, protocol,
			   PTHREAD_PROCESS_SHARED);
		pid_t pid = fork();
		if (pid == 0) {
			pthread_mutex_lock(shared);
			_exit(0);
		}
		waitpid(pid, NULL, 0);
		snprintf(name, sizeof(name), "a %s mutex of a dead process gives EOWNERDEAD", kind);
		check(name, pthread_mutex_lock(shared) == EOWNERDEAD);
		snprintf(name, sizeof(name), "a %s mutex works after pthread_mutex_consistent",
			 kind);
		check(name, pthread_mutex_consistent(shared) == 0 &&
				    pthread_mutex_unlock(shared) == 0 &&
				    pthread_mutex_lock(shared) == 0 &&
				    pthread_mutex_unlock(shared) == 0);
		munmap(shared, 4096);
	}
}

static pthread_cond_t cond;
static int ready, woken;

static void *wait_ready(void *arg)
{
	pthread_mutex_lock(&m);
	while (!ready)
		pthread_cond_wait(&cond, &m);
	woken++;
	pthread_mutex_unlock(&m);
	return NULL;
}

static void unlock(void *arg)
{
	pthread_mutex_unlock(arg);
}

static void *wait_cancel(void *arg)
{
	pthread_mutex_lock(&m);
	pthread_cleanup_push(unlock, &m);
	for (;;)
		pthread_cond_wait(&cond, &m);
	pthread_cleanup_pop(0);
	return NULL;
}

static void test_conds(void)
{
	pthread_t t[4];
	void *ret;

	init_mutex(&m, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_STALLED, PTHREAD_PRIO_NONE,
		   PTHREAD_PROCESS_PRIVATE);
	pthread_cond_init(&cond, NULL);
	pthread_create(&t[0], NULL, wait_ready, NULL);
	usleep(10000);
	pthread_mutex_lock(&m);
	ready = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&m);
	pthread_join(t[0], NULL);
	check("pthread_cond_signal wakes a thread", woken == 1);

	ready = 0;
	woken = 0;
	for (int i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, wait_ready, NULL);
	usleep(10000);
	pthread_mutex_lock(&m);
	ready = 1;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&m);
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	check("pthread_cond_broadcast wakes each thread", woken == 4);

	struct timespec ts = after_ms(CLOCK_REALTIME, 50);
	pthread_mutex_lock(&m);
	check("pthread_cond_timedwait gives ETIMEDOUT", pthread_cond_timedwait(&cond, &m, &ts) ==
								ETIMEDOUT);
	ts = after_ms(CLOCK_MONOTONIC, 50);
	check("pthread_cond_clockwait gives ETIMEDOUT",
	      pthread_cond_clockwait(&cond, &m, CLOCK_MONOTONIC, &ts) == ETIMEDOUT);
	pthread_mutex_unlock(&m);

	pthread_condattr_t ca;
	pthread_condattr_init(&ca);
	pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_cond_destroy(&cond);
	pthread_cond_init(&cond, &ca);
	ts = after_ms(CLOCK_MONOTONIC, 50);
	pthread_mutex_lock(&m);
	check("a condition variable on CLOCK_MONOTONIC gives ETIMEDOUT",
	      pthread_cond_timedwait(&cond, &m, &ts) == ETIMEDOUT);
	pthread_mutex_unlock(&m);

	/* The cancel unwinds the stack of the thread with libgcc_s, which glibc loads with dlopen. */
	pthread_create(&t[0], NULL, wait_cancel, NULL);
	usleep(10000);
	pthread_cancel(t[0]);
	pthread_join(t[0], &ret);
	check("pthread_cancel stops a thread in pthread_cond_wait", ret == PTHREAD_CANCELED);
	check("the cleanup handler unlocks the mutex",
	      pthread_mutex_trylock(&m) == 0 && pthread_mutex_unlock(&m) == 0);
}

static pthread_barrier_t barrier;
static pthread_rwlock_t rw;
static sem_t sem;
static __thread int tls;
static int serial;

static void *meet(void *arg)
{
	tls = (int)(long)arg;
	if (pthread_barrier_wait(&barrier) == PTHREAD_BARRIER_SERIAL_THREAD)
		__atomic_add_fetch(&serial, 1, __ATOMIC_SEQ_CST);
	return (void *)(long)(tls == (int)(long)arg);
}

static void *try_read(void *arg)
{
	return (void *)(long)pthread_rwlock_tryrdlock(&rw);
}

static void *post(void *arg)
{
	usleep(10000);
	sem_post(&sem);
	return NULL;
}

static void test_others(void)
{
	pthread_t t[4];
	void *ret;
	int ok = 1;

	pthread_barrier_init(&barrier, NULL, 4);
	for (long i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, meet, (void *)(i + 1));
	for (int i = 0; i < 4; i++) {
		pthread_join(t[i], &ret);
		ok &= ret == (void *)1;
	}
	check("a barrier lets 4 threads go with one serial thread", serial == 1);
	check("each thread has its own thread local variable", ok && tls == 0);

	pthread_rwlock_init(&rw, NULL);
	pthread_rwlock_rdlock(&rw);
	pthread_create(&t[0], NULL, try_read, NULL);
	pthread_join(t[0], &ret);
	check("two threads can hold a read lock", ret == 0);
	pthread_rwlock_unlock(&rw);
	pthread_rwlock_unlock(&rw);
	pthread_rwlock_wrlock(&rw);
	pthread_create(&t[0], NULL, try_read, NULL);
	pthread_join(t[0], &ret);
	check("a write lock stops a read lock", ret == (void *)EBUSY);
	pthread_rwlock_unlock(&rw);

	sem_init(&sem, 0, 0);
	pthread_create(&t[0], NULL, post, NULL);
	check("sem_wait waits for sem_post", sem_wait(&sem) == 0);
	pthread_join(t[0], NULL);
	struct timespec ts = after_ms(CLOCK_REALTIME, 50);
	check("sem_timedwait gives ETIMEDOUT", sem_timedwait(&sem, &ts) == -1 && errno ==
										    ETIMEDOUT);
}

int main(void)
{
	test_mutexes();
	test_robust();
	test_conds();
	test_others();
	printf("nptl: %s\n", failed ? "a check failed" : "each check passed");
	return failed;
}
