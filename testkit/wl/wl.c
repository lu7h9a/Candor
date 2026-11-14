// SPDX-License-Identifier: MIT
/*
 * wl - ground-truth workload generator for SysScope tests (plan WP05).
 *
 * Performs exactly N of each requested action using direct syscalls
 * (syscall(2), no stdio buffering in the measured paths) and prints a JSON
 * manifest of what it did on stdout when it finishes. Tests compare what the
 * tracer observed with this manifest. Every file it touches lives under the
 * directory given with --dir; network actions only use loopback.
 *
 * usage: wl --dir DIR ACTION [N] [ACTION [N] ...]
 * actions: exec N, fork N, open-read N, open-write N, rename N, unlink N,
 *          connect-tcp N, connect-tcp6 N, connect-fail N, connect-udp N,
 *          listen N, threads N, syscalls getppid N, flood N, longpath,
 *          badname, memfd-exec, leader-exits-first, exec-self (last), open-relative,
 *          open-symlink, uring-open, gen3, sleep MS, nanosleep N,
 *          spawn-hold N MS, busy MS, alloc MB MS, open-path PATH;
 *          arguments after "--" are ignored (they only appear in argv)
 * option: wl --dir DIR --wait-stdin ... waits for one byte on stdin first
 *
 * Built statically (make wl) so the same binary runs in every test VM.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/io_uring.h>
#include <sys/mman.h>

static const char *dir;
static char manifest[1 << 20];
static size_t mlen;
static int first_action = 1;

static void die(const char *what)
{
	fprintf(stderr, "wl: %s: %s\n", what, strerror(errno));
	exit(2);
}

static void mput(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void mput(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(manifest + mlen, sizeof(manifest) - mlen, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(manifest) - mlen) {
		fprintf(stderr, "wl: manifest too large\n");
		exit(2);
	}
	mlen += (size_t)n;
}

/* JSON string with every non-printable or non-ASCII byte as \u00XX, so the
 * manifest is valid JSON whatever the bytes (the test decodes it back). */
static void mput_bytes(const char *s, size_t n)
{
	mput("\"");
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\')
			mput("\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			mput("\\u%04x", c);
		else
			mput("%c", c);
	}
	mput("\"");
}

static void begin_action(const char *name, long n)
{
	mput("%s{\"action\":\"%s\",\"n\":%ld", first_action ? "" : ",", name, n);
	first_action = 0;
}

static void end_action(void)
{
	mput("}");
}

static void file_identity(const char *path)
{
	struct stat st;
	if (lstat(path, &st) != 0)
		die(path);
	mput("{\"path\":");
	mput_bytes(path, strlen(path));
	mput(",\"dev\":%llu,\"ino\":%llu}", (unsigned long long)st.st_dev,
	     (unsigned long long)st.st_ino);
}

static int raw_open(const char *path, int flags, int mode)
{
	return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static void raw_close(int fd)
{
	syscall(SYS_close, fd);
}

/* Start time in clock ticks: field 22 of /proc/self/stat, after the last ')'. */
static unsigned long long self_start_ticks(void)
{
	char buf[4096];
	int fd = open("/proc/self/stat", O_RDONLY);
	if (fd < 0)
		die("/proc/self/stat");
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		die("read stat");
	buf[n] = 0;
	char *p = strrchr(buf, ')');
	if (!p)
		die("parse stat");
	/* After ") " come fields 3..; starttime is field 22, i.e. the 20th here. */
	p += 2;
	for (int field = 3; field < 22; field++) {
		p = strchr(p, ' ');
		if (!p)
			die("parse stat");
		p++;
	}
	return strtoull(p, NULL, 10);
}

static void spawn_and_wait(const char *exe, int use_exec)
{
	pid_t pid = (pid_t)syscall(SYS_fork);
	if (pid < 0)
		die("fork");
	if (pid == 0) {
		if (use_exec) {
			char *argv[] = {(char *)exe, NULL};
			char *envp[] = {NULL};
			syscall(SYS_execve, exe, argv, envp);
			_exit(127);
		}
		syscall(SYS_exit_group, 0);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");
}

static void act_exec(long n)
{
	char real[4096];
	if (!realpath("/bin/true", real))
		die("realpath /bin/true");
	begin_action("exec", n);
	mput(",\"exe\":");
	mput_bytes(real, strlen(real));
	for (long i = 0; i < n; i++)
		spawn_and_wait("/bin/true", 1);
	end_action();
}

static void act_fork(long n)
{
	begin_action("fork", n);
	for (long i = 0; i < n; i++)
		spawn_and_wait(NULL, 0);
	end_action();
}

static void make_file(const char *path)
{
	int fd = raw_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		die(path);
	syscall(SYS_write, fd, "x", 1);
	raw_close(fd);
}

static void act_open_read(long n)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/read-target", dir);
	make_file(path);
	begin_action("open-read", n);
	mput(",\"file\":");
	file_identity(path);
	for (long i = 0; i < n; i++) {
		int fd = raw_open(path, O_RDONLY, 0);
		if (fd < 0)
			die("open-read");
		raw_close(fd);
	}
	end_action();
}

static void act_open_write(long n)
{
	char path[4096];
	begin_action("open-write", n);
	mput(",\"files\":[");
	for (long i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s/write-%ld", dir, i);
		int fd = raw_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			die("open-write");
		raw_close(fd);
		if (i)
			mput(",");
		file_identity(path);
	}
	mput("]");
	end_action();
}

/* rename and unlink first create their files; those creates are listed as
 * "setup_opens" so a test can account for them separately. */
static void act_rename(long n)
{
	char a[4096], b[4096];
	for (long i = 0; i < n; i++) {
		snprintf(a, sizeof(a), "%s/ren-%ld", dir, i);
		make_file(a);
	}
	begin_action("rename", n);
	mput(",\"setup_opens\":%ld,\"files\":[", n);
	for (long i = 0; i < n; i++) {
		snprintf(a, sizeof(a), "%s/ren-%ld", dir, i);
		snprintf(b, sizeof(b), "%s/ren-%ld.moved", dir, i);
		if (i)
			mput(",");
		struct stat st;
		if (lstat(a, &st) != 0)
			die(a);
		if (syscall(SYS_renameat, AT_FDCWD, a, AT_FDCWD, b) != 0)
			die("rename");
		mput("{\"old\":");
		mput_bytes(a, strlen(a));
		mput(",\"new\":");
		mput_bytes(b, strlen(b));
		mput(",\"dev\":%llu,\"ino\":%llu}", (unsigned long long)st.st_dev,
		     (unsigned long long)st.st_ino);
	}
	mput("]");
	end_action();
}

static void act_unlink(long n)
{
	char a[4096];
	for (long i = 0; i < n; i++) {
		snprintf(a, sizeof(a), "%s/unl-%ld", dir, i);
		make_file(a);
	}
	begin_action("unlink", n);
	mput(",\"setup_opens\":%ld,\"files\":[", n);
	for (long i = 0; i < n; i++) {
		snprintf(a, sizeof(a), "%s/unl-%ld", dir, i);
		if (i)
			mput(",");
		file_identity(a);
		if (syscall(SYS_unlinkat, AT_FDCWD, a, 0) != 0)
			die("unlink");
	}
	mput("]");
	end_action();
}

static int listener(int family, int type, uint16_t *port)
{
	int s = socket(family, type, 0);
	if (s < 0)
		die("socket");
	struct sockaddr_storage ss;
	socklen_t len;
	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;
		a->sin_family = AF_INET;
		a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		len = sizeof(*a);
	} else {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
		a->sin6_family = AF_INET6;
		a->sin6_addr = in6addr_loopback;
		len = sizeof(*a);
	}
	if (bind(s, (struct sockaddr *)&ss, len) != 0)
		die("bind");
	if (type == SOCK_STREAM && listen(s, 1024) != 0)
		die("listen");
	if (getsockname(s, (struct sockaddr *)&ss, &len) != 0)
		die("getsockname");
	*port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&ss)->sin_port
					: ((struct sockaddr_in6 *)&ss)->sin6_port);
	return s;
}

static void connect_n(const char *name, int family, int type, long n, int expect_fail)
{
	uint16_t port;
	int l = listener(family, type, &port);
	if (expect_fail) {
		close(l); /* the port is now closed: connects are refused */
	}
	begin_action(name, n);
	mput(",\"addr\":\"%s\",\"port\":%u", family == AF_INET ? "127.0.0.1" : "::1", port);
	int failed = 0;
	for (long i = 0; i < n; i++) {
		int s = socket(family, type, 0);
		if (s < 0)
			die("socket");
		struct sockaddr_storage ss;
		socklen_t len;
		memset(&ss, 0, sizeof(ss));
		if (family == AF_INET) {
			struct sockaddr_in *a = (struct sockaddr_in *)&ss;
			a->sin_family = AF_INET;
			a->sin_port = htons(port);
			a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			len = sizeof(*a);
		} else {
			struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
			a->sin6_family = AF_INET6;
			a->sin6_port = htons(port);
			a->sin6_addr = in6addr_loopback;
			len = sizeof(*a);
		}
		if (syscall(SYS_connect, s, (struct sockaddr *)&ss, len) != 0)
			failed++;
		close(s);
		if (!expect_fail && type == SOCK_STREAM) {
			int c = accept(l, NULL, NULL);
			if (c >= 0)
				close(c);
		}
	}
	if (!expect_fail)
		close(l);
	mput(",\"failed\":%d", failed);
	end_action();
}

static void act_listen(long n)
{
	begin_action("listen", n);
	mput(",\"ports\":[");
	int *fds = calloc((size_t)n, sizeof(int));
	if (!fds)
		die("calloc");
	for (long i = 0; i < n; i++) {
		uint16_t port;
		fds[i] = listener(AF_INET, SOCK_STREAM, &port);
		mput("%s%u", i ? "," : "", port);
	}
	for (long i = 0; i < n; i++)
		close(fds[i]);
	free(fds);
	mput("]");
	end_action();
}

static void *thread_noop(void *arg)
{
	(void)arg;
	return NULL;
}

static void act_threads(long n)
{
	begin_action("threads", n);
	for (long i = 0; i < n; i++) {
		pthread_t t;
		if (pthread_create(&t, NULL, thread_noop, NULL) != 0)
			die("pthread_create");
		pthread_join(t, NULL);
	}
	end_action();
}

static void act_syscalls(const char *name, long n)
{
	if (strcmp(name, "getppid") != 0) {
		fprintf(stderr, "wl: only 'syscalls getppid N' is supported\n");
		exit(2);
	}
	begin_action("syscalls", n);
	mput(",\"name\":\"getppid\",\"nr\":%d", SYS_getppid);
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	end_action();
}

static void act_flood(long n)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/flood-target", dir);
	make_file(path);
	begin_action("flood", n);
	mput(",\"file\":");
	file_identity(path);
	for (long i = 0; i < n; i++) {
		int fd = raw_open(path, O_RDONLY, 0);
		if (fd >= 0)
			raw_close(fd);
	}
	end_action();
}

/* Replaces this process's image with /bin/true (same pid and start time),
 * after writing the manifest; must be the last action. Run after a flood it
 * checks that an exec is not lost to an exhausted budget. */
static void act_exec_self(void)
{
	char real[4096];
	if (!realpath("/bin/true", real))
		die("realpath /bin/true");
	begin_action("exec-self", 1);
	mput(",\"exe\":");
	mput_bytes(real, strlen(real));
	end_action();
	mput("]}\n");
	if (write(1, manifest, mlen) != (ssize_t)mlen)
		die("write manifest");
	char *argv[] = {real, NULL};
	char *envp[] = {NULL};
	syscall(SYS_execve, real, argv, envp);
	die("execve");
}

static void act_longpath(void)
{
	/* 40 nested 20-byte directory names: well over PATH_CAP (512). */
	char path[4096];
	snprintf(path, sizeof(path), "%s", dir);
	for (int i = 0; i < 40; i++) {
		size_t l = strlen(path);
		snprintf(path + l, sizeof(path) - l, "/dddddddddddddddddd%02d", i);
		if (mkdir(path, 0700) != 0 && errno != EEXIST)
			die("mkdir longpath");
	}
	size_t l = strlen(path);
	snprintf(path + l, sizeof(path) - l, "/leaf-file");
	begin_action("longpath", 1);
	make_file(path);
	mput(",\"len\":%zu,\"file\":", strlen(path));
	file_identity(path);
	end_action();
}

static void act_badname(void)
{
	char path[4096];
	/* Invalid UTF-8, a newline and an ANSI escape sequence in one name. */
	snprintf(path, sizeof(path), "%s/bad\xff\xfe-\n-\x1b[31mred", dir);
	begin_action("badname", 1);
	make_file(path);
	mput(",\"file\":");
	file_identity(path);
	end_action();
}

static void act_memfd_exec(void)
{
	int src = open("/bin/true", O_RDONLY);
	if (src < 0)
		die("/bin/true");
	int mfd = (int)syscall(SYS_memfd_create, "wl-memfd", 0);
	if (mfd < 0)
		die("memfd_create");
	char buf[65536];
	ssize_t r;
	while ((r = read(src, buf, sizeof(buf))) > 0)
		if (write(mfd, buf, (size_t)r) != r)
			die("write memfd");
	close(src);
	begin_action("memfd-exec", 1);
	pid_t pid = (pid_t)syscall(SYS_fork);
	if (pid == 0) {
		char *argv[] = {"wl-memfd", NULL};
		char *envp[] = {NULL};
		syscall(SYS_execveat, mfd, "", argv, envp, AT_EMPTY_PATH);
		_exit(127);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	mput(",\"child\":%d,\"status\":%d", pid, status);
	end_action();
	close(mfd);
}


static void *leader_follower(void *arg)
{
	(void)arg;
	/* Give the leader time to exit, then end the process from this thread. */
	struct timespec ts = {0, 300 * 1000 * 1000};
	nanosleep(&ts, NULL);
	syscall(SYS_exit_group, 0);
	return NULL;
}

/* Opens "rel-target" by a relative path after chdir into dir. */
static void act_open_relative(void)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/rel-target", dir);
	make_file(path);
	char cwd[4096];
	if (!getcwd(cwd, sizeof(cwd)))
		die("getcwd");
	if (chdir(dir) != 0)
		die("chdir");
	begin_action("open-relative", 1);
	mput(",\"file\":");
	file_identity(path);
	int fd = raw_open("rel-target", O_RDONLY, 0);
	if (fd < 0)
		die("open relative");
	raw_close(fd);
	end_action();
	if (chdir(cwd) != 0)
		die("chdir back");
}

/* Opens "sym-target" through the symlink "sym-link". */
static void act_open_symlink(void)
{
	char target[4096], link[4096];
	snprintf(target, sizeof(target), "%s/sym-target", dir);
	snprintf(link, sizeof(link), "%s/sym-link", dir);
	make_file(target);
	unlink(link);
	if (symlink(target, link) != 0)
		die("symlink");
	begin_action("open-symlink", 1);
	mput(",\"file\":");
	file_identity(target);
	mput(",\"link\":");
	mput_bytes(link, strlen(link));
	int fd = raw_open(link, O_RDONLY, 0);
	if (fd < 0)
		die("open symlink");
	raw_close(fd);
	end_action();
}

/* Opens a file through io_uring (IORING_OP_OPENAT) with raw syscalls. */
static void act_uring_open(void)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/uring-target", dir);
	make_file(path);
	begin_action("uring-open", 1);
	mput(",\"file\":");
	file_identity(path);
	struct io_uring_params p;
	memset(&p, 0, sizeof(p));
	int ring = (int)syscall(__NR_io_uring_setup, 4, &p);
	if (ring < 0) {
		mput(",\"res\":%d,\"error\":\"io_uring_setup: %s\"", -errno, strerror(errno));
		end_action();
		return;
	}
	size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	char *sq = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring,
			IORING_OFF_SQ_RING);
	char *cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring,
			IORING_OFF_CQ_RING);
	struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
					 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring,
					 IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED)
		die("mmap io_uring");
	unsigned *sq_tail = (unsigned *)(sq + p.sq_off.tail);
	unsigned *sq_mask = (unsigned *)(sq + p.sq_off.ring_mask);
	unsigned *sq_array = (unsigned *)(sq + p.sq_off.array);
	unsigned tail = *sq_tail;
	unsigned idx = tail & *sq_mask;
	struct io_uring_sqe *sqe = &sqes[idx];
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)path;
	sqe->open_flags = O_RDONLY;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
	int r = (int)syscall(__NR_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
	unsigned *cq_head = (unsigned *)(cq + p.cq_off.head);
	unsigned *cq_mask = (unsigned *)(cq + p.cq_off.ring_mask);
	struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
	int res = r < 0 ? -errno : cqes[*cq_head & *cq_mask].res;
	if (res >= 0)
		close(res);
	mput(",\"res\":%d", res);
	end_action();
	close(ring);
}

/* Three generations below wl; the last one is a daemon made by a double
 * fork with setsid. Each generation opens DIR/gen-<n> once. */
static void open_gen(int n)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/gen-%d", dir, n);
	int fd = raw_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0)
		raw_close(fd);
}

static void act_gen3(void)
{
	begin_action("gen3", 3);
	end_action();
	pid_t c = (pid_t)syscall(SYS_fork);
	if (c == 0) {
		open_gen(1);
		pid_t g = (pid_t)syscall(SYS_fork);
		if (g == 0) {
			open_gen(2);
			pid_t mid = (pid_t)syscall(SYS_fork);
			if (mid == 0) {
				setsid();
				if (syscall(SYS_fork) == 0) {
					struct timespec ts = {0, 100 * 1000 * 1000};
					nanosleep(&ts, NULL);
					open_gen(3);
					syscall(SYS_exit_group, 0);
				}
				syscall(SYS_exit_group, 0);
			}
			waitpid(mid, NULL, 0);
			syscall(SYS_exit_group, 0);
		}
		waitpid(g, NULL, 0);
		syscall(SYS_exit_group, 0);
	}
	waitpid(c, NULL, 0);
	struct timespec ts = {0, 500 * 1000 * 1000};
	nanosleep(&ts, NULL); /* let the daemon finish */
}

static void act_sleep(long ms)
{
	begin_action("sleep", ms);
	end_action();
	struct timespec ts = {ms / 1000, (ms % 1000) * 1000 * 1000};
	nanosleep(&ts, NULL);
}

/* N raw nanosleep(1 ms) syscalls, for latency measurement. */
static void act_nanosleep(long n)
{
	begin_action("nanosleep", n);
	mput(",\"nr\":%d", SYS_nanosleep);
	struct timespec ts = {0, 1000 * 1000};
	for (long i = 0; i < n; i++)
		syscall(SYS_nanosleep, &ts, NULL);
	end_action();
}

/* N children that each sleep MS, then exit; their pids go in the manifest. */
static void act_spawn_hold(long n, long ms)
{
	begin_action("spawn-hold", n);
	mput(",\"pids\":[");
	pid_t *pids = calloc((size_t)n, sizeof(pid_t));
	if (!pids)
		die("calloc");
	for (long i = 0; i < n; i++) {
		pid_t c = (pid_t)syscall(SYS_fork);
		if (c == 0) {
			struct timespec ts = {ms / 1000, (ms % 1000) * 1000 * 1000};
			nanosleep(&ts, NULL);
			syscall(SYS_exit_group, 0);
		}
		pids[i] = c;
		mput("%s%d", i ? "," : "", c);
	}
	for (long i = 0; i < n; i++)
		waitpid(pids[i], NULL, 0);
	free(pids);
	mput("]");
	end_action();
}

/* One child that spins on the CPU for MS milliseconds. */
static void act_busy(long ms)
{
	begin_action("busy", ms);
	pid_t c = (pid_t)syscall(SYS_fork);
	if (c == 0) {
		struct timespec start, now;
		clock_gettime(CLOCK_MONOTONIC, &start);
		volatile unsigned long x = 0;
		do {
			for (int i = 0; i < 100000; i++)
				x += (unsigned long)i;
			clock_gettime(CLOCK_MONOTONIC, &now);
		} while ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 < ms);
		syscall(SYS_exit_group, 0);
	}
	waitpid(c, NULL, 0);
	mput(",\"child\":%d", c);
	end_action();
}

/* One child that allocates and touches MB MiB, then holds it for MS ms. */
static void act_alloc(long mb, long ms)
{
	begin_action("alloc", mb);
	pid_t c = (pid_t)syscall(SYS_fork);
	if (c == 0) {
		size_t sz = (size_t)mb * 1024 * 1024;
		char *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			syscall(SYS_exit_group, 3);
		for (size_t i = 0; i < sz; i += 4096)
			p[i] = 1;
		struct timespec ts = {ms / 1000, (ms % 1000) * 1000 * 1000};
		nanosleep(&ts, NULL);
		syscall(SYS_exit_group, 0);
	}
	waitpid(c, NULL, 0);
	mput(",\"child\":%d,\"bytes\":%ld", c, mb * 1024 * 1024);
	end_action();
}

/* Opens PATH read-only once (tests that need a specific path). */
static void act_open_path(const char *path)
{
	begin_action("open-path", 1);
	mput(",\"path\":");
	mput_bytes(path, strlen(path));
	int fd = raw_open(path, O_RDONLY, 0);
	mput(",\"ok\":%s", fd >= 0 ? "true" : "false");
	if (fd >= 0)
		raw_close(fd);
	end_action();
}

static void act_leader_exits_first(void)
{
	begin_action("leader-exits-first", 1);
	end_action();
	mput("]}\n");
	/* The manifest must be out before the leader thread disappears. */
	if (write(1, manifest, mlen) != (ssize_t)mlen)
		die("write manifest");
	pthread_t t;
	if (pthread_create(&t, NULL, leader_follower, NULL) != 0)
		die("pthread_create");
	syscall(SYS_exit, 0); /* only the leader thread exits */
}

static void print_manifest_header(void)
{
	mput("{\"tgid\":%d,\"start_ticks\":%llu,\"dir\":", getpid(), self_start_ticks());
	mput_bytes(dir, strlen(dir));
	mput(",\"actions\":[");
}

static long need_n(int argc, char **argv, int *i)
{
	if (*i + 1 >= argc) {
		fprintf(stderr, "wl: %s needs a count\n", argv[*i]);
		exit(2);
	}
	char *end;
	long n = strtol(argv[*i + 1], &end, 10);
	if (*end || n < 0) {
		fprintf(stderr, "wl: bad count %s\n", argv[*i + 1]);
		exit(2);
	}
	(*i)++;
	return n;
}

int main(int argc, char **argv)
{
	int i = 1;
	if (argc < 3 || strcmp(argv[1], "--dir") != 0) {
		fprintf(stderr, "usage: wl --dir DIR ACTION [N] ...\n");
		return 2;
	}
	dir = argv[2];
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		die(dir);
	/* --wait-stdin: block until one byte arrives (tests start tracing first). */
	if (argc > 3 && !strcmp(argv[3], "--wait-stdin")) {
		char b;
		if (read(0, &b, 1) < 0)
			die("read stdin");
		argv++;
		argc--;
	}
	print_manifest_header();
	for (i = 3; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "exec"))
			act_exec(need_n(argc, argv, &i));
		else if (!strcmp(a, "fork"))
			act_fork(need_n(argc, argv, &i));
		else if (!strcmp(a, "open-read"))
			act_open_read(need_n(argc, argv, &i));
		else if (!strcmp(a, "open-write"))
			act_open_write(need_n(argc, argv, &i));
		else if (!strcmp(a, "rename"))
			act_rename(need_n(argc, argv, &i));
		else if (!strcmp(a, "unlink"))
			act_unlink(need_n(argc, argv, &i));
		else if (!strcmp(a, "connect-tcp"))
			connect_n("connect-tcp", AF_INET, SOCK_STREAM, need_n(argc, argv, &i), 0);
		else if (!strcmp(a, "connect-tcp6"))
			connect_n("connect-tcp6", AF_INET6, SOCK_STREAM, need_n(argc, argv, &i), 0);
		else if (!strcmp(a, "connect-fail"))
			connect_n("connect-fail", AF_INET, SOCK_STREAM, need_n(argc, argv, &i), 1);
		else if (!strcmp(a, "connect-udp"))
			connect_n("connect-udp", AF_INET, SOCK_DGRAM, need_n(argc, argv, &i), 0);
		else if (!strcmp(a, "listen"))
			act_listen(need_n(argc, argv, &i));
		else if (!strcmp(a, "threads"))
			act_threads(need_n(argc, argv, &i));
		else if (!strcmp(a, "syscalls")) {
			if (i + 2 >= argc) {
				fprintf(stderr, "wl: syscalls NAME N\n");
				return 2;
			}
			const char *name = argv[++i];
			act_syscalls(name, need_n(argc, argv, &i));
		} else if (!strcmp(a, "flood"))
			act_flood(need_n(argc, argv, &i));
		else if (!strcmp(a, "exec-self"))
			act_exec_self(); /* does not return */
		else if (!strcmp(a, "longpath"))
			act_longpath();
		else if (!strcmp(a, "badname"))
			act_badname();
		else if (!strcmp(a, "memfd-exec"))
			act_memfd_exec();
		else if (!strcmp(a, "--"))
			break; /* the rest only shows up in argv (tests) */
		else if (!strcmp(a, "open-path")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "wl: open-path needs a path\n");
				return 2;
			}
			act_open_path(argv[++i]);
		} else if (!strcmp(a, "spawn-hold")) {
			long n = need_n(argc, argv, &i);
			act_spawn_hold(n, need_n(argc, argv, &i));
		} else if (!strcmp(a, "busy"))
			act_busy(need_n(argc, argv, &i));
		else if (!strcmp(a, "alloc")) {
			long mb = need_n(argc, argv, &i);
			act_alloc(mb, need_n(argc, argv, &i));
		} else if (!strcmp(a, "gen3"))
			act_gen3();
		else if (!strcmp(a, "sleep"))
			act_sleep(need_n(argc, argv, &i));
		else if (!strcmp(a, "nanosleep"))
			act_nanosleep(need_n(argc, argv, &i));
		else if (!strcmp(a, "open-relative"))
			act_open_relative();
		else if (!strcmp(a, "open-symlink"))
			act_open_symlink();
		else if (!strcmp(a, "uring-open"))
			act_uring_open();
		else if (!strcmp(a, "leader-exits-first"))
			act_leader_exits_first(); /* does not return */
		else {
			fprintf(stderr, "wl: unknown action %s\n", a);
			return 2;
		}
	}
	mput("]}\n");
	if (write(1, manifest, mlen) != (ssize_t)mlen)
		die("write manifest");
	return 0;
}
