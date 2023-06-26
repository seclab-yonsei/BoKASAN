// autogenerated by syzkaller (https://github.com/google/syzkaller)

#define _GNU_SOURCE 
#include "../../set_pid.h"

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/loop.h>

static unsigned long long procid;

static __thread int skip_segv;
static __thread jmp_buf segv_env;

static void segv_handler(int sig, siginfo_t* info, void* ctx)
{
	uintptr_t addr = (uintptr_t)info->si_addr;
	const uintptr_t prog_start = 1 << 20;
	const uintptr_t prog_end = 100 << 20;
	int skip = __atomic_load_n(&skip_segv, __ATOMIC_RELAXED) != 0;
	int valid = addr < prog_start || addr > prog_end;
	if (skip && valid) {
		_longjmp(segv_env, 1);
	}
	exit(sig);
}

static void install_segv_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall(SYS_rt_sigaction, 0x20, &sa, NULL, 8);
	syscall(SYS_rt_sigaction, 0x21, &sa, NULL, 8);
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

#define NONFAILING(...) ({ int ok = 1; __atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); if (_setjmp(segv_env) == 0) { __VA_ARGS__; } else ok = 0; __atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); ok; })

static void sleep_ms(uint64_t ms)
{
	usleep(ms * 1000);
}

static uint64_t current_time_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
	exit(1);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void thread_start(void* (*fn)(void*), void* arg)
{
	pthread_t th;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 << 10);
	int i = 0;
	for (; i < 100; i++) {
		if (pthread_create(&th, &attr, fn, arg) == 0) {
			pthread_attr_destroy(&attr);
			return;
		}
		if (errno == EAGAIN) {
			usleep(50);
			continue;
		}
		break;
	}
	exit(1);
}

#define BITMASK(bf_off,bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type,htobe,addr,val,bf_off,bf_len) *(type*)(addr) = htobe((htobe(*(type*)(addr)) & ~BITMASK((bf_off), (bf_len))) | (((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))

typedef struct {
	int state;
} event_t;

static void event_init(event_t* ev)
{
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	if (ev->state)
	exit(1);
	__atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &ev->state, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1000000);
}

static void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0);
}

static int event_isset(event_t* ev)
{
	return __atomic_load_n(&ev->state, __ATOMIC_ACQUIRE);
}

static int event_timedwait(event_t* ev, uint64_t timeout)
{
	uint64_t start = current_time_ms();
	uint64_t now = start;
	for (;;) {
		uint64_t remain = timeout - (now - start);
		struct timespec ts;
		ts.tv_sec = remain / 1000;
		ts.tv_nsec = (remain % 1000) * 1000 * 1000;
		syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts);
		if (__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
			return 1;
		now = current_time_ms();
		if (now - start > timeout)
			return 0;
	}
}

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		int err = errno;
		close(fd);
		errno = err;
		return false;
	}
	close(fd);
	return true;
}

#define MAX_FDS 30

static long syz_open_dev(volatile long a0, volatile long a1, volatile long a2)
{
	if (a0 == 0xc || a0 == 0xb) {
		char buf[128];
		sprintf(buf, "/dev/%s/%d:%d", a0 == 0xc ? "char" : "block", (uint8_t)a1, (uint8_t)a2);
		return open(buf, O_RDWR, 0);
	} else {
		char buf[1024];
		char* hash;
		strncpy(buf, (char*)a0, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = 0;
		while ((hash = strchr(buf, '#'))) {
			*hash = '0' + (char)(a1 % 10);
			a1 /= 10;
		}
		return open(buf, a2, 0);
	}
}

struct fs_image_segment {
	void* data;
	uintptr_t size;
	uintptr_t offset;
};

#define IMAGE_MAX_SEGMENTS 4096
#define IMAGE_MAX_SIZE (129 << 20)

#define sys_memfd_create 319

static unsigned long fs_image_segment_check(unsigned long size, unsigned long nsegs, struct fs_image_segment* segs)
{
	if (nsegs > IMAGE_MAX_SEGMENTS)
		nsegs = IMAGE_MAX_SEGMENTS;
	for (size_t i = 0; i < nsegs; i++) {
		if (segs[i].size > IMAGE_MAX_SIZE)
			segs[i].size = IMAGE_MAX_SIZE;
		segs[i].offset %= IMAGE_MAX_SIZE;
		if (segs[i].offset > IMAGE_MAX_SIZE - segs[i].size)
			segs[i].offset = IMAGE_MAX_SIZE - segs[i].size;
		if (size < segs[i].offset + segs[i].offset)
			size = segs[i].offset + segs[i].offset;
	}
	if (size > IMAGE_MAX_SIZE)
		size = IMAGE_MAX_SIZE;
	return size;
}
static int setup_loop_device(long unsigned size, long unsigned nsegs, struct fs_image_segment* segs, const char* loopname, int* memfd_p, int* loopfd_p)
{
	int err = 0, loopfd = -1;
	size = fs_image_segment_check(size, nsegs, segs);
	int memfd = syscall(sys_memfd_create, "syzkaller", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (ftruncate(memfd, size)) {
		err = errno;
		goto error_close_memfd;
	}
	for (size_t i = 0; i < nsegs; i++) {
		if (pwrite(memfd, segs[i].data, segs[i].size, segs[i].offset) < 0) {
		}
	}
	loopfd = open(loopname, O_RDWR);
	if (loopfd == -1) {
		err = errno;
		goto error_close_memfd;
	}
	if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
		if (errno != EBUSY) {
			err = errno;
			goto error_close_loop;
		}
		ioctl(loopfd, LOOP_CLR_FD, 0);
		usleep(1000);
		if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
			err = errno;
			goto error_close_loop;
		}
	}
	*memfd_p = memfd;
	*loopfd_p = loopfd;
	return 0;

error_close_loop:
	close(loopfd);
error_close_memfd:
	close(memfd);
error:
	errno = err;
	return -1;
}

static long syz_mount_image(volatile long fsarg, volatile long dir, volatile unsigned long size, volatile unsigned long nsegs, volatile long segments, volatile long flags, volatile long optsarg)
{
	struct fs_image_segment* segs = (struct fs_image_segment*)segments;
	int res = -1, err = 0, loopfd = -1, memfd = -1, need_loop_device = !!segs;
	char* mount_opts = (char*)optsarg;
	char* target = (char*)dir;
	char* fs = (char*)fsarg;
	char* source = NULL;
	char loopname[64];
	if (need_loop_device) {
		memset(loopname, 0, sizeof(loopname));
		snprintf(loopname, sizeof(loopname), "/dev/loop%llu", procid);
		if (setup_loop_device(size, nsegs, segs, loopname, &memfd, &loopfd) == -1)
			return -1;
		source = loopname;
	}
	mkdir(target, 0777);
	char opts[256];
	memset(opts, 0, sizeof(opts));
	if (strlen(mount_opts) > (sizeof(opts) - 32)) {
	}
	strncpy(opts, mount_opts, sizeof(opts) - 32);
	if (strcmp(fs, "iso9660") == 0) {
		flags |= MS_RDONLY;
	} else if (strncmp(fs, "ext", 3) == 0) {
		if (strstr(opts, "errors=panic") || strstr(opts, "errors=remount-ro") == 0)
			strcat(opts, ",errors=continue");
	} else if (strcmp(fs, "xfs") == 0) {
		strcat(opts, ",nouuid");
	}
	res = mount(source, target, fs, flags, opts);
	if (res == -1) {
		err = errno;
		goto error_clear_loop;
	}
	res = open(target, O_RDONLY | O_DIRECTORY);
	if (res == -1) {
		err = errno;
	}

error_clear_loop:
	if (need_loop_device) {
		ioctl(loopfd, LOOP_CLR_FD, 0);
		close(loopfd);
		close(memfd);
	}
	errno = err;
	return res;
}

static void setup_common()
{
	if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
	}
}

static void loop();

static void sandbox_common()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setsid();
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = (200 << 20);
	setrlimit(RLIMIT_AS, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 32 << 20;
	setrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 136 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 256;
	setrlimit(RLIMIT_NOFILE, &rlim);
	if (unshare(CLONE_NEWNS)) {
	}
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
	}
	if (unshare(CLONE_NEWIPC)) {
	}
	if (unshare(0x02000000)) {
	}
	if (unshare(CLONE_NEWUTS)) {
	}
	if (unshare(CLONE_SYSVSEM)) {
	}
	typedef struct {
		const char* name;
		const char* value;
	} sysctl_t;
	static const sysctl_t sysctls[] = {
	    {"/proc/sys/kernel/shmmax", "16777216"},
	    {"/proc/sys/kernel/shmall", "536870912"},
	    {"/proc/sys/kernel/shmmni", "1024"},
	    {"/proc/sys/kernel/msgmax", "8192"},
	    {"/proc/sys/kernel/msgmni", "1024"},
	    {"/proc/sys/kernel/msgmnb", "1024"},
	    {"/proc/sys/kernel/sem", "1024 1048576 500 1024"},
	};
	unsigned i;
	for (i = 0; i < sizeof(sysctls) / sizeof(sysctls[0]); i++)
		write_file(sysctls[i].name, sysctls[i].value);
}

static int wait_for_loop(int pid)
{
	if (pid < 0)
	exit(1);
	int status = 0;
	while (waitpid(-1, &status, __WALL) != pid) {
	}
	return WEXITSTATUS(status);
}

static void drop_caps(void)
{
	struct __user_cap_header_struct cap_hdr = {};
	struct __user_cap_data_struct cap_data[2] = {};
	cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
	cap_hdr.pid = getpid();
	if (syscall(SYS_capget, &cap_hdr, &cap_data))
	exit(1);
	const int drop = (1 << CAP_SYS_PTRACE) | (1 << CAP_SYS_NICE);
	cap_data[0].effective &= ~drop;
	cap_data[0].permitted &= ~drop;
	cap_data[0].inheritable &= ~drop;
	if (syscall(SYS_capset, &cap_hdr, &cap_data))
	exit(1);
}

static int do_sandbox_none(void)
{
	if (unshare(CLONE_NEWPID)) {
	}
	int pid = fork();
	if (pid != 0)
		return wait_for_loop(pid);
	setup_common();
	sandbox_common();
	drop_caps();
	if (unshare(CLONE_NEWNET)) {
	}
	loop();
	exit(1);
}

static void kill_and_wait(int pid, int* status)
{
	kill(-pid, SIGKILL);
	kill(pid, SIGKILL);
	for (int i = 0; i < 100; i++) {
		if (waitpid(-1, status, WNOHANG | __WALL) == pid)
			return;
		usleep(1000);
	}
	DIR* dir = opendir("/sys/fs/fuse/connections");
	if (dir) {
		for (;;) {
			struct dirent* ent = readdir(dir);
			if (!ent)
				break;
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;
			char abort[300];
			snprintf(abort, sizeof(abort), "/sys/fs/fuse/connections/%s/abort", ent->d_name);
			int fd = open(abort, O_WRONLY);
			if (fd == -1) {
				continue;
			}
			if (write(fd, abort, 1) < 0) {
			}
			close(fd);
		}
		closedir(dir);
	} else {
	}
	while (waitpid(-1, status, __WALL) != pid) {
	}
}

static void reset_loop()
{
	char buf[64];
	snprintf(buf, sizeof(buf), "/dev/loop%llu", procid);
	int loopfd = open(buf, O_RDWR);
	if (loopfd != -1) {
		ioctl(loopfd, LOOP_CLR_FD, 0);
		close(loopfd);
	}
}

static void setup_test()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
	write_file("/proc/self/oom_score_adj", "1000");
}

static void close_fds()
{
	for (int fd = 3; fd < MAX_FDS; fd++)
		close(fd);
}

struct thread_t {
	int created, call;
	event_t ready, done;
};

static struct thread_t threads[16];
static void execute_call(int call);
static int running;

static void* thr(void* arg)
{
	struct thread_t* th = (struct thread_t*)arg;
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		execute_call(th->call);
		__atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
		event_set(&th->done);
	}
	return 0;
}

static void execute_one(void)
{
	int i, call, thread;
	for (call = 0; call < 9; call++) {
		for (thread = 0; thread < (int)(sizeof(threads) / sizeof(threads[0])); thread++) {
			struct thread_t* th = &threads[thread];
			if (!th->created) {
				th->created = 1;
				event_init(&th->ready);
				event_init(&th->done);
				event_set(&th->done);
				thread_start(thr, th);
			}
			if (!event_isset(&th->done))
				continue;
			event_reset(&th->done);
			th->call = call;
			__atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
			event_set(&th->ready);
			event_timedwait(&th->done, 50 + (call == 0 ? 50 : 0));
			break;
		}
	}
	for (i = 0; i < 100 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
		sleep_ms(1);
	close_fds();
}

static void execute_one(void);

#define WAIT_FLAGS __WALL

static void loop(void)
{
	int iter = 0;
	for (;; iter++) {
		reset_loop();
		int pid = fork();
		if (pid < 0)
	exit(1);
		if (pid == 0) {
			setup_test();
			execute_one();
			exit(0);
		}
		int status = 0;
		uint64_t start = current_time_ms();
		for (;;) {
			if (waitpid(-1, &status, WNOHANG | WAIT_FLAGS) == pid)
				break;
			sleep_ms(1);
		if (current_time_ms() - start < 5000) {
			continue;
		}
			kill_and_wait(pid, &status);
			break;
		}
	}
}

uint64_t r[2] = {0xffffffffffffffff, 0xffffffffffffffff};

void execute_call(int call)
{
		intptr_t res = 0;
	switch (call) {
	case 0:
		NONFAILING(syz_mount_image(0, 0, 0, 0, 0, 0, 0));
		break;
	case 1:
		NONFAILING(*(uint32_t*)0x200000c0 = 2);
		NONFAILING(*(uint32_t*)0x200000c4 = 0x70);
		NONFAILING(*(uint8_t*)0x200000c8 = 1);
		NONFAILING(*(uint8_t*)0x200000c9 = 0);
		NONFAILING(*(uint8_t*)0x200000ca = 0);
		NONFAILING(*(uint8_t*)0x200000cb = 0);
		NONFAILING(*(uint32_t*)0x200000cc = 0);
		NONFAILING(*(uint64_t*)0x200000d0 = 0);
		NONFAILING(*(uint64_t*)0x200000d8 = 0);
		NONFAILING(*(uint64_t*)0x200000e0 = 0);
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 0, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 1, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 2, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 3, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 4, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 5, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 6, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 7, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 8, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 9, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 10, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 11, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 12, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 13, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 14, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 15, 2));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 17, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 18, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 19, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 20, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 21, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 22, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 23, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 24, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 25, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 26, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 27, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 28, 1));
		NONFAILING(STORE_BY_BITMASK(uint64_t, , 0x200000e8, 0, 29, 35));
		NONFAILING(*(uint32_t*)0x200000f0 = 0);
		NONFAILING(*(uint32_t*)0x200000f4 = 0);
		NONFAILING(*(uint64_t*)0x200000f8 = 0);
		NONFAILING(*(uint64_t*)0x20000100 = 0);
		NONFAILING(*(uint64_t*)0x20000108 = 0);
		NONFAILING(*(uint64_t*)0x20000110 = 0);
		NONFAILING(*(uint32_t*)0x20000118 = 0);
		NONFAILING(*(uint32_t*)0x2000011c = 0);
		NONFAILING(*(uint64_t*)0x20000120 = 0);
		NONFAILING(*(uint32_t*)0x20000128 = 0);
		NONFAILING(*(uint16_t*)0x2000012c = 0);
		NONFAILING(*(uint16_t*)0x2000012e = 0);
		syscall(__NR_perf_event_open, 0x200000c0ul, 0, 0ul, -1, 0ul);
		break;
	case 2:
		syscall(__NR_fork);
		break;
	case 3:
		syscall(__NR_getuid);
		break;
	case 4:
		NONFAILING(syz_open_dev(0xc, 4, 0x14));
		break;
	case 5:
		res = -1;
		NONFAILING(res = syz_open_dev(0xc, 4, 1));
		if (res != -1)
				r[0] = res;
		break;
	case 6:
		res = syscall(__NR_dup2, r[0], r[0]);
		if (res != -1)
				r[1] = res;
		break;
	case 7:
		NONFAILING(*(uint32_t*)0x20000080 = 1);
		NONFAILING(*(uint32_t*)0x20000084 = 0);
		NONFAILING(*(uint32_t*)0x20000088 = 0);
		NONFAILING(*(uint32_t*)0x2000008c = 0);
		NONFAILING(*(uint32_t*)0x20000090 = 0);
		NONFAILING(*(uint64_t*)0x20000098 = 0x20000140);
		syscall(__NR_ioctl, r[1], 0x4b72, 0x20000080ul);
		break;
	case 8:
		syscall(__NR_ioctl, r[1], 0x5608, 0);
		break;
	}

}
int main(void)
{
set_pid();
		syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
	syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
	syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
	install_segv_handler();
			do_sandbox_none();
	return 0;
}
