// autogenerated by syzkaller (https://github.com/google/syzkaller)

#define _GNU_SOURCE 

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

static void setup_test()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
	write_file("/proc/self/oom_score_adj", "1000");
}

static void execute_one(void);

#define WAIT_FLAGS __WALL

static void loop(void)
{
	int iter = 0;
	for (;; iter++) {
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

void execute_one(void)
{
		intptr_t res = 0;
	res = -1;
res = syz_open_dev(0xc, 4, 1);
	if (res != -1)
		r[0] = res;
*(uint16_t*)0x20001100 = 9;
*(uint16_t*)0x20001102 = 0x594c;
*(uint16_t*)0x20001104 = 0x1ff;
	syscall(__NR_ioctl, r[0], 0x5609, 0x20001100ul);
	res = -1;
res = syz_open_dev(0xc, 4, 1);
	if (res != -1)
		r[1] = res;
*(uint64_t*)0x20002300 = 0x20000080;
memcpy((void*)0x20000080, "\x1b\x4c\xa5\xf4\x65\x0d\xe0\x50\x84\x34\xd6\x58\x3a\x98\x0a\x88\xda\x24\xdd\x24\xf9\xc3\xa1\xe1\x3d\x16\xc5\xf0\xea\x7f\x84\x96\x37\x13\x66\x4f\x8a\xc2\x0a\xb0\x41\x04\x89\x4a\xc2\x61\x01\x46\xc9\x65\x37\xc4\x37\x5a\xc3\x03\x6e\x18\x62\x64\x05\x7a\xdc\x35\x31\x77\x26\xec\x53\x77\x24\xee\x96\x8f\xb7\x30\xd4\xd2\x8d\x00\xd7\x09\xd9\x54\x60\xfa\x22\x47\x77\xe8\x0f\x4e\xfb\x04\x2f\x4e\xe0\xcd\xbc\x21\x0e\xc0\x7a\x1f\xab\x7a\xaa\xbd\xe1\xcd\x9b\x53\xb4\xb3\x24\x76\x9c\x7a\x4c\x86\xab\xe9\x71\x4f\x4e\xb1\x52\xf5\x58\xd7\xc7\x4a\x19\x86\x82\xff\xbd\x78\xe2\xfb\xec\xd6\x9d\x0b\x8d\x81\x0a\xf0\x53\x4b\xef\x29\x30\x41\xe4\x68\x43\x76\x55\xe8\x3a\x80\x6b\x9f\xa9\x46\x46\xa6\x98\x1c\xf9\x0e\x44\xce\xc3\xc6\xc2\xcc\x7d\x2e\x87\xf3\x43\x4f\x1a\xe2\x06\x63\x36\xd6\xa4", 191);
*(uint64_t*)0x20002308 = 0xbf;
*(uint64_t*)0x20002310 = 0;
*(uint64_t*)0x20002318 = 0;
*(uint64_t*)0x20002320 = 0;
*(uint64_t*)0x20002328 = 0;
*(uint64_t*)0x20002330 = 0;
*(uint64_t*)0x20002338 = 0;
*(uint64_t*)0x20002340 = 0;
*(uint64_t*)0x20002348 = 0;
*(uint64_t*)0x20002350 = 0;
*(uint64_t*)0x20002358 = 0;
	syscall(__NR_writev, r[1], 0x20002300ul, 6ul);

}
int main(void)
{
		syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
	syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
	syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
			loop();
	return 0;
}
