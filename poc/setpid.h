#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#define             IOCTL_MAGIC         'K'
#define             SET_PID            _IO(IOCTL_MAGIC, 0)

void set_pid();
