#include "setpid.h"

typedef struct {
    pid_t pid; 
} __attribute__ ((packed)) pid_info;

void set_pid(){
    int fd;
    pid_info inf;
    inf.pid = getpid();
    printf("current pid: %d\n", inf.pid);
    if ((fd = open("/dev/kasan0", O_RDWR)) < 0){
        printf("Cannot open /dev/kasan0. Try again later.\n");
    }

    if (ioctl(fd, SET_PID, &inf) < 0){
        printf("Error : SET_PID.\n");
    }

    if (close(fd) != 0){
        printf("Cannot close.\n");
    }
}
