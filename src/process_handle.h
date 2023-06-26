#ifndef __BOKASAN_PROCESS_HANDLE__
#define __BOKASAN_PROCESS_HANDLE__

#include <linux/kernel.h>
#include <linux/module.h>

#define PID_MAX 262144

void add_pid(int pid);
void remove_pid(int pid);
bool is_pid_present(int pid);
bool is_current_pid_present(void);

#endif