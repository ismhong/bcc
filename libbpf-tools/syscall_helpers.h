#ifndef __SYSCALL_HELPERS_H
#define __SYSCALL_HELPERS_H

#include <sys/types.h>

void init_syscall_names(void);
void free_syscall_names(void);
int syscall_name(unsigned n, char *buf, size_t size);
int list_syscalls(void);
void set_arm32_syscall_table(void);

#endif
