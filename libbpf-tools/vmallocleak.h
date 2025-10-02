#ifndef __VMALLOCLEAK_H
#define __VMALLOCLEAK_H

#define TASK_COMM_LEN 16

struct key_t {
	__u32 tgid;
	__u32 pid;
	__u64 stack_id;
};

struct val_t {
	char name[TASK_COMM_LEN];
	__u64 size;
};

#endif /* __VMALLOCLEAK_H */
