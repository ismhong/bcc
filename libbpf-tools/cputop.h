#ifndef __CPUTOP_H
#define __CPUTOP_H

#define TASK_COMM_LEN 16

struct info_t {
	__u64 duration;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 preempts;
};

struct pid_key_t {
	__u32 cpuid;
	__u32 pid;
	unsigned int policy;
	int prio;
};

struct pid_info_t {
	__u64 tgid;
	char comm[TASK_COMM_LEN];
	struct info_t info;
};

struct name_key_t {
	__u32 cpuid;
	unsigned int policy;
	int prio;
	char comm[TASK_COMM_LEN];
};

#endif /* __CPUTOP_H */