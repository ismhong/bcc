#ifndef __SCHEDBLOCKEDTOP_H
#define __SCHEDBLOCKEDTOP_H

#define TASK_COMM_LEN 16

struct key_t {
	__u64 caller;
	char comm[TASK_COMM_LEN];
	__u32 pid;
	__u8 io_wait;
};

struct val_t {
	__u64 total_latency;
	__u64 count;
	__u64 max_latency;
	__u64 min_latency;
};

#endif /* __SCHEDBLOCKEDTOP_H */
