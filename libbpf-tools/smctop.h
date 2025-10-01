#ifndef __SMCTOP_H
#define __SMCTOP_H

#define TASK_COMM_LEN 16
#define MAX_CPU_NUM 16

struct session_uuid_t {
	__u32 timeLow;
	__u16 timeMid;
	__u16 timeHiAndVersion;
};

struct optee_latency_key_t {
	__u32 tgid;
	__u32 pid;
	char name[TASK_COMM_LEN];
	__u32 timeLow;
	__u16 timeMid;
	__u16 timeHiAndVersion;
	__u32 session;
	__u32 func;
};

struct latency_val_t {
	__u64 total_latency;
	__u64 total_count;
	__u64 max;
	__u64 min;
	__u64 isr_total_latency;
	__u64 isr_total_count;
	__u64 isr_max;
	__u64 schedout_total_latency;
	__u64 schedout_total_count;
	__u64 schedout_max;
};

#endif /* __SMCTOP_H */