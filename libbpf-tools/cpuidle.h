#ifndef __CPUIDLE_H
#define __CPUIDLE_H

#define MAX_CPU_NR 256
#define MAX_IDLE_STATE_NR 16

struct idle_t {
	__u64 latency_sum;
	__u64 error_times;
	__u64 count;
};

static struct env {
	float interval;
	float duration;
	int table;
	int dump_overlap;
	int least;
	int histogram;
	int clear;
	__u32 core_mask;
	__u32 state_mask;
	int microseconds;
	int milliseconds;
	int verbose;
} env = {
	.interval = -1,
	.duration = -1,
	.least = 1,
	.core_mask = 0,
	.state_mask = 0,
};

#endif /* __CPUIDLE_H */
