/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LOADAVG_H
#define __LOADAVG_H

#define TASK_COMM_LEN 16
#define MAX_CPU_NR 4

struct task_t {
	__u32 tgid;
	__u32 pid;
	__u32 on_cpu;
	__u32 policy;
};

struct nr_running_t {
	__u64 duration;
	char name[TASK_COMM_LEN];
	/* extended info */
	__u32 sum_nr_running[MAX_CPU_NR];
	__u32 max_nr_running[MAX_CPU_NR];
	__u32 min_nr_running[MAX_CPU_NR];
	__u32 nr_running[MAX_CPU_NR];
	__u32 count[MAX_CPU_NR];
	__u32 total_max_rq;
	__u32 tgid;
	__u32 policy;
};

struct cpu_stat_t {
	__u64 oncpu_duration;
	__u64 offcpu_duration;
	/* extended info */
	__u32 sum_nr_running;
	__u32 max_nr_running;
	__u32 min_nr_running;
	__u32 count;
};

struct task_info_t {
	__u32 pid;
	__u32 tgid;
	__u32 policy;
};

#endif /* __LOADAVG_H */
