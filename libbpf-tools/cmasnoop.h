/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CMASNOOP_H
#define __CMASNOOP_H

#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u32 tgid;
	__u64 count;
	__u32 align;
	__u32 fail;
	__u32 pfn;
	__u64 duration;
	__u32 alloc;
	__s64 total_sz;
	char comm[TASK_COMM_LEN];
};

#endif /* __CMASNOOP_H */
