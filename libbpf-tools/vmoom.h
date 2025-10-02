// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __VMOOM_H
#define __VMOOM_H

#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u32 tgid;
	__u64 flags;
	__u64 length;
	__u64 low_limit;
	__u64 high_limit;
	__u64 align_mask;
	__u64 align_offset;
	char comm[TASK_COMM_LEN];
};

#endif /* __VMOOM_H */
