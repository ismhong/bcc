/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PAGEOWNER_H
#define __PAGEOWNER_H

#define TASK_COMM_LEN 16

struct data_t {
	int migratetype;
	__u64 size;
	__s64 stack_id;
	__u32 pid;
	__u32 tgid;
	char comm[TASK_COMM_LEN];
	__u32 gfp_flags;
};

#endif /* __PAGEOWNER_H */
