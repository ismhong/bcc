/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PAGEALLOCTOP_H
#define __PAGEALLOCTOP_H

#define TASK_COMM_LEN 16

struct page_alloc_stat {
	__u32 tgid;
	__u64 movable_size;
	__u64 unmovable_size;
	char comm[TASK_COMM_LEN];
};

#endif /* __PAGEALLOCTOP_H */