/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * rtkheaptop: Analysis rtkheap allocation as a table.
 *
 * Copyright (c) 2025 Realtek, Inc.
 */
#ifndef __RTKHEPTOP_H
#define __RTKHEPTOP_H

#define HEAP_MAX_NAME 64
#define TASK_COMM_LEN 16

struct use_heap {
	__u32 tgid;
	__u32 pid;
	unsigned long flags;
	char name[HEAP_MAX_NAME];
	char comm[TASK_COMM_LEN];
	char caller[TASK_COMM_LEN];
};

struct heap_info {
	__u64 size;
	__u32 max_alloc_latency;
	__u32 success;
	__u32 fail;
};

struct alloc_info {
	__u64 ts;
	unsigned long flags;
	char name[HEAP_MAX_NAME];
	char caller[TASK_COMM_LEN];
	size_t size;
};

#endif /* __RTKHEPTOP_H */
