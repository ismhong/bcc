/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * poweralloc: Analyze power allocation as a table.
 *
 * Copyright (c) 2024 Realtek, Inc.
 */
#ifndef __POWERALLOC_H
#define __POWERALLOC_H

#define MAX_DEVICE_NAME 64
#define MAX_DEVICES     64
#define MAX_CPUS        16  /* compile-time upper bound; runtime uses cpu_num */

struct device_key {
	char name[MAX_DEVICE_NAME];
};

struct value_t {
	__u64 req;
	__u64 granted;
	__u64 count;
	/* detail fields */
	__u64 load;
	__u64 freq;
	__u64 state;
};

struct thermal_t {
	__u64 acc;
	__u64 count;
};

#endif /* __POWERALLOC_H */
