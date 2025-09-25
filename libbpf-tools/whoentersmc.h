/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __WHOENTERSMC_H
#define __WHOENTERSMC_H

#define TASK_COMM_LEN 16

struct candidate_table {
	__u32 tee_world;
	__u32 pid;
	__u32 tgid;
	__u64 ts;
	char comm[TASK_COMM_LEN];
};

struct optee_val_t {
	__u32 timeLow;
	__u16 timeMid;
	__u16 timeHiAndVersion;
	__u32 session;
	__u32 func;
};

#endif /* __WHOENTERSMC_H */
