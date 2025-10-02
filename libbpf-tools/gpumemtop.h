/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __GPUMEMTOP_H
#define __GPUMEMTOP_H

#define TASK_COMM_LEN 16

struct gpu_mem_total_key {
	__u32 gpu_id;
	__u32 pid;
};

#endif /* __GPUMEMTOP_H */
