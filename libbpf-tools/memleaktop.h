// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __MEMLEAKTOP_H
#define __MEMLEAKTOP_H

#define TASK_COMM_LEN 16

struct key_t {
	__u32 tgid;
	__u32 pid;
	__u64 sz;
	char name[TASK_COMM_LEN];
};

struct size_count {
	__u64 size;
	__u64 count;
};

#endif /* __MEMLEAKTOP_H */
