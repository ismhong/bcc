/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CMATRACK_H
#define __CMATRACK_H

#define TASK_COMM_LEN 16
#define MAX_PATHBUF_LEN 128

struct event {
	__u32 pid;
	__u32 tgid;
	char comm[TASK_COMM_LEN];
	int fail;
	__u32 migrate_succeeded;
	__u32 migrate_failed;
	bool range_mode;
	union {
		struct {
			unsigned long count;
			unsigned long start_pfn;
			unsigned long end_pfn;
		} range;
		struct {
			unsigned long count;
			unsigned int align;
			__u64 duration_ns;
		} alloc;
	};
};

struct file_key_t {
	__u32 ino;
};

struct file_name_t {
	char name[MAX_PATHBUF_LEN];
};

struct pid_ino_file_key_t {
	__u32 pid;
	__u32 ino;
};

struct pid_ino_file_name_t {
	__u32 polling_times;
	char name[MAX_PATHBUF_LEN];
};

#endif /* __CMATRACK_H */
