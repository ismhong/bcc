/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FORKSNOOP_H
#define __FORKSNOOP_H

#define TASK_COMM_LEN 16
#define ARGSIZE 128
#define MAX_ARGS 20

#define INVALID_PID (-1)

enum event_type {
	EVENT_FORK = 0,
	EVENT_EXIT,
	EVENT_EXEC,
	EVENT_RENAME,
};

struct event {
	/* common */
	enum event_type type;
	pid_t pid;
	pid_t tid;
	pid_t ppid;
	__u64 duration_ns;
	int retval;
	char comm[TASK_COMM_LEN];

	/* fork */
	pid_t child_pid;
	pid_t child_tid;
	char child_comm[TASK_COMM_LEN];

	/* rename */
	char newcomm[TASK_COMM_LEN];

	/* exec */
	int args_count;
	unsigned int args_size;
	char args[ARGSIZE * MAX_ARGS];
};

struct task_info {
	__u32 ppid;
	__u32 pid;
	__u32 tid;
};

struct event_count {
	__u64 duration;
	__u32 fork;
	__u32 exit;
	__u32 execute;
	__u32 rename;
	__u32 total;
	char comm[TASK_COMM_LEN];
	char newname[TASK_COMM_LEN];
};

#endif /* __FORKSNOOP_H */