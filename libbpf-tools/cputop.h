#ifndef __CPUTOP_H
#define __CPUTOP_H

#define TASK_COMM_LEN 16

/* Used in tsk->state: */
#define TASK_RUNNING                   0x0000
#define TASK_INTERRUPTIBLE             0x0001
#define TASK_UNINTERRUPTIBLE           0x0002
#define __TASK_STOPPED                 0x0004
#define __TASK_TRACED                  0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD                      0x0010
#define EXIT_ZOMBIE                    0x0020
#define EXIT_TRACE                     (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED                    0x0040
#define TASK_DEAD                      0x0080
#define TASK_WAKEKILL                  0x0100
#define TASK_WAKING                    0x0200
#define TASK_NOLOAD                    0x0400
#define TASK_NEW                       0x0800
/* RT specific auxilliary flag to mark RT lock waiters */
#define TASK_RTLOCK_WAIT               0x1000
#define TASK_STATE_MAX                 0x2000

/* Convenience macros for the sake of set_current_state: */
#define TASK_KILLABLE                  (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED                   (TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED                    (TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE                      (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up(): */
#define TASK_NORMAL                    (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)

/* get_task_state(): */
#define TASK_REPORT                    (TASK_RUNNING | TASK_INTERRUPTIBLE | \
                                        TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
                                        __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
                                        TASK_PARKED)

#define TASK_REPORT_IDLE               (TASK_REPORT + 1)
#define TASK_REPORT_MAX                (TASK_REPORT_IDLE << 1)

struct info_t {
	__u64 duration;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 preempts;
};

struct pid_key_t {
	__u32 cpuid;
	__u32 pid;
	unsigned int policy;
	int prio;
};

struct pid_info_t {
	__u64 tgid;
	char comm[TASK_COMM_LEN];
	struct info_t info;
};

struct name_key_t {
	__u32 cpuid;
	unsigned int policy;
	int prio;
	char comm[TASK_COMM_LEN];
};

#endif /* __CPUTOP_H */
