#ifndef __RPCTOP_H
#define __RPCTOP_H

#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u32 tgid;
	__u32 programID;
	__u32 versionID;
	__u32 procedureID;
	__u32 taskID;
	__u32 parameterSize;
	__u32 mycontext;
	__u64 refclk;
	__s32 rpc_num;
	__u64 delta;
	char comm[TASK_COMM_LEN];
};

#endif /* __RPCTOP_H */
