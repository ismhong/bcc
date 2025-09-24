#ifndef __MMCTOP_H
#define __MMCTOP_H

#define TASK_COMM_LEN 16

struct config {
    _Bool per_pid;
    _Bool per_blocks;
    _Bool per_cmd_arg;
    __s32 filter_cmd;
    __u32 min_blocks;
    __s32 max_blocks;
};

struct mmc_key {
    __u32 pid;
    __u32 tid;
    __u32 cmd;
    __u32 blksz;
    __u32 blocks;
    __u32 cmd_arg;
    __u32 cmd_flags;
    __u32 data_flags;
    __u64 ts;
    char name[TASK_COMM_LEN];
};

struct mmc_value {
    __u32 blocks;
    __u64 delay;
    __u64 max;
    __u64 min;
    __u32 io;
};

#endif /* __MMCTOP_H */
