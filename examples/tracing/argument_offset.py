#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from time import sleep
import os

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.prev_pid = prev->pid;

    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    bpf_trace_printk("argument key pid %d\\n");
    if (val) {
        (*val)++;
    }
    return 0;
}
"""

b = BPF(text=prog, debug=0x4)
b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

# generate many schedule events
for i in range(0, 10): sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d <-> %5d]=%u" % (k.prev_pid, os.getpid(), v.value))
