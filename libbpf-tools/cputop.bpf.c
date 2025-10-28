// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cputop.h"

#define MAX_ENTRIES 10240
#define MAX_PID 262144 // Corresponds to a high pid_max

#ifndef MAX_RT_PRIO
#define MAX_RT_PRIO 100
#endif

#define TASK_RUNNING 0
#define TASK_STATE_MAX 1024
#define PREEMPT_ON (TASK_RUNNING | TASK_STATE_MAX)

#define SM_PREEMPT		0x1

#ifndef CONFIG_PREEMPT_RT
# define SM_MASK_PREEMPT	(~0U)
#else
# define SM_MASK_PREEMPT	SM_PREEMPT
#endif

struct task_sched_in {
	u64 ts;
	u32 preempt;
};

struct task_state {
    u64 value;
    unsigned int sched_mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PID);
	__type(key, u32);
	__type(value, struct task_state);
} enter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PID);
	__type(key, u32);
	__type(value, struct task_sched_in);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct pid_key_t);
	__type(value, struct pid_info_t);
} pid_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct name_key_t);
	__type(value, struct info_t);
} name_counts SEC(".maps");

volatile const bool summarize_by_name = false;
volatile const bool per_cpu = false;
volatile const int filter_cpu = -1;
volatile const int filter_tgid = -1;
volatile const int filter_policy = -1;

static __always_inline int
sum_duration(u64 pid_tgid, u32 next_pid, long prev_state)
{
	u64 ts = bpf_ktime_get_ns();
	u32 tgid = pid_tgid >> 32;
	u32 pid = pid_tgid;
	u32 cpu = bpf_get_smp_processor_id();
	struct task_sched_in info = {0};
	struct task_struct *p;
	u64 delta;

	if (filter_cpu != -1 && cpu != filter_cpu)
		return 0;

	if (pid == 0)
		goto fail;

	bpf_map_delete_elem(&enter, &pid);

	struct task_sched_in *data = bpf_map_lookup_elem(&start, &pid);
	if (!data || !data->ts)
		goto fail;

	if (ts < data->ts)
		goto fail;

	delta = ts - data->ts;
	p = (struct task_struct *)bpf_get_current_task();

	// Filters are applied on `next` task's metadata due to bpf_get_current_task()
	// This is incorrect, but matches the python script's behavior.
	if (filter_tgid != -1 && (tgid != filter_tgid))
		goto fail;

	int policy = BPF_CORE_READ(p, policy);
	if (filter_policy != -1 && (policy != filter_policy))
		goto fail;

	if (summarize_by_name) {
		struct name_key_t key = {};
		struct info_t *valp;

		if (per_cpu)
			key.cpuid = cpu;
		key.policy = policy;
		key.prio = BPF_CORE_READ(p, prio) - MAX_RT_PRIO;
		bpf_probe_read_kernel_str(&key.comm, sizeof(key.comm), p->comm);

		valp = bpf_map_lookup_elem(&name_counts, &key);
		if (!valp) {
			struct info_t zero = {};
			bpf_map_update_elem(&name_counts, &key, &zero, BPF_NOEXIST);
			valp = bpf_map_lookup_elem(&name_counts, &key);
			if (!valp)
				goto fail;
		}

		__sync_fetch_and_add(&valp->duration, delta);
		if (data->preempt)
			__sync_fetch_and_add(&valp->preempts, 1);
		if (prev_state == PREEMPT_ON)
			__sync_fetch_and_add(&valp->nivcsw, 1);
		else
			__sync_fetch_and_add(&valp->nvcsw, 1);
	} else { // summarize by pid
		struct pid_key_t key = {};
		struct pid_info_t *valp;

		if (per_cpu)
			key.cpuid = cpu;
		key.pid = pid;
		key.policy = policy;
		key.prio = BPF_CORE_READ(p, prio) - MAX_RT_PRIO;

		valp = bpf_map_lookup_elem(&pid_counts, &key);
		if (!valp) {
			struct pid_info_t zero = {};
			zero.tgid = tgid;
			bpf_probe_read_kernel_str(&zero.comm, sizeof(zero.comm), p->comm);
			bpf_map_update_elem(&pid_counts, &key, &zero, BPF_NOEXIST);
			valp = bpf_map_lookup_elem(&pid_counts, &key);
			if (!valp)
				goto fail;
		}

		__sync_fetch_and_add(&valp->info.duration, delta);
		if (data->preempt)
			__sync_fetch_and_add(&valp->info.preempts, 1);
		if (prev_state == PREEMPT_ON)
			__sync_fetch_and_add(&valp->info.nivcsw, 1);
		else
			__sync_fetch_and_add(&valp->info.nvcsw, 1);
	}

fail:
	if (prev_state == PREEMPT_ON)
		info.preempt = 1;
	else
		info.preempt = 0;
	info.ts = ts;

	if (next_pid != 0)
		bpf_map_update_elem(&start, &next_pid, &info, BPF_ANY);

	return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	// This is buggy as in python version. bpf_get_current_pid_tgid() will
	// return next_pid, but sum_duration expects prev_pid.
	// To align, I'm replicating the buggy behavior.
	// The original python script is not using ctx->prev_pid.
	u64 pid_tgid = bpf_get_current_pid_tgid();
	return sum_duration(pid_tgid, ctx->next_pid, ctx->prev_state);
}

SEC("kprobe/__schedule")
int schedule_entry(struct pt_regs *ctx)
{
    unsigned int sched_mode = (unsigned int)PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_state info = {};

    info.value = 1;
    info.sched_mode = sched_mode;

    if (pid != 0)
        bpf_map_update_elem(&enter, &pid, &info, BPF_ANY);

    return 0;
}

SEC("kretprobe/__schedule")
int schedule_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    struct task_state *info = bpf_map_lookup_elem(&enter, &pid);

    if (!info || !info->value)
        return 0;

    // This is also buggy, as it passes next_pid to sum_duration.
    if (info->sched_mode & SM_MASK_PREEMPT)
        sum_duration(pid_tgid, pid, PREEMPT_ON);
    else
        sum_duration(pid_tgid, pid, info->sched_mode);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
