// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "cputop.h"

#ifndef MAX_RT_PRIO
#define MAX_RT_PRIO 100
#endif

#define MAX_ENTRIES 10240

struct task_sched_in {
	u64 ts;
	bool preempt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
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

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 prev_pid = ctx->prev_pid;
	u32 next_pid = ctx->next_pid;
	u32 cpu = bpf_get_smp_processor_id();
	struct task_struct *p;
	struct task_sched_in *data, info = {0};
	u64 delta;
	bool preempted;

	if (filter_cpu != -1 && cpu != filter_cpu)
		return 0;

	// process task switched out
	if (prev_pid != 0) {
		data = bpf_map_lookup_elem(&start, &prev_pid);
		if (data && data->ts) {
			delta = ts - data->ts;
			p = (struct task_struct *)bpf_get_current_task();
			u32 tgid = BPF_CORE_READ(p, tgid);

			if (filter_tgid != -1 && tgid != filter_tgid)
				goto record_next;

			int policy = BPF_CORE_READ(p, policy);
			if (filter_policy != -1 && policy != filter_policy)
				goto record_next;

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
						goto record_next;
				}

				__sync_fetch_and_add(&valp->duration, delta);
				if (data->preempt)
					__sync_fetch_and_add(&valp->preempts, 1);

				preempted = (ctx->prev_state == 0);
				if (preempted)
					__sync_fetch_and_add(&valp->nivcsw, 1);
				else
					__sync_fetch_and_add(&valp->nvcsw, 1);

			} else { // summarize by pid
				struct pid_key_t key = {};
				struct pid_info_t *valp;

				if (per_cpu)
					key.cpuid = cpu;
				key.pid = prev_pid;
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
						goto record_next;
				}

				__sync_fetch_and_add(&valp->info.duration, delta);
				if (data->preempt)
					__sync_fetch_and_add(&valp->info.preempts, 1);

				preempted = (ctx->prev_state == 0);
				if (preempted)
					__sync_fetch_and_add(&valp->info.nivcsw, 1);
				else
					__sync_fetch_and_add(&valp->info.nvcsw, 1);
			}
		}
	}

record_next:
	// record task switched in
	info.ts = ts;
	info.preempt = (ctx->prev_state == 0);
	if (next_pid != 0)
		bpf_map_update_elem(&start, &next_pid, &info, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
