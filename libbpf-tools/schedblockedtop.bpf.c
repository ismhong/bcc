// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Realtek, Inc.
// Copyright (c) 2024 The Gemini Coder.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "schedblockedtop.h"

// Manual struct definitions for tracepoints
// from /sys/kernel/debug/tracing/events/sched/sched_stat_blocked/format
struct sched_stat_blocked_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char comm[16];
	int pid;
	__u64 delay;
};

// from /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/format
struct sched_blocked_reason_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int pid;
	void * caller;
	__u8 io_wait;
};


struct sched_stat {
	__u64 delay;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct sched_stat);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct key_t);
	__type(value, struct val_t);
} counts SEC(".maps");

const volatile bool per_pid = false;
const volatile bool io_wait_only = false;

SEC("tracepoint/sched/sched_stat_blocked")
int sched_stat_blocked(struct sched_stat_blocked_ctx *ctx)
{
	u32 pid = ctx->pid;
	struct sched_stat stat = {};

	stat.delay = ctx->delay;
	if (per_pid) {
		bpf_probe_read_kernel_str(&stat.comm, sizeof(stat.comm), ctx->comm);
	}

	bpf_map_update_elem(&start, &pid, &stat, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_blocked_reason")
int sched_blocked_reason(struct sched_blocked_reason_ctx *ctx)
{
	u32 pid = ctx->pid;
	struct sched_stat *statp;
	struct key_t key = {};
	struct val_t *valp, zero = {};
	__u64 delay;

	if (io_wait_only && !ctx->io_wait)
		return 0;

	statp = bpf_map_lookup_elem(&start, &pid);
	if (!statp)
		return 0;

	delay = statp->delay;
	bpf_map_delete_elem(&start, &pid);

	key.caller = (__u64)ctx->caller;
	key.io_wait = ctx->io_wait;

	if (per_pid) {
		key.pid = pid;
		bpf_probe_read_kernel_str(&key.comm, sizeof(key.comm), statp->comm);
	} else {
		key.pid = 0;
		__builtin_memset(key.comm, 0, sizeof(key.comm));
	}

	valp = bpf_map_lookup_elem(&counts, &key);
	if (!valp) {
		bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
		valp = bpf_map_lookup_elem(&counts, &key);
		if (!valp)
			return 0;
	}

	valp->total_latency += delay;
	valp->count++;
	if (delay > valp->max_latency)
		valp->max_latency = delay;
	if (valp->min_latency == 0 || delay < valp->min_latency)
		valp->min_latency = delay;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
