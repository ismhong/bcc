// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pageowner.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64); // pfn
	__type(value, struct data_t);
} page_track_table SEC(".maps");

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 16384);
} stack_traces SEC(".maps");

volatile const int page_size = 4096;
volatile const unsigned long start_pfn = 0;
volatile const unsigned long end_pfn = 0;

SEC("tracepoint/kmem/mm_page_alloc")
int tp_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	if ((ctx->pfn < start_pfn) || (ctx->pfn > end_pfn))
		return 0;

	struct data_t data = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 pfn_key = ctx->pfn;

	data.migratetype = ctx->migratetype;
	data.size = (u64)page_size << ctx->order;
	data.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	data.pid = pid_tgid;
	data.tgid = pid_tgid >> 32;
	data.gfp_flags = ctx->gfp_flags;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	bpf_map_update_elem(&page_track_table, &pfn_key, &data, BPF_ANY);

	return 0;
}

SEC("tracepoint/kmem/mm_page_free")
int tp_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	u64 pfn_key = ctx->pfn;
	if ((pfn_key < start_pfn) || (pfn_key > end_pfn))
		return 0;

	bpf_map_delete_elem(&page_track_table, &pfn_key);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
