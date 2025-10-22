// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pagealloctop.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct page_alloc_stat);
} page_alloc_hash SEC(".maps");

#ifndef GFP_MOVABLE
#define GFP_MOVABLE 0x8
#endif

SEC("tracepoint/kmem/mm_page_alloc")
int pagealloc_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	u32 tgid = pid_tgid >> 32;
	struct page_alloc_stat *stat;
	struct page_alloc_stat new_stat = { .tgid = tgid };

	if (ctx->pfn < 0)
		return 0;

	stat = bpf_map_lookup_elem(&page_alloc_hash, &pid);
	if (!stat)
		stat = &new_stat;

	if (ctx->gfp_flags & GFP_MOVABLE)
		stat->movable_size += (__PAGE_SIZE << ctx->order);
	else
		stat->unmovable_size += (__PAGE_SIZE << ctx->order);

	stat->tgid = tgid;
	bpf_get_current_comm(&stat->comm, sizeof(stat->comm));

	bpf_map_update_elem(&page_alloc_hash, &pid, stat, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
