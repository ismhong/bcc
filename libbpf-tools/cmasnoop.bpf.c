// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cmasnoop.h"
#include "bits.bpf.h"

struct trace_event_raw_cma_alloc {
	unsigned long long __data_loc_dummy;
	unsigned long pfn;
	const void *page;
	unsigned int count;
};

struct entry_data_t {
	u64 ts;
	unsigned long count;
	u32 align;
	u32 pfn;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct entry_data_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, s64);
} total_outstanding_sz SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile bool contig_range = false;
const volatile bool addr_range = false;
const volatile bool has_cma_alloc_finish = false;

SEC("kprobe/cma_alloc")
int BPF_KPROBE(cma_alloc_entry, u32 cma, unsigned long count, unsigned int align)
{
	if (contig_range)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t data = {};

	data.ts = bpf_ktime_get_ns();
	data.count = count;
	data.align = align;

	bpf_map_update_elem(&start, &pid, &data, BPF_ANY);

	return 0;
}

SEC("kretprobe/cma_alloc")
int BPF_KRETPROBE(cma_alloc_return, struct page *ret)
{
	if (contig_range)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	u32 tgid = pid_tgid >> 32;
	struct entry_data_t *entry_data;
	struct event *e;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->duration = bpf_ktime_get_ns() - entry_data->ts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	u32 array_idx = 0;
	s64 *total_val = bpf_map_lookup_elem(&total_outstanding_sz, &array_idx);
	if (!total_val)
		goto cleanup_ringbuf;

	e->pid = pid;
	e->tgid = tgid;
	e->count = entry_data->count;
	e->align = entry_data->align;
	e->alloc = 1;
	e->pfn = entry_data->pfn;

	if (ret == 0) {
		e->fail = 1;
	} else {
		e->fail = 0;
		__sync_fetch_and_add(total_val, entry_data->count);
	}
	e->total_sz = *total_val;

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;

cleanup_ringbuf:
	bpf_ringbuf_discard(e, 0);
	goto cleanup;
}

SEC("kprobe/alloc_contig_range")
int BPF_KPROBE(alloc_contig_range_entry, unsigned long start_pfn, unsigned long end_pfn)
{
	if (!contig_range)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t data = {};

	data.ts = bpf_ktime_get_ns();
	data.count = end_pfn - start_pfn;
	data.align = 0;
	bpf_map_update_elem(&start, &pid, &data, BPF_ANY);

	return 0;
}

SEC("kretprobe/alloc_contig_range")
int BPF_KRETPROBE(alloc_contig_range_return, int ret)
{
	if (!contig_range)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	u32 tgid = pid_tgid >> 32;
	struct entry_data_t *entry_data;
	struct event *e;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->duration = bpf_ktime_get_ns() - entry_data->ts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	u32 array_idx = 0;
	s64 *total_val = bpf_map_lookup_elem(&total_outstanding_sz, &array_idx);
	if (!total_val)
		goto cleanup_ringbuf;

	e->pid = pid;
	e->tgid = tgid;
	e->count = entry_data->count;
	e->align = entry_data->align;
	e->alloc = 1;

	if (ret == 0) {
		e->fail = 0;
		__sync_fetch_and_add(total_val, entry_data->count);
	} else {
		e->fail = 1;
	}
	e->total_sz = *total_val;

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;

cleanup_ringbuf:
	bpf_ringbuf_discard(e, 0);
	goto cleanup;
}

SEC("tracepoint/cma/cma_release")
int cma_release(struct trace_event_raw_cma_release *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	u32 tgid = pid_tgid >> 32;
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	u32 array_idx = 0;
	s64 *total_val = bpf_map_lookup_elem(&total_outstanding_sz, &array_idx);
	if (!total_val) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	__sync_fetch_and_add(total_val, -(s64)BPF_CORE_READ(ctx, count));

	e->pid = pid;
	e->tgid = tgid;
	e->count = BPF_CORE_READ(ctx, count);
	e->align = 0;
	e->duration = 0;
	e->fail = 0;
	e->alloc = 0;
	e->pfn = BPF_CORE_READ(ctx, pfn);
	e->total_sz = *total_val;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("tracepoint/cma/cma_alloc_finish")
int cma_alloc_finish(struct trace_event_raw_cma_alloc_finish *ctx)
{
	if (!addr_range)
		return 0;

	if (!has_cma_alloc_finish)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;
	entry_data->pfn = BPF_CORE_READ(ctx, pfn);

	return 0;
}

SEC("tracepoint/cma/cma_alloc")
int cma_alloc(struct trace_event_raw_cma_alloc *ctx)
{
	if (!addr_range)
		return 0;

	if (has_cma_alloc_finish)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;
	entry_data->pfn = BPF_CORE_READ(ctx, pfn);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
