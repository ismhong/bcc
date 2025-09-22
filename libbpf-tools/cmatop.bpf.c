// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cmatop.h"

struct entry_data_t {
	u64 ts;
	unsigned long count;
	u32 align;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct entry_data_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct cma_alloc_t);
} cma_alloc_hash SEC(".maps");

const volatile bool track_range = false;

static __always_inline int
handle_cma_alloc_exit(bool is_cma_alloc, long ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;

	u64 delta = bpf_ktime_get_ns() - entry_data->ts;
	u64 pages = entry_data->count;
	struct cma_alloc_t *cma_val_t, zero = {};

	cma_val_t = bpf_map_lookup_elem(&cma_alloc_hash, &pages);
	if (!cma_val_t) {
		bpf_map_update_elem(&cma_alloc_hash, &pages, &zero, BPF_NOEXIST);
		cma_val_t = bpf_map_lookup_elem(&cma_alloc_hash, &pages);
		if (!cma_val_t)
			goto cleanup;
	}

	if (cma_val_t->max < delta || cma_val_t->max == 0)
		cma_val_t->max = delta;
	if (cma_val_t->min > delta || cma_val_t->min == 0)
		cma_val_t->min = delta;

	cma_val_t->align = entry_data->align;
	__sync_fetch_and_add(&cma_val_t->total_latency, delta);
	__sync_fetch_and_add(&cma_val_t->total_count, 1);

	if (is_cma_alloc) {
		if (ret == 0)
			__sync_fetch_and_add(&cma_val_t->fail, 1);
		else
			__sync_fetch_and_add(&cma_val_t->success, 1);
	} else { /* alloc_contig_range */
		if (ret == 0)
			__sync_fetch_and_add(&cma_val_t->success, 1);
		else
			__sync_fetch_and_add(&cma_val_t->fail, 1);
	}

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("kprobe/cma_alloc")
int BPF_KPROBE(cma_alloc_entry, struct cma *cma, unsigned long count,
		unsigned int align)
{
	if (track_range)
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
	if (track_range)
		return 0;

	return handle_cma_alloc_exit(true, (long)ret);
}

SEC("kprobe/alloc_contig_range")
int BPF_KPROBE(alloc_contig_range_entry, unsigned long start_pfn,
		unsigned long end_pfn)
{
	if (!track_range)
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
	if (!track_range)
		return 0;

	return handle_cma_alloc_exit(false, ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
