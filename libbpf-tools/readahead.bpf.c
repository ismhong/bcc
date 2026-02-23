// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "readahead.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} in_readahead SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct page *);
	__type(value, u64);
} birth SEC(".maps");

struct hist hist = {};

SEC("kprobe/do_page_cache_ra")
int BPF_KPROBE(do_page_cache_ra)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, 0);
	return 0;
}

static __always_inline
int alloc_done(struct page *page)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts;

	if (!bpf_map_lookup_elem(&in_readahead, &pid))
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&birth, &page, &ts, 0);
	__sync_fetch_and_add(&hist.unused, 1);
	__sync_fetch_and_add(&hist.total, 1);

	return 0;
}

SEC("kretprobe/__page_cache_alloc")
int BPF_KRETPROBE(page_cache_alloc_ret, struct page *ret)
{
	return alloc_done(ret);
}

SEC("kretprobe/filemap_alloc_folio")
int BPF_KRETPROBE(filemap_alloc_folio_ret, struct folio *ret)
{
	return alloc_done(&ret->page);
}

SEC("kretprobe/filemap_alloc_folio_noprof")
int BPF_KRETPROBE(filemap_alloc_folio_noprof_ret, struct folio *ret)
{
	return alloc_done(&ret->page);
}

SEC("kprobe/filemap_add_folio")
int BPF_KPROBE(filemap_add_folio, struct address_space *mapping, struct folio *folio)
{
	return alloc_done(&folio->page);
}

SEC("kretprobe/do_page_cache_ra")
int BPF_KRETPROBE(do_page_cache_ra_ret)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

static __always_inline
int mark_accessed(struct page *page)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&birth, &page);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto update_and_cleanup;
	slot = log2l(delta / 1000000U);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist.slots[slot], 1);

update_and_cleanup:
	__sync_fetch_and_add(&hist.unused, -1);
	bpf_map_delete_elem(&birth, &page);

	return 0;
}

SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed, struct folio *folio)
{
	return mark_accessed(&folio->page);
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(mark_page_accessed, struct page *page)
{
	return mark_accessed(page);
}

char LICENSE[] SEC("license") = "GPL";
