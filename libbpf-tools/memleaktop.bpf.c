// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Realtek, Inc.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memleaktop.h"
#include "core_fixes.bpf.h"

#define KMEM_ARRAY_SIZE 4
#define KMEM_OUTSTANDING_IDX 0
#define KMEM_CACHE_OUTSTANDING_IDX 1
#define MM_PAGE_OUTSTANDING_IDX 2
#define KMEM_ADDR_HASH_COUNTS_IDX 3

#define KMEM_FUNC 0
#define KMEM_CACHE_FUNC 1
#define MM_PAGE_FUNC 2

const volatile __u32 pid_filter = 0;
const volatile __u32 tid_filter = 0;
const volatile __u64 min_size = 0;
const volatile __u64 max_size = -1;
const volatile __u64 sample_rate = 1;
const volatile bool extend_output = false;
const volatile bool wa_missing_free = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct size_count);
	__uint(max_entries, 10240);
} pid_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 500000);
} addr_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct key_t);
	__uint(max_entries, 500000);
} addr_pid_map_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, KMEM_ARRAY_SIZE);
} total_size SEC(".maps");

static inline int gen_free_enter(u64 address, int kmem_func);

static inline int get_key(struct key_t* key, size_t size) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	key->tgid = pid_tgid >> 32;
	if (pid_filter && key->tgid != pid_filter)
		return 0;
	key->pid = pid_tgid;
	if (tid_filter && key->pid != tid_filter)
		return 0;
	bpf_get_current_comm(&(key->name), sizeof(key->name));
	if (extend_output)
		key->sz = size;
	else
		key->sz = 0;
	return 1;
}

static inline int gen_alloc_enter(size_t size, u64 address, int kmem_func) {
	if (size < min_size || (max_size != (u64)-1 && size > max_size))
		return 0;

	if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

	struct key_t key = {};
	if (!get_key(&key, size))
		return 0;

	struct size_count *sum_size, sum_zero = {0};
	sum_size = bpf_map_lookup_elem(&pid_sizes, &key);
	if (!sum_size) {
		bpf_map_update_elem(&pid_sizes, &key, &sum_zero, BPF_NOEXIST);
		sum_size = bpf_map_lookup_elem(&pid_sizes, &key);
		if (!sum_size)
			return 0;
	}

	__sync_fetch_and_add(&sum_size->size, size);
	__sync_fetch_and_add(&sum_size->count, 1);

	u32 array_idx;
	if (kmem_func == KMEM_FUNC)
		array_idx = KMEM_OUTSTANDING_IDX;
	else if (kmem_func == KMEM_CACHE_FUNC)
		array_idx = KMEM_CACHE_OUTSTANDING_IDX;
	else // MM_PAGE_FUNC
		array_idx = MM_PAGE_OUTSTANDING_IDX;

	u64 *mem_total_size = bpf_map_lookup_elem(&total_size, &array_idx);
	if (mem_total_size)
		__sync_fetch_and_add(mem_total_size, size);

	array_idx = KMEM_ADDR_HASH_COUNTS_IDX;
	u64 *total_count = bpf_map_lookup_elem(&total_size, &array_idx);
	if (total_count)
		__sync_fetch_and_add(total_count, 1);

	u64 sz = size;
	bpf_map_update_elem(&addr_sizes, &address, &sz, BPF_ANY);
	bpf_map_update_elem(&addr_pid_map_table, &address, &key, BPF_ANY);

	return 0;
}

static inline int gen_free_enter(u64 address, int kmem_func) {
	u64 *size_ptr = bpf_map_lookup_elem(&addr_sizes, &address);
	if (!size_ptr)
		return 0;

	u64 size = *size_ptr;

	struct key_t *alloc_key = bpf_map_lookup_elem(&addr_pid_map_table, &address);
	if (!alloc_key)
		return 0;

	struct size_count *sum_size = bpf_map_lookup_elem(&pid_sizes, alloc_key);
	if (!sum_size)
		return 0;

	__sync_fetch_and_sub(&sum_size->size, size);
	__sync_fetch_and_sub(&sum_size->count, 1);

	if (sum_size->size == 0)
		bpf_map_delete_elem(&pid_sizes, alloc_key);

	u32 array_idx;
	if (kmem_func == KMEM_FUNC)
		array_idx = KMEM_OUTSTANDING_IDX;
	else if (kmem_func == KMEM_CACHE_FUNC)
		array_idx = KMEM_CACHE_OUTSTANDING_IDX;
	else // MM_PAGE_FUNC
		array_idx = MM_PAGE_OUTSTANDING_IDX;

	u64 *mem_total_size = bpf_map_lookup_elem(&total_size, &array_idx);
	if (mem_total_size)
		__sync_fetch_and_sub(mem_total_size, size);

	bpf_map_delete_elem(&addr_sizes, &address);
	bpf_map_delete_elem(&addr_pid_map_table, &address);

	array_idx = KMEM_ADDR_HASH_COUNTS_IDX;
	u64 *total_count = bpf_map_lookup_elem(&total_size, &array_idx);
	if (total_count)
		__sync_fetch_and_sub(total_count, 1);

	return 0;
}

SEC("tracepoint/kmem/kmalloc")
int memleaktop__kmalloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter((u64)ptr, KMEM_FUNC);

	return gen_alloc_enter(bytes_alloc, (u64)ptr, KMEM_FUNC);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleaktop__kmalloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter((u64)ptr, KMEM_FUNC);

		return gen_alloc_enter(bytes_alloc, (u64)ptr, KMEM_FUNC);
	}
	return 0;
}

SEC("tracepoint/kmem/kfree")
int memleaktop__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter((u64)ptr, KMEM_FUNC);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleaktop__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter((u64)ptr, KMEM_CACHE_FUNC);

	return gen_alloc_enter(bytes_alloc, (u64)ptr, KMEM_CACHE_FUNC);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleaktop__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter((u64)ptr, KMEM_CACHE_FUNC);

		return gen_alloc_enter(bytes_alloc, (u64)ptr, KMEM_CACHE_FUNC);
	}
	return 0;
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleaktop__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter((u64)ptr, KMEM_CACHE_FUNC);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleaktop__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	return gen_alloc_enter(__PAGE_SIZE << ctx->order, (u64)ctx->pfn, MM_PAGE_FUNC);
}

SEC("tracepoint/kmem/mm_page_free")
int memleaktop__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((u64)ctx->pfn, MM_PAGE_FUNC);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
