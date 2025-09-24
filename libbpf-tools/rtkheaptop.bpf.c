// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * rtkheaptop: Analysis rtkheap allocation as a table.
 *
 * Copyright (c) 2025 Realtek, Inc.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "rtkheaptop.h"
#include "bits.bpf.h"

#define PAGE_SHIFT 12

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct alloc_info);
} pid_alloc_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct use_heap);
	__type(value, struct heap_info);
} heap_summary_hash SEC(".maps");

volatile const bool milliseconds = false;
volatile const char heap_name_filter[HEAP_MAX_NAME] = {};
volatile const char task_name_filter[TASK_COMM_LEN] = {};
volatile const char caller_name_filter[TASK_COMM_LEN] = {};

// From drivers/dma-buf/dma-heap.c
struct dma_heap {
	const char *name;
	const void *ops;
	void *priv;
	__kernel_dev_t heap_devt;
	struct list_head list;
	struct cdev heap_cdev;
	struct kref refcount;
	struct device *heap_dev;
};

struct rtk_heap {
	struct dma_heap *heap;
};

static int rtk_heap_pool_allocate_start(struct dma_heap *heap,
		size_t size, unsigned long flags, char *caller)
{
	struct alloc_info alloc_info = {};
	size_t align_size = (size + (1 << PAGE_SHIFT) - 1) & ~((1 << PAGE_SHIFT) - 1);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	const char *heap_name_ptr;

	alloc_info.size = align_size >> PAGE_SHIFT;
	alloc_info.ts = bpf_ktime_get_ns();
	alloc_info.flags = flags;

	bpf_probe_read_kernel(&heap_name_ptr, sizeof(heap_name_ptr), &heap->name);
	bpf_probe_read_kernel_str(alloc_info.name, sizeof(alloc_info.name), heap_name_ptr);

	if (heap_name_filter[0] != 0 && __builtin_memcmp(alloc_info.name, (const void *)heap_name_filter, sizeof(alloc_info.name)) != 0)
		return 0;

	if (caller != NULL)
		bpf_probe_read_kernel_str(alloc_info.caller, sizeof(alloc_info.caller), caller);

	bpf_map_update_elem(&pid_alloc_heap, &pid, &alloc_info, BPF_ANY);

	return 0;
}

static int rtk_heap_pool_allocate_end(struct pt_regs *ctx)
{
	u64 delta, pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct alloc_info *alloc_info_p;
	struct heap_info *heap_info_p, zero = {};

	alloc_info_p = bpf_map_lookup_elem(&pid_alloc_heap, &pid);
	if (!alloc_info_p)
		return 0;

	delta = bpf_ktime_get_ns() - alloc_info_p->ts;
	if (milliseconds)
		delta /= 1000000;
	else
		delta /= 1000;

	struct use_heap heap_key = {};
	heap_key.tgid = pid_tgid >> 32;
	heap_key.pid = pid;
	heap_key.flags = alloc_info_p->flags;
	bpf_probe_read_kernel_str(heap_key.name, sizeof(heap_key.name), alloc_info_p->name);
	bpf_probe_read_kernel_str(heap_key.caller, sizeof(heap_key.caller), alloc_info_p->caller);
	bpf_get_current_comm(heap_key.comm, sizeof(heap_key.comm));

	if (task_name_filter[0] != 0 && __builtin_memcmp(heap_key.comm, (const void *)task_name_filter, sizeof(heap_key.comm)) != 0)
		goto cleanup;
	if (caller_name_filter[0] != 0 && __builtin_memcmp(heap_key.caller, (const void *)caller_name_filter, sizeof(heap_key.caller)) != 0)
		goto cleanup;

	heap_info_p = bpf_map_lookup_elem(&heap_summary_hash, &heap_key);
	if (!heap_info_p) {
		bpf_map_update_elem(&heap_summary_hash, &heap_key, &zero, BPF_NOEXIST);
		heap_info_p = bpf_map_lookup_elem(&heap_summary_hash, &heap_key);
		if (!heap_info_p)
			goto cleanup;
	}

	__sync_fetch_and_add(&heap_info_p->size, alloc_info_p->size);

	if (delta > heap_info_p->max_alloc_latency)
		heap_info_p->max_alloc_latency = delta;

	void *ret = (void *)PT_REGS_RC(ctx);
	if (ret)
		__sync_fetch_and_add(&heap_info_p->success, 1);
	else
		__sync_fetch_and_add(&heap_info_p->fail, 1);

cleanup:
	bpf_map_delete_elem(&pid_alloc_heap, &pid);
	return 0;
}

#define ALLOC_ENTRY(name, rtk_heap_type, size_type) \
SEC("kprobe/" #name) \
int BPF_KPROBE(name##_entry, struct rtk_heap_type *rtk_heap_arg, size_type size, unsigned long flags, char *caller) \
{ \
	struct dma_heap *actual_dma_heap; \
	bpf_probe_read_kernel(&actual_dma_heap, sizeof(actual_dma_heap), &rtk_heap_arg->heap); \
	return rtk_heap_pool_allocate_start(actual_dma_heap, size, flags, caller); \
} \
SEC("kretprobe/" #name) \
int name##_exit(struct pt_regs *ctx) \
{ \
	return rtk_heap_pool_allocate_end(ctx); \
}

#define ALLOC_ENTRY_DMA(name) \
SEC("kprobe/" #name) \
int BPF_KPROBE(name##_entry, struct dma_heap *heap, unsigned long len, unsigned long flags, bool uncached) \
{ \
	return rtk_heap_pool_allocate_start(heap, len, flags, NULL); \
} \
SEC("kretprobe/" #name) \
int name##_exit(struct pt_regs *ctx) \
{ \
	return rtk_heap_pool_allocate_end(ctx); \
}

/* kernel >= 5.11 */
ALLOC_ENTRY(rtk_dynamic_secure_allocate, rtk_heap, size_t);
ALLOC_ENTRY(rtk_static_secure_allocate, rtk_heap, size_t);
ALLOC_ENTRY(rtk_normal_allocate, rtk_heap, size_t);
ALLOC_ENTRY(rtk_pool_allocate, rtk_heap, size_t);

/* kernel < 5.11 */
ALLOC_ENTRY_DMA(rtk_dyn_protect_cma_do_allocate);
ALLOC_ENTRY_DMA(rtk_stc_cma_do_allocate);
ALLOC_ENTRY_DMA(rtk_cma_do_allocate);
ALLOC_ENTRY_DMA(rtk_gen_do_allocate);

char _license[] SEC("license") = "GPL";
