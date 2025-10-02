// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmallocleak.h"

#define MAX_ENTRIES 32768

struct alloc_hash_val_t {
	u64 size;
	u64 stack_id;
};

struct addr_val_t {
	u32 tgid;
	u32 pid;
	u64 size;
	u64 stack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct addr_val_t);
	__uint(max_entries, MAX_ENTRIES);
} addr_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct alloc_hash_val_t);
	__uint(max_entries, MAX_ENTRIES);
} alloc_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} outstanding_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} total_addr_size SEC(".maps");

const volatile bool kernel_stacks = false;

SEC("kprobe/alloc_vmap_area")
int BPF_KPROBE(alloc_vmap_enter, u64 size) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct alloc_hash_val_t val = {};

	val.size = size;
	if (kernel_stacks)
		val.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	else
		val.stack_id = -1;

	bpf_map_update_elem(&alloc_hash, &pid, &val, BPF_ANY);

	return 0;
}

SEC("kretprobe/alloc_vmap_area")
int BPF_KRETPROBE(alloc_vmap_return, struct vmap_area *ret) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	u32 pid = pid_tgid;
	struct alloc_hash_val_t *alloc_hash_val;
	u64 va_addr = (u64)ret;
	u32 zero = 0;
	u64 *total;

	alloc_hash_val = bpf_map_lookup_elem(&alloc_hash, &pid);
	if (!alloc_hash_val)
		return 0;

	if (va_addr == 0) {
		bpf_map_delete_elem(&alloc_hash, &pid);
		return 0;
	}

	struct addr_val_t addr_val = {};
	addr_val.tgid = tgid;
	addr_val.pid = pid;
	addr_val.size = alloc_hash_val->size;
	addr_val.stack_id = alloc_hash_val->stack_id;

	bpf_map_update_elem(&addr_sizes, &va_addr, &addr_val, BPF_ANY);

	total = bpf_map_lookup_elem(&total_addr_size, &zero);
	if (total)
		*total += 1;

	struct key_t key = {};
	key.tgid = tgid;
	key.pid = pid;
	key.stack_id = alloc_hash_val->stack_id;

	struct val_t *val_p = bpf_map_lookup_elem(&outstanding_hash, &key);
	if (!val_p) {
		struct val_t new_val = {};
		bpf_get_current_comm(&new_val.name, sizeof(new_val.name));
		new_val.size = alloc_hash_val->size;
		bpf_map_update_elem(&outstanding_hash, &key, &new_val, BPF_ANY);
	} else {
		__sync_fetch_and_add(&val_p->size, alloc_hash_val->size);
	}

	bpf_map_delete_elem(&alloc_hash, &pid);
	return 0;
}

static int free_vmap(struct vmap_area *va) {
	struct addr_val_t *addr_val;
	u64 va_addr = (u64)va;
	u32 zero = 0;
	u64 *total;

	addr_val = bpf_map_lookup_elem(&addr_sizes, &va_addr);
	if (!addr_val)
		return 0; // missed alloc entry

	struct key_t key = {};
	key.tgid = addr_val->tgid;
	key.pid = addr_val->pid;
	key.stack_id = addr_val->stack_id;

	struct val_t *val_p = bpf_map_lookup_elem(&outstanding_hash, &key);
	if (!val_p)
		return 0;

	__sync_fetch_and_sub(&val_p->size, addr_val->size);

	bpf_map_delete_elem(&addr_sizes, &va_addr);

	total = bpf_map_lookup_elem(&total_addr_size, &zero);
	if (total)
		*total -= 1;

	return 0;
}

SEC("kprobe/free_vmap_area_noflush")
int BPF_KPROBE(free_vmap_area_noflush, struct vmap_area *va) {
	return free_vmap(va);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
