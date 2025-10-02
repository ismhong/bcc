// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Realtek, Inc. */
#include "vmlinux.h"
#define ENOMEM 12
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vmoom.h"
#include "bits.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct vm_unmapped_area_info);
} start SEC(".maps");

SEC("tp/mmap/vm_unmapped_area")
int handle_vm_unmapped_area(struct trace_event_raw_vm_unmapped_area* ctx)
{
	unsigned long ret = ctx->addr;

	if (ret != -ENOMEM)
		return 0;

	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid;
	e->tgid = pid_tgid >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->flags = ctx->flags;
	e->length = ctx->length;
	e->low_limit = ctx->low_limit;
	e->high_limit = ctx->high_limit;
	e->align_mask = ctx->align_mask;
	e->align_offset = ctx->align_offset;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

static int unmapped_area_entry(struct vm_unmapped_area_info *info)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct vm_unmapped_area_info entry_data = {};

	bpf_probe_read_kernel(&entry_data, sizeof(entry_data), info);

	bpf_map_update_elem(&start, &pid, &entry_data, BPF_ANY);

	return 0;
}

SEC("kprobe/unmapped_area")
int BPF_KPROBE(unmapped_area_entry_kprobe, struct vm_unmapped_area_info *info)
{
	return unmapped_area_entry(info);
}

SEC("kprobe/unmapped_area_topdown")
int BPF_KPROBE(unmapped_area_topdown_entry_kprobe, struct vm_unmapped_area_info *info)
{
	return unmapped_area_entry(info);
}

static int unmapped_area_return(struct pt_regs *ctx)
{
	unsigned long ret = PT_REGS_RC(ctx);

	if (ret != -ENOMEM)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	u32 tgid = pid_tgid >> 32;
	struct event *e;
	struct vm_unmapped_area_info *entry_data;

	entry_data = bpf_map_lookup_elem(&start, &pid);
	if (!entry_data)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->pid = pid;
	e->tgid = tgid;
	e->flags = entry_data->flags;
	e->length = entry_data->length;
	e->low_limit = entry_data->low_limit;
	e->high_limit = entry_data->high_limit;
	e->align_mask = entry_data->align_mask;
	e->align_offset = entry_data->align_offset;

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("kretprobe/unmapped_area")
int BPF_KRETPROBE(unmapped_area_return_kretprobe)
{
	return unmapped_area_return(ctx);
}

SEC("kretprobe/unmapped_area_topdown")
int BPF_KRETPROBE(unmapped_area_topdown_return_kretprobe)
{
	return unmapped_area_return(ctx);
}

char LICENSE[] SEC("license") = "GPL";
