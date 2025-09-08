// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tiago Ilieve
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syncsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


static void __syscall(void *ctx,
		      enum sync_syscalls sys)
{
	struct event event = {};

	bpf_get_current_comm(event.comm, sizeof(event.comm));
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.sys = sys;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("ksyscall/sync")
void BPF_KPROBE(sync)
{
	__syscall(ctx, SYS_SYNC);
}

SEC("ksyscall/fsync")
void BPF_KPROBE(fsync)
{
	__syscall(ctx, SYS_FSYNC);
}

SEC("ksyscall/fdatasync")
void BPF_KPROBE(fdatasync)
{
	__syscall(ctx, SYS_FDATASYNC);
}

SEC("ksyscall/msync")
void BPF_KPROBE(msync)
{
	__syscall(ctx, SYS_MSYNC);
}

SEC("ksyscall/sync_file_range")
void BPF_KPROBE(sync_file_range)
{
	__syscall(ctx, SYS_SYNC_FILE_RANGE);
}

SEC("ksyscall/syncfs")
void BPF_KPROBE(syncfs)
{
	__syscall(ctx, SYS_SYNCFS);
}

char LICENSE[] SEC("license") = "GPL";
