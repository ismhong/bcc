// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "gpumemtop.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct gpu_mem_total_key);
	__type(value, u64);
} gpu_memory_hash SEC(".maps");



SEC("tracepoint/gpu_mem/gpu_mem_total")
int gpumem_total(struct trace_event_raw_gpu_mem_total *ctx)
{
	struct gpu_mem_total_key key = {};
	u64 size = ctx->size;

	key.gpu_id = ctx->gpu_id;
	key.pid = ctx->pid;

	if (size == 0) {
		bpf_map_delete_elem(&gpu_memory_hash, &key);
		return 0;
	}

	bpf_map_update_elem(&gpu_memory_hash, &key, &size, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
