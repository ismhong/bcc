// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Realtek, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mmclatency.h"
#include "bits.bpf.h" // For log2l

#define MMC_DATA_WRITE      (1 << 8)
#define MMC_DATA_READ       (1 << 9)
#define EXECUTE_WRITE_TASK 47
#define EXECUTE_READ_TASK 46

const volatile int units = NSEC;
const volatile int target_command = 0;
const volatile int min_blocks = 0;
const volatile int max_blocks = 0;
const volatile bool avglatency = false;
const volatile bool per_command = false;
const volatile bool per_blocks = false;

struct mmc_value {
	u64 ts;
	u32 cmd;
	u64 blocks;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64); // Address of struct mmc_request
	__type(value, struct mmc_value);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256); // Max 256 commands
	__type(key, u32);
	__type(value, u64);
} latency_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256); // Max 256 commands
	__type(key, u32);
	__type(value, u64);
} count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} latency_sum_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, cmd_key_t);
	__type(value, u64);
} dist SEC(".maps");

// Dropped simplified tracepoint argument structures.
// We are now using trace event raw structures from vmlinux.h.

SEC("tp/mmc/mmc_request_start")
int mmc_request_start_probe(struct trace_event_raw_mmc_request_start *ctx)
{
	u32 cmd = ctx->cmd_opcode;
	u64 mrq_ptr = (u64)ctx->mrq;
	struct mmc_value val = {};

	if (!ctx->cmd_opcode) {
		if ((ctx->data_flags & MMC_DATA_WRITE) || (ctx->data_flags & MMC_DATA_READ)) {
			cmd = (ctx->data_flags & MMC_DATA_WRITE) ? EXECUTE_WRITE_TASK : EXECUTE_READ_TASK;
		}
	}

	if (target_command && target_command != cmd) {
		return 0;
	}

	if (min_blocks && ctx->blocks < min_blocks) {
		return 0;
	}
	if (max_blocks && ctx->blocks > max_blocks) {
		return 0;
	}

	val.cmd = cmd;
	val.blocks = ctx->blocks;
	val.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &mrq_ptr, &val, BPF_ANY);

	return 0;
}

SEC("tp/mmc/mmc_request_done")
int mmc_request_done_probe(struct trace_event_raw_mmc_request_done *ctx)
{
	struct mmc_value *start_val;
	u64 mrq_ptr = (u64)ctx->mrq;
	u64 delta = 0;
	u32 cmd, array_idx = 0;
	u64 *curlatcy;
	u64 *hist_val;
	cmd_key_t key = {};

	start_val = bpf_map_lookup_elem(&start, &mrq_ptr);
	if (!start_val)
		return 0;          // missed start

	cmd = start_val->cmd;
	if (target_command && target_command != cmd) {
		goto cleanup;
	}

	delta = bpf_ktime_get_ns() - start_val->ts;

	switch (units) {
		case USEC:
			delta /= 1000;
			break;
		case MSEC:
			delta /= 1000000;
			break;
	}

	if (avglatency) {
		curlatcy = bpf_map_lookup_elem(&latency_map, &cmd);
		if (curlatcy) {
			*curlatcy += delta;
		} else {
			bpf_map_update_elem(&latency_map, &cmd, &delta, BPF_ANY);
		}
		curlatcy = bpf_map_lookup_elem(&count_map, &cmd);
		if (curlatcy) {
			*curlatcy += 1;
		} else {
			u64 one = 1;
			bpf_map_update_elem(&count_map, &cmd, &one, BPF_ANY);
		}
	} else {
		curlatcy = bpf_map_lookup_elem(&latency_sum_map, &array_idx);
		if (curlatcy) {
			*curlatcy += delta;
		} else {
			bpf_map_update_elem(&latency_sum_map, &array_idx, &delta, BPF_ANY);
		}
	}

	u64 slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	if (per_command && per_blocks) {
		key.slot = slot;
		key.value = cmd;
		key.value = (key.value << 32) | start_val->blocks;
		hist_val = bpf_map_lookup_elem(&dist, &key);
		if (hist_val) {
			*hist_val += 1;
		} else {
			u64 one = 1;
			bpf_map_update_elem(&dist, &key, &one, BPF_ANY);
		}
	} else if (per_command) {
		key.slot = slot;
		key.value = cmd;
		hist_val = bpf_map_lookup_elem(&dist, &key);
		if (hist_val) {
			*hist_val += 1;
		} else {
			u64 one = 1;
			bpf_map_update_elem(&dist, &key, &one, BPF_ANY);
		}
	} else if (per_blocks) {
		key.slot = slot;
		key.value = start_val->blocks;
		hist_val = bpf_map_lookup_elem(&dist, &key);
		if (hist_val) {
			*hist_val += 1;
		} else {
			u64 one = 1;
			bpf_map_update_elem(&dist, &key, &one, BPF_ANY);
		}
	} else {
		key.slot = slot;
		key.value = 0; // Not used for global histogram
		hist_val = bpf_map_lookup_elem(&dist, &key);
		if (hist_val) {
			*hist_val += 1;
		} else {
			u64 one = 1;
			bpf_map_update_elem(&dist, &key, &one, BPF_ANY);
		}
	}

cleanup:
	bpf_map_delete_elem(&start, &mrq_ptr);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
