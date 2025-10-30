// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Realtek, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "smclatency.h"

volatile const int core = -1;
volatile const bool ftrace = false;
volatile const bool isr_time = false;
volatile const __u64 factor = 1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, u32);
	__type(value, u64);
} irq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

__u32 hist[HIST_SLOTS] = {};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_CPU_NR + 1);
	__type(key, u32);
	__type(value, u64);
} latency_sum SEC(".maps");

static inline int trace_irq_entry()
{
	u64 ts = bpf_ktime_get_ns();
	u32 idx = bpf_get_smp_processor_id();

	if (core != -1 && idx != core)
		return 0;

	bpf_map_update_elem(&irq_start, &idx, &ts, BPF_ANY);

	return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int irq_handler_entry_tp(struct trace_event_raw_irq_handler_entry *ctx)
{
	u64 *smc_start_ts;
	u32 idx = bpf_get_smp_processor_id();

	smc_start_ts = bpf_map_lookup_elem(&start, &idx);
	if (ftrace && smc_start_ts && *smc_start_ts != 0)
		bpf_printk("domain_irq_entry irq=%d\n", ctx->irq);

	return trace_irq_entry();
}

SEC("kprobe/handle_IPI")
int BPF_KPROBE(inter_processor_irq_entry)
{
	u64 *smc_start_ts;
	u32 idx = bpf_get_smp_processor_id();

	smc_start_ts = bpf_map_lookup_elem(&start, &idx);
	if (ftrace && smc_start_ts && *smc_start_ts != 0)
		bpf_printk("inter_processor_irq_entry\n");

	return trace_irq_entry();
}

SEC("kprobe/__arm_smccc_smc")
int BPF_KPROBE(trace_func_entry)
{
	u64 ts = bpf_ktime_get_ns();
	u32 idx = bpf_get_smp_processor_id();

	if (core != -1 && idx != core)
		return 0;

	bpf_map_delete_elem(&irq_start, &idx);
	bpf_map_update_elem(&start, &idx, &ts, BPF_ANY);

	if (ftrace)
		bpf_printk("__arm_smccc_smc func entry\n");

	return 0;
}

SEC("kretprobe/__arm_smccc_smc")
int BPF_KRETPROBE(trace_func_return)
{
	u64 *smc_start_ts, *irq_start_ts, delta, isr_latency = 0;
	u32 idx = bpf_get_smp_processor_id();
	u32 all_cpu_key = 0;
	u32 cpu_key = idx + 1;
	u64 *sum;

	smc_start_ts = bpf_map_lookup_elem(&start, &idx);
	if (smc_start_ts == 0)
		return 0;

	irq_start_ts = bpf_map_lookup_elem(&irq_start, &idx);

	if (irq_start_ts == 0) {
		delta = bpf_ktime_get_ns() - *smc_start_ts;
	} else {
		if (isr_time) {
			delta = bpf_ktime_get_ns() - *smc_start_ts;
		} else {
			delta = *irq_start_ts - *smc_start_ts;
		}
		isr_latency = (bpf_ktime_get_ns() - *irq_start_ts) / 1000;
	}

	if (ftrace) {
		u64 delta_us = delta / 1000;
		if (isr_time) {
			bpf_printk("return: SMCCC_lat(us)=%llu, ISR_lat(us)=%llu, SMCCC-ISR=%llu\n",
				delta_us, isr_latency, delta_us - isr_latency);
		} else {
			bpf_printk("return: SMCCC_lat(us)=%llu, ISR_lat(us)=%llu, SMCCC+ISR=%llu\n",
				delta_us, isr_latency, delta_us + isr_latency);
		}
	}

	bpf_map_delete_elem(&start, &idx);

	sum = bpf_map_lookup_elem(&latency_sum, &all_cpu_key);
	if (sum)
		*sum += delta;

	sum = bpf_map_lookup_elem(&latency_sum, &cpu_key);
	if (sum)
		*sum += delta;

	delta /= factor;
	__u32 slot = log2l(delta);
	if (slot >= HIST_SLOTS)
		slot = HIST_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
