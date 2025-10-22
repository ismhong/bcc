// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Note: Kprobe failed due to symbol lookup issues on the target Android kernel.
 * We are switching to the original method used by the BCC tool: Tracepoints on
 * preemptirq/irq_disable and preemptirq/preempt_disable, which is far more stable
 * on locked-down kernels and matches the original tool's intent.
 */

// This structure mirrors the relevant parts of the trace event context
// (struct trace_event_raw_preemptirq_irq_disable/preempt_disable)
// to access the instruction pointer offsets, matching the original BCC tool.
struct trace_preemptirq_entry {
    __u64 __unused_common_fields; // Placeholder for common tracepoint header fields
    __u32 caller_offs;            // Offset from _stext/kernel base (u32)
    __u32 parent_offs;            // Offset from _stext/kernel base (u32)
    // The rest of the struct is ignored
};

enum addr_offs {
    START_CALLER_OFF,
    START_PARENT_OFF,
};

struct candidate_ts_key {
    __u32 cpu;
};

struct candidate_table {
    __u64 addrs[2];  /* Stores u32 offsets, promoted to u64 for map consistency */
    __u32 pid;
    __u32 tgid;
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct candidate_ts_key);
    __type(value, struct candidate_table);
} irq_candidate_map_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct candidate_ts_key);
    __type(value, struct candidate_table);
} preempt_candidate_map_table SEC(".maps");


static __always_inline int handle_tracepoint_entry(struct trace_preemptirq_entry *ctx, void *map)
{
    struct candidate_table cand_t = {};
    struct candidate_ts_key cand_k = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    cand_k.cpu = bpf_get_smp_processor_id();

    // Store instruction offsets (u32) from the tracepoint context, promoted to u64
    // Note: The caller_offs and parent_offs are expected to be at the start of the
    // tracepoint data payload after the common header.
    cand_t.addrs[START_CALLER_OFF] = (__u64)ctx->caller_offs;
    cand_t.addrs[START_PARENT_OFF] = (__u64)ctx->parent_offs;

    cand_t.pid = pid;
    cand_t.tgid = tgid;
    cand_t.ts = bpf_ktime_get_ns();

    bpf_map_update_elem(map, &cand_k, &cand_t, BPF_ANY);

    return 0;
}

// Tracepoint for IRQ disable
SEC("tp/preemptirq/irq_disable")
int handle_irq_disable(struct trace_preemptirq_entry *ctx)
{
    // The skeleton will automatically attach this to /sys/kernel/tracing/events/preemptirq/irq_disable
    return handle_tracepoint_entry(ctx, &irq_candidate_map_table);
}

// Tracepoint for Preemption disable
SEC("tp/preemptirq/preempt_disable")
int handle_preempt_disable(struct trace_preemptirq_entry *ctx)
{
    // The skeleton will automatically attach this to /sys/kernel/tracing/events/preemptirq/preempt_disable
    return handle_tracepoint_entry(ctx, &preempt_candidate_map_table);
}

