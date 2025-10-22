// whoentercriticalstack.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 target_pid = 0;
#define DEFAULT_MAX_CPUS 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DEFAULT_MAX_CPUS);
    __type(key, struct candidate_ts_key);
    __type(value, struct candidate_table);
} candidate_map_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
} stack_traces SEC(".maps");


struct candidate_ts_key {
    __u32 cpu;
};

struct candidate_table {
    __s64 stack_id;
};

static int handle_disable_event(void *ctx)
{
    struct candidate_table cand_t = {};
    struct candidate_ts_key cand_k = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    if (target_pid != 0 && tgid != target_pid) {
        return 0;
    }

    cand_k.cpu = bpf_get_smp_processor_id();

    cand_t.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);

    bpf_map_update_elem(&candidate_map_table, &cand_k, &cand_t, BPF_ANY);

    return 0;
}

static int handle_enable_event(void *ctx)
{
    struct candidate_ts_key cand_k = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    if (target_pid != 0 && tgid != target_pid) {
        return 0;
    }

    cand_k.cpu = bpf_get_smp_processor_id();

    bpf_map_delete_elem(&candidate_map_table, &cand_k);

    return 0;
}

SEC("tp/preemptirq/irq_disable")
int irq_disable_entry(void *ctx)
{
    return handle_disable_event(ctx);
}

SEC("tp/preemptirq/irq_enable")
int irq_enable_entry(void *ctx)
{
    return handle_enable_event(ctx);
}

SEC("tp/preemptirq/preempt_disable")
int preempt_disable_entry(void *ctx)
{
    return handle_disable_event(ctx);
}

SEC("tp/preemptirq/preempt_enable")
int preempt_enable_entry(void *ctx)
{
    return handle_enable_event(ctx);
}
