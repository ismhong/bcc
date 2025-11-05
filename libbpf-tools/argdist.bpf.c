// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "argdist.h"
#include "bits.bpf.h"

const volatile __u32 target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct active_probe);
} active_probes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, u64);
	__type(value, struct probe_config);
} probes_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct hist_key);
	__type(value, u64);
} hist_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct freq_key);
	__type(value, u64);
} freq_map SEC(".maps");

static __always_inline bool eval_predicate(struct expr *pred, __u64 value)
{
	if (pred->op == PRED_NONE)
		return true;

	switch (pred->op) {
		case PRED_EQ:  return value == pred->val;
		case PRED_NEQ: return value != pred->val;
		case PRED_GT:  return value > pred->val;
		case PRED_LT:  return value < pred->val;
		case PRED_GE:  return value >= pred->val;
		case PRED_LE:  return value <= pred->val;
		default: return false;
	}
}

SEC("kprobe/dummy_kprobe")
int dummy_kprobe(struct pt_regs *ctx)
{
	__u64 ip = PT_REGS_IP(ctx);
	struct probe_config *config = bpf_map_lookup_elem(&probes_config, &ip);
	if (!config)
		return 0;

	if (config->is_kretprobe) {
		__u64 tid = bpf_get_current_pid_tgid();
		struct active_probe p = { .ip = ip, .entry_ts = bpf_ktime_get_ns() };
		bpf_map_update_elem(&active_probes, &tid, &p, BPF_ANY);
		return 0;
	}

	if (target_pid != 0) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		if ((pid_tgid >> 32) != target_pid) {
			return 0;
		}
	}

	struct expr *expr = &config->exprs[0];
	__u64 value = 0;
	if (expr->source == ARG_PID) value = bpf_get_current_pid_tgid() >> 32;
	else if (expr->source == ARG_CONST_1) value = 1;
	else if (expr->source == ARG1) value = ctx->regs[0];
	else if (expr->source == ARG2) value = ctx->regs[1];
	else if (expr->source == ARG3) value = ctx->regs[2];
	else if (expr->source == ARG4) value = ctx->regs[3];
	else if (expr->source == ARG5) value = ctx->regs[4];
	else return 0;

	if (!eval_predicate(&config->filter, value)) {
		return 0;
	}

	if (config->is_hist) {
		struct hist_key key = { .probe_id = config->id, .slot = log2l(value) };
		u64 *val = bpf_map_lookup_elem(&hist_map, &key);
		if (val)
			__sync_fetch_and_add(val, 1);
		else {
			u64 one = 1;
			bpf_map_update_elem(&hist_map, &key, &one, BPF_NOEXIST);
		}
	} else {
		struct freq_key key = { .probe_id = config->id, .value = value };
		u64 *val = bpf_map_lookup_elem(&freq_map, &key);
		if (val) {
			__sync_fetch_and_add(val, 1);
		} else {
			u64 one = 1;
			bpf_map_update_elem(&freq_map, &key, &one, BPF_NOEXIST);
		}
	}

	return 0;
}

SEC("kretprobe/dummy_kretprobe")
int dummy_kretprobe(struct pt_regs *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct active_probe *p = bpf_map_lookup_elem(&active_probes, &tid);
	if (!p)
		return 0;

	bpf_map_delete_elem(&active_probes, &tid);

	struct probe_config *config = bpf_map_lookup_elem(&probes_config, &p->ip);
	if (!config)
		return 0;

	if (target_pid != 0) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		if ((pid_tgid >> 32) != target_pid) {
			return 0;
		}
	}

	if (config->filter.source == ARG_LATENCY) {
		__u64 latency = bpf_ktime_get_ns() - p->entry_ts;
		if (!eval_predicate(&config->filter, latency))
			return 0;
	}

	struct expr *expr = &config->exprs[0];
	__u64 value = 0;
	if (expr->source == ARG_PID) value = bpf_get_current_pid_tgid() >> 32;
	else if (expr->source == ARG_RET) value = ctx->regs[0];
	else return 0; // Other sources not valid in kretprobe

	if (config->filter.source != ARG_LATENCY) {
		if (!eval_predicate(&config->filter, value))
			return 0;
	}

	if (config->is_hist) {
		struct hist_key key = { .probe_id = config->id, .slot = log2l(value) };
		u64 *val = bpf_map_lookup_elem(&hist_map, &key);
		if (val)
			__sync_fetch_and_add(val, 1);
		else {
			u64 one = 1;
			bpf_map_update_elem(&hist_map, &key, &one, BPF_NOEXIST);
		}
	} else {
		struct freq_key key = { .probe_id = config->id, .value = value };
		u64 *val = bpf_map_lookup_elem(&freq_map, &key);
		if (val) {
			__sync_fetch_and_add(val, 1);
		} else {
			u64 one = 1;
			bpf_map_update_elem(&freq_map, &key, &one, BPF_NOEXIST);
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
