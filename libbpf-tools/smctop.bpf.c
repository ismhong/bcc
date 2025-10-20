// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "smctop.h"

#define MAX_PID 262144 // TODO: get from /proc/sys/kernel/pid_max

struct task_sched_in {
	u64 ts;
};

struct smc_start {
	u64 smc_start_ts;
	u64 isr_total_latency;
	u64 isr_total_count;
	u64 isr_max_latency;
	u64 schedout_total_latency;
	u64 schedout_max_latency;
	u64 schedout_cnt;
	u32 cur_cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PID);
	__type(key, u32);
	__type(value, struct task_sched_in);
} offcpu_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} irq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct smc_start);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPU_NUM);
	__type(key, u32);
	__type(value, u32);
} smc_call_oncpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct session_uuid_t);
} session_uuid_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct latency_val_t);
} smcc_latency_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct optee_latency_key_t);
	__type(value, struct latency_val_t);
} optee_latency_hash SEC(".maps");

struct smc_session_t {
	u32 session;
	u32 func;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct smc_session_t);
} smcc_session_hash SEC(".maps");


volatile const bool per_optee_call = false;
volatile const bool isr_schout_time = false;
volatile const int core = -1;
volatile const bool ftrace = false;

struct trace_event_raw_optee_open_session_exit {
	unsigned long long dev;
	unsigned long long ret;
	unsigned int timeLow;
	unsigned short timeMid;
	unsigned short timeHiAndVersion;
	unsigned char clockSeqAndNode[8];
	unsigned int session;
};

// include/linux/tee_drv.h
// NOTE: DHC make proprietary changes to this strcuture
struct tee_shm_local {
	struct tee_device *teedev;
	struct tee_context *ctx;
	phys_addr_t paddr;
	void *kaddr;
	size_t size;
	unsigned int offset;
	struct page **pages;
	size_t num_pages;
	refcount_t refcount;
	u32 flags;
	int id;
};

struct optee_msg_param_value_local {
	u64 a;
	u64 b;
	u64 c;
};

struct optee_msg_param_local {
	u64 attr;
	union {
		struct optee_msg_param_tmem tmem;
		struct optee_msg_param_rmem rmem;
		struct optee_msg_param_fmem fmem;
		struct optee_msg_param_value_local value;
		u8 octets[24];
	} u;
};

struct optee_msg_arg_local {
	u32 cmd;
	u32 func;
	u32 session;
	u32 cancel_id;
	u32 pad;
	u32 ret;
	u32 ret_origin;
	u32 num_params;

	/* num_params tells the actual number of element in params */
	struct optee_msg_param_local params[];
};

struct tee_ioctl_invoke_arg_local {
	__u32 func;
	__u32 session;
	__u32 cancel_id;
	__u32 ret;
	__u32 ret_origin;
	__u32 num_params;
	/* num_params tells the actual number of element in params */
	struct tee_ioctl_param params[];
};

SEC("tracepoint/optee/optee_open_session_exit")
int optee_open_session_exit_tp(struct trace_event_raw_optee_open_session_exit *ctx)
{
	struct session_uuid_t session_uuid;
	u32 session = ctx->session;

	session_uuid.timeLow = ctx->timeLow;
	session_uuid.timeMid = ctx->timeMid;
	session_uuid.timeHiAndVersion = ctx->timeHiAndVersion;
	bpf_map_update_elem(&session_uuid_hash, &session, &session_uuid, BPF_ANY);

	if (ftrace)
		bpf_printk("optee_open_session func exit");

	return 0;
}

SEC("tracepoint/optee/optee_close_session_entry")
int optee_close_session_entry_tp(void *ctx)
{
	if (ftrace)
		bpf_printk("optee_close_session func entry");

	return 0;
}

SEC("tracepoint/optee/optee_close_session_exit")
int optee_close_session_exit_tp(void *ctx)
{
	if (ftrace)
		bpf_printk("optee_close_session func exit");

	return 0;
}

struct trace_event_raw_optee_invoke_func_entry {
	unsigned long long dev;
	unsigned int session;
	unsigned int func;
};

SEC("tracepoint/optee/optee_invoke_func_entry")
int optee_invoke_func_entry_tp(struct trace_event_raw_optee_invoke_func_entry *ctx)
{
	struct latency_val_t zero = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;

	bpf_map_update_elem(&smcc_latency_hash, &pid, &zero, BPF_ANY);

	if (ftrace)
		bpf_printk("optee_invoke_func func entry");

	return 0;
}

struct trace_event_raw_optee_invoke_func_exit {
	unsigned long long dev;
	struct tee_ioctl_invoke_arg_local *arg;
	unsigned int ret;
};

SEC("tracepoint/optee/optee_invoke_func_exit")
int optee_invoke_func_exit_tp(struct trace_event_raw_optee_invoke_func_exit *ctx)
{
	struct session_uuid_t uuid_zero = {}, *session_uuid_p;
	u32 session = BPF_PROBE_READ(ctx, arg, session);
	struct optee_latency_key_t optee_key = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct latency_val_t zero = {}, *optee_val_p;
	struct latency_val_t *smcc_val_p;

	session_uuid_p = bpf_map_lookup_elem(&session_uuid_hash, &session);
	if (!session_uuid_p) {
		bpf_map_update_elem(&session_uuid_hash, &session, &uuid_zero, BPF_NOEXIST);
		session_uuid_p = bpf_map_lookup_elem(&session_uuid_hash, &session);
		if (!session_uuid_p)
			return 0;
	}

	smcc_val_p = bpf_map_lookup_elem(&smcc_latency_hash, &pid);
	if (!smcc_val_p)
		return 0;

	optee_key.tgid = pid_tgid >> 32;
	optee_key.pid = pid;
	bpf_get_current_comm(&optee_key.name, sizeof(optee_key.name));
	optee_key.timeLow = session_uuid_p->timeLow;
	optee_key.timeMid = session_uuid_p->timeMid;
	optee_key.timeHiAndVersion = session_uuid_p->timeHiAndVersion;
	optee_key.session = session;
	optee_key.func = BPF_PROBE_READ(ctx, arg, func);

	optee_val_p = bpf_map_lookup_elem(&optee_latency_hash, &optee_key);
	if (!optee_val_p) {
		bpf_map_update_elem(&optee_latency_hash, &optee_key, &zero, BPF_NOEXIST);
		optee_val_p = bpf_map_lookup_elem(&optee_latency_hash, &optee_key);
		if (!optee_val_p)
			return 0;
	}

	optee_val_p->total_latency += smcc_val_p->total_latency;
	optee_val_p->isr_total_latency += smcc_val_p->isr_total_latency;
	optee_val_p->schedout_total_latency += smcc_val_p->schedout_total_latency;

	if (per_optee_call) {
		optee_val_p->total_count++;
		if (optee_val_p->max == 0 || smcc_val_p->total_latency > optee_val_p->max)
			optee_val_p->max = smcc_val_p->total_latency;
		if (optee_val_p->min == 0 || smcc_val_p->total_latency < optee_val_p->min)
			optee_val_p->min = smcc_val_p->total_latency;
		optee_val_p->isr_total_count++;
		if (optee_val_p->isr_max == 0 || smcc_val_p->isr_max > optee_val_p->isr_max)
			optee_val_p->isr_max = smcc_val_p->isr_total_latency;
		optee_val_p->schedout_total_count++;
		if (optee_val_p->schedout_max == 0 || smcc_val_p->schedout_max > optee_val_p->schedout_max)
			optee_val_p->schedout_max = smcc_val_p->schedout_total_latency;
	} else {
		optee_val_p->total_count += smcc_val_p->total_count;
		if (optee_val_p->max == 0 || smcc_val_p->max > optee_val_p->max)
			optee_val_p->max = smcc_val_p->max;
		if (optee_val_p->min == 0 || smcc_val_p->min < optee_val_p->min)
			optee_val_p->min = smcc_val_p->min;
		optee_val_p->isr_total_count += smcc_val_p->isr_total_count;
		if (optee_val_p->isr_max == 0 || smcc_val_p->isr_max > optee_val_p->isr_max)
			optee_val_p->isr_max = smcc_val_p->isr_max;
		optee_val_p->schedout_total_count += smcc_val_p->schedout_total_count;
		if (optee_val_p->schedout_max == 0 || smcc_val_p->schedout_max > optee_val_p->schedout_max)
			optee_val_p->schedout_max = smcc_val_p->schedout_max;
	}

	if (ftrace) {
		if (isr_schout_time) {
			bpf_printk("optee_invoke_func func exit: INVOKE_latency(us) = %llu, INVOKE_latency(us) - ISR_latency(us) - SCHOUT_latency(us) = %llu",
				smcc_val_p->total_latency,
				smcc_val_p->total_latency - (smcc_val_p->isr_total_latency + smcc_val_p->schedout_total_latency));
		} else {
			bpf_printk("optee_invoke_func func return: INVOKE_latency(us) = %llu, INVOKE_latency(us) + ISR_latency(us) + SCHOUT_latency(us) = %llu",
				smcc_val_p->total_latency,
				smcc_val_p->total_latency + (smcc_val_p->isr_total_latency + smcc_val_p->schedout_total_latency));
		}
		bpf_printk("invoke_return_stat: INVOKE_MAX_ISR_latency(us) = %llu, INVOKE_TOTAL_ISR_latency(us) = %llu, INVOKE_ISR_CNT = %llu",
			smcc_val_p->isr_max, smcc_val_p->isr_total_latency, smcc_val_p->isr_total_count);
		bpf_printk("invoke_return_stat: INVOKE_MAX_SCHOUT_latency(us) = %llu, INVOKE_TOTAL_SCHOUT_latency(us) = %llu, INVOKE_SCHOUT_CNT = %llu",
			smcc_val_p->schedout_max, smcc_val_p->schedout_total_latency, smcc_val_p->schedout_total_count);
	}

	bpf_map_delete_elem(&smcc_latency_hash, &pid);

	return 0;
}

struct open_session_t {
	u32 start;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct open_session_t);
} open_session_entry_hash SEC(".maps");

SEC("kprobe/optee_open_session")
int BPF_KPROBE(optee_open_session_entry)
{
	struct open_session_t open_session = { .start = 1 };
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;

	bpf_map_update_elem(&open_session_entry_hash, &pid, &open_session, BPF_ANY);

	if (ftrace)
		bpf_printk("optee_open_session func entry");

	return 0;
}

SEC("kprobe/optee_close_session")
int BPF_KPROBE(optee_close_session_entry)
{
	if (ftrace)
		bpf_printk("optee_close_session func entry");

	return 0;
}

SEC("kretprobe/optee_close_session")
int BPF_KRETPROBE(optee_close_session_exit)
{
	if (ftrace)
		bpf_printk("optee_close_session func exit");

	return 0;
}

SEC("kprobe/tee_shm_free")
int BPF_KPROBE(tee_shm_free_entry, struct tee_shm_local *shm)
{
	struct session_uuid_t session_uuid = {};
	struct open_session_t *open_session_p;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 upper, lower, session, pid = pid_tgid;
	void *kaddr;
	struct optee_msg_arg_local *msg_arg;
	u64 val_a;

	open_session_p = bpf_map_lookup_elem(&open_session_entry_hash, &pid);
	if (!open_session_p || !open_session_p->start)
		return 0;

	kaddr = BPF_PROBE_READ(shm, kaddr);
	if (!kaddr)
		return 0;

	msg_arg = (struct optee_msg_arg_local*)kaddr;
	val_a = BPF_PROBE_READ(msg_arg, params[0].u.value.a);

	upper = __builtin_bswap32(val_a >> 32);
	lower = __builtin_bswap32(val_a);

	session = BPF_PROBE_READ(msg_arg, session);
	session_uuid.timeLow = lower;
	session_uuid.timeMid = (upper >> 16);
	session_uuid.timeHiAndVersion = (u16)upper;
	bpf_map_update_elem(&session_uuid_hash, &session, &session_uuid, BPF_ANY);

	open_session_p->start = 0;

	return 0;
}

SEC("kprobe/optee_invoke_func")
int BPF_KPROBE(optee_invoke_func_entry, struct tee_context *context, struct tee_ioctl_invoke_arg_local *arg)
{
	struct latency_val_t zero = {};
	struct smc_session_t session_uuid;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;

	bpf_map_update_elem(&smcc_latency_hash, &pid, &zero, BPF_ANY);

	session_uuid.session = BPF_PROBE_READ(arg, session);
	session_uuid.func = BPF_PROBE_READ(arg, func);
	bpf_map_update_elem(&smcc_session_hash, &pid, &session_uuid, BPF_ANY);

	if (ftrace)
		bpf_printk("optee_invoke_func func entry");

	return 0;
}

SEC("kretprobe/optee_invoke_func")
int BPF_KRETPROBE(optee_invoke_func_exit)
{
	struct session_uuid_t uuid_zero = {}, *session_uuid_p;
	struct optee_latency_key_t optee_key = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 session, pid = pid_tgid;
	struct latency_val_t zero = {}, *optee_val_p;
	struct latency_val_t *smcc_val_p;
	struct smc_session_t *smcc_session_p;

	smcc_session_p = bpf_map_lookup_elem(&smcc_session_hash, &pid);
	if (!smcc_session_p)
		return 0;

	session = smcc_session_p->session;
	session_uuid_p = bpf_map_lookup_elem(&session_uuid_hash, &session);
	if (!session_uuid_p) {
		bpf_map_update_elem(&session_uuid_hash, &session, &uuid_zero, BPF_NOEXIST);
		session_uuid_p = bpf_map_lookup_elem(&session_uuid_hash, &session);
		if (!session_uuid_p)
			return 0;
	}

	smcc_val_p = bpf_map_lookup_elem(&smcc_latency_hash, &pid);
	if (!smcc_val_p)
		return 0;

	optee_key.tgid = pid_tgid >> 32;
	optee_key.pid = pid;
	bpf_get_current_comm(&optee_key.name, sizeof(optee_key.name));
	optee_key.timeLow = session_uuid_p->timeLow;
	optee_key.timeMid = session_uuid_p->timeMid;
	optee_key.timeHiAndVersion = session_uuid_p->timeHiAndVersion;
	optee_key.session = session;
	optee_key.func = smcc_session_p->func;

	optee_val_p = bpf_map_lookup_elem(&optee_latency_hash, &optee_key);
	if (!optee_val_p) {
		bpf_map_update_elem(&optee_latency_hash, &optee_key, &zero, BPF_NOEXIST);
		optee_val_p = bpf_map_lookup_elem(&optee_latency_hash, &optee_key);
		if (!optee_val_p)
			return 0;
	}

	optee_val_p->total_latency += smcc_val_p->total_latency;
	optee_val_p->isr_total_latency += smcc_val_p->isr_total_latency;
	optee_val_p->schedout_total_latency += smcc_val_p->schedout_total_latency;

	if (per_optee_call) {
		optee_val_p->total_count++;
		if (optee_val_p->max == 0 || smcc_val_p->total_latency > optee_val_p->max)
			optee_val_p->max = smcc_val_p->total_latency;
		if (optee_val_p->min == 0 || smcc_val_p->total_latency < optee_val_p->min)
			optee_val_p->min = smcc_val_p->total_latency;
		optee_val_p->isr_total_count++;
		if (optee_val_p->isr_max == 0 || smcc_val_p->isr_max > optee_val_p->isr_max)
			optee_val_p->isr_max = smcc_val_p->isr_total_latency;
		optee_val_p->schedout_total_count++;
		if (optee_val_p->schedout_max == 0 || smcc_val_p->schedout_max > optee_val_p->schedout_max)
			optee_val_p->schedout_max = smcc_val_p->schedout_total_latency;
	} else {
		optee_val_p->total_count += smcc_val_p->total_count;
		if (optee_val_p->max == 0 || smcc_val_p->max > optee_val_p->max)
			optee_val_p->max = smcc_val_p->max;
		if (optee_val_p->min == 0 || smcc_val_p->min < optee_val_p->min)
			optee_val_p->min = smcc_val_p->min;
		optee_val_p->isr_total_count += smcc_val_p->isr_total_count;
		if (optee_val_p->isr_max == 0 || smcc_val_p->isr_max > optee_val_p->isr_max)
			optee_val_p->isr_max = smcc_val_p->isr_max;
		optee_val_p->schedout_total_count += smcc_val_p->schedout_total_count;
		if (optee_val_p->schedout_max == 0 || smcc_val_p->schedout_max > optee_val_p->schedout_max)
			optee_val_p->schedout_max = smcc_val_p->schedout_max;
	}

	if (ftrace) {
		if (isr_schout_time) {
			bpf_printk("optee_invoke_func func exit: INVOKE_latency(us) = %llu, INVOKE_latency(us) - ISR_latency(us) - SCHOUT_latency(us) = %llu",
				smcc_val_p->total_latency,
				smcc_val_p->total_latency - (smcc_val_p->isr_total_latency + smcc_val_p->schedout_total_latency));
		} else {
			bpf_printk("optee_invoke_func func return: INVOKE_latency(us) = %llu, INVOKE_latency(us) + ISR_latency(us) + SCHOUT_latency(us) = %llu",
				smcc_val_p->total_latency,
				smcc_val_p->total_latency + (smcc_val_p->isr_total_latency + smcc_val_p->schedout_total_latency));
		}
		bpf_printk("invoke_return_stat: INVOKE_MAX_ISR_latency(us) = %llu, INVOKE_TOTAL_ISR_latency(us) = %llu, INVOKE_ISR_CNT = %llu",
			smcc_val_p->isr_max, smcc_val_p->isr_total_latency, smcc_val_p->isr_total_count);
		bpf_printk("invoke_return_stat: INVOKE_MAX_SCHOUT_latency(us) = %llu, INVOKE_TOTAL_SCHOUT_latency(us) = %llu, INVOKE_SCHOUT_CNT = %llu",
			smcc_val_p->schedout_max, smcc_val_p->schedout_total_latency, smcc_val_p->schedout_total_count);
	}

	bpf_map_delete_elem(&smcc_latency_hash, &pid);
	bpf_map_delete_elem(&smcc_session_hash, &pid);

	return 0;
}

struct sched_migrate_task_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char comm[16];
	int pid;
	int orig_cpu;
	int dest_cpu;
};

SEC("tracepoint/sched/sched_migrate_task")
int sched_migrate_task_tp(struct sched_migrate_task_ctx *ctx)
{
	u32 *smc_call_pid_p, zero = 0;
	u32 pid = ctx->pid;
	int orig_cpu = ctx->orig_cpu;
	int dest_cpu = ctx->dest_cpu;

	smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &orig_cpu);
	if (smc_call_pid_p && *smc_call_pid_p != 0) {
		if (pid == *smc_call_pid_p) {
			*smc_call_pid_p = 0;

			smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &dest_cpu);
			if (!smc_call_pid_p) {
				bpf_map_update_elem(&smc_call_oncpu, &dest_cpu, &zero, BPF_NOEXIST);
				smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &dest_cpu);
				if (!smc_call_pid_p)
					return 0;
			}

			*smc_call_pid_p = pid;

			struct smc_start *smc_start_p = bpf_map_lookup_elem(&start, &pid);
			if (!smc_start_p)
				return 0;

			smc_start_p->cur_cpu = dest_cpu;

			if (ftrace)
				bpf_printk("sched_migrate_task: comm=%s orig_cpu=%d dest_cpu=%d", ctx->comm, orig_cpu, dest_cpu);
		}
	}

	return 0;
}

static inline int sum_duration(u64 pid_tgid, u32 next_pid, u32 smc_call_pid)
{
	u64 ts = bpf_ktime_get_ns();
	u32 pid = pid_tgid;
	struct task_sched_in info = {};
	u32 idx = bpf_get_smp_processor_id();

	if (core != -1 && idx != core)
		return 0;

	if (pid == next_pid)
		return 0;

	if (next_pid != smc_call_pid)
		goto failed;

	struct task_sched_in *data = bpf_map_lookup_elem(&offcpu_start, &next_pid);
	if (!data || !data->ts)
		goto failed;

	if (ts < data->ts)
		goto failed;

	u64 delta = (ts - data->ts) / 1000;
	data->ts = 0;

	struct smc_start *smc_start_p = bpf_map_lookup_elem(&start, &smc_call_pid);
	if (!smc_start_p)
		return 0;

	smc_start_p->schedout_cnt++;
	smc_start_p->schedout_total_latency += delta;
	if (delta > smc_start_p->schedout_max_latency)
		smc_start_p->schedout_max_latency = delta;

failed:
	if (pid != smc_call_pid)
		return 0;

	info.ts = ts;
	bpf_map_update_elem(&offcpu_start, &pid, &info, BPF_ANY);

	return 0;
}

struct sched_switch_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int sched_switch_tp(struct sched_switch_ctx *ctx)
{
	u32 *smc_call_pid_p, idx = bpf_get_smp_processor_id();
	u32 pid, next_pid = ctx->next_pid;
	u64 pid_tgid;

	if (core != -1 && idx != core)
		return 0;

	smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (smc_call_pid_p && *smc_call_pid_p != 0) {
		u32 smc_call_pid = *smc_call_pid_p;
		pid_tgid = bpf_get_current_pid_tgid();
		pid = pid_tgid;
		if ((smc_call_pid == pid) || (smc_call_pid == next_pid))
			sum_duration(pid_tgid, next_pid, smc_call_pid);
		if (ftrace) {
			bpf_printk("schedule_exit : prev_state=%lld prev_prio=%d",
					ctx->prev_state, ctx->prev_prio);
			bpf_printk("schedule_entry: next_comm=%s next_pid=%d next_prio=%d",
					ctx->next_comm, next_pid, ctx->next_prio);
		}
	}

	return 0;
}

struct irq_handler_entry_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int irq;
	__u32 name;
};

#define TP_DATA_LOC_READ_STR(dst, field, length)                               \
	do {                                                                   \
		unsigned short __offset = ctx->field & 0xFFFF;        \
		bpf_probe_read_str((void *)dst, length, (char *)ctx + __offset);   \
	} while (0)

SEC("tracepoint/irq/irq_handler_entry")
int irq_handler_entry_tp(struct irq_handler_entry_ctx *ctx)
{
	struct smc_start *smc_start_p;
	u32 *smc_call_oncpus_p, pid, idx = bpf_get_smp_processor_id();

	smc_call_oncpus_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (smc_call_oncpus_p && *smc_call_oncpus_p > 0) {
		pid = *smc_call_oncpus_p;
		smc_start_p = bpf_map_lookup_elem(&start, &pid);
		if (!smc_start_p)
			return 0;

		struct task_sched_in *data = bpf_map_lookup_elem(&offcpu_start, &pid);
		if (!data || !data->ts) {
			if (idx == smc_start_p->cur_cpu) {
				u64 ts = bpf_ktime_get_ns();
				bpf_map_update_elem(&irq_start, &pid, &ts, BPF_ANY);
			}
		}
	}

	if (ftrace) {
		char irqname[32];
		TP_DATA_LOC_READ_STR(irqname, name, sizeof(irqname));
		bpf_printk("domain_irq_entry irq=%d name=%s\n", ctx->irq, irqname);
	}

	return 0;
}

struct irq_handler_exit_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int irq;
	int ret;
};

SEC("tracepoint/irq/irq_handler_exit")
int irq_handler_exit_tp(struct irq_handler_exit_ctx *ctx)
{
	struct smc_start *smc_start_p;
	u32 *smc_call_oncpus_p, pid, idx = bpf_get_smp_processor_id();
	u64 delta = 0;

	smc_call_oncpus_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (smc_call_oncpus_p && *smc_call_oncpus_p > 0) {
		pid = *smc_call_oncpus_p;
		smc_start_p = bpf_map_lookup_elem(&start, &pid);
		if (!smc_start_p)
			return 0;

		struct task_sched_in *data = bpf_map_lookup_elem(&offcpu_start, &pid);
		if (!data || !data->ts) {
			if (idx == smc_start_p->cur_cpu) {
				u64 *irq_start_p;

				if (core != -1 && idx != core)
					return 0;

				irq_start_p = bpf_map_lookup_elem(&irq_start, &pid);
				if (!irq_start_p)
					return 0;

				delta = (bpf_ktime_get_ns() - *irq_start_p) / 1000;

				smc_start_p->isr_total_count++;
				smc_start_p->isr_total_latency += delta;
				if (delta > smc_start_p->isr_max_latency)
					smc_start_p->isr_max_latency = delta;

				bpf_map_delete_elem(&irq_start, &pid);
			}
		}
	}

	if (ftrace) {
		if (delta)
			bpf_printk("domain_irq_exit irq=%d, ISR latency(us) = %llu", ctx->irq, delta);
		else
			bpf_printk("domain_irq_exit irq=%d", ctx->irq);
	}

	return 0;
}

SEC("kprobe/handle_IPI")
int BPF_KPROBE(inter_processor_irq_entry)
{
	struct smc_start *smc_start_p;
	u32 *smc_call_oncpus_p, pid, idx = bpf_get_smp_processor_id();

	smc_call_oncpus_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (smc_call_oncpus_p && *smc_call_oncpus_p > 0) {
		pid = *smc_call_oncpus_p;
		smc_start_p = bpf_map_lookup_elem(&start, &pid);
		if (!smc_start_p)
			return 0;

		struct task_sched_in *data = bpf_map_lookup_elem(&offcpu_start, &pid);
		if (!data || !data->ts) {
			if (idx == smc_start_p->cur_cpu) {
				u64 ts = bpf_ktime_get_ns();
				bpf_map_update_elem(&irq_start, &pid, &ts, BPF_ANY);
			}
		}
		if (ftrace)
			bpf_printk("inter_processor_irq_entry");
	}

	return 0;
}

SEC("kprobe/__arm_smccc_smc")
int BPF_KPROBE(trace_func_entry)
{
	struct latency_val_t *smcc_latency_val_p;
	struct smc_start smc_start_info = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 *smc_call_pid_p, zero = 0;
	u32 pid = pid_tgid, idx = bpf_get_smp_processor_id();

	if (core != -1 && idx != core)
		return 0;

	smc_start_info.cur_cpu = idx;
	smc_start_info.smc_start_ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &smc_start_info, BPF_ANY);

	smcc_latency_val_p = bpf_map_lookup_elem(&smcc_latency_hash, &pid);
	if (!smcc_latency_val_p)
		return 0;

	if (ftrace)
		bpf_printk("__arm_smccc_smc func entry");

	smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (!smc_call_pid_p) {
		bpf_map_update_elem(&smc_call_oncpu, &idx, &zero, BPF_NOEXIST);
		smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
		if (!smc_call_pid_p)
			return 0;
	}

	*smc_call_pid_p = pid;

	return 0;
}

SEC("kretprobe/__arm_smccc_smc")
int BPF_KRETPROBE(trace_func_return)
{
	struct latency_val_t *smcc_latency_val_p;
	struct smc_start *smc_start_p;
	u64 delta, isr_latency = 0, schedout_latency = 0;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 *smc_call_pid_p, zero = 0;
	u32 pid = pid_tgid, idx = bpf_get_smp_processor_id();

	if (core != -1 && idx != core)
		return 0;

	smc_start_p = bpf_map_lookup_elem(&start, &pid);
	if (!smc_start_p)
		return 0;

	smcc_latency_val_p = bpf_map_lookup_elem(&smcc_latency_hash, &pid);
	if (!smcc_latency_val_p)
		return 0;

	delta = (bpf_ktime_get_ns() - smc_start_p->smc_start_ts) / 1000;

	if (smc_start_p->isr_total_count) {
		isr_latency = smc_start_p->isr_total_latency;
		if (!isr_schout_time)
			delta -= isr_latency;

		smcc_latency_val_p->isr_total_latency += isr_latency;
		smcc_latency_val_p->isr_total_count += smc_start_p->isr_total_count;
		if (smc_start_p->isr_max_latency > smcc_latency_val_p->isr_max)
			smcc_latency_val_p->isr_max = smc_start_p->isr_max_latency;
	}

	if (smc_start_p->schedout_cnt) {
		schedout_latency = smc_start_p->schedout_total_latency;
		if (!isr_schout_time)
			delta -= schedout_latency;

		smcc_latency_val_p->schedout_total_latency += schedout_latency;
		smcc_latency_val_p->schedout_total_count += smc_start_p->schedout_cnt;
		if (smc_start_p->schedout_max_latency > smcc_latency_val_p->schedout_max)
			smcc_latency_val_p->schedout_max = smc_start_p->schedout_max_latency;
	}

	smcc_latency_val_p->total_latency += delta;
	smcc_latency_val_p->total_count++;
	if (smcc_latency_val_p->max == 0 || delta > smcc_latency_val_p->max)
		smcc_latency_val_p->max = delta;
	if (smcc_latency_val_p->min == 0 || delta < smcc_latency_val_p->min)
		smcc_latency_val_p->min = delta;

	if (ftrace) {
		if (isr_schout_time) {
			bpf_printk("__arm_smccc_smc func return: SMCCC_latency(us) = %llu, SMCCC_latency(us) - ISR_latency(us) - SCHOUT_latency(us) = %llu",
				delta, delta - (isr_latency + schedout_latency));
		} else {
			bpf_printk("__arm_smccc_smc func return: SMCCC_latency(us) = %llu, SMCCC_latency(us) + ISR_latency(us) + SCHOUT_latency(us) = %llu",
				delta, delta + (isr_latency + schedout_latency));
		}
		bpf_printk("smc_return_stat: SMCCC_MAX_ISR_latency(us) = %llu, SMCCC_TOTAL_ISR_latency(us) = %llu, SMCCC_ISR_CNT = %llu",
			smc_start_p->isr_max_latency, smc_start_p->isr_total_latency, smc_start_p->isr_total_count);
		bpf_printk("smc_return_stat: SMCCC_MAX_SCHOUT_latency(us) = %llu, SMCCC_TOTAL_SCHOUT_latency(us) = %llu, SMCCC_SCHOUT_CNT = %llu",
			smc_start_p->schedout_max_latency, smc_start_p->schedout_total_latency, smc_start_p->schedout_cnt);
	}

	bpf_map_delete_elem(&start, &pid);

	smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
	if (!smc_call_pid_p) {
		bpf_map_update_elem(&smc_call_oncpu, &idx, &zero, BPF_NOEXIST);
		smc_call_pid_p = bpf_map_lookup_elem(&smc_call_oncpu, &idx);
		if (!smc_call_pid_p)
			return 0;
	}

	*smc_call_pid_p = 0;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
