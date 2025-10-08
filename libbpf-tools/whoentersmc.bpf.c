/* SPDX-License-Identifier: GPL-2.0-only */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "whoentersmc.h"
#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4); /* NR_CPUS */
	__type(key, u32);
	__type(value, struct candidate_table);
} candidate_map_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4); /* NR_CPUS */
	__type(key, u32);
	__type(value, struct optee_val_t);
} optee_candidate SEC(".maps");

struct session_uuid_t {
	u32 timeLow;
	u16 timeMid;
	u16 timeHiAndVersion;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct session_uuid_t);
} session_uuid_hash SEC(".maps");

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

static inline int back_ree_world(void *ctx)
{
	struct candidate_table *cand_t;
	__u32 cpu = bpf_get_smp_processor_id();

	cand_t = bpf_map_lookup_elem(&candidate_map_table, &cpu);
	if (!cand_t) {
		bpf_printk("back_ree_world: candidate_map_table lookup failed for cpu %d\n", cpu);
		return 0;
	}

	cand_t->tee_world = 0;

	return 0;
}

SEC("kprobe/__arm_smccc_smc")
int BPF_KPROBE(enter_tee_world)
{
	struct candidate_table *cand_t;
	__u64 pid_tgid;
	__u32 pid, tgid, cpu;

	cpu = bpf_get_smp_processor_id();
	cand_t = bpf_map_lookup_elem(&candidate_map_table, &cpu);
	if (!cand_t) {
		bpf_printk("enter_tee_world: candidate_map_table lookup failed for cpu %d\n", cpu);
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid;
	tgid = pid_tgid >> 32;

	if (bpf_get_current_comm(&cand_t->comm, sizeof(cand_t->comm)) == 0) {
		cand_t->tee_world = 1;
		cand_t->pid = pid;
		cand_t->tgid = tgid;
		cand_t->ts = bpf_ktime_get_ns();
	}
	return 0;
}

SEC("kretprobe/__arm_smccc_smc")
int BPF_KRETPROBE(smc_back_ree_world)
{
	return back_ree_world(ctx);
}

SEC("kprobe/handle_IPI")
int BPF_KPROBE(ipi_back_ree_world)
{
	return back_ree_world(ctx);
}

SEC("tracepoint/irq/irq_handler_entry")
int irq_back_ree_world(void *ctx)
{
	return back_ree_world(ctx);
}

struct trace_event_raw_optee_open_session_exit {
	unsigned long long dev;
	unsigned long long ret;
	unsigned int timeLow;
	unsigned short timeMid;
	unsigned short timeHiAndVersion;
	unsigned char clockSeqAndNode[8];
	unsigned int session;
};

struct trace_event_raw_optee_invoke_func_entry {
	unsigned long long dev;
	unsigned int session;
	unsigned int func;
};

volatile const bool optee_tp = false;
volatile const bool optee_kprobe = false;

SEC("tracepoint/optee/optee_open_session_exit")
int optee_open_session_exit_tp(struct trace_event_raw_optee_open_session_exit *ctx)
{
	struct session_uuid_t *session_uuid_p;
	struct session_uuid_t uuid_zero = {};
	__u32 session = ctx->session;

	session_uuid_p = bpf_map_lookup_or_try_init(&session_uuid_hash, &session, &uuid_zero);
	if (!session_uuid_p) {
		bpf_printk("optee_open_session_exit_tp: session_uuid_hash lookup failed for session %d\n", session);
		return 0;
	}

	session_uuid_p->timeLow = ctx->timeLow;
	session_uuid_p->timeMid = ctx->timeMid;
	session_uuid_p->timeHiAndVersion = ctx->timeHiAndVersion;

	return 0;
}

SEC("tracepoint/optee/optee_invoke_func_entry")
int optee_invoke_func_entry_tp(struct trace_event_raw_optee_invoke_func_entry *ctx)
{
	__u32 cpu_idx = bpf_get_smp_processor_id();
	struct session_uuid_t *session_uuid_p;
	__u32 session = ctx->session;
	struct optee_val_t optee_val;
	struct session_uuid_t uuid_zero = {};

	session_uuid_p = bpf_map_lookup_or_try_init(&session_uuid_hash, &session, &uuid_zero);
	if (!session_uuid_p) {
		bpf_printk("optee_invoke_func_entry_tp: session_uuid_hash lookup failed for session %d\n", session);
		return 0;
	}

	optee_val.timeLow = session_uuid_p->timeLow;
	optee_val.timeMid = session_uuid_p->timeMid;
	optee_val.timeHiAndVersion = session_uuid_p->timeHiAndVersion;
	optee_val.session = session;
	optee_val.func = ctx->func;

	bpf_map_update_elem(&optee_candidate, &cpu_idx, &optee_val, BPF_ANY);

	return 0;
}

SEC("tracepoint/optee/optee_invoke_func_exit")
int optee_invoke_func_exit_tp(void *ctx)
{
	__u32 cpu_idx = bpf_get_smp_processor_id();

	bpf_map_delete_elem(&optee_candidate, &cpu_idx);
	return 0;
}


struct open_session_t {
	__u32 start;
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
	struct open_session_t *open_session_p;
	struct open_session_t open_session_zero = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	bpf_printk(">> optee_open_session: pid[%d]", pid);

	open_session_p = bpf_map_lookup_or_try_init(&open_session_entry_hash, &pid, &open_session_zero);
	if (!open_session_p) {
		bpf_printk("optee_open_session_entry: open_session_entry_hash lookup failed for pid %d\n", pid);
		return 0;
	}
	open_session_p->start = 1;

	return 0;
}

SEC("kprobe/tee_shm_free")
int BPF_KPROBE(tee_shm_free_entry, struct tee_shm_local *shm)
{
	struct open_session_t *open_session_p;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct open_session_t open_session_zero = {};
	__u32 upper, lower, session, pid = pid_tgid;
	struct optee_msg_arg_local *msg_arg;
	u64 val_a;

	open_session_p = bpf_map_lookup_or_try_init(&open_session_entry_hash, &pid, &open_session_zero);
	if (!open_session_p) {
		bpf_printk("tee_shm_free_entry: open_session_entry_hash lookup failed for pid %d\n", pid);
		return 0;
	}
	if (!open_session_p->start) {
		bpf_printk("tee_shm_free_entry: open_session not started for pid %d\n", pid);
		return 0;
	}

	void *kaddr = BPF_PROBE_READ(shm, kaddr);
	if (!kaddr)
		return 0;

	msg_arg = (struct optee_msg_arg_local *)kaddr;
	val_a = BPF_PROBE_READ(msg_arg, params[0].u.value.a);

	upper = __builtin_bswap32(val_a >> 32);
	lower = __builtin_bswap32(val_a);

	session = BPF_PROBE_READ(msg_arg, session);

	struct session_uuid_t *session_uuid_p;
	struct session_uuid_t uuid_zero = {};
	session_uuid_p = bpf_map_lookup_or_try_init(&session_uuid_hash, &session, &uuid_zero);
	if (!session_uuid_p) {
		bpf_printk("tee_shm_free_entry: session_uuid_hash lookup failed for session %d\n", session);
	} else {
		session_uuid_p->timeLow = lower;
		session_uuid_p->timeMid = (upper >> 16);
		session_uuid_p->timeHiAndVersion = (u16)upper;
	}

	open_session_p->start = 0;

	return 0;
}

SEC("kprobe/optee_invoke_func")
int BPF_KPROBE(optee_invoke_func_entry, struct tee_context *context,
		struct tee_ioctl_invoke_arg_local *arg)
{
	struct session_uuid_t *session_uuid_p;
	struct optee_val_t optee_val;
	struct session_uuid_t uuid_zero = {};
	__u32 cpu_idx = bpf_get_smp_processor_id();
	__u32 session = BPF_PROBE_READ(arg, session);

	session_uuid_p = bpf_map_lookup_or_try_init(&session_uuid_hash, &session, &uuid_zero);
	if (!session_uuid_p) {
		bpf_printk("optee_invoke_func_entry: session_uuid_hash lookup failed for session %d\n", session);
		return 0;
	}

	optee_val.timeLow = session_uuid_p->timeLow;
	optee_val.timeMid = session_uuid_p->timeMid;
	optee_val.timeHiAndVersion = session_uuid_p->timeHiAndVersion;
	optee_val.session = session;
	optee_val.func = BPF_PROBE_READ(arg, func);

	bpf_map_update_elem(&optee_candidate, &cpu_idx, &optee_val, BPF_ANY);

	return 0;
}

SEC("kretprobe/optee_invoke_func")
int BPF_KRETPROBE(optee_invoke_func_exit)
{
	__u32 cpu_idx = bpf_get_smp_processor_id();
	struct optee_val_t *optee_val_p;
	struct optee_val_t zero_val = {};

	optee_val_p = bpf_map_lookup_elem(&optee_candidate, &cpu_idx);
	if (!optee_val_p) {
		bpf_printk("optee_invoke_func_exit: optee_candidate lookup failed for cpu %d\n", cpu_idx);
		return 0;
	}
	*optee_val_p = zero_val;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
