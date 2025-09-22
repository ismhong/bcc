// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Realtek, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-MAX_ERRNO)

// Manually define struct event here to ensure it's seen
#define TASK_COMM_LEN 16
struct event {
	__u32 pid;
	__u32 tgid;
	__u32 programID;
	__u32 versionID;
	__u32 procedureID;
	__u32 taskID;
	__u32 parameterSize;
	__u32 mycontext;
	__u64 refclk;
	__s32 rpc_num;
	char comm[TASK_COMM_LEN];
};

// Manually define tracepoint structs, as they are not in vmlinux.h for custom tracepoints
struct trace_event_raw_rtk_rpc_peek_rpc_common {
	struct trace_entry ent;
	u32 programID;
	u32 versionID;
	u32 procedureID;
	u32 taskID;
	u32 parameterSize;
	u32 mycontext;
	u32 refclk;
	int num;
	char __data[0];
};

#define trace_event_raw_rtk_rpc_peek_rpc_request trace_event_raw_rtk_rpc_peek_rpc_common
#define trace_event_raw_rtk_rpc_peek_rpc_reply trace_event_raw_rtk_rpc_peek_rpc_common

// Manually define Realtek-specific structs for kprobes
struct rpc_struct {
	u32 programID;
	u32 versionID;
	u32 procedureID;
	u32 taskID;
	u32 sysTID;
	u32 sysPID;
	u32 parameterSize;
	u32 mycontext;
};

struct remote_cpu_info {
	char name[10];
	int to_rcpu_notify_bit;
	int to_rcpu_feedback_bit;
	int from_rcpu_notify_bit;
	int from_rcpu_feedback_bit;
	int to_rcpu_intr_bit;
	int from_rcpu_intr_bit;
	int intr_en;
	int big_endian;
	int id;
	void *isr;
	void *send_interrupt;
};

struct rtk_rcpu {
	struct device *dev;
	struct device_node *of_node;
	int irq;
	struct regmap *rcpu_intr_regmap;
	struct list_head channels;
	struct hwspinlock *hwlock;
	const struct remote_cpu_info *info;
	volatile u32 *rcpu_notify;
	volatile u32 *sync_flag;
	int status;
	struct rtk_rpmsg_device *rtk_rpdev;
};

struct rpc_shm_info {
	union {
		void *av;
		void *hifi;
		void *kr4;
	};
};

struct rtk_rpmsg_channel {
	struct rtk_rcpu *rcpu;
	struct rtk_rpmsg_device *rtk_rpdev;
	struct tasklet_struct tasklet;
	struct rpc_shm_info tx_info;
	struct rpc_shm_info rx_info;
	void *tx_fifo;
	void *rx_fifo;
	char name[32];
	u32 id;
	struct list_head list;
	struct list_head rtk_ept_lists;
	spinlock_t txlock;
	spinlock_t rxlock;
	spinlock_t list_lock;
	void *handle_data;
	struct dentry *debugfs_node;
	struct idr ept_ids;
	struct mutex ept_ids_lock;
	int use_idr;
};

#ifndef EAGAIN
#define EAGAIN 11
#endif

#define RPC_PG_ID_R_PROGRAM 98
#define RPC_PG_ID_REPLYID 99

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Common variables
const volatile __u32 target_programID = 0;

// For USE_RPMSG mode
struct rpc_data {
	__u32 programID;
	__u32 versionID;
	__u32 procedureID;
	__u32 taskID;
	__u32 parameterSize;
	__u32 mycontext;
	int rpc_num;
};

struct rcpu_data_t {
	int rpc_num;
	__u32 big_endian;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rpc_data);
} rpc_data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rcpu_data_t);
} rcpu_data_map SEC(".maps");

// For USE_RPC mode (tracepoints)
SEC("tracepoint/rtk_rpc/rtk_rpc_peek_rpc_request")
int rtk_rpc_peek_rpc_request(struct trace_event_raw_rtk_rpc_peek_rpc_request *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	struct event *e;

	if (target_programID && ctx->programID != target_programID) {
		bpf_printk("rpcsnoop: req filter programID: %u\n", ctx->programID);
		return 0;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_printk("rpcsnoop: req ringbuf_reserve failed\n");
		return 0;
	}

	e->pid = pid;
	e->tgid = tgid;
	e->programID = ctx->programID;
	e->versionID = ctx->versionID;
	e->procedureID = ctx->procedureID;
	e->taskID = ctx->taskID;
	e->parameterSize = ctx->parameterSize;
	e->mycontext = ctx->mycontext;
	e->refclk = ctx->refclk;
	e->rpc_num = ctx->num;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/rtk_rpc/rtk_rpc_peek_rpc_reply")
int rtk_rpc_peek_rpc_reply(struct trace_event_raw_rtk_rpc_peek_rpc_reply *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	struct event *e;

	if (target_programID && ctx->programID != target_programID) {
		bpf_printk("rpcsnoop: reply filter programID: %u\n", ctx->programID);
		return 0;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_printk("rpcsnoop: reply ringbuf_reserve failed\n");
		return 0;
	}

	e->pid = pid;
	e->tgid = tgid;
	e->programID = ctx->programID;
	e->versionID = ctx->versionID;
	e->procedureID = ctx->procedureID;
	e->taskID = ctx->taskID;
	e->parameterSize = ctx->parameterSize;
	e->mycontext = ctx->mycontext;
	e->refclk = ctx->refclk;
	e->rpc_num = ctx->num;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// For USE_RPMSG mode (kprobes)
SEC("kprobe/__rtk_rpmsg_send")
int BPF_KPROBE(__rtk_rpmsg_send, struct rtk_rpmsg_channel *channel,
		const void *data, int len, bool block)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	struct rpc_data buf = {};
	struct rpc_struct rpc_info;
	struct rtk_rcpu *rcpu;
	const struct remote_cpu_info *info;
	__u32 task_id_val;

	if (bpf_probe_read_kernel(&rpc_info, sizeof(rpc_info), data) < 0) {
		bpf_printk("rpcsnoop: send probe_read_kernel(rpc_info) failed\n");
		return 0;
	}
	rcpu = BPF_CORE_READ(channel, rcpu);
	info = BPF_CORE_READ(rcpu, info);

	if (BPF_CORE_READ(info, big_endian)) {
		buf.programID = bpf_ntohl(rpc_info.programID);
		buf.versionID = bpf_ntohl(rpc_info.versionID);
		buf.procedureID = bpf_ntohl(rpc_info.procedureID);
		if (buf.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					(char *)data + sizeof(struct rpc_struct));
			buf.taskID = bpf_ntohl(task_id_val);
		} else {
			buf.taskID = bpf_ntohl(rpc_info.taskID);
		}
		buf.parameterSize = bpf_ntohl(rpc_info.parameterSize);
		buf.mycontext = bpf_ntohl(rpc_info.mycontext);
	} else {
		buf.programID = rpc_info.programID;
		buf.versionID = rpc_info.versionID;
		buf.procedureID = rpc_info.procedureID;
		if (buf.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					(char *)data + sizeof(struct rpc_struct));
			buf.taskID = task_id_val;
		} else {
			buf.taskID = rpc_info.taskID;
		}
		buf.parameterSize = rpc_info.parameterSize;
		buf.mycontext = rpc_info.mycontext;
	}

	if (buf.programID == RPC_PG_ID_REPLYID)
		buf.rpc_num = 0;
	else
		buf.rpc_num = BPF_CORE_READ(info, id);

	bpf_map_update_elem(&rpc_data_map, &pid, &buf, BPF_ANY);

	return 0;
}

SEC("kretprobe/__rtk_rpmsg_send")
int BPF_KRETPROBE(__rtk_rpmsg_send_ret, int ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	struct rpc_data *buf;
	struct event *e;

	if (ret == -EAGAIN) {
		bpf_printk("rpcsnoop: send_ret ret is -EAGAIN\n");
		goto out;
	}

	buf = bpf_map_lookup_elem(&rpc_data_map, &pid);
	if (!buf) {
		bpf_printk("rpcsnoop: send_ret lookup failed, pid: %u\n", pid);
		return 0;
	}

	if (target_programID && buf->programID != target_programID) {
		bpf_printk("rpcsnoop: send_ret filter programID: %u\n", buf->programID);
		goto out;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_printk("rpcsnoop: send_ret ringbuf_reserve failed\n");
		goto out;
	}

	e->pid = pid;
	e->tgid = tgid;
	e->programID = buf->programID;
	e->versionID = buf->versionID;
	e->procedureID = buf->procedureID;
	e->taskID = buf->taskID;
	e->parameterSize = buf->parameterSize;
	e->mycontext = buf->mycontext;
	e->refclk = bpf_ktime_get_ns();
	e->rpc_num = buf->rpc_num;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

out:
	bpf_map_delete_elem(&rpc_data_map, &pid);
	return 0;
}

SEC("kprobe/get_ring_data")
int BPF_KPROBE(get_ring_data, struct rtk_rpmsg_channel *channel, int *retSize,
		struct rpc_struct *rpc)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	struct rcpu_data_t rcpu_info = {};
	struct rtk_rcpu *rcpu;
	const struct remote_cpu_info *info;

	rcpu = BPF_CORE_READ(channel, rcpu);
	info = BPF_CORE_READ(rcpu, info);

	rcpu_info.rpc_num = BPF_CORE_READ(info, id);
	rcpu_info.big_endian = BPF_CORE_READ(info, big_endian);

	bpf_map_update_elem(&rcpu_data_map, &pid, &rcpu_info, BPF_ANY);

	return 0;
}

SEC("kretprobe/get_ring_data")
int BPF_KRETPROBE(get_ring_data_ret, char *ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	struct rpc_struct rpc_buf;
	struct rcpu_data_t *rcpu_info;
	struct event *e;
	__u32 task_id_val;

	if (IS_ERR_VALUE(ret)) {
		bpf_printk("rpcsnoop: get_ring_data_ret ret is err or null: %ld\n", (long)ret);
		goto out;
	}

	rcpu_info = bpf_map_lookup_elem(&rcpu_data_map, &pid);
	if (!rcpu_info) {
		bpf_printk("rpcsnoop: get_ring_data_ret lookup failed, pid: %u\n", pid);
		return 0;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_printk("rpcsnoop: get_ring_data_ret ringbuf_reserve failed\n");
		goto out;
	}

	bpf_probe_read_kernel(&rpc_buf, sizeof(rpc_buf), ret);

	if (rcpu_info->big_endian) {
		e->programID = bpf_ntohl(rpc_buf.programID);
		e->versionID = bpf_ntohl(rpc_buf.versionID);
		e->procedureID = bpf_ntohl(rpc_buf.procedureID);
		if (e->programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			e->taskID = bpf_ntohl(task_id_val);
		} else {
			e->taskID = bpf_ntohl(rpc_buf.taskID);
		}
		e->parameterSize = bpf_ntohl(rpc_buf.parameterSize);
		e->mycontext = bpf_ntohl(rpc_buf.mycontext);
	} else {
		e->programID = rpc_buf.programID;
		e->versionID = rpc_buf.versionID;
		e->procedureID = rpc_buf.procedureID;
		if (e->programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			e->taskID = task_id_val;
		} else {
			e->taskID = rpc_buf.taskID;
		}
		e->parameterSize = rpc_buf.parameterSize;
		e->mycontext = rpc_buf.mycontext;
	}

	if (target_programID && e->programID != target_programID) {
		bpf_printk("rpcsnoop: get_ring_data_ret filter programID: %u\n", e->programID);
		bpf_ringbuf_discard(e, 0);
		goto out;
	}

	e->pid = pid;
		e->tgid = tgid;
		e->refclk = bpf_ktime_get_ns();
	if (e->programID == RPC_PG_ID_R_PROGRAM)
		e->rpc_num = 0;
	else
		e->rpc_num = rcpu_info->rpc_num;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

out:
	bpf_map_delete_elem(&rcpu_data_map, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
