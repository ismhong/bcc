// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Realtek, Inc. */
/* Copyright (c) 2023-2024, msinwu <msinwu@realtek.com> */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "rpcundone.h"

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-MAX_ERRNO)

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

// Manually define Realtek-specific structs for kprobes from rpcsnoop.bpf.c
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct event);
} start SEC(".maps");

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
	struct event e = {};
	u32 task_id = ctx->taskID;

	if (task_id) {
		bpf_get_current_comm(&e.comm, sizeof(e.comm));
		e.pid = pid;
		e.tgid = tgid;
		e.programID = ctx->programID;
		e.versionID = ctx->versionID;
		e.procedureID = ctx->procedureID;
		e.taskID = task_id;
		e.parameterSize = ctx->parameterSize;
		e.mycontext = ctx->mycontext;
		e.refclk = ctx->refclk;
		e.rpc_num = ctx->num;
		e.delta = bpf_ktime_get_ns();

		bpf_map_update_elem(&start, &task_id, &e, BPF_ANY);
	}

	return 0;
}

SEC("tracepoint/rtk_rpc/rtk_rpc_peek_rpc_reply")
int rtk_rpc_peek_rpc_reply(struct trace_event_raw_rtk_rpc_peek_rpc_reply *ctx)
{
	u32 task_id = ctx->taskID;
	struct event *e;

	e = bpf_map_lookup_elem(&start, &task_id);
	if (e)
		bpf_map_delete_elem(&start, &task_id);

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

	if (bpf_probe_read_kernel(&rpc_info, sizeof(rpc_info), data) < 0)
		return 0;

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
	struct event *e, data = {};
	u32 task_id;

	if (ret == -EAGAIN)
		goto out;

	buf = bpf_map_lookup_elem(&rpc_data_map, &pid);
	if (!buf)
		return 0;

	if (buf->programID == RPC_PG_ID_REPLYID) {
		task_id = buf->taskID;
		e = bpf_map_lookup_elem(&start, &task_id);
		if (e)
			bpf_map_delete_elem(&start, &task_id);
		goto out;
	}

	if (buf->taskID) {
		bpf_get_current_comm(&data.comm, sizeof(data.comm));
		data.pid = pid;
		data.tgid = tgid;
		data.programID = buf->programID;
		data.versionID = buf->versionID;
		data.procedureID = buf->procedureID;
		data.taskID = buf->taskID;
		data.parameterSize = buf->parameterSize;
		data.mycontext = buf->mycontext;
		data.refclk = bpf_ktime_get_ns();
		data.rpc_num = buf->rpc_num;
		data.delta = data.refclk;

		task_id = data.taskID;
		bpf_map_update_elem(&start, &task_id, &data, BPF_ANY);
	}

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
	struct event *e, data = {};
	__u32 task_id, task_id_val;

	if (IS_ERR_VALUE(ret))
		goto out;

	rcpu_info = bpf_map_lookup_elem(&rcpu_data_map, &pid);
	if (!rcpu_info)
		return 0;

	bpf_probe_read_kernel(&rpc_buf, sizeof(rpc_buf), ret);

	if (rcpu_info->big_endian) {
		data.programID = bpf_ntohl(rpc_buf.programID);
		if (data.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			data.taskID = bpf_ntohl(task_id_val);
		} else {
			data.taskID = bpf_ntohl(rpc_buf.taskID);
		}
	} else {
		data.programID = rpc_buf.programID;
		if (data.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			data.taskID = task_id_val;
		} else {
			data.taskID = rpc_buf.taskID;
		}
	}

	if (data.programID == RPC_PG_ID_REPLYID) {
		task_id = data.taskID;
		e = bpf_map_lookup_elem(&start, &task_id);
		if (e)
			bpf_map_delete_elem(&start, &task_id);
		goto out;
	}

	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	data.pid = pid;
	data.tgid = tgid;
	if (rcpu_info->big_endian) {
		data.versionID = bpf_ntohl(rpc_buf.versionID);
		data.procedureID = bpf_ntohl(rpc_buf.procedureID);
		data.parameterSize = bpf_ntohl(rpc_buf.parameterSize);
		data.mycontext = bpf_ntohl(rpc_buf.mycontext);
	} else {
		data.versionID = rpc_buf.versionID;
		data.procedureID = rpc_buf.procedureID;
		data.parameterSize = rpc_buf.parameterSize;
		data.mycontext = rpc_buf.mycontext;
	}
	task_id = data.taskID;
	if (task_id == 0)
		goto out;

	data.refclk = bpf_ktime_get_ns();
	data.delta = data.refclk;
	if (data.programID == RPC_PG_ID_R_PROGRAM)
		data.rpc_num = 0;
	else
		data.rpc_num = rcpu_info->rpc_num;

	bpf_map_update_elem(&start, &task_id, &data, BPF_ANY);

out:
	bpf_map_delete_elem(&rcpu_data_map, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
