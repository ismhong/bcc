// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "rpcdist.h"

#ifndef EAGAIN
#define EAGAIN 11
#endif

#ifndef IS_ERR_VALUE
#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-4095)
#endif

static __always_inline __u64 bpf_log2l(__u64 v)
{
	__u64 r = 0;

	if (v > 0xFFFFFFFF) {
		v >>= 32;
		r += 32;
	}
	if (v > 0xFFFF) {
		v >>= 16;
		r += 16;
	}
	if (v > 0xFF) {
		v >>= 8;
		r += 8;
	}
	if (v > 0xF) {
		v >>= 4;
		r += 4;
	}
	if (v > 0x3) {
		v >>= 2;
		r += 2;
	}
	if (v > 0x1) {
		r += 1;
	}

	return r;
}

#define MAX_ERRNO 4095

#define RPC_PG_ID_R_PROGRAM 98
#define RPC_PG_ID_REPLYID 99

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

const volatile __u32 target_programID = 0;
const volatile bool milliseconds = false;
const volatile bool append = false;
const volatile bool extension = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct rpc_info);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct hist_key);
	__type(value, __u32);
} dist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct rpc_stats);
} stats SEC(".maps");

struct rpc_data {
	__u32 programID;
	__u32 procedureID;
	__u32 taskID;
	int rpc_num;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rpc_data);
} rpc_data_map SEC(".maps");

struct rcpu_data_t {
	int rpc_num;
	__u32 big_endian;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rcpu_data_t);
} rcpu_data_map SEC(".maps");

static __always_inline void update_hist(u64 delta, struct rpc_info *info)
{
	struct hist_key hkey;
	__u32 *val;

	if (milliseconds)
		delta /= 1000000;
	else
		delta /= 1000;

	hkey.slot = bpf_log2l(delta);
	if (append)
		hkey.key = (info->programID << 40) | (info->procedureID << 20) | info->rpc_num;
	else
		hkey.key = info->programID;

	val = bpf_map_lookup_elem(&dist, &hkey);
	if (val)
		__sync_fetch_and_add(val, 1);
	else {
		__u32 one = 1;
		bpf_map_update_elem(&dist, &hkey, &one, BPF_NOEXIST);
	}

	if (extension) {
		struct rpc_stats *sval;
		sval = bpf_map_lookup_elem(&stats, &hkey.key);
		if (sval) {
			sval->count++;
			sval->latency += delta;
			if (delta > sval->max_latency)
				sval->max_latency = delta;
		} else {
			struct rpc_stats new_stats = { .latency = delta, .max_latency = delta, .count = 1 };
			bpf_map_update_elem(&stats, &hkey.key, &new_stats, BPF_NOEXIST);
		}
	}
}

SEC("tracepoint/rtk_rpc/rtk_rpc_peek_rpc_request")
int rtk_rpc_peek_rpc_request(struct trace_event_raw_rtk_rpc_peek_rpc_request *ctx)
{
	__u32 task_id = ctx->taskID;
	struct rpc_info info = {};

	if (!task_id) {
		return 0;
	}

	if (target_programID && ctx->programID != target_programID && ctx->programID != RPC_PG_ID_REPLYID) {
		return 0;
	}

	info.programID = ctx->programID;
	info.procedureID = ctx->procedureID;
	info.rpc_num = ctx->num;
	info.ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &task_id, &info, BPF_ANY);
	return 0;
}

SEC("tracepoint/rtk_rpc/rtk_rpc_peek_rpc_reply")
int rtk_rpc_peek_rpc_reply(struct trace_event_raw_rtk_rpc_peek_rpc_reply *ctx)
{
	__u32 task_id = ctx->taskID;
	struct rpc_info *info;
	u64 delta;

	info = bpf_map_lookup_elem(&start, &task_id);
	if (!info) {
		return 0;
	}

	delta = bpf_ktime_get_ns() - info->ts;
	update_hist(delta, info);

	bpf_map_delete_elem(&start, &task_id);
	return 0;
}

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
		return 0;
	}

	int big_endian_val;

	bpf_probe_read_kernel(&rcpu, sizeof(rcpu), &channel->rcpu);
	bpf_probe_read_kernel(&info, sizeof(info), &rcpu->info);
	bpf_probe_read_kernel(&big_endian_val, sizeof(big_endian_val), &info->big_endian);

	if (big_endian_val) {
		buf.programID = bpf_ntohl(rpc_info.programID);
		buf.procedureID = bpf_ntohl(rpc_info.procedureID);
		if (buf.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					(char *)data + sizeof(struct rpc_struct));
			buf.taskID = bpf_ntohl(task_id_val);
		} else {
			buf.taskID = bpf_ntohl(rpc_info.taskID);
		}
	} else {
		buf.programID = rpc_info.programID;
		buf.procedureID = rpc_info.procedureID;
		if (buf.programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					(char *)data + sizeof(struct rpc_struct));
			buf.taskID = task_id_val;
		} else {
			buf.taskID = rpc_info.taskID;
		}
	}

	if (buf.programID == RPC_PG_ID_REPLYID)
		buf.rpc_num = 0;
	else {
		int id_val;
		bpf_probe_read_kernel(&id_val, sizeof(id_val), &info->id);
		buf.rpc_num = id_val;
	}

	bpf_map_update_elem(&rpc_data_map, &pid, &buf, BPF_ANY);
	return 0;
}

SEC("kretprobe/__rtk_rpmsg_send")
int BPF_KRETPROBE(__rtk_rpmsg_send_ret, int ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	struct rpc_data *buf;
	struct rpc_info *info, rpc_info = {};
	u64 delta;
	__u32 task_id;

	if (ret == -EAGAIN) {
		goto out;
	}

	buf = bpf_map_lookup_elem(&rpc_data_map, &pid);
	if (!buf) {
		return 0;
	}

	task_id = buf->taskID;
	if (buf->programID == RPC_PG_ID_REPLYID) {
		info = bpf_map_lookup_elem(&start, &task_id);
		if (!info) {
			goto out;
		}

		delta = bpf_ktime_get_ns() - info->ts;
		update_hist(delta, info);
		bpf_map_delete_elem(&start, &task_id);
	} else {
		if (!task_id) {
			goto out;
		}

		if (target_programID && buf->programID != target_programID) {
			goto out;
		}

		rpc_info.programID = buf->programID;
		rpc_info.procedureID = buf->procedureID;
		rpc_info.rpc_num = buf->rpc_num;
		rpc_info.ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&start, &task_id, &rpc_info, BPF_ANY);
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

	int id_val;
	int big_endian_val;

	bpf_probe_read_kernel(&rcpu, sizeof(rcpu), &channel->rcpu);
	bpf_probe_read_kernel(&info, sizeof(info), &rcpu->info);

	bpf_probe_read_kernel(&id_val, sizeof(id_val), &info->id);
	rcpu_info.rpc_num = id_val;

	bpf_probe_read_kernel(&big_endian_val, sizeof(big_endian_val), &info->big_endian);
	rcpu_info.big_endian = big_endian_val;

	bpf_map_update_elem(&rcpu_data_map, &pid, &rcpu_info, BPF_ANY);
	return 0;
}

SEC("kretprobe/get_ring_data")
int BPF_KRETPROBE(get_ring_data_ret, char *ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	struct rpc_struct rpc_buf;
	struct rcpu_data_t *rcpu_info;
	struct rpc_info *info, rpc_info = {};
	u64 delta;
	__u32 task_id, task_id_val, programID;

	if (IS_ERR_VALUE(ret)) {
		goto out;
	}

	rcpu_info = bpf_map_lookup_elem(&rcpu_data_map, &pid);
	if (!rcpu_info) {
		return 0;
	}

	bpf_probe_read_kernel(&rpc_buf, sizeof(rpc_buf), ret);

	if (rcpu_info->big_endian) {
		programID = bpf_ntohl(rpc_buf.programID);
		if (programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			task_id = bpf_ntohl(task_id_val);
		} else {
			task_id = bpf_ntohl(rpc_buf.taskID);
		}
	} else {
		programID = rpc_buf.programID;
		if (programID == RPC_PG_ID_REPLYID) {
			bpf_probe_read_kernel(&task_id_val, sizeof(task_id_val),
					ret + sizeof(struct rpc_struct));
			task_id = task_id_val;
		} else {
			task_id = rpc_buf.taskID;
		}
	}

	if (programID == RPC_PG_ID_REPLYID) {
		info = bpf_map_lookup_elem(&start, &task_id);
		if (!info) {
			goto out;
		}

		delta = bpf_ktime_get_ns() - info->ts;
		update_hist(delta, info);
		bpf_map_delete_elem(&start, &task_id);
	} else {
		if (!task_id) {
			goto out;
		}

		if (target_programID && programID != target_programID) {
			goto out;
		}

		if (rcpu_info->big_endian) {
			rpc_info.programID = bpf_ntohl(rpc_buf.programID);
			rpc_info.procedureID = bpf_ntohl(rpc_buf.procedureID);
		} else {
			rpc_info.programID = rpc_buf.programID;
			rpc_info.procedureID = rpc_buf.procedureID;
		}

		if (rpc_info.programID == RPC_PG_ID_R_PROGRAM)
			rpc_info.rpc_num = 0;
		else
			rpc_info.rpc_num = rcpu_info->rpc_num;

		rpc_info.ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&start, &task_id, &rpc_info, BPF_ANY);
	}

out:
	bpf_map_delete_elem(&rcpu_data_map, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
