/* SPDX-License-Identifier: GPL-2.0-only */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "loadavg.h"
#include "bits.bpf.h"

#define MAX_ENTRIES 10240

const volatile bool extend_rq_info = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} on_cpu_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} off_cpu_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct task_t);
	__type(value, struct nr_running_t);
} load_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, u32);
	__type(value, struct cpu_stat_t);
} cpu_info SEC(".maps");

/* For extended info */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct nr_running_t);
} nr_running_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct nr_running_t);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, u32);
	__type(value, struct task_info_t);
} task_info SEC(".maps");

static int update_count(char *comm, u32 pid, u32 on_cpu)
{
	struct task_t task = {};
	struct nr_running_t *data, *info;
	u64 *tsp, delta, ts;
	__u32 cpuid, zero = 0;
	struct cpu_stat_t *stat, tmp;
	struct nr_running_t *newinfo;

	newinfo = bpf_map_lookup_elem(&heap, &zero);
	if (!newinfo)
		return 0;

	#pragma unroll
	for (int i = 0; i < sizeof(*newinfo); i++)
		((char *)newinfo)[i] = 0;

	if (on_cpu)
		tsp = bpf_map_lookup_elem(&on_cpu_start, &pid);
	else
		tsp = bpf_map_lookup_elem(&off_cpu_start, &pid);

	if (!tsp)
		return 0;

	ts = bpf_ktime_get_ns();
	if (ts < *tsp)
		return 0;

	delta = ts - *tsp;

	if (extend_rq_info) {
		data = bpf_map_lookup_elem(&nr_running_info, &pid);
		if (!data)
			return 0;

		task.tgid = data->tgid;
		task.policy = data->policy;
	}

	cpuid = bpf_get_smp_processor_id();
	if (cpuid >= MAX_CPU_NR)
		return 0;

	task.pid = pid;
	task.on_cpu = on_cpu;
	info = bpf_map_lookup_elem(&load_info, &task);

	if (info == 0) {
		newinfo->duration = delta;
	} else {
		bpf_probe_read_kernel(newinfo, sizeof(*newinfo), info);
		newinfo->duration += delta;
	}

	bpf_probe_read_kernel_str(&newinfo->name, sizeof(newinfo->name), comm);

	stat = bpf_map_lookup_elem(&cpu_info, &cpuid);
	if (!stat)
		return 0;

	bpf_probe_read_kernel(&tmp, sizeof(tmp), stat);

	if (extend_rq_info) {
		if (on_cpu == 1) {
			for (int i = 0; i < MAX_CPU_NR; i++) {
				newinfo->sum_nr_running[i] = data->sum_nr_running[i];
				newinfo->max_nr_running[i] = data->max_nr_running[i];
				newinfo->min_nr_running[i] = data->min_nr_running[i];
				newinfo->count[i] = data->count[i];
			}
		}
		tmp.sum_nr_running = stat->sum_nr_running + data->nr_running[cpuid];
		if (on_cpu == 1) {
			if(!stat->min_nr_running)
				tmp.min_nr_running = data->max_nr_running[cpuid];
			if (data->max_nr_running[cpuid] > stat->max_nr_running)
				tmp.max_nr_running = data->max_nr_running[cpuid];
			if (data->min_nr_running[cpuid] < stat->min_nr_running)
				tmp.min_nr_running = data->min_nr_running[cpuid];
			tmp.count += 1;
			tmp.oncpu_duration = stat->oncpu_duration + delta;
			tmp.offcpu_duration = stat->offcpu_duration;
			newinfo->total_max_rq = data->total_max_rq;
		} else {
			tmp.oncpu_duration = stat->oncpu_duration;
			tmp.offcpu_duration = stat->offcpu_duration + delta;
		}
	} else {
		if (on_cpu == 1) {
			tmp.oncpu_duration = stat->oncpu_duration + delta;
			tmp.offcpu_duration = stat->offcpu_duration;
		} else {
			tmp.oncpu_duration = stat->oncpu_duration;
			tmp.offcpu_duration = stat->offcpu_duration + delta;
		}
	}
	bpf_map_update_elem(&cpu_info, &cpuid, &tmp, BPF_ANY);

	bpf_map_update_elem(&load_info, &task, newinfo, BPF_ANY);

	if (on_cpu)
		bpf_map_delete_elem(&on_cpu_start, &pid);
	else
		bpf_map_delete_elem(&off_cpu_start, &pid);

	return 0;
}

static inline void store_start(u32 pid, u32 on_cpu)
{
	u64 ts = bpf_ktime_get_ns();

	if (on_cpu)
		bpf_map_update_elem(&on_cpu_start, &pid, &ts, BPF_ANY);
	else
		bpf_map_update_elem(&off_cpu_start, &pid, &ts, BPF_ANY);
}

SEC("tp/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *args)
{
	u32 prev_pid = args->prev_pid;
	u32 next_pid = args->next_pid;

	if (prev_pid != 0) {
		update_count(args->prev_comm, prev_pid, 1);
	}
	if (next_pid != 0) {
		store_start(next_pid, 1);
	}

	if (args->prev_state & 2 /* TASK_UNINTERRUPTIBLE */) {
		store_start(prev_pid, 0);
	}
	update_count(args->next_comm, next_pid, 0);

	return 0;
}

struct rtk_sched_update_nr_running_args {
	unsigned long long unused;
	int cpu;
	int change;
	unsigned int nr_running;
};

SEC("tracepoint/rtk_sched/rtk_sched_update_nr_running")
int rtk_sched_update_nr_running(struct rtk_sched_update_nr_running_args *args)
{
	struct task_info_t *ptr;
	struct nr_running_t *info;
	__u32 index = bpf_get_smp_processor_id();
	__u32 pid, cpuid = args->cpu;
	__u32 totalcount_max_rq = 0, nr_running = args->nr_running;
	__u32 zero_key = 0;
	struct nr_running_t *zero;

	if(args->change < 0)
		return 0;

	if (index >= MAX_CPU_NR || cpuid >= MAX_CPU_NR)
		return 0;

	ptr = bpf_map_lookup_elem(&task_info, &index);
	if (!ptr)
		return 0;

	pid = ptr->pid;

	zero = bpf_map_lookup_elem(&heap, &zero_key);
	if (!zero)
		return 0;

	#pragma unroll
	for (int i = 0; i < sizeof(*zero); i++)
		((char *)zero)[i] = 0;

	info = bpf_map_lookup_elem(&nr_running_info, &pid);
	if (!info) {
		bpf_map_update_elem(&nr_running_info, &pid, zero, BPF_NOEXIST);
		info = bpf_map_lookup_elem(&nr_running_info, &pid);
		if (!info)
			return 0;
	}

	#pragma unroll
	for (int i = 0; i < MAX_CPU_NR; ++i) {
		if (i == cpuid){
			if(!info->min_nr_running[i])
				info->min_nr_running[i] = nr_running;
			if (nr_running > info->max_nr_running[i])
				info->max_nr_running[i] = nr_running;
			if (nr_running < info->min_nr_running[i])
				info->min_nr_running[i] = nr_running;
			info->nr_running[i] = nr_running;
			info->sum_nr_running[i] += nr_running;
			info->count[i] += 1;
		}
		totalcount_max_rq += info->max_nr_running[i];
	}

	info->total_max_rq = totalcount_max_rq;
	info->tgid = ptr->tgid;
	info->policy = ptr->policy;

	return 0;
}

static int trace_enqueue_task(struct task_struct *p)
{
	struct task_info_t task = {};
	__u32 index = bpf_get_smp_processor_id();

	if (index >= MAX_CPU_NR)
		return 0;

	/*task.pid = p->pid;*/
	/*task.tgid = p->tgid;*/
	/*task.policy = p->policy;*/
	task.pid = BPF_CORE_READ(p, pid);
	task.tgid = BPF_CORE_READ(p, tgid);
	task.policy = BPF_CORE_READ(p, policy);
	bpf_map_update_elem(&task_info, &index, &task, BPF_ANY);

	return 0;
}

SEC("kprobe/enqueue_task_fair")
int BPF_KPROBE(enqueue_task_fair, struct rq *rq, struct task_struct *p, int flags)
{
	return trace_enqueue_task(p);
}

SEC("kprobe/enqueue_task_rt")
int BPF_KPROBE(enqueue_task_rt, struct rq *rq, struct task_struct *p, int flags)
{
	return trace_enqueue_task(p);
}

SEC("kprobe/enqueue_task_dl")
int BPF_KPROBE(enqueue_task_dl, struct rq *rq, struct task_struct *p, int flags)
{
	return trace_enqueue_task(p);
}

SEC("kprobe/enqueue_task_stop")
int BPF_KPROBE(enqueue_task_stop, struct rq *rq, struct task_struct *p, int flags)
{
	return trace_enqueue_task(p);
}

char LICENSE[] SEC("license") = "GPL";
