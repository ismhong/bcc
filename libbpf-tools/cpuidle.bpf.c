#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpuidle.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"

const volatile int cpu_num = 0;
const volatile int state_num = 0;
const volatile int least_state = 0;
const volatile bool dump_overlap = false;
const volatile __u32 core_mask = 0;
const volatile __u32 state_mask = 0;
const volatile bool histogram = false;
const volatile bool milliseconds = false;
const volatile bool microseconds = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, __u32);
	__type(value, __u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPU_NR);
	__type(key, __u32);
	__type(value, __u32);
} arguments SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPU_NR * MAX_IDLE_STATE_NR);
	__type(key, __u32);
	__type(value, struct idle_t);
} idlestats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} last_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} sleep_cpus SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} all_cpu_sleep SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u64);
} dist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} latency_sum SEC(".maps");

static void update_overlap_table(u64 ts, int cpu, int state, int is_entry)
{
	u64 zero = 0;
	u64 *last_event_ts, last_event_during;
	u64 *num_sleep_cpus, *all_cpu_sleep_duration;

	last_event_ts = bpf_map_lookup_elem(&last_event, &zero);
	if (!last_event_ts) {
		bpf_map_update_elem(&last_event, &zero, &ts, BPF_NOEXIST);
		last_event_ts = bpf_map_lookup_elem(&last_event, &zero);
		if (!last_event_ts)
			return;
	}

	num_sleep_cpus = bpf_map_lookup_elem(&sleep_cpus, &zero);
	if (!num_sleep_cpus) {
		bpf_map_update_elem(&sleep_cpus, &zero, &zero, BPF_NOEXIST);
		num_sleep_cpus = bpf_map_lookup_elem(&sleep_cpus, &zero);
		if (!num_sleep_cpus)
			return;
	}

	all_cpu_sleep_duration = bpf_map_lookup_elem(&all_cpu_sleep, &zero);
	if (!all_cpu_sleep_duration) {
		bpf_map_update_elem(&all_cpu_sleep, &zero, &zero, BPF_NOEXIST);
		all_cpu_sleep_duration =
			bpf_map_lookup_elem(&all_cpu_sleep, &zero);
		if (!all_cpu_sleep_duration)
			return;
	}

	if (ts > *last_event_ts) {
		last_event_during = ts - *last_event_ts;

		if (*num_sleep_cpus == (1 << cpu_num) - 1 && !is_entry) {
			*all_cpu_sleep_duration += last_event_during;
			if (dump_overlap)
				bpf_printk("%x, %d, cur: %lld",
						*num_sleep_cpus, is_entry,
						last_event_during);
		}
		*last_event_ts = ts;
	}

	if (is_entry) {
		if (state >= least_state) {
			*num_sleep_cpus |= (1 << cpu);
		}
	} else {
		*num_sleep_cpus &= ~(1 << cpu);
	}
}

SEC("kprobe/psci_enter_idle_state")
int BPF_KPROBE(kprobe__psci_enter_idle_state, struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int idx)
{
	__u64 ts = bpf_ktime_get_ns();
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 state_idx = idx;

	bpf_map_update_elem(&start, &cpu, &ts, BPF_ANY);
	bpf_map_update_elem(&arguments, &cpu, &state_idx, BPF_ANY);

	if (least_state > 0 || dump_overlap)
		update_overlap_table(ts, cpu, idx, 1);

	return 0;
}

SEC("kretprobe/psci_enter_idle_state")
int BPF_KRETPROBE(kretprobe__psci_enter_idle_state, int ret)
{
	__u64 ts = bpf_ktime_get_ns();
	__u64 *tsp;
	__u32 *argp;
	__u32 cpu = bpf_get_smp_processor_id();

	tsp = bpf_map_lookup_elem(&start, &cpu);
	argp = bpf_map_lookup_elem(&arguments, &cpu);
	if (!tsp || !argp)
		return 0;

	__u64 delta = ts - *tsp;
	int state_idx = *argp;

	bpf_map_delete_elem(&start, &cpu);
	bpf_map_delete_elem(&arguments, &cpu);

	if (state_idx < 0 || state_idx >= state_num)
		return 0;

	__u32 key = cpu * state_num + state_idx;
	struct idle_t *stat;

	stat = bpf_map_lookup_elem(&idlestats, &key);
	if (!stat)
		return 0; /* Should not happen */

	if (ret < 0) {
		__sync_fetch_and_add(&stat->error_times, 1);
	} else {
		__sync_fetch_and_add(&stat->latency_sum, delta);
	}
	__sync_fetch_and_add(&stat->count, 1);

	if (histogram) {
		if (ret >= 0 && (core_mask & (1 << cpu)) &&
				(state_mask & (1 << ret))) {
			__u64 latency = delta;
			__u32 idx = 0;
			__u64 *sum;

			if (milliseconds)
				latency /= 1000000;
			else if (microseconds)
				latency /= 1000;

			sum = bpf_map_lookup_elem(&latency_sum, &idx);
			if (sum)
				__sync_fetch_and_add(sum, latency);

			idx = 1;
			sum = bpf_map_lookup_elem(&latency_sum, &idx);
			if (sum)
				__sync_fetch_and_add(sum, 1);

			__u32 slot = log2l(latency);
			if (slot >= 32)
				slot = 31;
			sum = bpf_map_lookup_elem(&dist, &slot);
			if (sum)
				__sync_fetch_and_add(sum, 1);
		}
	}

	if (least_state > 0 || dump_overlap)
		update_overlap_table(ts, cpu, ret, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
