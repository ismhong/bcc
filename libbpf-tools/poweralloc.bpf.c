// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Realtek, Inc.
//
// poweralloc.bpf.c - BPF program for power allocation tracing
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "poweralloc.h"
#include "maps.bpf.h"

/* Set by userspace based on kernel version */
const volatile bool use_ipa_trace = false;   /* K6.8+: thermal_power_actor */
const volatile bool is_k60_plus = false;     /* K6.0+: cpu_get_power_simple */
const volatile bool detail = false;
const volatile bool percpu = false;
const volatile int  cpu_num = MAX_CPUS;      /* set by userspace via os.cpu_count() */

/* Read __data_loc dynamic string field from tracepoint context */
#define TP_DATA_LOC_READ_STR(dst, ctx, field, len)                      \
	do {                                                            \
		unsigned short __off = (ctx)->__data_loc_##field & 0xFFFF; \
		bpf_probe_read_str((void *)(dst), (len),                \
				   (char *)(ctx) + __off);              \
	} while (0)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES);
	__type(key, struct device_key);
	__type(value, struct value_t);
} power_budget SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct thermal_t);
} temps SEC(".maps");

static struct value_t zero_val;

/* ------------------------------------------------------------------ */
/* thermal_temperature: track current temperature                      */
/* ------------------------------------------------------------------ */
struct trace_event_raw_thermal_temperature_compat {
	struct trace_entry ent;
	__u32 __data_loc_thermal_zone;
	int id;
	int temp_prev;
	int temp;
	char __data[0];
};

SEC("tp/thermal/thermal_temperature")
int handle_thermal_temperature(struct trace_event_raw_thermal_temperature_compat *ctx)
{
	__u32 zero = 0;
	struct thermal_t *p;

	p = bpf_map_lookup_elem(&temps, &zero);
	if (!p) {
		struct thermal_t init = {};
		bpf_map_update_elem(&temps, &zero, &init, BPF_NOEXIST);
		p = bpf_map_lookup_elem(&temps, &zero);
		if (!p)
			return 0;
	}
	__sync_fetch_and_add(&p->acc, ctx->temp);
	__sync_fetch_and_add(&p->count, 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* thermal_power_allocator: TOTAL req/granted                          */
/* ------------------------------------------------------------------ */
SEC("tp/thermal_power_allocator/thermal_power_allocator")
int handle_power_allocator(struct trace_event_raw_thermal_power_allocator *ctx)
{
	struct device_key key = {};
	struct value_t *p;

	__builtin_memcpy(key.name, "TOTAL", 6);
	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->req, ctx->total_req_power);
	__sync_fetch_and_add(&p->granted, ctx->total_granted_power);
	__sync_fetch_and_add(&p->count, 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* K6.8+: thermal_power_actor (--use-ipa-trace)                       */
/* ------------------------------------------------------------------ */
SEC("tp/thermal_power_allocator/thermal_power_actor")
int handle_power_actor(struct trace_event_raw_thermal_power_actor *ctx)
{
	struct device_key key = {};
	struct value_t *p;
	int id;

	if (!use_ipa_trace)
		return 0;

	id = ctx->actor_id;
	__builtin_memcpy(key.name, "actor", 5);
	if (id >= 10) {
		key.name[5] = '0' + (id / 10);
		key.name[6] = '0' + (id % 10);
		key.name[7] = '\0';
	} else {
		key.name[5] = '0' + id;
		key.name[6] = '\0';
	}

	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->req, ctx->req_power);
	__sync_fetch_and_add(&p->granted, ctx->granted_power);
	__sync_fetch_and_add(&p->count, 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* K6.0+: thermal_power_cpu_get_power_simple                          */
/* ------------------------------------------------------------------ */
SEC("tp/thermal/thermal_power_cpu_get_power_simple")
int handle_cpu_get_power_simple(struct trace_event_raw_thermal_power_cpu_get_power_simple *ctx)
{
	struct device_key key = {};
	struct value_t *p;
	int cpu;

	if (!is_k60_plus)
		return 0;

	cpu = ctx->cpu;
	__builtin_memcpy(key.name, "cpu", 3);
	if (cpu >= 10) {
		key.name[3] = '0' + (cpu / 10);
		key.name[4] = '0' + (cpu % 10);
		key.name[5] = '\0';
	} else {
		key.name[3] = '0' + cpu;
		key.name[4] = '\0';
	}

	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->req, ctx->power);
	__sync_fetch_and_add(&p->count, 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* K6.0+: thermal_power_cpu_limit                                     */
/* ------------------------------------------------------------------ */
SEC("tp/thermal/thermal_power_cpu_limit")
int handle_cpu_limit(struct trace_event_raw_thermal_power_cpu_limit *ctx)
{
	/*
	 * cpumask is a __data_loc bitmask. We read the first 64 bits to find
	 * the lowest set bit (first CPU in the cluster).
	 */
	struct device_key key = {};
	struct value_t *p;
	__u32 cpumask_lo = 0;
	int first_cpu = -1;
	int i;

	if (!is_k60_plus)
		return 0;

	/* Read first 32 bits of cpumask from dynamic data area */
	{
		unsigned short off = ctx->__data_loc_cpumask & 0xFFFF;
		bpf_probe_read(&cpumask_lo, sizeof(cpumask_lo),
			       (char *)ctx + off);
	}

	/* Find lowest set bit (unrolled for verifier) */
#pragma unroll
	for (i = 0; i < 32; i++) {
		if (cpumask_lo & (1U << i)) {
			first_cpu = i;
			break;
		}
	}

	if (first_cpu < 0)
		return 0;

	__builtin_memcpy(key.name, "cpu", 3);
	if (first_cpu >= 10) {
		key.name[3] = '0' + (first_cpu / 10);
		key.name[4] = '0' + (first_cpu % 10);
		key.name[5] = '\0';
	} else {
		key.name[3] = '0' + first_cpu;
		key.name[4] = '\0';
	}

	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->granted, ctx->power);
	if (detail)
		__sync_fetch_and_add(&p->state, ctx->cdev_state);
	return 0;
}

/* ------------------------------------------------------------------ */
/* K<6.0: thermal_power_cpu_get_power (with load/freq/dynamic_power)  */
/* ------------------------------------------------------------------ */
struct trace_event_raw_thermal_power_cpu_get_power_compat {
	struct trace_entry ent;
	__u32 __data_loc_cpumask;
	unsigned long freq;
	__u32 __data_loc_load;
	size_t load_len;
	__u32 dynamic_power;
	char __data[0];
};

SEC("tp/thermal/thermal_power_cpu_get_power")
int handle_cpu_get_power(struct trace_event_raw_thermal_power_cpu_get_power_compat *ctx)
{
	struct device_key key = {};
	struct value_t *p;
	__u32 load[MAX_CPUS] = {};
	__u32 total_load = 0;
	size_t load_len;
	int i;

	if (is_k60_plus)
		return 0;

	__builtin_memcpy(key.name, "cpu", 4);
	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->req, ctx->dynamic_power);
	__sync_fetch_and_add(&p->count, 1);

	if (detail) {
		__sync_fetch_and_add(&p->freq, ctx->freq / 1000);

		load_len = ctx->load_len;
		if (load_len > MAX_CPUS)
			load_len = MAX_CPUS;

		{
			unsigned short off = ctx->__data_loc_load & 0xFFFF;
			bpf_probe_read(load, sizeof(__u32) * MAX_CPUS,
				       (char *)ctx + off);
		}

		/* Sum loads (unrolled) */
#pragma unroll
		for (i = 0; i < MAX_CPUS; i++)
			total_load += load[i];

		if (load_len > 0)
			__sync_fetch_and_add(&p->load, total_load / load_len);

		/* Per-CPU load tracking */
		if (percpu) {
#pragma unroll
			for (i = 0; i < MAX_CPUS; i++) {
				struct device_key cpu_key = {};
				struct value_t *cp;

				if (i >= cpu_num)
					break;

				__builtin_memcpy(cpu_key.name, "cpu", 3);
				if (i >= 10) {
					cpu_key.name[3] = '0' + (i / 10);
					cpu_key.name[4] = '0' + (i % 10);
					cpu_key.name[5] = '\0';
				} else {
					cpu_key.name[3] = '0' + i;
					cpu_key.name[4] = '\0';
				}

				cp = bpf_map_lookup_or_try_init(
					&power_budget, &cpu_key, &zero_val);
				if (cp) {
					__sync_fetch_and_add(&cp->load, load[i]);
					__sync_fetch_and_add(&cp->count, 1);
				}
			}
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* K<6.0: thermal_power_cpu_limit (same tracepoint, fixed key "cpu")  */
/* ------------------------------------------------------------------ */
SEC("tp/thermal/thermal_power_cpu_limit")
int handle_cpu_limit_old(struct trace_event_raw_thermal_power_cpu_limit *ctx)
{
	struct device_key key = {};
	struct value_t *p;

	if (is_k60_plus)
		return 0;

	__builtin_memcpy(key.name, "cpu", 4);
	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->granted, ctx->power);
	if (detail)
		__sync_fetch_and_add(&p->state, ctx->cdev_state);
	return 0;
}

/* ------------------------------------------------------------------ */
/* devfreq get_power (both old and new kernel share same struct)       */
/* ------------------------------------------------------------------ */
SEC("tp/thermal/thermal_power_devfreq_get_power")
int handle_devfreq_get_power(struct trace_event_raw_thermal_power_devfreq_get_power *ctx)
{
	struct device_key key = {};
	struct value_t *p;

	TP_DATA_LOC_READ_STR(key.name, ctx, type, sizeof(key.name));

	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->req, ctx->power);
	__sync_fetch_and_add(&p->count, 1);

	if (detail) {
		__u32 load = 0;
		if (ctx->total_time > 0)
			load = 100 * ctx->busy_time / ctx->total_time;
		__sync_fetch_and_add(&p->load, load);
		__sync_fetch_and_add(&p->freq, ctx->freq / 1000000);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* devfreq limit (both old and new kernel share same struct)           */
/* ------------------------------------------------------------------ */
SEC("tp/thermal/thermal_power_devfreq_limit")
int handle_devfreq_limit(struct trace_event_raw_thermal_power_devfreq_limit *ctx)
{
	struct device_key key = {};
	struct value_t *p;

	TP_DATA_LOC_READ_STR(key.name, ctx, type, sizeof(key.name));

	p = bpf_map_lookup_or_try_init(&power_budget, &key, &zero_val);
	if (!p)
		return 0;

	__sync_fetch_and_add(&p->granted, ctx->power);
	if (detail)
		__sync_fetch_and_add(&p->state, ctx->cdev_state);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
