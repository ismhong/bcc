/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * loadavg   Summarize /proc/loadavg contribution.
 *             For Linux, uses BCC, eBPF.
 *
 * Copyright 2025 Realtek, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "loadavg.h"
#include "loadavg.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

#define __unused __attribute__((__unused__))
#define MAX_ENTRIES 10240

static struct env {
	int timestamp;
	int maxrows;
	int extend;
	const char *sort_by;
	const char *policy;
	int interval;
	int count;
	int verbose;
} env = {
	.maxrows = 30,
	.sort_by = "SUM_LOAD",
	.policy = "all",
	.interval = 1,
	.count = -1,
};

static volatile bool exiting;
static int cpu_count;

static const char *const usages[] = {
	"loadavg [-h] [-T] [-r MAXROWS] [-e] [-s SORT] [-p POLICY] [interval] [count]",
	NULL,
};

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_INTEGER('r', "maxrows", &env.maxrows, "Maximum rows to print, default 30", NULL, 0, 0),
	OPT_BOOLEAN('e', "extend", &env.extend, "Extend runqueue info", NULL, 0, 0),
	OPT_STRING('s', "sort", &env.sort_by, "Sort by specific field, default SUM_LOAD", NULL, 0, 0),
	OPT_STRING('p', "policy", &env.policy, "Trace with this sched policy only, default all", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

struct load_info_t {
	struct task_t key;
	struct nr_running_t value;
};

static int sort_column;
static bool sort_cpu_max_rq;

static int get_sort_column(const char* sort_by)
{
	if (strcmp(sort_by, "SUM_LOAD") == 0)
		return 1;

	if (strcmp(sort_by, "AVG_LOAD") == 0)
		return 2;

	if (strncmp(sort_by, "CPU", 3) == 0 && strstr(sort_by, "_MAX_RQ")) {
		sort_cpu_max_rq = true;
		return atoi(sort_by + 3);
	}

	if (strcmp(sort_by, "SUM_MAX_RQ") == 0)
		return 3;

	return 1; /* default to SUM_LOAD */
}

static int sort_comparison(const void *a, const void *b)
{
	const struct load_info_t *la = a;
	const struct load_info_t *lb = b;

	if (sort_cpu_max_rq) {
		return lb->value.max_nr_running[sort_column] - la->value.max_nr_running[sort_column];
	}

	switch (sort_column) {
	case 1: /* SUM_LOAD */
		if (lb->value.duration > la->value.duration) return 1;
		if (lb->value.duration < la->value.duration) return -1;
		return 0;
	case 2: /* AVG_LOAD */
		{
			__u64 sum_count_a = 0, sum_count_b = 0;
			int i;
			for (i = 0; i < cpu_count; i++) {
				sum_count_a += la->value.count[i];
				sum_count_b += lb->value.count[i];
			}
			double avg_a = sum_count_a ? (double)la->value.duration / sum_count_a : 0;
			double avg_b = sum_count_b ? (double)lb->value.duration / sum_count_b : 0;
			if (avg_b > avg_a) return 1;
			if (avg_b < avg_a) return -1;
			return 0;
		}
	case 3: /* SUM_MAX_RQ */
		return lb->value.total_max_rq - la->value.total_max_rq;
	default:
		if (lb->value.duration > la->value.duration) return 1;
		if (lb->value.duration < la->value.duration) return -1;
		return 0;
	}
}

static void print_headers(void)
{
	if (env.extend) {
		printf("%-6s %-6s %-16s %-15s %-5s %9s %9s  ", "TGID", "PID", "COMM", "POLICY", "ONCPU", "SUM_LOAD", "AVG_LOAD");
		int i;
		for (i = 0; i < cpu_count && i < 4; i++) {
			printf("%-3s %12s %7s ", "CPU", "AVG,MIN,MAX", "ENQ_CNT");
		}
		printf("|%10s\n", "SUM_MAX_RQ");
	} else {
		printf("%-6s %-16s %-5s %9s\n", "PID", "COMM", "ONCPU", "SUM_LOAD");
	}
}

static const char* sched_policy_name(int policy)
{
	switch (policy) {
		case 0: return "SCHED_NORMAL";
		case 1: return "SCHED_FIFO";
		case 2: return "SCHED_RR";
		case 3: return "SCHED_BATCH";
		case 5: return "SCHED_IDLE";
		case 6: return "SCHED_DEADLINE";
		default: return "Unknown";
	}
}

static int print_data(struct loadavg_bpf *skel)
{
	struct task_t key = {};
	struct nr_running_t value;
	struct load_info_t *load_infos;
	int fd, i = 0, rows = 0;
	double denominator = (double)env.interval * 1000000000;
	FILE *f;
	char buf[256];

	fd = bpf_map__fd(skel->maps.load_info);
	load_infos = calloc(MAX_ENTRIES, sizeof(struct load_info_t));
	if (!load_infos)
		return -1;

	struct task_t *lookup_key = NULL;
	while (bpf_map_get_next_key(fd, lookup_key, &key) == 0) {
		if (bpf_map_lookup_elem(fd, &key, &value) != 0) {
			continue;
		}
		load_infos[rows].key = key;
		load_infos[rows].value = value;
		rows++;
		lookup_key = &key;
	}

	sort_column = get_sort_column(env.sort_by);
	qsort(load_infos, rows, sizeof(struct load_info_t), sort_comparison);

	if (env.timestamp) {
		time_t t = time(NULL);
		strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
		printf("%-8s\n", buf);
	}

	print_headers();

	double tsk_rn_total = 0.0, tsk_unint_total = 0.0;
	for (i = 0; i < rows && i < env.maxrows; i++) {
		struct load_info_t *info = &load_infos[i];
		if (info->key.on_cpu)
			tsk_rn_total += info->value.duration;
		else
			tsk_unint_total += info->value.duration;

		if (env.extend) {
			printf("%-6d %-6d %-16s %-15s %-5d %9.6f ", info->key.tgid, info->key.pid, info->value.name, sched_policy_name(info->key.policy), info->key.on_cpu, info->value.duration / denominator);
			__u64 sum_count = 0;
			int j;
			for (j = 0; j < cpu_count; j++) sum_count += info->value.count[j];
			printf("%9.6f  ", sum_count ? (info->value.duration / denominator) / sum_count : 0.0);
			for (j = 0; j < cpu_count && j < 4; j++) {
				printf("[%d] %4.1f,%3d,%3d %7d ", j, info->value.count[j] ? (double)info->value.sum_nr_running[j] / info->value.count[j] : 0.0, info->value.min_nr_running[j], info->value.max_nr_running[j], info->value.count[j]);
			}
			printf("|%10d\n", info->value.total_max_rq);
		} else {
			printf("%-6d %-16s %-5d %9.6f\n", info->key.pid, info->value.name, info->key.on_cpu, info->value.duration / denominator);
		}
	}
	free(load_infos);

	printf("Skip...\n\n");

	if (env.extend) {
		printf("%-3s %16s %16s %9s  %12s %7s\n", "CPU", "ON_CPU_SUM_LOAD", "OFF_CPU_SUM_LOAD", "AVG_LOAD", "AVG,MIN,MAX", "ENQ_CNT");
	} else {
		printf("%-3s %16s %16s\n", "CPU", "ON_CPU_SUM_LOAD", "OFF_CPU_SUM_LOAD");
	}

	struct cpu_stat_t cpu_stats[MAX_CPU_NR];
	fd = bpf_map__fd(skel->maps.cpu_info);
	for (i = 0; i < cpu_count; i++) {
		if (bpf_map_lookup_elem(fd, &i, &cpu_stats[i]) != 0) {
			memset(&cpu_stats[i], 0, sizeof(struct cpu_stat_t));
		}
	}

	for (i = 0; i < cpu_count; i++) {
		printf("%3d %16.6f %16.6f ", i, cpu_stats[i].oncpu_duration / denominator, cpu_stats[i].offcpu_duration / denominator);
		if (env.extend) {
			printf("%9.6f  ", cpu_stats[i].count ? (cpu_stats[i].oncpu_duration / denominator) / cpu_stats[i].count : 0.0);
			printf("%4.1f,%3d,%3d %7d", cpu_stats[i].count ? (double)cpu_stats[i].sum_nr_running / cpu_stats[i].count : 0.0, cpu_stats[i].min_nr_running, cpu_stats[i].max_nr_running, cpu_stats[i].count);
		}
		printf("\n");
	}

	printf("\n");
	f = fopen("/proc/loadavg", "r");
	if (f) {
		time_t t = time(NULL);
		strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
		printf("%-8s loadavg: %s", buf, fgets(buf, sizeof(buf), f));
		fclose(f);
	}

	f = fopen("/proc/stat", "r");
	if (f) {
		while(fgets(buf, sizeof(buf), f)) {
			if (strncmp(buf, "procs_running", 13) == 0) {
				printf("%s", buf);
				break;
			}
		}
		fclose(f);
	}

	tsk_rn_total /= denominator;
	tsk_unint_total /= denominator;
	printf("\n%-11s %-11s %-11s\n", "ONCPU", "OFFCPU", "TOTAL");
	printf("%-11.6f %-11.6f %-11.6f\n", tsk_rn_total, tsk_unint_total, tsk_rn_total + tsk_unint_total);

	/* Clear maps */
	fd = bpf_map__fd(skel->maps.load_info);
	lookup_key = NULL;
	while (bpf_map_get_next_key(fd, lookup_key, &key) == 0) {
		bpf_map_delete_elem(fd, &key);
		lookup_key = &key;
	}
	fd = bpf_map__fd(skel->maps.cpu_info);
	struct cpu_stat_t zero_cpu_stat = {};
	for (i = 0; i < cpu_count; i++) {
		bpf_map_update_elem(fd, &i, &zero_cpu_stat, BPF_ANY);
	}
	if (env.extend) {
		fd = bpf_map__fd(skel->maps.nr_running_info);
		__u32 pid_key, *lookup_pid_key = NULL;
		while (bpf_map_get_next_key(fd, lookup_pid_key, &pid_key) == 0) {
			bpf_map_delete_elem(fd, &pid_key);
			lookup_pid_key = &pid_key;
		}
	}

	return 0;
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct loadavg_bpf *skel;
	struct argparse argparse;
	int err;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "\nSummarize /proc/loadavg contribution.", "\n");
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (argc > 0)
		env.interval = atoi(argv[0]);
	if (argc > 1)
		env.count = atoi(argv[1]);

	if (env.count == 0)
		env.count = -1;

	libbpf_set_print(libbpf_print_fn);

	cpu_count = libbpf_num_possible_cpus();

	skel = loadavg_bpf__open();
	if (!skel)
		return 1;

	skel->rodata->extend_rq_info = env.extend;

	bpf_map__set_max_entries(skel->maps.cpu_info, cpu_count);
	bpf_map__set_max_entries(skel->maps.task_info, cpu_count);

	if (!tracepoint_exists("rtk_sched", "rtk_sched_update_nr_running")) {
		bpf_program__set_autoload(skel->progs.rtk_sched_update_nr_running, false);
		fprintf(stderr, "rtk_sched:rtk_sched_update_nr_running tracepoint not found, runqueue info may be limited\n");
	}

	if (env.extend) {
		if (strcmp(env.policy, "all") != 0) {
			bpf_program__set_autoload(skel->progs.enqueue_task_fair, strstr(env.policy, "fair") != NULL);
			bpf_program__set_autoload(skel->progs.enqueue_task_rt, strstr(env.policy, "rt") != NULL);
			bpf_program__set_autoload(skel->progs.enqueue_task_dl, strstr(env.policy, "dl") != NULL);
			bpf_program__set_autoload(skel->progs.enqueue_task_stop, strstr(env.policy, "stop") != NULL);
		}
	} else {
		bpf_program__set_autoload(skel->progs.rtk_sched_update_nr_running, false);
		bpf_program__set_autoload(skel->progs.enqueue_task_fair, false);
		bpf_program__set_autoload(skel->progs.enqueue_task_rt, false);
		bpf_program__set_autoload(skel->progs.enqueue_task_dl, false);
		bpf_program__set_autoload(skel->progs.enqueue_task_stop, false);
	}

	err = loadavg_bpf__load(skel);
	if (err)
		return 1;

	err = loadavg_bpf__attach(skel);
	if (err) {
		loadavg_bpf__destroy(skel);
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		sleep(env.interval);
		if (print_data(skel) != 0)
			break;
		if (env.count > 0)
			env.count--;
		if (env.count == 0)
			break;
	}

	loadavg_bpf__destroy(skel);

	return 0;
}
