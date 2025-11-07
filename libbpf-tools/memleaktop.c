// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Realtek, Inc.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "memleaktop.h"
#include "memleaktop.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

#define MAX_ENTRIES 10240

struct alloc_info {
	struct key_t key;
	struct size_count val;
};

static struct env {
	int interval;
	bool csv;
	pid_t pid;
	pid_t tid;
	uint64_t sample_rate;
	int maxrows;
	uint64_t min_size;
	uint64_t max_size;
	bool extend;
	bool timestamp;
	bool verbose;
	bool wa_missing_free;
	int map_size;
} env = {
	.interval = 30,
	.csv = false,
	.pid = 0,
	.tid = 0,
	.sample_rate = 1,
	.maxrows = 30,
	.min_size = 0,
	.max_size = -1,
	.extend = false,
	.timestamp = false,
	.verbose = false,
	.wa_missing_free = false,
	.map_size = 500000,
};

static volatile bool exiting;

static char *sample_rate_str;
static int cb_sample_rate(struct argparse *self, const struct argparse_option *option)
{
	env.sample_rate = strtoull(sample_rate_str, NULL, 10);
	return 0;
}

static char *min_size_str;
static int cb_min_size(struct argparse *self, const struct argparse_option *option)
{
	env.min_size = strtoull(min_size_str, NULL, 10);
	return 0;
}

static char *max_size_str;
static int cb_max_size(struct argparse *self, const struct argparse_option *option)
{
	env.max_size = strtoull(max_size_str, NULL, 10);
	return 0;
}

static const char *const usages[] = {
	"memleaktop [-h] [-i INTERVAL] [-s SAMPLE_RATE] [-r MAXROWS] [-z MIN_SIZE] [-Z MAX_SIZE] [-p PID] [-t TID] [-e] [-T] [-j] [--wa-missing-free] [-m MAP_SIZE]",
	NULL,
};

const char doc[] =
"Trace outstanding memory allocations to detect memory leaks.\n"
"\n"
"EXAMPLES:\n"
"    ./memleaktop -i 20 -T         # Output every 20 second summary with timestamp\n"
"    ./memleaktop -s 5             # Trace roughly every 5th allocation, to reduce overhead\n"
"    ./memleaktop -j -i 20 -T      # Show to csv format log with timestamp\n"
"    ./memleaktop -z 1024 -Z 4096  # Trace 1000~4000 byte allocations\n"
"    ./memleaktop -p 181           # Only trace PID 181\n"
"    ./memleaktop -t 123           # Only trace TID 123\n"
"    ./memleaktop -e               # Print per memory alloc size\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_INTEGER('i', "interval", &env.interval, "summary interval, seconds. Default 30", NULL, 0, 0),
	OPT_BOOLEAN('j', "csv", &env.csv, "just print fields: comma-separated values", NULL, 0, 0),
	OPT_INTEGER('p', "pid", &env.pid, "trace with this pid only", NULL, 0, 0),
	OPT_INTEGER('t', "tid", &env.tid, "trace with this tid only", NULL, 0, 0),
	OPT_STRING('s', "sample-rate", &sample_rate_str, "sample every N-th allocation to decrease the overhead", cb_sample_rate, 0, 0),
	OPT_INTEGER('r', "maxrows", &env.maxrows, "maximum rows to print, default 30", NULL, 0, 0),
	OPT_STRING('z', "min-size", &min_size_str, "capture only allocations larger than or equal to this size", cb_min_size, 0, 0),
	OPT_STRING('Z', "max-size", &max_size_str, "capture only allocations smaller than or equal to this size", cb_max_size, 0, 0),
	OPT_BOOLEAN('e', "extend", &env.extend, "print per memory alloc size", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "print the BPF program (for debugging purposes)", NULL, 0, 0),
	OPT_BOOLEAN(0, "wa-missing-free", &env.wa_missing_free, "Workaround to alleviate misjudgements when free is missing", NULL, 0, 0),
	OPT_INTEGER('m', "map-size", &env.map_size, "total entries of BPF map to track memleak. Default 500000", NULL, 0, 0),
	OPT_END(),
};


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int alloc_info_compare(const void *a, const void *b)
{
	const struct alloc_info *x = a;
	const struct alloc_info *y = b;

	if (x->val.size > y->val.size)
		return -1;
	if (x->val.size < y->val.size)
		return 1;
	return 0;
}

static int print_summary(struct memleaktop_bpf *skel)
{
	int pid_sizes_fd = bpf_map__fd(skel->maps.pid_sizes);
	int total_size_fd = bpf_map__fd(skel->maps.total_size);
	struct alloc_info *allocs = calloc(MAX_ENTRIES, sizeof(*allocs));
	if (!allocs) {
		fprintf(stderr, "Failed to allocate memory for allocs\n");
		return -1;
	}

	time_t t;
	struct tm *tm;

	if (env.csv) {
		char ts[32];
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("TIMESTAMP,PID:TID:NAME,ALLOC_SIZE,TOTAL_OUTSTANDING_MEM\n");
	} else {
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			printf("%s\n", asctime(tm));
		}
		printf("Summary outstanding memory allocate...\n");
		if (env.extend) {
			printf("%-8s %-8s %-16s %-12s %-12s %-22s\n", "PID", "TID", "NAME", "ALLOC_SIZE", "ALLOC_COUNT", "TOTAL_OUTSTANDING_MEM");
		} else {
			printf("%-8s %-8s %-16s %-12s %-22s\n", "PID", "TID", "NAME", "ALLOC_COUNT", "TOTAL_OUTSTANDING_MEM");
		}
	}

	struct key_t key = {}, next_key;
	int i = 0;
	while (bpf_map_get_next_key(pid_sizes_fd, &key, &next_key) == 0 && i < MAX_ENTRIES) {
		if (bpf_map_lookup_elem(pid_sizes_fd, &next_key, &allocs[i].val) == 0) {
			if (allocs[i].val.size > 0) {
				allocs[i].key = next_key;
				i++;
			}
		}
		key = next_key;
	}

	qsort(allocs, i, sizeof(*allocs), alloc_info_compare);

	int limit = MIN(i, env.maxrows);
	for (int j = 0; j < limit; j++) {
		if (env.csv) {
			printf("%ld,%d:%d:%s,%llu,%llu\n", time(NULL), allocs[j].key.tgid, allocs[j].key.pid, allocs[j].key.name, allocs[j].key.sz, allocs[j].val.size);
		} else {
			if (env.extend) {
				printf("%-8d %-8d %-16s %-12llu %-12llu %-22llu\n", allocs[j].key.tgid, allocs[j].key.pid, allocs[j].key.name, allocs[j].key.sz, allocs[j].val.count, allocs[j].val.size);
			} else {
				printf("%-8d %-8d %-16s %-12llu %-22llu\n", allocs[j].key.tgid, allocs[j].key.pid, allocs[j].key.name, allocs[j].val.count, allocs[j].val.size);
			}
		}
	}

	if (!env.csv) {
		__u32 key;
		__u64 val;
		key = 0;
		if(bpf_map_lookup_elem(total_size_fd, &key, &val) == 0)
			printf("kmalloc outstanding total size: %llu\n", val);
		key = 1;
		if(bpf_map_lookup_elem(total_size_fd, &key, &val) == 0)
			printf("kmem_cache_alloc outstanding total size: %llu\n", val);
		key = 2;
		if(bpf_map_lookup_elem(total_size_fd, &key, &val) == 0)
			printf("mm_page_alloc outstanding total size: %llu\n", val);
		key = 3;
		if(bpf_map_lookup_elem(total_size_fd, &key, &val) == 0)
			printf("ALLOC addr hash entry size: %llu\n", val);
		printf("\n");
	}

	free(allocs);
	return 0;
}

int main(int argc, char **argv)
{
	struct argparse argparse;
	int err;
	struct memleaktop_bpf *skel;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Trace outstanding memory allocations to detect memory leaks.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);
	if (env.min_size != 0 && env.max_size != -1 && env.min_size > env.max_size) {
		fprintf(stderr, "min_size can't be greater than max_size\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = memleaktop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->pid_filter = env.pid;
	skel->rodata->tid_filter = env.tid;
	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->extend_output = env.extend;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_max_entries(skel->maps.addr_sizes, env.map_size);
	bpf_map__set_max_entries(skel->maps.addr_pid_map_table, env.map_size);

	if (!tracepoint_exists("kmem", "kmalloc_node")) {
		bpf_program__set_autoload(skel->progs.memleaktop__kmalloc_node, false);
		bpf_program__set_autoload(skel->progs.memleaktop__kmem_cache_alloc_node, false);
	}

	err = memleaktop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = memleaktop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (env.csv) {
		printf("TIMESTAMP,PID:TID:NAME,ALLOC_SIZE,TOTAL_OUTSTANDING_MEM\n");
	} else {
		printf("Memory leak monitor as table... Hit Ctrl-C to end.\n\n");
	}

	while (!exiting) {
		sleep(env.interval);
		if (print_summary(skel) != 0)
			break;
	}

cleanup:
	memleaktop_bpf__destroy(skel);
	return -err;
}
