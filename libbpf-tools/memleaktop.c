// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Realtek, Inc.
#include <argp.h>
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

const char *argp_program_version = "memleaktop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_args_doc[] =
"Trace outstanding memory allocations to detect memory leaks.\n"
"\n"
"USAGE: memleaktop [-h] [-i INTERVAL] [-s SAMPLE_RATE] [-r MAXROWS] [-z MIN_SIZE] [-Z MAX_SIZE] [-p PID] [-t TID] [-e] [-T] [-j] [--wa-missing-free] [-m MAP_SIZE]\n"
"\n"
"EXAMPLES:\n"
"    ./memleaktop -i 20 -T         # Output every 20 second summary with timestamp\n"
"    ./memleaktop -s 5             # Trace roughly every 5th allocation, to reduce overhead\n"
"    ./memleaktop -j -i 20 -T      # Show to csv format log with timestamp\n"
"    ./memleaktop -z 1024 -Z 4096  # Trace 1000~4000 byte allocations\n"
"    ./memleaktop -p 181           # Only trace PID 181\n"
"    ./memleaktop -t 123           # Only trace TID 123\n"
"    ./memleaktop -e               # Print per memory alloc size\n";

static const struct argp_option opts[] = {
	{ "help", 'h', 0, 0, "Show this help message and exit", 0 },
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds. Default 30", 0 },
	{ "csv", 'j', 0, 0, "just print fields: comma-separated values", 0 },
	{ "pid", 'p', "PID", 0, "trace with this pid only", 0 },
	{ "tid", 't', "TID", 0, "trace with this tid only", 0 },
	{ "sample-rate", 's', "RATE", 0, "sample every N-th allocation to decrease the overhead", 0 },
	{ "maxrows", 'r', "MAXROWS", 0, "maximum rows to print, default 30", 0 },
	{ "min-size", 'z', "SIZE", 0, "capture only allocations larger than or equal to this size", 0 },
	{ "max-size", 'Z', "SIZE", 0, "capture only allocations smaller than or equal to this size", 0 },
	{ "extend", 'e', 0, 0, "print per memory alloc size", 0 },
	{ "timestamp", 'T', 0, 0, "include timestamp on output", 0 },
	{ "verbose", 'v', 0, 0, "print the BPF program (for debugging purposes)", 0 },
	{ "wa-missing-free", 1, 0, 0, "Workaround to alleviate misjudgements when free is missing", 0 },
	{ "map-size", 'm', "SIZE", 0, "total entries of BPF map to track memleak. Default 500000", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stdout, ARGP_HELP_USAGE | ARGP_HELP_LONG);
		exit(0);
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'j':
		env.csv = true;
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 't':
		env.tid = strtol(arg, NULL, 10);
		break;
	case 's':
		env.sample_rate = strtol(arg, NULL, 10);
		break;
	case 'r':
		env.maxrows = strtol(arg, NULL, 10);
		break;
	case 'z':
		env.min_size = strtol(arg, NULL, 10);
		break;
	case 'Z':
		env.max_size = strtol(arg, NULL, 10);
		break;
	case 'e':
		env.extend = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 1: /* --wa-missing-free */
		env.wa_missing_free = true;
		break;
	case 'm':
		env.map_size = strtol(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

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
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_args_doc,
	};
	int err;
	struct memleaktop_bpf *skel;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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
