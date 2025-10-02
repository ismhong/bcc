// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 Realtek, Inc.
//
// Based on vmallocleak from bcc by Edward Wu.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "vmallocleak.h"
#include "vmallocleak.skel.h"
#include "trace_helpers.h"

#define MAX_STACK_DEPTH 32
#define MAX_ENTRIES 32768

static struct env {
	int interval;
	int maxrows;
	bool kernel_stacks;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 30,
	.maxrows = 30,
	.kernel_stacks = false,
	.timestamp = false,
	.verbose = false,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "vmallocleak 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_args_doc[] =
"USAGE: vmallocleak [-h] [-i INTERVAL] [-r MAXROWS] [-K] [-T]\n"
"\n"
"EXAMPLES:\n"
"    ./vmallocleak -i 20 -T         # Output every 20 second summary with timestamp\n"
"    ./vmallocleak -r 200           # Output 200 rows summary\n"
"    ./vmallocleak -K               # Output kernel stack\n"
"";

static const struct argp_option argp_options[] = {
	{"help", 'h', 0, 0, "Show this help message and exit", 0},
	{"interval", 'i', "INTERVAL", 0, "summary interval, seconds. Default 30", 0},
	{"maxrows", 'r', "MAXROWS", 0, "maximum rows to print, default 30", 0},
	{"kernel-stacks", 'K', 0, 0, "analysis kernel stack", 0},
	{"timestamp", 'T', 0, 0, "include timestamp on output", 0},
	{"verbose", 'v', NULL, 0, "verbose debug output", 0 },
	{},
};

struct outstanding_alloc {
	struct key_t key;
	struct val_t val;
};

static int alloc_size_compare(const void *a, const void *b)
{
	const struct outstanding_alloc *x = a;
	const struct outstanding_alloc *y = b;

	if (x->val.size > y->val.size)
		return -1;
	if (x->val.size < y->val.size)
		return 1;
	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_usage(state);
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		env.maxrows = strtol(arg, NULL, 10);
		if (errno || env.maxrows <= 0) {
			fprintf(stderr, "invalid maxrows: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'K':
		env.kernel_stacks = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
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

static void sig_handler(int signo)
{
	exiting = 1;
}

static int print_outstanding(struct vmallocleak_bpf *skel, struct ksyms *ksyms)
{
	int outstanding_fd = bpf_map__fd(skel->maps.outstanding_hash);
	int stacks_fd = bpf_map__fd(skel->maps.stack_traces);
	struct outstanding_alloc *allocs;
	int err = 0, i = 0;
	struct key_t *p_key = NULL, key;
	__u32 num_cpus = libbpf_num_possible_cpus();
	__u64 *total_counts;

	allocs = calloc(MAX_ENTRIES, sizeof(*allocs));
	if (!allocs) {
		fprintf(stderr, "failed to allocate memory for outstanding allocs\n");
		return -1;
	}

	while (bpf_map_get_next_key(outstanding_fd, p_key, &key) == 0) {
		allocs[i].key = key;
		err = bpf_map_lookup_elem(outstanding_fd, &key, &allocs[i].val);
		if (err) {
			fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
			goto cleanup;
		}
		p_key = &key;
		i++;
	}

	qsort(allocs, i, sizeof(*allocs), alloc_size_compare);

	if (env.kernel_stacks) {
		__u64 *stack_addrs = calloc(MAX_STACK_DEPTH, sizeof(*stack_addrs));
		if (!stack_addrs) {
			fprintf(stderr, "failed to allocate memory for stack addresses\n");
			err = -1;
			goto cleanup;
		}

		printf("Top %d stacks with outstanding allocations:\n", env.maxrows);
		for (int j = 0; j < i && j < env.maxrows; j++) {
			if (allocs[j].val.size == 0)
				continue;

			printf("\tAllocation PID:%d TID:%d NAME:%s size:%llu\n",
				allocs[j].key.tgid, allocs[j].key.pid, allocs[j].val.name, allocs[j].val.size);

			if (bpf_map_lookup_elem(stacks_fd, &allocs[j].key.stack_id, stack_addrs) != 0) {
				printf("\t\tstack information lost\n");
				continue;
			}

			for (int k = 0; k < MAX_STACK_DEPTH && stack_addrs[k]; k++) {
				const struct ksym *ksym = ksyms__map_addr(ksyms, stack_addrs[k]);
				if (ksym)
					printf("\t\t%s+0x%llx\n", ksym->name, stack_addrs[k] - ksym->addr);
				else
					printf("\t\t0x%llx\n", stack_addrs[k]);
			}
		}
		free(stack_addrs);
	} else {
		printf("%-8s %-8s %-17s %25s\n", "PID", "TID", "NAME", "TOTAL_OUTSTANDING_VMEM");
		for (int j = 0; j < i && j < env.maxrows; j++) {
			if (allocs[j].val.size == 0)
				continue;
			printf("%-8d %-8d %-17s %25llu\n",
				allocs[j].key.tgid, allocs[j].key.pid, allocs[j].val.name, allocs[j].val.size);
		}
	}

	int total_addr_size_fd = bpf_map__fd(skel->maps.total_addr_size);
	total_counts = calloc(num_cpus, sizeof(*total_counts));
	if (!total_counts) {
		fprintf(stderr, "failed to allocate memory for total counts\n");
		err = -1;
		goto cleanup;
	}
	__u32 zero = 0;
	__u64 total_count = 0;
	if (bpf_map_lookup_elem(total_addr_size_fd, &zero, total_counts) == 0) {
		for (__u32 cpu = 0; cpu < num_cpus; cpu++) {
			total_count += total_counts[cpu];
		}
	}
	printf("\nALLOC addr hash entry size: %llu\n", total_count);
	free(total_counts);

cleanup:
	free(allocs);
	return err;
}

int main(int argc, char **argv)
{
	struct vmallocleak_bpf *skel;
	int err;
	static const struct argp argp = {
		.options = argp_options,
		.parser = parse_arg,
		.doc = argp_args_doc,
	};
	struct ksyms *ksyms = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = vmallocleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->kernel_stacks = env.kernel_stacks;

	bpf_map__set_value_size(skel->maps.stack_traces, MAX_STACK_DEPTH * sizeof(__u64));

	err = vmallocleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = vmallocleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (env.kernel_stacks) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "Failed to load ksyms\n");
			err = -1;
			goto cleanup;
		}
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Virtual Contiguous Memory leak monitor ... Hit Ctrl-C to end.\n");

	while (!exiting) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);
			strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", localtime(&t));
			printf("%-8s\n", ts);
		}

		err = print_outstanding(skel, ksyms);
		if (err)
			break;
	}

cleanup:
	ksyms__free(ksyms);
	vmallocleak_bpf__destroy(skel);
	return -err;
}
