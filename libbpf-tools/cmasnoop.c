// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Realtek, Inc. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cmasnoop.h"
#include "cmasnoop.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

static struct env {
	bool addr_range;
	bool contig_range;
	int duration;
	bool verbose;
} env = {
	.duration = 0,
};

static const char *const usages[] = {
	"cmasnoop [-h] [-d DURATION] [--contig_range] [-r]",
	NULL,
};

const char doc[] =
"Trace CMA allocation.\n"
"\n"
"EXAMPLES:\n"
"    ./cmasnoop                   # trace all cma allocations\n"
"    ./cmasnoop -d 10             # trace for 10 seconds only\n"
"    ./cmasnoop --contig_range    # track alloc_contig_range()\n"
"    ./cmasnoop -r                # track CMA track address range\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('r', "addr_range", &env.addr_range, "Track address range", NULL, 0, 0),
	OPT_BOOLEAN('c', "contig_range", &env.contig_range, "Track alloc_contig_range()", NULL, 0, 0),
	OPT_INTEGER('d', "duration", &env.duration, "Total duration of trace in seconds", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	static long long start_ts;
	long long page_size = sysconf(_SC_PAGESIZE);

	if (start_ts == 0)
		start_ts = get_ktime_ns();

	if (env.addr_range) {
		unsigned long long start_addr = 0, end_addr = 0;
		if (!e->fail) {
			start_addr = (unsigned long long)e->pfn * page_size;
			end_addr = ((unsigned long long)e->pfn + e->count) * page_size;
		}
		printf("%-11.6f %-14.14s %-6d %-6d %8.2f %5llu %10llx %10llx %5u %8s %8s %8lld\n",
			(get_ktime_ns() - start_ts) / 1000000000.0,
			e->comm, e->tgid, e->pid,
			(float)e->duration / 1000000,
			e->count, start_addr, end_addr, e->align,
			e->alloc ? "alloc" : "release",
			e->fail ? "FAIL" : "SUCCESS", e->total_sz);
	} else if (env.contig_range) {
		printf("%-11.6f %-14.14s %-6d %-6d %8.2f %5llu %5s %8s %8s %8lld\n",
			(get_ktime_ns() - start_ts) / 1000000000.0,
			e->comm, e->tgid, e->pid,
			(float)e->duration / 1000000,
			e->count, "NULL",
			e->alloc ? "alloc" : "release",
			e->fail ? "FAIL" : "SUCCESS", e->total_sz);
	} else {
		printf("%-11.6f %-14.14s %-6d %-6d %8.2f %5llu %5u %8s %8s %8lld\n",
			(get_ktime_ns() - start_ts) / 1000000000.0,
			e->comm, e->tgid, e->pid,
			(float)e->duration / 1000000,
			e->count, e->align,
			e->alloc ? "alloc" : "release",
			e->fail ? "FAIL" : "SUCCESS", e->total_sz);
	}

	return 0;
}

static void print_headers(void)
{
	if (env.addr_range) {
		printf("%-11s %-14s %-6s %-6s %8s %5s %10s %10s %5s %8s %8s %8s\n",
				"TIME(s)", "COMM", "TGID", "PID", "LAT(ms)",
				"PAGES", "START_ADDR", "END_ADDR", "ALIGN", "ACTION", "RESULT",
				"LEAK_PG");
	} else {
		printf("%-11s %-14s %-6s %-6s %8s %5s %5s %8s %8s %8s\n",
				"TIME(s)", "COMM", "TGID", "PID", "LAT(ms)",
				"PAGES", "ALIGN", "ACTION", "RESULT", "LEAK_PG");
	}
}

int main(int argc, char **argv)
{
	struct argparse argparse;
	struct ring_buffer *rb = NULL;
	struct cmasnoop_bpf *skel;
	int err;
	time_t start_time;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Trace CMA allocation.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (env.duration < 0) {
		fprintf(stderr, "Invalid duration: %d\n", env.duration);
		argparse_usage(&argparse);
		return 1;
	}
	if (env.contig_range && env.addr_range) {
		fprintf(stderr, "ERROR: We don't support contig_range and addr_range together yet\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = cmasnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->contig_range = env.contig_range;
	skel->rodata->addr_range = env.addr_range;
	skel->rodata->has_cma_alloc_finish = tracepoint_exists("cma", "cma_alloc_finish");

	if (!env.contig_range) {
		bpf_program__set_autoload(skel->progs.alloc_contig_range_entry, false);
		bpf_program__set_autoload(skel->progs.alloc_contig_range_return, false);
	} else {
		bpf_program__set_autoload(skel->progs.cma_alloc_entry, false);
		bpf_program__set_autoload(skel->progs.cma_alloc_return, false);
	}

	if (!env.addr_range) {
		bpf_program__set_autoload(skel->progs.cma_alloc_finish, false);
		bpf_program__set_autoload(skel->progs.cma_alloc, false);
	} else {
		if (skel->rodata->has_cma_alloc_finish) {
			bpf_program__set_autoload(skel->progs.cma_alloc, false);
		} else {
			bpf_program__set_autoload(skel->progs.cma_alloc_finish, false);
		}
	}

	err = cmasnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int zero = 0;
	__s64 val = 0;
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.total_outstanding_sz), &zero, &val, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to initialize total_outstanding_sz map\n");
		goto cleanup;
	}

	err = cmasnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR ||
		signal(SIGTERM, sig_handler) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	print_headers();

	start_time = time(NULL);
	while (!exiting) {
		if (env.duration > 0 && (time(NULL) - start_time) >= env.duration)
			break;

		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	cmasnoop_bpf__destroy(skel);
	return -err;
}
