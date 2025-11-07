// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pagealloctop.h"
#include "pagealloctop.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

#define MAX_ENTRIES 10240

static struct env {
	int interval;
	int duration;
	bool megabyte;
	bool timestamp;
	int top;
	int count;
	bool verbose;
} env = {
	.interval = 0,
	.duration = 99999999,
	.megabyte = false,
	.timestamp = false,
	.top = 30,
	.count = 99999999,
	.verbose = false,
};

static const char *const usages[] = {
	"pagealloctop [-h] [-i INTERVAL] [-d DURATION] [-m] [-T] [-t TOP]",
	NULL,
};

static const char doc[] =
"Analyze page allocation as a table.\n"
"\n"
"USAGE: ./pagealloctop [-h] [-i INTERVAL] [-d DURATION] [-m] [-T] [-t TOP]\n"
"\n"
"EXAMPLES:\n"
"    ./pagealloctop -i 2              # output every 2 seconds as kilobytes\n"
"    ./pagealloctop -i 2 -T           # output every 2 seconds with timestamp\n"
"    ./pagealloctop -i 2 -m           # output every 2 seconds as megabytes\n"
"    ./pagealloctop -i 2 -t 50        # 50 top rank list\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_INTEGER('i', "interval", &env.interval, "summary interval, in seconds", NULL, 0, 0),
	OPT_INTEGER('d', "duration", &env.duration, "total duration of trace, in seconds", NULL, 0, 0),
	OPT_BOOLEAN('m', "megabyte", &env.megabyte, "output in megabytes", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "include timestamp on output", NULL, 0, 0),
	OPT_INTEGER('t', "top", &env.top, "display only this many top allocating stacks (by size)", NULL, 0, 0),
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

struct alloc_info {
	__u32 pid;
	__u32 tgid;
	__u64 movable_size;
	__u64 unmovable_size;
	char comm[TASK_COMM_LEN];
};

static int sort_cb(const void *a, const void *b)
{
	const struct alloc_info *A = a;
	const struct alloc_info *B = b;
	__u64 total_A = A->movable_size + A->unmovable_size;
	__u64 total_B = B->movable_size + B->unmovable_size;

	if (total_B > total_A)
		return 1;
	if (total_B < total_A)
		return -1;
	return 0;
}

static int print_stat(struct pagealloctop_bpf *skel)
{
	int fd = bpf_map__fd(skel->maps.page_alloc_hash);
	struct alloc_info stats[MAX_ENTRIES] = {};
	__u32 keys_to_delete[MAX_ENTRIES] = {};
	int key_count = 0;
	__u32 lookup_pid = -1, next_pid;
	struct page_alloc_stat stat_val;
	int n = 0;

	if (env.timestamp) {
		char ts[32];
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("\n%-8s\n", ts);
	} else {
		printf("\n");
	}

	printf("%-6s %-6s %-16s %12s %12s %12s\n", "TGID", "PID",
			"COMM", "MOVABLE_SZ", "UNMOVABLE_SZ",
			env.megabyte ? "TOTAL_SZ(MB)" : "TOTAL_SZ(KB)");

	while (bpf_map_get_next_key(fd, &lookup_pid, &next_pid) == 0) {
		if (n >= MAX_ENTRIES) {
			fprintf(stderr, "too many entries in map\n");
			break;
		}
		if (bpf_map_lookup_elem(fd, &next_pid, &stat_val) != 0) {
			fprintf(stderr, "bpf_map_lookup_elem failed for pid %d\n", next_pid);
			lookup_pid = next_pid;
			continue;
		}
		stats[n].pid = next_pid;
		stats[n].tgid = stat_val.tgid;
		stats[n].movable_size = stat_val.movable_size;
		stats[n].unmovable_size = stat_val.unmovable_size;
		strcpy(stats[n].comm, stat_val.comm);
		n++;
		keys_to_delete[key_count++] = next_pid;
		lookup_pid = next_pid;
	}

	qsort(stats, n, sizeof(struct alloc_info), sort_cb);

	for (int i = 0; i < n && i < env.top; i++) {
		__u64 movable_sz = stats[i].movable_size;
		__u64 unmovable_sz = stats[i].unmovable_size;
		__u64 total_sz = movable_sz + unmovable_sz;

		if (env.megabyte) {
			movable_sz /= (1024 * 1024);
			unmovable_sz /= (1024 * 1024);
			total_sz /= (1024 * 1024);
		} else {
			movable_sz /= 1024;
			unmovable_sz /= 1024;
			total_sz /= 1024;
		}

		printf("%-6u %-6u %-16s %12llu %12llu %12llu\n",
			stats[i].tgid, stats[i].pid, stats[i].comm,
			movable_sz, unmovable_sz, total_sz);
	}

	for (int i = 0; i < key_count; i++) {
		bpf_map_delete_elem(fd, &keys_to_delete[i]);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct pagealloctop_bpf *skel;
	struct argparse argparse;
	int err;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, doc, "\n");
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (env.interval <= 0) {
		fprintf(stderr, "Invalid interval\n");
		argparse_usage(&argparse);
		return 1;
	}
	if (env.duration <= 0) {
		fprintf(stderr, "Invalid duration\n");
		argparse_usage(&argparse);
		return 1;
	}
	if (env.top <= 0) {
		fprintf(stderr, "Invalid top count\n");
		argparse_usage(&argparse);
		return 1;
	}

	if (env.duration != 99999999) {
		if (env.interval == 0)
			env.interval = env.duration;
		env.count = env.duration / env.interval;
	}
	if (env.interval == 0)
		env.interval = 99999999;

	libbpf_set_print(libbpf_print_fn);
	if (!tracepoint_exists("kmem", "mm_page_alloc")) {
		fprintf(stderr, "ERROR: Required tracepoint kmem:mm_page_alloc doesn't exist\n");
		return 1;
	}

	skel = pagealloctop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = pagealloctop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = pagealloctop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (true) {
		if (env.interval != 99999999)
			sleep(env.interval);
		else
			while(!exiting)
				sleep(1);

		if (print_stat(skel))
			break;

		env.count--;
		if (exiting || env.count == 0)
			break;
	}

cleanup:
	pagealloctop_bpf__destroy(skel);
	return -err;
}
