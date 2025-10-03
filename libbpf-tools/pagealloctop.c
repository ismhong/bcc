// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
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

const char *argp_program_version = "pagealloctop 0.1";
const char *argp_program_bug_address = "iovisor/bcc <project@iovisor.org>";
const char argp_program_doc[] =
"Analyze page allocation as a table.\n"
"\n"
"USAGE: ./pagealloctop [-h] [-i INTERVAL] [-d DURATION] [-m] [-T] [-t TOP]\n"
"\n"
"EXAMPLES:\n"
"    ./pagealloctop -i 2              # output every 2 seconds as kilobytes\n"
"    ./pagealloctop -i 2 -T           # output every 2 seconds with timestamp\n"
"    ./pagealloctop -i 2 -m           # output every 2 seconds as megabytes\n"
"    ./pagealloctop -i 2 -t 50        # 50 top rank list\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "SECONDS", 0, "summary interval, in seconds", 0 },
	{ "duration", 'd', "SECONDS", 0, "total duration of trace, in seconds", 0 },
	{ "megabyte", 'm', NULL, 0, "output in megabytes", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "top", 't', "COUNT", 0, "display only this many top allocating stacks (by size)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, ARGP_KEY_FINI, "Show this help message and exit", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state);

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "Invalid interval\n");
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration\n");
			argp_usage(state);
		}
		break;
	case 'm':
		env.megabyte = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 't':
		errno = 0;
		env.top = strtol(arg, NULL, 10);
		if (errno || env.top <= 0) {
			fprintf(stderr, "Invalid top count\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.duration != 99999999) {
			if (env.interval == 0)
				env.interval = env.duration;
			env.count = env.duration / env.interval;
		}
		if (env.interval == 0)
			env.interval = 99999999;
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

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static int read_line(const char *path, char *buf, int size)
{
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return -1;

	if (!fgets(buf, size, f)) {
		fclose(f);
		return -1;
	}

	buf[strcspn(buf, "\n")] = '\0';

	fclose(f);

	return 0;
}

static int get_comm(char *comm, int pid)
{
	char path[64];

	sprintf(path, "/proc/%d/comm", pid);
	if (read_line(path, comm, TASK_COMM_LEN) < 0)
		strcpy(comm, "[unknown]");
	return 0;
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
		printf("%-8s\n", ts);
	} else {
		printf("\n");
	}

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
		get_comm(stats[n].comm, next_pid);
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
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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

	printf("%-6s %-6s %-16s %12s %12s %12s\n", "TGID", "PID",
			"COMM", "MOVABLE_SZ", "UNMOVABLE_SZ",
			env.megabyte ? "TOTAL_SZ(MB)" : "TOTAL_SZ(KB)");

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
