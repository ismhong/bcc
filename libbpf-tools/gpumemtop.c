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
#include "gpumemtop.h"
#include "gpumemtop.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

#define MAX_ENTRIES 10240

static struct env {
	int interval;
	int count;
	bool timestamp;
	bool csv;
	bool verbose;
} env = {
	.interval = 99999999,
	.count = 99999999,
	.timestamp = false,
	.csv = false,
	.verbose = false,
};

static const char *const usages[] = {
	"gpumemtop [-h] [-T] [-j] [-v] [interval] [count]",
	NULL,
};

const char doc[] =
"Analysis GPU memory usage as a table.\n"
"\n"
"EXAMPLES:\n"
"    ./gpumemtop             # trace all GPU memory usage\n"
"    ./gpumemtop 5           # 5 second summaries\n"
"    ./gpumemtop 5 10        # 5 second summaries, 10 times only\n"
"    ./gpumemtop -T 5        # ls summaries and timestamps\n"
"    ./gpumemtop -j 5        # Show to csv format log\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('j', "csv", &env.csv, "Just print fields: comma-separated values", NULL, 0, 0),
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

	if (pid == 0) {
		strcpy(comm, "[Global]");
		return 0;
	}

	sprintf(path, "/proc/%d/comm", pid);
	if (read_line(path, comm, TASK_COMM_LEN) < 0)
		strcpy(comm, "[unknown]");
	return 0;
}

static long get_uptime(void)
{
	char buf[64];

	if (read_line("/proc/uptime", buf, sizeof(buf)) < 0)
		return -1;

	return strtol(buf, NULL, 10);
}

struct gpu_mem_stat {
	struct gpu_mem_total_key key;
	__u64 total_mem_size;
	char comm[TASK_COMM_LEN];
};

static int sort_column_cb(const void *a, const void *b)
{
	const struct gpu_mem_stat *A = a;
	const struct gpu_mem_stat *B = b;

	if (B->total_mem_size > A->total_mem_size)
		return 1;
	if (B->total_mem_size < A->total_mem_size)
		return -1;
	return 0;
}

static int print_stat(struct gpumemtop_bpf *skel)
{
	int fd = bpf_map__fd(skel->maps.gpu_memory_hash);
	struct gpu_mem_stat stats[MAX_ENTRIES] = {};
	struct gpu_mem_total_key *p_key = NULL;
	struct gpu_mem_total_key next_key;
	__u64 value;
	int n = 0;
	long uptime = -1;

	if (env.csv) {
		uptime = get_uptime();
		if (uptime < 0) {
			fprintf(stderr, "failed to get uptime\n");
			return 1;
		}
	} else {
		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}
	}

	p_key = NULL;
	while (bpf_map_get_next_key(fd, p_key, &next_key) == 0) {
		if (n >= MAX_ENTRIES) {
			fprintf(stderr, "too many entries in map\n");
			break;
		}
		if (bpf_map_lookup_elem(fd, &next_key, &value) != 0) {
			fprintf(stderr, "bpf_map_lookup_elem failed for pid %d\n", next_key.pid);
			p_key = &next_key;
			continue;
		}
		stats[n].key = next_key;
		stats[n].total_mem_size = value;
		get_comm(stats[n].comm, next_key.pid);
		n++;
		p_key = &next_key;
	}

	qsort(stats, n, sizeof(struct gpu_mem_stat), sort_column_cb);

	for (int i = 0; i < n; i++) {
		if (env.csv) {
			printf("%ld,%u,%u,%s,%llu\n", uptime, stats[i].key.gpu_id, stats[i].key.pid, stats[i].comm, stats[i].total_mem_size);
		} else {
			printf("%6u %6u %17s %17llu\n", stats[i].key.gpu_id, stats[i].key.pid, stats[i].comm, stats[i].total_mem_size);
		}
	}

	if (!env.csv) {
		printf("\n");
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct gpumemtop_bpf *skel;
	struct argparse argparse;
	int err;
	time_t start_time;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Analysis GPU memory usage as a table.", doc);
	int non_opts = argparse_parse(&argparse, argc, (const char **)argv);

	if (non_opts > 0) {
		errno = 0;
		env.interval = strtol(argparse.out[0], NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "Invalid interval\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (non_opts > 1) {
		errno = 0;
		env.count = strtol(argparse.out[1], NULL, 10);
		if (errno || env.count <= 0) {
			fprintf(stderr, "Invalid count\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (non_opts > 2) {
		fprintf(stderr, "Unrecognized positional argument: %s\n", argparse.out[2]);
		argparse_usage(&argparse);
		return 1;
	}

	if (env.interval == 99999999)
		env.interval = 1;
	libbpf_set_print(libbpf_print_fn);

	if (!tracepoint_exists("gpu_mem", "gpu_mem_total")) {
		fprintf(stderr, "ERROR: Required tracepoint gpu_mem:gpu_mem_total doesn't exist\n");
		return 1;
	}

	if (env.csv && env.interval == 99999999) {
		fprintf(stderr, "csv output need to set interval\n");
		env.csv = false;
	}

	skel = gpumemtop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = gpumemtop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = gpumemtop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	start_time = time(NULL);

	if (env.csv) {
		printf("TIMESTAMP,GPU_ID,PID,NAME,TOTAL_MEM_SIZE\n");
	} else {
		printf("%6s %6s %17s %17s\n", "GPU_ID", "PID", "NAME", "TOTAL_MEM_SIZE");
	}

	while (true) {
		sleep(env.interval);

		if (print_stat(skel))
			break;

		env.count--;
		if (exiting || env.count == 0)
			break;
	}

	if (!env.csv) {
		time_t end_time = time(NULL);
		printf("Total Runtime : %-8ld\n", end_time - start_time);
	}

cleanup:
	gpumemtop_bpf__destroy(skel);
	return -err;
}
