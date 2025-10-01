// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * schedblockedtop   Analysis scheduler block behavior as a table.
 *
 * Copyright (c) 2020 Realtek, Inc.
 * Copyright (c) 2024 The Gemini Coder.
 *
 * Based on schedblockedtop(8) from BCC by Edward Wu.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedblockedtop.h"
#include "schedblockedtop.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SCALE {
	NSEC,
	USEC,
	MSEC,
};

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 40;
static enum SCALE scale = NSEC;
static bool per_pid = false;
static bool io_wait_only = false;
static bool timestamp = false;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "schedblockedtop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Analysis scheduler block behavior as a table.\n"
"\n"
"USAGE: schedblockedtop [-h] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    schedblockedtop            # scheduler block analysis, refresh every 1s\n"
"    schedblockedtop 5 10       # 5s summaries, 10 times\n"
"    schedblockedtop -P         # display separately for each process\n"
"    schedblockedtop -I         # filter iowait=1 only\n"
"    schedblockedtop -u         # display in microseconds\n";

static const struct argp_option opts[] = {
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "maxrows", 'r', "ROWS", 0, "Maximum rows to print, default 40", 0 },
	{ "microseconds", 'u', NULL, 0, "microsecond histogram", 0 },
	{ "milliseconds", 'm', NULL, 0, "millisecond histogram", 0 },
	{ "perpid", 'P', NULL, 0, "display separately for each process", 0 },
	{ "iowait", 'I', NULL, 0, "filter iowait=1 only", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long rows;
	static int pos_args;

	switch (key) {
	case 'C':
		clear_screen = false;
		break;
	case 'r':
		errno = 0;

rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'u':
		scale = USEC;
		break;
	case 'm':
		scale = MSEC;
		break;
	case 'P':
		per_pid = true;
		break;
	case 'I':
		io_wait_only = true;
		break;
	case 'T':
		timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

struct data_t {
	struct key_t key;
	struct val_t value;
};

static int sort_column(const void *obj1, const void *obj2)
{
	struct data_t *d1 = (struct data_t *) obj1;
	struct data_t *d2 = (struct data_t *) obj2;

	if (d1->value.total_latency > d2->value.total_latency)
		return -1;
	if (d1->value.total_latency < d2->value.total_latency)
		return 1;
	return 0;
}

static int read_stat(struct schedblockedtop_bpf *obj, struct data_t *datas, __u32 *count)
{
	struct key_t keys[OUTPUT_ROWS_LIMIT];
	struct val_t values[OUTPUT_ROWS_LIMIT];
	struct key_t invalid_key = {};
	int fd = bpf_map__fd(obj->maps.counts);
	int err;

	err = dump_hash(fd, keys, sizeof(struct key_t), values, sizeof(struct val_t),
			count, &invalid_key, true /* lookup_and_delete */);
	if (err)
		return err;

	for (int i = 0; i < *count; i++) {
		datas[i].key = keys[i];
		datas[i].value = values[i];
	}

	return 0;
}

static const char *scale_str(void)
{
	switch (scale) {
	case USEC:
		return "usecs";
	case MSEC:
		return "msecs";
	case NSEC:
	default:
		return "nsecs";
	}
}

static double scale_val(unsigned long long val)
{
	switch (scale) {
	case USEC:
		return (double)val / 1000;
	case MSEC:
		return (double)val / 1000000;
	case NSEC:
	default:
		return val;
	}
}

static int print_stat(struct schedblockedtop_bpf *obj, struct ksyms *ksyms)
{
	static struct data_t datas[OUTPUT_ROWS_LIMIT];
	int err = 0, rows = OUTPUT_ROWS_LIMIT;
	const char *unit = scale_str();

	if (timestamp) {
		char ts[32];
		time_t t;
		time(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
		printf("%-8s\n", ts);
	}

	printf("%-26s ", "CALLER");

	if (per_pid)
		printf("%-16s %-6s ", "COMM", "PID");

	printf("%-6s %16s %16s %16s %16s %5s %16s\n",
			"IOWAIT", "Total_latency", "MAX_latency", "MIN_latency",
			"Average_latency", "UNIT", "Total_counts");

	err = read_stat(obj, datas, (__u32*) &rows);
	if (err) {
		fprintf(stderr, "read stat failed: %s\n", strerror(errno));
		return err;
	}

	qsort(datas, rows, sizeof(struct data_t), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (int i = 0; i < rows; i++) {
		struct key_t *key = &datas[i].key;
		struct val_t *value = &datas[i].value;
		const struct ksym *ksym = ksyms__map_addr(ksyms, key->caller);

		if (ksym)
			printf("%-26s ", ksym->name);
		else
			printf("%-26llx ", key->caller);

		if (per_pid)
			printf("%-16s %-6d ", key->comm, key->pid);

		printf("%6d %16.0f %16.0f %16.0f %16.0f %5s %16lld\n",
				key->io_wait,
				scale_val(value->total_latency),
				scale_val(value->max_latency),
				scale_val(value->min_latency),
				scale_val(value->total_latency / value->count),
				unit, value->count);
	}

	printf("\n");
	return err;
}

static bool check_kernel_settings(void)
{
	FILE *f;

	f = fopen("/proc/sys/kernel/sched_schedstats", "r");
	if (!f) {
		warn("failed to open /proc/sys/kernel/sched_schedstats: %s\n", strerror(errno));
		return false;
	}
	int val;
	if (fscanf(f, "%d\n", &val) != 1) {
		warn("failed to read /proc/sys/kernel/sched_schedstats\n");
		fclose(f);
		return false;
	}
	fclose(f);

	if (val == 0) {
		warn("ERROR: sched_schedstats is disabled.\n");
		warn("Please run: echo 1 > /proc/sys/kernel/sched_schedstats\n");
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct schedblockedtop_bpf *obj;
	struct ksyms *ksyms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	if (!check_kernel_settings())
		return 1;

	if (!tracepoint_exists("sched", "sched_stat_blocked") ||
		!tracepoint_exists("sched", "sched_blocked_reason")) {
		warn("ERROR: Required sched tracepoints not found.\n");
		return 1;
	}

	obj = schedblockedtop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->per_pid = per_pid;
	obj->rodata->io_wait_only = io_wait_only;

	ksyms = ksyms__load();
	if (!ksyms) {
		err = -ENOMEM;
		warn("failed to load kallsyms\n");
		goto cleanup;
	}

	err = schedblockedtop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = schedblockedtop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj, ksyms);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	ksyms__free(ksyms);
	schedblockedtop_bpf__destroy(obj);

	return err != 0;
}
