// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "argparse.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "smctop.h"
#include "smctop.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 40;
static bool per_optee_call = false;
static bool isr_schout_time = false;
static bool timestamp = false;
static int interval = 1;
static int count = 99999999;
static int core = -1;
static bool ftrace = false;
static bool verbose = false;

const char *argp_program_version = "smctop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Analysis OPTEE behavior as a table.\n"
"\n"
"USAGE: smctop [-h] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    smctop             # OPTEE top, 1 second refresh\n"
"    smctop 5 10        # 5s summaries, 10 times\n"
"    smctop -o          # measure latency as per optee call instead of smc call\n"
"    smctop -I          # OPTEE latency includes ISR interrupt & sched out time\n"
"    smctop -c 2        # filter CPU core 2\n";

static int handle_noclear(struct argparse *self, const struct argparse_option *option)
{
	clear_screen = false;
	return 0;
}

static const char * const usages[] = {
	"smctop [-h] [interval] [count]",
	NULL,
};

static struct argparse_option options[] = {
	OPT_BOOLEAN('C', "noclear", NULL, "Don't clear the screen", handle_noclear, 0, 0),
	OPT_INTEGER('r', "maxrows", &output_rows, "Maximum rows to print, default 40", NULL, 0, 0),
	OPT_BOOLEAN('o', "per-optee-call", &per_optee_call, "Measure latency per optee call instead of smc call", NULL, 0, 0),
	OPT_BOOLEAN('I', "isr-schout-time", &isr_schout_time, "OPTEE latency includes ISR interrupt & schedule out time", NULL, 0, 0),
	OPT_INTEGER('c', "core", &core, "Filter specific CPU core", NULL, 0, 0),
	OPT_BOOLEAN('f', "ftrace", &ftrace, "ftrace debug", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &verbose, "Verbose debug output", NULL, 0, 0),
	OPT_HELP(),
	OPT_END(),
};

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
	struct optee_latency_key_t key;
	struct latency_val_t value;
};

static int sort_column(const void *obj1, const void *obj2)
{
	struct data_t *d1 = (struct data_t *) obj1;
	struct data_t *d2 = (struct data_t *) obj2;

	if (d1->value.max > d2->value.max)
		return -1;
	if (d1->value.max < d2->value.max)
		return 1;
	return 0;
}

static int read_stat(struct smctop_bpf *obj, struct data_t *datas, __u32 *count)
{
	struct optee_latency_key_t keys[OUTPUT_ROWS_LIMIT];
	struct latency_val_t values[OUTPUT_ROWS_LIMIT];
	struct optee_latency_key_t invalid_key = {};
	int fd = bpf_map__fd(obj->maps.optee_latency_hash);
	int err;

	err = dump_hash(fd, keys, sizeof(struct optee_latency_key_t), values, sizeof(struct latency_val_t),
			count, &invalid_key, true /* lookup_and_delete */);
	if (err)
		return err;

	for (int i = 0; i < *count; i++) {
		datas[i].key = keys[i];
		datas[i].value = values[i];
	}

	return 0;
}

static int print_stat(struct smctop_bpf *obj)
{
	static struct data_t datas[OUTPUT_ROWS_LIMIT];
	int err = 0, rows = OUTPUT_ROWS_LIMIT;

	if (timestamp) {
		char ts[32];
		time_t t;
		time(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
		printf("%-8s\n", ts);
	}

	if (per_optee_call) {
		printf("%-" "5s %-5s %-16s %-12s %-8s %-14s %-8s %-6s %14s %14s %22s %16s %12s %12s %14s %9s %4s\n",
			"PID", "TID", "COMM", "Low", "Mid", "HiAndVersion", "session", "func",
			"INVOKE_MAX_lat", "INVOKE_MIN_lat", "INVOKE_MAX_SCHOUT_lat",
			"INVOKE_Total_lat", "INVOKE_cnts", "ISR_MAX_lat", "ISR_Total_lat", "ISR_cnts", "Unit");
	} else {
		printf("%-" "5s %-5s %-16s %-12s %-8s %-14s %-8s %-6s %14s %14s %22s %16s %12s %12s %14s %9s %4s\n",
			"PID", "TID", "COMM", "Low", "Mid", "HiAndVersion", "session", "func",
			"SMCCC_MAX_lat", "SMCCC_MIN_lat", "SMCCC_MAX_SCHOUT_lat",
			"SMCCC_Total_lat", "SMCCC_cnts", "ISR_MAX_lat", "ISR_Total_lat", "ISR_cnts", "Unit");
	}

	err = read_stat(obj, datas, (__u32*) &rows);
	if (err) {
		fprintf(stderr, "read stat failed: %s\n", strerror(errno));
		return err;
	}

	qsort(datas, rows, sizeof(struct data_t), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (int i = 0; i < rows; i++) {
		struct optee_latency_key_t *key = &datas[i].key;
		struct latency_val_t *value = &datas[i].value;

		printf("%-" "5d %-5d %-16s 0x%-10x 0x%-6x 0x%-12x %-8d %-6d %14llu %14llu %22llu %16llu %12llu %12llu %14llu %9llu %4s\n",
			key->tgid, key->pid, key->name, key->timeLow, key->timeMid, key->timeHiAndVersion,
			key->session, key->func, value->max, value->min, value->schedout_max,
			value->total_latency, value->total_count, value->isr_max, value->isr_total_latency,
			value->isr_total_count, "usec");
	}

	printf("\n");
	return err;
}

int main(int argc, char **argv)
{
	struct smctop_bpf *obj;
	struct argparse argparse;
	int err;
	bool use_optee_tp = false;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, argp_program_doc, NULL);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (output_rows <= 0) {
		warn("invalid rows: %d\n", output_rows);
		argparse_usage(&argparse);
		return 1;
	}
	if (output_rows > OUTPUT_ROWS_LIMIT)
		output_rows = OUTPUT_ROWS_LIMIT;

	if (core < -1) {
		warn("invalid core: %d\n", core);
		argparse_usage(&argparse);
		return 1;
	}

	if (argc > 0) {
		interval = atoi(argv[0]);
		if (interval <= 0) {
			warn("invalid interval\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 1) {
		count = atoi(argv[1]);
		if (count <= 0) {
			warn("invalid count\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 2) {
		warn("unrecognized positional arguments\n");
		argparse_usage(&argparse);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	if (ftrace) {
		FILE *f = fopen("/sys/kernel/tracing/tracing_on", "r");
		if (f) {
			int val;
			if (fscanf(f, "%d\n", &val) != 1 || val == 0) {
				warn("Warning: ftrace is not enabled. Please run: echo 1 > /sys/kernel/tracing/tracing_on\n");
			}
			fclose(f);
		} else {
			warn("Warning: can't open /sys/kernel/tracing/tracing_on: %s\n", strerror(errno));
		}
	}

	if (isr_schout_time)
		printf("HINT: %s_latency includes ISR inturrupt and schedule out latency\n", per_optee_call ? "INVOKE" : "SMCCC");
	else
		printf("HINT: %s_latency doesn't includes ISR inturrupt and schedule out latency\n", per_optee_call ? "INVOKE" : "SMCCC");


	obj = smctop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->per_optee_call = per_optee_call;
	obj->rodata->isr_schout_time = isr_schout_time;
	obj->rodata->core = core;
	obj->rodata->ftrace = ftrace;

	if (tracepoint_exists("optee", "optee_open_session_exit") &&
		tracepoint_exists("optee", "optee_invoke_func_entry") &&
		tracepoint_exists("optee", "optee_invoke_func_exit")) {
		use_optee_tp = true;
	}

	if (use_optee_tp) {
		bpf_program__set_autoload(obj->progs.optee_open_session_entry, false);
		bpf_program__set_autoload(obj->progs.tee_shm_free_entry, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_entry, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_exit, false);
		bpf_program__set_autoload(obj->progs.optee_close_session_entry, false);
		bpf_program__set_autoload(obj->progs.optee_close_session_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.optee_open_session_exit_tp, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_entry_tp, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_exit_tp, false);
		bpf_program__set_autoload(obj->progs.optee_close_session_entry_tp, false);
		bpf_program__set_autoload(obj->progs.optee_close_session_exit_tp, false);
	}

	if (!kprobe_exists("handle_IPI"))
		bpf_program__set_autoload(obj->progs.inter_processor_irq_entry, false);

	err = smctop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = smctop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing OPTEE count and latency ... Hit Ctrl-C to end.\n");

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	smctop_bpf__destroy(obj);

	return err != 0;
}
