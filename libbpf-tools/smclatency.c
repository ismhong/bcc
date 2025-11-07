// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Realtek, Inc. */
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

#include "smclatency.h"
#include "smclatency.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static int core = -1;
static int interval = -1;
static int duration = -1;
static int nr_cpus;
static bool ftrace = false;
static bool isr_time = false;
static bool timestamp = false;
static bool microseconds = false;
static bool milliseconds = false;
static bool verbose = false;

const char *argp_program_version = "smclatency 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Time __arm_smccc_smc function and print latency as a histogram."
"\n"
"USAGE: smclatency [-h] [-c CORE] [-i INTERVAL] [-d DURATION] [-f] [-I] [-T] [-u] [-m] [-v]\n"
"\n"
"EXAMPLES:\n"
"    smclatency -u                # in microseconds\n"
"    smclatency -m                # in milliseconds\n"
"    smclatency -i 2 -d 10        # output every 2 seconds, for duration 10s\n"
"    smclatency -mTi 5            # output every 5 seconds, with timestamps\n"
"    smclatency -i 2 -c 2         # filter CPU core 2\n"
"    smclatency 5 -I              # smc latency includes ISR interrupt time\n"
"    smclatency 5 -f              # ftrace debug\n";

static const char * const usages[] = {
	"smclatency [-h] [-c CORE] [-i INTERVAL] [-d DURATION] [-f] [-I] [-T] [-u] [-m] [-v]",
	NULL,
};

static struct argparse_option options[] = {
	OPT_INTEGER('c', "core", &core, "filter specific CPU core", NULL, 0, 0),
	OPT_INTEGER('i', "interval", &interval, "summary interval, in seconds", NULL, 0, 0),
	OPT_INTEGER('d', "duration", &duration, "total duration of trace, in seconds", NULL, 0, 0),
	OPT_BOOLEAN('f', "ftrace", &ftrace, "ftrace debug", NULL, 0, 0),
	OPT_BOOLEAN('I', "isr_time", &isr_time, "smc latency includes ISR interrupt time", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &timestamp, "include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('u', "microseconds", &microseconds, "microsecond histogram", NULL, 0, 0),
	OPT_BOOLEAN('m', "milliseconds", &milliseconds, "millisecond histogram", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &verbose, "print the BPF program (for debugging purposes)", NULL, 0, 0),
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

static int read_proc_stat(struct cpu_stat *stats)
{
	FILE *f = fopen("/proc/stat", "r");
	if (!f) {
		warn("failed to open /proc/stat: %s\n", strerror(errno));
		return -1;
	}

	for (int i = 0; i < nr_cpus + 1; i++) {
		char line[1024];
		if (!fgets(line, sizeof(line), f)) {
			break;
		}
		sscanf(line, "%s %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
			stats[i].name, &stats[i].user, &stats[i].nice, &stats[i].system,
			&stats[i].idle, &stats[i].iowait, &stats[i].irq, &stats[i].softirq,
			&stats[i].steal, &stats[i].guest, &stats[i].guest_nice);
	}

	fclose(f);
	return 0;
}

int main(int argc, char **argv)
{
	struct smclatency_bpf *obj;
	struct cpu_stat *start_stats = NULL, *end_stats = NULL;
	__u64 *latency_vals = NULL;
	struct argparse argparse;
	int err;
	const char *label;
	long clk_tck;
	time_t start_time_t;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, argp_program_doc, NULL);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (core < 0 && core != -1) {
		warn("invalid core: %d\n", core);
		argparse_usage(&argparse);
		return 1;
	}
	if (interval <= 0 && interval != -1) {
		warn("invalid interval: %d\n", interval);
		argparse_usage(&argparse);
		return 1;
	}
	if (duration <= 0 && duration != -1) {
		warn("invalid duration: %d\n", duration);
		argparse_usage(&argparse);
		return 1;
	}

	clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) {
		warn("failed to get sysconf(_SC_CLK_TCK): %s\n", strerror(errno));
		return 1;
	}

	if (duration != -1 && interval == -1)
		interval = duration;
	if (interval == -1)
		interval = 99999999;

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		warn("failed to get # of possible cpus: '%s'\n", strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		warn("cpu number %d exceeds max supported cpus %d.\n", nr_cpus, MAX_CPU_NR);
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

	if (isr_time)
		printf("HINT: SMCCC_latency includes ISR inturrupt latency\n");
	else
		printf("HINT: SMCCC_latency doesn't include ISR inturrupt latency\n");

	obj = smclatency_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->core = core;
	obj->rodata->ftrace = ftrace;
	obj->rodata->isr_time = isr_time;
	if (milliseconds) {
		obj->rodata->factor = 1000000;
		label = "msecs";
	} else if (microseconds) {
		obj->rodata->factor = 1000;
		label = "usecs";
	} else {
		obj->rodata->factor = 1;
		label = "nsecs";
	}

	if (!kprobe_exists("handle_IPI"))
		bpf_program__set_autoload(obj->progs.inter_processor_irq_entry, false);

	err = smclatency_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss) {
		warn("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = smclatency_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	time(&start_time_t); // Record start time
	printf("Tracing __arm_smccc_smc count and latency ... Hit Ctrl-C to end.\n");

	start_stats = calloc(nr_cpus + 1, sizeof(struct cpu_stat));
	end_stats = calloc(nr_cpus + 1, sizeof(struct cpu_stat));
	latency_vals = calloc(nr_cpus, sizeof(__u64));
	if (!start_stats || !end_stats || !latency_vals) {
		warn("failed to allocate memory\n");
		err = 1;
		goto cleanup;
	}

	read_proc_stat(start_stats);

	int loops = -1;
	if (duration > 0)
		loops = (duration + interval - 1) / interval;

	while (1) {
		sleep(interval);

		printf("\n");
		if (timestamp) {
			char ts[32];
			time_t t;
			time(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
			printf("%-8s\n", ts);
		}

		read_proc_stat(end_stats);

		printf("%6s %7s %7s %7s %8s %8s %7s %8s %7s %7s %8s\n",
				"CPU", "user", "nice", "kernel", "teeworld", "iowait", "irq",
				"softirq", "steal", "guest", "idle");

		for (int i = 0; i < nr_cpus + 1; i++) {
			long long time_diffs[11];
			double total_time = 0;

			time_diffs[0] = end_stats[i].user - start_stats[i].user;
			time_diffs[1] = end_stats[i].nice - start_stats[i].nice;
			time_diffs[2] = end_stats[i].system - start_stats[i].system;
			time_diffs[3] = end_stats[i].idle - start_stats[i].idle;
			time_diffs[4] = end_stats[i].iowait - start_stats[i].iowait;
			time_diffs[5] = end_stats[i].irq - start_stats[i].irq;
			time_diffs[6] = end_stats[i].softirq - start_stats[i].softirq;
			time_diffs[7] = end_stats[i].steal - start_stats[i].steal;
			time_diffs[8] = end_stats[i].guest - start_stats[i].guest;
			time_diffs[9] = end_stats[i].guest_nice - start_stats[i].guest_nice;

			__u32 key = i;
			bpf_map_lookup_elem(bpf_map__fd(obj->maps.latency_sum), &key, latency_vals);
			__u64 lat_sum = 0;
			for (int j = 0; j < nr_cpus; j++) {
				lat_sum += latency_vals[j];
			}
			time_diffs[10] = lat_sum / 1000000; // teeworld in ms

			for (int j = 0; j < 10; j++) {
				total_time += (double)time_diffs[j] * 1000 / clk_tck;
			}
			total_time += time_diffs[10];

			double kernel_ms = (double)time_diffs[2] * 1000 / clk_tck;
			if (kernel_ms > time_diffs[10])
				kernel_ms -= time_diffs[10];

			if (total_time < 1)
				total_time = 1;

			printf("%6s %6.2f%% %6.2f%% %6.2f%% %7.2f%% %7.2f%% %6.2f%% %7.2f%% %6.2f%% %6.2f%% %7.2f%%\n",
					i == 0 ? "all" : end_stats[i].name + 3,
					(double)time_diffs[0] * 1000 / clk_tck / total_time * 100,
					(double)time_diffs[1] * 1000 / clk_tck / total_time * 100,
					kernel_ms / total_time * 100,
					(double)time_diffs[10] / total_time * 100,
					(double)time_diffs[4] * 1000 / clk_tck / total_time * 100,
					(double)time_diffs[5] * 1000 / clk_tck / total_time * 100,
					(double)time_diffs[6] * 1000 / clk_tck / total_time * 100,
					(double)time_diffs[7] * 1000 / clk_tck / total_time * 100,
					((double)time_diffs[8] + time_diffs[9]) * 1000 / clk_tck / total_time * 100,
					(double)time_diffs[3] * 1000 / clk_tck / total_time * 100);
		}

		memcpy(start_stats, end_stats, (nr_cpus + 1) * sizeof(struct cpu_stat));

		print_log2_hist(obj->bss->hist, HIST_SLOTS, label);

		__u32 key = 0;
		bpf_map_lookup_elem(bpf_map__fd(obj->maps.latency_sum), &key, latency_vals);
		__u64 total_lat = 0;
		for (int j = 0; j < nr_cpus; j++) {
			total_lat += latency_vals[j];
		}
		if (milliseconds)
			total_lat /= 1000000;
		else if (microseconds)
			total_lat /= 1000;
		printf("The sum of latency:%llu %s\n", total_lat, label);

		// clear maps
		memset(obj->bss->hist, 0, sizeof(obj->bss->hist));
		__u64 *zero_counts = calloc(nr_cpus, sizeof(__u64));
		if (!zero_counts) {
			warn("failed to allocate zero counts\n");
			goto cleanup;
		}
		for (int i = 0; i < nr_cpus + 1; i++) {
			__u32 lat_key = i;
			bpf_map_update_elem(bpf_map__fd(obj->maps.latency_sum), &lat_key, zero_counts, BPF_ANY);
		}
		free(zero_counts);

		if (exiting || (loops > 0 && --loops == 0))
			break;
	}

	// After the loop, calculate and print total runtime
	time_t end_time_t;
	time(&end_time_t);
	double diff_seconds = difftime(end_time_t, start_time_t);

	int hours = (int)(diff_seconds / 3600);
	int minutes = (int)((diff_seconds - (hours * 3600)) / 60);
	int seconds = (int)(diff_seconds - (hours * 3600) - (minutes * 60));

	printf("Total Runtime : %02d:%02d:%02d\n", hours, minutes, seconds);

cleanup:
	free(start_stats);
	free(end_stats);
	free(latency_vals);
	smclatency_bpf__destroy(obj);

	return err != 0;
}
