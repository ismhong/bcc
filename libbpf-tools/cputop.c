// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "argparse.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cputop.h"
#include "cputop.skel.h"
#include "trace_helpers.h"

#define OUTPUT_ROWS_LIMIT 10240
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool timestamp;
	bool milliseconds;
	int max_rows;
	bool summarize_by_name;
	int filter_cpu;
	int filter_tgid;
	char *filter_policy_str;
	int filter_policy;
	bool per_cpu;
	bool extended_stats;
	long interval;
	long count;
	bool verbose;
} env = {
	.max_rows = 20,
	.filter_cpu = -1,
	.filter_tgid = -1,
	.filter_policy = -1,
	.interval = 99999999,
	.count = 99999999,
};

const char *argp_program_version = "cputop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize on-CPU time per task as a ranking table.\n"
"\n"
"USAGE: cputop [-h] [-T] [-m] [-r MAXROWS] [-n] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    cputop              # summarize on-CPU time as a ranking table.\n"
"    cputop 1 10         # print 1 second summaries, 10 times\n"
"    cputop 1 -c 1       # trace cpu1 only\n"
"    cputop -p fifo    # trace sched_fifo task only\n"
"    cputop -m -r 10     # milliseconds, and 10 max rows\n";

static int parse_policy(const char *str) {
	if (!strcmp(str, "normal")) return 0;
	if (!strcmp(str, "fifo")) return 1;
	if (!strcmp(str, "rr")) return 2;
	if (!strcmp(str, "batch")) return 3;
	if (!strcmp(str, "idle")) return 5;
	if (!strcmp(str, "deadline")) return 6;
	return -1;
}

static int parse_policy_callback(struct argparse *self, const struct argparse_option *option)
{
	env.filter_policy_str = (char *)self->optvalue;
	env.filter_policy = parse_policy(self->optvalue);
	if (env.filter_policy < 0) {
		fprintf(stderr, "invalid policy: %s\n", self->optvalue);
		argparse_usage(self);
		exit(EXIT_FAILURE);
	}
	return 0;
}

static const char * const usages[] = {
	"cputop [options] [interval] [count]",
	NULL,
};

static struct argparse_option options[] = {
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('m', "milliseconds", &env.milliseconds, "Millisecond histogram", NULL, 0, 0),
	OPT_INTEGER('r', "maxrows", &env.max_rows, "Maximum rows to print, default 20", NULL, 0, 0),
	OPT_BOOLEAN('n', "name", &env.summarize_by_name, "Use name as key to summarize", NULL, 0, 0),
	OPT_INTEGER('c', "cpu", &env.filter_cpu, "Trace with this cpu only", NULL, 0, 0),
	OPT_INTEGER('t', "tgid", &env.filter_tgid, "Trace with this tgid only", NULL, 0, 0),
	OPT_STRING('p', "sched_policy", NULL, "Trace with this sched policy only, default all", parse_policy_callback, 0, 0),
	OPT_BOOLEAN('C', "percpu", &env.per_cpu, "Show each cpu id separately", NULL, 0, 0),
	OPT_BOOLEAN('E', "extend", &env.extended_stats, "Extend to show context (in)voluntary switches and preempt counts", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_HELP(),
	OPT_END(),
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

struct pid_data {
	struct pid_key_t key;
	struct pid_info_t value;
};

struct name_data {
	struct name_key_t key;
	struct info_t value;
};

static int sort_pid_data(const void *a, const void *b)
{
	struct pid_data *pa = (struct pid_data *)a;
	struct pid_data *pb = (struct pid_data *)b;
	return pb->value.info.duration - pa->value.info.duration;
}

static int sort_name_data(const void *a, const void *b)
{
	struct name_data *na = (struct name_data *)a;
	struct name_data *nb = (struct name_data *)b;
	return nb->value.duration - na->value.duration;
}

static const char *policy_str(int policy) {
	switch (policy) {
		case 0: return "SCHED_NORMAL";
		case 1: return "SCHED_FIFO";
		case 2: return "SCHED_RR";
		case 3: return "SCHED_BATCH";
		case 5: return "SCHED_IDLE";
		case 6: return "SCHED_DEADLINE";
	}
	return "Unknown";
}

static int print_stats(struct cputop_bpf *obj, int num_cpus)
{
	time_t t;
	struct tm *tm;
	char ts[32];
	__u64 total_duration = 0;
	double total_percent;

	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s\n", ts);
	}

	const char *unit = env.milliseconds ? "msecs" : "usecs";
	long denominator = env.milliseconds ? 1000000 : 1000;
	char duration_header[32];

	snprintf(duration_header, sizeof(duration_header), "DURATION(%s)", unit);

	if (env.per_cpu)
		printf("%-3s  ", "CPU");

	if (env.summarize_by_name) {
		printf("%-16s %-15s %-4s %15s %11s", "COMM", "POLICY", "PRIO",
				duration_header, "PRECENTAGE");
	} else {
		printf("%-6s %-6s %-16s %-15s %-4s %15s %11s", "TGID", "PID", "COMM",
				"POLICY", "PRIO", duration_header, "PRECENTAGE");
	}
	if (env.extended_stats) {
		printf("%10s %10s %12s", "VCSW_CNT", "IVCSW_CNT", "PREEMPT_CNT");
	}
	printf("\n");

	double profile_time = (double)env.interval * 1e9 * num_cpus;

	if (env.summarize_by_name) {
		struct name_data data[OUTPUT_ROWS_LIMIT];
		int map_fd = bpf_map__fd(obj->maps.name_counts);
		struct name_key_t *p_key = NULL, key;
		struct info_t value;
		int err = 0, rows = 0;

		while (!bpf_map_get_next_key(map_fd, p_key, &key)) {
			err = bpf_map_lookup_and_delete_elem(map_fd, &key, &value);
			if (err) {
				warn("bpf_map_lookup_and_delete_elem failed: %s\n", strerror(errno));
				return err;
			}
			data[rows].key = key;
			data[rows].value = value;
			total_duration += value.duration;
			p_key = &key;
			rows++;
		}

		qsort(data, rows, sizeof(struct name_data), sort_name_data);

		for (int i = 0; i < rows && i < env.max_rows; i++) {
			if (env.per_cpu)
				printf("%3d  ", data[i].key.cpuid);
			printf("%-16s %-15s %4d %15lld %10.3f%%",
					data[i].key.comm, policy_str(data[i].key.policy), data[i].key.prio,
					data[i].value.duration / denominator,
					(data[i].value.duration * 100) / profile_time);
			if (env.extended_stats) {
				printf("%10lld %10lld %12lld", data[i].value.nvcsw, data[i].value.nivcsw, data[i].value.preempts);
			}
			printf("\n");
		}
	} else { // by pid
		struct pid_data data[OUTPUT_ROWS_LIMIT];
		int map_fd = bpf_map__fd(obj->maps.pid_counts);
		struct pid_key_t *p_key = NULL, key;
		struct pid_info_t value;
		int err = 0, rows = 0;

		while (!bpf_map_get_next_key(map_fd, p_key, &key)) {
			err = bpf_map_lookup_and_delete_elem(map_fd, &key, &value);
			if (err) {
				warn("bpf_map_lookup_and_delete_elem failed: %s\n", strerror(errno));
				return err;
			}
			data[rows].key = key;
			data[rows].value = value;
			total_duration += value.info.duration;
			p_key = &key;
			rows++;
		}

		qsort(data, rows, sizeof(struct pid_data), sort_pid_data);

		for (int i = 0; i < rows && i < env.max_rows; i++) {
			if (env.per_cpu)
				printf("%3d  ", data[i].key.cpuid);
			printf("%-6lld %-6d %-16s %-15s %4d %15lld %10.3f%%",
					data[i].value.tgid, data[i].key.pid, data[i].value.comm,
					policy_str(data[i].key.policy), data[i].key.prio,
					data[i].value.info.duration / denominator,
					(data[i].value.info.duration * 100) / profile_time);
			if (env.extended_stats) {
				printf("%10lld %10lld %12lld", data[i].value.info.nvcsw, data[i].value.info.nivcsw, data[i].value.info.preempts);
			}
			printf("\n");
		}
	}

	printf("\nTotal(%s) Total percentage\n", unit);
	total_percent = (total_duration * 100) / profile_time;
	printf("%16lld %15.3f%%\n\n", total_duration / denominator, total_percent);

	return 0;
}

int main(int argc, char **argv)
{
	struct cputop_bpf *obj;
	int err;
	int num_cpus;
	struct argparse argparse;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, argp_program_doc, NULL);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (env.max_rows <= 0) {
		warn("invalid max_rows: %d\n", env.max_rows);
		argparse_usage(&argparse);
		return 1;
	}
	if (env.filter_cpu < -1) {
		warn("invalid cpu: %d\n", env.filter_cpu);
		argparse_usage(&argparse);
		return 1;
	}
	if (env.filter_tgid <= 0 && env.filter_tgid != -1) {
		warn("invalid tgid: %d\n", env.filter_tgid);
		argparse_usage(&argparse);
		return 1;
	}

	if (argc > 0) {
		env.interval = strtol(argv[0], NULL, 10);
		if (env.interval <= 0) {
			warn("invalid interval\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 1) {
		env.count = strtol(argv[1], NULL, 10);
		if (env.count <= 0) {
			warn("invalid count\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 2) {
		warn("unrecognized positional argument\n");
		argparse_usage(&argparse);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus < 0) {
		warn("failed to get # of possible cpus: '%s'\n", strerror(-num_cpus));
		return 1;
	}
	if (env.filter_cpu >= num_cpus) {
		warn("invalid cpu id, choose from 0 ~ %d\n", num_cpus - 1);
		return 1;
	}

	obj = cputop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->summarize_by_name = env.summarize_by_name;
	obj->rodata->per_cpu = env.per_cpu;
	obj->rodata->filter_cpu = env.filter_cpu;
	obj->rodata->filter_tgid = env.filter_tgid;
	obj->rodata->filter_policy = env.filter_policy;

	if (!kprobe_exists("__schedule")) {
		bpf_program__set_autoload(obj->progs.schedule_entry, false);
		bpf_program__set_autoload(obj->progs.schedule_exit, false);
	}

	err = cputop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = cputop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing on-CPU time... Hit Ctrl-C to end.\n");

	time_t start_time;
	time(&start_time);

	while (1) {
		sleep(env.interval);

		printf("\n");

		if (exiting && env.interval == 99999999) {
			time_t end_time;
			time(&end_time);
			env.interval = end_time - start_time;
			if (env.interval <= 0)
				env.interval = 1;
		}

		err = print_stats(obj, (env.filter_cpu == -1)? num_cpus : 1);
		if (err)
			break;

		env.count--;
		if (exiting || !env.count)
			break;
	}

cleanup:
	cputop_bpf__destroy(obj);

	return err != 0;
}
