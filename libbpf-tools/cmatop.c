// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cmatop.h"
#include "cmatop.skel.h"
#include "argparse.h"

struct cma_alloc_info {
	__u64 pages;
	struct cma_alloc_t data;
};

static struct env {
	bool timestamp;
	int interval;
	int count;
	bool range;
	bool verbose;
} env = {
	.interval = 99999999,
	.count = 99999999,
};

static volatile bool exiting;

static const char *const usages[] = {
	"cmatop [-h] [-T] [-r] [-v] [interval] [count]",
	NULL,
};

const char doc[] =
"Analyse CMA allocation as a table.\n"
"USAGE: cmatop [-T] [interval] [count] [--range]\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('r', "range", &env.range, "Show specific PFN range", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

static int compare_cma_alloc(const void *a, const void *b)
{
	const struct cma_alloc_info *x = a;
	const struct cma_alloc_info *y = b;

	if (x->data.max > y->data.max)
		return -1;
	if (x->data.max < y->data.max)
		return 1;
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
		va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct argparse argparse;
	struct cmatop_bpf *skel;
	int err;
	time_t start_time;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Analyse CMA allocation as a table.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (argc > 0)
		env.interval = atoi(argparse.out[0]);
	if (argc > 1)
		env.count = atoi(argparse.out[1]);
	if (argc > 2) {
		fprintf(stderr, "Unrecognized positional argument: %s\n", argparse.out[2]);
		argparse_usage(&argparse);
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);

	skel = cmatop_bpf__open();
	if (!skel)
		return 1;

	skel->rodata->track_range = env.range;

	err = cmatop_bpf__load(skel);
	if (err) {
		cmatop_bpf__destroy(skel);
		return 1;
	}

	err = cmatop_bpf__attach(skel);
	if (err) {
		cmatop_bpf__destroy(skel);
		return 1;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		return 1;

	start_time = time(NULL);

	while (!exiting) {
		sleep(env.interval);

		if (env.timestamp) {
			char ts[32];
			struct timeval tv;

			gettimeofday(&tv, NULL);
			strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&tv.tv_sec));
			printf("%-8s\n", ts);
		}

		printf("%6s %7s %17s %17s %17s %8s %5s %6s\n", "PAGES",
				"ALIGN", "Max_latency(ms)", "Min_latency(ms)",
				"Avg_latency(ms)", "Success", "Fail", "Total");

		int fd = bpf_map__fd(skel->maps.cma_alloc_hash);
		struct cma_alloc_info infos[MAX_ENTRIES] = {};
		__u64 keys[MAX_ENTRIES];
		__u64 lookup_key = (unsigned long)-1, next_key;
		int i = 0;

		while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
			keys[i++] = next_key;
			lookup_key = next_key;
		}

		for (int j = 0; j < i; j++) {
			bpf_map_lookup_and_delete_elem(fd, &keys[j],
					&infos[j].data);
			infos[j].pages = keys[j];
		}

		qsort(infos, i, sizeof(struct cma_alloc_info),
				compare_cma_alloc);

		for (int j = 0; j < i; j++) {
			struct cma_alloc_info *info = &infos[j];

			if (info->data.total_count == 0)
				continue;

			if (info->data.align == 0) {
				printf("%6llu %7s %16.2f %17.2f %16.2f %9u %6u %6llu\n",
						info->pages,
						"NULL",
						(double)info->data.max / 1000000,
						(double)info->data.min / 1000000,
						(double)info->data.total_latency /
						info->data.total_count / 1000000,
						info->data.success, info->data.fail,
						info->data.total_count);
			} else {
				printf("%6llu %7u %16.2f %17.2f %16.2f %9u %6u %6llu\n",
						info->pages, info->data.align,
						(double)info->data.max / 1000000,
						(double)info->data.min / 1000000,
						(double)info->data.total_latency /
						info->data.total_count / 1000000,
						info->data.success, info->data.fail,
						info->data.total_count);
			}
		}

		printf("\n");

		env.count--;
		if (env.count == 0 || exiting)
			break;
	}

	printf("Total Runtime : %-8ld\n", time(NULL) - start_time);

	cmatop_bpf__destroy(skel);
	return 0;
}
