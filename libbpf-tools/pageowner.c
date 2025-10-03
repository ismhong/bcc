/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "pageowner.h"
#include "pageowner.skel.h"
#include "trace_helpers.h"

static struct env {
	unsigned long start_pfn;
	unsigned long end_pfn;
	int stack_storage_size;
	bool timestamp;
	int interval;
	bool verbose;
} env = {
	.stack_storage_size = 16384,
	.interval = 1,
};

static volatile bool exiting;

const char *argp_program_version = "pageowner 0.1";
const char *argp_program_bug_address = "<https://github.com/iovisor/bcc/tree/master/libbpf-tools>";
static const struct argp_option opts[] = {
	{ "start-pfn", 's', "PFN", 0, "Track start page frame number", 0 },
	{ "end-pfn", 'e', "PFN", 0, "Track end page frame number", 0 },
	{ "stack-storage-size", 1, "SIZE", 0, "The number of unique stack traces", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, 0, "Show this help message and exit", 0 },
	{},
};

// GFP flags mapping from pageowner.py
static const struct {
	const char *name;
	unsigned int flag;
} gfp_flags[] = {
	{ "GFP_DMA", 0x01 },
	{ "GFP_HIGHMEM", 0x02 },
	{ "GFP_DMA32", 0x04 },
	{ "GFP_MOVABLE", 0x08 },
	{ "GFP_RECLAIMABLE", 0x10 },
	{ "GFP_HIGH", 0x20 },
	{ "GFP_IO", 0x40 },
	{ "GFP_FS", 0x80 },
	{ "GFP_COLD", 0x100 },
	{ "GFP_NOWARN", 0x200 },
	{ "GFP_RETRY_MAYFAIL", 0x400 },
	{ "GFP_NOFAIL", 0x800 },
	{ "GFP_NORETRY", 0x1000 },
	{ "GFP_MEMALLOC", 0x2000 },
	{ "GFP_COMP", 0x4000 },
	{ "GFP_ZERO", 0x8000 },
	{ "GFP_NOMEMALLOC", 0x10000 },
	{ "GFP_HARDWALL", 0x20000 },
	{ "GFP_THISNODE", 0x40000 },
	{ "GFP_ATOMIC", 0x80000 },
	{ "GFP_ACCOUNT", 0x100000 },
	{ "GFP_DIRECT_RECLAIM", 0x400000 },
	{ "GFP_WRITE", 0x800000 },
	{ "GFP_KSWAPD_RECLAIM", 0x1000000 },
};

static void gfp_flag_to_name(unsigned int gfp_flag, char *buf, size_t size) {
	if (gfp_flag == 0) {
		snprintf(buf, size, "Unknown");
		return;
	}

	char *p = buf;
	char *end = buf + size;
	bool first = true;

	for (int i = 0; i < sizeof(gfp_flags) / sizeof(gfp_flags[0]); i++) {
		if (gfp_flag & gfp_flags[i].flag) {
			if (!first) {
				p += snprintf(p, end - p, "|");
			}
			if (p < end)
				p += snprintf(p, end - p, "%s", gfp_flags[i].name);
			first = false;
		}
	}
	if (first) {
		snprintf(buf, size, "Unknown");
	}
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 's':
		env.start_pfn = strtoul(arg, NULL, 0);
		break;
	case 'e':
		env.end_pfn = strtoul(arg, NULL, 0);
		break;
	case 1: // stack-storage-size
		env.stack_storage_size = strtol(arg, NULL, 10);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		if (env.interval <= 0) {
			fprintf(stderr, "Invalid interval\n");
			argp_usage(state);
		}
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

struct pfn_data {
	__u64 pfn;
	struct data_t data;
};

int compare_pfn(const void *a, const void *b) {
	const struct pfn_data *pa = a;
	const struct pfn_data *pb = b;
	if (pa->pfn < pb->pfn) return -1;
	if (pa->pfn > pb->pfn) return 1;
	return 0;
}

static int print_event(struct pageowner_bpf *obj, struct ksyms *ksyms)
{
	char gfp_flags_str[512];
	int map_fd = bpf_map__fd(obj->maps.page_track_table);
	int stack_map_fd = bpf_map__fd(obj->maps.stack_traces);
	struct bpf_map_info map_info = {};
	__u32 map_info_len = sizeof(map_info);
	int err;
	struct pfn_data *pfn_data_arr;
	int count = 0;
	int max_entries;

	err = bpf_obj_get_info_by_fd(map_fd, (void*)&map_info, &map_info_len);
	if (err) {
		fprintf(stderr, "bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
		max_entries = 10240; // fallback
	} else {
		max_entries = map_info.max_entries;
	}

	pfn_data_arr = calloc(max_entries, sizeof(*pfn_data_arr));
	if (!pfn_data_arr) {
		fprintf(stderr, "failed to allocate memory for sorting\n");
		return -1;
	}

	__u64 key, next_key;
	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		for (;;) {
			if (count >= max_entries) break;
			pfn_data_arr[count].pfn = key;
			if (bpf_map_lookup_elem(map_fd, &key, &pfn_data_arr[count].data) != 0) {
				fprintf(stderr, "Failed to lookup pfn %llu\n", (unsigned long long)key);
			} else {
				count++;
			}

			if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
				break;
			}
			key = next_key;
		}
	}

	qsort(pfn_data_arr, count, sizeof(*pfn_data_arr), compare_pfn);

	if (env.timestamp) {
		char ts[32];
		time_t t = time(NULL);
		strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", localtime(&t));
		printf("%-8s\n", ts);
	}

	printf("================TRACK PAGE OWNER===================\n");

	for (int i = 0; i < count; i++) {
		__u64 pfn = pfn_data_arr[i].pfn;
		struct data_t *data = &pfn_data_arr[i].data;

		printf("==========================\n");
		printf("PFN:%llu ALLOC_SIZE:%llu MIGRATE_TYPE:%d\n",
				(unsigned long long)pfn, (unsigned long long)data->size, data->migratetype);
		gfp_flag_to_name(data->gfp_flags, gfp_flags_str, sizeof(gfp_flags_str));
		printf("GFP_FLAGS:%s\n", gfp_flags_str);
		printf("PID:%u TGID:%u COMM:%s\n", data->pid, data->tgid, data->comm);
		printf("==========================\n");

		if (data->stack_id >= 0) {
			__u64 ip[PERF_MAX_STACK_DEPTH] = {};
			if (bpf_map_lookup_elem(stack_map_fd, &data->stack_id, ip) != 0) {
				fprintf(stderr, "Failed to lookup stack id %lld\n", data->stack_id);
			} else {
				for (int j = 0; j < PERF_MAX_STACK_DEPTH && ip[j]; j++) {
					const struct ksym *ksym = ksyms__map_addr(ksyms, ip[j]);
					if (ksym)
						printf("%s+0x%llx\n", ksym->name, ip[j] - ksym->addr);
					else
						printf("0x%llx\n", (unsigned long long)ip[j]);
				}
			}
		} else {
			printf("NO STACK FOUND DUE TO COLLISION\n");
		}
		printf("  \n");
	}
	printf("=====================================================\n\n");

	free(pfn_data_arr);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = "Track who allocated pages.\n\nUSAGE: ./pageowner -s <start_pfn> -e <end_pfn> [-T] [-i interval]\n",
	};
	struct pageowner_bpf *obj;
	int err;
	struct ksyms *ksyms = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.start_pfn == 0 || env.end_pfn == 0) {
		fprintf(stderr, "start-pfn and end-pfn must be specified.\n");
		return 1;
	}

	if (env.start_pfn > env.end_pfn) {
		fprintf(stderr, "start-pfn cannot be greater than end-pfn.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = pageowner_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->start_pfn = env.start_pfn;
	obj->rodata->end_pfn = env.end_pfn;
	obj->rodata->page_size = getpagesize();

	bpf_map__set_max_entries(obj->maps.stack_traces, env.stack_storage_size);

	err = pageowner_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		err = -1;
		goto cleanup;
	}

	err = pageowner_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracking who allocated page frame number %lu ~ %lu\n",
			env.start_pfn, env.end_pfn);

	while (!exiting) {
		sleep(env.interval);
		print_event(obj, ksyms);
	}

cleanup:
	ksyms__free(ksyms);
	pageowner_bpf__destroy(obj);
	return err < 0 ? -err : 0;
}
