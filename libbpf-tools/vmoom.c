// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Realtek, Inc. */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vmoom.h"
#include "vmoom.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64

static struct env {
	bool status;
	bool maps;
	bool fulldisplay;
	int duration;
	bool verbose;
} env = {
	.status = false,
	.maps = false,
	.fulldisplay = false,
	.duration = 0,
	.verbose = false,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "vmoom 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_doc[] =
"Trace out-of-memory in virtual memory.\n"
"\n"
"USAGE: vmoom [-h] [-d DURATION] [-s] [-m] [-f] [-v]\n"
"\n"
"EXAMPLES:\n"
"    ./vmoom            # trace out-of-memory in virtual memory\n"
"    ./vmoom -d 10      # trace for 10 seconds only\n"
"    ./vmoom -s         # also display /proc/PID/status\n"
"    ./vmoom -m         # also display /proc/PID/maps\n"
"    ./vmoom -f         # also display low_limit, high_limit, align_mask, align_offset\n";

static const struct argp_option opts[] = {
	{ "status", 's', 0, 0, "also display /proc/PID/status", 0 },
	{ "maps", 'm', 0, 0, "also display /proc/PID/maps", 0 },
	{ "fulldisplay", 'f', 0, 0, "also display low_limit, high_limit, align_mask, align_offset", 0 },
	{ "duration", 'd', "SECONDS", 0, "total duration of trace in seconds", 0 },
	{ "verbose", 'v', 0, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 's':
		env.status = true;
		break;
	case 'm':
		env.maps = true;
		break;
	case 'f':
		env.fulldisplay = true;
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'v':
		env.verbose = true;
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

static void sig_handler(int sig)
{
	exiting = 1;
}

static void print_header(void)
{
	if (env.fulldisplay) {
		printf("%-11s %-14s %-6s %-6s %16s %7s %4s %16s %16s %12s %12s\n",
				"TIME(s)", "COMM", "TGID", "PID", "LEN", "ERROR", "FLAG",
				"LOW_LIMIT", "HIGH_LIMIT", "ALIGN_MASK", "ALIGN_OFFSET");
	} else {
		printf("%-11s %-14s %-6s %-6s %16s %7s %4s\n",
				"TIME(s)", "COMM", "TGID", "PID", "LEN", "ERROR", "FLAG");
	}
}

static void show_proc_info(int tgid)
{
	char path[PATH_MAX];

	if (env.status) {
		snprintf(path, sizeof(path), "cat /proc/%d/status", tgid);
		printf("==========%s==========\n", path);
		fflush(stdout);
		system(path);
		printf("\n");
	}

	if (env.maps) {
		snprintf(path, sizeof(path), "cat /proc/%d/maps", tgid);
		printf("==========%s==========\n", path);
		fflush(stdout);
		system(path);
		printf("\n");
	}

	if (env.status || env.maps)
		print_header();
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	static struct timeval start_ts;
	struct timeval cur_ts;
	double time_s;

	if (start_ts.tv_sec == 0)
		gettimeofday(&start_ts, NULL);

	gettimeofday(&cur_ts, NULL);
	time_s = (cur_ts.tv_sec - start_ts.tv_sec) +
		(cur_ts.tv_usec - start_ts.tv_usec) / 1000000.0;

	if (env.fulldisplay) {
		printf("%-11.6f %-14s %-6d %-6d %16llu %7s %4s %16llx %16llx %12llx %12llx\n",
				time_s, e->comm, e->tgid, e->pid, e->length, "ENOMEM",
				e->flags & 0x1 ? "T->D" : "D->T", /* VM_UNMAPPED_AREA_TOPDOWN */
				e->low_limit, e->high_limit, e->align_mask, e->align_offset);
	} else {
		printf("%-11.6f %-14s %-6d %-6d %16llu %7s %4s\n",
				time_s, e->comm, e->tgid, e->pid, e->length, "ENOMEM",
				e->flags & 0x1 ? "T->D" : "D->T"); /* VM_UNMAPPED_AREA_TOPDOWN */
	}

	show_proc_info(e->tgid);

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_doc,
	};
	struct ring_buffer *rb = NULL;
	struct vmoom_bpf *skel;
	int err;
	bool use_tp;
	time_t start_time;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = vmoom_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	use_tp = tracepoint_exists("mmap", "vm_unmapped_area");

	if (use_tp) {
		bpf_program__set_autoload(skel->progs.unmapped_area_entry_kprobe, false);
		bpf_program__set_autoload(skel->progs.unmapped_area_topdown_entry_kprobe, false);
		bpf_program__set_autoload(skel->progs.unmapped_area_return_kretprobe, false);
		bpf_program__set_autoload(skel->progs.unmapped_area_topdown_return_kretprobe, false);
	} else {
		bpf_program__set_autoload(skel->progs.handle_vm_unmapped_area, false);
	}

	err = vmoom_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = vmoom_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
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

	print_header();

	start_time = time(NULL);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if (env.duration && time(NULL) - start_time >= env.duration)
			break;
	}

cleanup:
	ring_buffer__free(rb);
	vmoom_bpf__destroy(skel);
	return -err;
}
