// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause))
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cmatrack.h"
#include "cmatrack.skel.h"
#include "trace_helpers.h"

static struct env {
	bool range;
	int duration;
	bool verbose;
} env = {
	.duration = 0,
};

const char *argp_program_version = "cmatrack 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace CMA allocation.\n"
"\n"
"USAGE: ./cmatrack [-d DURATION] [--range]\n"
"\n"
"EXAMPLES:\n"
"./cmatrack           # Track all cma allocations\n"
"./cmatrack -d 10     # Track for 10 seconds only\n"
"./cmatrack --range   # Track all cma allocations display as PFN range\n";

static const struct argp_option opts[] = {
	{ "range", 'r', 0, 0, "Show specific PFN range", 0 },
	{ "duration", 'd', "SECONDS", 0, "Total duration of trace in seconds", 0 },
	{ "verbose", 'v', 0, 0, "Verbose debug output", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'r':
		env.range = true;
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
	case ARGP_KEY_ARG:
		argp_usage(state);
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct cmatrack_bpf *skel = ctx;

	if (e->range_mode) {
		printf("%-14.14s %-6d %-6d %5ld %10lx %10lx %12d %12d %8s\n",
				e->comm, e->tgid, e->pid, e->range.count,
				e->range.start_pfn, e->range.end_pfn, e->migrate_succeeded, e->migrate_failed,
				e->fail ? "FAIL" : "SUCCESS");
	} else {
		printf("%-14.14s %-6d %-6d %8.2f %5ld %5d %12d %12d %8s\n",
				e->comm, e->tgid, e->pid, (float)e->alloc.duration_ns / 1000000,
				e->alloc.count, e->alloc.align, e->migrate_succeeded, e->migrate_failed,
				e->fail ? "FAIL" : "SUCCESS");
	}

	struct pid_ino_file_key_t lookup_key = {}, next_key;
	struct pid_ino_file_name_t value;
	int map_fd = bpf_map__fd(skel->maps.pid_ino_file_map);
	bool has_files = false;

	lookup_key.pid = e->pid;
	lookup_key.ino = 0;

	while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
		if (next_key.pid != e->pid) {
			lookup_key = next_key;
			continue;
		}

		if (!has_files) {
			printf("        =======Who borrowed CMA memory=======\n");
			has_files = true;
		}
		if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
			printf("        INO:%u POLLING_TIMES:%u FILE:%s\n",
					next_key.ino, value.polling_times, value.name);
			bpf_map_delete_elem(map_fd, &next_key);
		}
		lookup_key = next_key;
	}
	if (has_files) {
		printf("        =====================================\n");
	}

	return 0;
}

static void print_headers(void)
{
	if (env.range) {
		printf("%-14s %-6s %-6s %5s %10s %10s %12s %12s %8s\n",
				"COMM", "TGID", "PID", "PAGES", "START_PFN", "END_PFN",
				"MIGRATE_SUCC", "MIGRATE_FAIL", "RESULT");
	} else {
		printf("%-14s %-6s %-6s %8s %5s %5s %12s %12s %8s\n",
				"COMM", "TGID", "PID", "LAT(ms)", "PAGES", "ALIGN",
				"MIGRATE_SUCC", "MIGRATE_FAIL", "RESULT");
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ring_buffer *rb = NULL;
	struct cmatrack_bpf *skel;
	int err;
	time_t start_time;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = cmatrack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->range_mode = env.range;

	if (!kprobe_exists("f2fs_release_page"))
		bpf_program__set_autoload(skel->progs.f2fs_release_page_entry, false);

	if (!tracepoint_exists("ext4", "ext4_releasepage"))
		bpf_program__set_autoload(skel->progs.ext4_releasepage, false);

	if (!tracepoint_exists("ext4", "ext4_release_folio"))
		bpf_program__set_autoload(skel->progs.ext4_release_folio, false);

	if (!tracepoint_exists("migrate", "mm_migrate_pages"))
		bpf_program__set_autoload(skel->progs.mm_migrate_pages, false);

	if (tracepoint_exists("android_fs", "android_fs_dataread_start")) {
		bpf_program__set_autoload(skel->progs.vfs_read_entry, false);
		bpf_program__set_autoload(skel->progs.vfs_write_entry, false);
	} else {
		bpf_program__set_autoload(skel->progs.android_fs_dataread_start, false);
		bpf_program__set_autoload(skel->progs.android_fs_datawrite_start, false);
	}

	err = cmatrack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = cmatrack_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
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

	print_headers();

	start_time = time(NULL);
	while (!exiting) {
		if (env.duration > 0 && (time(NULL) - start_time) >= env.duration)
			break;

		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	cmatrack_bpf__destroy(skel);
	return -err;
}
