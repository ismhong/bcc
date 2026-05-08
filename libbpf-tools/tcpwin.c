// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Realtek, Inc.
#include <arpa/inet.h>
#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpwin.h"
#include "tcpwin.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t duration;
	time_t interval;
	bool timestamp;
	bool snd_wnd;
	bool snd_cwnd;
	bool rcv_wnd;
	bool snd_ssthresh;
	bool verbose;
} env = {
	.interval = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "tcpwin 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize TCP window size for performance tuning.\n"
"\n"
"USAGE: \n"
"\n"
"EXAMPLES:\n"
"    tcpwin -i 1 -d 10     # print 1 second summaries, 10 times\n"
"    tcpwin -i 2 -T       # print 2 second summaries with timestamps\n"
"    tcpwin -s            # only show the window we expect to receive\n"
"    tcpwin -c            # only show the sending congestion window\n"
"    tcpwin -r            # only show the current receiver window\n"
"    tcpwin -S            # only show the slow start size threshold\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds", 0 },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "snd_wnd", 's', NULL, 0, "the window we expect to receive", 0 },
	{ "snd_cwnd", 'c', NULL, 0, "the sending congestion window", 0 },
	{ "rcv_wnd", 'r', NULL, 0, "the current receiver window", 0 },
	{ "snd_ssthresh", 'S', NULL, 0, "the slow start size threshold", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
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
			fprintf(stderr, "invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 's':
		env.snd_wnd = true;
		env.snd_cwnd = env.rcv_wnd = env.snd_ssthresh = false;
		break;
	case 'c':
		env.snd_cwnd = true;
		env.snd_wnd = env.rcv_wnd = env.snd_ssthresh = false;
		break;
	case 'r':
		env.rcv_wnd = true;
		env.snd_wnd = env.snd_cwnd = env.snd_ssthresh = false;
		break;
	case 'S':
		env.snd_ssthresh = true;
		env.snd_wnd = env.snd_cwnd = env.rcv_wnd = false;
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
	exiting = true;
}

static int print_hist(struct bpf_map *map, const char *title, const char *units)
{
	int err, fd = bpf_map__fd(map);
	struct hist hist = {0};
	struct hist zero_hist = {0};
	int key = 0;

	if (fd < 0)
		return -1;

	err = bpf_map_lookup_elem(fd, &key, &hist);
	if (err < 0) {
		return -1;
	}

	printf("%s\n", title);
	print_log2_hist(hist.slots, MAX_SLOTS, units);

	/* Clear the histogram for the next interval */
	bpf_map_update_elem(fd, &key, &zero_hist, BPF_ANY);

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpwin_bpf *obj;
	__u64 time_end = 0;
	char ts[32];
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* If no specific option is set, show all */
	if (!env.snd_wnd && !env.snd_cwnd && !env.rcv_wnd && !env.snd_ssthresh) {
		env.snd_wnd = env.snd_cwnd = env.rcv_wnd = env.snd_ssthresh = true;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = tcpwin_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_snd_wnd = env.snd_wnd;
	obj->rodata->targ_snd_cwnd = env.snd_cwnd;
	obj->rodata->targ_rcv_wnd = env.rcv_wnd;
	obj->rodata->targ_snd_ssthresh = env.snd_ssthresh;

	if (fentry_can_attach("tcp_rcv_established", NULL))
		bpf_program__set_autoload(obj->progs.tcp_rcv_kprobe, false);
	else
		bpf_program__set_autoload(obj->progs.tcp_rcv, false);

	err = tcpwin_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* Initialize array maps with zero histogram */
	struct hist zero_hist = {0};
	int key = 0;
	if (env.snd_wnd)
		bpf_map_update_elem(bpf_map__fd(obj->maps.snd_wnd_hist), &key, &zero_hist, BPF_ANY);
	if (env.snd_cwnd)
		bpf_map_update_elem(bpf_map__fd(obj->maps.snd_cwnd_hist), &key, &zero_hist, BPF_ANY);
	if (env.rcv_wnd)
		bpf_map_update_elem(bpf_map__fd(obj->maps.rcv_wnd_hist), &key, &zero_hist, BPF_ANY);
	if (env.snd_ssthresh)
		bpf_map_update_elem(bpf_map__fd(obj->maps.ssthresh_hist), &key, &zero_hist, BPF_ANY);

	err = tcpwin_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing TCP window size for performance tuning... Hit Ctrl-C to end.\n");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	/* main: poll */
	while (1) {
		sleep(env.interval);

		if (env.timestamp) {
			str_timestamp("%H:%M:%S", ts, sizeof(ts));
			printf("\n%-8s\n", ts);
		}

		if (env.snd_wnd) {
			err = print_hist(obj->maps.snd_wnd_hist,
					 "The window we expect to receive", "Byte");
			if (err)
				break;
		}
		if (env.snd_cwnd) {
			err = print_hist(obj->maps.snd_cwnd_hist,
					 "Sending congestion window", "Segments");
			if (err)
				break;
		}
		if (env.rcv_wnd) {
			err = print_hist(obj->maps.rcv_wnd_hist,
					 "Current receiver window", "Byte");
			if (err)
				break;
		}
		if (env.snd_ssthresh) {
			err = print_hist(obj->maps.ssthresh_hist,
					 "Slow start size threshold", "Segments");
			if (err)
				break;
		}

		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;

		if (exiting)
			break;
	}

cleanup:
	tcpwin_bpf__destroy(obj);
	return err != 0;
}