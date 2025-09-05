/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2021, Realtek Semiconductor Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   * Neither the name of the Realtek nor the names of its contributors may
 *     be used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// Based on netaggr from BCC by Edward Wu.
// 14-Aprial-2023   Mickey Zhu   Created this
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netaggr.h"
#include "netaggr.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	time_t interval;
	time_t duration;
	time_t iterations;
	bool extension;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};

static volatile bool exiting;
const char argp_args_doc[] =
"Analyze GRO/GSO aggregation and print as a histogram.\n"
"\n"
"USAGE: netaggr [-h] [-i INTERVAL] [-d DURATION] [-e] [-T] [-v]\n"
"\n"
"EXAMPLES:\n"
"    netaggr            # summarize aggregation\n"
"    netaggr -e         # show extension summary(average)\n"
"    netaggr -i 2       # print every 2 seconds\n"
"    netaggr -i 2 -T    # print every 2 seconds, with timestamps\n"
;

static const struct argp_option opts[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds", 0},
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0},
	{ "extension", 'e', NULL, 0, " Summarize average/total value", 0},
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0},
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long duration, interval;

	switch (key) {
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0) {
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env->interval = interval;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env->duration = duration;
		break;
	case 'e':
		env->extension = true;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_END:
		if (env->duration) {
			if (env->interval > env->duration)
				env->interval = env->duration;
			env->iterations = env->duration / env->interval;
		}
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

static int print_map(struct bpf_map *map, bool receive)
{
	int fd = bpf_map__fd(map);
	struct aggr_key lookup_key = {}, next_key;
	struct info info;
	float avg;
	int err;

	if (receive)
		printf("\n=== Generic Receive Offload (GRO) ===\n");
	else
		printf("\n=== Generic Segmentation Offload (GSO) ===\n");

	memset(lookup_key.name, '?', sizeof(lookup_key.name));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			return -1;
		}
		printf("\ndev->name = %s\n", next_key.name);
		print_linear_hist(info.slots, MAX_SLOTS, 0, 1, receive ?
				  "gro_segs": "gso_segs");
		lookup_key = next_key;
	}

	memset(lookup_key.name, '?', sizeof(lookup_key.name));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			return -1;
		}
		if (info.counts > 0) {
			avg = (float)info.total / info.counts;
			printf("\n%-8s: avg = %.3lf, total: %d, counts: %d\n",
				next_key.name, avg, info.total, info.counts);
		}
		lookup_key = next_key;
	}

	memset(lookup_key.name, '?', sizeof(lookup_key.name));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_args_doc,
	};
	struct netaggr_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int i, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = netaggr_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->extension = env.extension;

	err = netaggr_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		goto cleanup;
	}

	err = netaggr_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF object\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing GRO/GSO aggregation");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end\n");

	/* main: poll */
	for (i = 0; i < env.iterations && !exiting; i++) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_map(obj->maps.gro, true);
		if (err)
			break;

		err = print_map(obj->maps.gso, false);
		if (err)
			break;
	}

	printf("\nDetaching...\n");

cleanup:
	netaggr_bpf__destroy(obj);
	return err != 0;
}
