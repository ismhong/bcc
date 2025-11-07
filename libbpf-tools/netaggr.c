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
#include "argparse.h"

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

static const char *const usages[] = {
	"netaggr [-h] [-i INTERVAL] [-d DURATION] [-e] [-T] [-v]",
	NULL,
};

const char doc[] =
"Analyze GRO/GSO aggregation and print as a histogram.\n"
"\n"
"EXAMPLES:\n"
"    netaggr            # summarize aggregation\n"
"    netaggr -e         # show extension summary(average)\n"
"    netaggr -i 2       # print every 2 seconds\n"
"    netaggr -i 2 -T    # print every 2 seconds, with timestamps\n"
;

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_INTEGER('i', "interval", &env.interval, "Summary interval in seconds", NULL, 0, 0),
	OPT_INTEGER('d', "duration", &env.duration, "Duration to trace", NULL, 0, 0),
	OPT_BOOLEAN('e', "extension", &env.extension, " Summarize average/total value", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Print timestamp", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

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
	struct argparse argparse;
	struct netaggr_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int i, err;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Analyze GRO/GSO aggregation and print as a histogram.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (env.duration) {
		if (env.interval > env.duration)
			env.interval = env.duration;
		env.iterations = env.duration / env.interval;
	}
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
