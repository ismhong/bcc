/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "whoentersmc.h"
#include "whoentersmc.skel.h"
#include "trace_helpers.h"

static struct env {
	bool timestamp;
	bool verbose;
	int interval;
} env = {
	.interval = 1,
};

static volatile bool exiting;

const char *argp_program_version = "whoentersmc 0.1";
const char *argp_program_bug_address = "<https://github.com/iovisor/bcc/tree/master/libbpf-tools>";
static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, 0, "Show this help message and exit", 0 },
	{},
};

const char argp_doc[] = "Analysis which CPU entered secure world.\n\nUSAGE: whoentersmc [-T]\n";
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;

	switch (key) {
	case 'T':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0) {
			fprintf(stderr, "Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env.interval = interval;
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

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_doc,
	};
	struct whoentersmc_bpf *obj;
	bool optee_tp = false;
	bool optee_kprobe = false;
	int err, i, cpu_count;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = whoentersmc_bpf__open();
	if (!obj)
		return 1;

	if (tracepoint_exists("optee", "optee_open_session_exit") &&
		tracepoint_exists("optee", "optee_invoke_func_entry") &&
		tracepoint_exists("optee", "optee_invoke_func_exit")) {
		optee_tp = true;
	}
	obj->rodata->optee_tp = optee_tp;

	if (optee_tp) {
		bpf_program__set_autoload(obj->progs.optee_open_session_entry, false);
		bpf_program__set_autoload(obj->progs.tee_shm_free_entry, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_entry, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_exit, false);
	}

	if (kprobe_exists("optee_open_session") &&
		kprobe_exists("tee_shm_free") &&
		kprobe_exists("optee_invoke_func")) {
		optee_kprobe = true;
	}
	obj->rodata->optee_kprobe = optee_kprobe;

	if (optee_kprobe) {
		bpf_program__set_autoload(obj->progs.optee_open_session_exit_tp, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_entry_tp, false);
		bpf_program__set_autoload(obj->progs.optee_invoke_func_exit_tp, false);
	}

	if (!kprobe_exists("handle_IPI"))
		bpf_program__set_autoload(obj->progs.ipi_back_ree_world, false);

	err = whoentersmc_bpf__load(obj);
	if (err) {
		whoentersmc_bpf__destroy(obj);
		return 1;
	}

	err = whoentersmc_bpf__attach(obj);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	cpu_count = libbpf_num_possible_cpus();

	printf("Finding who entered critical section last\n");

	while (!exiting) {
		sleep(env.interval);

		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);

			strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", localtime(&t));
			printf("%s\n", ts);
		}

		for (i = 0; i < cpu_count; i++) {
			struct candidate_table cand;
			struct optee_val_t optee_val;

			if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.candidate_map_table), &i, &cand) != 0) {
				printf("CPU:%d CURR_WORLD:Non-Secure\n", i);
				continue;
			}

			if (cand.tee_world)
				printf("CPU:%d CURR_WORLD:Secure TGID:%d PID:%d COMM:%s TS:%llu\n",
						i, cand.tgid, cand.pid, cand.comm, cand.ts);
			else
				printf("CPU:%d CURR_WORLD:Non-Secure\n", i);

			if (cand.tee_world && (optee_tp || optee_kprobe)) {
				if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.optee_candidate), &i, &optee_val) == 0) {
					printf("   =OPTEE= Low:0x%x Mid:0x%x HiAndVersion:0x%x session:%u func:%u\n",
							optee_val.timeLow, optee_val.timeMid, optee_val.timeHiAndVersion,
							optee_val.session, optee_val.func);
				}
			}
		}
		printf("\n");
	}

cleanup:
	whoentersmc_bpf__destroy(obj);
	return err < 0 ? -err : 0;
}
