// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Realtek, Inc. */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h> // For uint32_t and uint64_t

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mmclatency.h"
#include "mmclatency.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	int units;
	unsigned int interval;
	unsigned int count;
	bool timestamp;
	bool avglatency;
	bool per_command;
	bool per_blocks;
	int command;
	int min_blocks;
	int max_blocks;
	bool verbose;
} env = {
	.units = USEC,
	.interval = 99999999,
	.count = 99999999,
};

const char *argp_program_version = "mmclatency 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "[interval] [count]";
static const char program_doc[] =
"Summarize mmc device I/O latency as a histogram\n"
"\n"
"USAGE: mmclatency [-h] [-T] [-m] [-a] [-C] [-B] [-c COMMAND] [-z MIN_BLOCKS]\n"
"                   [-Z MAX_BLOCKS]\n"
"                   [interval] [count]\n"
"\v"
"Examples:\n"
"    ./mmclatency              # summarize mmc block I/O latency as a histogram\n"
"    ./mmclatency 1 10         # print 1 second summaries, 10 times\n"
"    ./mmclatency -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    ./mmclatency -a           # print average latency\n"
"    ./mmclatency -C           # show each mmc command separately\n"
"    ./mmclatency -B           # show each mmc blocks separately\n"
"    ./mmclatency -c 25        # specific mmc command 25 only\n"
"    ./mmclatency -z 64 -Z 512 # Trace mmc request 64~512 blocks only\n"
;

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "millisecond histogram", 0 },
	{ "avglatency", 'a', NULL, 0, "print average latency", 0 },
	{ "Commands", 'C', NULL, 0, "print a histogram per mmc command", 0 },
	{ "Blocks", 'B', NULL, 0, "print a histogram per blocks of MMC I/O", 0 },
	{ "command", 'c', "COMMAND", 0, "trace specific mmc command only", 0 },
	{ "min_blocks", 'z', "MIN_BLOCKS", 0, "trace larger than this mmc blocks", 0 },
	{ "max_blocks", 'Z', "MAX_BLOCKS", 0, "trace smaller than this mmc blocks", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long val;

	switch (key) {
	case 'T':
		env->timestamp = true;
		break;
	case 'm':
		env->units = MSEC;
		break;
	case 'a':
		env->avglatency = true;
		break;
	case 'C':
		env->per_command = true;
		break;
	case 'B':
		env->per_blocks = true;
		break;
	case 'c':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			warn("Invalid command: %s\n", arg);
			argp_usage(state);
		}
		env->command = val;
		break;
	case 'z':
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			warn("Invalid min_blocks: %s\n", arg);
			argp_usage(state);
		}
		env->min_blocks = val;
		break;
	case 'Z':
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			warn("Invalid max_blocks: %s\n", arg);
			argp_usage(state);
		}
		env->max_blocks = val;
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			val = strtol(arg, NULL, 10);
			if (errno || val <= 0) {
				warn("Invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env->interval = val;
		} else if (state->arg_num == 1) {
			val = strtol(arg, NULL, 10);
			if (errno || val <= 0) {
				warn("Invalid count: %s\n", arg);
				argp_usage(state);
			}
			env->count = val;
		} else {
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env->min_blocks && env->max_blocks && env->min_blocks > env->max_blocks) {
			warn("min_blocks (-z) can't be greater than max_blocks (-Z)\n");
			argp_usage(state);
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

static volatile bool exiting;

static void sig_hand(int signr)
{
	exiting = true;
}

// Standard MMC commands
const char *mmc_cmd_str(uint32_t cmd_id)
{
	switch (cmd_id) {
		case 0: return "GO_IDLE_STATE";
		case 1: return "SEND_OP_COND";
		case 2: return "ALL_SEND_CID";
		case 3: return "SET_RELATIVE_ADDR";
		case 4: return "SET_DSR";
		case 5: return "SLEEP_AWAKE";
		case 6: return "SWITCH";
		case 7: return "SELECT_CARD";
		case 8: return "SEND_EXT_CSD";
		case 9: return "SEND_CSD";
		case 10: return "SEND_CID";
		case 11: return "READ_DAT_UNTIL_STOP";
		case 12: return "STOP_TRANSMISSION";
		case 13: return "SEND_STATUS";
		case 14: return "BUS_TEST_R";
		case 15: return "GO_INACTIVE_STATE";
		case 19: return "BUS_TEST_W";
		case 58: return "SPI_READ_OCR";
		case 59: return "SPI_CRC_ON_OFF";
		case 16: return "SET_BLOCKLEN";
		case 17: return "READ_SINGLE_BLOCK";
		case 18: return "READ_MULTIPLE_BLOCK";
		case 21: return "SEND_TUNING_BLOCK_HS200";
		case 20: return "WRITE_DAT_UNTIL_STOP";
		case 23: return "SET_BLOCK_COUNT";
		case 24: return "WRITE_BLOCK";
		case 25: return "WRITE_MULTIPLE_BLOCK";
		case 26: return "PROGRAM_CID";
		case 27: return "PROGRAM_CSD";
		case 28: return "SET_WRITE_PROT";
		case 29: return "CLR_WRITE_PROT";
		case 30: return "SEND_WRITE_PROT";
		case 35: return "ERASE_GROUP_START";
		case 36: return "ERASE_GROUP_END";
		case 38: return "ERASE";
		case 39: return "FAST_IO";
		case 40: return "GO_IRQ_STATE";
		case 42: return "LOCK_UNLOCK";
		case 55: return "APP_CMD";
		case 56: return "GEN_CMD";
		case 44: return "QUE_TASK_PARAMS";
		case 45: return "QUE_TASK_ADDR";
		case 46: return "EXECUTE_READ_TASK";
		case 47: return "EXECUTE_WRITE_TASK";
		case 48: return "CMDQ_TASK_MGMT";
		case 52: return "IO_MODE";
		default: return "Unknown";
	}
}

static const char *unit_str(void)
{
	switch (env.units) {
		case NSEC:
			return "nsec";
		case USEC:
			return "usecs";
		case MSEC:
			return "msecs";
	};

	return "bad units";
}

static int print_global_hist(struct mmclatency_bpf *obj)
{
	uint64_t val_from_map;
	cmd_key_t lookup_key = {};
	unsigned int *hist = calloc(MAX_SLOTS, sizeof(unsigned int));
	if (!hist) {
		warn("Failed to allocate memory for histogram\n");
		return 1;
	}

	for (int i = 0; i < MAX_SLOTS; i++) {
		lookup_key.slot = i;
		lookup_key.value = 0; // For global histogram, value is not used
		if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.dist), &lookup_key, &val_from_map) == 0) {
			hist[i] = val_from_map;
		} else {
			hist[i] = 0; // Ensure it's zero if not found
		}
	}
	print_log2_hist(hist, MAX_SLOTS, unit_str());
	free(hist);
	return 0;
}

// Helper to convert cmd_key_t.value to string for per-command/blocks output
static const char *cmd_key_value_to_str(uint64_t value)
{
	static char buf[64];
	if (env.per_command && env.per_blocks) {
		uint32_t cmd_id = (uint32_t)(value >> 32);
		uint32_t blocks = (uint32_t)(value & 0xFFFFFFFF);
		snprintf(buf, sizeof(buf), "%s[%u], blocks = %u", mmc_cmd_str(cmd_id), cmd_id, blocks);
	} else if (env.per_command) {
		uint32_t cmd_id = (uint32_t)value;
		snprintf(buf, sizeof(buf), "%s[%u]", mmc_cmd_str(cmd_id), cmd_id);
	} else if (env.per_blocks) {
		uint32_t blocks = (uint32_t)value;
		snprintf(buf, sizeof(buf), "blocks = %u", blocks);
	}
	return buf;
}

static int print_per_key_hist(struct mmclatency_bpf *obj)
{
	cmd_key_t lookup_key = {};
	cmd_key_t next_key = {};
	uint64_t val_from_map;
	int err = 0;

	// Temporary storage for histograms, grouped by key.value
	// This is a simplified approach. A more robust solution would involve dynamic allocation
	// and sorting, but for a fixed MAX_SLOTS, we can use a map-like structure.
	// For now, let's collect all keys and then iterate.

	// Collect all unique key.value values first
	uint64_t *unique_values = NULL;
	size_t num_unique_values = 0;
	size_t unique_values_capacity = 0;

	cmd_key_t current_key = {};
	while (bpf_map_get_next_key(bpf_map__fd(obj->maps.dist), &current_key, &next_key) == 0) {
		bool found = false;
		for (size_t i = 0; i < num_unique_values; i++) {
			if (unique_values[i] == next_key.value) {
				found = true;
				break;
			}
		}
		if (!found) {
			if (num_unique_values == unique_values_capacity) {
				unique_values_capacity = unique_values_capacity == 0 ? 16 : unique_values_capacity * 2;
				uint64_t *new_unique_values = realloc(unique_values, unique_values_capacity * sizeof(uint64_t));
				if (!new_unique_values) {
					warn("Failed to reallocate memory for unique values\n");
					free(unique_values);
					return 1;
				}
				unique_values = new_unique_values;
			}
			unique_values[num_unique_values++] = next_key.value;
		}
		current_key = next_key;
	}

	// Sort unique_values for consistent output (optional but good practice)
	// qsort(unique_values, num_unique_values, sizeof(uint64_t), compare_uint64);

	for (size_t j = 0; j < num_unique_values; j++) {
		uint64_t current_value = unique_values[j];
		printf("\n%s = %s\n", env.per_command ? "cmd" : "blocks", cmd_key_value_to_str(current_value));

		unsigned int *hist = calloc(MAX_SLOTS, sizeof(unsigned int));
		if (!hist) {
			warn("Failed to allocate memory for histogram\n");
			free(unique_values);
			return 1;
		}

		for (int i = 0; i < MAX_SLOTS; i++) {
			lookup_key.slot = i;
			lookup_key.value = current_value;
			if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.dist), &lookup_key, &val_from_map) == 0) {
				hist[i] = val_from_map;
			} else {
				hist[i] = 0;
			}
		}
		print_log2_hist(hist, MAX_SLOTS, unit_str());
		free(hist);
	}

	free(unique_values);
	return err;
}

static int print_average_latency(struct mmclatency_bpf *obj)
{
	uint32_t cmd_key = 0;
	uint32_t next_cmd_key;
	uint64_t total_latency = 0;
	uint64_t total_count = 0;
	uint64_t latency_val, count_val;

	printf("  CMD  latency   count    Avglatency\n");

	while (bpf_map_get_next_key(bpf_map__fd(obj->maps.latency_map), &cmd_key, &next_cmd_key) == 0) {
		if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.latency_map), &next_cmd_key, &latency_val) == 0 &&
				bpf_map_lookup_elem(bpf_map__fd(obj->maps.count_map), &next_cmd_key, &count_val) == 0) {

			total_latency += latency_val;
			total_count += count_val;

			printf("  %3d%9llu /%6llu =%6llu %s\n",
					next_cmd_key,
					(unsigned long long)latency_val,
					(unsigned long long)count_val,
					(unsigned long long)(count_val ? latency_val / count_val : 0),
					unit_str());
		}
		cmd_key = next_cmd_key;
	}

	if (!env.command) { // Only print sum if not tracing a specific command
		printf("  Sum%9llu /%6llu =%6llu %s\n",
				(unsigned long long)total_latency,
				(unsigned long long)total_count,
				(unsigned long long)(total_count ? total_latency / total_count : 0),
				unit_str());
	}
	return 0;
}

static void clear_maps(struct mmclatency_bpf *obj)
{
	cmd_key_t lookup_key = {};
	cmd_key_t next_key = {};
	uint32_t cmd_key = 0;
	uint32_t next_cmd_key;
	uint32_t array_idx = 0;

	// Clear dist map
	while (bpf_map_get_next_key(bpf_map__fd(obj->maps.dist), &lookup_key, &next_key) == 0) {
		bpf_map_delete_elem(bpf_map__fd(obj->maps.dist), &next_key);
		lookup_key = next_key;
	}

	// Clear latency_map and count_map
	while (bpf_map_get_next_key(bpf_map__fd(obj->maps.latency_map), &cmd_key, &next_cmd_key) == 0) {
		bpf_map_delete_elem(bpf_map__fd(obj->maps.latency_map), &next_cmd_key);
		bpf_map_delete_elem(bpf_map__fd(obj->maps.count_map), &next_cmd_key);
		cmd_key = next_cmd_key;
	}

	// Clear latency_sum_map
	bpf_map_update_elem(bpf_map__fd(obj->maps.latency_sum_map), &array_idx, &(uint64_t){0}, BPF_ANY);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct mmclatency_bpf *obj;
	int err;
	char ts[32];
	struct tm *tm;
	time_t t;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &(struct sigaction){.sa_handler = sig_hand}, NULL);
	sigaction(SIGTERM, &(struct sigaction){.sa_handler = sig_hand}, NULL);

	libbpf_set_print(libbpf_print_fn);

	obj = mmclatency_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->units = env.units;
	obj->rodata->target_command = env.command;
	obj->rodata->min_blocks = env.min_blocks;
	obj->rodata->max_blocks = env.max_blocks;
	obj->rodata->avglatency = env.avglatency;
	obj->rodata->per_command = env.per_command;
	obj->rodata->per_blocks = env.per_blocks;

	err = mmclatency_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		goto cleanup;
	}

	err = mmclatency_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
			strerror(-err));
		goto cleanup;
	}

	time_t start_time_t;
	time(&start_time_t); // Record start time

	printf("Tracing mmc device I/O... Hit Ctrl-C to end.\n");

	while (env.count > 0 && !exiting) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if (env.per_command || env.per_blocks) {
			print_per_key_hist(obj);
		} else {
			print_global_hist(obj);
		}

		if (env.avglatency) {
			print_average_latency(obj);
		} else {
			uint64_t total_latency = 0;
			uint32_t array_idx = 0;
			bpf_map_lookup_elem(bpf_map__fd(obj->maps.latency_sum_map), &array_idx, &total_latency);
			printf("The sum of latency:%llu %s\n", (unsigned long long)total_latency, unit_str());
		}

		clear_maps(obj);

		env.count--;
	}

	// After the loop, calculate and print total runtime
	time_t end_time_t;
	time(&end_time_t);
	double diff_seconds = difftime(end_time_t, start_time_t);

	int hours = (int)(diff_seconds / 3600);
	int minutes = (int)((diff_seconds - (hours * 3600)) / 60);
	int seconds = (int)(diff_seconds - (hours * 3600) - (minutes * 60));

	printf("\nTotal Runtime : %02d:%02d:%02d\n", hours, minutes, seconds);

cleanup:
	mmclatency_bpf__destroy(obj);

	return err != 0;
}
