// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mmctop.h"
#include "mmctop.skel.h"
#include "argparse.h"

#define MAX_ROWS 20
#define MAX_ENTRIES 4096

static struct env {
    _Bool noclear;
    int maxrows;
    _Bool timestamp;
    _Bool milliseconds;
    _Bool kilobytes;
    _Bool megabytes;
    _Bool per_blocks;
    _Bool per_pid;
    _Bool per_cmd_arg;
    int command;
    int min_blocks;
    int max_blocks;
    int interval;
    int count;
    _Bool verbose;
} env = {
    .maxrows = MAX_ROWS,
    .command = -1,
    .min_blocks = 0,
    .max_blocks = -1,
    .interval = 99999999,
    .count = 99999999,
};

static volatile _Bool exiting;

static const char *const usages[] = {
	"mmctop [-h] [-C] [-r MAXROWS] [-T] [-m] [-K] [-M] [-B] [-P] [-A] [-c COMMAND] [-z MIN_BLOCKS] [-Z MAX_BLOCKS] [interval] [count]",
	NULL,
};

const char doc[] =
"Summarize mmc device I/O behavior as a table.\n"
"\n"
"EXAMPLES:\n"
"    ./mmctop                # summarize mmc device I/O behavior as a table\n"
"    ./mmctop -C             # don't clear the screen\n"
"    ./mmctop 1 10           # print 1 second summaries, 10 times\n"
"    ./mmctop -mT 1          # 1s summaries, milliseconds, and timestamps\n"
"    ./mmctop -P             # show pid, tid and process name\n"
"    ./mmctop -B             # show each mmc blocks separately\n"
"    ./mmctop -A             # show CMD Argument\n"
"    ./mmctop -c 47          # trace mmc cmd_id = 47 only\n"
"    ./mmctop -z 64 -Z 512   # trace mmc request blocks=64~512 only\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('C', "noclear", &env.noclear, "Don't clear the screen", NULL, 0, 0),
	OPT_INTEGER('r', "maxrows", &env.maxrows, "Maximum rows to print, default 20", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('m', "milliseconds", &env.milliseconds, "Latency: set millisecond unit", NULL, 0, 0),
	OPT_BOOLEAN('K', "kilobytes", &env.kilobytes, "Total_size: set kilobytes unit", NULL, 0, 0),
	OPT_BOOLEAN('M', "megabytes", &env.megabytes, "Total_size: set megabytes unit", NULL, 0, 0),
	OPT_BOOLEAN('B', "Blocks", &env.per_blocks, "Display separately for each blocks of MMC I/O", NULL, 0, 0),
	OPT_BOOLEAN('P', "perpid", &env.per_pid, "Display separately for each process", NULL, 0, 0),
	OPT_BOOLEAN('A', "cmd_arg", &env.per_cmd_arg, "Display CMD Argument", NULL, 0, 0),
	OPT_INTEGER('c', "command", &env.command, "Trace specific mmc command only", NULL, 0, 0),
	OPT_INTEGER('z', "min_blocks", &env.min_blocks, "Trace larger than this mmc blocks", NULL, 0, 0),
	OPT_INTEGER('Z', "max_blocks", &env.max_blocks, "Trace smaller than this mmc blocks", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Enable libbpf verbose messages", NULL, 0, 0),
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

struct mmc_cmd_str {
	int id;
	const char *name;
};

static struct mmc_cmd_str mmc_cmds[] = {
	{0, "GO_IDLE_STATE"}, {1, "SEND_OP_COND"}, {2, "ALL_SEND_CID"},
	{3, "SET_RELATIVE_ADDR"}, {4, "SET_DSR"}, {5, "SLEEP_AWAKE"},
	{6, "SWITCH"}, {7, "SELECT_CARD"}, {8, "SEND_EXT_CSD"},
	{9, "SEND_CSD"}, {10, "SEND_CID"}, {11, "READ_DAT_UNTIL_STOP"},
	{12, "STOP_TRANSMISSION"}, {13, "SEND_STATUS"}, {14, "BUS_TEST_R"},
	{15, "GO_INACTIVE_STATE"}, {19, "BUS_TEST_W"}, {58, "SPI_READ_OCR"},
	{59, "SPI_CRC_ON_OFF"}, {16, "SET_BLOCKLEN"}, {17, "READ_SINGLE_BLOCK"},
	{18, "READ_MULTIPLE_BLOCK"}, {19, "SEND_TUNING_BLOCK"},
	{21, "SEND_TUNING_BLOCK_HS200"}, {20, "WRITE_DAT_UNTIL_STOP"},
	{23, "SET_BLOCK_COUNT"}, {24, "WRITE_BLOCK"}, {25, "WRITE_MULTIPLE_BLOCK"},
	{26, "PROGRAM_CID"}, {27, "PROGRAM_CSD"}, {28, "SET_WRITE_PROT"},
	{29, "CLR_WRITE_PROT"}, {30, "SEND_WRITE_PROT"}, {35, "ERASE_GROUP_START"},
	{36, "ERASE_GROUP_END"}, {38, "ERASE"}, {39, "FAST_IO"},
	{40, "GO_IRQ_STATE"}, {42, "LOCK_UNLOCK"}, {55, "APP_CMD"},
	{56, "GEN_CMD"}, {44, "QUE_TASK_PARAMS"}, {45, "QUE_TASK_ADDR"},
	{46, "EXECUTE_READ_TASK"}, {47, "EXECUTE_WRITE_TASK"},
	{48, "CMDQ_TASK_MGMT"}, {52, "IO_MODE"},
};

static const char *get_mmc_cmd(int id)
{
	for (size_t i = 0; i < sizeof(mmc_cmds) / sizeof(mmc_cmds[0]); i++) {
		if (mmc_cmds[i].id == id)
			return mmc_cmds[i].name;
	}
	return "Unknown";
}

struct sort_entry {
	struct mmc_key key;
	struct mmc_value val;
};

static int sort_cb(const void *a, const void *b)
{
	struct sort_entry *A = (struct sort_entry *)a;
	struct sort_entry *B = (struct sort_entry *)b;
	return B->val.delay - A->val.delay;
}

static void print_header(void)
{
	char loadavg[64];
	FILE *f;

	if (env.timestamp) {
		char ts[32];
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s\t", ts);
	}

	f = fopen("/proc/loadavg", "r");
	if (f) {
		if (fgets(loadavg, sizeof(loadavg), f))
			printf("loadavg: %s", loadavg);
		fclose(f);
	}

	if (env.per_pid)
		printf("%-6s %-6s %-16s ", "PID", "TID", "COMM");
	printf("%-28s ", "CMD_ID");
	if (env.per_blocks)
		printf("%8s ", "BLOCKS");
	printf("%8s %8s ", "BLKSZ", "I/O");
	if (env.per_cmd_arg)
		printf("%12s ", "CMD_ARG");

	const char *sizelabel = "Total_Bytes";
	if (env.megabytes)
		sizelabel = "Total_MBytes";
	else if (env.kilobytes)
		sizelabel = "Total_KBytes";

	printf("%12s %12s %12s %14s %12s %12s %12s %s\n",
			"CMD_FLAGS", "DATA_FLAGS", sizelabel, "Total_latency",
			"Max_latency", "Min_latency", "AVG_latency", "Unit");
}

static int print_stat(struct mmctop_bpf *skel)
{
	int map_fd = bpf_map__fd(skel->maps.counts);
	struct sort_entry *sorted_entries;
	struct mmc_key keys[MAX_ENTRIES], *prev_key = NULL;
	int err, i, rows;

	sorted_entries = calloc(MAX_ENTRIES, sizeof(struct sort_entry));
	if (!sorted_entries) {
		fprintf(stderr, "Failed to allocate memory\n");
		return 1;
	}

	i = 0;
	while (bpf_map_get_next_key(map_fd, prev_key, &keys[i]) == 0 && i < MAX_ENTRIES) {
		prev_key = &keys[i];
		i++;
	}
	rows = i;

	for (i = 0; i < rows; i++) {
		sorted_entries[i].key = keys[i];
		err = bpf_map_lookup_elem(map_fd, &keys[i], &sorted_entries[i].val);
		if (err) {
			fprintf(stderr, "Failed to lookup map elem: %d\n", err);
			free(sorted_entries);
			return 1;
		}
	}

	for (i = 0; i < rows; i++) {
		err = bpf_map_delete_elem(map_fd, &keys[i]);
		if (err) {
			fprintf(stderr, "Failed to delete map elem: %d\n", err);
			free(sorted_entries);
			return 1;
		}
	}

	qsort(sorted_entries, rows, sizeof(struct sort_entry), sort_cb);

	if (env.noclear)
		printf("\n");
	else
		printf("\033[H\033[J");

	print_header();

	for (i = 0; i < rows && i < env.maxrows; i++) {
		struct mmc_key *k = &sorted_entries[i].key;
		struct mmc_value *v = &sorted_entries[i].val;
		char cmd_id[32];
		snprintf(cmd_id, sizeof(cmd_id), "%s[%d]", get_mmc_cmd(k->cmd), k->cmd);

		if (env.per_pid)
			printf("%-6d %-6d %-16s ", k->pid, k->tid, k->name);
		printf("%-28s ", cmd_id);
		if (env.per_blocks)
			printf("%8d ", k->blocks);
		printf("%8u %8u ", k->blksz, v->io);
		if (env.per_cmd_arg)
			printf("%12x ", k->cmd_arg);

		double total_size = 0;
		int unit = 1;
		if (env.megabytes)
			unit = 1024 * 1024;
		else if (env.kilobytes)
			unit = 1024;

		if (env.per_blocks)
			total_size = (double)k->blocks * k->blksz * v->io / unit;
		else
			total_size = (double)v->blocks * k->blksz / unit;

		const char *timelabel = "usec";
		double time_div = 1000.0;
		if (env.milliseconds) {
			timelabel = "msec";
			time_div = 1000000.0;
		}

		printf("%12x %12x %12.1f %14.0f %12.0f %12.0f %12.2f %s\n",
				k->cmd_flags, k->data_flags, total_size,
				v->delay / time_div, v->max / time_div, v->min / time_div,
				(double)v->delay / v->io / time_div, timelabel);
	}

	free(sorted_entries);
	return 0;
}

int main(int argc, char **argv)
{
	struct argparse argparse;
	struct mmctop_bpf *skel;
	int err;
	struct timeval start_time;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Summarize mmc device I/O behavior as a table.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (argc > 0) {
		errno = 0;
		env.interval = strtol(argparse.out[0], NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid interval\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 1) {
		errno = 0;
		env.count = strtol(argparse.out[1], NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid count\n");
			argparse_usage(&argparse);
			return 1;
		}
	}
	if (argc > 2) {
		fprintf(stderr, "unrecognized positional argument: %s\n", argparse.out[2]);
		argparse_usage(&argparse);
		return 1;
	}

	if (env.min_blocks && env.max_blocks && env.min_blocks > env.max_blocks) {
		fprintf(stderr, "min_blocks (-z) can't be greater than max_blocks (-Z)\n");
		argparse_usage(&argparse);
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);

	skel = mmctop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = mmctop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	struct config cfg = {
		.per_pid = env.per_pid,
		.per_blocks = env.per_blocks,
		.per_cmd_arg = env.per_cmd_arg,
		.filter_cmd = env.command,
		.min_blocks = env.min_blocks,
		.max_blocks = env.max_blocks,
	};
	__u32 zero = 0;
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.config_map), &zero, &cfg, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update config map: %d\n", err);
		goto cleanup;
	}

	err = mmctop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing MMC device I/O... Hit Ctrl-C to end.\n");

	gettimeofday(&start_time, NULL);

	while (!exiting) {
		sleep(env.interval);

		err = print_stat(skel);
		if (err)
			break;

		if (env.count > 0)
			env.count--;
		if (env.count == 0)
			break;
	}

	struct timeval end_time;
	gettimeofday(&end_time, NULL);
	long runtime_sec = end_time.tv_sec - start_time.tv_sec;
	printf("\nTotal Runtime : %ld seconds\n", runtime_sec);

cleanup:
	mmctop_bpf__destroy(skel);
	return -err;
}
