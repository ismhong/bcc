// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * linuxfiletop  file reads and writes by process for Linux.
 *          For Linux, uses BCC, eBPF.
 *
 * USAGE: linuxfiletop [-h] [-a] [-C] [-r MAXROWS]
 *                     [-s {all,reads,writes,rbytes,wbytes}] [-p PID] [-t TID]
 *                     [-o {all,read,write}] [-f FS_TYPE] [-d DEV_NAME]
 *                     [-m MOUNT_POINT]
 *                     [interval] [count]
 *
 * This uses in-kernel eBPF maps to store per process summaries for efficiency.
 *
 * Copyright (c) 2025 Realtek, Inc. Reference from filetop.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 11-Jun-2025   msinwu      Created this.
 */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "trace_helpers.h"
#include "linuxfiletop.h"
#include "linuxfiletop.skel.h"
#include "btf_helpers.h"

#define DEVNAMELEN 256

struct DName
{
	char devName[DEVNAMELEN];
};

static struct env
{
	bool all_files;
	bool noclear;
	int maxrows;
	char *sort;
	pid_t pid;
	pid_t tid;
	char *rw_only;
	char *fs_type;
	char *dev_name;
	char *mount_point;
	int interval;
	int count;
	bool verbose;
}
 env = {
	.maxrows = 20,
	.sort = "all",
	.rw_only = "all",
	.fs_type = "0",
	.dev_name = "0",
	.mount_point = "0",
	.interval = 1,
	.count = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "linuxfiletop 0.1";
const char *argp_program_bug_address = "<https://github.com/iovisor/bcc/tree/master/tools>";
const char argp_doc[] = "Linux file reads and writes by process.\n\nUSAGE: linuxfiletop [-h] [-a] [-C] [-r MAXROWS] [-s {all,reads,writes,rbytes,wbytes}] [-p PID] [-t TID] [-o {all,read,write}] [-f FS_TYPE] [-d DEV_NAME] [-m MOUNT_POINT] [interval] [count]\n\nEXAMPLES:\n    ./linuxfiletop               # linux file I/O top, 1 second refresh\n    ./linuxfiletop -C            # don't clear the screen\n    ./linuxfiletop -t 181        # TID 181 only\n    ./linuxfiletop -f proc       # trace proc fs only\n    ./linuxfiletop -d dm-49      # trace dm-49 devname only\n    ./linuxfiletop -m /data      # trace /data mount point only\n    ./linuxfiletop 5             # 5 second summaries\n    ./linuxfiletop 5 10          # 5 second summaries, 10 times only\n";

static const struct argp_option opts[] = {
	{ .name = "all_files", .key = 'a', .doc = "include non-regular file types (sockets, FIFOs, etc)" },
	{ .name = "noclear", .key = 'C', .doc = "don't clear the screen" },
	{ .name = "maxrows", .key = 'r', .arg = "MAXROWS", .doc = "maximum rows to print, default 20" },
	{ .name = "sort", .key = 's', .arg = "SORT", .doc = "sort column, default all" },
	{ .name = "pid", .key = 'p', .arg = "PID", .doc = "trace this PID only" },
	{ .name = "tid", .key = 't', .arg = "TID", .doc = "trace this TID only" },
	{ .name = "rw_only", .key = 'o', .arg = "RW_ONLY", .doc = "trace only reads or writes" },
	{ .name = "fs_type", .key = 'f', .arg = "FS_TYPE", .doc = "trace this filesystem type only" },
	{ .name = "dev_name", .key = 'd', .arg = "DEV_NAME", .doc = "trace this device name only" },
	{ .name = "mount_point", .key = 'm', .arg = "MOUNT_POINT", .doc = "trace this mount point only" },
	{ .name = "verbose", .key = 'v', .doc = "Verbose debug output" },
	{ .name = NULL, .key = 'h', .flags = OPTION_HIDDEN, .doc = "Show the full help" },
	{},
};

static int parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'a':
		env.all_files = true;
		break;
	case 'C':
		env.noclear = true;
		break;
	case 'r':
		env.maxrows = atoi(arg);
		break;
	case 's':
		env.sort = arg;
		break;
	case 'p':
		env.pid = atoi(arg);
		break;
	case 't':
		env.tid = atoi(arg);
		break;
	case 'o':
		env.rw_only = arg;
		break;
	case 'f':
		env.fs_type = arg;
		break;
	case 'd':
		env.dev_name = arg;
		break;
	case 'm':
		env.mount_point = arg;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0)
			env.interval = atoi(arg);
		else if (state->arg_num == 1)
			env.count = atoi(arg);
		else
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
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

struct mount_info
{
	char dev[256];
	char mount_point[256];
};

static struct mount_info *mounts;
static int mounts_count = 0;

static void parse_mountinfo()
{
	FILE *f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return;

	char line[1024];
	while (fgets(line, sizeof(line), f))
	{
		mounts = realloc(mounts, (mounts_count + 1) * sizeof(struct mount_info));
		sscanf(line, "%*d %*d %s %*s %s %*s", mounts[mounts_count].dev,
		       mounts[mounts_count].mount_point);
		mounts_count++;
	}
	fclose(f);
}

static const char *find_mount_point(unsigned int major, unsigned int minor)
{
	char dev_id[32];
	snprintf(dev_id, sizeof(dev_id), "%u:%u", major, minor);
	for (int i = 0; i < mounts_count; i++)
	{
		if (strcmp(mounts[i].dev, dev_id) == 0)
			return mounts[i].mount_point;
	}
	return "None";
}

static const char *get_devname_from_sys_block(unsigned int major,
					  unsigned int minor)
{
	static __thread char devname[DEVNAMELEN];
	char path[256];
	snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/uevent", major, minor);
	FILE *f = fopen(path, "r");
	if (!f)
		return "";

	char line[256];
	while (fgets(line, sizeof(line), f))
	{
		if (strncmp(line, "DEVNAME=", 8) == 0)
		{
			strncpy(devname, line + 8, DEVNAMELEN - 1);
			devname[strcspn(devname, "\n")] = 0;
			fclose(f);
			return devname;
		}
	}
	fclose(f);
	return "";
}

struct combined_val
{
	struct info_t info;
	struct val_t val;
};

static int sort_column(const void *a, const void *b)
{
	struct combined_val *va = (struct combined_val *)a;
	struct combined_val *vb = (struct combined_val *)b;

	if (strcmp(env.sort, "reads") == 0)
		return vb->val.reads - va->val.reads;
	if (strcmp(env.sort, "writes") == 0)
		return vb->val.writes - va->val.writes;
	if (strcmp(env.sort, "rbytes") == 0)
		return vb->val.rbytes - va->val.rbytes;
	if (strcmp(env.sort, "wbytes") == 0)
		return vb->val.wbytes - va->val.wbytes;
	// default "all"
	return (vb->val.rbytes + vb->val.wbytes + vb->val.reads + vb->val.writes) -
	       (va->val.rbytes + va->val.wbytes + va->val.reads + va->val.writes);
}

static int print_stat(struct linuxfiletop_bpf *obj)
{
	int fd = bpf_map__fd(obj->maps.counts);
	struct info_t *lookup_key = NULL, next_key;
	struct combined_val *combined_vals = NULL;
	int i = 0, rows = 0;
	__u64 total_rbytes = 0, total_wbytes = 0;
	__u64 val_arr[libbpf_num_possible_cpus()];

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.total_read_bytes), &i, val_arr) == 0)
	{
		for (i = 0; i < libbpf_num_possible_cpus(); i++)
			total_rbytes += val_arr[i];
	}
	i = 0;
	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.total_write_bytes), &i, val_arr) == 0)
	{
		for (i = 0; i < libbpf_num_possible_cpus(); i++)
			total_wbytes += val_arr[i];
	}

	/*memset(&lookup_key, 0, sizeof(lookup_key));*/
	memset(&next_key, 0, sizeof(next_key));
	while (bpf_map_get_next_key(fd, lookup_key, &next_key) == 0)
	{
		rows++;
		combined_vals = realloc(combined_vals, rows * sizeof(struct combined_val));
		struct val_t val;
		bpf_map_lookup_elem(fd, &next_key, &val);
		combined_vals[rows - 1].info = next_key;
		combined_vals[rows - 1].val = val;
		lookup_key = &next_key;
	}

	qsort(combined_vals, rows, sizeof(struct combined_val), sort_column);

	if (env.noclear)
		printf("\n");
	else
		printf("\033[2J\033[H");

	char timestr[32];
	time_t t;
	struct tm *tm;
	time(&t);
	tm = localtime(&t);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);

	printf("%s\n", timestr);
	printf("%-7s %-7s %-16s %-6s %-6s %-7s %-7s %-2s %-12s %-12s %s\n", "PID",
	       "TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "DEVNAME",
	       "FS_TYPE", "FILE");

	__u64 total_reads = 0, total_writes = 0, total_rkb = 0, total_wkb = 0;

	for (i = 0; i < MIN(rows, env.maxrows); i++)
	{
		struct info_t k = combined_vals[i].info;
		struct val_t v = combined_vals[i].val;

		if (strcmp(env.fs_type, "0") != 0 && strcmp(env.fs_type, k.fs_type) != 0)
			continue;

		const char *mount_point = find_mount_point(k.dev_major, k.dev_minor);
		if (strcmp(env.mount_point, "/") != 0 &&
		    strcmp(env.mount_point, "0") != 0 &&
		    strncmp(mount_point, env.mount_point, strlen(env.mount_point)) != 0)
			continue;

		const char *dev_name = get_devname_from_sys_block(k.dev_major, k.dev_minor);
		if (strcmp(env.dev_name, "0") != 0 && strcmp(env.dev_name, dev_name) != 0)
			continue;

		char name[DNAME_INLINE_LEN];
		strncpy(name, k.name, DNAME_INLINE_LEN);
		if (k.name_len > DNAME_INLINE_LEN)
		{
			name[DNAME_INLINE_LEN - 4] = '.';
			name[DNAME_INLINE_LEN - 3] = '.';
			name[DNAME_INLINE_LEN - 2] = '.';
			name[DNAME_INLINE_LEN - 1] = '\0';
		}

		char full_path[1024] = "";
		char *dirs[] = { k.file_dir1, k.file_dir2, k.file_dir3, k.file_dir4,
				 k.file_dir5, k.file_dir6, k.file_dir7 };
		if (k.file_dir7[0] == '/')
		{
			strcat(full_path, "");
		}
		else
		{
			strcat(full_path, ".../");
		}

		for (int j = MAX_DIR_DEPTH - 2; j >= 0; j--)
		{
			if (dirs[j][0] != '/' && dirs[j][0] != '\0')
			{
				strcat(full_path, dirs[j]);
				strcat(full_path, "/");
			}
		}

		char final_name[2048];
		if (strcmp(mount_point, "None") != 0)
		{
			snprintf(final_name, sizeof(final_name), "%s%s%s", mount_point,
				strcmp(mount_point, "/") == 0 ? "" : "/", full_path);
			strcat(final_name, name);
		}
		else
		{
			strcpy(final_name, name);
		}

		total_reads += v.reads;
		total_writes += v.writes;
		total_rkb += v.rbytes / 1024;
		total_wkb += v.wbytes / 1024;

		printf("%-7d %-7d %-16s %-6llu %-6llu %-7llu %-7llu %-2c %-12s %-12s %s\n",
			   k.pid, k.tid, k.comm, v.reads, v.writes, v.rbytes / 1024,
			   v.wbytes / 1024, k.type, dev_name, k.fs_type, final_name);
	}

	printf("%-7s %-7s %-16s %-6llu %-6llu %-7llu %-7llu\n", "", "", "",
		   total_reads, total_writes, total_rkb, total_wkb);
	printf("TOTAL READ  KB:%llu\n", total_rbytes / 1024);
	printf("TOTAL WRITE KB:%llu\n", total_wbytes / 1024);

	lookup_key = NULL;
	while (bpf_map_get_next_key(fd, lookup_key, &next_key) == 0)
	{
		bpf_map_delete_elem(fd, &next_key);
		lookup_key = &next_key;
	}

	int map_key = 0;
	__u64 zero_arr[libbpf_num_possible_cpus()];

	memset(zero_arr, 0, sizeof(zero_arr));
	bpf_map_update_elem(bpf_map__fd(obj->maps.total_read_bytes), &map_key,
			    zero_arr, BPF_ANY);
	bpf_map_update_elem(bpf_map__fd(obj->maps.total_write_bytes), &map_key,
			    zero_arr, BPF_ANY);

	free(combined_vals);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp =
	    {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_doc,
	    };
	int err;
	struct linuxfiletop_bpf *obj;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = linuxfiletop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->all_files = env.all_files;

	if (strcmp(env.rw_only, "read") == 0)
	{
		bpf_program__set_autoload(obj->progs.trace_write_entry, false);
	}
	else if (strcmp(env.rw_only, "write") == 0)
	{
		bpf_program__set_autoload(obj->progs.trace_read_entry, false);
	}

	err = linuxfiletop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = linuxfiletop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	parse_mountinfo();

	printf("Tracing... Output every %d secs. Hit Ctrl-C to end\n", env.interval);

	while (1)
	{
		sleep(env.interval);

		if (exiting || --env.count == 0)
			break;

		err = print_stat(obj);
		if (err)
			break;
	}

cleanup:
	linuxfiletop_bpf__destroy(obj);
	free(mounts);

	return err != 0;
}
