/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * rtkheaptop: Analysis rtkheap allocation as a table.
 *
 * Copyright (c) 2025 Realtek, Inc.
 */
#include "argparse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "rtkheaptop.h"
#include "rtkheaptop.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}
#define BYTES_TO_PAGES 4096
#define BASE_PATH "/sys/kernel/debug/rtk_heap"

// Simple linked list implementation for userspace
struct simple_list_head {
	struct simple_list_head *next, *prev;
};

#define SIMPLE_LIST_HEAD_INIT(name) { &(name), &(name) }
#define SIMPLE_LIST_HEAD(name) \
	struct simple_list_head name = SIMPLE_LIST_HEAD_INIT(name)

static inline void simple_init_list_head(struct simple_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void simple_list_add_tail(struct simple_list_head *new, struct simple_list_head *head)
{
	head->prev->next = new;
	new->prev = head->prev;
	new->next = head;
	head->prev = new;
}

static inline void simple_list_del(struct simple_list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = NULL; /* for safety */
	entry->prev = NULL; /* for safety */
}

static inline int simple_list_empty(const struct simple_list_head *head)
{
	return head->next == head;
}

#define simple_list_entry(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

#define simple_list_for_each_entry(pos, head, member) \
	for (pos = simple_list_entry((head)->next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = simple_list_entry(pos->member.next, typeof(*pos), member))

#define simple_list_for_each_entry_safe(pos, n, head, member) \
	for (pos = simple_list_entry((head)->next, typeof(*pos), member), \
			n = simple_list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = n, n = simple_list_entry(n->member.next, typeof(*n), member))

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

static struct env {
	const char *heap_name;
	const char *task_name;
	const char *caller_name;
	bool noclear;
	bool milliseconds;
	bool timestamp;
	int interval;
	int count;
} env = {
	.heap_name = "0",
	.task_name = "0",
	.caller_name = "0",
	.interval = 1,
	.count = 99999999,
};

static const char * const usages[] = {
	"rtkheaptop [options] [interval] [count]",
	NULL,
};

static struct argparse_option options[] = {
	OPT_BOOLEAN('C', "noclear", &env.noclear, "Don't clear the screen", NULL, 0, 0),
	OPT_BOOLEAN('m', "milliseconds", &env.milliseconds, "Millisecond histogram", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_STRING('n', "heap_name", &env.heap_name, "Trace this heap name only", NULL, 0, 0),
	OPT_STRING('t', "task_name", &env.task_name, "Trace this task name only", NULL, 0, 0),
	OPT_STRING('c', "caller_name", &env.caller_name, "Trace this caller name only", NULL, 0, 0),
	OPT_HELP(),
	OPT_END(),
};

static const char *get_caller_str(const struct use_heap *key, char *buffer, size_t size)
{
	if (key->caller[0] != '\0')
		return key->caller;

	snprintf(buffer, size, "tgid-%d", key->tgid);
	return buffer;
}

struct heap_summary_entry {
	char name[HEAP_MAX_NAME];
	unsigned long usage;
	unsigned long free;
	struct simple_list_head list;
};

SIMPLE_LIST_HEAD(heap_summary_list);

struct task_info {
	char comm[TASK_COMM_LEN];
	int used_pages;
	struct simple_list_head list;
};

struct rtk_heap_info {
	char heap_name[HEAP_MAX_NAME];
	int count_cma;
	int used_cma;
	int free_cma;
	int count_gen;
	int used_gen;
	int free_gen;
	char flag_line[256];
	struct simple_list_head task_list;
	struct simple_list_head list;
};

SIMPLE_LIST_HEAD(rtk_heap_info_list);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_WARN)
		return vfprintf(stderr, format, args);
	return 0;
}

static void parse_heap_summary()
{
	FILE *f;
	char line[256];
	char heap_name[HEAP_MAX_NAME];
	unsigned long usage, free_mem;
	struct heap_summary_entry *entry, *tmp;

	/* free previous list */
	simple_list_for_each_entry_safe(entry, tmp, &heap_summary_list, list) {
		simple_list_del(&entry->list);
		free(entry);
	}
	simple_init_list_head(&heap_summary_list);

	f = fopen(BASE_PATH "/heap_summary", "r");
	if (!f) {
		warn("Failed to open %s/heap_summary\n", BASE_PATH);
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, " Heap: %s", heap_name) == 1) {
			entry = calloc(1, sizeof(*entry));
			if (!entry) {
				warn("Failed to allocate memory for heap_summary_entry\n");
				break;
			}
			strncpy(entry->name, heap_name, sizeof(entry->name) - 1);
			entry->name[sizeof(entry->name) - 1] = '\0';
			simple_list_add_tail(&entry->list, &heap_summary_list);
		} else {
			if (!simple_list_empty(&heap_summary_list)) {
				struct heap_summary_entry *last_entry =
					simple_list_entry(heap_summary_list.prev, struct heap_summary_entry, list);
				if (strstr(line, "Usage:") && strstr(line, "free:")) {
					if (sscanf(line, " Usage: 0x%lx free: 0x%lx", &usage, &free_mem) == 2) {
						last_entry->usage = usage;
						last_entry->free = free_mem;
					}
				}
			}
		}
	}
	fclose(f);
}

static bool dump_rtkheap_info(const char *entry_name)
{
	char full_path[256];
	char file_path[256];
	FILE *f;
	char line[256];
	struct rtk_heap_info *heap_info;

	if (env.heap_name[0] != '0' && strstr(entry_name, env.heap_name) == NULL)
		return false;

	snprintf(full_path, sizeof(full_path), "%s/%s", BASE_PATH, entry_name);
	if (access(full_path, F_OK) != 0)
		return false;

	heap_info = calloc(1, sizeof(*heap_info));
	if (!heap_info) {
		warn("Failed to allocate memory for rtk_heap_info\n");
		return false;
	}
	strncpy(heap_info->heap_name, entry_name, sizeof(heap_info->heap_name) - 1);
	heap_info->heap_name[sizeof(heap_info->heap_name) - 1] = '\0';
	simple_init_list_head(&heap_info->task_list);
	simple_list_add_tail(&heap_info->list, &rtk_heap_info_list);

	// Read count_cma
	snprintf(file_path, sizeof(file_path), "%s/count_cma", full_path);
	f = fopen(file_path, "r");
	if (f) {
		if (fgets(line, sizeof(line), f))
			heap_info->count_cma = atoi(line);
		fclose(f);
	} else {
		// Read size (for gen pool)
		snprintf(file_path, sizeof(file_path), "%s/size", full_path);
		f = fopen(file_path, "r");
		if (f) {
			if (fgets(line, sizeof(line), f))
				heap_info->count_gen = strtol(line, NULL, 16) / BYTES_TO_PAGES;
			fclose(f);
		}
	}

	// Read used_cma
	snprintf(file_path, sizeof(file_path), "%s/used_cma", full_path);
	f = fopen(file_path, "r");
	if (f) {
		if (fgets(line, sizeof(line), f))
			heap_info->used_cma = atoi(line);
		fclose(f);
	} else {
		// Read avail (for gen pool)
		snprintf(file_path, sizeof(file_path), "%s/avail", full_path);
		f = fopen(file_path, "r");
		if (f) {
			if (fgets(line, sizeof(line), f))
				heap_info->free_gen = strtol(line, NULL, 16) / BYTES_TO_PAGES;
			fclose(f);
		}
	}

	// Read attribute
	snprintf(file_path, sizeof(file_path), "%s/attribute", full_path);
	f = fopen(file_path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "flags :")) {
				strncpy(heap_info->flag_line, line, sizeof(heap_info->flag_line) - 1);
				heap_info->flag_line[sizeof(heap_info->flag_line) - 1] = '\0';
				break;
			}
		}
		fclose(f);
	}

	if (heap_info->count_gen == 0) {
		heap_info->free_cma = heap_info->count_cma - heap_info->used_cma;
		if (heap_info->count_cma == 0) {
			struct heap_summary_entry *summary_entry;
			simple_list_for_each_entry(summary_entry, &heap_summary_list, list) {
				if (strcmp(summary_entry->name, heap_info->heap_name) == 0) {
					heap_info->free_cma = summary_entry->free;
					heap_info->used_cma = summary_entry->usage;
					heap_info->count_cma = heap_info->free_cma + heap_info->used_cma;
					break;
				}
			}
		}
	} else {
		heap_info->used_gen = heap_info->count_gen - heap_info->free_gen;
	}

	// Parse task file
	snprintf(file_path, sizeof(file_path), "%s/task", full_path);
	f = fopen(file_path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			char comm_name[TASK_COMM_LEN];
			unsigned int value;
			if (sscanf(line, "name: %s %x", comm_name, &value) == 2) {
				struct task_info *task = calloc(1, sizeof(*task));
				if (!task) {
					warn("Failed to allocate memory for task_info\n");
					break;
				}
			strncpy(task->comm, comm_name, sizeof(task->comm) - 1);
			task->comm[sizeof(task->comm) - 1] = '\0';
			task->used_pages = value / BYTES_TO_PAGES;
			simple_list_add_tail(&task->list, &heap_info->task_list);
			}
		}
		fclose(f);
	}

	return true;
}

int main(int argc, char **argv)
{
	struct rtkheaptop_bpf *skel;
	int err = 0, map_fd;

	struct argparse argparse;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Analysis rtkheap allocation as a table.",
			"Default interval is 1s, default count is infinite.");
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (argc) {
		if (argc > 2) {
			warn("Too many arguments\n");
			argparse_usage(&argparse);
			return -1;
		}
		env.interval = atoi(argv[0]);
		if (env.interval == 0) {
			warn("invalid interval\n");
			argparse_usage(&argparse);
			return -1;
		}
		if (argc > 1)
			env.count = atoi(argv[1]);
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(libbpf_print_fn);

	skel = rtkheaptop_bpf__open();
	if (!skel)
		goto cleanup;

	// Set BPF global variables
	skel->rodata->milliseconds = env.milliseconds;

	if (strcmp(env.heap_name, "0") != 0) {
		strncpy((char *)skel->rodata->heap_name_filter, env.heap_name, sizeof(skel->rodata->heap_name_filter) - 1);
		skel->rodata->heap_name_filter[sizeof(skel->rodata->heap_name_filter) - 1] = '\0';
	}
	if (strcmp(env.task_name, "0") != 0) {
		strncpy((char *)skel->rodata->task_name_filter, env.task_name, sizeof(skel->rodata->task_name_filter) - 1);
		skel->rodata->task_name_filter[sizeof(skel->rodata->task_name_filter) - 1] = '\0';
	}
	if (strcmp(env.caller_name, "0") != 0) {
		strncpy((char *)skel->rodata->caller_name_filter, env.caller_name, sizeof(skel->rodata->caller_name_filter) - 1);
		skel->rodata->caller_name_filter[sizeof(skel->rodata->caller_name_filter) - 1] = '\0';
	}

	// FIXME:
	// Hardcode kernel version check to assume modern kernel (>= 5.11)
	// This is a workaround for sys/utsname.h not found error.
	// In a proper environment, get_kernel_version() should be used.
	// int kernel_version = get_kernel_version();
	// if (kernel_version < 511) {
	// ... original logic ...
	// } else {
	// ... original logic ...
	// }

	// Assuming kernel >= 5.11, so disable older kprobes
	bpf_program__set_autoload(skel->progs.rtk_dyn_protect_cma_do_allocate_entry, false);
	bpf_program__set_autoload(skel->progs.rtk_dyn_protect_cma_do_allocate_exit, false);
	bpf_program__set_autoload(skel->progs.rtk_stc_cma_do_allocate_entry, false);
	bpf_program__set_autoload(skel->progs.rtk_stc_cma_do_allocate_exit, false);
	bpf_program__set_autoload(skel->progs.rtk_cma_do_allocate_entry, false);
	bpf_program__set_autoload(skel->progs.rtk_cma_do_allocate_exit, false);
	bpf_program__set_autoload(skel->progs.rtk_gen_do_allocate_entry, false);
	bpf_program__set_autoload(skel->progs.rtk_gen_do_allocate_exit, false);

	err = rtkheaptop_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = rtkheaptop_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	printf("Tracing rtkheap allocation ... Hit Ctrl-C to end.\n");

	map_fd = bpf_map__fd(skel->maps.heap_summary_hash);

	while (env.count--) {
		DIR *dir;
		struct dirent *entry;
		struct rtk_heap_info *h_info, *h_tmp;
		struct task_info *t_info, *t_tmp;

		sleep(env.interval);

		if (!env.noclear)
			printf("\033[2J\033[H");

		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);
			strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
			printf("%-8s\n", ts);
		}

		// Clear previous heap info
		simple_list_for_each_entry_safe(h_info, h_tmp, &rtk_heap_info_list, list) {
			simple_list_for_each_entry_safe(t_info, t_tmp, &h_info->task_list, list) {
				simple_list_del(&t_info->list);
				free(t_info);
			}
			simple_list_del(&h_info->list);
			free(h_info);
		}
		simple_init_list_head(&rtk_heap_info_list);

		// Parse heap summary (if needed, based on kernel version)
		// For now, always parse as we hardcoded kernel >= 5.11
		parse_heap_summary();

		dir = opendir(BASE_PATH);
		if (!dir) {
			warn("Failed to open directory %s\n", BASE_PATH);
			continue;
		}

		while ((entry = readdir(dir)) != NULL) {
			if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
				dump_rtkheap_info(entry->d_name);
			}
		}
		closedir(dir);

		struct bpf_map_entry {
			struct use_heap key;
			struct heap_info value;
			bool printed;
		};

		int num_map_entries = 0;
		struct use_heap key_count, *prev_key_count = NULL;
		while (bpf_map_get_next_key(map_fd, prev_key_count, &key_count) == 0) {
			num_map_entries++;
			prev_key_count = &key_count;
		}

		struct bpf_map_entry *map_entries = NULL;
		if (num_map_entries > 0) {
			map_entries = calloc(num_map_entries, sizeof(struct bpf_map_entry));
			if (!map_entries) {
				warn("Failed to allocate memory for map_entries\n");
			} else {
				int i = 0;
				struct use_heap key, *prev_key = NULL;
				while (bpf_map_get_next_key(map_fd, prev_key, &key) == 0) {
					if (i < num_map_entries && bpf_map_lookup_elem(map_fd, &key, &map_entries[i].value) == 0) {
						map_entries[i].key = key;
						map_entries[i].printed = false;
						i++;
					}
					prev_key = &key;
				}
				num_map_entries = i;
			}
		}

		// Print collected data
		simple_list_for_each_entry(h_info, &rtk_heap_info_list, list) {
			if (h_info->count_gen == 0) {
				printf("heap_name : %-30s  count_cma : %-8d  used_cma : %-8d  free_cma : %-8d  %s",
						h_info->heap_name, h_info->count_cma, h_info->used_cma, h_info->free_cma, h_info->flag_line);
			} else {
				printf("heap_name : %-30s  count_gen : %-8d  used_gen : %-8d  free_gen : %-8d  %s",
						h_info->heap_name, h_info->count_gen, h_info->used_gen, h_info->free_gen, h_info->flag_line);
			}

			if (simple_list_empty(&h_info->task_list) && (!map_entries || num_map_entries == 0)) {
				printf("\n");
				continue;
			}

			printf("%-16s %-12s %-16s %-10s %12s %15s %8s %5s\n",
					"COMM", "USED_PAGES", "CALLER", "FLAGS", "ALLOC_PAGES",
					"MAX_ALLOC_LAT", "SUCCESS", "FAIL");

			int total_used = 0;
			long long total_alloc = 0;
			struct task_info *t_entry;

			simple_list_for_each_entry(t_entry, &h_info->task_list, list) {
				if (env.task_name[0] != '0' && strstr(t_entry->comm, env.task_name) == NULL)
					continue;

				bool task_alloc_printed = false;
				total_used += t_entry->used_pages;

				if (map_entries) {
					for (int i = 0; i < num_map_entries; i++) {
						char caller_buf[TASK_COMM_LEN];

						if (strcmp(map_entries[i].key.name, h_info->heap_name) != 0 ||
							strcmp(map_entries[i].key.comm, t_entry->comm) != 0)
							continue;

						if (env.caller_name[0] != '0' && strstr(map_entries[i].key.caller, env.caller_name) == NULL)
							continue;

						char flag_str[20];
						snprintf(flag_str, sizeof(flag_str), "0x%lx", map_entries[i].key.flags);
						const char *label = env.milliseconds ? "ms" : "us";

						if (!task_alloc_printed) {
							printf("%-16s %-12d ", t_entry->comm, t_entry->used_pages);
							task_alloc_printed = true;
						} else {
							printf("%-16s %-12s ", "", "");
						}

						total_alloc += map_entries[i].value.size;

						printf("%-16s %-10s %12llu %12u %2s %8u %5u\n",
								get_caller_str(&map_entries[i].key, caller_buf, sizeof(caller_buf)),
								flag_str,
								map_entries[i].value.size, map_entries[i].value.max_alloc_latency,
								label,
								map_entries[i].value.success, map_entries[i].value.fail);

						map_entries[i].printed = true;
					}
				}

				if (!task_alloc_printed) {
					printf("%-16s %-12d\n", t_entry->comm, t_entry->used_pages);
				}
			}

			if (map_entries) {
				char last_task_name[TASK_COMM_LEN] = "";
				for (int i = 0; i < num_map_entries; i++) {
					char caller_buf[TASK_COMM_LEN];

					if (map_entries[i].printed || strcmp(map_entries[i].key.name, h_info->heap_name) != 0)
						continue;

					if (env.task_name[0] != '0' && strstr(map_entries[i].key.comm, env.task_name) == NULL)
						continue;

					if (env.caller_name[0] != '0' && strstr(map_entries[i].key.caller, env.caller_name) == NULL)
						continue;

					bool task_in_list = false;
					simple_list_for_each_entry(t_entry, &h_info->task_list, list) {
						if (strcmp(t_entry->comm, map_entries[i].key.comm) == 0) {
							task_in_list = true;
							break;
						}
					}
					if (task_in_list)
						continue;

					if (strcmp(last_task_name, map_entries[i].key.comm) != 0) {
						printf("%-16s %-12d ", map_entries[i].key.comm, 0);
						strncpy(last_task_name, map_entries[i].key.comm, sizeof(last_task_name) - 1);
						last_task_name[sizeof(last_task_name) - 1] = '\0';
					} else {
						printf("%-16s %-12s ", "", "");
					}

					total_alloc += map_entries[i].value.size;

					char flag_str[20];
					snprintf(flag_str, sizeof(flag_str), "0x%lx", map_entries[i].key.flags);
					const char *label = env.milliseconds ? "ms" : "us";

					printf("%-16s %-10s %12llu %12u %2s %8u %5u\n",
							get_caller_str(&map_entries[i].key, caller_buf, sizeof(caller_buf)),
							flag_str,
							map_entries[i].value.size, map_entries[i].value.max_alloc_latency,
							label,
							map_entries[i].value.success, map_entries[i].value.fail);
					map_entries[i].printed = true;
				}
			}

			printf("%-16s %-12d", "Total = ", total_used);
			if (total_alloc > 0) {
				printf(" %-16s %-10s %12lld", "", "", total_alloc);
			}
			printf("\n\n");
		}

		if (map_entries) {
			for (int i = 0; i < num_map_entries; i++) {
				if (bpf_map_delete_elem(map_fd, &map_entries[i].key) != 0) {
					warn("bpf_map_delete_elem failed for key\n");
				}
			}
			free(map_entries);
		}

		if (exiting)
			break;

	}

cleanup:
	// Free remaining heap summary entries
	struct heap_summary_entry *hs_entry, *hs_tmp;
	simple_list_for_each_entry_safe(hs_entry, hs_tmp, &heap_summary_list, list) {
		simple_list_del(&hs_entry->list);
		free(hs_entry);
	}

	// Free remaining rtk heap info entries
	struct rtk_heap_info *h_info, *h_tmp;
	struct task_info *t_info, *t_tmp;
	simple_list_for_each_entry_safe(h_info, h_tmp, &rtk_heap_info_list, list) {
		simple_list_for_each_entry_safe(t_info, t_tmp, &h_info->task_list, list) {
			simple_list_del(&t_info->list);
			free(t_info);
		}
		simple_list_del(&h_info->list);
		free(h_info);
	}

	rtkheaptop_bpf__destroy(skel);
	return -err;
}
