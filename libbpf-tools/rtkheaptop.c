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
#include <sys/utsname.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "rtkheaptop.h"
#include "rtkheaptop.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile int exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}
#define BYTES_TO_PAGES 4096
#define BASE_PATH "/sys/kernel/debug/rtk_heap"
#define PROCFS_BASE_PATH "/proc/rtk_heap/heap_summary"

static int k_major = 0;
static int k_minor = 0;

static void init_kernel_version(void)
{
	struct utsname uts;
	if (uname(&uts) == 0) {
		sscanf(uts.release, "%d.%d", &k_major, &k_minor);
	}
}

static bool is_use_rtk_heap(void)
{
	return ((k_major == 5 && k_minor > 10) || k_major >= 6);
}

static bool is_rtk_dev_name(void)
{
	return ((k_major == 6 && k_minor >= 12) || k_major >= 7);
}

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
	int noclear;
	int milliseconds;
	int timestamp;
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
	char raw_heap_name[HEAP_MAX_NAME];
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

struct name_map_entry {
	const char *raw_name;
	const char *mapped_name;
};

static const struct name_map_entry name_map[] = {
	{"vo_dsc3", "vo_non-ve"},
	{"vo_s_dsc3", "vo_non-vc-ac-ve"},
	{"ota_dsc8", "ota_u1p5_non-ve_secure8"},
	{"ao_ssc6", "ao_u1p5_non-ve_secure6"},
	{"audio_ssc1", "audio_u1p5_non-ve_secure1"},
};

static const char *map_heap_name(const char *map_name)
{
	if (is_rtk_dev_name() == false) {
		return map_name;
	}

	for (size_t i = 0; i < sizeof(name_map) / sizeof(name_map[0]); i++) {
		if (strcmp(name_map[i].mapped_name, map_name) == 0)
			return name_map[i].raw_name;
	}
	return map_name;
}

struct secure_map_entry {
	const char *key;
	const char *value;
};

static const struct secure_map_entry secure_map[] = {
	{"metadata", "secure-meta"},
	{"vo_dsc3", "secure-vo-client"},
	{"vo_dsc3", "secure-vo-deint"},
	{"vo_dsc3", "secure-vo-cvbs"},
	{"vo_dsc3", "secure-vo-lastf"},
	{"tp_ssc2", "secure-tp"},
	{"audio_ssc1", "secure-audio-stack"},
	{"audio_ssc1", "secure-audio-client"},
	{"audio_ssc1", "secure-hifi-client"},
	{"video_ssc5", "secure-video-client"},
	{"video_ssc5", "secure-video-usrdata"},
	{"video_dsc5", "secure-video-client"},
	{"video_dsc5", "secure-video-usrdata"},
	{"video2_ssc5", "secure-video2-client"},
	{"video2_dsc5", "secure-video2-client"},
	{"ao_ssc6", "secure-ao-client"},
	{"ao_dsc6", "secure-ao-client"},
	{"ota_dsc8", "secure-ota"},
	{"vo_s_dsc3", "secure-vos-client"},
	{"vo_s_dsc3", "secure-vos-deint"},
	{"vo_s_dsc3", "secure-vos-cvbs"},
	{"vo_s_dsc3", "secure-vos-lastf"},
	{"fwstack_dsc4", "secure-fwstack"},
	{"hifi_b1p5", "hifi"},
	{"npp", "secure-npp"},
	{"npu-inference", "secure-npuinf"},
	{"npu-model", "secure-npumodel"},
	{"heap_b1p5", "heap-high"},
	{"hifi-ssc12", "secure-hifi-data"},
};

static bool is_procfs_heap_in_keys(const char *dev_name, const char *procfs_heap_raw_name)
{
	for (size_t i = 0; i < sizeof(secure_map) / sizeof(secure_map[0]); i++) {
		if (strcmp(secure_map[i].value, dev_name) == 0) {
			if (strcmp(secure_map[i].key, procfs_heap_raw_name) == 0)
				return true;
		}
	}
	return false;
}

struct bpf_map_entry {
	struct use_heap key;
	struct heap_info value;
	bool printed;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_WARN)
		return vfprintf(stderr, format, args);
	return 0;
}

static void cleanup_rtk_heap_info_list(void)
{
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
	simple_init_list_head(&rtk_heap_info_list);
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
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, " Heap: %s", heap_name) == 1) {
			entry = calloc(1, sizeof(*entry));
			if (!entry) {
				warn("Failed to allocate memory for heap_summary_entry\n");
				break;
			}
			snprintf(entry->name, sizeof(entry->name), "%s", heap_name);
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

static struct rtk_heap_info *parse_procfs_heap_line(char *s, bool is_cma)
{
	char *heap_ptr = strstr(s, "Heap:");
	if (!heap_ptr || !strstr(s, "size") || !strstr(s, "flag"))
		return NULL;

	char raw_name[HEAP_MAX_NAME] = {0};
	unsigned int size_pages = 0;
	char flag_hex[32] = {0};

	// Parse name
	char *name_start = heap_ptr + 5;
	while (*name_start == ' ' || *name_start == '\t' || *name_start == ':') name_start++;
	char *name_end = name_start;
	while (*name_end && *name_end != ' ' && *name_end != '\t' && *name_end != '[' && *name_end != ':') name_end++;
	int name_len = name_end - name_start;
	snprintf(raw_name, sizeof(raw_name), "%.*s", name_len, name_start);

	if (env.heap_name[0] != '0' && strstr(raw_name, env.heap_name) == NULL)
		return NULL;

	// Parse size
	char *size_ptr = strstr(s, "size = ");
	if (size_ptr) sscanf(size_ptr, "size = %x", &size_pages);

	// Parse flag
	char *flag_ptr = strstr(s, "flag = ");
	if (flag_ptr) {
		sscanf(flag_ptr, "flag = %31s", flag_hex);
		char *comma = strpbrk(flag_hex, ",\n\r ");
		if (comma) *comma = '\0';
	}

	struct rtk_heap_info *heap = calloc(1, sizeof(*heap));
	if (!heap) return NULL;

	snprintf(heap->raw_heap_name, sizeof(heap->raw_heap_name), "%s", raw_name);
	snprintf(heap->heap_name, sizeof(heap->heap_name), "%s", map_heap_name(raw_name));
	if (is_cma) {
		heap->count_cma = size_pages;
	} else {
		heap->count_gen = size_pages;
	}
	snprintf(heap->flag_line, sizeof(heap->flag_line), "flags : %s", flag_hex);
	simple_init_list_head(&heap->task_list);
	return heap;
}

static void parse_procfs_usage_line(struct rtk_heap_info *heap, char *s, bool is_cma)
{
	unsigned int usage_pages = 0, free_pages = 0;
	char *usage_ptr = strstr(s, "Usage:");
	char *free_ptr = strstr(s, "free:");
	if (usage_ptr) sscanf(usage_ptr, "Usage: %x", &usage_pages);
	if (free_ptr) sscanf(free_ptr, "free: %x", &free_pages);

	if (is_cma) {
		heap->used_cma = usage_pages;
		heap->free_cma = free_pages;
	} else {
		heap->used_gen = usage_pages;
		heap->free_gen = free_pages;
	}
}

static void parse_procfs_task_line(struct rtk_heap_info *heap, char *s)
{
	char *alloc_ptr = strstr(s, "alloc");
	char *bytes_ptr = strstr(s, "bytes");
	if (!alloc_ptr || !bytes_ptr)
		return;

	// Find the colon that separates the comm and the allocation info.
	// Task names like 'binder:pid_tid' contain colons, so we look for the last colon before 'alloc'.
	char *colon_ptr = NULL;
	char *p = s;
	while ((p = strchr(p, ':')) != NULL && p < alloc_ptr) {
		colon_ptr = p;
		p++;
	}

	if (!colon_ptr)
		return;

	unsigned int alloc_bytes = 0;
	if (sscanf(alloc_ptr, "alloc %u bytes", &alloc_bytes) != 1)
		return;

	char comm[TASK_COMM_LEN] = {0};
	int len = colon_ptr - s;
	snprintf(comm, sizeof(comm), "%.*s", len, s);

	// Trim comm
	char *c_start = comm;
	while (*c_start == ' ' || *c_start == '\t') c_start++;
	char *c_end = c_start + strlen(c_start) - 1;
	while (c_end > c_start && (*c_end == ' ' || *c_end == '\t' || *c_end == '\n' || *c_end == '\r')) c_end--;
	if (c_end >= c_start) *(c_end + 1) = '\0';
	else if (c_end < c_start) *c_start = '\0';

	struct task_info *task = NULL;
	struct task_info *t_entry;
	simple_list_for_each_entry(t_entry, &heap->task_list, list) {
		if (strcmp(t_entry->comm, c_start) == 0) {
			task = t_entry;
			break;
		}
	}
	if (!task) {
		task = calloc(1, sizeof(*task));
		if (task) {
			snprintf(task->comm, sizeof(task->comm), "%s", c_start);
			simple_list_add_tail(&task->list, &heap->task_list);
		}
	}
	if (task) {
		task->used_pages += alloc_bytes / BYTES_TO_PAGES;
	}
}

static bool parse_procfs_heap_summary(void)
{
	FILE *f = fopen(PROCFS_BASE_PATH, "r");
	if (!f) return false;

	char line[512];
	struct rtk_heap_info *current_heap = NULL;
	bool is_cma = false;

	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;

		if (strstr(s, "CMA heaps info:")) {
			is_cma = true;
			continue;
		}
		if (strstr(s, "GEN heaps info:")) {
			is_cma = false;
			continue;
		}

		struct rtk_heap_info *new_heap = parse_procfs_heap_line(s, is_cma);
		if (new_heap) {
			current_heap = new_heap;
			simple_list_add_tail(&current_heap->list, &rtk_heap_info_list);
			continue;
		}

		if (!current_heap) continue;

		if (strstr(s, "Usage:") && strstr(s, "free:")) {
			parse_procfs_usage_line(current_heap, s, is_cma);
			continue;
		}

		parse_procfs_task_line(current_heap, s);
	}
	fclose(f);
	return !simple_list_empty(&rtk_heap_info_list);
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
	snprintf(heap_info->raw_heap_name, sizeof(heap_info->raw_heap_name), "%s", entry_name);
	snprintf(heap_info->heap_name, sizeof(heap_info->heap_name), "%s", entry_name);
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
				snprintf(heap_info->flag_line, sizeof(heap_info->flag_line), "%s", line);
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
				snprintf(task->comm, sizeof(task->comm), "%s", comm_name);
				task->used_pages = value / BYTES_TO_PAGES;
			simple_list_add_tail(&task->list, &heap_info->task_list);
			}
		}
		fclose(f);
	}

	return true;
}

static struct bpf_map_entry *collect_bpf_map_entries(int map_fd, int *count)
{
	int num_entries = 0;
	struct use_heap key_count, *prev_key_count = NULL;
	while (bpf_map_get_next_key(map_fd, prev_key_count, &key_count) == 0) {
		num_entries++;
		prev_key_count = &key_count;
	}

	if (num_entries == 0) {
		*count = 0;
		return NULL;
	}

	struct bpf_map_entry *map_entries = calloc(num_entries, sizeof(struct bpf_map_entry));
	if (!map_entries) {
		warn("Failed to allocate memory for map_entries\n");
		*count = 0;
		return NULL;
	}

	int i = 0;
	struct use_heap key, *prev_key = NULL;
	while (bpf_map_get_next_key(map_fd, prev_key, &key) == 0) {
		if (i < num_entries && bpf_map_lookup_elem(map_fd, &key, &map_entries[i].value) == 0) {
			map_entries[i].key = key;
			map_entries[i].printed = false;
			i++;
		}
		prev_key = &key;
	}
	*count = i;
	return map_entries;
}

static void print_stat_row(const char *comm, const char *used_pages_str, const char *dev_name, const struct bpf_map_entry *entry, bool rtk_dev_enabled)
{
	char caller_buf[TASK_COMM_LEN];
	const char *label = env.milliseconds ? "ms" : "us";

	if (rtk_dev_enabled) {
		printf("%-16s %-12s %-20s ", comm, used_pages_str, dev_name);
	} else {
		printf("%-16s %-12s ", comm, used_pages_str);
	}

	if (entry) {
		char flag_str[20];
		snprintf(flag_str, sizeof(flag_str), "0x%lx", entry->key.flags);
		printf("%-16s %-10s %12llu %12u %2s %8u %5u\n",
				get_caller_str(&entry->key, caller_buf, sizeof(caller_buf)),
				flag_str, entry->value.size, entry->value.max_alloc_latency,
				label, entry->value.success, entry->value.fail);
	} else {
		printf("\n");
	}
}

static void print_rtk_heap_stats(struct rtk_heap_info *h_info, struct bpf_map_entry *map_entries, int num_map_entries, bool rtk_dev_enabled, bool use_procfs)
{
	char flags_stripped[256];
	snprintf(flags_stripped, sizeof(flags_stripped), "%s", h_info->flag_line);
	char *nl = strpbrk(flags_stripped, "\n\r");
	if (nl) *nl = '\0';

	if (h_info->count_gen == 0) {
		printf("heap_name : %-30s  count_cma : %-8d  used_cma : %-8d  free_cma : %-8d  %s\n",
				h_info->heap_name, h_info->count_cma, h_info->used_cma, h_info->free_cma, flags_stripped);
	} else {
		printf("heap_name : %-30s  count_gen : %-8d  used_gen : %-8d  free_gen : %-8d  %s\n",
				h_info->heap_name, h_info->count_gen, h_info->used_gen, h_info->free_gen, flags_stripped);
	}

	if (simple_list_empty(&h_info->task_list) && (!map_entries || num_map_entries == 0)) {
		printf("\n");
		return;
	}

	if (rtk_dev_enabled) {
		printf("%-16s %-12s %-20s %-16s %-10s %12s %15s %8s %5s\n",
				"COMM", "USED_PAGES", "DEV_NAME", "CALLER", "FLAGS", "ALLOC_PAGES",
				"MAX_ALLOC_LAT", "SUCCESS", "FAIL");
	} else {
		printf("%-16s %-12s %-16s %-10s %12s %15s %8s %5s\n",
				"COMM", "USED_PAGES", "CALLER", "FLAGS", "ALLOC_PAGES",
				"MAX_ALLOC_LAT", "SUCCESS", "FAIL");
	}

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
				char heap_dev_name_stripped[HEAP_MAX_NAME];
				snprintf(heap_dev_name_stripped, sizeof(heap_dev_name_stripped), "%s", map_entries[i].key.name);
				char *uncached = strstr(heap_dev_name_stripped, "_uncached");
				if (uncached) *uncached = '\0';

				bool match = use_procfs && rtk_dev_enabled ?
					is_procfs_heap_in_keys(heap_dev_name_stripped, h_info->raw_heap_name) :
					(strcmp(heap_dev_name_stripped, h_info->raw_heap_name) == 0);

				if (!match || strcmp(map_entries[i].key.comm, t_entry->comm) != 0)
					continue;

				if (env.caller_name[0] != '0' && strstr(map_entries[i].key.caller, env.caller_name) == NULL)
					continue;

				char used_pages_buf[16];
				snprintf(used_pages_buf, sizeof(used_pages_buf), "%d", t_entry->used_pages);
				print_stat_row(task_alloc_printed ? "" : t_entry->comm,
						task_alloc_printed ? "" : used_pages_buf,
						use_procfs && rtk_dev_enabled ? heap_dev_name_stripped : "",
						&map_entries[i], rtk_dev_enabled);

				total_alloc += map_entries[i].value.size;
				task_alloc_printed = true;
				map_entries[i].printed = true;
			}
		}

		if (!task_alloc_printed) {
			char used_pages_buf[16];
			snprintf(used_pages_buf, sizeof(used_pages_buf), "%d", t_entry->used_pages);
			print_stat_row(t_entry->comm, used_pages_buf, "", NULL, rtk_dev_enabled);
		}
	}

	// New Task alloc pages
	if (map_entries) {
		char last_task_name[TASK_COMM_LEN] = "";
		for (int i = 0; i < num_map_entries; i++) {
			if (map_entries[i].printed)
				continue;

			char heap_dev_name_stripped[HEAP_MAX_NAME];
			snprintf(heap_dev_name_stripped, sizeof(heap_dev_name_stripped), "%s", map_entries[i].key.name);
			char *uncached = strstr(heap_dev_name_stripped, "_uncached");
			if (uncached) *uncached = '\0';

			bool match = use_procfs && rtk_dev_enabled ?
				is_procfs_heap_in_keys(heap_dev_name_stripped, h_info->raw_heap_name) :
				(strcmp(heap_dev_name_stripped, h_info->raw_heap_name) == 0);

			if (!match) continue;

			if (env.task_name[0] != '0' && strstr(map_entries[i].key.comm, env.task_name) == NULL)
				continue;
			if (env.caller_name[0] != '0' && strstr(map_entries[i].key.caller, env.caller_name) == NULL)
				continue;

			bool task_in_list = false;
			simple_list_for_each_entry(t_entry, &h_info->task_list, list) {
				if (strcmp(t_entry->comm, map_entries[i].key.comm) == 0) {
					task_in_list = true; break;
				}
			}
			if (task_in_list) continue;

			bool same_task = (strcmp(last_task_name, map_entries[i].key.comm) == 0);
			print_stat_row(same_task ? "" : map_entries[i].key.comm,
					same_task ? "" : "0",
					use_procfs && rtk_dev_enabled ? heap_dev_name_stripped : "",
					&map_entries[i], rtk_dev_enabled);

			total_alloc += map_entries[i].value.size;
			snprintf(last_task_name, sizeof(last_task_name), "%s", map_entries[i].key.comm);
			map_entries[i].printed = true;
		}
	}

	printf("%-16s %-12d", "Total = ", total_used);
	if (rtk_dev_enabled) printf(" %-20s", "");
	if (total_alloc > 0) printf(" %-16s %-10s %12lld", "", "", total_alloc);
	printf("\n\n");
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

	init_kernel_version();

	skel = rtkheaptop_bpf__open();
	if (!skel)
		goto cleanup;

	// Set BPF global variables
	skel->rodata->milliseconds = env.milliseconds;

	if (strcmp(env.heap_name, "0") != 0) {
		snprintf((char *)skel->rodata->heap_name_filter, sizeof(skel->rodata->heap_name_filter), "%s", env.heap_name);
	}
	if (strcmp(env.task_name, "0") != 0) {
		snprintf((char *)skel->rodata->task_name_filter, sizeof(skel->rodata->task_name_filter), "%s", env.task_name);
	}
	if (strcmp(env.caller_name, "0") != 0) {
		snprintf((char *)skel->rodata->caller_name_filter, sizeof(skel->rodata->caller_name_filter), "%s", env.caller_name);
	}

	if (is_use_rtk_heap()) {
		bpf_program__set_autoload(skel->progs.rtk_dyn_protect_cma_do_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_dyn_protect_cma_do_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_stc_cma_do_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_stc_cma_do_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_cma_do_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_cma_do_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_gen_do_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_gen_do_allocate_exit, false);
	} else {
		bpf_program__set_autoload(skel->progs.rtk_dynamic_secure_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_dynamic_secure_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_static_secure_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_static_secure_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_normal_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_normal_allocate_exit, false);
		bpf_program__set_autoload(skel->progs.rtk_pool_allocate_entry, false);
		bpf_program__set_autoload(skel->progs.rtk_pool_allocate_exit, false);
	}

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

	bool rtk_dev_enabled = is_rtk_dev_name();

	while (env.count--) {
		DIR *dir;
		struct dirent *entry;
		struct rtk_heap_info *h_info;

		sleep(env.interval);

		if (!env.noclear)
			printf("\033[2J\033[H");

		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);
			strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
			printf("%-8s\n", ts);
		}

		cleanup_rtk_heap_info_list();

		bool use_procfs = (access(PROCFS_BASE_PATH, F_OK) == 0);
		bool debugfs_path_ok = (access(BASE_PATH, F_OK) == 0);

		if (use_procfs) {
			if (!parse_procfs_heap_summary()) {
				use_procfs = false;
				cleanup_rtk_heap_info_list();
			}
		}

		if (!use_procfs && debugfs_path_ok) {
			if (!is_use_rtk_heap())
				parse_heap_summary();

			dir = opendir(BASE_PATH);
			if (dir) {
				while ((entry = readdir(dir)) != NULL) {
					if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
						dump_rtkheap_info(entry->d_name);
					}
				}
				closedir(dir);
			}
		}

		int num_map_entries = 0;
		struct bpf_map_entry *map_entries = collect_bpf_map_entries(map_fd, &num_map_entries);

		simple_list_for_each_entry(h_info, &rtk_heap_info_list, list) {
			print_rtk_heap_stats(h_info, map_entries, num_map_entries, rtk_dev_enabled, use_procfs);
		}

		if (map_entries) {
			for (int i = 0; i < num_map_entries; i++) {
				bpf_map_delete_elem(map_fd, &map_entries[i].key);
			}
			free(map_entries);
		}

		if (exiting)
			break;
	}

cleanup:
	struct heap_summary_entry *hs_entry, *hs_tmp;
	simple_list_for_each_entry_safe(hs_entry, hs_tmp, &heap_summary_list, list) {
		simple_list_del(&hs_entry->list);
		free(hs_entry);
	}

	cleanup_rtk_heap_info_list();

	rtkheaptop_bpf__destroy(skel);
	return -err;
}
