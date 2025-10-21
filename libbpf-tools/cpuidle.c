#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <glob.h>
#include <stddef.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpuidle.h"
#include "cpuidle.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"
#include <ctype.h>

static char *lcs(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return strdup("");
	int s1_len = strlen(s1);
	int s2_len = strlen(s2);
	if (s1_len == 0 || s2_len == 0)
		return strdup("");

	int max_len = 0;
	int end_pos_s1 = 0;
	int *curr = (int *)calloc(s2_len + 1, sizeof(int));
	int *prev = (int *)calloc(s2_len + 1, sizeof(int));

	if (!curr || !prev) {
		free(curr);
		free(prev);
		return strdup("");
	}

	for (int i = 0; i < s1_len; i++) {
		for (int j = 0; j < s2_len; j++) {
			if (s1[i] == s2[j]) {
				curr[j + 1] = prev[j] + 1;
				if (curr[j + 1] > max_len) {
					max_len = curr[j + 1];
					end_pos_s1 = i;
				}
			} else {
				curr[j + 1] = 0;
			}
		}
		int *temp = curr;
		curr = prev;
		prev = temp;
	}

	free(curr);
	free(prev);

	if (max_len == 0)
		return strdup("");

	char *result = (char *)malloc(max_len + 1);
	if (!result)
		return strdup("");

	strncpy(result, s1 + end_pos_s1 - max_len + 1, max_len);
	result[max_len] = '\0';
	return result;
}

/*
 * get_idle_state_names - Get idle state names.
 *
 * This function determines the names for CPU idle states to be used as labels
 * in the output table. For each state index, it does the following:
 * 1. Reads the idle state name from each CPU.
 * 2. Finds the longest common substring among all CPU's names for that state.
 *    This is to find a representative name, as names can differ across CPUs
 *    (e.g., "WFI" vs "CPU-WFI").
 * 3. Cleans up the resulting name by:
 *    - Trimming leading/trailing non-alphabetic characters.
 *    - Converting to uppercase.
 * 4. Ensures name uniqueness by appending a numerical suffix ("-0", "-1", etc.)
 *    if a name is duplicated.
 *
 * The final names are stored in the `state_names` array.
 */
static void get_idle_state_names(char state_names[MAX_IDLE_STATE_NR][32],
				   int state_num, int cpu_num)
{
	memset(state_names, 0, sizeof(char) * MAX_IDLE_STATE_NR * 32);

	for (int i = 0; i < state_num; i++) {
		char path[128];
		char *sub = NULL;

		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu0/cpuidle/state%d/name", i);
		FILE *f = fopen(path, "r");

		if (f) {
			char name[128];

			if (fscanf(f, "%127s", name) == 1)
				sub = strdup(name);
			fclose(f);
		}

		if (!sub) {
			snprintf(state_names[i], 32, "STATE%d", i);
			continue;
		}

		for (int j = 1; j < cpu_num; j++) {
			snprintf(
				path, sizeof(path),
				"/sys/devices/system/cpu/cpu%d/cpuidle/state%d/name", j,
				i);
			f = fopen(path, "r");
			if (f) {
				char name_j[128];

				if (fscanf(f, "%127s", name_j) == 1) {
					char *new_sub = lcs(sub, name_j);

					free(sub);
					sub = new_sub;
				}
				fclose(f);
			}
		}

		char *start = sub;

		while (*start && !isalpha((unsigned char)*start))
			start++;

		if (strlen(start) > 0) {
			char *end = start + strlen(start) - 1;

			while (end > start && !isalpha((unsigned char)*end))
				*end-- = '\0';
		}

		for (char *p = start; *p; p++)
			*p = toupper((unsigned char)*p);

		char temp_name[32];

		snprintf(temp_name, sizeof(temp_name), "%s", start);

		int repeat_idx = 0;
		bool is_dup;

		do {
			is_dup = false;
			for (int k = 0; k < i; k++) {
				if (strcmp(state_names[k], temp_name) == 0) {
					is_dup = true;
					snprintf(temp_name, sizeof(temp_name),
						 "%s-%d", start, repeat_idx++);
					break;
				}
			}
		} while (is_dup);
		strncpy(state_names[i], temp_name, 32);
		state_names[i][31] = '\0';

		free(sub);
	}
}


#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "cpuidle 0.1";
const char *argp_program_bug_address = "<https://github.com/iovisor/bcc/tree/master/libbpf-tools>";
static const char argp_doc[] =
"Analyze cpuidle states.\n"
"\n"
"USAGE: cpuidle [-h] [-i INTERVAL] [-d DURATION] [-T] [-D] [-L LEAST] [-H] [-C] [-c CORE] [-s STATE] [-u] [-m] \n"
"\n"
"EXAMPLES:\n"
"    ./cpuidle -mTd 10       # Show the cpuidle table within 10 second duration\n"
"    ./cpuidle -uHd 120 -s 8 -c 32 # Show the cpuidle histogram for state 3 and core 5 for 120 seconds\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "INTERVAL", 0, "summary interval, in seconds", 0 },
    { "duration", 'd', "DURATION", 0, "total duration of trace, in seconds", 0 },
    { "table", 'T', 0, 0, "show cpuidle table", 0 },
    { "dump_overlap", 'D', 0, 0, "dump overlap summary in ftrace", 0 },
    { "least", 'L', "LEAST", 0, "compute the overlapping duration over the least state", 0 },
    { "histogram", 'H', 0, 0, "Show histogram", 0 },
    { "clear", 'C', 0, 0, "clear the screen", 0 },
    { "core", 'c', "CORE", 0, "Mask of the core contained in the histogram", 0 },
    { "state", 's', "STATE", 0, "Mask of the state contained in the histogram", 0 },
    { "microseconds", 'u', 0, 0, "use microsecond as time unit", 0 },
    { "milliseconds", 'm', 0, 0, "use millisecond as time unit", 0 },
    { "verbose", 'v', 0, 0, "Verbose debug output", 0 },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *end;
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interval = strtof(arg, NULL);
		break;
	case 'd':
		env.duration = strtof(arg, NULL);
		break;
	case 'T':
		env.table = true;
		break;
	case 'D':
		env.dump_overlap = true;
		break;
	case 'L':
		env.least = strtol(arg, NULL, 10);
		break;
	case 'H':
		env.histogram = true;
		break;
	case 'C':
		env.clear = true;
		break;
	case 'c':
		env.core_mask = strtoul(arg, &end, 10);
		break;
	case 's':
		env.state_mask = strtoul(arg, &end, 10);
		break;
	case 'u':
		env.microseconds = true;
		break;
	case 'm':
		env.milliseconds = true;
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

static int get_max_idle_state_num(int cpus)
{
	int i, max_state = 0;

	for (i = 0; i < cpus; i++) {
		char path[128];
		glob_t glob_result;
		sprintf(path, "/sys/devices/system/cpu/cpu%d/cpuidle/state*", i);
		if (glob(path, 0, NULL, &glob_result) == 0) {
			if (glob_result.gl_pathc > max_state)
				max_state = glob_result.gl_pathc;
			globfree(&glob_result);
		}
	}
	return max_state;
}

static int check_driver(void)
{
	FILE *f = fopen("/sys/devices/system/cpu/cpuidle/current_driver", "r");
	if (!f) {
		warn("Failed to open /sys/devices/system/cpu/cpuidle/current_driver\n");
		return -1;
	}
	char drv_name[128];
	if (fscanf(f, "%s", drv_name) != 1) {
		warn("Failed to read driver name\n");
		fclose(f);
		return -1;
	}
	fclose(f);
	if (strcmp(drv_name, "psci_idle") != 0) {
		warn("The cpuidle driver is not implemented by psci.\n");
		return -1;
	}
	return 0;
}

enum FMAT {
	LAT,
	ERR,
	CNT,
	AVG,
	PCT,
};

static double val_convert(enum FMAT fmat, __u64 lat, __u64 err, __u64 cnt, bool is_allcpu, int cpu_num, double interval)
{
	double val = 0;
	switch (fmat) {
	case LAT:
		val = lat;
		if (env.milliseconds)
			val /= 1e6;
		else if (env.microseconds)
			val /= 1e3;
		break;
	case ERR:
		val = err;
		break;
	case CNT:
		val = cnt;
		break;
	case AVG:
		val = (cnt - err > 0) ? (double)lat / (cnt - err) : 0;
		if (env.milliseconds)
			val /= 1e6;
		else if (env.microseconds)
			val /= 1e3;
		break;
	case PCT:
		val = (interval > 0) ? (double)lat / interval * 100 : 0;
		if (is_allcpu)
			val /= cpu_num;
		break;
	}
	return val;
}

static void print_idle_table(enum FMAT fmat, int cpu_num, int state_num,
			   const char state_names[MAX_IDLE_STATE_NR][32],
			   struct idle_t percpustate[MAX_IDLE_STATE_NR][MAX_CPU_NR],
			   double interval)
{
	const char *label;
    switch (fmat) {
        case LAT: label = "DURATION"; break;
        case ERR: label = "ERROR"; break;
        case CNT: label = "COUNT"; break;
        case AVG: label = "AVERAGE"; break;
        case PCT: label = "PERCENTAGE"; break;
        default: return;
    }

    printf("%20s", label);
    for (int i = 0; i < cpu_num; i++) {
        char cpu_str[16];
        snprintf(cpu_str, sizeof(cpu_str), "CPU%d", i);
        printf("%15s", cpu_str);
    }
    printf("%15s\n", "TOTAL");

	struct idle_t allcpu[MAX_IDLE_STATE_NR] = {};
	struct idle_t percpu[MAX_CPU_NR] = {};
	struct idle_t allcpustate = {};

	for (int i = 0; i < state_num; i++) {
		for (int j = 0; j < cpu_num; j++) {
			allcpu[i].latency_sum += percpustate[i][j].latency_sum;
			allcpu[i].error_times += percpustate[i][j].error_times;
			allcpu[i].count += percpustate[i][j].count;
		}
	}

	for (int i = 0; i < cpu_num; i++) {
		for (int j = 0; j < state_num; j++) {
			percpu[i].latency_sum += percpustate[j][i].latency_sum;
			percpu[i].error_times += percpustate[j][i].error_times;
			percpu[i].count += percpustate[j][i].count;
		}
	}

	for (int i = 0; i < state_num; i++) {
		allcpustate.latency_sum += allcpu[i].latency_sum;
		allcpustate.error_times += allcpu[i].error_times;
		allcpustate.count += allcpu[i].count;
	}

	for (int i = 0; i < state_num; i++) {
		printf("%20s", state_names[i]);
		for (int j = 0; j < cpu_num; j++) {
			printf("%15.2f", val_convert(fmat, percpustate[i][j].latency_sum, percpustate[i][j].error_times, percpustate[i][j].count, false, cpu_num, interval));
		}
		printf("%15.2f\n", val_convert(fmat, allcpu[i].latency_sum, allcpu[i].error_times, allcpu[i].count, true, cpu_num, interval));
	}

	printf("%20s", "TOTAL");
	for (int i = 0; i < cpu_num; i++) {
		printf("%15.2f", val_convert(fmat, percpu[i].latency_sum, percpu[i].error_times, percpu[i].count, false, cpu_num, interval));
	}
	printf("%15.2f\n\n", val_convert(fmat, allcpustate.latency_sum, allcpustate.error_times, allcpustate.count, true, cpu_num, interval));
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_doc,
	};
	int err;
	struct cpuidle_bpf *skel;
	time_t t;
	struct tm *tm;
	char ts[32];
	double interval_ns = 0;
	struct timespec start_time, end_time;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	if (check_driver() < 0)
		return 1;

	int cpu_num = libbpf_num_possible_cpus();
	if (cpu_num < 0) {
		warn("Failed to get CPU count\n");
		return 1;
	}
	if (cpu_num > MAX_CPU_NR) {
		warn("CPU count %d exceeds max %d\n", cpu_num, MAX_CPU_NR);
		return 1;
	}

	int state_num = get_max_idle_state_num(cpu_num);
	if (state_num <= 0) {
		warn("Cpuidle is not implemented on this platform.\n");
		return 1;
	}
	if (state_num > MAX_IDLE_STATE_NR) {
		warn("Idle state count %d exceeds max %d\n", state_num, MAX_IDLE_STATE_NR);
		return 1;
	}

	char state_names[MAX_IDLE_STATE_NR][32];

	get_idle_state_names(state_names, state_num, cpu_num);

	skel = cpuidle_bpf__open();
	if (!skel)
		return 1;

	skel->rodata->cpu_num = cpu_num;
	skel->rodata->state_num = state_num;
	skel->rodata->least_state = env.least;
	skel->rodata->dump_overlap = env.dump_overlap;
	skel->rodata->histogram = env.histogram;
	if (env.histogram) {
		if (env.core_mask == 0)
			env.core_mask = (1 << cpu_num) - 1;
		if (env.state_mask == 0)
			env.state_mask = (1 << state_num) - 1;
	}
	skel->rodata->core_mask = env.core_mask;
	skel->rodata->state_mask = env.state_mask;
	skel->rodata->milliseconds = env.milliseconds;
	skel->rodata->microseconds = env.microseconds;

	bpf_map__set_max_entries(skel->maps.idlestats, cpu_num * state_num);

	err = cpuidle_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = cpuidle_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (env.duration > 0 && env.interval < 0)
		env.interval = env.duration;
	if (env.interval < 0)
		env.interval = 99999999;

	printf("Tracing CPUidle... Hit Ctrl-C to end.\n");

	struct idle_t prev_percpustate[MAX_IDLE_STATE_NR][MAX_CPU_NR] = {};
	__u64 prev_all_cpu_sleep = 0;
	__u64 prev_latency_sum[2] = {};
	__u64 prev_dist[32] = {};

	clock_gettime(CLOCK_MONOTONIC, &start_time);

	for (int i = 0; ; i++) {
		sleep(env.interval);

		if (env.clear)
			system("clear");

		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("\n%-8s\n", ts);
		printf("*************************\n");

		clock_gettime(CLOCK_MONOTONIC, &end_time);
		interval_ns = (end_time.tv_sec - start_time.tv_sec) * 1e9 + (end_time.tv_nsec - start_time.tv_nsec);
		start_time = end_time;

		struct idle_t percpustate[MAX_IDLE_STATE_NR][MAX_CPU_NR] = {};
		int idlestats_fd = bpf_map__fd(skel->maps.idlestats);
		for (int j = 0; j < state_num; j++) {
			for (int k = 0; k < cpu_num; k++) {
				__u32 key = k * state_num + j;
				struct idle_t current_stat;
				if (bpf_map_lookup_elem(idlestats_fd, &key, &current_stat) == 0) {
					percpustate[j][k].latency_sum = current_stat.latency_sum - prev_percpustate[j][k].latency_sum;
					percpustate[j][k].error_times = current_stat.error_times - prev_percpustate[j][k].error_times;
					percpustate[j][k].count = current_stat.count - prev_percpustate[j][k].count;
					prev_percpustate[j][k] = current_stat;
				}
			}
		}

		if (env.table) {
			print_idle_table(LAT, cpu_num, state_num, state_names, percpustate, interval_ns);
			print_idle_table(ERR, cpu_num, state_num, state_names, percpustate, interval_ns);
			print_idle_table(CNT, cpu_num, state_num, state_names, percpustate, interval_ns);
			print_idle_table(AVG, cpu_num, state_num, state_names, percpustate, interval_ns);
			print_idle_table(PCT, cpu_num, state_num, state_names, percpustate, interval_ns);

			__u64 all_cpu_sleep_duration = 0;
			__u32 key = 0;
			int all_cpu_sleep_fd = bpf_map__fd(skel->maps.all_cpu_sleep);
			if (bpf_map_lookup_elem(all_cpu_sleep_fd, &key, &all_cpu_sleep_duration) == 0) {
				__u64 val = all_cpu_sleep_duration - prev_all_cpu_sleep;
				prev_all_cpu_sleep = all_cpu_sleep_duration;
				const char *unit = "nsecs";
				double dval = val;
				if (env.milliseconds) {
					dval /= 1e6;
					unit = "msecs";
				} else if (env.microseconds) {
					dval /= 1e3;
					unit = "usecs";
				}
				printf("Overlap duration above state %d is %.2f %s.\n\n", env.least, dval, unit);
			}
		}

		if (env.histogram) {
			unsigned int dist[32];
			int dist_fd = bpf_map__fd(skel->maps.dist);
			for (int j = 0; j < 32; j++) {
				__u32 key = j;
				__u64 current_val;
				if (bpf_map_lookup_elem(dist_fd, &key, &current_val) == 0) {
					dist[j] = current_val - prev_dist[j];
					prev_dist[j] = current_val;
				} else {
					dist[j] = 0;
				}
			}
			const char *unit = env.milliseconds ? "msecs" : (env.microseconds ? "usecs" : "nsecs");
			print_log2_hist(dist, 32, unit);

			__u64 latency_sum_val[2] = {};
			int latency_sum_fd = bpf_map__fd(skel->maps.latency_sum);
			for (int j = 0; j < 2; j++) {
				__u32 key = j;
				__u64 current_val;
				if (bpf_map_lookup_elem(latency_sum_fd, &key, &current_val) == 0) {
					latency_sum_val[j] = current_val - prev_latency_sum[j];
					prev_latency_sum[j] = current_val;
				}
			}
			__u64 total = latency_sum_val[0];
			__u64 count = latency_sum_val[1];
			__u64 avg = (count > 0) ? total / count : 0;
			printf("avg = %llu %s, total: %llu %s, count: %llu\n\n", avg, unit, total, unit, count);
		}

		if (env.duration > 0 && (i + 1) * env.interval >= env.duration)
			break;
	}

cleanup:
	cpuidle_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
