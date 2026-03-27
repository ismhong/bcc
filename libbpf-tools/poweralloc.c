// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * poweralloc  Analyze power allocation as a table.
 *
 * USAGE: poweralloc [-h] [-i INTERVAL] [-d DURATION] [-D] [-P] [-T] [-C]
 *                   [--use-ipa-trace]
 *
 * Copyright (c) 2024 Realtek, Inc.
 * 13-Jun-2024   Hao-Wen Ting    Created this (BCC version).
 * 2025          libbpf port
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "poweralloc.h"
#include "poweralloc.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static struct env {
	float    interval;
	int      duration;
	bool     detail;
	bool     percpu;
	bool     timestamp;
	bool     noclear;
	bool     use_ipa_trace;
	bool     verbose;
} env = {
	.interval = 0,
};

/* Kernel version */
static int k_major = 6, k_minor = 0;

static void init_kernel_version(void)
{
	struct utsname uts;
	if (uname(&uts) == 0)
		sscanf(uts.release, "%d.%d", &k_major, &k_minor);
}

static bool is_k60_plus(void)
{
	return k_major > 6 || (k_major == 6 && k_minor >= 0);
}

/* cdev name resolution for --use-ipa-trace */
#define MAX_CDEV_NAMES 64
static char cdev_names[MAX_CDEV_NAMES][MAX_DEVICE_NAME];
static int  cdev_names_count = 0;

static void resolve_cdev_names(void)
{
	const char *thermal_root = "/sys/class/thermal/";
	DIR *dir;
	struct dirent *ent;

	/* Default fallback */
	for (int i = 0; i < MAX_CDEV_NAMES; i++)
		snprintf(cdev_names[i], MAX_DEVICE_NAME, "Actor_%d", i);
	cdev_names_count = MAX_CDEV_NAMES;

	dir = opendir(thermal_root);
	if (!dir)
		return;

	while ((ent = readdir(dir)) != NULL) {
		char zone_path[512], type_path[520];
		char z_type[64];
		FILE *f;

		if (strncmp(ent->d_name, "thermal_zone", 12) != 0)
			continue;

		snprintf(zone_path, sizeof(zone_path), "%s%s",
			 thermal_root, ent->d_name);
		snprintf(type_path, sizeof(type_path), "%s/type", zone_path);

		f = fopen(type_path, "r");
		if (!f)
			continue;
		if (!fgets(z_type, sizeof(z_type), f)) {
			fclose(f);
			continue;
		}
		fclose(f);
		z_type[strcspn(z_type, "\n")] = '\0';

		if (strcmp(z_type, "cpu-thermal") != 0)
			continue;

		/* Found cpu-thermal zone, enumerate cdevX entries */
		DIR *zdir = opendir(zone_path);
		if (!zdir)
			break;

		struct dirent *ze;
		while ((ze = readdir(zdir)) != NULL) {
			char *p;
			int idx;
			char cdev_type_path[540], cname[MAX_DEVICE_NAME];

			if (strncmp(ze->d_name, "cdev", 4) != 0)
				continue;
			p = ze->d_name + 4;
			if (!*p || !isdigit((unsigned char)*p))
				continue;
			idx = atoi(p);
			if (idx < 0 || idx >= MAX_CDEV_NAMES)
				continue;

			snprintf(cdev_type_path, sizeof(cdev_type_path),
				 "%s/%s/type", zone_path, ze->d_name);
			f = fopen(cdev_type_path, "r");
			if (!f)
				continue;
			if (fgets(cname, sizeof(cname), f)) {
				cname[strcspn(cname, "\n")] = '\0';
				snprintf(cdev_names[idx], MAX_DEVICE_NAME,
					 "%s", cname);
			}
			fclose(f);
		}
		closedir(zdir);
		break;
	}
	closedir(dir);
}

/* ------------------------------------------------------------------ */
/* Name normalization (mirrors Python tool logic)                      */
/* ------------------------------------------------------------------ */
static void normalize_name(const char *in, char *out, size_t outsz)
{
	char tmp[MAX_DEVICE_NAME];
	char upper[MAX_DEVICE_NAME];

	strncpy(tmp, in, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	/* Upper-case */
	for (int i = 0; tmp[i]; i++)
		upper[i] = toupper((unsigned char)tmp[i]);
	upper[strlen(tmp)] = '\0';

	/* Strip DEVFREQ- / CPUFREQ- prefix */
	char *s = upper;
	if (strncmp(s, "DEVFREQ-", 8) == 0)
		s += 8;
	else if (strncmp(s, "CPUFREQ-", 8) == 0)
		s += 8;

	/* Remove purely-digit dot-separated parts */
	if (strchr(s, '.')) {
		char work[MAX_DEVICE_NAME];
		char result[MAX_DEVICE_NAME] = "";
		snprintf(work, sizeof(work), "%s", s);
		char *tok = strtok(work, ".");
		while (tok) {
			/* Check if purely digits */
			bool all_digit = true;
			for (int i = 0; tok[i]; i++) {
				if (!isdigit((unsigned char)tok[i])) {
					all_digit = false;
					break;
				}
			}
			if (!all_digit) {
				if (result[0])
					strncat(result, ".", sizeof(result) - strlen(result) - 1);
				strncat(result, tok, sizeof(result) - strlen(result) - 1);
			}
			tok = strtok(NULL, ".");
		}
		if (result[0])
			s = result;
		snprintf(out, outsz, "%s", s);
		return;
	}

	snprintf(out, outsz, "%s", s);
}

/* ------------------------------------------------------------------ */
/* argp                                                                */
/* ------------------------------------------------------------------ */
const char *argp_program_version = "poweralloc 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"Analyze power allocation as a table.\n"
	"\n"
	"EXAMPLES:\n"
	"    poweralloc           # trace IPA\n"
	"    poweralloc -d 10     # set duration to 10 seconds\n"
	"    poweralloc -i 2      # 2 second summaries\n"
	"    poweralloc -PDi 2    # show details and percpu load (Kernel < 6.0)\n"
	"    poweralloc -C        # don't clear the screen\n"
	"    poweralloc --use-ipa-trace  # use thermal_power_actor (K 6.8+)\n";

static const struct argp_option opts[] = {
	{ "interval",      'i', "INTERVAL", 0, "Summary interval in seconds", 0 },
	{ "duration",      'd', "DURATION", 0, "Total duration in seconds", 0 },
	{ "detail",        'D', NULL,       0, "Show detail of each cdev", 0 },
	{ "percpu",        'P', NULL,       0, "Show percpu load (Kernel < 6.0)", 0 },
	{ "timestamp",     'T', NULL,       0, "Include timestamp on output", 0 },
	{ "noclear",       'C', NULL,       0, "Don't clear the screen", 0 },
	{ "use-ipa-trace", 'I', NULL,       0, "Use thermal_power_actor (K 6.8+)", 0 },
	{ "verbose",       'v', NULL,       0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i':
		env.interval = atof(arg);
		break;
	case 'd':
		env.duration = atoi(arg);
		break;
	case 'D':
		env.detail = true;
		break;
	case 'P':
		env.percpu = true;
		env.detail = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'C':
		env.noclear = true;
		break;
	case 'I':
		env.use_ipa_trace = true;
		break;
	case 'v':
		env.verbose = true;
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
	exiting = 1;
}

/* ------------------------------------------------------------------ */
/* Sorting helpers                                                     */
/* ------------------------------------------------------------------ */
struct entry {
	struct device_key key;
	struct value_t    val;
};

static int entry_cmp(const void *a, const void *b)
{
	const struct entry *ea = a, *eb = b;
	const char *na = ea->key.name, *nb = eb->key.name;
	int ra, rb;

	/* TOTAL first */
	int ta = strcmp(na, "TOTAL") == 0 ? 0 : 1;
	int tb = strcmp(nb, "TOTAL") == 0 ? 0 : 1;
	if (ta != tb)
		return ta - tb;

	/* cpu/actor second, others third */
	ra = (strncmp(na, "cpu", 3) == 0 || strncmp(na, "actor", 5) == 0) ? 1 : 2;
	rb = (strncmp(nb, "cpu", 3) == 0 || strncmp(nb, "actor", 5) == 0) ? 1 : 2;
	if (ra != rb)
		return ra - rb;

	/* Within cpu/actor: aggregate ("cpu") before indexed ("cpu0", "cpu1"...) */
	if (ra == 1) {
		int pa = strncmp(na, "cpu", 3) == 0 ? 3 : 5;
		int pb = strncmp(nb, "cpu", 3) == 0 ? 3 : 5;
		/* no digit suffix = aggregate, sorts before any indexed entry */
		bool ia_idx = isdigit((unsigned char)na[pa]);
		bool ib_idx = isdigit((unsigned char)nb[pb]);
		if (ia_idx != ib_idx)
			return ia_idx - ib_idx;  /* aggregate (false=0) first */
		return atoi(na + pa) - atoi(nb + pb);
	}

	return strcmp(na, nb);
}

/* ------------------------------------------------------------------ */
/* Print one interval                                                  */
/* ------------------------------------------------------------------ */
/* Returns 0 if table was printed, 1 if skipped (not active) */
static int print_table(int pb_fd, int temp_fd)
{
	struct device_key key = {}, next_key = {};
	struct value_t val;
	struct thermal_t tval;
	__u32 zero = 0;
	double cur_temp = 0.0;
	__u64 total_granted = 0;

	/* Check thermal framework active (temps map has data) */
	if (bpf_map_lookup_elem(temp_fd, &zero, &tval) != 0 || tval.count == 0) {
		printf("Interval too short or thermal framework disabled...\n");
		return 1;
	}
	cur_temp = (double)tval.acc / tval.count;

	/* Check power allocator active (power_budget map has entries) */
	if (bpf_map_get_next_key(pb_fd, NULL, &next_key) != 0) {
		printf("Power allocator is not active...\n");
		return 1;
	}

	/* Collect all entries */
	static struct entry entries[MAX_DEVICES];
	int n = 0;

	memset(&key, 0, sizeof(key));
	while (bpf_map_get_next_key(pb_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(pb_fd, &next_key, &val) == 0 &&
		    n < MAX_DEVICES) {
			entries[n].key = next_key;
			entries[n].val = val;
			n++;
		}
		key = next_key;
	}

	/* Find TOTAL granted for percent calculation */
	for (int i = 0; i < n; i++) {
		if (strcmp(entries[i].key.name, "TOTAL") == 0) {
			__u64 cnt = entries[i].val.count;
			total_granted = cnt ? entries[i].val.granted : 0;
			break;
		}
	}

	/* Sort */
	qsort(entries, n, sizeof(entries[0]), entry_cmp);

	/* Print */
	if (env.timestamp) {
		char ts[16];
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s\n", ts);
	}

	printf("Temp: %8.2f\n", cur_temp);
	printf("Power Budget Allocation:\n");

	if (env.detail)
		printf("%10s%10s%10s%10s%10s%10s%10s\n",
		       "Device", "Request", "Freq", "Load",
		       "Granted", "Percent", "State");
	else
		printf("%10s%10s%10s%10s\n",
		       "Device", "Request", "Granted", "Percent");

	for (int i = 0; i < n; i++) {
		struct entry *e = &entries[i];
		const char *raw_name = e->key.name;
		char disp_name[MAX_DEVICE_NAME];
		__u64 cnt = e->val.count;
		double req, granted, percent, freq, load, state;

		req     = cnt ? (double)e->val.req     / cnt : 0.0;
		granted = cnt ? (double)e->val.granted / cnt : 0.0;
		freq    = cnt ? (double)e->val.freq    / cnt : 0.0;
		load    = cnt ? (double)e->val.load    / cnt : 0.0;
		state   = cnt ? (double)e->val.state   / cnt : 0.0;

		if (total_granted > 0)
			percent = (double)e->val.granted * 100.0 / total_granted;
		else
			percent = 0.0;

		/* Resolve display name */
		if (strcmp(raw_name, "TOTAL") == 0) {
			strncpy(disp_name, "TOTAL", sizeof(disp_name));
		} else if (env.use_ipa_trace &&
			   strncmp(raw_name, "actor", 5) == 0) {
			int id = atoi(raw_name + 5);
			if (id >= 0 && id < MAX_CDEV_NAMES)
				normalize_name(cdev_names[id], disp_name,
					       sizeof(disp_name));
			else
				normalize_name(raw_name, disp_name,
					       sizeof(disp_name));
		} else {
			normalize_name(raw_name, disp_name, sizeof(disp_name));
		}

		if (strcmp(raw_name, "TOTAL") == 0) {
			if (env.detail)
				printf("%10s%10.2f%10s%10s%10.2f%10.2f%10s\n",
				       disp_name, req, "", "", granted,
				       percent, "");
			else
				printf("%10s%10.2f%10.2f%10.2f\n",
				       disp_name, req, granted, percent);
		} else if (env.percpu &&
			   strncmp(raw_name, "cpu", 3) == 0 &&
			   isdigit((unsigned char)raw_name[3])) {
			/* Per-CPU load line (K<6.0 only) */
			printf("%10s%10s%10s%10.2f%10s%10s%10s\n",
			       disp_name, "", "", load, "", "", "");
		} else {
			if (env.detail)
				printf("%10s%10.2f%10.2f%10.2f%10.2f%10.2f%10.2f\n",
				       disp_name, req, freq, load, granted,
				       percent, state);
			else
				printf("%10s%10.2f%10.2f%10.2f\n",
				       disp_name, req, granted, percent);
		}
	}

	/* Clear maps for next interval */
	memset(&key, 0, sizeof(key));
	while (bpf_map_get_next_key(pb_fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(pb_fd, &next_key);
		key = next_key;
	}
	/* Reset temp */
	struct thermal_t zero_t = {};
	bpf_map_update_elem(temp_fd, &zero, &zero_t, BPF_ANY);
	return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser  = parse_arg,
		.doc     = argp_program_doc,
	};
	struct poweralloc_bpf *skel;
	int err;
	int seconds = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	init_kernel_version();

	/* Validate flags */
	if (env.percpu && is_k60_plus()) {
		warn("Warning: -P (percpu) not supported on Kernel 6.0+, ignoring.\n");
		env.percpu = false;
	}
	if (env.use_ipa_trace &&
	    !(k_major > 6 || (k_major == 6 && k_minor >= 8))) {
		warn("Warning: --use-ipa-trace requires Kernel 6.8+, falling back.\n");
		env.use_ipa_trace = false;
	}

	/* Resolve interval */
	if (env.duration && env.interval == 0) {
		env.interval = env.duration;
		env.noclear = true;
	} else if (env.interval == 0) {
		env.interval = 99999999;
	}

	if (env.use_ipa_trace)
		resolve_cdev_names();

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	skel = poweralloc_bpf__open_opts(&open_opts);
	if (!skel) {
		warn("failed to open BPF skeleton\n");
		return 1;
	}

	/* Pass config to BPF */
	int cpu_num = get_nprocs_conf();
	if (cpu_num <= 0 || cpu_num > MAX_CPUS)
		cpu_num = MAX_CPUS;
	skel->rodata->cpu_num        = cpu_num;
	skel->rodata->use_ipa_trace = env.use_ipa_trace;
	skel->rodata->is_k60_plus   = is_k60_plus();
	skel->rodata->detail        = env.detail;
	skel->rodata->percpu        = env.percpu;

	/*
	 * Disable programs that don't apply to this kernel version.
	 * K6.0+: use cpu_get_power_simple + cpu_limit (new)
	 * K<6.0: use cpu_get_power (old) + cpu_limit_old
	 */
	if (is_k60_plus()) {
		bpf_program__set_autoload(
			skel->progs.handle_cpu_get_power, false);
		bpf_program__set_autoload(
			skel->progs.handle_cpu_limit_old, false);
	} else {
		bpf_program__set_autoload(
			skel->progs.handle_cpu_get_power_simple, false);
		bpf_program__set_autoload(
			skel->progs.handle_cpu_limit, false);
	}

	/* Disable thermal_power_actor if not using ipa-trace */
	if (!env.use_ipa_trace)
		bpf_program__set_autoload(
			skel->progs.handle_power_actor, false);

	/* Disable old cpu_get_power if tracepoint doesn't exist */
	if (!is_k60_plus() &&
	    !tracepoint_exists("thermal", "thermal_power_cpu_get_power"))
		bpf_program__set_autoload(
			skel->progs.handle_cpu_get_power, false);

	err = poweralloc_bpf__load(skel);
	if (err) {
		warn("failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = poweralloc_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing Power Budget Allocation... Hit Ctrl-C to end.\n");

	int pb_fd   = bpf_map__fd(skel->maps.power_budget);
	int temp_fd = bpf_map__fd(skel->maps.temps);

	while (!exiting) {
		sleep((unsigned int)env.interval);
		seconds += (int)env.interval;

		if (!env.noclear)
			system("clear");
		else
			printf("\n");

		int rc = print_table(pb_fd, temp_fd);

		if (rc != 0 && (env.duration && seconds >= env.duration))
			break;
		if (rc != 0 && exiting)
			break;

		if (env.duration && seconds >= env.duration)
			break;
	}

	printf("Detaching...\n");

cleanup:
	poweralloc_bpf__destroy(skel);
	cleanup_core_btf(&open_opts);
	return err != 0;
}
