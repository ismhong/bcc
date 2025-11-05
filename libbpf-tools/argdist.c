// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "argdist.h"
#include "argdist.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, "WARN: " __VA_ARGS__)
#define err(...) fprintf(stderr, "ERR: " __VA_ARGS__)

struct probe_bpf_info {
	char *spec;
	bool is_hist;
	char *func_name;
	char *expr_str;
	__u64 func_ip;
	struct probe_config config;
	struct bpf_link *link;
	struct bpf_link *ret_link;
};

static struct env {
	pid_t pid;
	int interval;
	int count;
	bool verbose;
	bool cumulative;
	bool hex;
	char *info_func_name;
	char **histspecs;
	int hist_count;
	char **countspecs;
	int count_count;
	struct probe_bpf_info *probes[MAX_PROBES];
	int probe_count;
} env = {
	.interval = 1,
};

static struct btf *vmlinux_btf;
static struct ksyms *ksyms;

const char *argp_program_version = "argdist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "";
static const char program_doc[] =
"Trace a function and display a distribution of its parameter values.\n"
"\n"
"USAGE: argdist [-h] [-p PID] [-i INTERVAL] [-n COUNT] [-H SPEC] [-C SPEC] [-I FUNC]\n"
"\n"
"Probe specifier syntax:\n"
"        {p,r}:[library]:function(signature):[type]:expr[:filter]\n"
"Where:\n"
"        p,r        -- probe at function entry, function exit\n"
"                      in exit probes: can use $retval, $latency in filter\n"
"        library    -- the library that contains the function\n"
"                      (leave empty for kernel functions)\n"
"        function   -- the function name to trace\n"
"        signature  -- the function's parameters, as in the C header (for documentation)\n"
"        type       -- the type of the expression to collect (e.g., u64, ssize_t)\n"
"        expr       -- the expression to collect (e.g., argument name, $retval, $PID)\n"
"        filter     -- the filter that is applied to collected values (e.g., size==16, $latency > 100000)\n"
"\n"
"EXAMPLES:\n"
"\n"
"argdist -I __kmalloc\n"
"        Print the prototype of the __kmalloc kernel function and exit.\n"
"\n"
"argdist -H 'p::__kmalloc(u64 size):u64:size'\n"
"        Print a histogram of allocation sizes passed to kmalloc\n"
"\n"
"argdist -C 'p::__kmalloc(size_t size, gfp_t flags):size_t:size:size==16'\n"
"        Print a frequency count of how many times kmalloc was called with size 16\n"
"\n"
"argdist -H 'r::vfs_read():ssize_t:$retval'\n"
"        Print a histogram of return values from vfs_read()\n"
"\n"
"argdist -C 'r::vfs_read():u32:$PID:$latency > 100000'\n"
"        Print frequency of PIDs that called vfs_read() with latency > 100us\n"
"\n"
"argdist -p 123 -C 'p::__kmalloc(u64 size):u64:size'\n"
"        Print frequency count of kmalloc sizes for PID 123 only\n"
;

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "info", 'I', "FUNC", 0, "Print kernel function prototype and exit", 0 },
	{ "interval", 'i', "SECONDS", 0, "Output interval", 0 },
	{ "count", 'n', "COUNT", 0, "Number of outputs", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose BPF logging", 0 },
	{ "cumulative", 'c', NULL, 0, "Do not clear maps at each interval", 0 },
	{ "histogram", 'H', "SPEC", 0, "Histogram probe specifier", 0 },
	{ "count", 'C', "SPEC", 0, "Frequency count probe specifier", 0 },
	{ "hex", 'x', NULL, 0, "Show event data in hexadecimal", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 'I':
		env.info_func_name = strdup(arg);
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'n':
		env.count = strtol(arg, NULL, 10);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		env.cumulative = true;
		break;
	case 'x':
		env.hex = true;
		break;
	case 'H':
		env.histspecs = realloc(env.histspecs, (env.hist_count + 1) * sizeof(*env.histspecs));
		env.histspecs[env.hist_count++] = strdup(arg);
		break;
	case 'C':
		env.countspecs = realloc(env.countspecs, (env.count_count + 1) * sizeof(*env.countspecs));
		env.countspecs[env.count_count++] = strdup(arg);
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

static char *type_id_to_str(struct btf *btf, __s32 type_id, char *str)
{
	const struct btf_type *type;
	const char *name = "";
	char *prefix = "";
	char *suffix = " ";
	char *ptr = "";

	str[0] = '\0';

	switch (type_id) {
	case 0:
		name = "void";
		break;
	default:
		do {
			if (type_id == 0) {
				name = "void";
				break;
			}
			type = btf__type_by_id(btf, type_id);
			if (!type) {
				name = "?";
				break;
			}

			switch (BTF_INFO_KIND(type->info)) {
			case BTF_KIND_CONST:
			case BTF_KIND_VOLATILE:
			case BTF_KIND_RESTRICT:
				type_id = type->type;
				break;
			case BTF_KIND_PTR:
				ptr = "*";
				type_id = type->type;
				break;
			case BTF_KIND_ARRAY:
				suffix = "[]";
				type_id = type->type;
				break;
			case BTF_KIND_STRUCT:
				prefix = "struct ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_UNION:
				prefix = "union ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_ENUM:
				prefix = "enum ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_TYPEDEF:
			default:
				name = btf__str_by_offset(btf, type->name_off);
				break;
			}
		} while (type_id >= 0 && strlen(name) == 0);
		break;
	}
	snprintf(str, 64, "%s%s%s%s", prefix, name, suffix, ptr);

	return str;
}

static int print_func_proto(const char *func_name)
{
	char str[64];
	const struct btf_type *type;
	const struct btf_param *param;
	__s32 func_id;
	int i;

	func_id = btf__find_by_name_kind(vmlinux_btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0) {
		err("Failed to find function %s in BTF\n", func_name);
		return -1;
	}

	type = btf__type_by_id(vmlinux_btf, func_id);
	type = btf__type_by_id(vmlinux_btf, type->type);

	printf("%s%s(", type_id_to_str(vmlinux_btf, type->type, str), func_name);

	for (i = 0; i < BTF_INFO_VLEN(type->info); i++) {
		param = (const struct btf_param *)(type + 1) + i;
		if (i > 0)
			printf(", ");
		printf("%s%s", type_id_to_str(vmlinux_btf, param->type, str),
				btf__str_by_offset(vmlinux_btf, param->name_off));
	}
	printf(");\n");

	return 0;
}

static int setup_probe(const char *spec, bool is_hist)
{
	char *spec_copy = strdup(spec);
	if (!spec_copy) {
		err("Failed to copy spec string\n");
		return -1;
	}

	if (env.probe_count >= MAX_PROBES) {
		err("Too many probes\n");
		free(spec_copy);
		return -1;
	}

	struct probe_bpf_info *probe = calloc(1, sizeof(*probe));
	if (!probe) {
		err("Failed to allocate probe info\n");
		free(spec_copy);
		return -1;
	}

	probe->spec = strdup(spec);
	probe->is_hist = is_hist;

	char *s = spec_copy;
	char *token;

	// Part 1: probe type
	token = strsep(&s, ":");
	if (!token || (strlen(token) != 1 && token[0] != 'p' && token[0] != 'r')) {
		err("Invalid probe type: %s\n", token);
		goto fail;
	}
	char probe_type = token[0];

	// Part 2: library (ignored for now, only kernel funcs supported)
	token = strsep(&s, ":");

	// Part 3: function
	token = strsep(&s, ":");
	if (!token) {
		err("Function not specified\n");
		goto fail;
	}
	char *func_name = strdup(token);
	char *paren = strchr(func_name, '(');
	if (paren) *paren = '\0';
	probe->func_name = func_name;

	const struct ksym *ksym = ksyms__get_symbol(ksyms, func_name);
	if (!ksym) {
		err("Failed to find function %s\n", func_name);
		goto fail;
	}
	probe->func_ip = ksym->addr;

	__s32 func_id = btf__find_by_name_kind(vmlinux_btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0) {
		err("Failed to find BTF for function %s\n", func_name);
		goto fail;
	}
	const struct btf_type *func_proto = btf__type_by_id(vmlinux_btf, btf__type_by_id(vmlinux_btf, func_id)->type);

	// Part 4 & 5: type and expression
	char *part4 = strsep(&s, ":");
	char *part5 = strsep(&s, ":");
	char *part6 = strsep(&s, ":");

	char *expr_str = NULL;
	char *filter_str = NULL;

	if (part6) { // Full format: ...:type:expr:filter
		expr_str = part5;
		filter_str = part6;
	} else if (part5) { // ...:type:expr
		expr_str = part5;
		filter_str = NULL;
	} else if (part4) { // ...:expr
		expr_str = part4;
		filter_str = NULL;
	} else {
		if (is_hist) {
			if (probe_type == 'r') {
				expr_str = "$retval";
			} else {
				err("Expression not specified for histogram\n");
				goto fail;
			}
		} else {
			expr_str = "1";
		}
	}

	if (!expr_str) {
		err("Expression not specified\n");
		goto fail;
	}

	probe->expr_str = strdup(expr_str);
	probe->config.id = env.probe_count;
	probe->config.is_hist = is_hist;
	probe->config.is_kretprobe = (probe_type == 'r');
	probe->config.expr_count = 1;

	struct expr *expr = &probe->config.exprs[0];

	if (strcmp(expr_str, "$PID") == 0) {
		expr->source = ARG_PID;
	} else if (strcmp(expr_str, "$retval") == 0) {
		if (probe_type != 'r') {
			err("$retval only valid for return probes\n");
			goto fail;
		}
		expr->source = ARG_RET;
	} else if (strcmp(expr_str, "1") == 0) {
		expr->source = ARG_CONST_1;
	} else {
		const struct btf_param *params = (const struct btf_param *)(func_proto + 1);
		int arg_idx = -1;
		for (int i = 0; i < BTF_INFO_VLEN(func_proto->info); i++) {
			const char *arg_name = btf__str_by_offset(vmlinux_btf, params[i].name_off);
			if (strcmp(arg_name, expr_str) == 0) {
				arg_idx = i;
				break;
			}
		}
		if (arg_idx == -1) {
			err("Argument %s not found in function %s\n", expr_str, func_name);
			goto fail;
		}
		expr->source = arg_idx + 1;
	}

	if (filter_str) {
		char *op_ptr = strpbrk(filter_str, "=!<>");
		if (op_ptr) {
			char var_buf[32] = {0};
			strncpy(var_buf, filter_str, op_ptr - filter_str);

			if (strstr(var_buf, "$latency")) {
				probe->config.filter.source = ARG_LATENCY;
			} else {
				probe->config.filter.source = probe->config.exprs[0].source;
			}

			char op[3] = {0};
			size_t op_len = 1;
			if (op_ptr[1] == '=')
				op_len = 2;
			strncpy(op, op_ptr, op_len);

			__u64 value = strtoull(op_ptr + op_len, NULL, 0);
			probe->config.filter.val = value;

			if (strcmp(op, "==") == 0) probe->config.filter.op = PRED_EQ;
			else if (strcmp(op, "!=") == 0) probe->config.filter.op = PRED_NEQ;
			else if (strcmp(op, ">") == 0) probe->config.filter.op = PRED_GT;
			else if (strcmp(op, "<") == 0) probe->config.filter.op = PRED_LT;
			else if (strcmp(op, ">=") == 0) probe->config.filter.op = PRED_GE;
			else if (strcmp(op, "<=") == 0) probe->config.filter.op = PRED_LE;
		}
	}

	env.probes[env.probe_count++] = probe;
	free(spec_copy);
	return 0;

fail:
	free(spec_copy);
	free(probe);
	return -1;
}

struct freq_count {
	__u64 value;
	__u64 count;
};

static int compare_freq_counts(const void *a, const void *b) {
	const struct freq_count *fa = a;
	const struct freq_count *fb = b;
	return fa->count - fb->count;
}

static void print_maps(struct argdist_bpf *skel)
{
	for (int i = 0; i < env.probe_count; i++) {
		struct probe_bpf_info *p = env.probes[i];
		printf("Probe: %s\n", p->spec);

		if (p->config.is_hist) {
			unsigned int vals[MAX_SLOTS] = {};
			struct hist_key key = {};
			key.probe_id = p->config.id;

			for (__u32 slot = 0; slot < MAX_SLOTS; slot++) {
				key.slot = slot;
				__u64 count;
				if (bpf_map__lookup_elem(skel->maps.hist_map, &key, sizeof(key), &count, sizeof(count), 0) == 0) {
					vals[slot] = count;
				}
			}
			print_log2_hist(vals, MAX_SLOTS, p->func_name);

			if (!env.cumulative) {
				for (__u32 slot = 0; slot < MAX_SLOTS; slot++) {
					key.slot = slot;
					__u64 zero = 0;
					bpf_map__update_elem(skel->maps.hist_map, &key, sizeof(key), &zero, sizeof(zero), 0);
				}
			}
		} else { // Frequency count
			struct freq_key key = {}, *prev_key = NULL;
			struct freq_count *counts = NULL;
			size_t counts_cap = 0;
			size_t counts_len = 0;

			while (bpf_map__get_next_key(skel->maps.freq_map, prev_key, &key, sizeof(key)) == 0) {
				if (key.probe_id == p->config.id) {
					__u64 count;
					if (bpf_map__lookup_elem(skel->maps.freq_map, &key, sizeof(key), &count, sizeof(count), 0) == 0) {
						if (counts_len >= counts_cap) {
							counts_cap = counts_cap == 0 ? 64 : counts_cap * 2;
							struct freq_count *new_counts = realloc(counts, counts_cap * sizeof(*counts));
							if (!new_counts) {
								err("Failed to allocate memory for freq counts\n");
								free(counts);
								return;
							}
							counts = new_counts;
						}
						counts[counts_len].value = key.value;
						counts[counts_len].count = count;
						counts_len++;
					}
				}
				prev_key = &key;
			}

			qsort(counts, counts_len, sizeof(*counts), compare_freq_counts);

			printf("\t%-10s %s\n", "COUNT", "EVENT");
			for (size_t j = 0; j < counts_len; j++) {
				const char *event_prefix;
				bool is_total_calls = false;
				if (strcmp(p->expr_str, "1") == 0) {
					event_prefix = "total calls";
					is_total_calls = true;
				} else {
					event_prefix = p->expr_str;
				}

				if (is_total_calls) {
					printf("\t%-10llu %s\n",
							(unsigned long long)counts[j].count,
							event_prefix);
				} else if (env.hex) {
					printf("\t%-10llu %s = %#llx\n",
							(unsigned long long)counts[j].count,
							event_prefix,
							(unsigned long long)counts[j].value);
				} else if ((long long)counts[j].value < 0) {
					printf("\t%-10llu %s = %lld (%llu)\n",
							(unsigned long long)counts[j].count,
							event_prefix,
							(long long)counts[j].value,
							(unsigned long long)counts[j].value);
				} else {
					printf("\t%-10llu %s = %llu\n",
							(unsigned long long)counts[j].count,
							event_prefix,
							(unsigned long long)counts[j].value);
				}
			}
			free(counts);

			if (!env.cumulative) {
				prev_key = NULL;
				while (bpf_map__get_next_key(skel->maps.freq_map, prev_key, &key, sizeof(key)) == 0) {
					if (key.probe_id == p->config.id) {
						bpf_map__delete_elem(skel->maps.freq_map, &key, sizeof(key), 0);
					}
					prev_key = &key;
				}
			}
		}
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct argdist_bpf *skel;
	int err = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	ksyms = ksyms__load();
	if (!ksyms) {
		err("Failed to load kallsyms\n");
		return 1;
	}
	vmlinux_btf = btf__load_vmlinux_btf();
	if (!vmlinux_btf) {
		err("Failed to load vmlinux BTF\n");
		ksyms__free(ksyms);
		return 1;
	}

	if (env.info_func_name) {
		err = print_func_proto(env.info_func_name);
		goto cleanup_btf;
	}

	if (env.hist_count == 0 && env.count_count == 0) {
		err("at least one specifier is required\n");
		goto cleanup_btf;
	}

	for (int i = 0; i < env.hist_count; i++) {
		if (setup_probe(env.histspecs[i], true) != 0) goto cleanup_btf;
	}
	for (int i = 0; i < env.count_count; i++) {
		if (setup_probe(env.countspecs[i], false) != 0) goto cleanup_btf;
	}

	skel = argdist_bpf__open();
	if (!skel) {
		err("Failed to open BPF skeleton\n");
		goto cleanup_btf;
	}

	if (env.pid != 0)
		skel->rodata->target_pid = env.pid;

	err = argdist_bpf__load(skel);
	if (err) {
		err("Failed to load BPF skeleton\n");
		goto cleanup;
	}

	for (int i = 0; i < env.probe_count; i++) {
		struct probe_bpf_info *probe = env.probes[i];
		err = bpf_map__update_elem(skel->maps.probes_config,
				&probe->func_ip, sizeof(probe->func_ip),
				&probe->config, sizeof(probe->config), BPF_ANY);
		if (err < 0) {
			err("Failed to update probes_config map: %s\n", strerror(-err));
			goto cleanup;
		}

		if (probe->config.is_kretprobe) {
			probe->link = bpf_program__attach_kprobe(skel->progs.dummy_kprobe, false, probe->func_name);
			if (!probe->link) {
				err = -errno;
				err("Failed to attach entry kprobe for %s: %s\n", probe->func_name, strerror(-err));
				goto cleanup;
			}
			probe->ret_link = bpf_program__attach_kprobe(skel->progs.dummy_kretprobe, true, probe->func_name);
			if (!probe->ret_link) {
				err = -errno;
				err("Failed to attach kretprobe for %s: %s\n", probe->func_name, strerror(-err));
				goto cleanup;
			}
		} else {
			probe->link = bpf_program__attach_kprobe(skel->progs.dummy_kprobe, false, probe->func_name);
			if (!probe->link) {
				err = -errno;
				err("Failed to attach kprobe for %s: %s\n", probe->func_name, strerror(-err));
				goto cleanup;
			}
		}
	}

	if (signal(SIGINT, sig_hand) == SIG_ERR) {
		err("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Tracing... Hit Ctrl-C to end.\n");

	while (!exiting) {
		sleep(env.interval);
		char ts[32];
		str_timestamp("%H:%M:%S", ts, sizeof(ts));
		printf("[%s]\n", ts);
		print_maps(skel);
	}

cleanup:
	for (int i = 0; i < env.probe_count; i++) {
		bpf_link__destroy(env.probes[i]->link);
		bpf_link__destroy(env.probes[i]->ret_link);
	}
	argdist_bpf__destroy(skel);
cleanup_btf:
	ksyms__free(ksyms);
	btf__free(vmlinux_btf);
	return -err;
}
