// Based on forksnoop(8) from bcc by msinwu.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "forksnoop.h"
#include "forksnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "argparse.h"

#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	pid_t tid;
	int duration;
	bool timeunit;
	const char *sort_by;
	const char *event;
	const char *mode;
	bool verbose;
} env = {
	.pid = INVALID_PID,
	.tid = INVALID_PID,
	.duration = 0,
	.timeunit = false,
	.sort_by = "all",
	.event = "all",
	.mode = "all",
};

static const char *const usages[] = {
	"forksnoop [-h] [-p PID] [-t TID] [-d DURATION] [-u] [-s SORT] [-e EVENT] [-m MODE]",
	NULL,
};

const char doc[] =
"Trace fork, exec, exit and rename syscalls.\n"
"\nUSAGE: forksnoop [-h] [-p PID] [-t TID] [-d DURATION] [-u] [-s SORT] [-e EVENT] [-m MODE]\n"
"\nEXAMPLES:\n"
"./forksnoop           # trace all process events\n"
"./forksnoop -p 181    # only trace PID 181\n"
"./forksnoop -t 123    # only trace TID 123\n"
"./forksnoop -d 10     # trace for 10 seconds\n"
"./forksnoop -s fork   # sort by fork event count\n"
"./forksnoop -m stat   # only show event statistics\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_INTEGER('p', "pid", &env.pid, "trace this PID only", NULL, 0, 0),
	OPT_INTEGER('t', "tid", &env.tid, "trace this TID only", NULL, 0, 0),
	OPT_INTEGER('d', "duration", &env.duration, "total duration of trace, in seconds", NULL, 0, 0),
	OPT_BOOLEAN('u', "timeunit", &env.timeunit, "set humanable time unit", NULL, 0, 0),
	OPT_STRING('s', "sort", &env.sort_by, "sort by specific field, default all", NULL, 0, 0),
	OPT_STRING('e', "event", &env.event, "trace with this event only, default all", NULL, 0, 0),
	OPT_STRING('m', "mode", &env.mode, "output display mode, default all", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}



static void print_args(const struct event *e)
{
	int i, args_counter = 0;

	for (i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];
		if (c == '\0') {
			args_counter++;
			putchar(' ');
		} else {
			putchar(c);
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char ts[32];

	str_timestamp("%H:%M:%S", ts, sizeof(ts));

	printf("%-10s", ts);

	switch (e->type) {
	case EVENT_FORK:
		printf("%-6s %6d %6d %6d %6s %12s %s\n", "fork", e->ppid, e->pid, e->tid, "parent", "", e->comm);
		printf("%-10s%-6s %6d %6d %6d %6s %12s %s\n", ts, "fork", e->ppid, e->child_pid, e->child_tid, "child", "", e->child_comm);
		break;
	case EVENT_EXIT:
		printf("%-6s %6d %6d %6d %4s%14.3f  %s\n", "exit", e->ppid, e->pid, e->tid, "", e->duration_ns / 1000000.0, e->comm);
		break;
	case EVENT_EXEC:
		printf("%-6s %6d %6d %6d %18s %s (", "exec", e->ppid, e->pid, e->tid, "", e->comm);
		print_args(e);
		printf(")\n");
		break;
	case EVENT_RENAME:
		printf("%-6s %6d %6d %6d %6s %12s %s -> %s\n", "rename", e->ppid, e->pid, e->tid, "", "", e->comm, e->newcomm);
		break;
	}
	return 0;
}


static void exit_handler(int signum)
{
	exiting = 1;
}

struct event_count_user {
	struct task_info key;
	struct event_count value;
};

static int sort_column(const void *p1, const void *p2)
{
	const struct event_count_user *c1 = p1;
	const struct event_count_user *c2 = p2;

	if (strcmp(env.sort_by, "fork") == 0)
		return c2->value.fork - c1->value.fork;
	if (strcmp(env.sort_by, "exec") == 0)
		return c2->value.execute - c1->value.execute;
	if (strcmp(env.sort_by, "exit") == 0)
		return c2->value.exit - c1->value.exit;
	if (strcmp(env.sort_by, "rename") == 0)
		return c2->value.rename - c1->value.rename;
	if (strcmp(env.sort_by, "duration") == 0)
		return c2->value.duration - c1->value.duration;
	return c2->value.total - c1->value.total;
}

static void print_stat(struct forksnoop_bpf *obj)
{
	if (strcmp(env.mode, "snoop") == 0)
		return;

	int map_fd = bpf_map__fd(obj->maps.counts);
	struct task_info key, *prev_key = NULL;
	struct event_count_user *stats;
	int i = 0, err;
	const int max_entries = 10240;

	stats = calloc(max_entries, sizeof(*stats));
	if (!stats) {
		fprintf(stderr, "failed to allocate memory for stats\n");
		return;
	}

	while (bpf_map_get_next_key(map_fd, prev_key, &key) == 0) {
		stats[i].key = key;
		err = bpf_map_lookup_elem(map_fd, &key, &stats[i].value);
		if (err) {
			fprintf(stderr, "failed to lookup elem: %d\n", err);
			goto cleanup;
		}
		prev_key = &key;
		i++;
	}

	qsort(stats, i, sizeof(*stats), sort_column);

	printf("\n");
	printf("%6s %6s %6s %6s %6s %15s %6s %6s %6s %-s\n", "Fork", "Exec",
			"Exit", "Rename", "Total", "Duration(ms)", "PPID", "PID",
			"TID", "Process (exec path & args)");

	for (int j = 0; j < i; j++) {
		printf("%6d %6d %6d %6d %6d %14.3f %6d %6d %6d %-s",
				stats[j].value.fork, stats[j].value.execute, stats[j].value.exit,
				stats[j].value.rename, stats[j].value.total,
				stats[j].value.duration / 1000000.0,
				stats[j].key.ppid, stats[j].key.pid, stats[j].key.tid,
				stats[j].value.comm);
		if (stats[j].value.rename > 0) {
			printf(" -> %s", stats[j].value.newname);
		}
		printf("\n");
	}

cleanup:
	free(stats);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct argparse argparse;
	struct ring_buffer *rb = NULL;
	struct forksnoop_bpf *obj;
	int err;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "Trace fork, exec, exit and rename syscalls.", doc);
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	if (env.pid != INVALID_PID && env.pid <= 0) {
		fprintf(stderr, "Invalid PID: must be a positive integer\n");
		return 1;
	}
	if (env.tid != INVALID_PID && env.tid <= 0) {
		fprintf(stderr, "Invalid TID: must be a positive integer\n");
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = forksnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	if (strcmp(env.mode, "snoop") == 0) {
		obj->rodata->snoop_mode = true;
		obj->rodata->stat_mode = false;
	} else if (strcmp(env.mode, "stat") == 0) {
		obj->rodata->snoop_mode = false;
		obj->rodata->stat_mode = true;
	} else {
		obj->rodata->snoop_mode = true;
		obj->rodata->stat_mode = true;
	}

	if (strcmp(env.event, "fork") == 0)
		obj->rodata->targ_event_type = EVENT_FORK;
	else if (strcmp(env.event, "exec") == 0)
		obj->rodata->targ_event_type = EVENT_EXEC;
	else if (strcmp(env.event, "exit") == 0)
		obj->rodata->targ_event_type = EVENT_EXIT;
	else if (strcmp(env.event, "rename") == 0)
		obj->rodata->targ_event_type = EVENT_RENAME;
	else
		obj->rodata->targ_event_type = -1;

	if (!kprobe_exists("__arm64_compat_sys_execve")) {
		bpf_program__set_autoload(obj->progs.compat_execve_entry, false);
		bpf_program__set_autoload(obj->progs.compat_execve_exit, false);
	} else {
		printf("Monitor both native and compat execve syscall\n");
	}

	err = forksnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = forksnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	if (strcmp(env.mode, "stat") != 0) {
		printf("%-10s%-6s %6s %6s %6s %6s %12s %s\n", "Time", "Event", "PPID", "PID", "TID", "Info", "Duration(ms)", "Process (exec path & args)");
	}

	rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	if (signal(SIGINT, exit_handler) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.duration) {
		signal(SIGALRM, exit_handler);
		alarm(env.duration);
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

	print_stat(obj);

cleanup:
	ring_buffer__free(rb);
	forksnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
