// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Dispatcher for libbpf-tools multi-call binary.
// Allows a single binary to serve as all 91 libbpf-tools via busybox-style
// symlinks or direct invocation: libbpf-tools-box <toolname> [args...].

#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Forward declarations — one per tool.
 * Each tool's main() is renamed to TOOL_main() by the wrapper .c.
 * Declared weak so that tools not compiled on this branch (e.g. arm32
 * with fewer tools) resolve to NULL instead of causing linker errors. */
extern int argdist_main(int argc, char **argv) __attribute__((weak));
extern int bashreadline_main(int argc, char **argv) __attribute__((weak));
extern int bindsnoop_main(int argc, char **argv) __attribute__((weak));
extern int biolatency_main(int argc, char **argv) __attribute__((weak));
extern int biopattern_main(int argc, char **argv) __attribute__((weak));
extern int biosnoop_main(int argc, char **argv) __attribute__((weak));
extern int biostacks_main(int argc, char **argv) __attribute__((weak));
extern int biotop_main(int argc, char **argv) __attribute__((weak));
extern int bitesize_main(int argc, char **argv) __attribute__((weak));
extern int cachestat_main(int argc, char **argv) __attribute__((weak));
extern int capable_main(int argc, char **argv) __attribute__((weak));
extern int cmasnoop_main(int argc, char **argv) __attribute__((weak));
extern int cmatop_main(int argc, char **argv) __attribute__((weak));
extern int cmatrack_main(int argc, char **argv) __attribute__((weak));
extern int cpudist_main(int argc, char **argv) __attribute__((weak));
extern int cpufreq_main(int argc, char **argv) __attribute__((weak));
extern int cpuidle_main(int argc, char **argv) __attribute__((weak));
extern int cputop_main(int argc, char **argv) __attribute__((weak));
extern int drsnoop_main(int argc, char **argv) __attribute__((weak));
extern int execsnoop_main(int argc, char **argv) __attribute__((weak));
extern int exitsnoop_main(int argc, char **argv) __attribute__((weak));
extern int filelife_main(int argc, char **argv) __attribute__((weak));
extern int filetop_main(int argc, char **argv) __attribute__((weak));
extern int forksnoop_main(int argc, char **argv) __attribute__((weak));
extern int fsdist_main(int argc, char **argv) __attribute__((weak));
extern int fsslower_main(int argc, char **argv) __attribute__((weak));
extern int funclatency_main(int argc, char **argv) __attribute__((weak));
extern int funcslower_main(int argc, char **argv) __attribute__((weak));
extern int futexctn_main(int argc, char **argv) __attribute__((weak));
extern int gethostlatency_main(int argc, char **argv) __attribute__((weak));
extern int gpumemtop_main(int argc, char **argv) __attribute__((weak));
extern int hardirqs_main(int argc, char **argv) __attribute__((weak));
extern int javagc_main(int argc, char **argv) __attribute__((weak));
extern int klockstat_main(int argc, char **argv) __attribute__((weak));
extern int ksnoop_main(int argc, char **argv) __attribute__((weak));
extern int linuxfiletop_main(int argc, char **argv) __attribute__((weak));
extern int llcstat_main(int argc, char **argv) __attribute__((weak));
extern int loadavg_main(int argc, char **argv) __attribute__((weak));
extern int mdflush_main(int argc, char **argv) __attribute__((weak));
extern int memleak_main(int argc, char **argv) __attribute__((weak));
extern int memleaktop_main(int argc, char **argv) __attribute__((weak));
extern int mmclatency_main(int argc, char **argv) __attribute__((weak));
extern int mmctop_main(int argc, char **argv) __attribute__((weak));
extern int mountsnoop_main(int argc, char **argv) __attribute__((weak));
extern int netaggr_main(int argc, char **argv) __attribute__((weak));
extern int numamove_main(int argc, char **argv) __attribute__((weak));
extern int offcputime_main(int argc, char **argv) __attribute__((weak));
extern int oomkill_main(int argc, char **argv) __attribute__((weak));
extern int opensnoop_main(int argc, char **argv) __attribute__((weak));
extern int pagealloctop_main(int argc, char **argv) __attribute__((weak));
extern int pageowner_main(int argc, char **argv) __attribute__((weak));
extern int poweralloc_main(int argc, char **argv) __attribute__((weak));
extern int profile_main(int argc, char **argv) __attribute__((weak));
extern int readahead_main(int argc, char **argv) __attribute__((weak));
extern int rpcdist_main(int argc, char **argv) __attribute__((weak));
extern int rpcsnoop_main(int argc, char **argv) __attribute__((weak));
extern int rpctop_main(int argc, char **argv) __attribute__((weak));
extern int rpcundone_main(int argc, char **argv) __attribute__((weak));
extern int rtkheaptop_main(int argc, char **argv) __attribute__((weak));
extern int runqlat_main(int argc, char **argv) __attribute__((weak));
extern int runqlen_main(int argc, char **argv) __attribute__((weak));
extern int runqslower_main(int argc, char **argv) __attribute__((weak));
extern int schedblockedtop_main(int argc, char **argv) __attribute__((weak));
extern int sigsnoop_main(int argc, char **argv) __attribute__((weak));
extern int slabratetop_main(int argc, char **argv) __attribute__((weak));
extern int smclatency_main(int argc, char **argv) __attribute__((weak));
extern int smctop_main(int argc, char **argv) __attribute__((weak));
extern int softirqs_main(int argc, char **argv) __attribute__((weak));
extern int softirqslower_main(int argc, char **argv) __attribute__((weak));
extern int solisten_main(int argc, char **argv) __attribute__((weak));
extern int stackcount_main(int argc, char **argv) __attribute__((weak));
extern int statsnoop_main(int argc, char **argv) __attribute__((weak));
extern int syncsnoop_main(int argc, char **argv) __attribute__((weak));
extern int syscount_main(int argc, char **argv) __attribute__((weak));
extern int tcpconnect_main(int argc, char **argv) __attribute__((weak));
extern int tcpconnlat_main(int argc, char **argv) __attribute__((weak));
extern int tcplife_main(int argc, char **argv) __attribute__((weak));
extern int tcppktlat_main(int argc, char **argv) __attribute__((weak));
extern int tcprtt_main(int argc, char **argv) __attribute__((weak));
extern int tcpstates_main(int argc, char **argv) __attribute__((weak));
extern int tcpsynbl_main(int argc, char **argv) __attribute__((weak));
extern int tcptop_main(int argc, char **argv) __attribute__((weak));
extern int tcptracer_main(int argc, char **argv) __attribute__((weak));
extern int tcpwin_main(int argc, char **argv) __attribute__((weak));
extern int vfsstat_main(int argc, char **argv) __attribute__((weak));
extern int vmallocleak_main(int argc, char **argv) __attribute__((weak));
extern int vmoom_main(int argc, char **argv) __attribute__((weak));
extern int wakeuptime_main(int argc, char **argv) __attribute__((weak));
extern int whoentercritical_main(int argc, char **argv) __attribute__((weak));
extern int whoentercriticalstack_main(int argc, char **argv) __attribute__((weak));
extern int whoentersmc_main(int argc, char **argv) __attribute__((weak));

struct tool_entry {
	const char *name;
	const char *desc;
	int (*fn)(int argc, char **argv);
};

static const struct tool_entry tools[] = {
	{ "argdist",               "Trace a function/tracepoint parameter",              argdist_main },
	{ "bashreadline",          "Print entered bash commands",                        bashreadline_main },
	{ "bindsnoop",             "Trace socket bind operations",                       bindsnoop_main },
	{ "biolatency",            "Block I/O latency distribution",                     biolatency_main },
	{ "biopattern",            "Identify block I/O patterns",                        biopattern_main },
	{ "biosnoop",              "Block I/O request tracing",                          biosnoop_main },
	{ "biostacks",             "Show block I/O stack traces",                        biostacks_main },
	{ "biotop",                "Block I/O top by process",                           biotop_main },
	{ "bitesize",              "Block I/O size distribution",                        bitesize_main },
	{ "cachestat",             "File system cache hit statistics",                   cachestat_main },
	{ "capable",               "Capability check tracing",                           capable_main },
	{ "cmasnoop",              "CMA (Contiguous Memory Allocator) events",           cmasnoop_main },
	{ "cmatop",                "CMA allocation top",                                 cmatop_main },
	{ "cmatrack",              "CMA allocation tracker",                             cmatrack_main },
	{ "cpudist",               "CPU time distribution by process",                   cpudist_main },
	{ "cpufreq",               "CPU frequency sampling",                             cpufreq_main },
	{ "cpuidle",               "CPU idle state tracing",                             cpuidle_main },
	{ "cputop",                "CPU utilization top",                                cputop_main },
	{ "drsnoop",               "Direct reclaim tracing",                             drsnoop_main },
	{ "execsnoop",             "Trace process execution",                            execsnoop_main },
	{ "exitsnoop",             "Trace process exit events",                          exitsnoop_main },
	{ "filelife",              "Trace short-lived file lifespan",                    filelife_main },
	{ "filetop",               "File reads and writes by process",                   filetop_main },
	{ "forksnoop",             "Trace fork operations",                              forksnoop_main },
	{ "fsdist",                "File system latency distribution",                   fsdist_main },
	{ "fsslower",              "Trace slow file system operations",                  fsslower_main },
	{ "funclatency",           "Function latency distribution",                      funclatency_main },
	{ "funcslower",            "Trace slow kernel functions",                        funcslower_main },
	{ "futexctn",              "Trace futex contention",                             futexctn_main },
	{ "gethostlatency",        "DNS resolution latency",                             gethostlatency_main },
	{ "gpumemtop",             "GPU memory usage top",                               gpumemtop_main },
	{ "hardirqs",              "Hard IRQ tracing",                                   hardirqs_main },
	{ "javagc",                "Java garbage collection tracing",                    javagc_main },
	{ "klockstat",             "Kernel lock statistics",                             klockstat_main },
	{ "ksnoop",                "Trace kernel function parameters",                   ksnoop_main },
	{ "linuxfiletop",          "Linux file reads and writes top",                    linuxfiletop_main },
	{ "llcstat",               "LLC cache miss statistics",                          llcstat_main },
	{ "loadavg",               "System load average sampling",                       loadavg_main },
	{ "mdflush",               "MD flush tracing",                                   mdflush_main },
	{ "memleak",               "Detect memory leaks",                                memleak_main },
	{ "memleaktop",            "Memory allocation top",                              memleaktop_main },
	{ "mmclatency",            "MMC command latency",                                mmclatency_main },
	{ "mmctop",                "MMC operation top",                                  mmctop_main },
	{ "mountsnoop",            "Trace mount and unmount operations",                 mountsnoop_main },
	{ "netaggr",               "Network aggregation tracing",                        netaggr_main },
	{ "numamove",              "NUMA page migration tracing",                        numamove_main },
	{ "offcputime",            "Off-CPU time analysis by stack trace",               offcputime_main },
	{ "oomkill",               "Trace OOM killer",                                   oomkill_main },
	{ "opensnoop",             "Trace file open operations",                         opensnoop_main },
	{ "pagealloctop",          "Page allocation top",                                pagealloctop_main },
	{ "pageowner",             "Page owner tracking",                                pageowner_main },
	{ "poweralloc",            "Power allocation tracing",                           poweralloc_main },
	{ "profile",               "CPU profiling sampler",                              profile_main },
	{ "readahead",             "Trace read-ahead operations",                        readahead_main },
	{ "rpcdist",               "RPC latency distribution",                           rpcdist_main },
	{ "rpcsnoop",              "Trace RPC operations",                               rpcsnoop_main },
	{ "rpctop",                "RPC operation top",                                  rpctop_main },
	{ "rpcundone",             "Trace unfinished RPC operations",                    rpcundone_main },
	{ "rtkheaptop",            "RTK heap allocation top",                            rtkheaptop_main },
	{ "runqlat",               "CPU run queue latency distribution",                 runqlat_main },
	{ "runqlen",               "CPU run queue length distribution",                  runqlen_main },
	{ "runqslower",            "Trace long run queue delays",                        runqslower_main },
	{ "schedblockedtop",       "Blocked tasks top",                                  schedblockedtop_main },
	{ "sigsnoop",              "Trace signal delivery",                              sigsnoop_main },
	{ "slabratetop",           "Slab cache allocation rate top",                     slabratetop_main },
	{ "smclatency",            "SMC (Secure Monitor Call) latency",                  smclatency_main },
	{ "smctop",                "SMC operation top",                                  smctop_main },
	{ "softirqs",              "Soft IRQ tracing",                                   softirqs_main },
	{ "softirqslower",         "Trace slow softirqs",                                softirqslower_main },
	{ "solisten",              "Trace socket listen requests",                       solisten_main },
	{ "stackcount",            "Count kernel stack traces",                          stackcount_main },
	{ "statsnoop",             "Trace stat() syscalls",                              statsnoop_main },
	{ "syncsnoop",             "Trace sync operations",                              syncsnoop_main },
	{ "syscount",              "Count system calls",                                 syscount_main },
	{ "tcpconnect",            "Trace TCP connect connections",                      tcpconnect_main },
	{ "tcpconnlat",            "TCP connection latency",                             tcpconnlat_main },
	{ "tcplife",               "TCP session life cycle tracing",                     tcplife_main },
	{ "tcppktlat",             "TCP packet latency",                                 tcppktlat_main },
	{ "tcprtt",                "TCP RTT tracing",                                    tcprtt_main },
	{ "tcpstates",             "TCP state transition tracing",                       tcpstates_main },
	{ "tcpsynbl",              "TCP SYN backlog tracing",                            tcpsynbl_main },
	{ "tcptop",                "TCP traffic top by process",                         tcptop_main },
	{ "tcptracer",             "TCP connection tracer",                              tcptracer_main },
	{ "tcpwin",                "TCP window size tracing",                            tcpwin_main },
	{ "vfsstat",               "VFS call statistics",                                vfsstat_main },
	{ "vmallocleak",           "Detect vmalloc leaks",                               vmallocleak_main },
	{ "vmoom",                 "VM OOM (Out-Of-Memory) tracing",                     vmoom_main },
	{ "wakeuptime",            "Wakeup time analysis by trace",                      wakeuptime_main },
	{ "whoentercritical",      "Trace entering critical section",                    whoentercritical_main },
	{ "whoentercriticalstack", "Trace critical section entry with stack",            whoentercriticalstack_main },
	{ "whoentersmc",           "Trace SMC entry",                                    whoentersmc_main },
	{ NULL, NULL, NULL }
};

#define MAX_TOOL_NAME_LEN 24

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <tool> [args...]\n\n", prog);
	fprintf(stderr, "For detailed documentation and examples, see:\n");
	fprintf(stderr, "  https://processor.realtek.com/bpf/bpftools.html\n\n");
	fprintf(stderr, "Available tools:\n");
		for (const struct tool_entry *t = tools; t->name; t++) {
			if (!t->fn) /* skip tools not compiled on this branch */
				continue;
			fprintf(stderr, "  %-*s %s\n", MAX_TOOL_NAME_LEN, t->name, t->desc);
		}
}

int main(int argc, char **argv)
{
	const char *prog = argv[0];
	const char *tool_name;
	char *bn = basename(argv[0]);

	/* If invoked as libbpf-tools-box directly, use argv[1] as tool name */
	if (strcmp(bn, "libbpf-tools-box") == 0) {
		if (argc < 2) {
			print_usage(prog);
			return 1;
		}
		tool_name = argv[1];
		/* Shift args so tool sees argv[0] = tool name */
		argv[1] = argv[0];
		argv++;
		argc--;
		argv[0] = (char *)tool_name;
	} else {
		/* Invoked via symlink: argv[0] is the tool name */
		tool_name = bn;
	}

	for (const struct tool_entry *t = tools; t->name; t++) {
		if (t->fn && strcmp(tool_name, t->name) == 0)
			return t->fn(argc, argv);
	}

	fprintf(stderr, "libbpf-tools-box: unknown tool '%s'\n", tool_name);
	fprintf(stderr, "Run 'libbpf-tools-box' for a list of available tools.\n");
	return 1;
}
