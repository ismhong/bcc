// whoentercriticalstack.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <argp.h>
#include <stdbool.h>
#include <sys/sysinfo.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Assuming the existence of trace_helpers.h for ksyms functions
#include "trace_helpers.h"

#include "whoentercriticalstack.skel.h"

// ------------------------------------------------------------------
// Program Info (Required for Argp)
// ------------------------------------------------------------------
const char *argp_program_version = "whoentercriticalstack 0.1";
const char *argp_program_bug_address = "msinwu@realtek.com";

static const char argp_program_doc[] =
"Record the last suspect who entered critical section\n"
"\n"
"USAGE: whoentercriticalstack [-h] [-P PID] [-p | -i] [-T] [--stack-storage-size SIZE]\n"
"\n"
"examples:\n"
"  ./whoentercriticalstack -T         # Analysis what stack disabled IRQ/preempt last\n"
"  ./whoentercriticalstack -p         # Analysis what stack disabled preempt last\n"
"  ./whoentercriticalstack -i         # Analysis what stack disabled IRQ last\n"
"  ./whoentercriticalstack -P 210 -p  # Analysis what stack disabled preempt last with PID 210\n";


// ------------------------------------------------------------------
// Global Environment Parameters Structure
// ------------------------------------------------------------------
struct env {
    pid_t pid_filter;
    bool irq_mode;
    bool preempt_mode;
    bool print_timestamp;
    int stack_storage_size;
} env = {
    .pid_filter = 0,
    .irq_mode = false,
    .preempt_mode = true, // Default
    .print_timestamp = false,
    .stack_storage_size = 16384,
};


// ------------------------------------------------------------------
// Function Forward Declarations
// ------------------------------------------------------------------
static void sig_handler(int sig);
static int compare_u32(const void *a, const void *b);
static void print_stacks(struct ksyms *ksyms);


#define OPT_STACK_STORAGE_SIZE 1

static const struct argp_option opts[] = {
    {"pid", 'P', "PID", 0, "trace this PID only", 0},
    {"preemptoff", 'p', NULL, 0, "Find long sections where preemption was off (Default)", 0},
    {"irqoff", 'i', NULL, 0, "Find long sections where IRQ was off", 0},
    {"timestamp", 'T', NULL, 0, "include timestamp on output", 0},
    {"stack-storage-size", OPT_STACK_STORAGE_SIZE, "SIZE", 0, "the number of unique stack traces (default 16384)", 0},
    { NULL, 'h', NULL, OPTION_HIDDEN, "show this help message and exit", 0 },
    {},
};


// ------------------------------------------------------------------
// Argp Parse Function
// ------------------------------------------------------------------
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
        case 'P':
            errno = 0;
            env.pid_filter = strtol(arg, NULL, 10);
            if (errno || env.pid_filter <= 0) {
                fprintf(stderr, "Invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 'p':
            env.preempt_mode = true;
            env.irq_mode = false;
            break;
        case 'i':
            env.irq_mode = true;
            env.preempt_mode = false;
            break;
        case 'T':
            env.print_timestamp = true;
            break;
        case OPT_STACK_STORAGE_SIZE:
            errno = 0;
            env.stack_storage_size = strtol(arg, NULL, 10);
            if (errno || env.stack_storage_size <= 0) {
                fprintf(stderr, "Invalid stack storage size: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case ARGP_KEY_END:
            // Handle mode conflict or default mode
            if (env.irq_mode && env.preempt_mode) {
                env.preempt_mode = false;
            } else if (!env.irq_mode && !env.preempt_mode) {
                env.preempt_mode = true;
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


// ------------------------------------------------------------------
// Map/Structure Definitions
// ------------------------------------------------------------------
struct candidate_ts_key {
    __u32 cpu;
};

struct candidate_table {
    __s64 stack_id;
};

static struct whoentercriticalstack_bpf *skel;
static volatile sig_atomic_t exiting = 0;

// ------------------------------------------------------------------
// Helper Function Implementations
// ------------------------------------------------------------------

static void sig_handler(int sig)
{
    exiting = 1;
}

// Helper function for qsort to compare two __u32 (CPU IDs)
static int compare_u32(const void *a, const void *b) {
    __u32 val_a = *(__u32 *)a;
    __u32 val_b = *(__u32 *)b;
    if (val_a < val_b) return -1;
    if (val_a > val_b) return 1;
    return 0;
}

static void print_stacks(struct ksyms *ksyms)
{
    struct bpf_map *map = skel->maps.candidate_map_table;
    struct bpf_map *stack_map = skel->maps.stack_traces;

    struct candidate_ts_key key = {}, *p_key = NULL;
    struct candidate_table value;
    char time_str[32];

    size_t key_sz = sizeof(struct candidate_ts_key);
    size_t value_sz = sizeof(struct candidate_table);

    __u64 *stack_buf = NULL;
    int stack_map_fd = bpf_map__fd(stack_map);
    size_t stack_buf_size;

    const struct ksym *ksym;

    // CPU sorting variables
    __u32 *cpu_keys = NULL;
    size_t cpu_count = 0;
    size_t max_cpus = bpf_map__max_entries(map);

    if (stack_map_fd < 0) {
        fprintf(stderr, "Error: Stack map FD invalid. Cannot read stack traces.\n");
        return;
    }

    stack_buf_size = bpf_map__value_size(stack_map);
    if (stack_buf_size == 0 || stack_buf_size > (127 * sizeof(__u64))) {
        stack_buf_size = 127 * sizeof(__u64);
    }

    stack_buf = malloc(stack_buf_size);
    cpu_keys = malloc(max_cpus * sizeof(__u32));
    if (!stack_buf || !cpu_keys) {
        fprintf(stderr, "Error: Failed to allocate buffer memory.\n");
        if (stack_buf) free(stack_buf);
        if (cpu_keys) free(cpu_keys);
        return;
    }

    // 1. Iterate map and collect all existing CPU keys
    p_key = NULL;
    while (bpf_map__get_next_key(map, p_key, &key, key_sz) == 0) {
        if (cpu_count < max_cpus) {
            cpu_keys[cpu_count++] = key.cpu;
        }
        p_key = &key;
    }

    // 2. Sort the collected CPU keys
    qsort(cpu_keys, cpu_count, sizeof(__u32), compare_u32);

    if (env.print_timestamp) {
        time_t t = time(NULL);
        strftime(time_str, sizeof(time_str), "%m-%d %H:%M:%S", localtime(&t));
        printf("%-8s\n", time_str);
    }

    if (env.preempt_mode) {
        printf("================ENTER PREEMPT CRITICAL===============\n");
    } else {
        printf("================ENTER IRQ CRITICAL===================\n");
    }

    // 3. Look up and print results in CPU order
    for (size_t i = 0; i < cpu_count; i++) {
        struct candidate_ts_key current_key;
        current_key.cpu = cpu_keys[i];

        if (bpf_map__lookup_elem(map, &current_key, key_sz, &value, value_sz, 0) != 0) {
            // This is an expected race condition where the kernel deleted the entry
            continue;
        }

        printf("CPU:%u\n", current_key.cpu);

        if (value.stack_id >= 0) {

            if (bpf_map_lookup_elem(stack_map_fd, &value.stack_id, stack_buf) == 0) {

                for (size_t j = 0; j < stack_buf_size / sizeof(__u64); j++) {
                    if (stack_buf[j] == 0)
                        break;

                    ksym = ksyms__map_addr(ksyms, stack_buf[j]);

                    if (ksym) {
                        // Use %llx for 64-bit offsets (unsigned long long)
                        printf("  %s+0x%llx\n",
                                ksym->name,
                                stack_buf[j] - ksym->addr);
                    } else {
                        printf("  %p Unknown\n", (void *)stack_buf[j]);
                    }
                }
            } else {
                printf("ERROR: Failed to lookup stack trace for ID %lld\n", value.stack_id);
            }
        } else {
            printf("STACK ID: %lld (Failed to record stack trace)\n", value.stack_id);
        }

        printf("  \n");
    }

    printf("=====================================================\n");

    if (stack_buf) free(stack_buf);
    if (cpu_keys) free(cpu_keys);
}


// ------------------------------------------------------------------
// main Function
// ------------------------------------------------------------------

int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = " ",
    };

    int err = 0;
    int num_cpus = 0;
    struct ksyms *ksyms = NULL;

    // Parse arguments using argp
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load kernel symbols for resolution
    ksyms = ksyms__load();
    if (!ksyms) {
        fprintf(stderr, "ERROR: Failed to load kallsyms (required for symbol resolution). Are you running as root?\n");
        return 1;
    }

    // Open BPF skeleton
    skel = whoentercriticalstack_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        goto cleanup_ksyms;
    }

    // Set map size based on CPU count
    num_cpus = get_nprocs();
    if (num_cpus <= 0) {
        fprintf(stderr, "WARNING: Could not determine CPU count, assuming 8.\n");
        num_cpus = 8;
    }
    bpf_map__set_max_entries(skel->maps.candidate_map_table, num_cpus);

    // Set stack traces map size before load
    bpf_map__set_value_size(skel->maps.stack_traces, 127 * sizeof(__u64));
    bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_storage_size);

    // Pass parameters to BPF program
    skel->rodata->target_pid = env.pid_filter;

    // Set program autoload based on selected mode
    if (env.irq_mode) {
        printf("Mode: IRQ Off\n");
        bpf_program__set_autoload(skel->progs.preempt_disable_entry, false);
        bpf_program__set_autoload(skel->progs.preempt_enable_entry, false);
    } else {
        printf("Mode: Preempt Off\n");
        bpf_program__set_autoload(skel->progs.irq_disable_entry, false);
        bpf_program__set_autoload(skel->progs.irq_enable_entry, false);
    }

    // Load BPF program
    err = whoentercriticalstack_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF program: %s\n", strerror(-err));
        goto cleanup_skel;
    }

    // Attach BPF program
    err = whoentercriticalstack_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to attach BPF program: %s\n", strerror(-err));
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        fprintf(stderr, "Make sure the kernel is built with following kernel config\n");
        fprintf(stderr, "   - CONFIG_PREEMPT_TRACER\n");
        fprintf(stderr, "   - CONFIG_PREEMPTIRQ_EVENTS (CONFIG_PREEMPTIRQ_TRACEPOINTS in kernel 4.19 and later)\n");
        fprintf(stderr, "   - CONFIG_PREEMPTIRQ_TRACEPOINTS\n");
        fprintf(stderr, "   - CONFIG_TRACE_PREEMPT_TOGGLE\n");
        fprintf(stderr, "   - CONFIG_TRACE_IRQFLAGS\n");
        fprintf(stderr, "   - CONFIG_DEBUG_PREEMPT\n");
        fprintf(stderr, "Also please disable CONFIG_PROVE_LOCKING and CONFIG_LOCKDEP on older kernels.\n\n");
        goto cleanup_skel;
    }

    printf("Finding who entered critical section last (with kernel symbol resolution)\n");
    printf("Press Ctrl-C to exit...\n");

    while (!exiting) {
        sleep(1);
        print_stacks(ksyms);
    }

cleanup_skel:
    whoentercriticalstack_bpf__destroy(skel);
cleanup_ksyms:
    ksyms__free(ksyms);
    return err < 0 ? -err : 0;
}
