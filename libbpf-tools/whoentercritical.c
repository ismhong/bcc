// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>

#include "whoentercritical.skel.h"

// Define structs locally for easy access, matching the eBPF code
enum addr_offs {
    START_CALLER_OFF,
    START_PARENT_OFF,
};

struct candidate_ts_key {
    unsigned int cpu;
};

struct candidate_table {
    unsigned long long addrs[2];
    unsigned int pid;
    unsigned int tgid;
    unsigned long long ts;
};

// --- Kernel Symbol Resolution Structures ---
#define MAX_SYMBOL_NAME_LEN 64
struct ksym {
    unsigned long long addr;
    char name[MAX_SYMBOL_NAME_LEN];
};

static struct ksym *kallsyms = NULL;
static size_t kallsyms_count = 0;
// Static variable to hold the base address of the kernel text (lowest address in kallsyms)
static unsigned long long kernel_base_addr = 0;

static struct whoentercritical_bpf *skel;
static int exiting = 0;
static int print_timestamp = 0;
static int num_cpus = 0;

/*
 * Reads the command name for a given PID from /proc/<pid>/comm.
 */
static void pid_to_comm(unsigned int pid, char *comm_buf, size_t buf_size)
{
    char path[PATH_MAX];
    int fd;
    ssize_t n;

    if (pid == 0) {
        strncpy(comm_buf, "swapper/0", buf_size - 1);
        comm_buf[buf_size - 1] = '\0';
        return;
    }

    snprintf(path, PATH_MAX, "/proc/%u/comm", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(comm_buf, buf_size, "%u (Unknown)", pid);
        return;
    }

    n = read(fd, comm_buf, buf_size - 1);
    close(fd);

    if (n > 0) {
        // Remove trailing newline
        if (comm_buf[n - 1] == '\n')
            comm_buf[n - 1] = '\0';
        else
            comm_buf[n] = '\0';
    } else {
        snprintf(comm_buf, buf_size, "%u (ReadError)", pid);
    }
}

/*
 * Loads kernel symbols from /proc/kallsyms.
 * Assumes the symbol file is sorted by address.
 */
static int load_kallsyms()
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        // Print detailed error using perror
        perror("Warning: Could not open /proc/kallsyms for symbol resolution");
        return -ENOENT;
    }

    // First pass to count lines
    char line[256];
    size_t count = 0;
    while (fgets(line, sizeof(line), f)) {
        count++;
    }

    if (count == 0) {
        fclose(f);
        return -EINVAL;
    }

    kallsyms = (struct ksym *)calloc(count, sizeof(struct ksym));
    if (!kallsyms) {
        fclose(f);
        fprintf(stderr, "Error: Failed to allocate memory for %zu ksyms.\n", count);
        return -ENOMEM;
    }
    kallsyms_count = count;

    // Second pass to read data
    fseek(f, 0, SEEK_SET);
    size_t i = 0;
    while (fgets(line, sizeof(line), f) && i < kallsyms_count) {
        unsigned long long addr;
        char type, name[MAX_SYMBOL_NAME_LEN];

        // Format: <address> <type> <symbol_name>
        if (sscanf(line, "%llx %c %s", &addr, &type, name) == 3) {
            kallsyms[i].addr = addr;
            strncpy(kallsyms[i].name, name, MAX_SYMBOL_NAME_LEN - 1);
            kallsyms[i].name[MAX_SYMBOL_NAME_LEN - 1] = '\0';
            i++;
        }
    }
    kallsyms_count = i; // Adjust count in case of parsing errors

    fclose(f);

    if (kallsyms_count > 0) {
        // FIX: Search for _stext (as done by bcc) instead of relying on the first symbol.
        unsigned long long stext_addr = 0;
        for (size_t j = 0; j < kallsyms_count; j++) {
            if (strcmp(kallsyms[j].name, "_stext") == 0) {
                stext_addr = kallsyms[j].addr;
                break;
            }
        }

        if (stext_addr > 0) {
            kernel_base_addr = stext_addr;
            printf("Info: Loaded %zu kernel symbols. Base address (_stext): 0x%llx\n", kallsyms_count, kernel_base_addr);
        } else {
            // Fallback to the lowest address if _stext is not found
            kernel_base_addr = kallsyms[0].addr;
            printf("Warning: _stext not found. Falling back to lowest address: 0x%llx\n", kernel_base_addr);
        }
    } else {
        printf("Info: Loaded 0 kernel symbols.\n");
    }

    return 0;
}

/*
 * Resolves a kernel instruction offset (address) to its nearest symbol.
 * Returns the symbol's name and its start address offset.
 */
static void resolve_symbol(unsigned long long offset, char *sym_buf, size_t sym_buf_size, unsigned long long *func_offset)
{
    // If symbols are not loaded or we didn't find a base address, revert to raw offset display.
    if (kallsyms_count == 0 || kernel_base_addr == 0) {
        snprintf(sym_buf, sym_buf_size, "+0x%llx", offset);
        *func_offset = offset;
        return;
    }

    // Convert the relative offset (from _stext) to an absolute virtual address.
    unsigned long long absolute_addr = kernel_base_addr + offset;

    // Binary search for the symbol with the largest address <= absolute_addr
    int low = 0, high = kallsyms_count - 1;
    int best_match = -1;

    while (low <= high) {
        int mid = low + (high - low) / 2;
        if (kallsyms[mid].addr <= absolute_addr) { // Check against absolute address
            best_match = mid;
            low = mid + 1; // Try to find a larger match
        } else {
            high = mid - 1; // Current symbol is too large
        }
    }

    if (best_match != -1) {
        unsigned long long base_addr = kallsyms[best_match].addr;
        const char *name = kallsyms[best_match].name;
        // Calculate the offset of the instruction within the resolved function
        // unsigned long long relative_offset_in_func = absolute_addr - base_addr;

        // Format: <function_name> (Only the function name, excluding the offset)
        snprintf(sym_buf, sym_buf_size, "%s", name);
        *func_offset = base_addr;
    } else {
        // Fallback: If no symbol found (even with absolute address)
        snprintf(sym_buf, sym_buf_size, "+0x%llx (Absolute: 0x%llx)", offset, absolute_addr);
        *func_offset = offset;
    }
}

static void print_event()
{
    // Use bpf_map__fd() to get the file descriptor (int) for raw BPF syscall wrappers
    int irq_map_fd = bpf_map__fd(skel->maps.irq_candidate_map_table);
    int preempt_map_fd = bpf_map__fd(skel->maps.preempt_candidate_map_table);
    struct candidate_ts_key key;
    struct candidate_table val;
    char comm[16] = {0};
    int err;
    time_t timer;
    char time_buf[26];
    struct tm* tm_info;
    int irq_count = 0;      // Counter for IRQ events
    int preempt_count = 0;  // Counter for PREEMPT events

    char parent_sym[MAX_SYMBOL_NAME_LEN * 2];
    char caller_sym[MAX_SYMBOL_NAME_LEN * 2];
    unsigned long long parent_base_off, caller_base_off;

    if (print_timestamp) {
        time(&timer);
        tm_info = localtime(&timer);
        // Format the time string
        strftime(time_buf, 26, "%m-%d %H:%M:%S", tm_info);
        // Print the timestamp (fixed formatting)
        printf("%s\n", time_buf);
    }

    // Header update: Indicates the "last seen" record per CPU
    printf("================ENTER IRQ CRITICAL===================\n");
    // Removed the "Resolved Symbols" header for cleaner output

    // Iterate through fixed CPU IDs (0 to num_cpus - 1) to ensure each is checked once.
    for (int i = 0; i < num_cpus; i++) {
        key.cpu = i;
        // Use lookup to atomically check the latest value for this specific CPU key
        err = bpf_map_lookup_elem(irq_map_fd, &key, &val);

        if (err == 0) {
            pid_to_comm(val.pid, comm, sizeof(comm));

            // Resolve symbols
            resolve_symbol(val.addrs[START_PARENT_OFF], parent_sym, sizeof(parent_sym), &parent_base_off);
            resolve_symbol(val.addrs[START_CALLER_OFF], caller_sym, sizeof(caller_sym), &caller_base_off);

            // Re-introducing "Section start:" prefix to match the user's reference bcc output
            printf("CPU:%-2u TGID:%-5u PID:%-5u COMM:%-16s TS:%llu Section start: %s -> %s\n",
                   key.cpu, val.tgid, val.pid, comm, val.ts,
                   parent_sym, caller_sym);

            irq_count++; // Increment counter
        }
    }

    // Feedback if no events were found (since program start)
    if (irq_count == 0) {
        printf("--- No IRQ disable events captured yet ---\n");
    }

    // Header update: Indicates the "last seen" record per CPU
    printf("================ENTER PREEMPT CRITICAL===============\n");
    // Removed the "Resolved Symbols" header for cleaner output


    // Iterate through fixed CPU IDs (0 to num_cpus - 1)
    for (int i = 0; i < num_cpus; i++) {
        key.cpu = i;
        // Use lookup to atomically check the latest value for this specific CPU key
        err = bpf_map_lookup_elem(preempt_map_fd, &key, &val);

        if (err == 0) {
            pid_to_comm(val.pid, comm, sizeof(comm));

            // Resolve symbols
            resolve_symbol(val.addrs[START_PARENT_OFF], parent_sym, sizeof(parent_sym), &parent_base_off);
            resolve_symbol(val.addrs[START_CALLER_OFF], caller_sym, sizeof(caller_sym), &caller_base_off);

            // Re-introducing "Section start:" prefix to match the user's reference bcc output
            printf("CPU:%-2u TGID:%-5u PID:%-5u COMM:%-16s TS:%llu Section start: %s -> %s\n",
                   key.cpu, val.tgid, val.pid, comm, val.ts,
                   parent_sym, caller_sym);

            preempt_count++; // Increment counter
        }
    }

    // Feedback if no events were found (since program start)
    if (preempt_count == 0) {
        printf("--- No PREEMPT disable events captured yet ---\n");
    }

    printf("=====================================================\n");
}

static void sig_handler(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    int err = 0; // Initialize err to 0 to prevent uninitialized warning/error

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [-T]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -T  Print a timestamp before each output block.\n");
            printf("  -h  Show this help message.\n");
            return 0; // Exit after showing help
        } else if (strcmp(argv[1], "-T") == 0) {
            print_timestamp = 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load kernel symbols first
    if (load_kallsyms() != 0) {
        // Warning message is now handled within load_kallsyms() via perror.
        fprintf(stderr, "Output will only show raw offsets.\n");
    }

    // Now using Tracepoint for stability
    printf("Finding who entered critical section last (Tracepoint on preemptirq/irq_disable, preemptirq/preempt_disable)\n");

    // 1. Open BPF program
    skel = whoentercritical_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1; // Explicitly set error code
        goto cleanup;
    }

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "Failed to get number of possible CPUs\n");
        err = 1;
        goto cleanup;
    }
    bpf_map__set_max_entries(skel->maps.irq_candidate_map_table, num_cpus);
    bpf_map__set_max_entries(skel->maps.preempt_candidate_map_table, num_cpus);

    // 2. Load BPF program
    err = whoentercritical_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    // 3. Attach BPF program
    // The skeleton handles attaching the tracepoints automatically
    err = whoentercritical_bpf__attach(skel);
    if (err) {
        // Tracepoint attachment can fail if the tracepoint is not available
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        fprintf(stderr, "Make sure the kernel is built with following kernel config\n");
        fprintf(stderr, "   - CONFIG_PREEMPT_TRACER\n");
        fprintf(stderr, "   - CONFIG_PREEMPTIRQ_EVENTS (CONFIG_PREEMPTIRQ_TRACEPOINTS in kernel 4.19 and later)\n");
        fprintf(stderr, "   - CONFIG_PREEMPTIRQ_TRACEPOINTS\n");
        fprintf(stderr, "   - CONFIG_TRACE_PREEMPT_TOGGLE\n");
        fprintf(stderr, "   - CONFIG_TRACE_IRQFLAGS\n");
        fprintf(stderr, "   - CONFIG_DEBUG_PREEMPT\n");
        fprintf(stderr, "Also please disable CONFIG_PROVE_LOCKING and CONFIG_LOCKDEP on older kernels.\n\n");
        goto cleanup;
    }

    // Main loop
    while (!exiting) {
        sleep(1);
        print_event();
    }

cleanup:
    whoentercritical_bpf__destroy(skel);
    if (kallsyms) {
        free(kallsyms);
    }
    return err;
}

