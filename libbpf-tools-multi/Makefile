# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# libbpf-tools-multi: Busybox-style multi-call binary wrapping all libbpf-tools.
#
# Usage:
#   make                                  # native host build
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-  # cross-compile
#
# Prerequisites: ../libbpf-tools must be built first.
#   make -C ../libbpf-tools [ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-]

LIBBPF_TOOLS := $(abspath ../libbpf-tools)
OUTPUT       := $(abspath .output)
WRAPPERS_DIR := $(OUTPUT)/wrappers

# Reuse build artifacts from ../libbpf-tools/.output
LIBBPF_OBJ  := $(LIBBPF_TOOLS)/.output/libbpf.a

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' \
		 | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' \
		 | sed 's/riscv64/riscv/' | sed 's/loongarch.*/loongarch/' \
		 | sed 's/s390x/s390/')

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef
$(call allow-override,CC,$(CROSS_COMPILE)cc)

CFLAGS := -g -O2 -Wall -Wmissing-field-initializers
# Include headers from libbpf-tools/.output (skeletons, libbpf headers, etc.)
INCLUDES := -I$(LIBBPF_TOOLS)/.output \
            -I$(LIBBPF_TOOLS) \
            -I$(LIBBPF_TOOLS)/../src/cc/libbpf/include/uapi

LDFLAGS := -static -largp -lz -lzstd -lelf -Wl,--wrap=btf__load_vmlinux_btf

# All 91 tools (those with a main() function in libbpf-tools/)
TOOLS = \
	argdist \
	bashreadline \
	bindsnoop \
	biolatency \
	biopattern \
	biosnoop \
	biostacks \
	biotop \
	bitesize \
	cachestat \
	capable \
	cmasnoop \
	cmatop \
	cmatrack \
	cpudist \
	cpufreq \
	cpuidle \
	cputop \
	drsnoop \
	execsnoop \
	exitsnoop \
	filelife \
	filetop \
	forksnoop \
	fsdist \
	fsslower \
	funclatency \
	funcslower \
	futexctn \
	gethostlatency \
	gpumemtop \
	hardirqs \
	javagc \
	klockstat \
	ksnoop \
	linuxfiletop \
	llcstat \
	loadavg \
	mdflush \
	memleak \
	memleaktop \
	mmclatency \
	mmctop \
	mountsnoop \
	netaggr \
	numamove \
	offcputime \
	oomkill \
	opensnoop \
	pagealloctop \
	pageowner \
	poweralloc \
	profile \
	readahead \
	rpcdist \
	rpcsnoop \
	rpctop \
	rpcundone \
	rtkheaptop \
	runqlat \
	runqlen \
	runqslower \
	schedblockedtop \
	sigsnoop \
	slabratetop \
	smclatency \
	smctop \
	softirqs \
	softirqslower \
	solisten \
	stackcount \
	statsnoop \
	syncsnoop \
	syscount \
	tcpconnect \
	tcpconnlat \
	tcplife \
	tcppktlat \
	tcprtt \
	tcpstates \
	tcpsynbl \
	tcptop \
	tcptracer \
	tcpwin \
	vfsstat \
	vmallocleak \
	vmoom \
	wakeuptime \
	whoentercritical \
	whoentercriticalstack \
	whoentersmc \
	#

# Common helper objects compiled from libbpf-tools/*.c (no main(), no renaming needed)
COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/syscall_helpers.o \
	$(OUTPUT)/errno_helpers.o \
	$(OUTPUT)/map_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \
	$(OUTPUT)/btf_helpers.o \
	$(OUTPUT)/compat.o \
	$(OUTPUT)/path_helpers.o \
	$(OUTPUT)/argparse.o \
	#

TOOL_OBJS := $(patsubst %,$(OUTPUT)/%.o,$(TOOLS))

.PHONY: all prereq clean

all: prereq libbpf-tools-box

# ── Phase 1: Prerequisite check ─────────────────────────────────────────────
prereq:
	@if [ ! -f "$(LIBBPF_OBJ)" ]; then \
		echo ""; \
		echo "ERROR: $(LIBBPF_OBJ) not found."; \
		echo ""; \
		echo "Build libbpf-tools first:"; \
		echo "  make -C $(LIBBPF_TOOLS) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)"; \
		echo ""; \
		exit 1; \
	fi

# ── Phase 2: Wrapper generation + compile + link ─────────────────────────────

# Create output directories
$(OUTPUT) $(WRAPPERS_DIR):
	mkdir -p $@

# Generate a thin wrapper .c for each tool.
# #defines rename conflicting non-static globals before #include-ing the tool .c.
# Symbols renamed (safe to apply even if tool doesn't use them):
#   main                    → TOOL_main
#   argp_program_version    → TOOL_argp_version
#   argp_program_bug_address → TOOL_argp_bug_address
#   argp_program_doc        → TOOL_argp_doc
#   argp_args_doc           → TOOL_argp_args_doc
#   handle_event            → TOOL_handle_event
#   handle_lost_events      → TOOL_handle_lost_events
#   libbpf_print_fn         → TOOL_libbpf_print_fn
$(WRAPPERS_DIR)/%.c: $(LIBBPF_TOOLS)/%.c | $(WRAPPERS_DIR)
	@TOOL=$*; \
	printf '/* Auto-generated wrapper for %s — DO NOT EDIT */\n' "$$TOOL" > $@; \
	printf '#define main                     %s_main\n' "$$TOOL" >> $@; \
	printf '#define argp_program_version     %s_argp_version\n' "$$TOOL" >> $@; \
	printf '#define argp_program_bug_address %s_argp_bug_address\n' "$$TOOL" >> $@; \
	printf '#define argp_program_doc         %s_argp_doc\n' "$$TOOL" >> $@; \
	printf '#define argp_args_doc            %s_argp_args_doc\n' "$$TOOL" >> $@; \
	printf '#define handle_event             %s_handle_event\n' "$$TOOL" >> $@; \
	printf '#define handle_lost_events       %s_handle_lost_events\n' "$$TOOL" >> $@; \
	printf '#define libbpf_print_fn          %s_libbpf_print_fn\n' "$$TOOL" >> $@; \
	printf '#define doc                      %s_doc\n' "$$TOOL" >> $@; \
	printf '#define env                      %s_env\n' "$$TOOL" >> $@; \
	printf '#define ksyms                    %s_ksyms\n' "$$TOOL" >> $@; \
	printf '#define syms_cache               %s_syms_cache\n' "$$TOOL" >> $@; \
	printf '#define argp_doc                 %s_argp_doc\n' "$$TOOL" >> $@; \
	printf '#include "%s"\n' "$(abspath $<)" >> $@

# Compile a wrapper .o (depends on the corresponding skel.h from libbpf-tools build)
$(TOOL_OBJS): $(OUTPUT)/%.o: $(WRAPPERS_DIR)/%.c $(LIBBPF_TOOLS)/.output/%.skel.h | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Compile common helper .o files from libbpf-tools/*.c
$(COMMON_OBJ): $(OUTPUT)/%.o: $(LIBBPF_TOOLS)/%.c | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Compile the dispatcher
$(OUTPUT)/dispatch.o: dispatch.c | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Final link: dispatcher + all tool wrappers + shared helpers + libbpf.a
libbpf-tools-box: $(OUTPUT)/dispatch.o $(TOOL_OBJS) $(COMMON_OBJ) $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -rf $(OUTPUT) libbpf-tools-box

# Phony convenience: show how many _main symbols are linked
.PHONY: verify
verify: libbpf-tools-box
	@echo "=== _main symbol count (should be 91) ==="
	@nm libbpf-tools-box | grep '_main$$' | wc -l
	@echo "=== handle_event symbols (should all be unique/prefixed) ==="
	@nm libbpf-tools-box | grep 'handle_event' || echo "(none — all renamed)"
