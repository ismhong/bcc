# libbpf-tools-multi — Busybox-style Multi-Call Binary

A single statically-linked binary (`libbpf-tools-box`) that contains all 91 tools from
[`libbpf-tools/`](../libbpf-tools/), dispatched by name — just like BusyBox.

---

## Overview

Instead of shipping 91 separate binaries (each duplicating libbpf, skeleton
bytecode, and helper code), `libbpf-tools-box` packs them all into one file. This
matters especially for embedded Linux / Android, where storage and transfer
bandwidth are at a premium.

```
libbpf-tools-box opensnoop            # direct invocation
libbpf-tools-box softirqs 1 5
ln -s libbpf-tools-box opensnoop && ./opensnoop   # busybox symlink style
```

All 91 tools retain their full feature set; the only difference is how they
are invoked.

---

## Prerequisites

You **must** build `libbpf-tools/` first. This generates:

- `libbpf-tools/.output/libbpf.a` — the libbpf static library
- `libbpf-tools/.output/<tool>.skel.h` — per-tool BPF skeletons
- `libbpf-tools/.output/bpftool` — (used during that build only)

```bash
# Host build
make -C ../libbpf-tools

# Cross-compile for arm64
make -C ../libbpf-tools ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

# Cross-compile for arm32
make -C ../libbpf-tools ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```

---

## Build

```bash
cd libbpf-tools-multi/

# Native host build
make

# Cross-compile for arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

# Cross-compile for arm32
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```

The output binary is `libbpf-tools-box` in the current directory.

---

## Usage

### Direct invocation

```bash
./libbpf-tools-box opensnoop
./libbpf-tools-box softirqs 1 5
./libbpf-tools-box runqlat --help
./libbpf-tools-box profile -F 99 10
```

### Busybox symlink style

```bash
for tool in $(./libbpf-tools-box 2>&1 | grep '  ' | awk '{print $1}'); do
    ln -sf libbpf-tools-box "$tool"
done
./opensnoop
./softirqs 1 5
```

### On Android

```bash
adb push libbpf-tools-box /data/libbpf-tools-box
adb shell "chmod +x /data/libbpf-tools-box"
adb shell "/data/libbpf-tools-box opensnoop"
adb shell "/data/libbpf-tools-box --btf /data/vmlinux softirqs 1 2"
```

---

## Architecture

### The Wrapper Approach

`libbpf-tools/` tools cannot be linked directly together because 68+ of them
define conflicting non-static global symbols (e.g. `argp_program_version`,
`handle_event`, `libbpf_print_fn`, `main`).

**Solution:** for each tool, the Makefile auto-generates a thin wrapper `.c`
in `.output/wrappers/<tool>.c`. The wrapper uses C preprocessor `#define`
to rename conflicting symbols *before* `#include`-ing the original tool source:

```c
/* Auto-generated wrapper for opensnoop — DO NOT EDIT */
#define main                     opensnoop_main
#define argp_program_version     opensnoop_argp_version
#define argp_program_bug_address opensnoop_argp_bug_address
#define argp_program_doc         opensnoop_argp_doc
#define argp_args_doc            opensnoop_argp_args_doc
#define handle_event             opensnoop_handle_event
#define handle_lost_events       opensnoop_handle_lost_events
#define libbpf_print_fn          opensnoop_libbpf_print_fn
#include "/path/to/libbpf-tools/opensnoop.c"
```

- **Static** globals/functions inside the tool `.c` remain `static` — they
  never conflict between translation units.
- All conflicting **non-static** symbols get unique per-tool names.
- `#include`-ing `.c` files is intentional and is how the renaming is applied.

### What's Shared vs. Unique

| What | How it's handled |
|---|---|
| `libbpf.a` | Linked once, shared by all tools |
| `trace_helpers.o`, `compat.o`, etc. | Compiled once from `libbpf-tools/*.c`, linked once |
| Tool BPF skeletons (`*.skel.h`) | Embedded in each tool's object (unique per tool) |
| `argp_program_version`, `main`, etc. | Renamed per-tool via `#define` in wrapper |
| Static helpers inside tool `.c` | Stay `static` — no conflict possible |

### Build Phases

1. **Phase 1 — Prerequisite check**: Verify `../libbpf-tools/.output/libbpf.a`
   exists. Exit with helpful error if not.
2. **Phase 2 — Build**:
   - Generate wrapper `.c` per tool
   - Compile each wrapper `.o` (using the pre-built `*.skel.h`)
   - Compile common helper `.o` files from `libbpf-tools/*.c`
   - Link everything with `libbpf.a` → `libbpf-tools-box`

---

## Upstream Sync and Adding New Tools

This directory **never modifies files in `../libbpf-tools/`**. Syncing upstream
is simply:

```bash
git fetch upstream
git merge upstream/main
# Done — libbpf-tools/ is untouched by this directory
```

### When upstream adds a new tool

Suppose upstream adds `newtool` (i.e. `libbpf-tools/newtool.c` with `main()`
appears after a merge):

1. Add `newtool` to the `TOOLS` list in [`Makefile`](Makefile).
2. Add `extern int newtool_main(int argc, char **argv);` to [`dispatch.c`](dispatch.c).
3. Add `{ "newtool", newtool_main }` to the `tools[]` table in `dispatch.c`.
4. Run `make` — the wrapper is auto-generated, tool compiled, and linked.

No changes needed in `libbpf-tools/` itself.

### If the build fails with `multiple definition`

Upstream added a non-static global symbol that conflicts. Fix:

1. Identify the symbol from the linker error message.
2. Add a `#define` line to the wrapper generation rule in `Makefile`:
   ```makefile
   printf '#define new_symbol  %s_new_symbol\n' "$$TOOL" >> $@; \
   ```
3. Rebuild — no changes needed in `libbpf-tools/`.

### Symbols renamed in every wrapper

| Original symbol | Renamed to |
|---|---|
| `main` | `TOOL_main` |
| `argp_program_version` | `TOOL_argp_version` |
| `argp_program_bug_address` | `TOOL_argp_bug_address` |
| `argp_program_doc` | `TOOL_argp_doc` |
| `argp_args_doc` | `TOOL_argp_args_doc` |
| `handle_event` | `TOOL_handle_event` |
| `handle_lost_events` | `TOOL_handle_lost_events` |
| `libbpf_print_fn` | `TOOL_libbpf_print_fn` |

These `#define`s are applied to every tool (harmless if the tool doesn't use
a particular symbol).

---

## Verification

```bash
# Count unique _main symbols — should be 91
nm libbpf-tools-box | grep '_main$' | wc -l

# Verify no bare handle_event (all should be prefixed)
nm libbpf-tools-box | grep 'T handle_event' || echo "OK: no bare handle_event"

# Or use the built-in verify target
make verify
```

---

## Size Comparison

| Approach | Approximate size (arm64 static) |
|---|---|
| 91 individual binaries | ~91 × 4 MB ≈ 364 MB |
| `libbpf-tools-box` multi-call | ~20–30 MB (shared libbpf + skeletons) |

Exact numbers depend on kernel version, debug info, and compression.

---

## Files in this Directory

| File | Purpose |
|---|---|
| `Makefile` | Build system (generates wrappers, compiles, links) |
| `dispatch.c` | `main()` dispatcher — routes by argv[0] or argv[1] |
| `README.md` | This file |
| `.output/wrappers/` | Auto-generated wrapper `.c` files (gitignored) |
| `.output/*.o` | Compiled objects (gitignored) |
| `libbpf-tools-box` | Output binary (gitignored) |
