# libbpf-tools-rs: Rust-based Busybox eBPF Tracing Suite

`libbpf-tools-rs` is a modern, Rust-based eBPF tracing suite powered by **Aya**. It aims to re-implement the classic C-based tools from `libbpf-tools` into a single, fully self-contained static executable (similar to Busybox). By routing multiple commands through a single binary, it simplifies deployment on target systems.

This suite is fully static-linked, highly optimized, and specifically tailored for modern platforms including standard Linux hosts, containerized systems, and remote Android boxes (AArch64).

---

## Architecture and Components

The workspace is organized into four core crates under the `libbpf-tools-rs/` subdirectory:

1. **`bcc-box` (Userspace Tool CLI)**
   - The primary user-facing binary.
   - Implements **Busybox-style routing**: if symlinked to tool names (e.g., `opensnoop` -> `bcc-box`), running the symlink executes that specific sub-command.
   - Manages BTF file loading, CO-RE relocations, loading/initializing BPF rings, and formatting tracing logs.
2. **`bcc-box-ebpf` (Kernel eBPF Programs)**
   - Contains raw BPF source code compiling to BPF bytecode.
   - Built using Rust's `nightly` toolchain and targeted for `bpfel-unknown-none`.
3. **`bcc-box-common` (Shared Data Structure definitions)**
   - Holds shared types (e.g., `Event` structures) utilized by both the kernel-space eBPF programs and userspace CLI parser.
4. **`xtask` (BPF Codegen Build Helper)**
   - A compilation helper task. Compiles `bcc-box-ebpf` using the nightly toolchain and copies the resulting BPF bytecode directly into `bcc-box/resources/` so it is compiled into the userspace binary at compile-time via `include_bytes!`.

---

## Technical Features & Highlights

- **Static Linking**: Compiles with `musl` targets (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) to yield a standalone binary with absolutely zero dynamic library dependencies.
- **External BTF Support (`--btf` / `LIBBPF_VMLINUX_BTF`)**: Essential for devices that lack built-in BTF (`/sys/kernel/btf/vmlinux`). Users can load external BTF files either by passing `--btf /path/to/vmlinux` or setting `LIBBPF_VMLINUX_BTF`.
- **AArch64 LTO Workaround (Double `pt_regs` Dereferencing)**: On LTO-enabled kernels (e.g. Android GKI), static kernel function parameters can be optimized or removed by LLVM. `bcc-box` attaches to the stable system call entry points (`__arm64_sys_*`) and uses double-dereferencing of the user registers pointer to safely read userspace pointers.
- **32-Bit Compat Support**: Automatically hooks into both 64-bit (`__arm64_sys_*`) and 32-bit compat (`__arm64_compat_sys_*`) system call entries to monitor both 32-bit and 64-bit processes on ARM64.

---

## Build Prerequisites

To compile the suite, you need to install Rust and the target toolchains:

1. **Rustup**: Install Rust toolchains.
2. **Nightly Toolchain & BPF Target**: Required to compile the eBPF programs.
   ```bash
   rustup toolchain install nightly
   rustup target add --toolchain nightly bpfel-unknown-none
   ```
3. **Cross-Compilation Targets** (Optional, if cross-compiling):
   ```bash
   rustup target add aarch64-unknown-linux-musl
   rustup target add x86_64-unknown-linux-musl
   ```

---

## Building the Suite

A helper `build.sh` script and a `Makefile` are provided in this folder to simplify builds across different platforms.

Navigate into `libbpf-tools-rs/` and run the build command:

### 1. Build for Host (Default)
Builds the eBPF programs and compiles userspace for the host system:
```bash
make host
# or: ./build.sh host
```
The output binary will be generated under `target/release/bcc-box`.

### 2. Cross-Compile for ARM64 (AArch64 Musl)
```bash
make arm64
# or: ./build.sh arm64
```
The output binary will be generated at `target/aarch64-unknown-linux-musl/release/bcc-box`.

### 3. Cross-Compile for x86_64 (x86_64 Musl)
```bash
make x86_64
# or: ./build.sh x86_64
```
The output binary will be generated at `target/x86_64-unknown-linux-musl/release/bcc-box`.

### 4. Build All Targets
```bash
make all
# or: ./build.sh all
```

### 5. Clean Build Artifacts
```bash
make clean
# or: ./build.sh clean
```

---

## Usage

### 1. Directly Running Subcommands
Run the binary and pass the tool name as a subcommand:
```bash
# General usage
./bcc-box <tool_name> [options]

# Example: Run opensnoop with external BTF file
./bcc-box --btf /data/vmlinux opensnoop
```

### 2. Busybox Symlink Routing
You can create symbolic links matching the supported tool names. The binary will automatically parse the symlink name to route to the correct tool:
```bash
# Create symlinks
ln -s bcc-box opensnoop
ln -s bcc-box execsnoop

# Run the symlink directly (equivalent to running subcommand)
./opensnoop --btf /data/vmlinux
./execsnoop --btf /data/vmlinux
```

---

## Supported Tools

- **`opensnoop`**: Trace files opened across the system, displaying process information, file descriptors, return errors, and file paths.
- **`execsnoop`**: Trace new process executions via system calls, capturing process names, parent IDs, execution results, and arguments.
