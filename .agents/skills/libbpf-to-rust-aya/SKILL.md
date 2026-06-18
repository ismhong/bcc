---
name: libbpf-to-rust-aya
description: Guidelines and step-by-step process for porting C-based libbpf-tools to the Rust/Aya-based libbpf-tools-rs workspace.
---

# Porting C libbpf-tools to Rust/Aya (`libbpf-tools-rs`)

This skill guide outlines the architectural design and workflow for porting traditional C-based `libbpf-tools` to the modern, Rust-based `libbpf-tools-rs` workspace using the **Aya** eBPF framework.

---

## Architecture of `libbpf-tools-rs`

Ensure the target tool is mapped to the four core crates:
- **`bcc-box-common`**: Shared event formats and options structs. Must use `#[repr(C)]`.
- **`bcc-box-ebpf`**: Kernel-space eBPF programs compiling to `bpfel-unknown-none`.
- **`bcc-box`**: Userspace controller that loads BPF bytecode, handles arguments, resolves BTF, and formats stdout.
- **`xtask`**: Automates eBPF compilation and resources bundling.

---

## Step-by-Step Porting Process

### Step 1: Analyze the C Implementation
Locate the C files in `libbpf-tools/`:
- `<tool>.h`: Shared event structs.
- `<tool>.bpf.c`: Kernel probe attachments and map definitions.
- `<tool>.c`: Userspace command-line flags, ring-buffer polling, and print logs.

### Step 2: Implement Shared Types (`bcc-box-common`)
Define the shared structures in `libbpf-tools-rs/bcc-box-common/src/lib.rs`.
- Match C alignments using `#[repr(C)]`.
- Example for a common event structure:
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct SampleEvent {
      pub pid: u32,
      pub comm: [u8; 16],
      pub filename: [u8; 256],
  }
  ```

### Step 3: Write Kernel eBPF Code (`bcc-box-ebpf`)
Create `libbpf-tools-rs/bcc-box-ebpf/src/<tool>.rs`.
1. **Map Definition**: Define maps like `RingBuf` for events or `HashMap` to pass data between entry and exit probes.
2. **ARM64 LTO Workaround (Double Dereferencing)**:
   On LTO-enabled kernels (e.g. Android GKI), do NOT use standard `ctx.arg(N)` or probe parameters directly, as compiler optimizations can scramble registers. Instead:
   - Attach kprobes to stable syscall wrappers (e.g. `__arm64_sys_openat`).
   - Extract userspace registers by double dereferencing `x0`:
     ```rust
     let regs_ptr = ctx.as_ptr() as *const PtRegsArm64;
     let mut user_regs_ptr: *const PtRegsArm64 = core::ptr::null();
     bpf_probe_read_kernel(&(*regs_ptr).regs[0], &mut user_regs_ptr);
     // Now read userspace arguments from user_regs_ptr:
     // regs[0] = x0, regs[1] = x1, regs[2] = x2, etc.
     ```
3. **Compat Syscalls**: Hook both 64-bit (`__arm64_sys_*`) and 32-bit compat (`__arm64_compat_sys_*`) wrappers.
4. **Exit Probe (Return Values)**: Directly dereference `x0` from the register list in kretprobe context:
   ```rust
   let ret = unsafe {
       let regs = ctx.as_ptr() as *const i64;
       bpf_probe_read_kernel(regs).unwrap_or(-1) as i32
   };
   ```

### Step 4: Bundle the eBPF Program
1. Add binary target to `libbpf-tools-rs/bcc-box-ebpf/Cargo.toml`:
   ```toml
   [[bin]]
   name = "<tool>"
   path = "src/<tool>.rs"
   ```
2. Update `libbpf-tools-rs/xtask/src/main.rs` to compile and bundle:
   - Ensure it compiles `<tool>` and copies it to `bcc-box/resources/`.

### Step 5: Implement Userspace Tracing (`bcc-box`)
Create `libbpf-tools-rs/bcc-box/src/tools/<tool>.rs`.
1. **Argument Parsing**: Define options using `clap` (e.g., `-p` PID filter, `-u` UID filter, `-x` failed only, etc.). Ensure **all arguments of the original tool** are supported.
2. **BTF Handling**: Ensure external BTF files can be loaded:
   ```rust
   let mut loader = aya::EbpfLoader::new();
   if let Ok(btf_path) = std::env::var("LIBBPF_VMLINUX_BTF") {
       loader.btf(aya::Btf::parse_file(&btf_path).ok().as_ref());
   }
   ```
3. **Double Hooking**: Programmatically attach probes to both the 64-bit and compat system call entry/exit points if target is arm64.
4. **RingBuffer polling**: Read events and print matching the original tool's output headers and formatting.

### Step 6: Route in Main Entry
Register `<tool>` in the Busybox router inside `libbpf-tools-rs/bcc-box/src/main.rs`.

---

## Verification on Remote Android Target

Always verify porting against a live target.

1. **Clean and Compile**:
   ```bash
   make clean
   make arm64
   ```
2. **Push to Android**:
   ```bash
   adb push target/aarch64-unknown-linux-musl/release/bcc-box /data/bcc-box
   adb shell "chmod +x /data/bcc-box"
   ```
3. **Workload Validation**:
   Run the tool specifying the external BTF file path and verify using a short-running timeout (so it exits automatically):
   ```bash
   adb shell "timeout 5 /data/bcc-box --btf /data/vmlinux <tool> [args]"
   ```
4. **Compare Outputs**: Check that the PID, Command, Return values, and target arguments match the original tool exactly.
